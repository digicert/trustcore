/*
 * cert_store.c
 *
 * Certificate Store
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
@file       cert_store.c
@brief      Mocana SoT Platform certificate store factory.
@details    This file contains Mocana SoT Platform certificate store functions.

@since 2.02
@version 6.4 and later

@flags
No flag definitions are required to use this file's functions.

@filedoc    cert_store.c
*/
#include "../common/moptions.h"

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/hash_value.h"
#include "../common/hash_table.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/sizedbuffer.h"
#if defined(__ENABLE_DIGICERT_MINIMAL_CA__)
#include "../common/mfmgmt.h"
#endif
#include "../crypto/rsa.h"
#if (defined(__ENABLE_DIGICERT_DSA__))
#include "../crypto/dsa.h"
#include "../crypto/dsa2.h"
#endif
#if (defined(__ENABLE_DIGICERT_ECC__))
#include "../crypto/primefld.h"
#include "../crypto/ecc.h"
#endif
#include "../crypto/pubcrypto.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/crypto.h"
#include "../crypto/pkcs7.h"
#include "../crypto/keyblob.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/cert_store.h"
#include "../crypto/cert_chain.h"
#include "../crypto/pkcs7_cert_store.h"
#include "../harness/harness.h"
#ifndef __DISABLE_DIGICERT_CERTIFICATE_PARSING__
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"
#include "../asn1/ASN1TreeWalker.h"
#include "../asn1/oiddefs.h"
#endif
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_pubcrypto_priv.h"
#if (defined(__ENABLE_DIGICERT_DSA__))
#include "../crypto_interface/crypto_interface_dsa.h"
#endif
#endif
#include "../asn1/derencoder.h"
#include "../crypto/malgo_id.h"
#if defined(__ENABLE_DIGICERT_MINIMAL_CA__) && defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
#include "../data_protection/file_protect.h"
#endif

#ifdef __ENABLE_DIGICERT_CV_CERT__
#include "../crypto/cvcert.h"
#endif

/*------------------------------------------------------------------*/

#define MOCANA_CERT_STORE_INIT_HASH_VALUE   (0x07d50624)

/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 */
typedef struct identityPair
{
    AsymmetricKey               identityKey;
    ubyte                      *pAlias;
    ubyte4                      aliasLen;
    sbyte4                      numCertificate;
    SizedBuffer*                certificates;
    ubyte4                      certAlgoFlags; /* see flag definitions in the .h file */
    ubyte4                      certAlgoId;
    ubyte4                      signAlgoId;
    ubyte2                      certKeyUsage;  /* key usage for certificate */
    extendedData                extData;
    struct identityPair*        pNextIdentityKeyPair;
} identityPair;

/**
 * @dont_show
 * @internal
 */
typedef struct identityPskTuple
{
    ubyte*                      pPskIdentity;               /* i.e. PSK identity */
    ubyte4                      pskIdentityLength;
    ubyte*                      pPskHint;                   /* i.e. PSK hint */
    ubyte4                      pskHintLength;
    ubyte*                      pPskSecret;                 /* i.e. PSK secret */
    ubyte4                      pskSecretLength;

    struct identityPskTuple*    pNextIdentityPskTuple;

} identityPskTuple;


/**
 * @dont_show
 * @internal
 */
typedef struct certStore
{
    identityPair*               pIdentityMatrixList[CERT_STORE_AUTH_TYPE_ARRAY_SIZE][CERT_STORE_IDENTITY_TYPE_ARRAY_SIZE];
    identityPskTuple*           pIdentityPskList;
    hashTableOfPtrs*            pTrustHashTable;            /* a hash table of "trustPoint"s */

#if !defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__)
    hashTableOfPtrs*            pCertHashTable;            /* a hash table of "certificateEntry"s */
#endif

    intBoolean                  isCertStoreLocked;          /*!!!! TODO */

#if defined (__ENABLE_DIGICERT_ASYM_KEY__)
    MocCtx                      pMocCtx;
#endif

} certStore;

#if defined(__ENABLE_DIGICERT_MINIMAL_CA__)

/**
 * @dont_show
 * @internal
 */
typedef struct certificateFileEntry
{
    ubyte *pSerialNumber;
    ubyte4 serialNumberLen;
    ubyte *pSubject;
    ubyte4 subjectLen;
    ubyte *pIssuer;
    ubyte4 issuerLen;
    sbyte *pFileName;
    byteBoolean isChild;
    intBoolean fpSigFileExists;
} certificateFileEntry;

#endif /* __ENABLE_DIGICERT_MINIMAL_CA__ */

/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 */
typedef struct trustPoint
{
    ubyte*                      pDerCert;
    ubyte4                      derCertLength;

    ubyte4                      subjectOffset;              /* for fast comparisons */
    ubyte4                      subjectLength;

    struct  trustPoint*         pNextTrustPoint;            /* another trust point with the same subject */
} trustPoint;

/**
 * @dont_show
 * @internal
 */
typedef struct subjectDescr
{
    const ubyte*                pSubject;
    ubyte4                      subjectLength;

} subjectDescr;


/*------------------------------------------------------------------*/


#if !defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__)

/**
 @cond
 */

/* every cert entered as an identity or a trust point is also indexed
 by issuer/serial number */
typedef struct certificateEntry
{
    ubyte4 issuerOffset;
    ubyte4 issuerLength;
    ubyte4 serialNumberOffset;
    ubyte4 serialNumberLength;

    sbyte4 index; /* -1 -> trustPoint, 0 - n: index of certificate in identity pair */
    union
    {
        trustPoint* pTrustPoint;
        identityPair* pIdentityPair;
    } link;
} certificateEntry;


typedef struct issuerSerialPair
{
    const ubyte* pIssuer;
    ubyte4       issuerLength;
    const ubyte* serialNumber;
    ubyte4       serialNumberLength;
} issuerSerialPair;

typedef struct validateParentArg
{
    ASN1_ITEMPTR pCertificate;
    CStream cs;
    ubyte4 chainLength;
} validateParentArg;

PKCS7_Callbacks CERT_STORE_PKCS7Callbacks =
{
    CERT_STORE_PKCS7_GetPrivateKey,
    CERT_STORE_PKCS7_ValidateRootCertificate,
    CERT_STORE_PKCS7_GetCertificate,
    0
};
/**
 @endcond
 */

/* Build an AsymmetricKey from the key blob.
 * The caller determined that the blob type is MocAsym and calls this function.
 * The caller passes in an empty AsymmetricKey, this function will build a
 * MocAsymKey using the MocCtx stored in the CertStore. It will then set the
 * AsymmetricKey object.
 */
MSTATUS SpecialMocAsymKeyDeserialize (
  certStorePtr pCertStore,
  const ubyte *pKeyBlob,
  ubyte4 keyBlobLen,
  AsymmetricKey *pAsymKey
  );

/*------------------------------------------------------------------*/
/* function prototypes */

static MSTATUS
CERT_STORE_testIssuerSerialNumber(void* pAppData, void* pTestData,
                                  intBoolean *pRetIsMatch);

/* All the Add functions Ex call this one.
 * <p>This function will add a key, a cert, or a pair. Actually, it adds a cert
 * chain.
 * <p>Some functions can add a cert and key or a cert alone, but there must be a
 * cert. This function does not require a cert. So the caller will have already
 * returned an error if there is no cert and a cert is required.
 */
static MSTATUS CERT_STORE_addGenericIdentityEx (
  certStorePtr pCertStore,
  enum identityTypes identityType,
  ubyte *pAlias,
  ubyte4 aliasLen,
  struct SizedBuffer *certificates,
  ubyte4 numCertificate,
  const ubyte *pKeyBlob,
  ubyte4 keyBlobLength,
  extendedData *pExtData
  );

/*------------------------------------------------------------------*/

static MSTATUS CERT_STORE_getCertificateEntryData( certificateEntry* pCertEntry,
                                                   const ubyte** ppRetCertDer,
                                                   ubyte4* retCertDerLength,
                                                   const AsymmetricKey** key)
{
    MSTATUS status = OK;

    if (!pCertEntry)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (pCertEntry->index < 0)
    {
        /* trustpoint */
        if (ppRetCertDer)
        {
            *ppRetCertDer = pCertEntry->link.pTrustPoint->pDerCert;
        }
        if (retCertDerLength)
        {
            *retCertDerLength = pCertEntry->link.pTrustPoint->derCertLength;
        }
        if (key)
        {
            *key = 0;
        }
    }
    else
    {
        identityPair* pIP = pCertEntry->link.pIdentityPair;

        if ( pCertEntry->index >= pIP->numCertificate)
        {
            status = ERR_INDEX_OOB;
            goto exit;
        }

        if (ppRetCertDer)
        {
            *ppRetCertDer = pIP->certificates[ pCertEntry->index].data;
        }

        if (retCertDerLength)
        {
            *retCertDerLength = pIP->certificates[pCertEntry->index].length;
        }

        if (key)
        {
            *key = (0 == pCertEntry->index) ? &(pIP->identityKey) : 0;
        }
    }
exit:

    return status;
}
#endif /* !defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__) */


/*------------------------------------------------------------------*/

static MSTATUS
CERT_STORE_convertPubKeyTypeToCertStoreKeyType(ubyte4 pubKeyType, ubyte4 *pRetCertStoreKeyType)
{
    MSTATUS status = OK;

    switch (pubKeyType & 0xff)
    {
        case akt_rsa:
        {
            *pRetCertStoreKeyType = CERT_STORE_AUTH_TYPE_RSA;
            break;
        }
        case akt_rsa_pss:
        {
            *pRetCertStoreKeyType = CERT_STORE_AUTH_TYPE_RSA_PSS;
            break;
        }
#if (defined(__ENABLE_DIGICERT_ECC__))
        case akt_ecc:
        {
            *pRetCertStoreKeyType = CERT_STORE_AUTH_TYPE_ECDSA;
            break;
        }
#if (defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__))
        case akt_ecc_ed:
        {
            *pRetCertStoreKeyType = CERT_STORE_AUTH_TYPE_EDDSA;
            break;
        }
#endif
#if (defined(__ENABLE_DIGICERT_PQC__))
        case akt_hybrid:
        {
            *pRetCertStoreKeyType = CERT_STORE_AUTH_TYPE_HYBRID;
            break;
        }
#endif
#endif /* __ENABLE_DIGICERT_ECC__ */
#if (defined(__ENABLE_DIGICERT_PQC__))
        case akt_qs:
        {
            *pRetCertStoreKeyType = CERT_STORE_AUTH_TYPE_QS;
            break;
        }
#endif
#if (defined(__ENABLE_DIGICERT_DSA__))
        case akt_dsa:
        {
            *pRetCertStoreKeyType = CERT_STORE_AUTH_TYPE_DSA;
            break;
        }
#endif
        default:
        {
            status = ERR_CERT_STORE_UNKNOWN_KEY_TYPE;
            break;
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
CERT_STORE_convertCertStoreKeyTypeToPubKeyType(ubyte4 certStoreKeyType, ubyte4 *pRetPubKeyType)
{
    MSTATUS status = OK;

    switch (certStoreKeyType)
    {
        case CERT_STORE_AUTH_TYPE_RSA:
        {
            *pRetPubKeyType = akt_rsa;
            break;
        }
        case CERT_STORE_AUTH_TYPE_RSA_PSS:
        {
            *pRetPubKeyType = akt_rsa_pss;
            break;
        }
#if (defined(__ENABLE_DIGICERT_ECC__))
        case CERT_STORE_AUTH_TYPE_ECDSA:
        {
            *pRetPubKeyType = akt_ecc;
            break;
        }
#if (defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__))
        case CERT_STORE_AUTH_TYPE_EDDSA:
        {
            *pRetPubKeyType = akt_ecc_ed;
            break;
        }
#endif
#if (defined(__ENABLE_DIGICERT_PQC__))
        case CERT_STORE_AUTH_TYPE_HYBRID:
        {
            *pRetPubKeyType = akt_hybrid;
            break;
        }
#endif
#endif /* __ENABLE_DIGICERT_ECC__ */
#if (defined(__ENABLE_DIGICERT_PQC__))
        case CERT_STORE_AUTH_TYPE_QS:
        {
            *pRetPubKeyType = akt_qs;
            break;
        }
#endif
#if (defined(__ENABLE_DIGICERT_DSA__))
        case CERT_STORE_AUTH_TYPE_DSA:
        {
            *pRetPubKeyType = akt_dsa;
            break;
        }
#endif
        default:
        {
            status = ERR_CERT_STORE_UNKNOWN_KEY_TYPE;
            break;
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
CERT_STORE_allocHashPtrElement(void *pHashCookie,
                               hashTablePtrElement **ppRetNewHashElement)
{
    /* we could use a memory pool here to reduce probability of fragmentation */
    /* certificates stores should be fairly small, so a pool is probably not necessary */
    MSTATUS status = OK;
    MOC_UNUSED(pHashCookie);

    if (NULL == (*ppRetNewHashElement = (hashTablePtrElement*) MALLOC(sizeof(hashTablePtrElement))))
        status = ERR_MEM_ALLOC_FAIL;

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
CERT_STORE_freeTrustHashPtrElement(void *pHashCookie,
                                   hashTablePtrElement *pFreeHashElement)
{
    trustPoint*     pTrustPointDescr = (trustPoint *)pFreeHashElement->pAppData;
    MOC_UNUSED(pHashCookie);

    /* Clear App data added to Hash Table */
    while(pTrustPointDescr)
    {
        trustPoint* pNextTrustPoint = pTrustPointDescr->pNextTrustPoint;

        FREE(pTrustPointDescr->pDerCert);
        FREE(pTrustPointDescr);

        pTrustPointDescr = pNextTrustPoint;
    }

    FREE(pFreeHashElement);
    return OK;
}

#if !defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__)

/*------------------------------------------------------------------*/

static MSTATUS
CERT_STORE_freeCertHashPtrElement(void *pHashCookie,
                                  hashTablePtrElement *pFreeHashElement)
{
    certificateEntry*     pCertEntry = (certificateEntry *)pFreeHashElement->pAppData;
    MOC_UNUSED(pHashCookie);

    /* Clear App data added to Hash Table */
    if (pCertEntry)
    {
         FREE(pCertEntry);
   }

    FREE(pFreeHashElement);
    return OK;
}

#endif /* !defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__) */


/*------------------------------------------------------------------*/

/**
@brief      Create and initialize a Mocana SoT Platform certificate store.

@details    This function creates and initializes a Mocana SoT Platform
            certificate store container instance. (Multiple instances are
            allowed.)

@ingroup    cert_store_functions

@since 2.02
@version 6.4 and later

@todo_version (interior changes w/\__DISABLE_DIGICERT_CERTIFICATE_PARSING__)

@flags
No flag definitions are required to use this callback.

@inc_file cert_store.h

@param ppNewStore   Pointer to \c certStorePtr, which on return, contains the
                      newly allocated and initialized certificate store
                      container.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cert_store.c
*/
extern MSTATUS
CERT_STORE_createStore(certStorePtr *ppNewStore)
{
    hashTableOfPtrs*    pTrustHashTable = NULL;

#if !defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__)
    hashTableOfPtrs*    pCertHashTable = NULL;
#endif

    certStore*          pNewStore = NULL;
    MSTATUS             status;

    if (NULL == ppNewStore)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (pNewStore = (certStore*) MALLOC(sizeof(certStore))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)(pNewStore), 0x00, sizeof(certStore));

    if (OK > (status = HASH_TABLE_createPtrsTable(&pTrustHashTable,
                                                  MAX_SIZE_CERT_STORE_TRUST_HASH_TABLE,
                                                  NULL,
                                                  CERT_STORE_allocHashPtrElement,
                                                  CERT_STORE_freeTrustHashPtrElement)))
    {
        goto exit;
    }

#if !defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__)
    if (OK > (status = HASH_TABLE_createPtrsTable(&pCertHashTable,
                                                  MAX_SIZE_CERT_STORE_TRUST_HASH_TABLE,
                                                  NULL,
                                                  CERT_STORE_allocHashPtrElement,
                                                  CERT_STORE_freeCertHashPtrElement)))
    {
        goto exit;
    }
#endif

    /* add/clean trust hash tables to new store */
    pNewStore->pTrustHashTable = pTrustHashTable;
    pTrustHashTable = NULL;

#if !defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__)
    pNewStore->pCertHashTable = pCertHashTable;
    pCertHashTable = NULL;
#endif

    /* return/clean new store */
    *ppNewStore = pNewStore;
    pNewStore = NULL;

exit:

    HASH_TABLE_removePtrsTable(pTrustHashTable, NULL);

#if !defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__)
    HASH_TABLE_removePtrsTable(pCertHashTable, NULL);
#endif

    if (pNewStore)
        FREE(pNewStore);

    return status;
}


/*------------------------------------------------------------------*/

/**
@brief      Release (free) memory used by a Mocana SoT Platform certificate
            store.

@details    This function releases (frees) memory used by a Mocana SoT
            Platform certificate store, including all its component structures.

@ingroup    cert_store_functions

@since 2.02
@version 2.02 and later

@todo_version (removed interior sbyte4 typecasting for i).

@flags
No flag definitions are required to use this callback.

@inc_file cert_store.h

@param ppReleaseStore   Pointer to Mocana SoT Platform certificate store to
                          release (free).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cert_store.c
*/
extern MSTATUS
CERT_STORE_releaseStore(certStorePtr *ppReleaseStore)
{
    ubyte4  i, j;
    sbyte4  k;
    MSTATUS status = OK;

    if ((NULL == ppReleaseStore) || (NULL == *ppReleaseStore))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if defined (__ENABLE_DIGICERT_ASYM_KEY__)
    if (NULL != (*ppReleaseStore)->pMocCtx)
    {
      ReleaseMocCtxRef ((*ppReleaseStore)->pMocCtx);
    }
#endif

    /* Remove identity descriptors */
    for (i = 0; i < CERT_STORE_AUTH_TYPE_ARRAY_SIZE; i++)
    {
        identityPair*   pIdentityPair;
        identityPair*   pNextIdentityPair;

        for (j = 0; j < CERT_STORE_IDENTITY_TYPE_ARRAY_SIZE; j++)
        {
            if (NULL != (pIdentityPair = (*ppReleaseStore)->pIdentityMatrixList[i][j]))
            {
                /* clear head */
                (*ppReleaseStore)->pIdentityMatrixList[i][j] = NULL;

                while (pIdentityPair)
                {
                    /* get next pair ptr */
                    pNextIdentityPair = (identityPair *)pIdentityPair->pNextIdentityKeyPair;

                    /* free identity record */
                    CRYPTO_uninitAsymmetricKey(&pIdentityPair->identityKey, NULL);

                    if (NULL != pIdentityPair->pAlias)
                    {
                      DIGI_FREE ((void **)&(pIdentityPair->pAlias));
                    }

                    if (NULL != pIdentityPair->certificates)
                    {
                        for (k = 0; k < pIdentityPair->numCertificate; k++)
                        {
                            SB_Release(&pIdentityPair->certificates[k]);
                        }
                        FREE(pIdentityPair->certificates);
                    }

                    FREE(pIdentityPair);

                    /* move to next identity in list */
                    pIdentityPair = pNextIdentityPair;
                }
            }
        }
    }

    /* Remove PSK identity descriptors */
    if (NULL != (*ppReleaseStore)->pIdentityPskList)
    {
        identityPskTuple*   pIdentityPskTuple = (*ppReleaseStore)->pIdentityPskList;
        identityPskTuple*   pNextIdentityPskTuple;

        /* clear head */
        (*ppReleaseStore)->pIdentityPskList = NULL;

        while (pIdentityPskTuple)
        {
            /* get next tuple */
            pNextIdentityPskTuple = pIdentityPskTuple->pNextIdentityPskTuple;

            /* clear out current tuple */
            if (pIdentityPskTuple->pPskIdentity)
                FREE(pIdentityPskTuple->pPskIdentity);

            if (pIdentityPskTuple->pPskHint)
                FREE(pIdentityPskTuple->pPskHint);

            if (pIdentityPskTuple->pPskSecret)
                FREE(pIdentityPskTuple->pPskSecret);

            /* free whole record */
            FREE(pIdentityPskTuple);

            /* move to next tuple */
            pIdentityPskTuple = pNextIdentityPskTuple;
        }
    }

    /* remove hash table of trust points, CAs, etc */
    HASH_TABLE_removePtrsTable((*ppReleaseStore)->pTrustHashTable, NULL);

#if !defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__)
    HASH_TABLE_removePtrsTable((*ppReleaseStore)->pCertHashTable, NULL);
#endif

    FREE(*ppReleaseStore);
    *ppReleaseStore = NULL;

exit:
    return status;
}

MOC_EXTERN MSTATUS CERT_STORE_loadMocCtx (
  certStorePtr pCertStore,
  MocCtx pMocCtx
  )
{
#if !defined (__ENABLE_DIGICERT_ASYM_KEY__)
  return (ERR_NOT_IMPLEMENTED);
#else
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if ( (NULL == pCertStore) || (NULL == pMocCtx) )
    goto exit;

  status = ERR_INVALID_INPUT;
  if (NULL != pCertStore->pMocCtx)
    goto exit;

  status = AcquireMocCtxRef (pMocCtx);
  if (OK != status)
    goto exit;

  pCertStore->pMocCtx = pMocCtx;

exit:

  return (status);
#endif
}

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_CERTIFICATE_PARSING__

static MSTATUS
CERT_STORE_addIdentityComponent(certStorePtr pCertStore,
                                identityPair* pIdentity,
                                sbyte4 indexInIdentity)
{
    ASN1_ITEMPTR pIssuer, pSerialNumber;
    issuerSerialPair isp;
    certificateEntry* pPreviousCertEntry;
    certificateEntry* pNewCertEntry = NULL;
    intBoolean foundPreviousCertEntry;
    ubyte4 hashValue;
    ASN1_ITEMPTR pRoot = 0;
    CStream cs;
    MemFile mf;
    ubyte* cert;

    MSTATUS status;

    cert = pIdentity->certificates[indexInIdentity].data;

    MF_attach(&mf, pIdentity->certificates[indexInIdentity].length, cert);

    CS_AttachMemFile(&cs, &mf);

    if (OK > ( status = X509_parseCertificate(cs, &pRoot)))
    {
        goto exit;
    }

    if (OK > (status = X509_getCertificateIssuerSerialNumber(ASN1_FIRST_CHILD(pRoot),
                                                             &pIssuer,
                                                             &pSerialNumber)))
    {
        goto exit;
    }

    isp.pIssuer = cert + pIssuer->dataOffset;
    isp.issuerLength = pIssuer->length;
    isp.serialNumber = cert + pSerialNumber->dataOffset;
    isp.serialNumberLength = pSerialNumber->length;

    /* calculate hash for serial number */
    HASH_VALUE_hashGen(isp.serialNumber, isp.serialNumberLength,
                       MOCANA_CERT_STORE_INIT_HASH_VALUE, &hashValue);

    /* find a possible cert entry with the same value already in the hash table */
    if (OK > (status = HASH_TABLE_findPtr(pCertStore->pCertHashTable,
                                          hashValue,
                                          (void *)&isp,
                                          CERT_STORE_testIssuerSerialNumber,
                                          (void **)&pPreviousCertEntry,
                                          &foundPreviousCertEntry)))
    {
        goto exit;

    }

    if ((!foundPreviousCertEntry) || (NULL == pPreviousCertEntry))
    {
        /* no previous one: store a new point*/
        /* allocate/init trust point structure */
        if (NULL == (pNewCertEntry = (certificateEntry*) MALLOC(sizeof(certificateEntry))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMSET((ubyte *)pNewCertEntry, 0x00, sizeof(certificateEntry));

        pNewCertEntry->issuerOffset = pIssuer->dataOffset;
        pNewCertEntry->issuerLength = pIssuer->length;
        pNewCertEntry->serialNumberOffset = pSerialNumber->dataOffset;
        pNewCertEntry->serialNumberLength = pSerialNumber->length;
        pNewCertEntry->index = indexInIdentity; /* link is identityPair */
        pNewCertEntry->link.pIdentityPair = pIdentity;

        if (OK > (status = HASH_TABLE_addPtr(pCertStore->pCertHashTable,
                                             hashValue,
                                             pNewCertEntry)))
        {
            goto exit;
        }
    }
    else if ( 0 == indexInIdentity && 0 != pPreviousCertEntry->index)
    {
        /* no duplicate entry allowed: issuer/serial number should be unique */
        /* BUT it's possible this was registered earlier without a key. So make
         sure to replace the link if the index of the found one is not 0 (has no key,
         either a trust point or a non leaf cert) and the index of the new one is
         0 (leaf cert) */

        pPreviousCertEntry->index = indexInIdentity;
        pPreviousCertEntry->link.pIdentityPair = pIdentity;
    }

exit:
    if (pRoot)
        TREE_DeleteTreeItem((TreeItem*)pRoot);

    return status;
}

#ifdef __ENABLE_DIGICERT_CV_CERT__
static MSTATUS
CERT_STORE_CVC_addIdentityComponent(certStorePtr pCertStore,
                                    identityPair* pIdentity,
                                    sbyte4 indexInIdentity)
{
    issuerSerialPair isp;
    certificateEntry* pPreviousCertEntry;
    certificateEntry* pNewCertEntry = NULL;
    intBoolean foundPreviousCertEntry;
    ubyte4 hashValue;
    ubyte* pCertStart = NULL;
    CV_CERT *pCertData = NULL;
    MSTATUS status;

    pCertStart = pIdentity->certificates[indexInIdentity].data;

    status = CV_CERT_parseCert (
        pIdentity->certificates[indexInIdentity].data, pIdentity->certificates[indexInIdentity].length, &pCertData);
    if (OK != status)
        goto exit;

    isp.pIssuer = pCertData->pCertAuthRef;
    isp.issuerLength = pCertData->certAuthRefLen;
    isp.serialNumber = pCertData->pCertHolderRef;
    isp.serialNumberLength = pCertData->certHolderRefLen;

    /* For CVC use the CHR as the serial number */
    HASH_VALUE_hashGen(pCertData->pCertHolderRef, pCertData->certHolderRefLen,
                       MOCANA_CERT_STORE_INIT_HASH_VALUE, &hashValue);

    /* find a possible cert entry with the same value already in the hash table */
    if (OK > (status = HASH_TABLE_findPtr(pCertStore->pCertHashTable,
                                          hashValue,
                                          (void *)&isp,
                                          CERT_STORE_testIssuerSerialNumber,
                                          (void **)&pPreviousCertEntry,
                                          &foundPreviousCertEntry)))
    {
        goto exit;

    }

    if ((!foundPreviousCertEntry) || (NULL == pPreviousCertEntry))
    {
        /* no previous one: store a new point*/
        /* allocate/init trust point structure */
        if (NULL == (pNewCertEntry = (certificateEntry*) MALLOC(sizeof(certificateEntry))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMSET((ubyte *)pNewCertEntry, 0x00, sizeof(certificateEntry));

        pNewCertEntry->issuerOffset = pCertData->pCertAuthRef - pCertStart;
        pNewCertEntry->issuerLength = pCertData->certAuthRefLen;
        pNewCertEntry->serialNumberOffset = pCertData->pCertHolderRef - pCertStart;
        pNewCertEntry->serialNumberLength = pCertData->certHolderRefLen;
        pNewCertEntry->index = indexInIdentity; /* link is identityPair */
        pNewCertEntry->link.pIdentityPair = pIdentity;

        if (OK > (status = HASH_TABLE_addPtr(pCertStore->pCertHashTable,
                                             hashValue,
                                             pNewCertEntry)))
        {
            goto exit;
        }
    }
    else if ( 0 == indexInIdentity && 0 != pPreviousCertEntry->index)
    {
        /* no duplicate entry allowed: issuer/serial number should be unique */
        /* BUT it's possible this was registered earlier without a key. So make
         sure to replace the link if the index of the found one is not 0 (has no key,
         either a trust point or a non leaf cert) and the index of the new one is
         0 (leaf cert) */

        pPreviousCertEntry->index = indexInIdentity;
        pPreviousCertEntry->link.pIdentityPair = pIdentity;
    }

exit:
    if (NULL != pCertData)
    {
        DIGI_FREE((void **)&pCertData);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_CV_CERT__ */
/*------------------------------------------------------------------*/

static MSTATUS
CERT_STORE_ptrMatchTest(void *pEntry, void *pEntryToDelete, intBoolean *pMatch)
{
    /* simple test */
    *pMatch = (pEntry == pEntryToDelete) ? TRUE : FALSE;

    return OK;
}

/*------------------------------------------------------------------*/

static MSTATUS
CERT_STORE_removeIdentityComponent(certStorePtr pCertStore,
                                   identityPair *pIdentity,
                                   sbyte4 indexInIdentity)
{
    MSTATUS status;
    issuerSerialPair isp;
    ASN1_ITEMPTR pIssuer, pSerialNumber;
    ASN1_ITEMPTR pRoot = 0;
    CStream cs;
    MemFile mf;
    ubyte *pCert;
    ubyte4 hashValue;
    intBoolean foundPreviousCertEntry;
    certificateEntry* pPreviousCertEntry;
    certificateEntry* pDelete = NULL;
    intBoolean deleteFound;

    pCert = pIdentity->certificates[indexInIdentity].data;

    MF_attach(&mf, pIdentity->certificates[indexInIdentity].length, pCert);
    CS_AttachMemFile(&cs, &mf);

    if (OK > ( status = X509_parseCertificate(cs, &pRoot)))
    {
        goto exit;
    }

    if (OK > (status = X509_getCertificateIssuerSerialNumber(ASN1_FIRST_CHILD(pRoot),
                                                             &pIssuer,
                                                             &pSerialNumber)))
    {
        goto exit;
    }

    isp.pIssuer = pCert + pIssuer->dataOffset;
    isp.issuerLength = pIssuer->length;
    isp.serialNumber = pCert + pSerialNumber->dataOffset;
    isp.serialNumberLength = pSerialNumber->length;

    /* calculate hash for serial number */
    HASH_VALUE_hashGen(isp.serialNumber, isp.serialNumberLength,
                       MOCANA_CERT_STORE_INIT_HASH_VALUE, &hashValue);

    /* find a possible cert entry with the same value already in the hash table */
    if (OK > (status = HASH_TABLE_findPtr(pCertStore->pCertHashTable,
                                          hashValue,
                                          (void *)&isp,
                                          CERT_STORE_testIssuerSerialNumber,
                                          (void **)&pPreviousCertEntry,
                                          &foundPreviousCertEntry)))
    {
        goto exit;

    }

    /* caller provided an identity but identity was not found */
    if ((TRUE != foundPreviousCertEntry) || (NULL == pPreviousCertEntry))
    {
        status = ERR_NOT_FOUND;
        goto exit;
    }

    /* Remove entry */
    if (OK > (status = HASH_TABLE_deletePtr(pCertStore->pCertHashTable,
                                            hashValue, pPreviousCertEntry,
                                            CERT_STORE_ptrMatchTest,
                                            (void **) &pDelete, &deleteFound)))
    {
        goto exit;
    }

exit:
    if (pRoot)
        TREE_DeleteTreeItem((TreeItem*)pRoot);

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
CERT_STORE_removeIdentityPairFromCertHashTable(certStorePtr pCertStore,
                                               identityPair *pIdentity)
{
    MSTATUS status = OK;
    sbyte4 i;

    for (i = 0; i < pIdentity->numCertificate; ++i)
    {
        if (OK > ( status = CERT_STORE_removeIdentityComponent(pCertStore,
                                                               pIdentity,
                                                               i)))
        {
            goto exit;
        }
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_CV_CERT__
static MSTATUS
CERT_STORE_CVC_addIdentityPairToCertHashTable(certStorePtr pCertStore,
                                          identityPair* pIdentity)
{
    MSTATUS status;
    sbyte4 i;

    for (i = 0; i < pIdentity->numCertificate; ++i)
    {
        if (OK > ( status = CERT_STORE_CVC_addIdentityComponent(pCertStore,
                                                                pIdentity,
                                                                i)))
        {
            return status;
        }
    }

    return OK;
}
#endif

static MSTATUS
CERT_STORE_addIdentityPairToCertHashTable(certStorePtr pCertStore,
                                          identityPair* pIdentity)
{
    MSTATUS status;
    sbyte4 i;

    for (i = 0; i < pIdentity->numCertificate; ++i)
    {
        if (OK > ( status = CERT_STORE_addIdentityComponent(pCertStore,
                                                            pIdentity,
                                                            i)))
        {
            return status;
        }
    }

    return OK;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CV_CERT__

static MSTATUS
CERT_STORE_CVC_addTrustPointToCertHashTable(certStorePtr pCertStore,
                                        CV_CERT *pCertData,
                                        trustPoint* pTrustPoint)
{
    issuerSerialPair isp;
    certificateEntry* pPreviousCertEntry;
    certificateEntry* pNewCertEntry = NULL;
    intBoolean foundPreviousCertEntry;
    ubyte4 hashValue;
    MSTATUS status;
    ubyte *pCertStart = pTrustPoint->pDerCert;

    isp.pIssuer = pCertData->pCertAuthRef;
    isp.issuerLength = pCertData->certAuthRefLen;
    isp.serialNumber = pCertData->pCertHolderRef;
    isp.serialNumberLength = pCertData->certHolderRefLen;

    /* calculate hash for serial number */
    HASH_VALUE_hashGen(isp.serialNumber, isp.serialNumberLength,
                       MOCANA_CERT_STORE_INIT_HASH_VALUE, &hashValue);

    /* find a possible cert entry with the same value already in the hash table */
    if (OK > (status = HASH_TABLE_findPtr(pCertStore->pCertHashTable,
                                          hashValue,
                                          (void *)&isp,
                                          CERT_STORE_testIssuerSerialNumber,
                                          (void **)&pPreviousCertEntry,
                                          &foundPreviousCertEntry)))
    {
        goto exit;

    }

    if ((!foundPreviousCertEntry) || (NULL == pPreviousCertEntry))
    {
        /* no previous one: store a new point*/
        /* allocate/init trust point structure */
        if (NULL == (pNewCertEntry = (certificateEntry*) MALLOC(sizeof(certificateEntry))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMSET((ubyte *)pNewCertEntry, 0x00, sizeof(certificateEntry));

        pNewCertEntry->issuerOffset = pCertData->pCertAuthRef - pCertStart;
        pNewCertEntry->issuerLength = pCertData->certAuthRefLen;
        pNewCertEntry->serialNumberOffset = pCertData->pCertHolderRef - pCertStart;
        pNewCertEntry->serialNumberLength = pCertData->certHolderRefLen;
        pNewCertEntry->index = -1; /* link is trustPoint */
        pNewCertEntry->link.pTrustPoint = pTrustPoint;

        if (OK > (status = HASH_TABLE_addPtr(pCertStore->pCertHashTable,
                                             hashValue,
                                             pNewCertEntry)))
        {
            goto exit;
        }
    }
    /* no duplicate entry allowed: issuer/serial number should be unique */

exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_CV_CERT__ */

static MSTATUS
CERT_STORE_addTrustPointToCertHashTable(certStorePtr pCertStore,
                                        ASN1_ITEMPTR pRootItem,
                                        trustPoint* pTrustPoint)
{
    ASN1_ITEMPTR pIssuer, pSerialNumber;
    issuerSerialPair isp;
    certificateEntry* pPreviousCertEntry;
    certificateEntry* pNewCertEntry = NULL;
    intBoolean foundPreviousCertEntry;
    ubyte4 hashValue;
    MSTATUS status;

    if (OK > (status = X509_getCertificateIssuerSerialNumber(ASN1_FIRST_CHILD(pRootItem),
                                                             &pIssuer,
                                                             &pSerialNumber)))
    {
        goto exit;
    }

    isp.pIssuer = pTrustPoint->pDerCert + pIssuer->dataOffset;
    isp.issuerLength = pIssuer->length;
    isp.serialNumber = pTrustPoint->pDerCert + pSerialNumber->dataOffset;
    isp.serialNumberLength = pSerialNumber->length;

    /* calculate hash for serial number */
    HASH_VALUE_hashGen(isp.serialNumber, isp.serialNumberLength,
                       MOCANA_CERT_STORE_INIT_HASH_VALUE, &hashValue);

    /* find a possible cert entry with the same value already in the hash table */
    if (OK > (status = HASH_TABLE_findPtr(pCertStore->pCertHashTable,
                                          hashValue,
                                          (void *)&isp,
                                          CERT_STORE_testIssuerSerialNumber,
                                          (void **)&pPreviousCertEntry,
                                          &foundPreviousCertEntry)))
    {
        goto exit;

    }

    if ((!foundPreviousCertEntry) || (NULL == pPreviousCertEntry))
    {
        /* no previous one: store a new point*/
        /* allocate/init trust point structure */
        if (NULL == (pNewCertEntry = (certificateEntry*) MALLOC(sizeof(certificateEntry))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMSET((ubyte *)pNewCertEntry, 0x00, sizeof(certificateEntry));

        pNewCertEntry->issuerOffset = pIssuer->dataOffset;
        pNewCertEntry->issuerLength = pIssuer->length;
        pNewCertEntry->serialNumberOffset = pSerialNumber->dataOffset;
        pNewCertEntry->serialNumberLength = pSerialNumber->length;
        pNewCertEntry->index = -1; /* link is trustPoint */
        pNewCertEntry->link.pTrustPoint = pTrustPoint;

        if (OK > (status = HASH_TABLE_addPtr(pCertStore->pCertHashTable,
                                             hashValue,
                                             pNewCertEntry)))
        {
            goto exit;
        }
    }
    /* no duplicate entry allowed: issuer/serial number should be unique */

exit:

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
CERT_STORE_verifyCertWithAsymmetricKey(identityPair *pIdentity,
                                       ubyte4 *pRetCertPubKeyType,
                                       intBoolean *pIsGood)
{
    hwAccelDescr    hwAccelCtx;
    ubyte*          pDerCert = NULL;
    ubyte4          derCertLength = 0;
    AsymmetricKey*  pKey;
    ASN1_ITEM*      pRoot = NULL;
    ASN1_ITEM*      pSignAlgoId = NULL;
    MemFile         certMemFile;
    CStream         cs;
    AsymmetricKey   certKey;
    vlong*          pN = NULL;
    /* Type variables will be CERT STORE algo bit field flags */
    ubyte4          pubKeyType = 0;
    ubyte4          hashType = 0;
    /* Id variables will be ca_mgmt style identifiers, we need some for both the sign algo and cert key */
    ubyte4          signAlgoKeyId = 0;
    ubyte4          signAlgoHashId = 0;
    ubyte4          signAlgoClAlgId = 0;
    ubyte4          signAlgoQsAlgId = 0;
    ubyte4          certCurveId = 0;
#ifdef __ENABLE_DIGICERT_PQC__
    ubyte4          certQsAlgId = 0;
#endif
    MSTATUS         status;
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    MRsaKeyTemplate template = { 0 };
#ifndef __ENABLE_DIGICERT_TAP__
    vlong *pPrime = NULL, *pSubprime = NULL, *pModulus = NULL;
#endif
    AsymmetricKey   temp = { 0 };
    void *pPubKey = NULL;
#endif
#if defined(__ENABLE_DIGICERT_DSA__) || !defined(__ENABLE_DIGICERT_TAP__)
    byteBoolean cmpRes;
#endif
    certChainPtr pCertChain = NULL;
    struct certDescriptor *pDescr = NULL;
    sbyte4 i = 0;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        goto exit;

    static WalkerStep signatureAlgoWalkInstructions[] =
    {
        { GoFirstChild, 0, 0},
        { GoNthChild, 2, 0},
        { VerifyType, SEQUENCE, 0 },
        { Complete, 0, 0}
    };

    if (pIdentity->numCertificate > 0)
    {
        pDerCert = pIdentity->certificates[0].data;
        derCertLength = pIdentity->certificates[0].length;
    }

    pKey = &pIdentity->identityKey;

    if ((NULL == pDerCert) || (NULL == pIsGood))
        return ERR_NULL_POINTER;

    if (OK > (status = CRYPTO_initAsymmetricKey(&certKey)))
        goto exit;

    *pIsGood = FALSE;

    /* extract the public key of the certificate */
    if (0 == derCertLength)
    {
        status = ERR_CERT_AUTH_BAD_CERT_LENGTH;
        goto exit;
    }

    /* Validate the certificates form a valid chain via CERTCHAIN_createFromIKE, need to create certDescriptor array */
    status = DIGI_CALLOC((void **) &pDescr, pIdentity->numCertificate, sizeof(certDescriptor));
    if (OK != status)
      goto exit;

    /* copy each cert into a pDescr instance */
    for(i = 0; i < pIdentity->numCertificate; ++i)
    {
        status = DIGI_MALLOC((void **) &pDescr[i].pCertificate, pIdentity->certificates[i].length);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pDescr[i].pCertificate, pIdentity->certificates[i].data, pIdentity->certificates[i].length);
        if (OK != status)
            goto exit;

        pDescr[i].certLength = pIdentity->certificates[i].length;
    }

    status = CERTCHAIN_createFromIKE(MOC_ASYM(hwAccelCtx) &pCertChain, pDescr, (ubyte4) pIdentity->numCertificate);
    if (OK != status)
      goto exit;

    MF_attach(&certMemFile, derCertLength, (ubyte *)pDerCert);
    CS_AttachMemFile(&cs, &certMemFile);

    /* parse the certificate */
    if (OK > (status = X509_parseCertificate( cs, &pRoot)))
        goto exit;

    status = X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(hwAccelCtx)
                                                 ASN1_FIRST_CHILD(pRoot), cs,
                                                 &certKey);


    if (OK > status)
      goto exit;

    /* If the private key is MocAsym, get the public key out of it.
     * Currently, the only MocAsym keys we will support have a 0x020000 in the
     * type (drawn from the blob). In the future, there might be larger numbers
     * in that position. But 0x010000 means TPM 1.2 key.
     */
    if (0x010000 < (pKey->type & 0xff0000))
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        /* Extract the public key using the Crypto Interface.
         */
        switch (pKey->type)
        {
#ifndef __DISABLE_DIGICERT_RSA__
            case akt_tap_rsa:
                status = CRYPTO_INTERFACE_getRSAPublicKey(
                    pKey, (RSAKey **) &pPubKey);
                break;
#endif
#if (defined(__ENABLE_DIGICERT_ECC__))
            case akt_tap_ecc:
                status = CRYPTO_INTERFACE_getECCPublicKey(
                    pKey, (ECCKey **) &pPubKey);
                break;
#endif

            default:
                status = ERR_CERT_AUTH_MISMATCH_PUBLIC_KEYS;
                goto exit;
        }
        if (OK != status)
            goto exit;

        /* Store the key into the AsymmetricKey
         */
        temp.type = pKey->type;
        temp.key.pMocAsymKey = pPubKey;

        status = ERR_CERT_AUTH_MISMATCH_PUBLIC_KEYS;
        if (certKey.type != (temp.type & 0xff))
            goto exit;

        pKey = &temp;
        status = OK;
#else
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
#endif
    }
    else if ((akt_undefined != pKey->type) && (certKey.type != pKey->type))
    {
            status = ERR_CERT_AUTH_MISMATCH_PUBLIC_KEYS;
            goto exit;
    }

    if ( (akt_rsa == certKey.type) &&
        (ALG_ID_RSA_SSA_PSS_OID == certKey.pAlgoId->oidFlag) )
    {
        *pRetCertPubKeyType = akt_rsa_pss;
    }
    else
    {
        *pRetCertPubKeyType = certKey.type;
    }


    if ( OK > ASN1_WalkTree( pRoot, cs, signatureAlgoWalkInstructions, &pSignAlgoId))
    {
      status = ERR_CERT_INVALID_STRUCT;
      goto exit;
    }

    /* reminder for ECDSA-with SHA, sign algo we don't know the curve and signAlgoClAlgId stays zero */
    status = X509_getCertSignAlgoTypeEx( pSignAlgoId, cs, &signAlgoHashId, &signAlgoKeyId, &signAlgoClAlgId, &signAlgoQsAlgId);
    if (OK > status)
    {
        status = ERR_CERT_STORE_UNSUPPORTED_SIGNALGO;
        goto exit;
    }

    if (rsaSsaPss == signAlgoHashId && akt_rsa == signAlgoKeyId)
    {
        signAlgoHashId = ht_none;
        signAlgoKeyId = akt_rsa_pss;
    }

    switch (signAlgoHashId)
    {
    case ht_md5:
        hashType = CERT_STORE_ALGO_FLAG_MD5;
        break;

    case ht_sha1:
        hashType = CERT_STORE_ALGO_FLAG_SHA1;
        break;

#ifndef __DISABLE_DIGICERT_SHA224__
    case ht_sha224:
        hashType = CERT_STORE_ALGO_FLAG_SHA224;
        break;
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
    case ht_sha256:
        hashType = CERT_STORE_ALGO_FLAG_SHA256;
        break;
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
    case ht_sha384:
        hashType = CERT_STORE_ALGO_FLAG_SHA384;
        break;
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
    case ht_sha512:
        hashType = CERT_STORE_ALGO_FLAG_SHA512;
        break;
#endif
#ifdef __ENABLE_DIGICERT_PKCS1__
    case rsaSsaPss:
        hashType = CERT_STORE_ALGO_FLAG_INTRINSIC;
        break;
#endif /* __ENABLE_DIGICERT_PKCS1__ */
#if defined(__ENABLE_DIGICERT_PKCS1__) || defined(__ENABLE_DIGICERT_ECC_EDDSA__)
    case ht_none:
        hashType = CERT_STORE_ALGO_FLAG_INTRINSIC;
        break;
#endif
    default:
        status = ERR_CERT_STORE_UNSUPPORTED_SIGNALGO;
        goto exit;
    }

    switch (signAlgoKeyId & 0xff)
    {
    case akt_rsa:
#if defined(__ENABLE_DIGICERT_PKCS1__)
    case akt_rsa_pss:
#endif
        pubKeyType = CERT_STORE_ALGO_FLAG_RSA;
        break;
#if defined(__ENABLE_DIGICERT_DSA__)
    case akt_dsa:
        pubKeyType = CERT_STORE_ALGO_FLAG_DSA;
        break;
#endif
#if (defined(__ENABLE_DIGICERT_ECC__))
    case akt_ecc:
        pubKeyType = CERT_STORE_ALGO_FLAG_ECDSA;
        break;
#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
    case akt_ecc_ed:
        if (cid_EC_Ed25519 == signAlgoClAlgId)
        {
            pubKeyType = CERT_STORE_ALGO_FLAG_EDDSA_25519;
        }
        else if (cid_EC_Ed448 == signAlgoClAlgId)
        {
            pubKeyType = CERT_STORE_ALGO_FLAG_EDDSA_448;
        }
        else
        {
            status = ERR_CERT_STORE_UNSUPPORTED_SIGNALGO;
        }
        break;
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    case akt_hybrid:
	        pubKeyType = CERT_STORE_ALGO_FLAG_HYBRID;
        break;
#endif
#endif /* __ENABLE_DIGICERT_ECC__ */
#ifdef __ENABLE_DIGICERT_PQC__
    case akt_qs:
	        pubKeyType = CERT_STORE_ALGO_FLAG_QS;
        break;
#endif
    default:
        status = ERR_CERT_STORE_UNSUPPORTED_SIGNALGO;
        goto exit;
    }

    /* we set both certAlgoFlags for legacy API purposes and set signAlgoId */
    pIdentity->certAlgoFlags = hashType | pubKeyType;

    /* call to X509_getCertSignAlgoTypeEx will zero non-applicable id's, so ok to xor everything */
    pIdentity->signAlgoId = 0;
    CERT_STORE_ALGO_ID_SET_KEYTYPE(pIdentity->signAlgoId, signAlgoKeyId);
    CERT_STORE_ALGO_ID_SET_HASH(pIdentity->signAlgoId, signAlgoHashId);
    CERT_STORE_ALGO_ID_SET_CURVE(pIdentity->signAlgoId, signAlgoClAlgId);
#ifdef __ENABLE_DIGICERT_PQC__
    CERT_STORE_ALGO_ID_SET_QSALG(pIdentity->signAlgoId, signAlgoQsAlgId);
#endif

    /* Also we'll be setting the certAlgoId */
    pIdentity->certAlgoId = 0;
    CERT_STORE_ALGO_ID_SET_KEYTYPE(pIdentity->certAlgoId, (certKey.type));

    switch (certKey.type)
    {
#if defined(__ENABLE_DIGICERT_DSA__)
        case akt_dsa:
        {
            if (akt_undefined != pKey->type)
            {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                status = CRYPTO_INTERFACE_DSA_equalKey (MOC_DSA(hwAccelCtx)
                    (const DSAKey *)certKey.key.pDSA,
                    (const DSAKey *)pKey->key.pDSA, &cmpRes);
#else
                status = DSA_equalKey (MOC_DSA(hwAccelCtx)
                    (const DSAKey *)certKey.key.pDSA,
                    (const DSAKey *)pKey->key.pDSA, &cmpRes);
#endif
                if ( (OK != status) || (TRUE != cmpRes) )
                {
                    status = ERR_CERT_AUTH_MISMATCH_PUBLIC_KEYS;
                    goto exit;
                }
            }

            pIdentity->certAlgoFlags &= ~(CERT_STORE_ALGO_FLAG_ECCURVES);
            *pIsGood = TRUE;
            break;
	    }
#endif
        case akt_rsa:
        {
#ifndef __DISABLE_DIGICERT_RSA__
#ifndef __ENABLE_DIGICERT_TAP__
            if (akt_undefined != pKey->type)
            {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                status = CRYPTO_INTERFACE_RSA_equalKey(MOC_RSA(hwAccelCtx)
                    certKey.key.pRSA, pKey->key.pRSA, &cmpRes);
                if ( (OK != status) || (TRUE != cmpRes) )
                {
                    status = ERR_CERT_AUTH_MISMATCH_PUBLIC_KEYS;
                    goto exit;
                }
#else
                /* verify key blob and certificate public keys match */
                if ((0 != VLONG_compareSignedVlongs(RSA_N(certKey.key.pRSA), RSA_N(pKey->key.pRSA))) ||
                    (0 != VLONG_compareSignedVlongs(RSA_E(certKey.key.pRSA), RSA_E(pKey->key.pRSA))) )
                {
                    status = ERR_CERT_AUTH_MISMATCH_PUBLIC_KEYS;
                    goto exit;
                }
#endif

                /* If the type includes bits in the 0xff0000 position, then we
                 * can't run all tests. If not, go ahead and run these next tests.
                 */
                if (0 == (pKey->type & 0xff0000))
                {
                /* verify key blob private key matches public key */
#if (defined(__ENABLE_DIGICERT_HW_SECURITY_MODULE__) && defined(__ENABLE_DIGICERT_TPM__))
                if (NULL == pKey->key.pRSA->hsmInfo)
                {
#endif
                    if (OK > (status = VLONG_allocVlong(&pN, NULL)))
                        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                    status = CRYPTO_INTERFACE_RSA_getKeyParametersAlloc(MOC_RSA(hwAccelCtx)
                        pKey->key.pRSA, &template, MOC_GET_PRIVATE_KEY_DATA,
                        pKey->type);
                    if (OK != status)
                        goto exit;

                    status = VLONG_vlongFromByteString(
                        template.pN, template.nLen, &pModulus, NULL);
                    if (OK != status)
                        goto exit;

                    status = VLONG_vlongFromByteString(
                        template.pP, template.pLen, &pPrime, NULL);
                    if (OK != status)
                        goto exit;

                    status = VLONG_vlongFromByteString(
                        template.pQ, template.qLen, &pSubprime, NULL);
                    if (OK != status)
                        goto exit;

                    if (OK > (status = VLONG_vlongSignedMultiply(pN, pPrime, pSubprime)))
                        goto exit;

                    if (0 != VLONG_compareSignedVlongs(pN, pModulus))
                    {
                        status = ERR_CERT_AUTH_KEY_BLOB_CORRUPT;
                        goto exit;
                    }
#else
                    if (OK > (status = VLONG_vlongSignedMultiply(pN, RSA_P(pKey->key.pRSA), RSA_Q(pKey->key.pRSA))))
                        goto exit;

                    if (0 != VLONG_compareSignedVlongs(pN, RSA_N(pKey->key.pRSA)))
                    {
                        status = ERR_CERT_AUTH_KEY_BLOB_CORRUPT;
                        goto exit;
                    }
#endif
#if (defined(__ENABLE_DIGICERT_HW_SECURITY_MODULE__) && defined(__ENABLE_DIGICERT_TPM__))
                }
#endif
                }
            }
#endif

            pIdentity->certAlgoFlags &= ~(CERT_STORE_ALGO_FLAG_ECCURVES);

            *pIsGood = TRUE;

            break;
#else
            status = ERR_RSA_DISABLED;
            goto exit;
#endif /* __DISABLE_DIGICERT_RSA__ */
        }
#if (defined(__ENABLE_DIGICERT_ECC__))
        case akt_ecc:
        case akt_ecc_ed:
        {
          /* If the type includes bits in the 0xff0000 position, then we
           * can't run all tests. If not, go ahead and run these next tests.
           */
            if (0 == (pKey->type & 0xff0000))
            {
                if (akt_undefined != pKey->type)
                {
                    status = CRYPTO_matchPublicKey(pKey, &certKey);
                    if (OK != status)
                        goto exit;
                }
            }

            /* Now get the curveId for the certificate key */
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
            status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(certKey.key.pECC, &certCurveId);
#else
            status = EC_getCurveIdFromKey(certKey.key.pECC, &certCurveId);
#endif
            if (OK > status)
                goto exit;

            CERT_STORE_ALGO_ID_SET_CURVE(pIdentity->certAlgoId, certCurveId);

            if (akt_ecc == certKey.type)
            {
                /* record the ec Curve of the cert */
#ifdef __ENABLE_DIGICERT_ECC_P192__
                if (cid_EC_P192 == certCurveId)
                {
                    pIdentity->certAlgoFlags |= CERT_STORE_ALGO_FLAG_EC192;
                } else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
                if (cid_EC_P224 == certCurveId)
                {
                    pIdentity->certAlgoFlags |= CERT_STORE_ALGO_FLAG_EC224;
                } else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
                if (cid_EC_P256 == certCurveId)
                {
                    pIdentity->certAlgoFlags |= CERT_STORE_ALGO_FLAG_EC256;
                } else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
                if (cid_EC_P384 == certCurveId)
                {
                    pIdentity->certAlgoFlags |= CERT_STORE_ALGO_FLAG_EC384;
                } else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
                if (cid_EC_P521 == certCurveId)
                {
                    pIdentity->certAlgoFlags |= CERT_STORE_ALGO_FLAG_EC521;
                } else
#endif
                {
                    status = ERR_CERT_STORE_UNSUPPORTED_ECCURVE;
                    goto exit;
                }
            }
            else if( akt_ecc_ed == certKey.type)
            {
                if (cid_EC_Ed25519 == certCurveId)
                {
                    pIdentity->certAlgoFlags |= CERT_STORE_ALGO_FLAG_EC25519;
                }
                else if (cid_EC_Ed448 == certCurveId)
                {
                    pIdentity->certAlgoFlags |= CERT_STORE_ALGO_FLAG_EC448;

                }
            }

            *pIsGood = TRUE;
            break;
        }
#ifdef __ENABLE_DIGICERT_PQC__
        case akt_hybrid:
        {
            /* validate the public keys match */
            status = CRYPTO_matchPublicKey(pKey, &certKey);
            if (OK != status)
                goto exit;

            status = CRYPTO_INTERFACE_QS_getAlg(certKey.pQsCtx, &certQsAlgId);
            if(OK != status)
                goto exit;

            /* pIdentity->certAlgoFlags will just indicate the hybrid type and nothing else.
               We already had the hash portion 0x00, make sure the curve portion is 0x00 */
            pIdentity->certAlgoFlags &= ~(CERT_STORE_ALGO_FLAG_ECCURVES);

            /* certAlgoId is what will actually contain the qsAlg and curve   */
            CERT_STORE_ALGO_ID_SET_CLALG(pIdentity->certAlgoId, certKey.clAlg);
            CERT_STORE_ALGO_ID_SET_QSALG(pIdentity->certAlgoId, certQsAlgId);
            *pIsGood = TRUE;
            break;
	    }
#endif /* __ENABLE_DIGICERT_PQC__ */
#endif /* __ENABLE_DIGICERT_ECC__ */
#ifdef __ENABLE_DIGICERT_PQC__
        case akt_qs:
        {
            /* validate the public keys match */
            status = CRYPTO_matchPublicKey(pKey, &certKey);
            if (OK != status)
                goto exit;

            status = CRYPTO_INTERFACE_QS_getAlg(certKey.pQsCtx, &certQsAlgId);
            if(OK != status)
                goto exit;

            /* pIdentity->certAlgoFlags will just indicate the qs type and nothing else.
               We already had the hash portion 0x00, make sure the curve portion is 0x00 */
            pIdentity->certAlgoFlags &= ~(CERT_STORE_ALGO_FLAG_ECCURVES);

            /* certAlgoId is what will actually contain the qsAlg  */
            CERT_STORE_ALGO_ID_SET_QSALG(pIdentity->certAlgoId, certQsAlgId);
            *pIsGood = TRUE;
            break;
	    }
#endif /* __ENABLE_DIGICERT_PQC__ */
        default:
        {
            status = ERR_CERT_AUTH_MISMATCH_PUBLIC_KEYS;
            goto exit;
        }

    } /* switch */

    /* now set the key usage */
    if (OK > (status = X509_getCertificateKeyUsageValue(ASN1_FIRST_CHILD(pRoot),
                                                         cs,
                                                        &pIdentity->certKeyUsage)))
    {
        goto exit;
    }

exit:

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    if(NULL != pDescr)
    {
        for(i = 0; i < pIdentity->numCertificate; ++i)
        {
            (void) CA_MGMT_freeCertificate(&pDescr[i]);
        }

        (void) DIGI_FREE((void **) &pDescr);
    }

    if (NULL != pCertChain)
    {
        (void) CERTCHAIN_delete(&pCertChain);
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#ifndef __ENABLE_DIGICERT_TAP__
    if (NULL != pModulus)
        VLONG_freeVlong(&pModulus, NULL);

    if (NULL != pPrime)
        VLONG_freeVlong(&pPrime, NULL);

    if (NULL != pSubprime)
        VLONG_freeVlong(&pSubprime, NULL);
#endif

    if ( (NULL != pKey) && (NULL != pPubKey) )
    {
        pKey->type = pKey->type & 0xffff;
        CRYPTO_uninitAsymmetricKey(pKey, NULL);
    }
#ifndef __DISABLE_DIGICERT_RSA__
    if (NULL != pKey)
    {
        if (akt_rsa == pKey->type)
        {
            CRYPTO_INTERFACE_RSA_freeKeyTemplate(
                pKey->key.pRSA, &template, pKey->type);
        }
    }
#endif
#endif

    if (pRoot)
        TREE_DeleteTreeItem((TreeItem*)pRoot);

    VLONG_freeVlong(&pN, NULL);
    CRYPTO_uninitAsymmetricKey(&certKey, NULL);

    return status;
}


#ifdef __ENABLE_DIGICERT_CV_CERT__
static MSTATUS
CERT_STORE_CVC_verifyCertWithAsymmetricKey(identityPair *pIdentity,
                                       ubyte4 *pRetCertPubKeyType,
                                       intBoolean *pIsGood)
{
    hwAccelDescr    hwAccelCtx;
    ubyte*          pDerCert = NULL;
    ubyte4          derCertLength = 0;
    AsymmetricKey*  pKey;
    AsymmetricKey   certKey;
    vlong*          pN = NULL;
    /* Type variables will be CERT STORE algo bit field flags */
    ubyte4          pubKeyType = 0;
    ubyte4          hashType = 0;
    /* Id variables will be ca_mgmt style identifiers, we need some for both the sign algo and cert key */
    ubyte4          signAlgoKeyId = 0;
    ubyte4          signAlgoHashId = 0;
    ubyte4          signAlgoClAlgId = 0;
    ubyte4          certCurveId = 0;
    MSTATUS         status;
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    MRsaKeyTemplate template = { 0 };
#ifndef __ENABLE_DIGICERT_TAP__
    vlong *pPrime = NULL, *pSubprime = NULL, *pModulus = NULL;
#endif
    AsymmetricKey   temp = { 0 };
    void *pPubKey = NULL;
#endif
#if defined(__ENABLE_DIGICERT_DSA__) || !defined(__ENABLE_DIGICERT_TAP__)
    byteBoolean cmpRes;
#endif
    certChainPtr pCertChain = NULL;
    struct certDescriptor *pDescr = NULL;
    sbyte4 i = 0;
    CV_CERT *pCertData = NULL;
    byteBoolean isPss = FALSE;
    ubyte2 keyUsage = 0;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        goto exit;


    if (pIdentity->numCertificate > 0)
    {
        pDerCert = pIdentity->certificates[0].data;
        derCertLength = pIdentity->certificates[0].length;
    }

    pKey = &pIdentity->identityKey;

    if ((NULL == pDerCert) || (NULL == pIsGood))
        return ERR_NULL_POINTER;

    if (OK > (status = CRYPTO_initAsymmetricKey(&certKey)))
        goto exit;

    *pIsGood = FALSE;

    /* extract the public key of the certificate */
    if (0 == derCertLength)
    {
        status = ERR_CERT_AUTH_BAD_CERT_LENGTH;
        goto exit;
    }

    /* Validate the certificates form a valid chain via CERTCHAIN_createFromCVC, need to create certDescriptor array */
    status = DIGI_CALLOC((void **) &pDescr, pIdentity->numCertificate, sizeof(certDescriptor));
    if (OK != status)
      goto exit;

    /* copy each cert into a pDescr instance */
    for(i = 0; i < pIdentity->numCertificate; ++i)
    {
        status = DIGI_MALLOC((void **) &pDescr[i].pCertificate, pIdentity->certificates[i].length);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pDescr[i].pCertificate, pIdentity->certificates[i].data, pIdentity->certificates[i].length);
        if (OK != status)
            goto exit;

        pDescr[i].certLength = pIdentity->certificates[i].length;
    }

    status = CERTCHAIN_createFromCVC(MOC_ASYM(hwAccelCtx) &pCertChain, pDescr, (ubyte4) pIdentity->numCertificate);
    if (OK != status)
      goto exit;

    /* parse the certificate */
    status = CV_CERT_parseCert (
        pIdentity->certificates[0].data, pIdentity->certificates[0].length, &pCertData);
    if (OK != status)
        goto exit;

    /* Get the key */
    status = CV_CERT_parseKey (MOC_ASYM(hwAccelCtx)
        pCertData->pCvcKey, pCertData->cvcKeyLen, &certKey, &signAlgoHashId, &isPss);
    if (OK != status)
        goto exit;

    /* If the private key is MocAsym, get the public key out of it.
     * Currently, the only MocAsym keys we will support have a 0x020000 in the
     * type (drawn from the blob). In the future, there might be larger numbers
     * in that position. But 0x010000 means TPM 1.2 key.
     */
    if (0x010000 < (pKey->type & 0xff0000))
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        /* Extract the public key using the Crypto Interface.
         */
        switch (pKey->type)
        {
#ifndef __DISABLE_DIGICERT_RSA__
            case akt_tap_rsa:
                status = CRYPTO_INTERFACE_getRSAPublicKey(
                    pKey, (RSAKey **) &pPubKey);
                break;
#endif
#if (defined(__ENABLE_DIGICERT_ECC__))
            case akt_tap_ecc:
                status = CRYPTO_INTERFACE_getECCPublicKey(
                    pKey, (ECCKey **) &pPubKey);
                break;
#endif

            default:
                status = ERR_CERT_AUTH_MISMATCH_PUBLIC_KEYS;
                goto exit;
        }
        if (OK != status)
            goto exit;

        /* Store the key into the AsymmetricKey
         */
        temp.type = pKey->type;
        temp.key.pMocAsymKey = pPubKey;

        status = ERR_CERT_AUTH_MISMATCH_PUBLIC_KEYS;
        if (certKey.type != (temp.type & 0xff))
            goto exit;

        pKey = &temp;
        status = OK;
#else
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
#endif
    }
    else if ((akt_undefined != pKey->type) && (certKey.type != pKey->type))
    {
            status = ERR_CERT_AUTH_MISMATCH_PUBLIC_KEYS;
            goto exit;
    }

    if (TRUE == isPss)
    {
        *pRetCertPubKeyType = akt_rsa_pss;
        signAlgoKeyId = akt_rsa_pss;
        signAlgoHashId = ht_none;
    }
    else
    {
        *pRetCertPubKeyType = certKey.type;
        signAlgoKeyId = certKey.type;
    }

    switch (signAlgoHashId)
    {
    case ht_md5:
        hashType = CERT_STORE_ALGO_FLAG_MD5;
        break;

    case ht_sha1:
        hashType = CERT_STORE_ALGO_FLAG_SHA1;
        break;

#ifndef __DISABLE_DIGICERT_SHA224__
    case ht_sha224:
        hashType = CERT_STORE_ALGO_FLAG_SHA224;
        break;
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
    case ht_sha256:
        hashType = CERT_STORE_ALGO_FLAG_SHA256;
        break;
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
    case ht_sha384:
        hashType = CERT_STORE_ALGO_FLAG_SHA384;
        break;
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
    case ht_sha512:
        hashType = CERT_STORE_ALGO_FLAG_SHA512;
        break;
#endif
#ifdef __ENABLE_DIGICERT_PKCS1__
    case rsaSsaPss:
        hashType = CERT_STORE_ALGO_FLAG_INTRINSIC;
        break;
#endif /* __ENABLE_DIGICERT_PKCS1__ */
#if defined(__ENABLE_DIGICERT_PKCS1__) || defined(__ENABLE_DIGICERT_ECC_EDDSA__)
    case ht_none:
        hashType = CERT_STORE_ALGO_FLAG_INTRINSIC;
        break;
#endif
    default:
        status = ERR_CERT_STORE_UNSUPPORTED_SIGNALGO;
        goto exit;
    }

    switch (signAlgoKeyId & 0xff)
    {
    case akt_rsa:
#if defined(__ENABLE_DIGICERT_PKCS1__)
    case akt_rsa_pss:
#endif
        pubKeyType = CERT_STORE_ALGO_FLAG_RSA;
        break;
#if defined(__ENABLE_DIGICERT_DSA__)
    case akt_dsa:
        pubKeyType = CERT_STORE_ALGO_FLAG_DSA;
        break;
#endif
#if (defined(__ENABLE_DIGICERT_ECC__))
    case akt_ecc:
        pubKeyType = CERT_STORE_ALGO_FLAG_ECDSA;
        break;
#endif /* __ENABLE_DIGICERT_ECC__ */
    default:
        status = ERR_CERT_STORE_UNSUPPORTED_SIGNALGO;
        goto exit;
    }

    /* we set both certAlgoFlags for legacy API purposes and set signAlgoId */
    pIdentity->certAlgoFlags = hashType | pubKeyType;

    /* call to CV_CERT_getCertSignAlgoTypeEx will zero non-applicable id's, so ok to xor everything */
    pIdentity->signAlgoId = 0;
    CERT_STORE_ALGO_ID_SET_KEYTYPE(pIdentity->signAlgoId, signAlgoKeyId);
    CERT_STORE_ALGO_ID_SET_HASH(pIdentity->signAlgoId, signAlgoHashId);
    CERT_STORE_ALGO_ID_SET_CURVE(pIdentity->signAlgoId, signAlgoClAlgId);

    /* Also we'll be setting the certAlgoId */
    pIdentity->certAlgoId = 0;
    CERT_STORE_ALGO_ID_SET_KEYTYPE(pIdentity->certAlgoId, (certKey.type));

    switch (certKey.type)
    {
#if defined(__ENABLE_DIGICERT_DSA__)
        case akt_dsa:
        {
            if (akt_undefined != pKey->type)
            {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                status = CRYPTO_INTERFACE_DSA_equalKey (MOC_DSA(hwAccelCtx)
                    (const DSAKey *)certKey.key.pDSA,
                    (const DSAKey *)pKey->key.pDSA, &cmpRes);
#else
                status = DSA_equalKey (MOC_DSA(hwAccelCtx)
                    (const DSAKey *)certKey.key.pDSA,
                    (const DSAKey *)pKey->key.pDSA, &cmpRes);
#endif
                if ( (OK != status) || (TRUE != cmpRes) )
                {
                    status = ERR_CERT_AUTH_MISMATCH_PUBLIC_KEYS;
                    goto exit;
                }
            }

            pIdentity->certAlgoFlags &= ~(CERT_STORE_ALGO_FLAG_ECCURVES);
            *pIsGood = TRUE;
            break;
	    }
#endif
        case akt_rsa:
        {
#ifndef __DISABLE_DIGICERT_RSA__
            /* For RSA, default key usage to signature and key encipherment */
            keyUsage = (1 << digitalSignature | 1 << keyEncipherment);
#ifndef __ENABLE_DIGICERT_TAP__
            if (akt_undefined != pKey->type)
            {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                status = CRYPTO_INTERFACE_RSA_equalKey(MOC_RSA(hwAccelCtx)
                    certKey.key.pRSA, pKey->key.pRSA, &cmpRes);
                if ( (OK != status) || (TRUE != cmpRes) )
                {
                    status = ERR_CERT_AUTH_MISMATCH_PUBLIC_KEYS;
                    goto exit;
                }
#else
                /* verify key blob and certificate public keys match */
                if ((0 != VLONG_compareSignedVlongs(RSA_N(certKey.key.pRSA), RSA_N(pKey->key.pRSA))) ||
                    (0 != VLONG_compareSignedVlongs(RSA_E(certKey.key.pRSA), RSA_E(pKey->key.pRSA))) )
                {
                    status = ERR_CERT_AUTH_MISMATCH_PUBLIC_KEYS;
                    goto exit;
                }
#endif

                /* If the type includes bits in the 0xff0000 position, then we
                 * can't run all tests. If not, go ahead and run these next tests.
                 */
                if (0 == (pKey->type & 0xff0000))
                {
                /* verify key blob private key matches public key */
#if (defined(__ENABLE_DIGICERT_HW_SECURITY_MODULE__) && defined(__ENABLE_DIGICERT_TPM__))
                if (NULL == pKey->key.pRSA->hsmInfo)
                {
#endif
                    if (OK > (status = VLONG_allocVlong(&pN, NULL)))
                        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                    status = CRYPTO_INTERFACE_RSA_getKeyParametersAlloc(MOC_RSA(hwAccelCtx)
                        pKey->key.pRSA, &template, MOC_GET_PRIVATE_KEY_DATA,
                        pKey->type);
                    if (OK != status)
                        goto exit;

                    status = VLONG_vlongFromByteString(
                        template.pN, template.nLen, &pModulus, NULL);
                    if (OK != status)
                        goto exit;

                    status = VLONG_vlongFromByteString(
                        template.pP, template.pLen, &pPrime, NULL);
                    if (OK != status)
                        goto exit;

                    status = VLONG_vlongFromByteString(
                        template.pQ, template.qLen, &pSubprime, NULL);
                    if (OK != status)
                        goto exit;

                    if (OK > (status = VLONG_vlongSignedMultiply(pN, pPrime, pSubprime)))
                        goto exit;

                    if (0 != VLONG_compareSignedVlongs(pN, pModulus))
                    {
                        status = ERR_CERT_AUTH_KEY_BLOB_CORRUPT;
                        goto exit;
                    }
#else
                    if (OK > (status = VLONG_vlongSignedMultiply(pN, RSA_P(pKey->key.pRSA), RSA_Q(pKey->key.pRSA))))
                        goto exit;

                    if (0 != VLONG_compareSignedVlongs(pN, RSA_N(pKey->key.pRSA)))
                    {
                        status = ERR_CERT_AUTH_KEY_BLOB_CORRUPT;
                        goto exit;
                    }
#endif
#if (defined(__ENABLE_DIGICERT_HW_SECURITY_MODULE__) && defined(__ENABLE_DIGICERT_TPM__))
                }
#endif
                }
            }
#endif

            pIdentity->certAlgoFlags &= ~(CERT_STORE_ALGO_FLAG_ECCURVES);

            *pIsGood = TRUE;

            break;
#else
            status = ERR_RSA_DISABLED;
            goto exit;
#endif /* __DISABLE_DIGICERT_RSA__ */
        }
#if (defined(__ENABLE_DIGICERT_ECC__))
        case akt_ecc:
        {
            /* For ECC, default key usage to signature and key encipherment */
            keyUsage = (1 << digitalSignature | 1 << keyAgreement);

            /* If the type includes bits in the 0xff0000 position, then we
             * can't run all tests. If not, go ahead and run these next tests.
             */
            if (0 == (pKey->type & 0xff0000))
            {
                if (akt_undefined != pKey->type)
                {
                    status = CRYPTO_matchPublicKey(pKey, &certKey);
                    if (OK != status)
                        goto exit;
                }
            }

            /* Now get the curveId for the certificate key */
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
            status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(certKey.key.pECC, &certCurveId);
#else
            status = EC_getCurveIdFromKey(certKey.key.pECC, &certCurveId);
#endif
            if (OK > status)
                goto exit;

            CERT_STORE_ALGO_ID_SET_CURVE(pIdentity->certAlgoId, certCurveId);

            if (akt_ecc == certKey.type)
            {
                /* record the ec Curve of the cert */
#ifdef __ENABLE_DIGICERT_ECC_P192__
                if (cid_EC_P192 == certCurveId)
                {
                    pIdentity->certAlgoFlags |= CERT_STORE_ALGO_FLAG_EC192;
                } else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
                if (cid_EC_P224 == certCurveId)
                {
                    pIdentity->certAlgoFlags |= CERT_STORE_ALGO_FLAG_EC224;
                } else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
                if (cid_EC_P256 == certCurveId)
                {
                    pIdentity->certAlgoFlags |= CERT_STORE_ALGO_FLAG_EC256;
                } else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
                if (cid_EC_P384 == certCurveId)
                {
                    pIdentity->certAlgoFlags |= CERT_STORE_ALGO_FLAG_EC384;
                } else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
                if (cid_EC_P521 == certCurveId)
                {
                    pIdentity->certAlgoFlags |= CERT_STORE_ALGO_FLAG_EC521;
                } else
#endif
                {
                    status = ERR_CERT_STORE_UNSUPPORTED_ECCURVE;
                    goto exit;
                }
            }

            *pIsGood = TRUE;
            break;
        }
#endif /* __ENABLE_DIGICERT_ECC__ */
        default:
        {
            status = ERR_CERT_AUTH_MISMATCH_PUBLIC_KEYS;
            goto exit;
        }

    } /* switch */

    /* Set the per algorithm default key usage */
    pIdentity->certKeyUsage = keyUsage;

exit:

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    if(NULL != pDescr)
    {
        for(i = 0; i < pIdentity->numCertificate; ++i)
        {
            (void) CA_MGMT_freeCertificate(&pDescr[i]);
        }

        (void) DIGI_FREE((void **) &pDescr);
    }

    if (NULL != pCertChain)
    {
        (void) CERTCHAIN_delete(&pCertChain);
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#ifndef __ENABLE_DIGICERT_TAP__
    if (NULL != pModulus)
        VLONG_freeVlong(&pModulus, NULL);

    if (NULL != pPrime)
        VLONG_freeVlong(&pPrime, NULL);

    if (NULL != pSubprime)
        VLONG_freeVlong(&pSubprime, NULL);
#endif

    if ( (NULL != pKey) && (NULL != pPubKey) )
    {
        pKey->type = pKey->type & 0xffff;
        CRYPTO_uninitAsymmetricKey(pKey, NULL);
    }
#ifndef __DISABLE_DIGICERT_RSA__
    if (NULL != pKey)
    {
        if (akt_rsa == pKey->type)
        {
            CRYPTO_INTERFACE_RSA_freeKeyTemplate(
                pKey->key.pRSA, &template, pKey->type);
        }
    }
#endif
#endif

    if (NULL != pCertData)
    {
        DIGI_FREE((void **)&pCertData);
    }

    VLONG_freeVlong(&pN, NULL);
    CRYPTO_uninitAsymmetricKey(&certKey, NULL);

    return status;
}
#endif /* __ENABLE_DIGICERT_CV_CERT__ */
#endif


/*------------------------------------------------------------------*/

static MSTATUS
CERT_STORE_checkStore(const certStorePtr pCertStore)
{
    MSTATUS status = OK;

    if (pCertStore->isCertStoreLocked)
        status = ERR_CERT_STORE_LOCKED_STORE;

    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CERT_STORE_addGenericIdentity (
  certStorePtr pCertStore,
  ubyte *pAlias,
  ubyte4 aliasLen,
  const ubyte *pKeyBlob,
  ubyte4 keyBlobLength,
  enum identityTypes identityType,
  SizedBuffer *certificates,
  ubyte4 numCertificate,
  extendedData *pExtData
  )
{
    ubyte4          keyType = 0;
    ubyte4          certLen = 0;
    identityPair*   pNewIdentity = NULL;
    MSTATUS         status;
#ifdef __ENABLE_DIGICERT_CV_CERT__
    byteBoolean isCvc = FALSE;
#endif

    status = DIGI_CALLOC ((void **)&pNewIdentity, sizeof(identityPair), 1);
    if (OK != status)
      goto exit;

    if ( (NULL != pAlias) && (0 != aliasLen) )
    {
      status = DIGI_MALLOC ((void **)&(pNewIdentity->pAlias), aliasLen);
      if (OK != status)
        goto exit;

      status = DIGI_MEMCPY (
        (void *)(pNewIdentity->pAlias), (void *)pAlias, aliasLen);
      if (OK != status)
        goto exit;

      pNewIdentity->aliasLen = aliasLen;
    }

    if ((NULL != pExtData) && (NULL != pExtData->extDataFunc))
    {
        pNewIdentity->extData.extDataFunc = pExtData->extDataFunc;
        pNewIdentity->extData.extDataIdentifier = pExtData->extDataIdentifier;
    }

    if (numCertificate > 0)
    {
        ubyte4 i;

        /* duplicate the certificates */
        if (NULL == (pNewIdentity->certificates = (SizedBuffer*) MALLOC(sizeof(SizedBuffer)*numCertificate)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        for (i = 0; i < numCertificate; i++)
        {
            /* Determine the certificate length from the ASN1 encoding */
            status = ASN1_getTagLen(0x30, certificates[i].data, &certLen);
            if (OK != status)
            {
#ifdef __ENABLE_DIGICERT_CV_CERT__
                if (0x7f == certificates[i].data[0])
                {
                    /* Not ASN1 sequence and starts with the right CVC tag byte.
                     * Assume this is CVC for now, if it is not we will fail the
                     * parse when adding to the store */
                    certLen = certificates[i].length;
                    isCvc = TRUE;
                }
                else
                {
                    goto exit;
                }
#else
                goto exit;
#endif
            }

            /* Certlen should never be zero because that indicates indefinite length,
            * but if that happens for some reason allow this cert into the store.
            * We are checking here to make sure that the certificate length from
            * the encoding matches the actual data length. There are some cases
            * where we try to add two certs in a single bundle even though we only
            * need the first cert. In these cases we will simply reset the data
            * length so that only the first cert is actually processed. */
            if ( (0 != certLen) && (certLen != certificates[i].length) )
            {
                certificates[i].length = certLen;
            }

            status = SB_Allocate (
                &pNewIdentity->certificates[i], certificates[i].length);
            if (OK != status)
                goto exit;

            DIGI_MEMCPY(pNewIdentity->certificates[i].data, certificates[i].data, certificates[i].length);
        }
        pNewIdentity->numCertificate = numCertificate;
    }

    if (NULL != pKeyBlob)
    {
      /* If this is not a standard RSA/ECC/DSA key, then call the special
       * function that builds a key object.
       */
      if ( (0 == pKeyBlob[8]) && (0x01 < pKeyBlob[9]) )
      {
        status = SpecialMocAsymKeyDeserialize (
          pCertStore, pKeyBlob, keyBlobLength, &(pNewIdentity->identityKey));
        if (OK != status)
          goto exit;
      }
      else
      {
        /* extract key from blob */
        /* store extracted key */
        status = KEYBLOB_extractKeyBlobEx(pKeyBlob, keyBlobLength, &(pNewIdentity->identityKey));
        if (OK > status)
          goto exit;
      }

      keyType = (pNewIdentity->identityKey.type & 0xff);
    }

#ifndef __DISABLE_DIGICERT_CERTIFICATE_PARSING__
    /* verify certificate and key blob match */
    if (numCertificate > 0)
    {
        intBoolean isGood = FALSE;

#ifdef __ENABLE_DIGICERT_CV_CERT__
        if (TRUE == isCvc)
        {
            status = CERT_STORE_CVC_verifyCertWithAsymmetricKey(pNewIdentity, &keyType, &isGood);
            if (OK != status)
                goto exit;
        }
        else
#endif
        {
            if (OK > (status = CERT_STORE_verifyCertWithAsymmetricKey(pNewIdentity, &keyType, &isGood)))
                goto exit;

        }

        if (FALSE == isGood)
        {
            status = ERR_CERT_STORE_CERT_KEY_MISMATCH;
            goto exit;
        }
    }
#endif

    if (OK > (status = CERT_STORE_convertPubKeyTypeToCertStoreKeyType(keyType, &keyType)))
        goto exit;

    if (NULL == pCertStore->pIdentityMatrixList[keyType][identityType])
    {
        /* add to head of list */
        pCertStore->pIdentityMatrixList[keyType][identityType] = pNewIdentity;
    }
    else
    {
        /* add to end of list */
        identityPair *pIdentityTravseList = pCertStore->pIdentityMatrixList[keyType][identityType];

        /* traverse to end of list */
        while (NULL != pIdentityTravseList->pNextIdentityKeyPair)
            pIdentityTravseList = (identityPair *)pIdentityTravseList->pNextIdentityKeyPair;

        /* tack new identity to the end of the list */
        pIdentityTravseList->pNextIdentityKeyPair = pNewIdentity;
    }

#if !defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__)

#ifdef __ENABLE_DIGICERT_CV_CERT__
    if (TRUE == isCvc)
    {
        status = CERT_STORE_CVC_addIdentityPairToCertHashTable(pCertStore, pNewIdentity);
    }
    else
#endif
    {
        /* index the new identity pair for issuer/serial number*/
        status = CERT_STORE_addIdentityPairToCertHashTable(pCertStore, pNewIdentity);
    }
#endif

    pNewIdentity = NULL;

exit:

    if (NULL != pNewIdentity)
    {

      CRYPTO_uninitAsymmetricKey (&(pNewIdentity->identityKey), NULL);

      if (NULL != pNewIdentity->pAlias)
      {
        DIGI_FREE ((void **)&(pNewIdentity->pAlias));
      }

      if (pNewIdentity->numCertificate > 0 && NULL != pNewIdentity->certificates)
      {
        sbyte4 i;
        for (i = 0; i < pNewIdentity->numCertificate; i++)
        {
          SB_Release(&pNewIdentity->certificates[i]);
        }

        FREE(pNewIdentity->certificates);
      }

      FREE (pNewIdentity);
    }

    return status;

} /* CERT_STORE_addGenericIdentity */

MSTATUS SpecialMocAsymKeyDeserialize (
  certStorePtr pCertStore,
  const ubyte *pKeyBlob,
  ubyte4 keyBlobLen,
  AsymmetricKey *pAsymKey
  )
{
#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
  return (ERR_NOT_IMPLEMENTED);
#else
  MSTATUS status;
  ubyte4 keyType;
  ubyte *pData = NULL;
  ubyte *pBlob;
  MocAsymKey pNewKey = NULL;
  MOC_UNUSED(pCertStore);

  /* The input has the 0200-- or greater in the type part of the blob.
   * If 0x7F, clear it out for deserialization.
   */
  pBlob = (ubyte *)pKeyBlob;
  keyType = ((ubyte4)(pKeyBlob[8]) << 24) +
            ((ubyte4)(pKeyBlob[9]) << 16) +
            ((ubyte4)(pKeyBlob[10]) << 8) +
            ((ubyte4)(pKeyBlob[11]));

  if (0x7f0000 == (keyType & 0x00ff0000))
  {
    /* The key type 0x7f00-- is for testing. Only the cert store recognizes this
     * key type.
     */
    status = DIGI_MALLOC_MEMCPY (
      (void **)&pData, keyBlobLen, (void *)pKeyBlob, keyBlobLen);
    if (OK != status)
      goto exit;

    pData[9] = 0;
    pBlob = pData;

    /* Adjust the key type to something recognized by the rest of NanoCrypto.
     */
    keyType &= 0x000200ff;
  }

  status = CRYPTO_deserializeMocAsymKey (
    pBlob, keyBlobLen, NULL, &pNewKey, NULL);
  if (OK != status)
    goto exit;

  status = CRYPTO_INTERFACE_loadAsymmetricKey (
      pAsymKey, keyType, (void **)&pNewKey);
  if (OK != status)
    goto exit;

exit:

  if (NULL != pData)
  {
    DIGI_FREE ((void **)&pData);
  }
  if (NULL != pNewKey)
  {
    CRYPTO_freeMocAsymKey (&pNewKey, NULL);
  }

  return (status);
#endif
}
/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_CERTIFICATE_PARSING__

MOC_EXTERN MSTATUS CERT_STORE_addIdentityEx (
  certStorePtr pCertStore,
  ubyte *pAlias,
  ubyte4 aliasLen,
  ubyte *pDerCert,
  ubyte4 derCertLength,
  ubyte *pKeyBlob,
  ubyte4 keyBlobLength
  )
{
  MSTATUS status;
  SizedBuffer certificate;

  status = ERR_NULL_POINTER;
  if ( (NULL == pDerCert) || (0 == derCertLength) )
    goto exit;

  certificate.data = (ubyte *)pDerCert;
  certificate.length = derCertLength;

  status = CERT_STORE_addGenericIdentityEx (
    pCertStore, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, pAlias, aliasLen,
    &certificate, 1, pKeyBlob, keyBlobLength, NULL);

exit:

  return (status);
}

static MSTATUS CERT_STORE_addGenericIdentityEx (
  certStorePtr pCertStore,
  enum identityTypes identityType,
  ubyte *pAlias,
  ubyte4 aliasLen,
  struct SizedBuffer *certificates,
  ubyte4 numCertificate,
  const ubyte *pKeyBlob,
  ubyte4 keyBlobLength,
  extendedData *pExtData
  )
{
  MSTATUS status;
  ubyte4 getCertLen;
  AsymmetricKey *pGetKey = NULL;
  ubyte *pGetCert = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pCertStore) || (NULL == pAlias) || (0 == aliasLen) )
    goto exit;

  /* Verify that the alias has not been used.
   */
  status = CERT_STORE_findIdentityByAlias (
    pCertStore, pAlias, aliasLen, &pGetKey, &pGetCert, &getCertLen);
  if (OK != status)
    goto exit;

  status = ERR_CERT_STORE_EXISTING_ALIAS;
  if ( (NULL != pGetKey) || (NULL != pGetCert) )
    goto exit;

  status = CERT_STORE_addGenericIdentity (
    pCertStore, pAlias, aliasLen, pKeyBlob, keyBlobLength,
    identityType, certificates, numCertificate, pExtData);

exit:

  return (status);
}

/**
@coming_soon
@ingroup    cert_store_functions
*/
extern MSTATUS
CERT_STORE_addIdentity(certStorePtr pCertStore,
                       const ubyte *pDerCert, ubyte4 derCertLength,
                       const ubyte *pKeyBlob, ubyte4 keyBlobLength)
{
    MSTATUS status;
    SizedBuffer certificate;
    ubyte4 numCertificate = 1;

    if (pDerCert && derCertLength > 0)
    {
        certificate.data   = (ubyte*)pDerCert;
        certificate.length = derCertLength;
    } else
    {
        numCertificate = 0;
    }

    status = CERT_STORE_addIdentityWithCertificateChain(pCertStore,
                                                        &certificate,
                                                        numCertificate,
                                                        pKeyBlob,
                                                        keyBlobLength);

    return status;
}

extern MSTATUS CERT_STORE_addIdentityWithCertificateChainExtDataEx (
  certStorePtr pCertStore,
  ubyte *pAlias,
  ubyte4 aliasLen,
  struct SizedBuffer *certificates,
  ubyte4 numCertificate,
  const ubyte *pKeyBlob,
  ubyte4 keyBlobLength,
  ExtendedDataCallback extDataFunc,
  sbyte4 extDataIdentifier
  )
{
  MSTATUS status;
  extendedData extData;

  status = ERR_NULL_POINTER;
  if ( (NULL == certificates) || (0 == numCertificate) )
    goto exit;

  extData.extDataFunc = extDataFunc;
  extData.extDataIdentifier = extDataIdentifier;

  status = CERT_STORE_addGenericIdentityEx (
    pCertStore, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, pAlias, aliasLen,
    certificates, numCertificate, pKeyBlob, keyBlobLength, &extData);

exit:

  return (status);
}

extern MSTATUS CERT_STORE_addIdentityWithCertificateChainEx (
  certStorePtr pCertStore,
  ubyte *pAlias,
  ubyte4 aliasLen,
  struct SizedBuffer *certificates,
  ubyte4 numCertificate,
  const ubyte *pKeyBlob,
  ubyte4 keyBlobLength
  )
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if ( (NULL == certificates) || (0 == numCertificate) )
    goto exit;

  status = CERT_STORE_addGenericIdentityEx (
    pCertStore, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3, pAlias, aliasLen,
    certificates, numCertificate, pKeyBlob, keyBlobLength, NULL);

exit:

  return (status);
}

/**
@todo_64
@ingroup    cert_store_functions
*/
extern MSTATUS
CERT_STORE_addIdentityWithCertificateChainExtData(certStorePtr pCertStore,
                                           SizedBuffer *certificates,
                                           ubyte4 numCertificate,
                                           const ubyte *pKeyBlob,
                                           ubyte4 keyBlobLength,
                                           ExtendedDataCallback extDataFunc,
                                           sbyte4 extDataIdentifier)
{
    MSTATUS status;
    extendedData extData;

    if ((NULL == pCertStore) || (NULL == certificates) || (0 == numCertificate))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    extData.extDataFunc = extDataFunc;
    extData.extDataIdentifier = extDataIdentifier;

    if (OK > (status = CERT_STORE_checkStore(pCertStore)))
        goto exit;

    status = CERT_STORE_addGenericIdentity(pCertStore, NULL, 0,
                                           pKeyBlob, keyBlobLength,
                                           CERT_STORE_IDENTITY_TYPE_CERT_X509_V3,
                                           certificates, numCertificate, &extData);

exit:
    return status;
}

/**
@todo_64
@ingroup    cert_store_functions
*/
extern MSTATUS
CERT_STORE_addIdentityWithCertificateChain(certStorePtr pCertStore,
                                           SizedBuffer *certificates,
                                           ubyte4 numCertificate,
                                           const ubyte *pKeyBlob,
                                           ubyte4 keyBlobLength)
{
    MSTATUS status;

    if ((NULL == pCertStore) || (NULL == certificates) || (0 == numCertificate))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = CERT_STORE_checkStore(pCertStore)))
        goto exit;

    status = CERT_STORE_addGenericIdentity(pCertStore, NULL, 0,
                                           pKeyBlob, keyBlobLength,
                                           CERT_STORE_IDENTITY_TYPE_CERT_X509_V3,
                                           certificates, numCertificate, NULL);

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

extern MSTATUS CERT_STORE_addIdentityNakedKeyEx (
  certStorePtr pCertStore,
  ubyte *pAlias,
  ubyte4 aliasLen,
  ubyte *pKeyBlob,
  ubyte4 keyBlobLength
  )
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKeyBlob) || (0 == keyBlobLength) )
    goto exit;

  status = CERT_STORE_addGenericIdentityEx (
    pCertStore, CERT_STORE_IDENTITY_TYPE_NAKED, pAlias, aliasLen,
    NULL, 0, pKeyBlob, keyBlobLength, NULL);

exit:

  return (status);
}

/**
@brief      Add a naked key to a Mocana SoT Platform certificate store.

@details    This function adds a <em>naked key</em>&mdash;a Mocana SoT Platform
            key blob that has no associated certificate&mdash;to a Mocana
            SoT Platform certificate store.

@ingroup    cert_store_functions

@since 2.02
@version 2.02 and later

@todo_version (interior changes for pskIdentify...)

@flags
No flag definitions are required to use this callback.

@inc_file cert_store.h

@param pCertStore       Pointer to the SoT Platform certificate store to
                          which to add the naked key.
@param pKeyBlob         Pointer to the naked key to add.
@param keyBlobLength    Number of bytes in the naked key (\p pKeyBlob).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cert_store.c
*/
extern MSTATUS
CERT_STORE_addIdentityNakedKey(certStorePtr pCertStore, const ubyte *pKeyBlob, ubyte4 keyBlobLength)
{
    MSTATUS status;

    if ((NULL == pCertStore) || (NULL == pKeyBlob))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = CERT_STORE_checkStore(pCertStore)))
        goto exit;

    status = CERT_STORE_addGenericIdentity(pCertStore, NULL, 0,
                                           pKeyBlob, keyBlobLength,
                                           CERT_STORE_IDENTITY_TYPE_NAKED,
                                           NULL, 0, NULL);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for future use, and should not be included in
 * the API documentation.
 */
extern MSTATUS
CERT_STORE_addIdentityPSK(certStorePtr pCertStore,
                          const ubyte *pPskIdentity, ubyte4 pskIdentityLength,
                          const ubyte *pPskHint, ubyte4 pskHintLength,
                          const ubyte *pPskSecret, ubyte4 pskSecretLength)
{
    identityPskTuple*   pNewPskIdentity = NULL;
    MSTATUS             status = OK;

    if ((NULL == pCertStore) || (NULL == pPskIdentity) || (NULL == pPskSecret))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = CERT_STORE_checkStore(pCertStore)))
        goto exit;

    /* allocate store for new identity */
    if (NULL == (pNewPskIdentity = (identityPskTuple*) MALLOC(sizeof(identityPskTuple))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pNewPskIdentity, 0x00, sizeof(identityPskTuple));

    /* duplicate the psk identity */
    if (NULL == (pNewPskIdentity->pPskIdentity = (ubyte*) MALLOC(pskIdentityLength)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(pNewPskIdentity->pPskIdentity, pPskIdentity, pskIdentityLength);
    pNewPskIdentity->pskIdentityLength = pskIdentityLength;

    /* optionally, duplicate the psk hint */
    if (NULL != pPskHint)
    {
        if (NULL == (pNewPskIdentity->pPskHint = (ubyte*) MALLOC(pskHintLength)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMCPY(pNewPskIdentity->pPskHint, pPskHint, pskHintLength);
        pNewPskIdentity->pskIdentityLength = pskHintLength;
    }

    /* duplicate the psk secret */
    if (NULL == (pNewPskIdentity->pPskSecret = (ubyte*) MALLOC(pskSecretLength)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(pNewPskIdentity->pPskSecret, pPskSecret, pskSecretLength);
    pNewPskIdentity->pskSecretLength = pskSecretLength;

    /* insert new identity to head of list */
    pNewPskIdentity->pNextIdentityPskTuple = pCertStore->pIdentityPskList;
    pCertStore->pIdentityPskList = pNewPskIdentity;

    pNewPskIdentity = NULL;

exit:
    if (pNewPskIdentity)
    {
        if(pNewPskIdentity->pPskIdentity)
            FREE(pNewPskIdentity->pPskIdentity);

        if(pNewPskIdentity->pPskHint)
            FREE(pNewPskIdentity->pPskHint);

        if(pNewPskIdentity->pPskSecret)
            FREE(pNewPskIdentity->pPskSecret);

        FREE(pNewPskIdentity);
    }
    return status;

} /* CERT_STORE_addIdentityPSK */


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_CERTIFICATE_PARSING__
static MSTATUS
CERT_STORE_testSubject(void* pAppData, void* pTestData, intBoolean *pRetIsMatch)
{
    trustPoint*     pTrustPointDescr = (trustPoint*) pAppData;
    subjectDescr*   pSubjectDescr    = (subjectDescr*) pTestData;
    sbyte4          compareResult;
    MSTATUS         status = OK;

    if ((NULL == pTrustPointDescr) || (NULL == pSubjectDescr))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pRetIsMatch = FALSE;

    if (pTrustPointDescr->subjectLength == pSubjectDescr->subjectLength)
    {
        status = DIGI_MEMCMP(pTrustPointDescr->pDerCert + pTrustPointDescr->subjectOffset,
                            pSubjectDescr->pSubject,
                            pSubjectDescr->subjectLength, &compareResult);

        if (0 == compareResult)
            *pRetIsMatch = TRUE;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
CERT_STORE_testIssuerSerialNumber(void* pAppData, void* pTestData,
                                  intBoolean *pRetIsMatch)
{
    certificateEntry*   pCertEntry  = (certificateEntry*) pAppData;
    issuerSerialPair*   pISP        = (issuerSerialPair*) pTestData;
    sbyte4              compareResult;
    MSTATUS             status = OK;

    if ((NULL == pCertEntry) || (NULL == pISP))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pRetIsMatch = FALSE;

    if (pCertEntry->issuerLength == pISP->issuerLength &&
        pCertEntry->serialNumberLength == pISP->serialNumberLength)
    {
        const ubyte* certDer;

        status = CERT_STORE_getCertificateEntryData( pCertEntry, &certDer, NULL, NULL);
        if (OK != status)
          goto exit;

        DIGI_MEMCMP(certDer + pCertEntry->issuerOffset,
                   pISP->pIssuer, pISP->issuerLength, &compareResult);

        if (0 == compareResult)
        {
            DIGI_MEMCMP(certDer + pCertEntry->serialNumberOffset,
                       pISP->serialNumber, pISP->serialNumberLength,
                       &compareResult);
            if ( 0 == compareResult)
            {
                *pRetIsMatch = TRUE;
            }
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_CV_CERT__

static MSTATUS
CERT_STORE_CVC_addToTrustHashTable(certStorePtr pCertStore, const ubyte *pDerCert, ubyte4 derCertLength)
{
    trustPoint*     pNewTrustPoint = NULL;
    trustPoint*     pPreviousTrustPoint;
    intBoolean      foundPreviousTrustPoint;
    subjectDescr    subjectData;
    ubyte*          pCertClone = NULL;
    ubyte4          hashValue;
    MSTATUS         status = OK;
    CV_CERT        *pCertData = NULL;
    ubyte          *pCertStart = NULL;

    /* clone certificate */
    if (NULL == (pCertClone = (ubyte*) MALLOC(derCertLength)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(pCertClone, pDerCert, derCertLength);

    /* allocate/init trust point structure */
    if (NULL == (pNewTrustPoint = (trustPoint*) MALLOC(sizeof(trustPoint))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pNewTrustPoint, 0x00, sizeof(trustPoint));

    pNewTrustPoint->pDerCert       = pCertClone;
    pNewTrustPoint->derCertLength  = derCertLength;

    pCertClone = NULL;  /* to prevent double-free */

    pCertStart = pNewTrustPoint->pDerCert;

    /* Parse the cert */
    status = CV_CERT_parseCert (
        pNewTrustPoint->pDerCert, pNewTrustPoint->derCertLength, &pCertData);
    if (OK != status)
        goto exit;

    pNewTrustPoint->subjectOffset = pCertData->pCertHolderRef - pCertStart;
    pNewTrustPoint->subjectLength = pCertData->certHolderRefLen;
    pNewTrustPoint->pNextTrustPoint = 0;

    subjectData.pSubject      = pCertData->pCertHolderRef;
    subjectData.subjectLength = pCertData->certHolderRefLen;

    /* calculate hash for subject */
    HASH_VALUE_hashGen(subjectData.pSubject,
                       subjectData.subjectLength,
                       MOCANA_CERT_STORE_INIT_HASH_VALUE, &hashValue);

    /* find a possible trust point with the same value already in the hash table */
    if (OK > (status = HASH_TABLE_findPtr(pCertStore->pTrustHashTable,
                                          hashValue,
                                          (void *)&subjectData,
                                          CERT_STORE_testSubject,
                                          (void **)&pPreviousTrustPoint,
                                          &foundPreviousTrustPoint)))
    {
        goto exit;

    }

    if ((!foundPreviousTrustPoint) || (NULL == pPreviousTrustPoint))
    {
        /* no previous one: store a new pointer in the table */
        if (OK > (status = HASH_TABLE_addPtr(pCertStore->pTrustHashTable,
                                             hashValue,
                                             pNewTrustPoint)))
        {
            goto exit;
        }
    }
    else
    {
        sbyte4 cmpRes;

        /* append to the list of existing ones if it's not already one of those */
        if (pPreviousTrustPoint->derCertLength == derCertLength &&
            0 == (DIGI_MEMCMP(pPreviousTrustPoint->pDerCert, pDerCert, derCertLength, &cmpRes), cmpRes))
        {
            pPreviousTrustPoint = pNewTrustPoint;
        }

        while (pPreviousTrustPoint->pNextTrustPoint)
        {
            trustPoint*  pTestTrustPoint = pPreviousTrustPoint->pNextTrustPoint;
            if (pTestTrustPoint->derCertLength == derCertLength &&
                0 == (DIGI_MEMCMP(pTestTrustPoint->pDerCert, pDerCert, derCertLength, &cmpRes), cmpRes))
            {
                pPreviousTrustPoint = pNewTrustPoint;
                break;
            }
            pPreviousTrustPoint = pTestTrustPoint;
        }

        /* add if was not found */
        if (pPreviousTrustPoint != pNewTrustPoint)
        {
            pPreviousTrustPoint->pNextTrustPoint = pNewTrustPoint;
        }
    }

    /* index the trust point by issuer/serial number */
    status = CERT_STORE_CVC_addTrustPointToCertHashTable(pCertStore, pCertData,
                                                     pNewTrustPoint);

    if (foundPreviousTrustPoint && NULL != pPreviousTrustPoint)
    {
        if (pPreviousTrustPoint != pNewTrustPoint)
        {
            pNewTrustPoint = NULL;
        }
    }
    else
    {
        pNewTrustPoint = NULL;
    }

exit:

    if (NULL != pCertData)
    {
        DIGI_FREE((void **)&pCertData);
    }
    if (NULL != pNewTrustPoint)
    {
        if (NULL != pNewTrustPoint->pDerCert)
        {
            DIGI_FREE((void **)&pNewTrustPoint->pDerCert);
        }
        DIGI_FREE((void **)&pNewTrustPoint);
    }

    if (pCertClone)
        FREE(pCertClone);

    return status;
}


extern MSTATUS
CERT_STORE_CVC_addTrustPoint(certStorePtr pCertStore, const ubyte *pDerTrustPoint,
                         ubyte4 derTrustPointLength)
{
    MSTATUS status = OK;

    if ((NULL == pCertStore) || (NULL == pDerTrustPoint))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = CERT_STORE_checkStore(pCertStore)))
        goto exit;

    status = CERT_STORE_CVC_addToTrustHashTable(pCertStore, pDerTrustPoint,
                                            derTrustPointLength);

exit:
    return status;
}

#endif /* __ENABLE_DIGICERT_CV_CERT__ */

static MSTATUS
CERT_STORE_addToTrustHashTable(certStorePtr pCertStore,
                               const ubyte *pDerCert,
                               ubyte4 derCertLength)
{
    trustPoint*     pNewTrustPoint = NULL;
    trustPoint*     pPreviousTrustPoint;
    intBoolean      foundPreviousTrustPoint;
    subjectDescr    subjectData;
    ASN1_ITEMPTR    pAsn1CertTree = NULL;
    ASN1_ITEMPTR    pSubject;
    MemFile         certMemFile;
    CStream         cs;
    ubyte*          pCertClone = NULL;
    ubyte4          hashValue;
    MSTATUS         status = OK;

    /* clone certificate */
    if (NULL == (pCertClone = (ubyte*) MALLOC(derCertLength)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(pCertClone, pDerCert, derCertLength);

    /* allocate/init trust point structure */
    if (NULL == (pNewTrustPoint = (trustPoint*) MALLOC(sizeof(trustPoint))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pNewTrustPoint, 0x00, sizeof(trustPoint));

    pNewTrustPoint->pDerCert       = pCertClone;
    pNewTrustPoint->derCertLength  = derCertLength;

    pCertClone = NULL;  /* to prevent double-free */

    /* extract certificate's subject */
    MF_attach(&certMemFile, derCertLength, (ubyte*)pNewTrustPoint->pDerCert);
    CS_AttachMemFile(&cs, &certMemFile);

    /* parse the certificate */
    if (OK > (status = X509_parseCertificate(cs, &pAsn1CertTree)))
    {
        goto exit;
    }

    /* fetch the data we want to grab */
    if (OK > (status = X509_getCertificateSubject(ASN1_FIRST_CHILD(pAsn1CertTree),
                                                  &pSubject)))
    {
        goto exit;
    }

    pNewTrustPoint->subjectOffset = pSubject->dataOffset;
    pNewTrustPoint->subjectLength = pSubject->length;
    pNewTrustPoint->pNextTrustPoint = 0;

    subjectData.pSubject      = pDerCert + pSubject->dataOffset;
    subjectData.subjectLength = pSubject->length;

    /* calculate hash for subject */
    HASH_VALUE_hashGen(subjectData.pSubject,
                       subjectData.subjectLength,
                       MOCANA_CERT_STORE_INIT_HASH_VALUE, &hashValue);

    /* find a possible trust point with the same value already in the hash table */
    if (OK > (status = HASH_TABLE_findPtr(pCertStore->pTrustHashTable,
                                          hashValue,
                                          (void *)&subjectData,
                                          CERT_STORE_testSubject,
                                          (void **)&pPreviousTrustPoint,
                                          &foundPreviousTrustPoint)))
    {
        goto exit;

    }

    if ((!foundPreviousTrustPoint) || (NULL == pPreviousTrustPoint))
    {
        /* no previous one: store a new pointer in the table */
        if (OK > (status = HASH_TABLE_addPtr(pCertStore->pTrustHashTable,
                                             hashValue,
                                             pNewTrustPoint)))
        {
            goto exit;
        }
    }
    else
    {
        sbyte4 cmpRes;

        /* append to the list of existing ones if it's not already one of those */
        if (pPreviousTrustPoint->derCertLength == derCertLength &&
            0 == (DIGI_MEMCMP(pPreviousTrustPoint->pDerCert, pDerCert, derCertLength, &cmpRes), cmpRes))
        {
            pPreviousTrustPoint = pNewTrustPoint;
        }

        while (pPreviousTrustPoint->pNextTrustPoint)
        {
            trustPoint*  pTestTrustPoint = pPreviousTrustPoint->pNextTrustPoint;
            if (pTestTrustPoint->derCertLength == derCertLength &&
                0 == (DIGI_MEMCMP(pTestTrustPoint->pDerCert, pDerCert, derCertLength, &cmpRes), cmpRes))
            {
                pPreviousTrustPoint = pNewTrustPoint;
                break;
            }
            pPreviousTrustPoint = pTestTrustPoint;
        }

        /* add if was not found */
        if (pPreviousTrustPoint != pNewTrustPoint)
        {
            pPreviousTrustPoint->pNextTrustPoint = pNewTrustPoint;
        }
    }

    /* index the trust point by issuer/serial number */
    status = CERT_STORE_addTrustPointToCertHashTable(pCertStore, pAsn1CertTree,
                                                     pNewTrustPoint);

    if (foundPreviousTrustPoint && NULL != pPreviousTrustPoint)
    {
        if (pPreviousTrustPoint != pNewTrustPoint)
        {
            pNewTrustPoint = NULL;
        }
    }
    else
    {
        pNewTrustPoint = NULL;
    }

exit:
    if (pAsn1CertTree)
        TREE_DeleteTreeItem((TreeItem*)pAsn1CertTree);

    if (NULL != pNewTrustPoint)
    {
        if (pNewTrustPoint->pDerCert)
            FREE(pNewTrustPoint->pDerCert);

        FREE(pNewTrustPoint);
    }

    if (pCertClone)
        FREE(pCertClone);

    return status;
}


/*------------------------------------------------------------------*/

/**
@brief      Add a trust point to a Mocana SoT Platform certificate store.

@details    This function adds a trust point to a Mocana SoT Platform
            certificate store.

@ingroup    cert_store_functions

@since 2.02
@version 2.02 and later

@todo_version (interior changes to function call params...)

@flags
No flag definitions are required to use this callback.

@inc_file cert_store.h

@param pCertStore           Pointer to the SoT Platform certificate store to
                              which to add the trust point.
@param pDerTrustPoint       Pointer to the trust point to add.
@param derTrustPointLength  Number of bytes in the trust point
                              (\p pDerTrustPoint).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cert_store.c
*/
extern MSTATUS
CERT_STORE_addTrustPoint(certStorePtr pCertStore, const ubyte *pDerTrustPoint,
                         ubyte4 derTrustPointLength)
{
    MSTATUS status = OK;

    if ((NULL == pCertStore) || (NULL == pDerTrustPoint))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = CERT_STORE_checkStore(pCertStore)))
        goto exit;

    status = CERT_STORE_addToTrustHashTable(pCertStore, pDerTrustPoint,
                                            derTrustPointLength);

exit:
    return status;
}

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_MINIMAL_CA__)

/**
 * This function is used to identify whether an entry exists for a particular
 * certificate when loading it into the issuer store.
 */
static MSTATUS
CERT_STORE_testCertFileEntry(void *pAppData, void *pTestData, intBoolean *pRetIsMatch)
{
    MSTATUS status = OK;
    certificateFileEntry *pCertFileEntry = (certificateFileEntry *) pAppData;
    certificateFileEntry *pEntry = (certificateFileEntry *) pTestData;
    sbyte4 cmpRes;

    if ( (NULL == pCertFileEntry) || (NULL == pEntry) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pRetIsMatch = FALSE;

    /* Compare the certificate buffers. If they match then we already have a entry for
     * this certificate. */
    if ( (pCertFileEntry->serialNumberLen == pEntry->serialNumberLen) &&
         (pCertFileEntry->subjectLen == pEntry->subjectLen) &&
         (pCertFileEntry->issuerLen == pEntry->issuerLen) )
    {
        status = DIGI_MEMCMP(
            pCertFileEntry->pSerialNumber, pEntry->pSerialNumber, pEntry->serialNumberLen, &cmpRes);
        if ( (OK == status) && (0 == cmpRes) )
        {
            status = DIGI_MEMCMP(
                pCertFileEntry->pSubject, pEntry->pSubject, pEntry->subjectLen, &cmpRes);
            if ( (OK == status) && (0 == cmpRes) )
            {
                status = DIGI_MEMCMP(
                    pCertFileEntry->pIssuer, pEntry->pIssuer, pEntry->issuerLen, &cmpRes);
                if ( (OK == status) && (0 == cmpRes) )
                {
                    *pRetIsMatch = TRUE;
                }
            }
        }
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

/**
 * This function is used to free a certificate file entry.
 */
static MSTATUS
CERT_STORE_deleteCertificateFileEntry(certificateFileEntry **ppEntry)
{
    if (NULL != *ppEntry)
    {
        if (NULL != (*ppEntry)->pSerialNumber)
        {
            DIGI_FREE((void **) &((*ppEntry)->pSerialNumber));
        }

        if (NULL != (*ppEntry)->pSubject)
        {
            DIGI_FREE((void **) &((*ppEntry)->pSubject));
        }

        if (NULL != (*ppEntry)->pIssuer)
        {
            DIGI_FREE((void **) &((*ppEntry)->pIssuer));
        }

        if (NULL != (*ppEntry)->pFileName)
        {
            DIGI_FREE((void **) &((*ppEntry)->pFileName));
        }

        DIGI_FREE((void **) ppEntry);
    }

    return OK;
}

/*------------------------------------------------------------------*/

/**
 * This function is used to create a certificate file entry.
 */
static MSTATUS
CERT_STORE_createCertificateFileEntry(
   ubyte *pSerial, ubyte4 serialLen, ubyte *pSubject, ubyte4 subjectLen,
   ubyte *pIssuer, ubyte4 issuerLen, sbyte *pFile, ubyte4 fileLen,
   byteBoolean isChild, intBoolean fpSigFileExists,
   certificateFileEntry **ppEntry)
{
    MSTATUS status;
    certificateFileEntry *pNewEntry = NULL;

    if ( (NULL == pSerial) || (NULL == pSubject) || (NULL == pIssuer) || (NULL == pFile) ||
         (NULL == ppEntry) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_CALLOC((void **) &pNewEntry, 1, sizeof(certificateFileEntry));
    if (OK != status)
    {
        goto exit;
    }

    /* Copy over the serial number, subject, issuer, and file name into the
     * structure */
    status = DIGI_MALLOC_MEMCPY(
        (void **) &(pNewEntry->pSerialNumber), serialLen, pSerial, serialLen);
    if (OK != status)
    {
        goto exit;
    }
    pNewEntry->serialNumberLen = serialLen;

    status = DIGI_MALLOC_MEMCPY(
        (void **) &(pNewEntry->pSubject), subjectLen, pSubject, subjectLen);
    if (OK != status)
    {
        goto exit;
    }
    pNewEntry->subjectLen = subjectLen;

    status = DIGI_MALLOC_MEMCPY(
        (void **) &(pNewEntry->pIssuer), issuerLen, pIssuer, issuerLen);
    if (OK != status)
    {
        goto exit;
    }
    pNewEntry->issuerLen = issuerLen;

    status = DIGI_MALLOC_MEMCPY(
        (void **) &(pNewEntry->pFileName), fileLen + 1, pFile, fileLen);
    if (OK != status)
    {
        goto exit;
    }
    pNewEntry->pFileName[fileLen] = '\0';

    pNewEntry->isChild = isChild;
    pNewEntry->fpSigFileExists = fpSigFileExists;

    *ppEntry = pNewEntry;
    pNewEntry = NULL;

exit:

    if (NULL != pNewEntry)
    {
        CERT_STORE_deleteCertificateFileEntry(&pNewEntry);
    }

    return status;
}

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)

static MSTATUS
CERT_STORE_updateCertFileEntryDataProtect(
    certificateFileEntry *pEntry, sbyte *pFile, intBoolean fpSigFileExists)
{
    MSTATUS status;
    ubyte4 fileLen;

    if ( (NULL == pEntry) || (NULL == pFile) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    DIGI_FREE((void **) &(pEntry->pFileName));

    fileLen = DIGI_STRLEN(pFile);
    status = DIGI_MALLOC_MEMCPY(
        (void **) &(pEntry->pFileName), fileLen + 1, pFile, fileLen);
    if (OK != status)
    {
        goto exit;
    }
    pEntry->pFileName[fileLen] = '\0';

    pEntry->fpSigFileExists = fpSigFileExists;

exit:

    return status;
}

#endif

/*------------------------------------------------------------------*/

/* This function takes in a certificate file entry and searches for a parent in
 * the certificate issuer store that has the isChild field set to TRUE. Once a
 * parent is found the isChild field is toggled to false.
 */
static MSTATUS
CERT_STORE_checkForParents(certStoreIssuerPtr pStore, certificateFileEntry *pEntry)
{
    MSTATUS status = OK;
    void *pBucket = NULL;
    ubyte4 index = 0;
    certificateFileEntry *pParentEntry = NULL;
    sbyte4 cmpRes;

    /* Loop through all the certificate entries in the hash table */
    while (NULL != (pParentEntry = HASH_TABLE_iteratePtrTable((hashTableOfPtrs *) pStore, &pBucket, &index)))
    {
        if ( (pParentEntry != pEntry) && (pParentEntry->isChild == TRUE) )
        {
            if (pParentEntry->subjectLen == pEntry->issuerLen)
            {
                /* Check if entry has issued the certificate by comparing the
                 * parents subject with the certificates issuer */
                status = DIGI_MEMCMP(pParentEntry->pSubject, pEntry->pIssuer, pEntry->issuerLen, &cmpRes);
                if ( (OK == status) && (0 == cmpRes) )
                {
                    pParentEntry->isChild = FALSE;
                }
            }
        }
    }

    return OK;
}

/*------------------------------------------------------------------*/

/* This function checks if an entry in the hash table is a child certificate of
 * the current certificate being processed. */
static MSTATUS
CERT_STORE_testCertFileEntryChild(void *pAppData, void *pTestData, intBoolean *pRetIsMatch)
{
    MSTATUS status;
    certificateFileEntry *pChild = pAppData;
    /* Parent certificate that we want to find the child certificate for */
    certificateFileEntry *pParent = pTestData;
    sbyte4 cmpRes;

    if ( (NULL == pParent) || (NULL == pChild) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pRetIsMatch = FALSE;
    status = OK;

    /* This check is for if the certificate entry itself is found. This can happen for
     * self-signed certificates. We don't want to return TRUE for self-signed certificates. */
    if (pParent == pChild)
    {
        goto exit;
    }


    if (pParent->subjectLen == pChild->issuerLen)
    {
        /* Check if entry has issued the certificate by comparing the
         * parents subject with the certificates issuer */
        status = DIGI_MEMCMP(pParent->pSubject, pChild->pIssuer, pChild->issuerLen, &cmpRes);
        if ( (OK == status) && (0 == cmpRes) )
        {
            *pRetIsMatch = TRUE;
        }
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

/**
 * Loops through the provided directory one level down and adds the certificates
 * found to the issuer store.
 */
static MSTATUS
CERT_STORE_addCertificateFileEntryByDir(certStoreIssuerPtr pStore, sbyte *pDirPath)
{
    MSTATUS status;
    DirectoryDescriptor pDir = NULL;
    DirectoryEntry ent;
    ubyte *pCert = NULL, *pCertDecoded = NULL;
    ubyte4 certLen = 0, certDecodedLen = 0;
    ASN1_ITEMPTR pRoot = NULL, pSerial, pIssuer, pSubject;
    CStream cs;
    MemFile mf;
    ubyte4 hashValue;
    certificateFileEntry *pEntry = NULL, *pNewEntry = NULL;
    certificateFileEntry curEntry;
    intBoolean found;
    sbyte *pFullpath = NULL;
    ubyte4 pathLen;
    sbyte *pNewFile = NULL;
#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
    intBoolean fileExists;
#endif

    /* Loop through the directory and load in certificates into the hash table. */
    pathLen = DIGI_STRLEN(pDirPath);
    status = FMGMT_getFirstFile(pDirPath, &pDir, &ent);
    while ( (OK == status) && (FTNone != ent.type) )
    {
        /* Only filter for .pem and .der files (case insensitive) */
        if ( (FTFile == ent.type) && (ent.nameLength > 4) &&
             ((0 == DIGI_STRNICMP(ent.pName + ent.nameLength - 4, ".pem", 4)) || (0 == DIGI_STRNICMP(ent.pName + ent.nameLength - 4, ".der", 4))) )
        {
            /* Construct the full path so the certificate can be read */
            status = DIGI_MALLOC((void **) &pFullpath, pathLen + 1 + ent.nameLength + 1);
            if (OK != status)
            {
                goto exit;
            }
            DIGI_MEMCPY(pFullpath, pDirPath, pathLen);
            pFullpath[pathLen] = '/';
            DIGI_MEMCPY(pFullpath + pathLen + 1, ent.pName, ent.nameLength);
            pFullpath[pathLen + 1 + ent.nameLength] = '\0';
            status = DIGICERT_readFile(pFullpath, &pCert, &certLen);
            if (OK != status)
            {
                goto exit;
            }

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
            status = DIGICERT_checkFile(
                pFullpath, MOC_FP_SIG_SUFFIX, &fileExists);
            if (OK != status)
            {
                goto exit;
            }
#endif

            /* Decode the certificate. Need to parse certificate information
             * from DER buffer.
             */
            status = CA_MGMT_decodeCertificate(pCert, certLen, &pCertDecoded, &certDecodedLen);
            if (OK == status)
            {
                DIGI_FREE((void **) &pCert);
                pCert = pCertDecoded;
                certLen = certDecodedLen;
            }

            MF_attach(&mf, certLen, pCert);
            CS_AttachMemFile(&cs, &mf);

            status = X509_parseCertificate(cs, &pRoot);
            if (OK != status)
            {
                goto exit;
            }

            /* Get the certificate issuer. This will be used as the key in our
             * hash table. */
            status = X509_getCertificateIssuerSerialNumber(
                ASN1_FIRST_CHILD(pRoot), &pIssuer, &pSerial);
            if (OK != status)
            {
                goto exit;
            }

            /* Retrieve the subject as well. The serial number, subject, and
             * issuer will be used to identify whether there is an existing
             * entry added into the issuer store (existing entries can come
             * from other files which contain the same certificate, we want to
             * avoid the duplication of those entries).
             */
            status = X509_getCertificateSubject(
                ASN1_FIRST_CHILD(pRoot), &pSubject);
            if (OK != status)
            {
                goto exit;
            }

            HASH_VALUE_hashGen(
                pCert + pIssuer->dataOffset, pIssuer->length,
                MOCANA_CERT_STORE_INIT_HASH_VALUE, &hashValue);

            /* Check if this entry was already added to our hash table. The
             * CERT_STORE_testCertFileEntry callback will check if the current
             * certificate we are processing (passed in through curEntry) is
             * already in the hash table. */
            curEntry.pSerialNumber = pCert + pSerial->dataOffset;
            curEntry.serialNumberLen = pSerial->length;
            curEntry.pSubject = pCert + pSubject->dataOffset;
            curEntry.subjectLen = pSubject->length;
            curEntry.pIssuer = pCert + pIssuer->dataOffset;
            curEntry.issuerLen = pIssuer->length;
            status = HASH_TABLE_findPtr(
                (hashTableOfPtrs *) pStore, hashValue,
                &curEntry, CERT_STORE_testCertFileEntry, (void **) &pEntry, &found);
            if (OK != status)
            {
                goto exit;
            }

            /* If the entry does not exist then create one. We'll store the
             * certificates serial number, subject, issuer, full filename, and
             * whether its a child certificate or not. */
            if ( (NULL == pEntry) || (FALSE == found) )
            {
                /* Create a new certificate file entry. Assume the new entry is
                 * a child certificate */
#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
                status = CERT_STORE_createCertificateFileEntry(
                    pCert + pSerial->dataOffset, pSerial->length,
                    pCert + pSubject->dataOffset, pSubject->length,
                    pCert + pIssuer->dataOffset, pIssuer->length,
                    pFullpath, DIGI_STRLEN(pFullpath), TRUE, fileExists, &pNewEntry);
#else
                status = CERT_STORE_createCertificateFileEntry(
                    pCert + pSerial->dataOffset, pSerial->length,
                    pCert + pSubject->dataOffset, pSubject->length,
                    pCert + pIssuer->dataOffset, pIssuer->length,
                    pFullpath, DIGI_STRLEN(pFullpath), TRUE, FALSE, &pNewEntry);
#endif
                if (OK != status)
                {
                    goto exit;
                }

                status = HASH_TABLE_addPtr((hashTableOfPtrs *) pStore, hashValue, pNewEntry);
                if (OK != status)
                {
                    goto exit;
                }

                HASH_VALUE_hashGen(
                    pCert + pSubject->dataOffset, pSubject->length,
                    MOCANA_CERT_STORE_INIT_HASH_VALUE, &hashValue);

                /* Check if the entry that was just added has issued any
                 * certificates (self-signed certificate do not count). If it
                 * has issued any other certificate then set the isChild field
                 * to FALSE.
                 */
                pEntry = NULL;
                found = FALSE;
                status = HASH_TABLE_findPtr(
                    (hashTableOfPtrs *) pStore, hashValue,
                    pNewEntry, CERT_STORE_testCertFileEntryChild, (void **) &pEntry, &found);
                if (OK != status)
                {
                    goto exit;
                }

                if ( (NULL != pEntry) && (TRUE == found) )
                {
                    pNewEntry->isChild = FALSE;
                }

                /* Check if the entry that was just added has any parent
                 * certificates that were added where the isChild field is TRUE.
                 * This function will find the parent certificate and set the
                 * isChild field to FALSE.
                 */
                status = CERT_STORE_checkForParents(pStore, pNewEntry);
                if (OK != status)
                {
                    goto exit;
                }
            }
#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
            else if ( (NULL != pEntry) && (FALSE == pEntry->fpSigFileExists) &&
                      (TRUE == fileExists) )
            {
                /* For data protect builds its possible that there are duplicate
                 * certificates with different names in the same directory but
                 * only one of the certificates is protected using data protect.
                 * If the non data protect certificate was encountered first
                 * when looping through the directory then the entry would store
                 * the filename of the certificate which doesn't have a data
                 * protected signature file. We want to keep this entry,
                 * but if another file is found with the same certificate which
                 * does have the data protect signature file, then we want to
                 * update the existing entry to point to that file. This code
                 * will update the entry so that it points to the new file. */
                status = CERT_STORE_updateCertFileEntryDataProtect(
                    pEntry, pFullpath, fileExists);
                if (OK != status)
                {
                    goto exit;
                }
            }
#endif

            TREE_DeleteTreeItem((TreeItem *) pRoot);
            pRoot = NULL;
            DIGI_FREE((void **) &pCert);
            DIGI_FREE((void **) &pFullpath);
        }

        status = FMGMT_getNextFile(pDir, &ent);
    }

exit:

    if (NULL != pRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pRoot);
    }

    if (NULL != pCert)
    {
        DIGI_FREE((void **) &pCert);
    }

    if (NULL != pFullpath)
    {
        DIGI_FREE((void **) &pFullpath);
    }

    if (NULL != pDir)
    {
        FMGMT_closeDir(&pDir);
    }

    return status;
}

/*------------------------------------------------------------------*/

/**
 * Loop through the child certificates by filename.
 * <p>This API loops through the issuer store and searches for a child
 * certificate and gives back the filename of that certificate. The caller
 * maintains the location into the issuer store to start searching from through
 * a cookie and index.
 *
 * @ingroup cert_store_functions
 *
 * @param pStore The issuer store to search for child certificates.
 * @param ppCookie The starting location to search from. Pass in as NULL to
 * search from the the start of the store.
 * @param pIndex The last visited index into the issuer store. Pass in as 0 to
 * search from the start of the store.
 * @param ppFile The location where the full filename is stored once a child
 * entry is found. If this is set to NULL then there are no more child entries.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
extern MSTATUS
CERT_STORE_traverseChildCertsByFile(
    certStoreIssuerPtr pStore, void **ppCookie, ubyte4 *pIndex, sbyte **ppFile)
{
    MSTATUS status;
    certificateFileEntry *pCertFileEntry = NULL;

    if ( (NULL == pStore) || (NULL == ppCookie) || (NULL == pIndex) || (NULL == ppFile) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Initialize to NULL. If no entries are found then NULL is returned to let
     * the caller know that no more entries remain. */
    *ppFile = NULL;
    status = OK;

    while (NULL != (pCertFileEntry = HASH_TABLE_iteratePtrTable((hashTableOfPtrs *) pStore, ppCookie, pIndex)))
    {
        if (TRUE == pCertFileEntry->isChild)
        {
            *ppFile = pCertFileEntry->pFileName;
            goto exit;
        }
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

/**
 * Function is used to free up the certificate entries in the hash table.
 */
static MSTATUS
CERT_STORE_freeCertificateEntryPtrElement(void *pHashCookie,
                                   hashTablePtrElement *pFreeHashElement)
{
    MOC_UNUSED(pHashCookie);

    if (pFreeHashElement->pAppData)
    {
        CERT_STORE_deleteCertificateFileEntry((certificateFileEntry **) &(pFreeHashElement->pAppData));
    }
    FREE(pFreeHashElement);
    return OK;
}

/*------------------------------------------------------------------*/

/**
 * Create a issuer store which only contains certificate entries from the
 * directory specified.
 * <p>This API creates a issuer store which only contains entries from the
 * directory specified. Only the first level of the directory is searched for
 * certificates.
 *
 * @ingroup cert_store_functions
 *
 * @param pDirPath Path to directory to load certificates from.
 * @param certStoreIssuerPtr Pointer to store the new certificate issuer store.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
extern MSTATUS
CERT_STORE_createIssuerStore(sbyte *pDirPath, certStoreIssuerPtr *pStore)
{
    MSTATUS status;
    certStoreIssuerPtr pNewStore = NULL;

    if ( (NULL == pStore) || (NULL == pDirPath) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = HASH_TABLE_createPtrsTable(
        (hashTableOfPtrs **) &pNewStore, MAX_SIZE_CERT_STORE_TRUST_HASH_TABLE, NULL,
        CERT_STORE_allocHashPtrElement, CERT_STORE_freeCertificateEntryPtrElement);
    if (OK != status)
    {
        goto exit;
    }

    /* Load in all the certificates from the specified directory. */
    status = CERT_STORE_addCertificateFileEntryByDir(pNewStore, pDirPath);
    if (OK != status)
    {
        goto exit;
    }

    *pStore = pNewStore;
    pNewStore = NULL;

exit:

    if (NULL != pNewStore)
    {
        HASH_TABLE_removePtrsTable((hashTableOfPtrs *) pNewStore, NULL);
    }

    return status;
}

/*------------------------------------------------------------------*/

/**
 * Frees the issuer store.
 * <p>This API frees the issuer store along with any entries in the hash table.
 *
 * @ingroup cert_store_functions
 *
 * @param pStore Issuer store to cleanup.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
extern MSTATUS
CERT_STORE_releaseIssuerStore(certStoreIssuerPtr *pStore)
{
    if ( (NULL != pStore) && (NULL != *pStore) )
    {
        HASH_TABLE_removePtrsTable((hashTableOfPtrs *) *pStore, NULL);
    }
    return OK;
}

#endif /* __ENABLE_DIGICERT_MINIMAL_CA__ */

/*------------------------------------------------------------------*/

/**
@todo_64
@ingroup    cert_store_functions
*/
extern MSTATUS
CERT_STORE_findTrustPointBySubjectFirst(const certStorePtr pCertStore,
                                        const ubyte *subject,
                                        ubyte4 subjectLength,
                                        const ubyte **ppRetDerCert,
                                        ubyte4 *pRetDerCertLength,
                                        const void** pIterator)
{
    trustPoint*     pTrustPointDescr = NULL;
    subjectDescr    subjectData;
    ubyte4          hashValue;
    intBoolean      foundHashValue;
    MSTATUS         status = OK;

    if ((NULL == pCertStore) || (NULL == subject) || (NULL == ppRetDerCert) ||
        (NULL == pRetDerCertLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* calculate hash for subject */
    HASH_VALUE_hashGen(subject, subjectLength,
                       MOCANA_CERT_STORE_INIT_HASH_VALUE, &hashValue);

    subjectData.pSubject      = subject;
    subjectData.subjectLength = subjectLength;

    /* look up subject in certificate store */
    if (OK > (status = HASH_TABLE_findPtr(pCertStore->pTrustHashTable,
                                          hashValue,
                                          (void *)&subjectData,
                                          CERT_STORE_testSubject,
                                          (void **)&pTrustPointDescr,
                                          &foundHashValue)))
    {
        goto exit;

    }

    if ((TRUE != foundHashValue) || (NULL == pTrustPointDescr))
    {
        if (pIterator)
        {
            *pIterator = 0;
        }
        *ppRetDerCert = NULL;
        *pRetDerCertLength = 0;
    }
    else
    {
        /* found it, and pTrustPointDescr pointer is good */
        if (pIterator)
        {
            *pIterator = pTrustPointDescr->pNextTrustPoint;
        }
        *ppRetDerCert = pTrustPointDescr->pDerCert;
        *pRetDerCertLength = pTrustPointDescr->derCertLength;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

/**
@todo_64
@ingroup    cert_store_functions
*/
extern MSTATUS
CERT_STORE_findTrustPointBySubjectNext(const void** pIterator,
                                       const ubyte **ppRetDerCert,
                                       ubyte4 *pRetDerCertLength)
{
    trustPoint*     pTrustPointDescr;

    if ((NULL == pIterator) || (NULL == ppRetDerCert) || (NULL == pRetDerCertLength))
    {
        return ERR_NULL_POINTER;
    }

    if (NULL == *pIterator)
    {
        *ppRetDerCert = 0;
        *pRetDerCertLength = 0;
        return ERR_INVALID_ARG;
    }

    /* return next in the list */
    pTrustPointDescr = (trustPoint*) (*pIterator);

    *ppRetDerCert = pTrustPointDescr->pDerCert;
    *pRetDerCertLength = pTrustPointDescr->derCertLength;
    *pIterator = pTrustPointDescr->pNextTrustPoint;
    return OK;
}


/*------------------------------------------------------------------*/

/**
@todo_64
@ingroup    cert_store_functions
*/
extern MSTATUS
CERT_STORE_findTrustPointBySubject(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                   const certStorePtr pCertStore,
                                   const ubyte* subject,
                                   ubyte4 subjectLength,
                                   const void* cbArg,
                                   CERT_STORE_MatchFun matchFun,
                                   const ubyte** ppRetDerCert,
                                   ubyte4* pRetDerCertLength)
{
    MSTATUS status;
    const ubyte* foundCert;
    ubyte4 foundCertLen;
    const void* iterator;

    if ((NULL == pCertStore) || (NULL == subject) || (NULL == matchFun) ||
        (NULL == ppRetDerCert) || (NULL == pRetDerCertLength))
    {
        return ERR_NULL_POINTER;
    }

    *ppRetDerCert = 0;
    *pRetDerCertLength = 0;

    if (OK > (status = CERT_STORE_findTrustPointBySubjectFirst(pCertStore,
                                                               subject,
                                                               subjectLength,
                                                               &foundCert,
                                                               &foundCertLen,
                                                               &iterator)))
    {
        return status;
    }

    /* did we find something? */
    if (foundCertLen && foundCert)
    {
        /* call the match function */
        status = matchFun( MOC_ASYM(hwAccelCtx) cbArg, foundCert, foundCertLen);
        switch (status)
        {
            case OK:
                *ppRetDerCert = foundCert;
                *pRetDerCertLength = foundCertLen;
                return OK;

            case ERR_FALSE:
                break;

            default:
                return status;
        }

        while (iterator)
        {
            if (OK > ( status = CERT_STORE_findTrustPointBySubjectNext(&iterator,
                                                                       &foundCert,
                                                                       &foundCertLen)))
            {
                return status;
            }
            /* call the match function */
            status = matchFun( MOC_ASYM(hwAccelCtx) cbArg, foundCert, foundCertLen);
            switch (status)
            {
                case OK:
                    *ppRetDerCert = foundCert;
                    *pRetDerCertLength = foundCertLen;
                    return OK;

                case ERR_FALSE:
                    break;

                default:
                    return status;
            }
        }
    }
    return OK;
}


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
CERT_STORE_traverseTrustPoints(MOC_ASYM(hwAccelDescr hwAccelCtx)
                               const certStorePtr pCertStore,
                               const void* cbArg,
                               CERT_STORE_MatchFun matchFun)
{
    MSTATUS status = OK;
    trustPoint *pTrustPointDescr;
    void *pBucketCookie = NULL;
    ubyte4 index = 0;

    if ((NULL == pCertStore) || (NULL == matchFun))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    while (NULL != (pTrustPointDescr = (trustPoint*) HASH_TABLE_iteratePtrTable(
                                                    pCertStore->pTrustHashTable,
                                                    &pBucketCookie, &index)))
    {
        do
        {
            /* call the match function */
            status = matchFun(MOC_ASYM(hwAccelCtx)
                              cbArg, pTrustPointDescr->pDerCert,
                              pTrustPointDescr->derCertLength);
            if (ERR_FALSE == status)
            { 
                status = OK;
                /* continue */
            }
            else
            {
                goto exit;
            }
        } while (NULL != (pTrustPointDescr = pTrustPointDescr->pNextTrustPoint));
    }

exit:
    return status;
}


#endif /* #ifndef __DISABLE_DIGICERT_CERTIFICATE_PARSING__ */
/*------------------------------------------------------------------*/

extern MSTATUS CERT_STORE_findIdentityByAlias (
  certStorePtr pCertStore,
  ubyte *pAlias,
  ubyte4 aliasLen,
  struct AsymmetricKey **ppReturnIdentityKey,
  ubyte **ppRetDerCert,
  ubyte4 *pRetDerCertLength
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  ubyte4 indexA, indexT;
  certStore *pStore = (certStore *)pCertStore;
  identityPair *pCurrent, *pNext;

  status = ERR_NULL_POINTER;
  if ( (NULL == pCertStore) || (NULL == pAlias) || (0 == aliasLen)  )
    goto exit;

  /* Init the returns to NULL/0.
   */
  if (NULL != ppReturnIdentityKey)
    *ppReturnIdentityKey = NULL;

  if (NULL != ppRetDerCert)
    *ppRetDerCert = NULL;

  if (NULL != pRetDerCertLength)
    *pRetDerCertLength = 0;

  /* Cycle through all the identity pairs. Check for the alias. If it is there,
   * return the key and cert.
   */
  for (indexA = 0; indexA < CERT_STORE_AUTH_TYPE_ARRAY_SIZE; ++indexA)
  {
    for (indexT = 0; indexT < CERT_STORE_IDENTITY_TYPE_ARRAY_SIZE; ++indexT)
    {
      pNext = pStore->pIdentityMatrixList[indexA][indexT];

      while (NULL != pNext)
      {
        pCurrent = pNext;
        pNext = pCurrent->pNextIdentityKeyPair;

        /* Check the alias in this entry. Is it the same?
         */
        if (pCurrent->aliasLen != aliasLen)
          continue;

        status = DIGI_MEMCMP (
          (void *)(pCurrent->pAlias), (void *)pAlias, aliasLen, &cmpResult);
        if (OK != status)
          goto exit;

        if (0 != cmpResult)
          continue;

        /* We have a match.
         */
        if (NULL != ppReturnIdentityKey)
          *ppReturnIdentityKey = &(pCurrent->identityKey);
        if (0 != pCurrent->numCertificate)
        {
          if (NULL != ppRetDerCert)
            *ppRetDerCert = pCurrent->certificates->data;

          if (NULL != pRetDerCertLength)
            *pRetDerCertLength = pCurrent->certificates->length;
        }

        goto exit;
      }
    }
  }

  /* If we went through the entire list and found no match, we're done, no need
   * to do anything. We already init the return values to NULL/0.
   */
  status = OK;

exit:

  return (status);
}

/*------------------------------------------------------------------*/

extern MSTATUS CERT_STORE_findIdentityByAliasAndAlgo (
  certStorePtr pCertStore,
  ubyte4 pubKeyType,
  ubyte2 keyUsage,
  ubyte4 *pSupportedCertKeyAlgos,
  ubyte4 supportedCertKeyAlgosLen,
  ubyte4 *pSupportedSignAlgos,
  ubyte4 supportedSignAlgosLen,
  ubyte *pAlias,
  ubyte4 aliasLen,
  struct AsymmetricKey **ppReturnIdentityKey,
  struct SizedBuffer **ppRetCertificates,
  ubyte4 *pRetNumCertificates,
  void **ppRetHint
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  sbyte4 cmpResult;
  ubyte4 indexT;
  certStore *pStore = (certStore *) pCertStore;
  identityPair *pCurrent, *pNext;
  ubyte4 authType = 0;
  ubyte4          i = 0;
  byteBoolean     certAlgoOK = TRUE;
  byteBoolean     signAlgoOK = TRUE;
  ubyte4          tempId = 0;

  if ( (NULL == pCertStore) || (NULL == pAlias) || (0 == aliasLen) ||
       (NULL == pSupportedCertKeyAlgos && supportedCertKeyAlgosLen) || (NULL == pSupportedSignAlgos && supportedSignAlgosLen) )
    goto exit;

  /* Init the returns to NULL/0.
   */
  if (NULL != ppReturnIdentityKey)
    *ppReturnIdentityKey = NULL;

  if (NULL != ppRetCertificates)
    *ppRetCertificates = NULL;

  if (NULL != pRetNumCertificates)
    *pRetNumCertificates = 0;

  if (NULL != ppRetHint)
    *ppRetHint = NULL;

  status = CERT_STORE_convertPubKeyTypeToCertStoreKeyType(pubKeyType, &authType);
  if (OK != status)
    goto exit;

  /* Cycle through all the identity pairs of this authtype. Check for the alias. If it is there,
   * return the key and cert.
   */
  for (indexT = 0; indexT < CERT_STORE_IDENTITY_TYPE_ARRAY_SIZE; ++indexT)
  {
      pNext = pStore->pIdentityMatrixList[authType][indexT];

      while (NULL != pNext)
      {
        pCurrent = pNext;
        pNext = pCurrent->pNextIdentityKeyPair;

        /* Check the alias in this entry. Is it the same?
         */
        if (pCurrent->aliasLen != aliasLen)
          continue;

        status = DIGI_MEMCMP (
          (void *)(pCurrent->pAlias), (void *)pAlias, aliasLen, &cmpResult);
        if (OK != status)
          goto exit;

        if (0 != cmpResult)
          continue;

        /* Validate the keyUsage */
        if (keyUsage != (pCurrent->certKeyUsage & keyUsage))
        {
            /* status still OK but output pointers will be NULL */
            goto exit;
        }

        /* Validate the certAgloId is in the list of key Ids */
        if (NULL != pSupportedCertKeyAlgos)
        {
            i = 0; certAlgoOK = FALSE;
            while (i < supportedCertKeyAlgosLen)
            {
                /* Cert keys don't contain a hashAlgo Id so ignore that in case its there */
#ifdef __ENABLE_DIGICERT_PQC__
                /* hybrid or qs already don't contain a hashAlgo Id so do nothing in that case */
                if (akt_hybrid != (pSupportedCertKeyAlgos[i] >> 24) && akt_qs != (pSupportedCertKeyAlgos[i] >> 24))
                {
                    tempId = pSupportedCertKeyAlgos[i] & CERT_STORE_ALGO_ID_MASK_REMOVE_HASH_MASK;
                }
                else
                {
                    tempId = pSupportedCertKeyAlgos[i];
                }
#else
                tempId = pSupportedCertKeyAlgos[i] & CERT_STORE_ALGO_ID_MASK_REMOVE_HASH_MASK;
#endif
                if (pCurrent->certAlgoId == tempId)
                {
                    certAlgoOK = TRUE;
                    break;  /*inner while loop */
                }
                i++;
            }
        }

        /* Validate the certAgloId is in the list of alg Ids */
        if (NULL != pSupportedSignAlgos)
        {
            i = 0; signAlgoOK = FALSE;
            while (i < supportedSignAlgosLen)
            {
                /* Sign Algo for ECDSA does not contain a curve so ignore those bits */
                if (akt_ecc == (pSupportedSignAlgos[i] >> 24))
                {
                    tempId = pSupportedSignAlgos[i] & CERT_STORE_ALGO_ID_MASK_REMOVE_CURVE_MASK;
                }
                else
                {
                    tempId = pSupportedSignAlgos[i];
                }

                if (pCurrent->signAlgoId == tempId)
                {
                    signAlgoOK = TRUE;
                    break;  /*inner while loop */
                }
                i++;
            }
        }

        if (certAlgoOK && signAlgoOK)
        {
            /* We have a match.
            */
            if (NULL != ppReturnIdentityKey)
               *ppReturnIdentityKey = &(pCurrent->identityKey);

            if (0 != pCurrent->numCertificate)
            {
                if (NULL != ppRetCertificates)
                    *ppRetCertificates = pCurrent->certificates;

                if (NULL != pRetNumCertificates)
                    *pRetNumCertificates = pCurrent->numCertificate;
            }

            if (ppRetHint)
                *ppRetHint = (void *) pCurrent;
        }

        /* alias matched but whether in lists or not, goto exit in either case */
        goto exit;
    }
  }

exit:

  return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS CERT_STORE_getIdentityPairExtData (
  void *pIdentity,
  ExtendedDataCallback *pExtDataFunc,
  sbyte4 *pExtDataIdentifier
)
{
    identityPair *pId;
    MSTATUS status;

    if ((NULL == pIdentity) || (NULL == pExtDataFunc) || (NULL == pExtDataIdentifier))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pExtDataFunc = NULL;
    *pExtDataIdentifier = 0;

    pId = (identityPair *)pIdentity;

    if (NULL != pId->extData.extDataFunc)
    {
        *pExtDataFunc = pId->extData.extDataFunc;
        *pExtDataIdentifier = pId->extData.extDataIdentifier;
    }

    status = OK;

exit:
    return status;
}

/*------------------------------------------------------------------*/

static void CERT_STORE_freeIndentityPair(identityPair **ppIdentity)
{
    sbyte4 k;

    if (NULL != ppIdentity && NULL != *ppIdentity)
    {
        CRYPTO_uninitAsymmetricKey(&((*ppIdentity)->identityKey), NULL);
        DIGI_FREE((void **) &((*ppIdentity)->pAlias));
        if (NULL != (*ppIdentity)->certificates)
        {
            for (k = 0; k < (*ppIdentity)->numCertificate; k++)
            {
                SB_Release(&((*ppIdentity)->certificates[k]));
            }
            FREE((*ppIdentity)->certificates);
        }
        FREE(*ppIdentity);
        *ppIdentity = NULL;
    }
}

/*------------------------------------------------------------------*/

static MSTATUS CERT_STORE_updateIdentityByAliasEx (
    certStorePtr pCertStore,
    ubyte *pAlias,
    ubyte4 aliasLen,
    struct SizedBuffer *pCertChain,
    ubyte4 certChainCount,
    const ubyte *pKeyBlob,
    ubyte4 keyBlobLen,
    extendedData *pExtData
    )
{
    MSTATUS status;
    sbyte4 cmpResult = -1;
    ubyte4 indexA, indexT;
    certStore *pStore = (certStore *)pCertStore;
    identityPair *pCurrent = NULL, *pNext, *pPrevious;
    identityPair **ppListHead;

    status = ERR_NULL_POINTER;
    if ( (NULL == pCertStore) || (NULL == pAlias) || (0 == aliasLen) ||
         (NULL == pCertChain) || (0 == certChainCount) )
        goto exit;

    /* Cycle through all the identity pairs. Check for the alias.
     */
    for (indexA = 0; indexA < CERT_STORE_AUTH_TYPE_ARRAY_SIZE; ++indexA)
    {
        for (indexT = 0; indexT < CERT_STORE_IDENTITY_TYPE_ARRAY_SIZE; ++indexT)
        {
            pPrevious = NULL;
            pNext = pStore->pIdentityMatrixList[indexA][indexT];
            ppListHead = &(pStore->pIdentityMatrixList[indexA][indexT]);

            while (NULL != pNext)
            {
                pCurrent = pNext;
                pNext = pCurrent->pNextIdentityKeyPair;

                if (pCurrent->aliasLen == aliasLen)
                {
                    status = DIGI_MEMCMP (
                        (void *)(pCurrent->pAlias), (void *)pAlias, aliasLen, &cmpResult);
                    if (OK != status)
                        goto exit;

                    /* Found alias. Exit out of while and double for loops */
                    if (0 == cmpResult)
                    {
                        indexA = CERT_STORE_AUTH_TYPE_ARRAY_SIZE;
                        indexT = CERT_STORE_IDENTITY_TYPE_ARRAY_SIZE;
                        break;
                    }
                }

                pPrevious = pCurrent;
            }
        }
    }

    if (0 == cmpResult)
    {
        /* If there is a previous identity, update it to point to the identity
         * after the current one that is being deleted.
         *
         * If there is no previous identity then the current node must be the
         * head, set the head to next identity pair. */
        if (NULL != pPrevious)
        {
            pPrevious->pNextIdentityKeyPair = pNext;
        }
        else
        {
            *ppListHead = pNext;
        }

        CERT_STORE_removeIdentityPairFromCertHashTable(pCertStore, pCurrent);
        CERT_STORE_freeIndentityPair(&pCurrent);
    }

    /* Add the identity pair */
    if (NULL != pExtData)
    {
        status = CERT_STORE_addIdentityWithCertificateChainExtDataEx(
            pCertStore, pAlias, aliasLen, pCertChain, certChainCount,
            pKeyBlob, keyBlobLen, pExtData->extDataFunc, pExtData->extDataIdentifier);
    }
    else
    {
        status = CERT_STORE_addIdentityWithCertificateChainEx(
            pCertStore, pAlias, aliasLen, pCertChain, certChainCount,
            pKeyBlob, keyBlobLen);
    }

exit:

    return (status);
}

/*------------------------------------------------------------------*/

extern MSTATUS CERT_STORE_updateIdentityByAliasExtData (
    certStorePtr pCertStore,
    ubyte *pAlias,
    ubyte4 aliasLen,
    struct SizedBuffer *pCertChain,
    ubyte4 certChainCount,
    const ubyte *pKeyBlob,
    ubyte4 keyBlobLen,
    ExtendedDataCallback extDataFunc,
    sbyte4 extDataIdentifier
    )
{
    extendedData extData;
    extData.extDataFunc = extDataFunc;
    extData.extDataIdentifier = extDataIdentifier;
    return CERT_STORE_updateIdentityByAliasEx(pCertStore, pAlias, aliasLen, pCertChain,
        certChainCount, pKeyBlob, keyBlobLen, &extData);
}

/*------------------------------------------------------------------*/


extern MSTATUS CERT_STORE_updateIdentityByAlias (
    certStorePtr pCertStore,
    ubyte *pAlias,
    ubyte4 aliasLen,
    struct SizedBuffer *pCertChain,
    ubyte4 certChainCount,
    const ubyte *pKeyBlob,
    ubyte4 keyBlobLen
    )
{
    return CERT_STORE_updateIdentityByAliasEx(pCertStore, pAlias, aliasLen, pCertChain,
        certChainCount, pKeyBlob, keyBlobLen, NULL);
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CERT_STORE_findIdentityByAliasEx (
  certStorePtr pCertStore,
  ubyte *pAlias,
  ubyte4 aliasLen,
  struct AsymmetricKey **ppReturnIdentityKey,
  struct SizedBuffer **ppRetCertificates,
  ubyte4 *pRetNumCertificates
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  ubyte4 indexA, indexT;
  certStore *pStore = (certStore *)pCertStore;
  identityPair *pCurrent, *pNext;

  status = ERR_NULL_POINTER;
  if ( (NULL == pCertStore) || (NULL == pAlias) || (0 == aliasLen)  )
    goto exit;

  /* Init the returns to NULL/0.
   */
  if (NULL != ppReturnIdentityKey)
    *ppReturnIdentityKey = NULL;

  if (NULL != ppRetCertificates)
    *ppRetCertificates = NULL;

  if (NULL != pRetNumCertificates)
    *pRetNumCertificates = 0;

  /* Cycle through all the identity pairs. Check for the alias. If it is there,
   * return the key and cert.
   */
  for (indexA = 0; indexA < CERT_STORE_AUTH_TYPE_ARRAY_SIZE; ++indexA)
  {
    for (indexT = 0; indexT < CERT_STORE_IDENTITY_TYPE_ARRAY_SIZE; ++indexT)
    {
      pNext = pStore->pIdentityMatrixList[indexA][indexT];

      while (NULL != pNext)
      {
        pCurrent = pNext;
        pNext = pCurrent->pNextIdentityKeyPair;

        /* Check the alias in this entry. Is it the same?
         */
        if (pCurrent->aliasLen != aliasLen)
          continue;

        status = DIGI_MEMCMP (
          (void *)(pCurrent->pAlias), (void *)pAlias, aliasLen, &cmpResult);
        if (OK != status)
          goto exit;

        if (0 != cmpResult)
          continue;

        /* We have a match.
         */
        if (NULL != ppReturnIdentityKey)
          *ppReturnIdentityKey = &(pCurrent->identityKey);
        if (0 != pCurrent->numCertificate)
        {
          if (NULL != ppRetCertificates)
            *ppRetCertificates = pCurrent->certificates;

          if (NULL != pRetNumCertificates)
            *pRetNumCertificates = pCurrent->numCertificate;
        }

        goto exit;
      }
    }
  }

  /* If we went through the entire list and found no match, we're done, no need
   * to do anything. We already init the return values to NULL/0.
   */
  status = OK;

exit:

  return (status);
}

/*------------------------------------------------------------------*/

/**
@todo_64
@ingroup    cert_store_functions
*/
extern MSTATUS
CERT_STORE_findIdentityByTypeFirst(const certStorePtr pCertStore,
                                   enum authTypes authType, enum identityTypes identityType,
                                   const AsymmetricKey** ppRetIdentityKey,
                                   const ubyte **ppRetDerCert,
                                   ubyte4 *pRetDerCertLength,
                                   void** ppRetHint)
{
    identityPair*   pIdentityPair;
    MSTATUS         status = OK;

    if (NULL == pCertStore)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != (pIdentityPair = pCertStore->pIdentityMatrixList[authType][identityType]))
    {
        if (ppRetIdentityKey)
            *ppRetIdentityKey  = &(pIdentityPair->identityKey);

        if (ppRetDerCert)
            *ppRetDerCert      = pIdentityPair->numCertificate > 0? pIdentityPair->certificates[0].data : NULL;

        if (pRetDerCertLength)
            *pRetDerCertLength = pIdentityPair->numCertificate > 0? pIdentityPair->certificates[0].length : 0;
    }
    else
    {
        if (ppRetIdentityKey)
            *ppRetIdentityKey  = NULL;

        if (ppRetDerCert)
            *ppRetDerCert      = NULL;

        if (pRetDerCertLength)
            *pRetDerCertLength = 0;
    }

    if (ppRetHint)
        *ppRetHint = pIdentityPair;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/**
@todo_64
@version 6.4 and later
@ingroup    cert_store_functions
*/
extern MSTATUS
CERT_STORE_findIdentityByTypeNext(const certStorePtr pCertStore,
                                  enum authTypes authType,
                                  enum identityTypes identityType,
                                  const AsymmetricKey** ppRetIdentityKey,
                                  const ubyte **ppRetDerCert,
                                  ubyte4 *pRetDerCertLength,
                                  void** ppRetHint)
{
    identityPair*   pIdentityPair;
    MSTATUS         status = OK;
    MOC_UNUSED(authType);
    MOC_UNUSED(identityType);

    if ((NULL == pCertStore) || (NULL == ppRetHint))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (ppRetIdentityKey)
        *ppRetIdentityKey  = NULL;

    if (ppRetDerCert)
        *ppRetDerCert      = NULL;

    if (pRetDerCertLength)
        *pRetDerCertLength = 0;

    if (NULL == *ppRetHint)
        goto exit;          /* nothing to continue from */

    pIdentityPair = (identityPair*) *ppRetHint;
    pIdentityPair = pIdentityPair->pNextIdentityKeyPair;

    if (NULL != pIdentityPair)
    {
        if (ppRetIdentityKey)
        {
            *ppRetIdentityKey  = &(pIdentityPair->identityKey);
        }

        if (ppRetDerCert)
        {
            *ppRetDerCert      = pIdentityPair->numCertificate > 0? pIdentityPair->certificates[0].data : NULL;
        }

        if (pRetDerCertLength)
        {
            *pRetDerCertLength = pIdentityPair->numCertificate > 0? pIdentityPair->certificates[0].length : 0;
        }
    }

    *ppRetHint = pIdentityPair;

exit:
    return status;
}

/*------------------------------------------------------------------*/

/* find an identity certificate by type:the following is only applicable to identityTypes == IDENTITY_TYPE_CERT_X509_V3  */
/**
@todo_64
@ingroup    cert_store_functions
*/
extern MSTATUS
CERT_STORE_findIdentityCertChainFirst(const certStorePtr pCertStore,
                                      ubyte4 pubKeyType,
                                      ubyte4 supportedAlgoFlags,
                                      const struct AsymmetricKey** ppRetIdentityKey,
                                      const SizedBuffer** ppRetCertificates,
                                      ubyte4 *pRetNumberCertificate,
                                      void** ppRetHint)
{
    return CERT_STORE_findIdentityCertChainFirstEx(pCertStore,
                                                   pubKeyType,
                                                   0,
                                                   supportedAlgoFlags,
                                                   ppRetIdentityKey,
                                                   ppRetCertificates,
                                                   pRetNumberCertificate,
                                                   ppRetHint);
}

/*------------------------------------------------------------------*/

/**
@todo_64
@ingroup    cert_store_functions
*/
extern MSTATUS
CERT_STORE_findIdentityCertChainNext(const certStorePtr pCertStore,
                                     ubyte4 pubKeyType,
                                     ubyte4 supportedAlgoFlags,
                                     const struct AsymmetricKey** ppRetIdentityKey,
                                     const SizedBuffer** ppRetCertificates,
                                     ubyte4 *pRetNumberCertificate,
                                     void** ppRetHint)
{
    return CERT_STORE_findIdentityCertChainNextEx(pCertStore,
                                                  pubKeyType,
                                                  0,
                                                  supportedAlgoFlags,
                                                  ppRetIdentityKey,
                                                  ppRetCertificates,
                                                  pRetNumberCertificate,
                                                  ppRetHint);
}


/*------------------------------------------------------------------*/

/* find an identity certificate by type:the following is only applicable to identityTypes == IDENTITY_TYPE_CERT_X509_V3  */
/**
@todo_64
@ingroup    cert_store_functions
*/
extern MSTATUS
CERT_STORE_findIdentityCertChainFirstEx(const certStorePtr pCertStore,
                                        ubyte4 pubKeyType,
                                        ubyte2 keyUsage,
                                        ubyte4 supportedAlgoFlags,
                                        const struct AsymmetricKey** ppRetIdentityKey,
                                        const SizedBuffer** ppRetCertificates,
                                        ubyte4 *pRetNumberCertificate,
                                        void** ppRetHint)
{
    identityPair*   pIdentityPair;
    ubyte4          authType;
    MSTATUS         status = OK;

    if (NULL == pCertStore || NULL == ppRetIdentityKey ||
        NULL == ppRetCertificates || NULL == pRetNumberCertificate)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* initialize */
    *ppRetIdentityKey       = NULL;
    *ppRetCertificates      = NULL;
    *pRetNumberCertificate  = 0;
    if (ppRetHint)
    {
        *ppRetHint = NULL;
    }

    if (OK > (status = CERT_STORE_convertPubKeyTypeToCertStoreKeyType(pubKeyType, &authType)))
        goto exit;

    pIdentityPair = pCertStore->pIdentityMatrixList[authType][CERT_STORE_IDENTITY_TYPE_CERT_X509_V3];
    while (pIdentityPair)
    {
        /* check whether the cert algos flags falls into the supported algo flags */
        if ((keyUsage == (pIdentityPair->certKeyUsage & keyUsage)) &&
            (pIdentityPair->certAlgoFlags & supportedAlgoFlags & CERT_STORE_ALGO_FLAG_SIGNKEYTYPE) &&
            (pIdentityPair->certAlgoFlags & supportedAlgoFlags & CERT_STORE_ALGO_FLAG_HASHALGO) &&
            ( !(pIdentityPair->certAlgoFlags & CERT_STORE_ALGO_FLAG_ECCURVES) ||
             (pIdentityPair->certAlgoFlags & supportedAlgoFlags & CERT_STORE_ALGO_FLAG_ECCURVES)) )
        {
            *ppRetIdentityKey       = &pIdentityPair->identityKey;
            *ppRetCertificates      = pIdentityPair->certificates;
            *pRetNumberCertificate  = pIdentityPair->numCertificate;
            break;
        }
        pIdentityPair = pIdentityPair->pNextIdentityKeyPair;
    }

    if (ppRetHint)
        *ppRetHint = pIdentityPair;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/**
@todo_64
@version 6.4 and later
@ingroup    cert_store_functions
*/
extern MSTATUS
CERT_STORE_findIdentityCertChainNextEx(const certStorePtr pCertStore,
                                       ubyte4 pubKeyType,
                                       ubyte2 keyUsage,
                                       ubyte4 supportedAlgoFlags,
                                       const struct AsymmetricKey** ppRetIdentityKey,
                                       const SizedBuffer** ppRetCertificates,
                                       ubyte4 *pRetNumberCertificate,
                                       void** ppRetHint)
{
    identityPair*   pIdentityPair;
    MSTATUS         status = OK;
    MOC_UNUSED(pubKeyType);

    if ((NULL == pCertStore) || (NULL == ppRetHint) ||
        (NULL == ppRetIdentityKey) || (NULL == ppRetCertificates) ||
        (NULL == pRetNumberCertificate))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppRetIdentityKey       = NULL;
    *ppRetCertificates      = NULL;
    *pRetNumberCertificate  = 0;

    if (NULL == *ppRetHint)
    {
        goto exit;          /* nothing to continue from */
    }

    pIdentityPair = (identityPair*) *ppRetHint;
    pIdentityPair = pIdentityPair->pNextIdentityKeyPair;

    while (NULL != pIdentityPair)
    {
        /* check whether the cert algos flags falls into the supported algo flags */
        if ((keyUsage == (pIdentityPair->certKeyUsage & keyUsage)) &&
            (pIdentityPair->certAlgoFlags & supportedAlgoFlags & CERT_STORE_ALGO_FLAG_SIGNKEYTYPE) &&
            (pIdentityPair->certAlgoFlags & supportedAlgoFlags & CERT_STORE_ALGO_FLAG_HASHALGO) &&
            ( !(pIdentityPair->certAlgoFlags & CERT_STORE_ALGO_FLAG_ECCURVES) ||
             (pIdentityPair->certAlgoFlags & supportedAlgoFlags & CERT_STORE_ALGO_FLAG_ECCURVES)) )
        {
            *ppRetIdentityKey       = &pIdentityPair->identityKey;
            *ppRetCertificates      = pIdentityPair->certificates;
            *pRetNumberCertificate  = pIdentityPair->numCertificate;
            break;
        }
        pIdentityPair = pIdentityPair->pNextIdentityKeyPair;
    }
    *ppRetHint = pIdentityPair;

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS CERT_STORE_findIdentityCertChainFirstFromList(
    const certStorePtr pCertStore,
    ubyte4 pubKeyType,
    ubyte2 keyUsage,
    ubyte4 *pSupportedCertKeyIds,
    ubyte4 supportedCertKeyIdsLen,
    ubyte4 *pSupportedSignAlgoIds,
    ubyte4 supportedSignAlgoIdsLen,
    const struct AsymmetricKey** ppRetIdentityKey,
    const struct SizedBuffer** ppRetCertificates,
    ubyte4 *pRetNumberCertificate,
    void** ppRetHint)
{
    identityPair*   pIdentityPair = NULL;
    ubyte4          authType = 0;
    MSTATUS         status = OK;
    ubyte4          i = 0;
    byteBoolean     certAlgoOK = FALSE;
    byteBoolean     signAlgoOK = FALSE;
    ubyte4          tempId = 0;

    if (NULL == pCertStore || NULL == ppRetIdentityKey ||
        NULL == ppRetCertificates || NULL == pRetNumberCertificate ||
        (NULL == pSupportedCertKeyIds && supportedCertKeyIdsLen) ||
        (NULL == pSupportedSignAlgoIds && supportedSignAlgoIdsLen) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* initialize */
    *ppRetIdentityKey       = NULL;
    *ppRetCertificates      = NULL;
    *pRetNumberCertificate  = 0;
    if (ppRetHint)
    {
        *ppRetHint = NULL;
    }

    if (OK > (status = CERT_STORE_convertPubKeyTypeToCertStoreKeyType(pubKeyType, &authType)))
        goto exit;

    pIdentityPair = pCertStore->pIdentityMatrixList[authType][CERT_STORE_IDENTITY_TYPE_CERT_X509_V3];
    while (pIdentityPair)
    {
        /* check first the keyUsage */
        if (keyUsage == (pIdentityPair->certKeyUsage & keyUsage))
        {
            certAlgoOK = FALSE;
            signAlgoOK = FALSE;

            if (NULL == pSupportedCertKeyIds)  /* Don't need to verify support */
            {
                 certAlgoOK = TRUE;
            }
            else
            {
                i = 0;
                while (i < supportedCertKeyIdsLen)
                {
                    /* Cert keys don't contain a hashAlgo Id so ignore that in case its there */
#ifdef __ENABLE_DIGICERT_PQC__
                    /* hybrid already didn't contain a hashAlgo Id so do nothing in that case */
                    if (akt_hybrid != (pSupportedCertKeyIds[i] >> 24) && akt_qs != (pSupportedCertKeyIds[i] >> 24))
                    {
                        tempId = pSupportedCertKeyIds[i] & CERT_STORE_ALGO_ID_MASK_REMOVE_HASH_MASK;
                    }
                    else
                    {
                        tempId = pSupportedCertKeyIds[i];
                    }
#else
                    tempId = pSupportedCertKeyIds[i] & CERT_STORE_ALGO_ID_MASK_REMOVE_HASH_MASK;
#endif
                    if (pIdentityPair->certAlgoId == tempId)
                    {
                        certAlgoOK = TRUE;
                        break;  /*inner while loop */
                    }

                    i++;
                }
            }

            if (NULL == pSupportedSignAlgoIds)  /* Don't need to verify support */
            {
                 signAlgoOK = TRUE;
            }
            else
            {
                i = 0;
                while (i < supportedSignAlgoIdsLen)
                {
                    /* Sign Algo for ECDSA does not contain a curve so ignore those bits */
                    if (akt_ecc == (pSupportedSignAlgoIds[i] >> 24))
                    {
                        tempId = pSupportedSignAlgoIds[i] & CERT_STORE_ALGO_ID_MASK_REMOVE_CURVE_MASK;
                    }
                    else
                    {
                        tempId = pSupportedSignAlgoIds[i];
                    }

                    if (pIdentityPair->signAlgoId == tempId)
                    {
                        signAlgoOK = TRUE;
                        break;  /*inner while loop */
                    }

                    i++;
                }
            }

            if (certAlgoOK && signAlgoOK)
            {
                *ppRetIdentityKey       = &pIdentityPair->identityKey;
                *ppRetCertificates      = pIdentityPair->certificates;
                *pRetNumberCertificate  = pIdentityPair->numCertificate;

                break; /* outer while loop */
            }
        }

        pIdentityPair = pIdentityPair->pNextIdentityKeyPair;
    }

    if (ppRetHint)
        *ppRetHint = pIdentityPair;

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS CERT_STORE_findIdentityCertChainNextFromList(
    const certStorePtr pCertStore,
    ubyte4 pubKeyType,
    ubyte2 keyUsage,
    ubyte4 *pSupportedCertKeyIds,
    ubyte4 supportedCertKeyIdsLen,
    ubyte4 *pSupportedSignAlgoIds,
    ubyte4 supportedSignAlgoIdsLen,
    const struct AsymmetricKey** ppRetIdentityKey,
    const struct SizedBuffer** ppRetCertificates,
    ubyte4 *pRetNumberCertificate,
    void** ppRetHint)
{
    identityPair*   pIdentityPair = NULL;
    MSTATUS         status = OK;
    ubyte4          i = 0;
    byteBoolean     certAlgoOK = FALSE;
    byteBoolean     signAlgoOK = FALSE;
    ubyte4          tempId = 0;
    MOC_UNUSED(pubKeyType);

    if (NULL == pCertStore || NULL == ppRetIdentityKey ||
        NULL == ppRetCertificates || NULL == pRetNumberCertificate || NULL == ppRetHint ||
        (NULL == pSupportedCertKeyIds && supportedCertKeyIdsLen) ||
        (NULL == pSupportedSignAlgoIds && supportedSignAlgoIdsLen) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* initialize */
    *ppRetIdentityKey       = NULL;
    *ppRetCertificates      = NULL;
    *pRetNumberCertificate  = 0;
    if (NULL == *ppRetHint)
    {
        goto exit;   /* can't possibly find any certs so return OK with NULL in output params */
    }

    pIdentityPair = (identityPair *) *ppRetHint;
    pIdentityPair = pIdentityPair->pNextIdentityKeyPair;

    while (pIdentityPair)
    {
        /* check first the keyUsage */
        if (keyUsage == (pIdentityPair->certKeyUsage & keyUsage))
        {
            certAlgoOK = FALSE;
            signAlgoOK = FALSE;

            if (NULL == pSupportedCertKeyIds)  /* Don't need to verify support */
            {
                 certAlgoOK = TRUE;
            }
            else
            {
                i = 0;
                while (i < supportedCertKeyIdsLen)
                {
                    /* Cert keys don't contain a hashAlgo Id so ignore that in case its there */
#ifdef __ENABLE_DIGICERT_PQC__
                    /* hybrid already didn't contain a hashAlgo Id so do nothing in that case */
                    if (akt_hybrid != (pSupportedCertKeyIds[i] >> 24) && akt_qs != (pSupportedCertKeyIds[i] >> 24))
                    {
                        tempId = pSupportedCertKeyIds[i] & CERT_STORE_ALGO_ID_MASK_REMOVE_HASH_MASK;
                    }
                    else
                    {
                        tempId = pSupportedCertKeyIds[i];
                    }
#else
                    tempId = pSupportedCertKeyIds[i] & CERT_STORE_ALGO_ID_MASK_REMOVE_HASH_MASK;
#endif
                    if (pIdentityPair->certAlgoId == tempId)
                    {
                        certAlgoOK = TRUE;
                        break;  /*inner while loop */
                    }

                    i++;
                }
            }

            if (NULL == pSupportedSignAlgoIds)  /* Don't need to verify support */
            {
                 signAlgoOK = TRUE;
            }
            else
            {
                i = 0;
                while (i < supportedSignAlgoIdsLen)
                {
                    /* Sign Algo for ECDSA does not contain a curve so ignore those bits */
                    if (akt_ecc == (pSupportedSignAlgoIds[i] >> 24))
                    {
                        tempId = pSupportedSignAlgoIds[i] & CERT_STORE_ALGO_ID_MASK_REMOVE_CURVE_MASK;
                    }
                    else
                    {
                        tempId = pSupportedSignAlgoIds[i];
                    }

                    if (pIdentityPair->signAlgoId == tempId)
                    {
                        signAlgoOK = TRUE;
                        break;  /*inner while loop */
                    }

                    i++;
                }
            }

            if (certAlgoOK && signAlgoOK)
            {
                *ppRetIdentityKey       = &pIdentityPair->identityKey;
                *ppRetCertificates      = pIdentityPair->certificates;
                *pRetNumberCertificate  = pIdentityPair->numCertificate;
                break; /* outer while loop */
            }
        }

        pIdentityPair = pIdentityPair->pNextIdentityKeyPair;
    }

    *ppRetHint = pIdentityPair;

exit:

    return status;
}

/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
CERT_STORE_traversePskListHead(const certStorePtr pCertStore,
                               ubyte **ppRetPskIdentity, ubyte4 *pRetPskIdentityLength,
                               ubyte **ppRetPskHint, ubyte4 *pRetPskHintLength,
                               ubyte **ppRetPskSecret, ubyte4 *pRetPskSecretLength,
                               void** ppRetHint)
{
    identityPskTuple*   pIdentityPskTuple;
    MSTATUS             status = OK;

    if (NULL == pCertStore)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != (pIdentityPskTuple = pCertStore->pIdentityPskList))
    {
        if (ppRetPskIdentity)
            *ppRetPskIdentity      = pIdentityPskTuple->pPskIdentity;

        if (pRetPskIdentityLength)
            *pRetPskIdentityLength = pIdentityPskTuple->pskIdentityLength;

        if (ppRetPskHint)
            *ppRetPskHint = pIdentityPskTuple->pPskHint;

        if (pRetPskHintLength)
            *pRetPskHintLength = pIdentityPskTuple->pskHintLength;

        if (ppRetPskSecret)
            *ppRetPskSecret = pIdentityPskTuple->pPskSecret;

        if (pRetPskSecretLength)
            *pRetPskSecretLength = pIdentityPskTuple->pskSecretLength;
    }
    else
    {
        if (ppRetPskIdentity)
            *ppRetPskIdentity      = NULL;

        if (pRetPskIdentityLength)
            *pRetPskIdentityLength = 0;

        if (ppRetPskHint)
            *ppRetPskHint = NULL;

        if (pRetPskHintLength)
            *pRetPskHintLength = 0;

        if (ppRetPskSecret)
            *ppRetPskSecret = NULL;

        if (pRetPskSecretLength)
            *pRetPskSecretLength = 0;
    }

    if (ppRetHint)
        *ppRetHint = pIdentityPskTuple;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
CERT_STORE_traversePskListNext(const certStorePtr pCertStore,
                               ubyte **ppRetPskIdentity, ubyte4 *pRetPskIdentityLength,
                               ubyte **ppRetPskHint, ubyte4 *pRetPskHintLength,
                               ubyte **ppRetPskSecret, ubyte4 *pRetPskSecretLength,
                               void** ppRetHint)
{
    identityPskTuple*   pIdentityPskTuple;
    MSTATUS             status = OK;

    if ((NULL == pCertStore) || (NULL == ppRetHint))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (ppRetPskIdentity)
        *ppRetPskIdentity      = NULL;

    if (pRetPskIdentityLength)
        *pRetPskIdentityLength = 0;

    if (ppRetPskHint)
        *ppRetPskHint = NULL;

    if (pRetPskHintLength)
        *pRetPskHintLength = 0;

    if (ppRetPskSecret)
        *ppRetPskSecret = NULL;

    if (pRetPskSecretLength)
        *pRetPskSecretLength = 0;

    if (NULL == *ppRetHint)
        goto exit;          /* nothing to continue from */

    pIdentityPskTuple = (identityPskTuple*) *ppRetHint;
    pIdentityPskTuple = pIdentityPskTuple->pNextIdentityPskTuple;

    if (NULL != pIdentityPskTuple)
    {
        if (ppRetPskIdentity)
            *ppRetPskIdentity      = pIdentityPskTuple->pPskIdentity;

        if (pRetPskIdentityLength)
            *pRetPskIdentityLength = pIdentityPskTuple->pskIdentityLength;

        if (ppRetPskHint)
            *ppRetPskHint = pIdentityPskTuple->pPskHint;

        if (pRetPskHintLength)
            *pRetPskHintLength = pIdentityPskTuple->pskHintLength;

        if (ppRetPskSecret)
            *ppRetPskSecret = pIdentityPskTuple->pPskSecret;

        if (pRetPskSecretLength)
            *pRetPskSecretLength = pIdentityPskTuple->pskSecretLength;
    }

    *ppRetHint = pIdentityPskTuple;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for future use, and should not be included in
 * the API documentation.
 */
extern MSTATUS
CERT_STORE_findPskByIdentity(const certStorePtr pCertStore,
                             ubyte *pPskIdentity, ubyte4 pskIdentityLength,
                             ubyte **ppRetPskSecret, ubyte4 *pRetPskSecretLength)
{
    sbyte4              compareResults;
    identityPskTuple*   pIdentityPskTuple;
    MSTATUS             status = OK;

    if ((NULL == pCertStore) || (NULL == pPskIdentity) || (NULL == ppRetPskSecret) || (NULL == pRetPskSecretLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppRetPskSecret      = NULL;
    *pRetPskSecretLength = 0;

    pIdentityPskTuple = pCertStore->pIdentityPskList;

    while (NULL != pIdentityPskTuple)
    {
        if ((pIdentityPskTuple->pskIdentityLength == pskIdentityLength) &&
            (OK <= DIGI_MEMCMP(pIdentityPskTuple->pPskIdentity, pPskIdentity, pskIdentityLength, &compareResults)) &&
            (0 == compareResults) )
        {
            break;
        }

        pIdentityPskTuple = pIdentityPskTuple->pNextIdentityPskTuple;
    }

    if (NULL != pIdentityPskTuple)
    {
        *ppRetPskSecret      = pIdentityPskTuple->pPskSecret;
        *pRetPskSecretLength = pIdentityPskTuple->pskSecretLength;
    }

exit:
    return status;
}

#if !defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__)

/*------------------------------------------------------------------*/

/**
@todo_64
@ingroup    cert_store_functions
*/
extern MSTATUS
CERT_STORE_findCertificateByIssuerSerialNumber(const certStorePtr pCertStore,
                                               const ubyte* pIssuer,
                                               ubyte4 issuerLength,
                                               const ubyte* serialNumber,
                                               ubyte4 serialNumberLength,
                                               const ubyte** ppRetDerCert,
                                               ubyte4* ppRetDerCertLength,
                                               const struct AsymmetricKey** ppRetPrivateKey)
{
    certificateEntry*   pCertEntry = NULL;
    issuerSerialPair    issuerSerial;
    ubyte4              hashValue;
    intBoolean          foundHashValue;
    MSTATUS             status = OK;

    if ((NULL == pCertStore) || (NULL == pIssuer) || (NULL == serialNumber))
    {
        /* the [out] params can be null */
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* clear out return values if provided */

    if (ppRetDerCert)
    {
        *ppRetDerCert = 0;
    }

    if (ppRetDerCertLength)
    {
        *ppRetDerCertLength = 0;
    }

    if (ppRetPrivateKey)
    {
        *ppRetPrivateKey = 0;
    }

    /* calculate hash for serial number */
    HASH_VALUE_hashGen(serialNumber, serialNumberLength,
                       MOCANA_CERT_STORE_INIT_HASH_VALUE, &hashValue);

    issuerSerial.pIssuer            = pIssuer;
    issuerSerial.issuerLength       = issuerLength;
    issuerSerial.serialNumber       = serialNumber;
    issuerSerial.serialNumberLength = serialNumberLength;

    /* look up subject in certificate store */
    if (OK > (status = HASH_TABLE_findPtr(pCertStore->pCertHashTable,
                                          hashValue,
                                          (void *)&issuerSerial,
                                          CERT_STORE_testIssuerSerialNumber,
                                          (void **)&pCertEntry,
                                          &foundHashValue)))
    {
        goto exit;
    }

    if ((TRUE != foundHashValue) || (NULL == pCertEntry))
    {
        status = ERR_NOT_FOUND;
        goto exit;
    }

    /* found it, and pCertEntry pointer is good */
    status = CERT_STORE_getCertificateEntryData(pCertEntry,
                                                ppRetDerCert,
                                                ppRetDerCertLength,
                                                ppRetPrivateKey);
exit:
    return status;

}


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
CERT_STORE_PKCS7_GetPrivateKey(const void* arg, CStream cs,
                               struct ASN1_ITEM* pSerialNumber,
                               struct ASN1_ITEM* pIssuer,
                               struct AsymmetricKey* pKey)
{
    MSTATUS status;
    certStorePtr pCertStore = (certStorePtr) arg;
    const AsymmetricKey *foundKey = NULL;
    const ubyte* serialNumber = 0;
    const ubyte* issuer = 0;

    if (!pCertStore)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (!pSerialNumber || !pIssuer || !pKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    serialNumber = (const ubyte*) CS_memaccess(cs,
                                               pSerialNumber->dataOffset,
                                               pSerialNumber->length);
    issuer = (const ubyte*) CS_memaccess(cs,
                                         pIssuer->dataOffset, pIssuer->length);

    if (!serialNumber || !issuer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = CERT_STORE_findCertificateByIssuerSerialNumber(pCertStore,
                                                                      issuer,
                                                                      pIssuer->length,
                                                                      serialNumber,
                                                                      pSerialNumber->length,
                                                                      NULL,
                                                                      NULL,
                                                                      &foundKey)))
    {
        goto exit;
    }

    /* need to make a copy since the PKCS#7 stack will own the key */
    if (OK > ( status = CRYPTO_copyAsymmetricKey(pKey, foundKey)))
    {
        goto exit;
    }

exit:

    CS_stopaccess(cs, serialNumber);
    CS_stopaccess(cs, issuer);

    return status;
}


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
CERT_STORE_PKCS7_GetCertificate(const void* arg, CStream cs,
                                struct ASN1_ITEM* pSerialNumber,
                                struct ASN1_ITEM* pIssuer,
                                ubyte** ppCertificate,
                                ubyte4* certificateLength)
{
    MSTATUS status;
    certStorePtr pCertStore = (certStorePtr) arg;
    const ubyte* foundCertificate;
    const ubyte* serialNumber = 0;
    const ubyte* issuer = 0;

    if (!pCertStore)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    serialNumber = (const ubyte*) CS_memaccess(cs,
                                               pSerialNumber->dataOffset,
                                               pSerialNumber->length);
    issuer = (const ubyte*) CS_memaccess(cs,
                                         pIssuer->dataOffset, pIssuer->length);

    if (!serialNumber || !issuer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = CERT_STORE_findCertificateByIssuerSerialNumber(pCertStore,
                                                                      issuer,
                                                                      pIssuer->length,
                                                                      serialNumber,
                                                                      pSerialNumber->length,
                                                                      &foundCertificate,
                                                                      certificateLength,
                                                                      NULL)))
    {
        goto exit;
    }

    /* need to make a copy since the PKCS#7 stack will own the certificate */
    *ppCertificate = (ubyte*) MALLOC( *certificateLength);
    if (!*ppCertificate)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(*ppCertificate, foundCertificate, *certificateLength);

exit:

    CS_stopaccess(cs, serialNumber);
    CS_stopaccess(cs, issuer);

    if (ERR_NOT_FOUND == status)
    {
        status = OK;
    }
    return status;
}


/*---------------------------------------------------------------------------*/

static MSTATUS
CERT_STORE_PKCS7_matchCert( MOC_ASYM(hwAccelDescr hwAccelCtx)
                           const void* arg,
                           const ubyte* testCert, ubyte4 testCertLength)
{
    sbyte4 resCmp;

    const SizedBuffer* pCert = (SizedBuffer*) arg;

    if (pCert->length == testCertLength &&
        0 == (DIGI_MEMCMP(pCert->data, testCert, testCertLength, &resCmp), resCmp) )
    {
        return OK;
    }
    return ERR_FALSE;
}


/*---------------------------------------------------------------------------*/

static MSTATUS
CERT_STORE_PKCS7_validateLink(MOC_ASYM(hwAccelDescr hwAccelCtx)
                              const void* arg,
                              const ubyte* testCert, ubyte4 testCertLength)
{
    MSTATUS status;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pAnchorRoot;

    const validateParentArg* pVLA = (const validateParentArg*) arg;

    MF_attach(&mf, testCertLength, (ubyte*) testCert);
    CS_AttachMemFile(&cs, &mf);

    /* parse it */
    if (OK > (status = X509_parseCertificate(cs, &pAnchorRoot)))
    {
        goto exit;
    }

    status = X509_validateLink(MOC_ASYM(hwAccelCtx)
                               pVLA->pCertificate, pVLA->cs,
                               ASN1_FIRST_CHILD(pAnchorRoot), cs,
                               pVLA->chainLength);
    if (OK > status)
    {
        status = ERR_FALSE; /* let's try another one */
        goto exit;
    }

exit:

    if (pAnchorRoot)
    {
        TREE_DeleteTreeItem((TreeItem*) pAnchorRoot);
    }

    return status;

}


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
CERT_STORE_PKCS7_ValidateRootCertificate(const void* arg, CStream cs,
                                         struct ASN1_ITEM* pCertificate,
                                         sbyte4 chainLength)
{
    /* look if that certificate or the parent of it is in the cert store as
     a trust point */
    MSTATUS status;
    certStorePtr pCertStore = (certStorePtr) arg;
    const ubyte* foundCert = 0;
    ubyte4 foundCertLength = 0;
    const ubyte* dn;
    const ubyte* certData = 0;
    ASN1_ITEMPTR pDN;
    SizedBuffer sb;
    validateParentArg vpa;
    hwAccelDescr hwAccelCtx;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        return status;

    if (!pCertStore)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = X509_getCertificateSubject(pCertificate, &pDN)))
    {
        goto exit;
    }

    /* get the whole certificate buffer */
    certData = (const ubyte*) CS_memaccess(cs,
                                           pCertificate->dataOffset - pCertificate->headerSize,
                                           pCertificate->length + pCertificate->headerSize);
    if (!certData)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    dn = certData + pDN->dataOffset + pCertificate->headerSize - pCertificate->dataOffset;

    sb.data = (ubyte*) certData;
    sb.length = (pCertificate->length + pCertificate->headerSize);

    if (OK > (status = CERT_STORE_findTrustPointBySubject(MOC_ASYM(hwAccelCtx)
                                                          pCertStore,
                                                          dn,
                                                          pDN->length,
                                                          &sb,
                                                          CERT_STORE_PKCS7_matchCert,
                                                          &foundCert,
                                                          &foundCertLength)))
    {
        goto exit;
    }

    /* match ? */
    if (foundCertLength && foundCert)
    {
        status = OK;
        goto exit;
    }

    /* no match: look for its parent, then */
    if (OK > (status = X509_getCertificateIssuerSerialNumber(pCertificate, &pDN,
                                                             NULL)))
    {
        goto exit;
    }

    dn = certData + pDN->dataOffset + pCertificate->headerSize - pCertificate->dataOffset;
    vpa.pCertificate = pCertificate;
    vpa.cs = cs;
    vpa.chainLength = chainLength;

    if (OK > (status = CERT_STORE_findTrustPointBySubject(MOC_ASYM(hwAccelCtx)
                                                          pCertStore,
                                                          dn,
                                                          pDN->length,
                                                          &vpa,
                                                          CERT_STORE_PKCS7_validateLink,
                                                          &foundCert,
                                                          &foundCertLength)))
    {
        goto exit;
    }

    status = (foundCert && foundCertLength) ? OK : ERR_FALSE;

exit:

    CS_stopaccess(cs, certData);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    return status;

}

#endif
