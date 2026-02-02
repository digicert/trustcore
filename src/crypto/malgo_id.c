/*
 * malgo_id.c
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/tree.h"
#include "../common/vlong.h"
#include "../common/random.h"

#include "../asn1/parseasn1.h"
#include "../asn1/ASN1TreeWalker.h"
#include "../asn1/derencoder.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parsecert.h"

#include "../crypto/crypto.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/rsa.h"
#include "../crypto/pkcs1.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/malgo_id.h"


/* Generic OID handler methods
 */
static MSTATUS nullParams(
    ASN1_ITEMPTR pParams,
    CStream cs,
    void **ppParams
    );

static MSTATUS ignoreParams(
    ASN1_ITEMPTR pParams,
    CStream cs,
    void **ppParams
    );

#ifdef __ENABLE_DIGICERT_ECC__
/* Method(s) to handle ecPublicKey_OID
 */
static MSTATUS ecPublicKeyDeserializeParams(
    ASN1_ITEMPTR pParams,
    CStream cs,
    void **ppParams
    );

static MSTATUS ecPublicKeySerializeParams(
    DER_ITEMPTR pItem,
    void *pParams
    );

static MSTATUS ecPublicKeyCopyParams(
    void *pParams,
    void **ppParams
    );
#endif

#ifdef __ENABLE_DIGICERT_PKCS1__
/* Method(s) to handle rsaSsaPss_OID
 */
static MSTATUS rsaSsaPssDeserializeParams(
    ASN1_ITEMPTR pParams,
    CStream cs,
    void **ppParams
    );

static MSTATUS rsaSsaPssSerializeParams(
    DER_ITEMPTR pItem,
    void *pParams
    );

static MSTATUS rsaSsaPssCopyParams(
    void *pParams,
    void **ppParams
    );
#endif

/* Structure to hold OID information
 */
typedef struct
{
    const ubyte *pOid;
    AlgIdDeserializeParams deserialParams;
    AlgIdSerializeParams serialParams;
    AlgIdFreeParams freeParams;
    AlgIdCopyParams copyParams;
} MAlgoIdInfo;

/* OIDs that are currently supported. The MAlgoOid enum must match with the
 * indexes in this array of OID information.
 */
static MAlgoIdInfo pOidInfo[ALG_ID_SUPPORTED_OID_COUNT] = {
    {
#ifndef __DISABLE_DIGICERT_RSA__
        rsaEncryption_OID,
        nullParams,
#else
        NULL,
        NULL,
#endif
        NULL,
        NULL,
        NULL
    },
    {
#ifdef __ENABLE_DIGICERT_DSA__
        dsa_OID,
        ignoreParams,
#else
        NULL,
        NULL,
#endif
        NULL,
        NULL,
        NULL
    },
    {
#ifdef __ENABLE_DIGICERT_ECC__
        ecPublicKey_OID,
        ecPublicKeyDeserializeParams,
        ecPublicKeySerializeParams,
        DIGI_FREE,
        ecPublicKeyCopyParams
#else
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
#endif /* __ENABLE_DIGICERT_ECC__ */
    },
    {
#if defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__)
        ed25519sig_OID,
        ignoreParams,
        NULL,
        DIGI_FREE,
        ecPublicKeyCopyParams
#else
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
#endif /* __ENABLE_DIGICERT_ECC__ && __ENABLE_DIGICERT_ECC_EDDSA_25519__ */
    },
    {
#if defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)
        ed448sig_OID,
        ignoreParams,
        NULL,
        DIGI_FREE,
        ecPublicKeyCopyParams
#else
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
#endif /* __ENABLE_DIGICERT_ECC__ && __ENABLE_DIGICERT_ECC_EDDSA_448__*/
    },
    {
#ifdef __ENABLE_DIGICERT_PKCS1__
        rsaSsaPss_OID,
        rsaSsaPssDeserializeParams,
        rsaSsaPssSerializeParams,
        DIGI_FREE,
        rsaSsaPssCopyParams
#else
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
#endif /* __ENABLE_DIGICERT_PKCS1__ */
    }
};

/*----------------------------------------------------------------------------*/

/* Method to deserialize an algorithm identifier.
 *
 * This method takes in an OID flag and algorithm identifier and converts it
 * into the appropriate MAlgoId structure. It is expected that the caller has
 * already performed the OID check and passed in the appropriate OID flag.
 */
MOC_EXTERN MSTATUS ALG_ID_deserialize(
    MAlgoOid oidFlag,
    ASN1_ITEMPTR pAlgId,
    CStream cs,
    MAlgoId **ppRetAlgoId
    )
{
    MSTATUS status;
    ASN1_ITEMPTR pItem;
    MAlgoId *pNewAlgId = NULL;

    if ( (NULL == pAlgId) || (NULL == ppRetAlgoId) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Verify the OID is correct.
     */
    pItem = ASN1_FIRST_CHILD(pAlgId);
    status = ASN1_VerifyOID(pItem, cs, pOidInfo[oidFlag].pOid);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_CALLOC((void **) &pNewAlgId, 1, sizeof(MAlgoId));
    if (OK != status)
    {
        goto exit;
    }

    /* Set the OID pointer and OID flag.
     */
    pNewAlgId->oidFlag = oidFlag;

    /* Check for a deserialization method.
     */
    if (NULL != pOidInfo[oidFlag].deserialParams)
    {
        status = pOidInfo[oidFlag].deserialParams(
            ASN1_NEXT_SIBLING(pItem), cs, &(pNewAlgId->pParams));
    }
    else
    {
        status = ERR_NULL_POINTER;
    }
    if (OK != status)
    {
        goto exit;
    }

    *ppRetAlgoId = pNewAlgId;
    pNewAlgId = NULL;

exit:

    if (NULL != pNewAlgId)
    {
        ALG_ID_free(&pNewAlgId);
    }

    return status;
}

MOC_EXTERN MSTATUS ALG_ID_deserializeBuffer(
    MAlgoOid oidFlag,
    ubyte *pAlgId,
    ubyte4 algIdLen,
    MAlgoId **ppRetAlgoId
    )
{
    MSTATUS status;
    CStream cs;
    MemFile mf;
    ASN1_ITEMPTR pRoot = NULL;

    MF_attach(&mf, algIdLen, pAlgId);
    CS_AttachMemFile(&cs, &mf);

    status = ASN1_Parse(cs, &pRoot);
    if (OK != status)
    {
        goto exit;
    }

    status = ALG_ID_deserialize(
        oidFlag, ASN1_FIRST_CHILD(pRoot), cs, ppRetAlgoId);

exit:

    if (NULL != pRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pRoot);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

/* Method to serialize an algorithm identifier.
 *
 * This method takes in a MAlgoId structure and returns the appropriate ASN.1
 * encoding. The caller is responsible for freeing the buffer.
 */
MOC_EXTERN MSTATUS ALG_ID_serializeAlloc(
    MAlgoId *pAlgoId,
    ubyte **ppRetAlgId,
    ubyte4 *pRetAlgIdLen
    )
{
    MSTATUS status;
    DER_ITEMPTR pSequence = NULL;

    if (NULL == pAlgoId)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Create an empty sequence. This will be the algorithm identifier.
     */
    status = DER_AddSequence(NULL, &pSequence);
    if (OK != status)
    {
        goto exit;
    }

    /* Store the algorithm OID. This OID is retrieved from the MAlgoId passed
     * in by the caller. If the MAlgoId does not contain any additional
     * parameters then add a NULLTAG as the optional parameters.
     */
    status = DER_StoreAlgoOID(
        pSequence, pOidInfo[pAlgoId->oidFlag].pOid, !(pAlgoId->pParams));
    if (OK != status)
    {
        goto exit;
    }

    /* If there are parameters then there should be an appropriate serialize
     * function pointer method to serialize the parameters.
     */
    if (NULL != pAlgoId->pParams)
    {
        if (NULL != pOidInfo[pAlgoId->oidFlag].serialParams)
        {
            status = pOidInfo[pAlgoId->oidFlag].serialParams(
                DER_FIRST_CHILD(pSequence), pAlgoId->pParams);
        }
        else
        {
            status = ERR_NULL_POINTER;
        }
        if (OK != status)
        {
            goto exit;
        }
    }

    /* Serialize the data into an ASN.1 buffer.
     */
    status = DER_Serialize(
        DER_FIRST_CHILD(pSequence), ppRetAlgId, pRetAlgIdLen);

exit:

    if (NULL != pSequence)
    {
        TREE_DeleteTreeItem((TreeItem *) pSequence);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

/* Method to free the MAlgoId structure.
 */
MOC_EXTERN MSTATUS ALG_ID_free(
    MAlgoId **ppAlgoId
    )
{
    MSTATUS status = OK, fstatus;

    if ( (NULL != ppAlgoId) && (NULL != *ppAlgoId) )
    {
        if ((*ppAlgoId)->oidFlag >= ALG_ID_SUPPORTED_OID_COUNT)
        {
            status = ERR_INTERNAL_ERROR;
            goto exit;
        }

        /* If there are parameters then call the free function pointer. An error
         * is thrown if there are params but there is no method to free the
         * data.
         */
        if (NULL != (*ppAlgoId)->pParams)
        {
            if (NULL != pOidInfo[(*ppAlgoId)->oidFlag].freeParams)
            {
                status = pOidInfo[(*ppAlgoId)->oidFlag].freeParams(
                    &((*ppAlgoId)->pParams));
            }
            else
            {
                status = ERR_NULL_POINTER;
            }
        }
        fstatus = DIGI_FREE((void **) ppAlgoId);
        if (OK == status)
        {
            status = fstatus;
        }
    }

exit:
    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS createMAlgoId(
    MAlgoOid oidFlag,
    void **ppParams,
    MAlgoId **ppAlgoId
    )
{
    MSTATUS status;
    void *pDefault = NULL;

    if (NULL == ppAlgoId)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == ppParams)
    {
        ppParams = &pDefault;
    }

    status = DIGI_MALLOC((void **) ppAlgoId, sizeof(MAlgoId));
    if (OK != status)
    {
        goto exit;
    }

    (*ppAlgoId)->oidFlag = oidFlag;
    (*ppAlgoId)->pParams = *ppParams;
    *ppParams = NULL;

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS ALG_ID_copy(
    MAlgoId *pAlgoId,
    MAlgoId **ppRetAlgoId
    )
{
    MSTATUS status;
    void *pParams = NULL;

    if ( (NULL == pAlgoId) || (NULL == ppRetAlgoId) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pAlgoId->pParams)
    {
        if (NULL != pOidInfo[pAlgoId->oidFlag].copyParams)
        {
            status = pOidInfo[pAlgoId->oidFlag].copyParams(
                pAlgoId->pParams, &pParams);
        }
        else
        {
            status = ERR_NULL_POINTER;
        }
        if (OK != status)
        {
            goto exit;
        }
    }

    status = createMAlgoId(pAlgoId->oidFlag, &pParams, ppRetAlgoId);

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

/* Generic deserialization method to handle the NULLTAG. This method will verify
 * whether the parameters section of an algorithm identifier is a NULLTAG or
 * not. If it is not a NULLTAG then an error is thrown.
 */
static MSTATUS nullParams(
    ASN1_ITEMPTR pParams,
    CStream cs,
    void **ppParams
    )
{
    MSTATUS status = ERR_ASN_INVALID_DATA;
    MOC_UNUSED(cs);
    MOC_UNUSED(ppParams);

    if (NULL != pParams)
    {
        if (NULLTAG == pParams->tag)
        {
            status = OK;
        }
    }

    return status;
}

/*----------------------------------------------------------------------------*/

/* Generic deserialization method to ignore any parameters.
 */
static MSTATUS ignoreParams(
    ASN1_ITEMPTR pParams,
    CStream cs,
    void **ppParams
    )
{
    return OK;
}

/*----------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__

MOC_EXTERN MSTATUS ALG_ID_rsaEncryptionCreate(
    MAlgoId **ppAlgoId
    )
{
    return createMAlgoId(ALG_ID_RSA_ENC_OID, NULL, ppAlgoId);
}

#endif /* !__DISABLE_DIGICERT_RSA__ */

/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_DSA__

MOC_EXTERN MSTATUS ALG_ID_dsaCreate(
    MAlgoId **ppAlgoId
    )
{
    return createMAlgoId(ALG_ID_DSA_OID, NULL, ppAlgoId);
}

#endif /* __ENABLE_DIGICERT_DSA__ */

/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PKCS1__

/* Method to convert a digest ID into the appropriate digest length. This method
 * is implemented in reference to RFC 8017 (PKCS #1). Specifically to handle
 * the HashAlgorithm ASN.1 definition defined in section A.2.1. This algorithm
 * identifier is defined as the following
 *
 * HashAlgorithm ::= AlgorithmIdentifier {
 *         {OAEP-PSSDigestAlgorithms}
 *      }
 *
 * OAEP-PSSDigestAlgorithms    ALGORITHM-IDENTIFIER ::= {
 *          { OID id-sha1       PARAMETERS NULL }|
 *          { OID id-sha224     PARAMETERS NULL }|
 *          { OID id-sha256     PARAMETERS NULL }|
 *          { OID id-sha384     PARAMETERS NULL }|
 *          { OID id-sha512     PARAMETERS NULL }|
 *          { OID id-sha512-224 PARAMETERS NULL }|
 *          { OID id-sha512-256 PARAMETERS NULL },
 *          ...  -- Allows for future expansion --
 *      }
 *
 * This function is written to support id-sha1, id-sha224, id-sha256, id-sha384,
 * and id-sha512.
 */
static MSTATUS convertDigestIdToLength(
    ubyte digestId,
    ubyte4 *pLength
    )
{
    MSTATUS status = OK;

    switch (digestId)
    {
        case ht_sha1:
            *pLength = SHA1_RESULT_SIZE;
            break;

        case ht_sha224:
            *pLength = SHA224_RESULT_SIZE;
            break;

        case ht_sha256:
            *pLength = SHA256_RESULT_SIZE;
            break;

        case ht_sha384:
            *pLength = SHA384_RESULT_SIZE;
            break;

        case ht_sha512:
            *pLength = SHA512_RESULT_SIZE;
            break;

        default:
            status = ERR_INVALID_INPUT;
    }

    return status;
}

/*----------------------------------------------------------------------------*/

typedef struct
{
    const ubyte *pOid;
    ubyte digestId;
} OidIdentifier;

/*----------------------------------------------------------------------------*/

/* This method is used to convert an algorithm identifier into a digest ID. This
 * function follows RFC 8017 and only supports the digest ID specified by the
 * HashAlgorithm ASN.1 definition defined in section A.2.1.
 *
 * NOTE: id-sha512-224 and id-sha512-256 are not supported
 */
static MSTATUS convertRsaSsaPssAlgIdToDigestId(
    ASN1_ITEMPTR pItem,
    CStream cs,
    ubyte *pDigestId
    )
{
    MSTATUS status;
    OidIdentifier supportedOids[] = {
        { sha1_OID, ht_sha1 },
        { sha224_OID, ht_sha224 },
        { sha256_OID, ht_sha256 },
        { sha384_OID, ht_sha384 },
        { sha512_OID, ht_sha512 }
    };
    ubyte4 i;

    /* The caller passes in an algorithm identifier. Verify that it is indeed
     * a sequence.
     */
    status = ASN1_VerifyType(pItem, SEQUENCE);
    if (OK != status)
    {
        goto exit;
    }

    pItem = ASN1_FIRST_CHILD(pItem);

    if (NULL != pItem)
    {
        ASN1_ITEMPTR pNext = ASN1_NEXT_SIBLING(pItem);

        /* For the digest OIDs supported, none of them can be non-NULL so verify
         * that the parameters are NULL or a NULL TAG.
         */
        if (NULL != pNext)
        {
            /* validate it's a NULL tag */
            status = ASN1_VerifyType(pNext, NULLTAG);
            if (OK != status)
                goto exit;
        }
    }

    /* Check against each OID and set the appropriate digest ID flag.
     */
    for (i = 0; i < COUNTOF(supportedOids); i++)
    {
        status = ASN1_VerifyOID(pItem, cs, supportedOids[i].pOid);
        if (OK == status)
        {
            *pDigestId = supportedOids[i].digestId;
            break;
        }
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

/* Method used to deserialize RSA SSA-PSS parameters.
 *
 * This method will parse an ASN.1 RSASSA-PSS-params module defined in RFC 8017.
 * The RSA SSA-PSS parameters are defined in section A.2.3. The following ASN.1
 * structure is expected
 *
 * RSASSA-PSS-params ::= SEQUENCE {
 *      hashAlgorithm      [0] HashAlgorithm      DEFAULT sha1,
 *      maskGenAlgorithm   [1] MaskGenAlgorithm   DEFAULT mgf1SHA1,
 *      saltLength         [2] INTEGER            DEFAULT 20,
 *      trailerField       [3] TrailerField       DEFAULT trailerFieldBC
 *  }
 *
 * The RFC defines the default values for each of the parameters so it is
 * possible that the parameter field may not be provided. If the parameter
 * field is provided then it will be parsed and each value will be converted
 * into a Mocana type.
 */
static MSTATUS rsaSsaPssDeserializeParams(
    ASN1_ITEMPTR pParams,
    CStream cs,
    void **ppParams
    )
{
    MSTATUS status;
    RsaSsaPssAlgIdParams *pRsaSsaPssParams = NULL;

    /* Allocate memory for the RSA SSA-PSS structure.
     */
    status = DIGI_MALLOC(
        (void **) &pRsaSsaPssParams, sizeof(RsaSsaPssAlgIdParams));
    if (OK != status)
    {
        goto exit;
    }

    /* Set the default values.
     */
    pRsaSsaPssParams->digestId = ht_sha1;
    pRsaSsaPssParams->mgfAlgo = MOC_PKCS1_ALG_MGF1;
    pRsaSsaPssParams->mgfDigestId = ht_sha1;
    pRsaSsaPssParams->saltLen = 20;
    pRsaSsaPssParams->trailerField = 0xBC;

    /* Parse the parameters if they are available.
     */
    if (NULL != pParams)
    {
        ASN1_ITEMPTR pItem;

        status = ASN1_VerifyType(pParams, SEQUENCE);
        if (OK != status)
        {
            goto exit;
        }

        status = ASN1_GetChildWithTag(pParams, 0, &pItem);
        if (OK != status)
        {
            goto exit;
        }

        /* Handle the hashAlgorithm
         */
        if (NULL != pItem)
        {
            status = convertRsaSsaPssAlgIdToDigestId(
                pItem, cs, &(pRsaSsaPssParams->digestId));
            if (OK != status)
            {
                goto exit;
            }

            /* RFC 8017 section A.2.3 defines the salt length default value as
             * the digest length of the hashAlgorithm, therefore the salt length
             * is set during the parsing of the hashAlgorithm.
             *
             * NOTE: If the salt length is also provided explicitly in the
             * parameters then it will override this value.
             */
            status = convertDigestIdToLength(
                pRsaSsaPssParams->digestId, &(pRsaSsaPssParams->saltLen));
            if (OK != status)
            {
                goto exit;
            }
        }

        status = ASN1_GetChildWithTag(pParams, 1, &pItem);
        if (OK != status)
        {
            goto exit;
        }

        /* Handle the maskGenAlgorithm
         */
        if (NULL != pItem)
        {
            status = ASN1_VerifyType(pItem, SEQUENCE);
            if (OK != status)
            {
                goto exit;
            }

            pItem = ASN1_FIRST_CHILD(pItem);

            /* The set of supported maskGenAlgorithm values are defined in
             * RFC 8017 section A.2.1 (This section is for RSAES-OAEP but some
             * portions of this section apply to RSA SSA-PSS as well).
             *
             *   MaskGenAlgorithm ::= AlgorithmIdentifier { {PKCS1MGFAlgorithms} }
             *
             *   PKCS1MGFAlgorithms    ALGORITHM-IDENTIFIER ::= {
             *       { OID id-mgf1 PARAMETERS HashAlgorithm },
             *       ...  -- Allows for future expansion --
             *   }
             *
             * Currently only id-mgf1 with parameters defined as HashAlgorithm
             * is supported.
             */
            status = ASN1_VerifyOID(pItem, cs, pkcs1Mgf_OID);
            if (OK != status)
            {
                goto exit;
            }

            status = convertRsaSsaPssAlgIdToDigestId(
                ASN1_NEXT_SIBLING(pItem), cs, &(pRsaSsaPssParams->mgfDigestId));
            if (OK != status)
            {
                goto exit;
            }
        }

        status = ASN1_GetChildWithTag(pParams, 2, &pItem);
        if (OK != status)
        {
            goto exit;
        }

        /* Handle the saltLength
         */
        if (NULL != pItem)
        {
            if ( (UNIVERSAL != (pItem->id & CLASS_MASK)) ||
                 (INTEGER != pItem->tag) || (sizeof(sbyte4) < pItem->length) )
            {
                status = ERR_INVALID_INPUT;
                goto exit;
            }
            else
            {
                pRsaSsaPssParams->saltLen = pItem->data.m_intVal;
            }
        }

        status = ASN1_GetChildWithTag(pParams, 3, &pItem);
        if (OK != status)
        {
            goto exit;
        }

        /* Handle the trailerField
         *
         * RFC 8017 only supports a trailer field value of 0xBC which is defined
         * as a value of 1 in the ASN.1 encoding (section A.2.3).
         */
        if (NULL != pItem)
        {
            status = ASN1_VerifyInteger(pItem, 1);
            if (OK != status)
            {
                goto exit;
            }
        }
    }

    *ppParams = pRsaSsaPssParams;
    pRsaSsaPssParams = NULL;

exit:

    if (NULL != pRsaSsaPssParams)
    {
        DIGI_FREE((void **) &pRsaSsaPssParams);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

/* This method will takes in a digest ID and DER sequence and appends the
 * appropriate OID based on the digest ID. This function is implemented to
 * support HashAlgorithms defined in RFC 8017.
 */
static MSTATUS addRsaSsaPssAlgIdByDigest(
    ubyte digestId,
    DER_ITEMPTR pSeq
    )
{
    MSTATUS status = ERR_INVALID_INPUT;
    OidIdentifier supportedOids[] = {
        { sha1_OID, ht_sha1 },
        { sha224_OID, ht_sha224 },
        { sha256_OID, ht_sha256 },
        { sha384_OID, ht_sha384 },
        { sha512_OID, ht_sha512 }
    };
    ubyte4 i;
    const ubyte *pOid = NULL;

    for (i = 0; i < COUNTOF(supportedOids); i++)
    {
        if (digestId == supportedOids[i].digestId)
        {
            pOid = supportedOids[i].pOid;
            break;
        }
    }

    if (NULL != pOid)
    {
        /* Add the digest ID.
         *
         * DER encoding omits default values, do not add the NULL tag.
         */
        status = DER_StoreAlgoOID(pSeq, pOid, FALSE);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

/* Method used to serialize RSA SSA-PSS parameters.
 *
 * This method will construct the appropriate ASN.1 definition for RSA SSA-PSS
 * parameters as defined in RFC 8017 section A.2.3. The following ASN.1 module
 * is constructed
 *
 * RSASSA-PSS-params ::= SEQUENCE {
 *      hashAlgorithm      [0] HashAlgorithm      DEFAULT sha1,
 *      maskGenAlgorithm   [1] MaskGenAlgorithm   DEFAULT mgf1SHA1,
 *      saltLength         [2] INTEGER            DEFAULT 20,
 *      trailerField       [3] TrailerField       DEFAULT trailerFieldBC
 *  }
 */
static MSTATUS rsaSsaPssSerializeParams(
    DER_ITEMPTR pItem,
    void *pParams
    )
{
    MSTATUS status = OK;
    DER_ITEMPTR pSeq = NULL, pNewItem = NULL;
    RsaSsaPssAlgIdParams *pRsaPssParams = pParams;

    /* Ensure that the trailer field is 0xBC (RFC 8017 only supports 0xBC) and
     * ensure the MGF algorithm is MGF1.
     */
    if ( (MOC_PKCS1_ALG_MGF1 != pRsaPssParams->mgfAlgo) ||
         (0xBC != pRsaPssParams->trailerField) )
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* If any of the values are not their default values then construct the
     * appropriate RSA SSA-PSS params.
     */
    if ( (ht_sha1 != pRsaPssParams->digestId) ||
         (ht_sha1 != pRsaPssParams->mgfDigestId) ||
         (20 != pRsaPssParams->saltLen) )
    {
        status = DER_AddSequence(pItem, &pSeq);
        if (OK != status)
        {
            goto exit;
        }

        /* Handle the hashAlgorithm
         */
        if (ht_sha1 != pRsaPssParams->digestId)
        {
            status = DER_AddTag(pSeq, 0, &pNewItem);
            if (OK != status)
            {
                goto exit;
            }

            status = addRsaSsaPssAlgIdByDigest(pRsaPssParams->digestId, pNewItem);
            if (OK != status)
            {
                goto exit;
            }
        }

        /* Handle the maskGenAlgorithm
         */
        if (ht_sha1 != pRsaPssParams->mgfDigestId)
        {
            status = DER_AddTag(pSeq, 1, &pNewItem);
            if (OK != status)
            {
                goto exit;
            }

            /* Must be MGF1
             */
            status = DER_StoreAlgoOID(pNewItem, pkcs1Mgf_OID, FALSE);
            if (OK != status)
            {
                goto exit;
            }

            /* Parameter for MGF1 algorithm ID is the algorithm identifier for
             * the MGF1 digest algorithm.
             */
            status = addRsaSsaPssAlgIdByDigest(
                pRsaPssParams->mgfDigestId, DER_FIRST_CHILD(pNewItem));
            if (OK != status)
            {
                goto exit;
            }
        }

        /* Handle the saltLength
         */
        if (20 != pRsaPssParams->saltLen)
        {
            status = DER_AddTag(pSeq, 2, &pNewItem);
            if (OK != status)
            {
                goto exit;
            }

            status = DER_AddIntegerEx(pNewItem, pRsaPssParams->saltLen, NULL);
            if (OK != status)
            {
                goto exit;
            }
        }

        /* There is no handling for the trailerField. The trailerField will
         * always be the default value as defined by RFC 8017, therefore it can
         * be omitted for DER encodings.
         */
    }

exit:

    if (NULL != pSeq)
    {
        TREE_DeleteTreeItem((TreeItem *) pSeq);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS rsaSsaPssCopyParams(
    void *pParams,
    void **ppParams
    )
{
    MSTATUS status;

    status = DIGI_MALLOC((void **) ppParams, sizeof(RsaSsaPssAlgIdParams));
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY(*ppParams, pParams, sizeof(RsaSsaPssAlgIdParams));

exit:

    return status;
}

#endif /* __ENABLE_DIGICERT_PKCS1__ */

/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_ECC__

/* Method is used to deserialize EC parameters.
 *
 * RFC 5480 defines the algorithm identifier in section 2.1.1. The OID must be
 * id-ecPublicKey and the parameters for id-ecPublicKey must be
 *
 *  ECParameters ::= CHOICE {
 *      namedCurve         OBJECT IDENTIFIER
 *      -- implicitCurve   NULL
 *      -- specifiedCurve  SpecifiedECDomain
 *    }
 *
 * This method will only handle the namedCurve choice.
 */
static MSTATUS ecPublicKeyDeserializeParams(
    ASN1_ITEMPTR pParams,
    CStream cs,
    void **ppParams
    )
{
    MSTATUS status;
    EcPublicKeyAlgIdParams *pEcPublicKeyParams = NULL;
    ubyte curveId = 0;

    status = DIGI_MALLOC(
        (void **) &pEcPublicKeyParams, sizeof(EcPublicKeyAlgIdParams));
    if (OK != status)
    {
        goto exit;
    }

    /* For PKCS#8 the curve ID may be in the PrivateKey ASN.1 element and/or in
     * the parameters section of the PKCS#8 algorithm identifier. If the curve
     * ID is not located in the parameters section then set the curve ID value
     * to 0 to indicate that it was not found.
     *
     * If the algorithm identifier parameters section does specify the curve
     * then set it appropriately.
     */
    if (NULL != pParams)
    {
        /* NULL tag is also acceptable for the parameters.
         */
        status = nullParams(pParams, cs, NULL);
        if (OK != status)
        {
            status = ASN1_VerifyType(pParams, OID);
            if (OK != status)
            {
                goto exit;
            }

            /* Validate the namedCurve. Section 2.1.1.1 in RFC 5480 lists the set
            * of supported curves.
            *
            * This method supports the following curves
            *   - secp192r1 (ansi x9.62)
            *   - secp224r1 (certicom)
            *   - secp256r1 (ansi x9.62)
            *   - secp384r1 (certicom)
            *   - secp521r1 (certicom)
            */
            status = ASN1_VerifyOIDRoot(
                pParams, cs, ansiX962CurvesPrime_OID, &curveId);
            if (OK != status)
            {
                status = ASN1_VerifyOIDRoot(
                    pParams, cs, certicomCurve_OID, &curveId);
            }

            if (OK != status)
            {
                status = ERR_EC_UNSUPPORTED_CURVE;
                goto exit;
            }
        }
    }

    pEcPublicKeyParams->curveId = curveId;

    *ppParams = pEcPublicKeyParams;
    pEcPublicKeyParams = NULL;

exit:

    if (NULL != pEcPublicKeyParams)
    {
        DIGI_FREE((void **) &pEcPublicKeyParams);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

/* Method is used to serialize EC parameters.
 *
 * RFC 5480 defines the algorithm identifier in section 2.1.1. The OID must be
 * id-ecPublicKey and the parameters for id-ecPublicKey must be
 *
 *  ECParameters ::= CHOICE {
 *      namedCurve         OBJECT IDENTIFIER
 *      -- implicitCurve   NULL
 *      -- specifiedCurve  SpecifiedECDomain
 *    }
 *
 * This method will only handle the namedCurve choice.
 */
static MSTATUS ecPublicKeySerializeParams(
    DER_ITEMPTR pItem,
    void *pParams
    )
{
    MSTATUS status = OK;
    EcPublicKeyAlgIdParams *pEcPublicKeyParams = pParams;
    const ubyte *pOid = NULL;

    /* For a curve ID of 0 there is no need to place the namedCurve. If the
     * curve ID is present then place the appropriate curve ID.
     */
    if (0 != pEcPublicKeyParams->curveId)
    {
        switch (pEcPublicKeyParams->curveId)
        {
            case cid_EC_P192:
                pOid = secp192r1_OID;
                break;

            case cid_EC_P256:
                pOid = secp256r1_OID;
                break;

            case cid_EC_P224:
                pOid = secp224r1_OID;
                break;

            case cid_EC_P384:
                pOid = secp384r1_OID;
                break;

            case cid_EC_P521:
                pOid = secp521r1_OID;
                break;

            default:
                status = ERR_EC_UNSUPPORTED_CURVE;
                goto exit;
        }

        status = DER_AddOID(pItem, pOid, NULL);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS ecPublicKeyCopyParams(
    void *pParams,
    void **ppParams
    )
{
    MSTATUS status;

    status = DIGI_MALLOC((void **) ppParams, sizeof(EcPublicKeyAlgIdParams));
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY(*ppParams, pParams, sizeof(EcPublicKeyAlgIdParams));

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS ALG_ID_ecPublicKeyCreate(
    ubyte4 curveId,
    MAlgoId **ppAlgoId
    )
{
    MSTATUS status;
    EcPublicKeyAlgIdParams *pParams = NULL;

    status = DIGI_MALLOC((void **) &pParams, sizeof(EcPublicKeyAlgIdParams));
    if (OK != status)
    {
        goto exit;
    }

    pParams->curveId = curveId;

    status = createMAlgoId(
        ALG_ID_EC_PUBLIC_KEY_OID, (void **) &pParams, ppAlgoId);
    if (OK != status)
    {
        goto exit;
    }

exit:

    if (NULL != pParams)
    {
        DIGI_FREE((void **) &pParams);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_ECC__ */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS ALG_ID_createRsaPssParams(
    ubyte digestId,
    ubyte mgfAlgo,
    ubyte mgfDigestId,
    ubyte4 saltLen,
    ubyte trailerField,
    MAlgoId **ppRetAlgoId
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAlgoId *pAlgoId = NULL;
    RsaSsaPssAlgIdParams *pPssParams = NULL;

    if (NULL == ppRetAlgoId)
        goto exit;

    status = DIGI_MALLOC((void **) &pPssParams, sizeof(RsaSsaPssAlgIdParams));
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pAlgoId, sizeof(MAlgoId));
    if (OK != status)
        goto exit;

    pPssParams->digestId = digestId;
    pPssParams->mgfAlgo = mgfAlgo;
    pPssParams->mgfDigestId = mgfDigestId;
    pPssParams->saltLen = saltLen;
    pPssParams->trailerField = trailerField;

    pAlgoId->oidFlag = ALG_ID_RSA_SSA_PSS_OID;
    pAlgoId->pParams = pPssParams; pPssParams = NULL;
    
    *ppRetAlgoId = pAlgoId; pAlgoId = NULL;

exit:

    if (NULL != pPssParams)
    {
        (void) DIGI_FREE((void **) &pPssParams);
    }

    if (NULL != pAlgoId)
    {
        (void) DIGI_FREE((void **) &pAlgoId);
    }

    return status;
}
