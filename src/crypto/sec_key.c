/*
 * sec_key.c
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

#if defined(__ENABLE_DIGICERT_ECC__)

#if !defined( __DISABLE_DIGICERT_CERTIFICATE_PARSING__) || defined(__ENABLE_DIGICERT_DER_CONVERSION__)

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
#include "../common/random.h"
#include "../common/vlong.h"
#include "../crypto/primefld.h"
#include "../crypto/ecc.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/pubcrypto_data.h"
#include "../crypto/rsa.h"
#include "../harness/harness.h"
#include "../asn1/parseasn1.h"
#include "../asn1/ASN1TreeWalker.h"
#include "../asn1/oiddefs.h"
#include "../asn1/derencoder.h"
#include "../crypto/ca_mgmt.h"
#include "../asn1/parsecert.h"
#include "../crypto/asn1cert.h"
#include "../crypto/sec_key.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_ecc.h"
#endif

#endif


#if !defined( __DISABLE_DIGICERT_CERTIFICATE_PARSING__)


/*---------------------------------------------------------------------------*/

MSTATUS SEC_getPrivateKey(MOC_ECC(hwAccelDescr hwAccelCtx) ASN1_ITEMPTR pSeq, CStream cs, ubyte curveId, AsymmetricKey* pECCKey)
{
    MSTATUS status;
    ASN1_ITEMPTR pTmp, pPrivateKey, pOID;
    const ubyte* pk = 0;
    ubyte *pPoint = NULL;
    sbyte4 pointLen = 0;

    pTmp = ASN1_FIRST_CHILD(pSeq);
    if (NULL == pTmp || pTmp->data.m_intVal != 1)
    {
        status = ERR_EC_UNKNOWN_KEY_FILE_VERSION;
        goto exit;
    }

    pPrivateKey = ASN1_NEXT_SIBLING( pTmp);
    if ( OK > ASN1_VerifyType( pPrivateKey, OCTETSTRING))
    {
        status = ERR_EC_INVALID_KEY_FILE_FORMAT;
        goto exit;
    }

    /* we require a tag [0] if curveId = 0 */
    if ( 0 == curveId)
    {
        /* go to 0 tag */
        if (OK > ( status = ASN1_GoToTag( pSeq, 0, &pTmp)))
            goto exit;

        if ( !pTmp)
        {
            status = ERR_EC_INCOMPLETE_KEY_FILE;
            goto exit;
        }

        pOID = ASN1_FIRST_CHILD(pTmp);
        /* this should be one of the OID for the curves we support */
        status = ASN1_VerifyOIDRoot( pOID, cs, ansiX962CurvesPrime_OID, &curveId);
        if ( OK > status) /* try another ASN1 arc */
        {
            status = ASN1_VerifyOIDRoot( pOID, cs, certicomCurve_OID, &curveId);
        }

        if (OK > status)
        {
            status = ERR_EC_UNSUPPORTED_CURVE;
            goto exit;
        }
    }

    /* access the private key data */
    pk = (const ubyte*) CS_memaccess( cs, pPrivateKey->dataOffset,
                                      pPrivateKey->length);
    if (!pk)
    {
	    status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* go to 1 tag */
    if (OK > ( status = ASN1_GoToTag( pSeq, 1, &pTmp)))
        goto exit;

    /* check if there's a public key */
    if(pTmp)
    {
        pTmp = ASN1_FIRST_CHILD(pTmp);
        if (NULL != pTmp)
        {
            if (OK > ASN1_VerifyType( pTmp, BITSTRING))
            {
                status = ERR_EC_INVALID_KEY_FILE_FORMAT;
                goto exit;
            }

            pPoint = (ubyte *) pk + pTmp->dataOffset - pPrivateKey->dataOffset;
            pointLen = pTmp->length;
        }
    }
    else
    {
        /* curveId is required */
        if (0 == curveId)
        {
            status = ERR_EC_INCOMPLETE_KEY_FILE;
	        goto exit;
        }
        /* pPoint and pointLen remain NULL and 0 respectively, and pub key will be computed */
    }

    if (OK > (status = CRYPTO_setECCParameters( MOC_ECC(hwAccelCtx) pECCKey, curveId,
                                               pPoint, (ubyte4) pointLen,
                                               pk, pPrivateKey->length)))
    {
        goto exit;
    }

exit:

    if (pk)
    {
        CS_stopaccess( cs, pk);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_ECC_EDDSA__)
static MSTATUS SEC_getEdPrivateKey(MOC_ECC(hwAccelDescr hwAccelCtx) ASN1_ITEMPTR pSeq, CStream cs, AsymmetricKey* pECCKey)
{
    MSTATUS status = OK;
    ASN1_ITEMPTR pTmp = NULL, pPrivateKey = NULL, pOid = NULL;
    ubyte *pPriv = NULL;
    ubyte *pPub = NULL;
    const ubyte *pBuff = NULL;
    ubyte curveId = 0;
    ubyte4 keyLen = 0;
    ubyte4 i = 0;

    pTmp = ASN1_FIRST_CHILD(pSeq);
    if (NULL == pTmp || pTmp->data.m_intVal > 2)
    {
        status = ERR_EC_UNKNOWN_KEY_FILE_VERSION;
        goto exit;
    }

    pTmp = ASN1_NEXT_SIBLING(pTmp);
    if (NULL == pTmp)
    {
        status = ERR_EC_UNKNOWN_KEY_FILE_VERSION;
        goto exit;
    }

    pOid = ASN1_FIRST_CHILD(pTmp);

    if ( OK > ASN1_VerifyOIDRoot( pOid, cs, ecced_OID, &curveId))
    {
        status = ERR_EC_INVALID_KEY_FILE_FORMAT;
        goto exit;
    }

    /* Get the true keyLength for Edward's curves */
    if ( OK > (status = CRYPTO_INTERFACE_EC_getPointByteStringLenByCurveId(curveId, &keyLen)))
        goto exit;

    pTmp = ASN1_NEXT_SIBLING(pTmp);
    if ( OK > ASN1_VerifyType( pTmp, OCTETSTRING))
    {
        status = ERR_EC_INVALID_KEY_FILE_FORMAT;
        goto exit;
    }

    pPrivateKey = ASN1_FIRST_CHILD(pTmp);
    if ( OK > ASN1_VerifyType( pPrivateKey, OCTETSTRING))
    {
        status = ERR_EC_INVALID_KEY_FILE_FORMAT;
        goto exit;
    }

    /* access the data */
    pBuff = (const ubyte*) CS_memaccess(cs, pPrivateKey->dataOffset, pPrivateKey->length);
    if (!pBuff)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = DIGI_CALLOC((void **) &pPriv, 1, keyLen)))
        goto exit;

    if (pPrivateKey->length <= keyLen)
    {
        /* zero pad if necc */
        DIGI_MEMCPY(pPriv + keyLen - pPrivateKey->length, pBuff, pPrivateKey->length);
    }
    else
    {
        /* remove zero padding if necc */
        for (i = 0; i < pPrivateKey->length; ++i)
        {
            if (pBuff[i])
                break;
        }

        if (pPrivateKey->length - i > keyLen)
        {
            status = ERR_EC_INVALID_KEY_FILE_FORMAT;
            goto exit;
        }
        else
        {
            DIGI_MEMCPY(pPriv, pBuff + i, pPrivateKey->length - i);
        }
    }

    /* stop access so we can reuse pBuff for the public key */
    CS_stopaccess( cs, pBuff);

    /* See if there is a public key */
    pTmp = ASN1_NEXT_SIBLING(pTmp);
    if (NULL != pTmp)
    {
        /* use pOid again as another temp variable */
        pOid = ASN1_FIRST_CHILD(pTmp);

        /* check if it's the optional params SEQUENCE */
        if ( OK == ASN1_VerifyType( pOid, SEQUENCE))
        {
            pTmp = ASN1_NEXT_SIBLING(pTmp);
            if (NULL == pTmp)
            {
                status = ERR_EC_UNKNOWN_KEY_FILE_VERSION;
                goto exit;
            }
        }

        /* pTmp then should now point to the public key */
        pBuff = (const ubyte*) CS_memaccess(cs, pTmp->dataOffset, pTmp->length);
        if (!pBuff)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        if (OK > (status = DIGI_CALLOC((void **) &pPub, 1, keyLen)))
            goto exit;

        if (pTmp->length <= keyLen)
        {
            /* zero pad if necc */
            DIGI_MEMCPY(pPub + keyLen - pTmp->length, pBuff, pTmp->length);
        }
        else
        {
            /* remove zero padding if necc */
            for (i = 0; i < pTmp->length; ++i)
            {
                if (pBuff[i])
                    break;
            }

            if (pTmp->length - i > keyLen)
            {
                status = ERR_EC_INVALID_KEY_FILE_FORMAT;
                goto exit;
            }
            else
            {
                DIGI_MEMCPY(pPub, pBuff + i, pTmp->length - i);
            }
        }
    }

    /* Set the keys, if no public key was found then it'll be generated */
    if (OK > (status = CRYPTO_setECCParameters( MOC_ECC(hwAccelCtx) pECCKey, curveId, pPub, (NULL != pPub) ? keyLen : 0, pPriv, keyLen)))
    {
        goto exit;
    }

exit:

    if (pBuff)
    {
        CS_stopaccess( cs, pBuff);
    }

    if (pPriv)
    {
        DIGI_MEMSET_FREE(&pPriv, keyLen);
    }

    if (pPub)
    {
        DIGI_MEMSET_FREE(&pPub, keyLen);
    }

    return status;
}
#endif

/*---------------------------------------------------------------------------*/

MSTATUS
SEC_getKey(MOC_ECC(hwAccelDescr hwAccelCtx) const ubyte* sec1DER, ubyte4 sec1DERLen, AsymmetricKey* pECCKey)
{
    CStream         cs;
    MemFile         mf;
    ASN1_ITEMPTR    pRoot = 0;
    ASN1_ITEMPTR    pSeq, pTmp;
    MSTATUS         status;

    if (!sec1DER || !pECCKey)
        return ERR_NULL_POINTER;

    /* parse the DER */
    MF_attach( &mf, sec1DERLen, (ubyte*) sec1DER);

    CS_AttachMemFile( &cs, &mf);

    if ( OK > (status = ASN1_Parse(cs, &pRoot)))
        goto exit;

    /* public or private key ? */
    pSeq = ASN1_FIRST_CHILD( pRoot);
    if (OK > ASN1_VerifyType(pSeq, SEQUENCE))
    {
        status = ERR_EC_INVALID_KEY_FILE_FORMAT;
        goto exit;
    }

    pTmp = ASN1_FIRST_CHILD(pSeq);

    if (OK <= ASN1_VerifyType(pTmp, SEQUENCE))
    {
        status = X509_extractECCKey( MOC_ECC(hwAccelCtx) pSeq, cs, pECCKey);

#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
        if (ERR_CERT_NOT_EXPECTED_OID == status)
        {
            status = X509_extractECCEdKey( MOC_ECC(hwAccelCtx) pSeq, cs, pECCKey);
        }
#endif
        goto exit;
    }
    else if (OK <= ASN1_VerifyType(pTmp, INTEGER))
    {
        status = SEC_getPrivateKey(MOC_ECC(hwAccelCtx) pSeq, cs, 0, pECCKey);

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_ECC_EDDSA__)
        if (OK > status)  /* try as an Edwards's form key */
        {
            status = SEC_getEdPrivateKey(MOC_ECC(hwAccelCtx) pSeq, cs, pECCKey);
        }
#endif
        goto exit;
    }
    else
    {
        status = ERR_EC_INVALID_KEY_FILE_FORMAT;
        goto exit;
    }

exit:
    if ( pRoot)
    {
        TREE_DeleteTreeItem((TreeItem*) pRoot);
    }
    return status;
}

#endif


#if defined(__ENABLE_DIGICERT_DER_CONVERSION__) || defined(__ENABLE_DIGICERT_PEM_CONVERSION__)

/*---------------------------------------------------------------------------*/

static MSTATUS
SEC_setPublicKey(MOC_ASYM(hwAccelDescr hwAccelCtx) const AsymmetricKey* pECCKey, ubyte **ppRetKeyDER, ubyte4 *pRetKeyDERLength)
{
    MSTATUS status;
    DER_ITEMPTR pRoot = 0;
    DER_ITEMPTR pPublicKeyInfo;

    /* create a root */
    if (OK > ( status = DER_AddSequence( NULL, &pRoot)))
        goto exit;

    /* use the usual routine to store the key info under the root */
    if (OK > ( status = ASN1CERT_storePublicKeyInfo(MOC_ASYM(hwAccelCtx) pECCKey, pRoot)))
        goto exit;

    /* serialize the public key info */
    pPublicKeyInfo = DER_FIRST_CHILD( pRoot);
    if (OK > ( status = DER_Serialize( pPublicKeyInfo, ppRetKeyDER, pRetKeyDERLength)))
        goto exit;

exit:

    if ( pRoot)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRoot);
    }

    return status;
}


/*---------------------------------------------------------------------------*/

static MSTATUS SEC_setPrivateKey(
    MOC_ECC(hwAccelDescr hwAccelCtx)
    const ECCKey* pECCKey,
    ubyte4 keyType,
    ubyte4 options,
    ubyte **ppRetKeyDER,
    ubyte4 *pRetKeyDERLength
    )
{
    MSTATUS status;
    MEccKeyTemplate eccData = { 0 };
    DER_ITEMPTR pRoot = NULL, pTag = NULL;
    ubyte4 offset;
    ubyte *pCurveOid = NULL, *pPubBuf = NULL;
    ubyte4 pubLen = 0;
    ubyte4 version = 1;  /* version with pub key */
#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
    ubyte *pPrivBuf = NULL;
    ubyte4 privLen = 0;
#endif

    /* Create a root
     */
    if (OK > (status = DER_AddSequence(NULL, &pRoot)))
        goto exit;

    /* Create an integer for version
     */
#if defined(__ENABLE_DIGICERT_ECC_EDDSA__) && !defined(__ENABLE_DIGICERT_EDDSA_PRIV_W_PUB_SER__)
    if (akt_ecc_ed == keyType)
        version = 0;
#endif

    if (OK > (status = DER_AddIntegerEx(pRoot, version, NULL)))
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_EC_getKeyParametersAllocAux(MOC_ECC(hwAccelCtx) (ECCKey *) pECCKey, &eccData, MOC_GET_PRIVATE_KEY_DATA)))
        goto exit;
#else
    if (OK > (status = EC_getKeyParametersAlloc( MOC_ECC(hwAccelCtx)
            (ECCKey *) pECCKey, &eccData, MOC_GET_PRIVATE_KEY_DATA)))
        goto exit;
#endif

    for (offset = 0; offset < eccData.privateKeyLen; ++offset)
        if (0 != eccData.pPrivateKey[offset])
            break;

#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
    if (akt_ecc == keyType)
    {
#endif
        if (OK > (status = DER_AddItem(pRoot, OCTETSTRING, eccData.privateKeyLen - offset,
                                       eccData.pPrivateKey + offset, NULL)))
            goto exit;

        if (0 == (options & E_SEC_omitCurveOID))
        {
            /* Add tag [0]
             */
            if (OK > (status = DER_AddTag(pRoot, 0, &pTag)))
                goto exit;

            if (OK > (status = CRYPTO_getECCurveOID(pECCKey, (const ubyte**)&pCurveOid)))
                goto exit;

            /* Add OID for the curve
             */
            if (OK > (status = DER_AddOID(pTag, pCurveOid, NULL)))
                goto exit;
        }

        /* Add tag [1]
         */
        if (OK > (status = DER_AddTag(pRoot, 1, &pTag)))
            goto exit;

        pubLen = eccData.publicKeyLen + 1;
        if (OK > (status = DIGI_MALLOC((void **) &pPubBuf, pubLen)))
            goto exit;

        pPubBuf[0] = 0x00;
        if (OK > (status = DIGI_MEMCPY((void *) (pPubBuf + 1), eccData.pPublicKey, eccData.publicKeyLen)))
            goto exit;

        if (OK > (status = DER_AddItem(pTag, BITSTRING, pubLen, pPubBuf, NULL)))
            goto exit;

#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
    }
    else if (akt_ecc_ed == keyType)
    {
        /* Add tag [0]
         */
        if (OK > (status = DER_AddSequence(pRoot, &pTag)))
            goto exit;

        if (OK > (status = CRYPTO_getECCurveOID(pECCKey, (const ubyte**)&pCurveOid)))
            goto exit;

        /* Add OID for the curve
         */
        if (OK > (status = DER_AddOID(pTag, pCurveOid, NULL)))
            goto exit;

        privLen = eccData.privateKeyLen + 2 - offset;
        if (OK > (status = DIGI_MALLOC((void **) &pPrivBuf, privLen)))
            goto exit;

        pPrivBuf[0] = OCTETSTRING; /* OCTETSTRING TAG */
        pPrivBuf[1] = (ubyte) (privLen - 2);  /* Length of the private key, must change if curves bigger than 127 bytes are used! */

        if (OK > (status = DIGI_MEMCPY(pPrivBuf + 2, eccData.pPrivateKey + offset, privLen - 2)))
            goto exit;

        if (OK > (status = DER_AddItem(pRoot, OCTETSTRING, privLen, pPrivBuf, NULL)))
            goto exit;

#ifdef __ENABLE_DIGICERT_EDDSA_PRIV_W_PUB_SER__
        pubLen = eccData.publicKeyLen + 3;
        if (OK > (status = DIGI_MALLOC((void **) &pPubBuf, pubLen)))
            goto exit;

        pPubBuf[0] = 0x81;
        pPubBuf[1] = (ubyte) (eccData.publicKeyLen + 1); /* account for a zero pad, if larger curves are used this must be changed! */
        pPubBuf[2] = 0x00;    /* zero pad*/

        if (OK > (status = DIGI_MEMCPY((void *) (pPubBuf + 3), eccData.pPublicKey, eccData.publicKeyLen)))
            goto exit;

        if (OK > (status = DER_AddDERBuffer(pRoot, pubLen, pPubBuf, NULL)))
            goto exit;
#endif
    }
#endif /* __ENABLE_DIGICERT_ECC_EDDSA__ */

    if (OK > (status = DER_Serialize(pRoot, ppRetKeyDER, pRetKeyDERLength)))
        goto exit;

exit:

#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
    if (NULL != pPrivBuf)
        DIGI_MEMSET_FREE(&pPrivBuf, privLen);
#endif

    if (NULL != pPubBuf)
        DIGI_MEMSET_FREE(&pPubBuf, pubLen);

    if (NULL != pRoot)
        TREE_DeleteTreeItem((TreeItem *) pRoot);

    EC_freeKeyTemplate((ECCKey *) pECCKey, &eccData);

    return status;
}


/*---------------------------------------------------------------------------*/

MSTATUS SEC_setKeyEx(MOC_ASYM(hwAccelDescr hwAccelCtx) const AsymmetricKey* pKey, ubyte4 options,
                     ubyte **ppRetKeyDER, ubyte4 *pRetKeyDERLength)
{
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    intBoolean isPriv = FALSE;
    MSTATUS status = OK;
#endif

    if (!pKey || !ppRetKeyDER || !pRetKeyDERLength)
        return ERR_NULL_POINTER;

    if (akt_ecc != pKey->type && akt_ecc_ed != pKey->type)
        return ERR_EC_INVALID_KEY_TYPE;

    if (!pKey->key.pECC)
        return ERR_NULL_POINTER;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_isKeyPrivate (pKey->key.pECC, &isPriv);
    if (OK != status)
        goto exit;

    if (isPriv)
    {
        status = SEC_setPrivateKey( MOC_ECC(hwAccelCtx) pKey->key.pECC, pKey->type, options, ppRetKeyDER, pRetKeyDERLength);
    }
    else
    {
        status = SEC_setPublicKey( MOC_ASYM(hwAccelCtx) pKey, ppRetKeyDER, pRetKeyDERLength);
    }

exit:

    return status;

#else
    return pKey->key.pECC->privateKey ? SEC_setPrivateKey( MOC_ECC(hwAccelCtx) pKey->key.pECC, pKey->type, options, ppRetKeyDER, pRetKeyDERLength) :
                                        SEC_setPublicKey( MOC_ASYM(hwAccelCtx) pKey, ppRetKeyDER, pRetKeyDERLength);
#endif
}


/*---------------------------------------------------------------------------*/

MSTATUS SEC_setKey(MOC_ASYM(hwAccelDescr hwAccelCtx) const AsymmetricKey* pKey, ubyte **ppRetKeyDER, ubyte4 *pRetKeyDERLength)
{
    return SEC_setKeyEx(MOC_ASYM(hwAccelCtx) pKey, 0, ppRetKeyDER, pRetKeyDERLength);
}

#endif /* defined( __ENABLE_DIGICERT_DER_CONVERSION__) || defined(__ENABLE_DIGICERT_PEM_CONVERSION__) */


#endif /* defined( __ENABLE_DIGICERT_ECC__) */
