/*
 * pkcs_key.c
 *
 * PKCS Utilities (PKCS1 and PKCS8 )
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
@file       pkcs_key.c
@brief      Mocana SoT Platform source code for PKCS&nbsp;\#1 and PKCS&nbsp;\#10
            utility routines.

@details    This file contains Mocana SoT Platform source code for PKCS&nbsp;\#1
            and PKCS&nbsp;\#10 utility routines.

@flags
Whether the following flags are defined determines which additional header files
are included:
+ \c \__ENABLE_DIGICERT_ECC__
+ \c \__ENABLE_DIGICERT_PKCS12__
+ \c \__ENABLE_DIGICERT_PKCS5__
+ \c \__ENABLE_DIGICERT_PKCS7__

@todo_eng_review (verify the \@flags info)

@filedoc    pkcs_key.c
*/


#include "../common/moptions.h"

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
#include "../common/vlong.h"
#include "../common/random.h"
#include "../crypto/crypto.h"
#include "../crypto/rsa.h"
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#ifdef __ENABLE_DIGICERT_DSA__
#include "../crypto/dsa.h"
#endif
#include "../crypto/pubcrypto.h"
#include "../crypto/pubcrypto_data.h"
#include "../harness/harness.h"
#include "../asn1/parseasn1.h"
#include "../asn1/ASN1TreeWalker.h"
#include "../asn1/oiddefs.h"
#include "../asn1/derencoder.h"
#include "../asn1/parsecert.h"
#include "../asn1/parseasn1.h"
#include "../asn1/mocasn1.h"
#include "../crypto/pkcs_common.h"
#if defined( __ENABLE_DIGICERT_PKCS7__ ) || defined(__ENABLE_DIGICERT_PKCS12__)
#include "../crypto/pkcs7.h"
#endif
#ifdef __ENABLE_DIGICERT_PKCS12__
#include "../crypto/pkcs12.h"
#endif
#ifdef __ENABLE_DIGICERT_PKCS5__
#include "../crypto/pkcs5.h"
#endif
#include "../crypto/ca_mgmt.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/sec_key.h"
#endif

#include "../crypto/malgo_id.h"
#include "../crypto/pkcs_key.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_ecc.h"
#ifdef __ENABLE_DIGICERT_DSA__
#include "../crypto_interface/crypto_interface_dsa.h"
#endif
#endif

#endif

#if defined(__ENABLE_DIGICERT_PKCS5__)
#ifndef MOC_DEFAULT_ENCRYPTED_KEY_SALT_LEN
#define MOC_DEFAULT_ENCRYPTED_KEY_SALT_LEN MOC_MIN_800_132_SALT_LEN
#endif
#endif


#if !defined( __DISABLE_DIGICERT_CERTIFICATE_PARSING__)
/*

PKCS#1:

RSAPublicKey ::= SEQUENCE {
    modulus           INTEGER,  -- n
    publicExponent    INTEGER   -- e
}

RSAPrivateKey ::= SEQUENCE {
    version           Version,
    modulus           INTEGER,  -- n
    publicExponent    INTEGER,  -- e
    privateExponent   INTEGER,  -- d
    prime1            INTEGER,  -- p
    prime2            INTEGER,  -- q
    exponent1         INTEGER,  -- d mod (p-1)
    exponent2         INTEGER,  -- d mod (q-1)
    coefficient       INTEGER,  -- (inverse of q) mod p
    otherPrimeInfos   OtherPrimeInfos OPTIONAL
}

PKCS#8:

PrivateKeyInfo ::= SEQUENCE {
  version Version,
  privateKeyAlgorithm AlgorithmIdentifier {{PrivateKeyAlgorithms}},
  privateKey PrivateKey,
  attributes [0] Attributes OPTIONAL }

  Version ::= INTEGER {v1(0)} (v1,...)

  PrivateKey ::= OCTET STRING

EncryptedPrivateKeyInfo ::= SEQUENCE {
  encryptionAlgorithm  EncryptionAlgorithmIdentifier,
  encryptedData        EncryptedData }

  EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier

  EncryptedData ::= OCTET STRING

*/


/*-----------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__
static MSTATUS
PKCS1_ExtractPublicKey( MOC_RSA(hwAccelDescr hwAccelCtx) CStream cs, ASN1_ITEMPTR pFirst,
                        ASN1_ITEMPTR pSecond, RSAKey* pRSAKey)
{
    MSTATUS status;
    const ubyte* buffer = 0;

    /* public key */
    if ( OK > ASN1_VerifyType(pFirst, INTEGER) ||
        OK > ASN1_VerifyType( pSecond, INTEGER) ||
        pSecond->length > sizeof (ubyte4) )
    {
        status = ERR_RSA_INVALID_PKCS1;
        goto exit;
    }

    /*Set the public key parameters*/
    buffer = (const ubyte*) CS_memaccess( cs, pFirst->dataOffset, pFirst->length);
    if (!buffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    status = RSA_setPublicKeyParameters(MOC_RSA(hwAccelCtx) pRSAKey,
                                        pSecond->data.m_intVal,
                                        buffer,
                                        pFirst->length,
                                        NULL);
exit:

    CS_stopaccess( cs, buffer);

    return status;
}
#endif

/*-----------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__
static MSTATUS
PKCS1_ExtractPrivateKey(MOC_RSA(hwAccelDescr hwAccelCtx) CStream cs,
                        ASN1_ITEMPTR pFirst,
                        ASN1_ITEMPTR pSecond, RSAKey* pRSAKey)
{
    MSTATUS         status;
    ubyte4          version;
    ASN1_ITEMPTR    pExponent;
    ASN1_ITEMPTR    pIgnore;
    ASN1_ITEMPTR    pPrime1;
    ASN1_ITEMPTR    pPrime2;
    const ubyte*    modulusBuffer = 0;
    const ubyte*    prime1Buffer = 0;
    const ubyte*    prime2Buffer = 0;


    /* private key */
    if ( OK > ASN1_VerifyType(pFirst, INTEGER) ||
        OK > ASN1_VerifyType( pSecond, INTEGER) )
    {
        status = ERR_RSA_INVALID_PKCS1;
        goto exit;
    }

    version = pFirst->data.m_intVal;

    if ( 0 != version && 1 != version)
    {
        status = ERR_RSA_INVALID_PKCS1_VERSION;
        goto exit;
    }

    pExponent = ASN1_NEXT_SIBLING( pSecond);
    if ( !pExponent || pExponent->length > sizeof(ubyte4))
    {
        status = ERR_RSA_INVALID_PKCS1;
        goto exit;
    }

    /* get prime1 and prime2 after jumping
        over the private exponent */
    if ( !(pIgnore = ASN1_NEXT_SIBLING( pExponent)) ||
            !(pPrime1 = ASN1_NEXT_SIBLING(pIgnore)) ||
            !(pPrime2 = ASN1_NEXT_SIBLING(pPrime1)))
    {
        status = ERR_RSA_INVALID_PKCS1;
        goto exit;
    }

    modulusBuffer = (const ubyte*) CS_memaccess( cs, pSecond->dataOffset, pSecond->length);
    if (!modulusBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    prime1Buffer = (const ubyte*) CS_memaccess( cs, pPrime1->dataOffset, pPrime1->length);
    if (!prime1Buffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    prime2Buffer = (const ubyte*) CS_memaccess( cs, pPrime2->dataOffset, pPrime2->length);
    if (!prime2Buffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    status = RSA_setAllKeyParameters(MOC_RSA(hwAccelCtx) pRSAKey,
                            pExponent->data.m_intVal,
                            modulusBuffer,
                            pSecond->length,
                            prime1Buffer,
                            pPrime1->length,
                            prime2Buffer,
                            pPrime2->length, NULL);

exit:

    CS_stopaccess( cs, modulusBuffer);
    CS_stopaccess( cs, prime1Buffer);
    CS_stopaccess( cs, prime2Buffer);

    return status;
}
#endif

/*-----------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__
static MSTATUS
PKCS_getPKCS1KeyAux(MOC_RSA(hwAccelDescr hwAccelCtx) ASN1_ITEMPTR pSequence,
                    CStream cs, AsymmetricKey* pRSAKey)
{
    MSTATUS         status;
    ASN1_ITEMPTR    pFirst,
                    pSecond;

    /* is it a public key or a private key ?*/
    if (!(pFirst = ASN1_FIRST_CHILD( pSequence)) ||
        !(pSecond = ASN1_NEXT_SIBLING( pFirst)))
    {
        status = ERR_RSA_INVALID_PKCS1;
        goto exit;
    }

    if (OK >( status = CRYPTO_createRSAKey(pRSAKey, NULL)))
        goto exit;

    if ( ASN1_NEXT_SIBLING( pSecond))
    {
        /* private key */
        status = PKCS1_ExtractPrivateKey(MOC_RSA(hwAccelCtx) cs, pFirst, pSecond, pRSAKey->key.pRSA);
    }
    else
    {
#ifdef __ENABLE_DIGICERT_OPENSSL_PUBKEY_COMPATIBILITY__
        status = X509_extractRSAKey(MOC_RSA(hwAccelCtx) pSequence, cs, pRSAKey);
#else
        status = PKCS1_ExtractPublicKey(MOC_RSA(hwAccelCtx) cs, pFirst, pSecond, pRSAKey->key.pRSA);
#endif
    }

exit:

    if (OK > status)
    {
        CRYPTO_uninitAsymmetricKey( pRSAKey, NULL);
    }

    return status;
}
#endif

/*-----------------------------------------------------------------------------*/

/**
@coming_soon
@ingroup    pkcs_functions

@funcdoc    pkcs_key.c
*/
#ifndef __DISABLE_DIGICERT_RSA__
extern MSTATUS
PKCS_getPKCS1Key(MOC_RSA(hwAccelDescr hwAccelCtx) const ubyte* pPKCS1DER, ubyte4 pkcs1DERLen,
                 AsymmetricKey* pRSAKey)
{
    CStream         cs;
    MemFile         mf;
    ASN1_ITEMPTR    pRoot = 0;
    ASN1_ITEMPTR    pSequence;
    MSTATUS         status;

    if ( !pPKCS1DER || !pRSAKey)
        return ERR_NULL_POINTER;

    /* parse the DER */
    MF_attach( &mf, pkcs1DERLen, (ubyte*) pPKCS1DER);

    CS_AttachMemFile( &cs, &mf);

    if ( OK > (status = ASN1_Parse(cs, &pRoot)))
        goto exit;

    pSequence = ASN1_FIRST_CHILD( pRoot);

    if (!pSequence || OK > ASN1_VerifyType(pSequence, SEQUENCE))
    {
        status = ERR_RSA_INVALID_PKCS1;
        goto exit;
    }

    status = PKCS_getPKCS1KeyAux(MOC_RSA(hwAccelCtx) pSequence, cs, pRSAKey);

exit:
    if ( pRoot)
    {
        TREE_DeleteTreeItem((TreeItem*) pRoot);
    }

    return status;
}
#endif

/*-----------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_DSA__
/**
@coming_soon
@ingroup    pkcs_functions

@funcdoc    pkcs_key.c
*/
MOC_EXTERN MSTATUS PKCS_getDSAKey(MOC_DSA(hwAccelDescr hwAccelCtx)
                                  const ubyte* pDSAKeyDer, ubyte4 pDSAKeyDerLen,
                                  AsymmetricKey* pKey)
{
    CStream         s;
    MemFile         mf;
    ASN1_ITEMPTR    pRoot = 0;
    ASN1_ITEMPTR    pTemp;
    MSTATUS         status;
    const ubyte     *p = 0,
                    *q = 0,
                    *g = 0,
                    *x = 0;
    ubyte4 pLen, qLen, gLen, xLen;

    if ( !pDSAKeyDer || !pKey)
        return ERR_NULL_POINTER;

    /* parse the DER */
    MF_attach( &mf, pDSAKeyDerLen, (ubyte*) pDSAKeyDer);

    CS_AttachMemFile( &s, &mf);

    if ( OK > (status = ASN1_Parse(s, &pRoot)))
        goto exit;

    pTemp = ASN1_FIRST_CHILD( pRoot);

    if (OK > ASN1_VerifyType(pTemp, SEQUENCE))
    {
        status = ERR_RSA_INVALID_PKCS1;
        goto exit;
    }

    /* version */
    pTemp = ASN1_FIRST_CHILD( pTemp);
    if (OK > ASN1_VerifyType( pTemp, INTEGER))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }


    /* p */
    pTemp = ASN1_NEXT_SIBLING( pTemp);
    if (OK > ASN1_VerifyType( pTemp, INTEGER))
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
    g = CS_memaccess( s, pTemp->dataOffset, gLen = pTemp->length);
    if (!g)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* y -- no read */
    pTemp = ASN1_NEXT_SIBLING(pTemp);
    if (OK > ASN1_VerifyType( pTemp, INTEGER))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* x */
    pTemp = ASN1_NEXT_SIBLING( pTemp);
    if (OK > ASN1_VerifyType( pTemp, INTEGER))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }
    x = CS_memaccess( s, pTemp->dataOffset, xLen = pTemp->length);
    if (!x)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK >( status = CRYPTO_createDSAKey(pKey, NULL)))
        goto exit;

    if (OK > ( status = DSA_setAllKeyParameters(MOC_DSA(hwAccelCtx)
                                                pKey->key.pDSA, p, pLen, q, qLen,
                                                g, gLen, x, xLen, NULL)))
    {
        goto exit;
    }

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
    if (x)
    {
        CS_stopaccess( s, x);
    }
    if ( pRoot)
    {
        TREE_DeleteTreeItem((TreeItem*) pRoot);
    }

    if (OK > status)
    {
        CRYPTO_uninitAsymmetricKey( pKey, NULL);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_DSA__ */

/*-----------------------------------------------------------------------------*/

extern MSTATUS
PKCS_getPKCS8Key(MOC_ASYM(hwAccelDescr hwAccelCtx) const ubyte* pPKCS8DER, ubyte4 pkcs8DERLen,
                 AsymmetricKey* pKey)
{
    MSTATUS       status;
    sbyte4        cmpResult = 0;
    ubyte4        bytesRead = 0;
    MAsn1Element *pArray = NULL;
    MAsn1TypeAndCount pTemplate[4] = {
        { MASN1_TYPE_SEQUENCE, 2 },
            { MASN1_TYPE_INTEGER, 0 },
            { MASN1_TYPE_SEQUENCE, 1 },
                { MASN1_TYPE_OID, 0 }
    };

    if ( !pPKCS8DER || !pKey)
        return ERR_NULL_POINTER;

    /* The format for an unencrypted private key as defined in RFC 5208:
     *   SEQUENCE {
     *     INTEGER Version
     *     AlgorithmIdentifier PrivateKeyAlgorithmIdentifier
     *     OCTET STRING PrivateKey
     *   }
     *
     * We need to determine what type of key this is, which can be determined
     * from the algorithm identifier. The algorithm identifiers for RSA< ECC
     * and DSA all share the same format of:
     *   SEQUENCE {
     *     OID Algorithm
     *     ENCODED Params
     *   }
     *
     * We will do a partial parse to determine the algorithm, then hand it off
     * to the respective algorithm-specific deserialization routines. */

    /* Prepare the template */
    status = MAsn1CreateElementArray(pTemplate, 4, MASN1_FNCT_DECODE, NULL, &pArray);
    if (OK != status)
        goto exit;

    /* Do a partial parse to determine the OID */
    status = MAsn1Decode(pPKCS8DER, pkcs8DERLen, pArray, &bytesRead);
    if (OK != status)
        goto exit;

    /* Compare the OID lengths, the rsaEncryption_OID is stored without the
     * 0x06 OID tag but still contains the length prepended, so we just
     * compare the length to the first byte of the OID. */
#ifndef __DISABLE_DIGICERT_RSA__
    if ((ubyte)(*rsaEncryption_OID) == pArray[3].valueLen)
    {
        /* The lengths match, ensure the OID is exact */
        status = DIGI_MEMCMP (
            (const ubyte *)(rsaEncryption_OID + 1), pArray[3].value.pValue,
            pArray[3].valueLen, &cmpResult);
        if (OK != status)
            goto exit;

        if (0 == cmpResult)
        {
            /* This is an RSA key, the underlying function can handle PKCS8 encodings */
            status = KeySerializeRsa(MOC_ASYM(hwAccelCtx) pKey, deserialize, (ubyte **)&pPKCS8DER, &pkcs8DERLen);
            goto exit;
        }

        status = DIGI_MEMCMP (
            (const ubyte *)(rsaSsaPss_OID + 1), pArray[3].value.pValue,
            pArray[3].valueLen, &cmpResult);
        if (0 == cmpResult)
        {
            /* This is an RSA key, the underlying function can handle PKCS8 encodings */
            status = KeySerializeRsa(MOC_ASYM(hwAccelCtx) pKey, deserialize, (ubyte **)&pPKCS8DER, &pkcs8DERLen);
            goto exit;
        }
    }

#endif /* __DISABLE_DIGICERT_RSA__ */

    /* Compare the OID lengths */
#ifdef __ENABLE_DIGICERT_ECC__
    if ((ubyte)(*ecPublicKey_OID) == pArray[3].valueLen)
    {
        /* The lengths match, ensure the OID is exact. The ECC and DSA OIDs are equal
         * length so this could fail. */
        status = DIGI_MEMCMP (
            (const ubyte *)(ecPublicKey_OID + 1), pArray[3].value.pValue,
            pArray[3].valueLen, &cmpResult);
        if (0 == cmpResult)
        {
            /* This is an ECC key, the underlying function can handle PKCS8 encodings */
            status = KeySerializeEcc(MOC_ASYM(hwAccelCtx) pKey, deserialize, (ubyte **)&pPKCS8DER, &pkcs8DERLen);
            goto exit;
        }
    }
#endif

    /* Compare the OID lengths */
#ifdef __ENABLE_DIGICERT_DSA__
    if ((ubyte)(*dsa_OID) == pArray[3].valueLen)
    {
        /* The lengths match, ensure the OID is exact */
        status = DIGI_MEMCMP (
            (const ubyte *)(dsa_OID + 1), pArray[3].value.pValue,
            pArray[3].valueLen, &cmpResult);
        if (0 == cmpResult)
        {
            /* This is a DSA key, the underlying function can handle PKCS8 encodings */
            status = KeySerializeDsa(MOC_ASYM(hwAccelCtx) pKey, deserialize, (ubyte **)&pPKCS8DER, &pkcs8DERLen);
            goto exit;
        }
    }
#endif

    status = ERR_RSA_INVALID_PKCS8;

exit:

    if (NULL != pArray)
    {
        MAsn1FreeElementArray (&pArray);
    }

    return status;
}


/*-----------------------------------------------------------------------------*/

extern MSTATUS
PKCS_getPKCS8KeyEx(MOC_HW(hwAccelDescr hwAccelCtx) const ubyte* pPKCS8DER,
                   ubyte4 pkcs8DERLen, const ubyte* password, ubyte4 passwordLen,
                   AsymmetricKey* pKey)
{
    MSTATUS         status;
    ubyte          *pIter = NULL;
    ubyte4          iterLen = 0;
    ubyte4          tag = 0;
    sbyte4          len = 0;
    ubyte4          tagAndLen = 0;
#if defined(__ENABLE_DIGICERT_PKCS5__) || defined(__ENABLE_DIGICERT_PKCS12__)
    ASN1_ITEMPTR    pRoot = 0;
    ubyte          *plainText = 0;
    CStream         cs;
    MemFile         mf;
    ASN1_ITEMPTR    pSequence;
    sbyte4          ptLen;
#endif

    if ( !pPKCS8DER || !pKey)
        return ERR_NULL_POINTER;

    /* We need to determine if this is an encrypted or unencrypted PKCS8 private
     * key. The format for an unencrypted private key as defined in RFC 5208:
     *   SEQUENCE {
     *     INTEGER Version
     *     AlgorithmIdentifier PrivateKeyAlgorithmIdentifier
     *     OCTET STRING PrivateKey
     *   }
     *
     * The format for an encrypted private key as defined in RFC 5208:
     *   SEQUENCE {
     *     AlgorithmIdentifier EncryptionAlgorithmIdentifier
     *     OCTET STRING EncryptedData
     *   }
     *
     * All AlgorithmIdentifiers begin with a sequence, so from the tag of the
     * second element we should be able to tell if it is encrypted. */

    /* Read the root sequence */
    pIter = (ubyte *)pPKCS8DER;
    iterLen = pkcs8DERLen;
    status = ASN1_readTagAndLen (
        (ubyte *)pPKCS8DER, pkcs8DERLen, &tag, &len, &tagAndLen);
    if (OK != status)
        goto exit;

    /* This must be a sequence to be a valid PKCS8 encoding */
    if (0x30 != tag)
    {
        status = ERR_RSA_INVALID_PKCS8;
        goto exit;
    }

    /* Sequences are simply containers for other data, move the iterator pointer
     * beyond the tag and length of the initial sequence so it points to the
     * tag of the next element */
    pIter += tagAndLen;
    iterLen -= tagAndLen;

    /* Read the next element */
    status = ASN1_readTagAndLen (
        pIter, iterLen, &tag, &len, &tagAndLen);
    if (OK != status)
        goto exit;

    /* If the tag is 0x02 then the element is an integer, so this is unencrypted */
    if (0x02 == tag)
    {
        /* Process the unencrypted PKCS8 encoding */
        status = PKCS_getPKCS8Key(MOC_ASYM(hwAccelCtx) pPKCS8DER, pkcs8DERLen, pKey);
    }
    else if (0x30 == tag)
    {
#if defined(__ENABLE_DIGICERT_PKCS5__) || defined(__ENABLE_DIGICERT_PKCS12__)

        /* The tag is 0x30, which is a sequence, so this is encrypted. Parse the
         * DER in full and decrypt the data */
        MF_attach( &mf, pkcs8DERLen, (ubyte*) pPKCS8DER);

        CS_AttachMemFile( &cs, &mf);

        if ( OK > (status = ASN1_Parse(cs, &pRoot)))
            goto exit;

        /* look at the type: encrypted or unencrypted */
        pSequence = ASN1_FIRST_CHILD( pRoot);
        if (OK > (status = PKCS_DecryptPKCS8Key( MOC_SYM(hwAccelCtx)
                pSequence, cs, password, passwordLen,
                &plainText, &ptLen)))
        {
            status = ERR_PKCS8_ENCRYPTED_KEY;
            goto exit;
        }

        /* Process the decrypted PKCS8 encoding */
        status = PKCS_getPKCS8Key(MOC_ASYM(hwAccelCtx) plainText, ptLen, pKey);
        if (OK != status)
            status = ERR_PKCS8_ENCRYPTED_KEY;
#else
        status = ERR_RSA_BUILT_WITH_NO_PKCS8_DECRYPTION;
#endif
    }
    else
    {
        status = ERR_RSA_INVALID_PKCS8;
    }

exit:

#if defined(__ENABLE_DIGICERT_PKCS5__) || defined(__ENABLE_DIGICERT_PKCS12__)
    if (plainText)
    {
        FREE(plainText);
    }

    if ( pRoot)
    {
        TREE_DeleteTreeItem((TreeItem*) pRoot);
    }
#endif

    return status;
}

#endif /* __DISABLE_DIGICERT_CERTIFICATE_PARSING__ */

/*------------------------------------------------------------------*/

#if defined( __ENABLE_DIGICERT_DER_CONVERSION__) || defined(__ENABLE_DIGICERT_PEM_CONVERSION__)

#ifndef __DISABLE_DIGICERT_RSA__

/*
   PKCS1 standard for RSA private key:
    --
    -- Representation of RSA private key with information for the CRT algorithm.
    --
    RSAPrivateKey ::= SEQUENCE {
        version           Version,
        modulus           INTEGER,  -- n
        publicExponent    INTEGER,  -- e
        privateExponent   INTEGER,  -- d
        prime1            INTEGER,  -- p
        prime2            INTEGER,  -- q
        exponent1         INTEGER,  -- d mod (p-1)
        exponent2         INTEGER,  -- d mod (q-1)
        coefficient       INTEGER,  -- (inverse of q) mod p
        otherPrimeInfos   OtherPrimeInfos OPTIONAL
    }

    Version ::= INTEGER { two-prime(0), multi(1) }
        (CONSTRAINED BY {-- version must be multi if otherPrimeInfos present --})

    OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo


    OtherPrimeInfo ::= SEQUENCE {
        prime             INTEGER,  -- ri
        exponent          INTEGER,  -- di
        coefficient       INTEGER   -- ti
    }
*/

/**
@coming_soon
@ingroup    pkcs_functions

@funcdoc    pkcs_key.c
*/
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
MOC_EXTERN MSTATUS PKCS_setPKCS1Key(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    const AsymmetricKey *pKey,
    ubyte **ppRetKeyDer,
    ubyte4 *pRetKeyDerLength
    )
{
    MSTATUS status;
    ubyte *pTemp = NULL, *pIter;
    ubyte4 numLeadZero, dataType, tempLen, index;
    MRsaKeyTemplate template = { 0 };
    DER_ITEMPTR pSequence = NULL;
    ubyte *ppRsaData[8] = { 0 };
    ubyte4 pRsaDataLen[8] = { 0 };

    if ( (NULL == pKey) || (NULL == ppRetKeyDer) || (NULL == pRetKeyDerLength) )
        return ERR_NULL_POINTER;

    if (akt_rsa != pKey->type && akt_rsa_pss != pKey->type)
        return ERR_BAD_KEY_TYPE;

    numLeadZero = 2;

    dataType = MOC_GET_PUBLIC_KEY_DATA;
    if (pKey->key.pRSA->privateKey)
    {
        dataType = MOC_GET_PRIVATE_KEY_DATA;
        numLeadZero = numLeadZero + 6 + 1;
    }

    status = CRYPTO_INTERFACE_RSA_getKeyParametersAlloc(
        MOC_RSA(hwAccelCtx) pKey->key.pRSA, &template, dataType, pKey->type);
    if (OK != status)
        goto exit;

    ppRsaData[0] = template.pN;
    pRsaDataLen[0] = template.nLen;

    ppRsaData[1] = template.pE;
    pRsaDataLen[1] = template.eLen;

    ppRsaData[2] = template.pD;
    pRsaDataLen[2] = template.dLen;

    ppRsaData[3] = template.pP;
    pRsaDataLen[3] = template.pLen;

    ppRsaData[4] = template.pQ;
    pRsaDataLen[4] = template.qLen;

    ppRsaData[5] = template.pDp;
    pRsaDataLen[5] = template.dpLen;

    ppRsaData[6] = template.pDq;
    pRsaDataLen[6] = template.dqLen;

    ppRsaData[7] = template.pQinv;
    pRsaDataLen[7] = template.qInvLen;

    tempLen = template.eLen + template.nLen + template.pLen + template.qLen +
        template.dLen + template.dpLen + template.dqLen + template.qInvLen +
        numLeadZero;
    status = DIGI_MALLOC((void **) &pTemp, tempLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMSET(pTemp, 0x00, tempLen);
    if (OK != status)
        goto exit;

    pIter = pTemp;

    status = DER_AddSequence(NULL, &pSequence);
    if (OK > status)
        goto exit;

    if (pKey->key.pRSA->privateKey)
    {
        status = DER_AddInteger(pSequence, 1, pIter, NULL);
        if (OK > status)
            goto exit;

        pIter += 1;
    }

    for (index = 0; (index < 8) && (NULL != ppRsaData[index]); index++)
    {
        status = DIGI_MEMCPY(pIter + 1, ppRsaData[index], pRsaDataLen[index]);
        if (OK != status)
            goto exit;

        status = DER_AddInteger(pSequence, pRsaDataLen[index] + 1, pIter, NULL);
        if (OK > status)
            goto exit;

        pIter += pRsaDataLen[index] + 1;
    }

    status = DER_Serialize(pSequence, ppRetKeyDer, pRetKeyDerLength);

exit:

    CRYPTO_INTERFACE_RSA_freeKeyTemplate(pKey->key.pRSA, &template, pKey->type);

    if (NULL != pTemp)
        DIGI_FREE((void **) &pTemp);

    if (NULL != pSequence)
    {
        TREE_DeleteTreeItem( (TreeItem*) pSequence);
    }
    return status;
}
#else
extern MSTATUS
PKCS_setPKCS1Key(MOC_RSA(hwAccelDescr hwAccelCtx) const AsymmetricKey* pKey,
                 ubyte **ppRetKeyDER, ubyte4 *pRetKeyDERLength)
{
    MSTATUS       status = OK;
    DER_ITEMPTR   pSequence = NULL;
    RSAKey*       pRSAKey = NULL;
    ubyte4        i, tmpLen;
    ubyte4        numLeadZero;
    ubyte*        pBufStart = NULL;
    ubyte*        pTmpBuf = NULL;
    ubyte4        tmpBufLen;
    ubyte4        keyParamLen[NUM_RSA_VLONG + 1] = {0};
    vlong*        d = NULL;
    vlong*        v[NUM_RSA_VLONG + 1] = {0}; /* extra 1 for D */

    if (!pKey || !ppRetKeyDER || !pRetKeyDERLength)
        return ERR_NULL_POINTER;

    if (akt_rsa != pKey->type && akt_rsa_pss != pKey->type)
        return ERR_BAD_KEY_TYPE;

    pRSAKey = pKey->key.pRSA;

    /* create a tmp buffer large enough to hold all components of a key */
    /* need space for leading zeros, see comment for DER_AddInteger in derencoder.h */
    numLeadZero = 2;

    /* organize key components in specified order */
    v[0] = RSA_N(pRSAKey);
    v[1] = RSA_E(pRSAKey);

    if (pRSAKey->privateKey)
    {
        if (OK > RSA_getPrivateExponent(MOC_RSA(hwAccelCtx) pRSAKey, &d, NULL))
            goto exit;

        v[2] = d;
        v[3] = RSA_P(pRSAKey);
        v[4] = RSA_Q(pRSAKey);
        v[5] = RSA_DP(pRSAKey);
        v[6] = RSA_DQ(pRSAKey);
        v[7] = RSA_QINV(pRSAKey);

        /* add extra 1 for leading zero in version */
        numLeadZero = numLeadZero + 6 + 1;
    }

    tmpBufLen = numLeadZero;

    for (i=0; (i < NUM_RSA_VLONG + 1) && (NULL != v[i]); i++)
    {
        if (OK > (status = VLONG_byteStringFromVlong(v[i], NULL, (sbyte4 *)&tmpLen)))
            goto exit;

        keyParamLen[i] = tmpLen;
        tmpBufLen = tmpBufLen + tmpLen;
    }

    if (NULL == (pBufStart = (ubyte *)MALLOC(tmpBufLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    pTmpBuf = pBufStart;
    DIGI_MEMSET(pTmpBuf, 0x00, tmpBufLen);

    /* create an empty sequence */
    if (OK > (status = DER_AddSequence(NULL, &pSequence)))
        goto exit;

    /* only need version if this is a private key */
    if (pRSAKey->privateKey)
    {
        /* version is 0 */
        if (OK > (status = DER_AddInteger(pSequence, 1, pTmpBuf, NULL)))
            goto exit;

        pTmpBuf = pTmpBuf + 1;
    }

    for (i=0; (i < NUM_RSA_VLONG + 1) && (NULL != v[i]); i++)
    {
        tmpLen = keyParamLen[i];

        if (OK > (status = VLONG_byteStringFromVlong(v[i], pTmpBuf + 1, (sbyte4 *)&tmpLen)))
            goto exit;

        if (OK > (status = DER_AddInteger(pSequence, tmpLen + 1, pTmpBuf, NULL)))
            goto exit;

        pTmpBuf = pTmpBuf + tmpLen + 1;
    }

    status = DER_Serialize(pSequence, ppRetKeyDER, pRetKeyDERLength);

exit:
    VLONG_freeVlong(&d, NULL);

    if (NULL != pBufStart)
        FREE(pBufStart);

    if (NULL != pSequence)
    {
        TREE_DeleteTreeItem( (TreeItem*) pSequence);
    }

    return status;
}
#endif

#endif /* __DISABLE_DIGICERT_RSA__ */

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_DSA__
/**
@coming_soon
@ingroup    pkcs_functions

@funcdoc    pkcs_key.c
*/
extern MSTATUS
PKCS_setDsaDerKey(MOC_DSA(hwAccelDescr hwAccelCtx) const AsymmetricKey* pKey, ubyte **ppRetKeyDER, ubyte4 *pRetKeyDERLength)
{
    MSTATUS         status = OK;
    DER_ITEMPTR     pSequence = NULL;
    DSAKey*         pDSAKey = NULL;
    ubyte4          i;
    ubyte4          numLeadZero;
    ubyte*          pBufStart = NULL;
    ubyte*          pTmpBuf = NULL;
    ubyte4          tmpBufLen;
    ubyte*          pTmp = NULL;
    ubyte4          tmpLen = 0;
    MDsaKeyTemplate keyData = {0};

    if (!pKey || !ppRetKeyDER || !pRetKeyDERLength)
        return ERR_NULL_POINTER;

    if (akt_dsa != pKey->type)
        return ERR_BAD_KEY_TYPE;

    pDSAKey = pKey->key.pDSA;

    /* create a tmp buffer large enough to hold all components of a key */
    /* need space for leading zeros, see comment for DER_AddInteger in derencoder.h */
    /* add extra 1 for leading zero in version */
    numLeadZero = NUM_DSA_VLONG + 1;

    tmpBufLen = numLeadZero;

    /* Try to get the private key data, if that fails then this must be a public key
     * so get the public key data instead */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_getKeyParametersAlloc(MOC_DSA(hwAccelCtx) pDSAKey, &keyData, MOC_GET_PRIVATE_KEY_DATA);
    if (ERR_DSA_INVALID_PARAM == status)
    {
        status = CRYPTO_INTERFACE_DSA_getKeyParametersAlloc(MOC_DSA(hwAccelCtx) pDSAKey, &keyData, MOC_GET_PUBLIC_KEY_DATA);
    }
#else
    status = DSA_getKeyParametersAlloc(MOC_DSA(hwAccelCtx) pDSAKey, &keyData, MOC_GET_PRIVATE_KEY_DATA);
    if (ERR_DSA_INVALID_PARAM == status)
    {
        status = DSA_getKeyParametersAlloc(MOC_DSA(hwAccelCtx) pDSAKey, &keyData, MOC_GET_PUBLIC_KEY_DATA);
    }
#endif
    if (OK != status)
        goto exit;


    tmpBufLen += keyData.pLen + keyData.qLen + keyData.gLen + keyData.yLen + keyData.xLen;

    if (NULL == (pBufStart = (ubyte *)MALLOC(tmpBufLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    pTmpBuf = pBufStart;
    DIGI_MEMSET(pTmpBuf, 0x00, tmpBufLen);

    /* create an empty sequence */
    if (OK > (status = DER_AddSequence(NULL, &pSequence)))
        goto exit;

    /* version is 0 */
    if (OK > (status = DER_AddInteger(pSequence, 1, pTmpBuf, NULL)))
        goto exit;

    pTmpBuf = pTmpBuf + 1;

    for (i = 0; i < 5; i++)
    {
        switch(i)
        {
            case 0:
                pTmp = keyData.pP;
                tmpLen = keyData.pLen;
                break;

            case 1:
                pTmp = keyData.pQ;
                tmpLen = keyData.qLen;
                break;

            case 2:
                pTmp = keyData.pG;
                tmpLen = keyData.gLen;
                break;

            case 3:
                pTmp = keyData.pY;
                tmpLen = keyData.yLen;
                break;

            case 4:
                pTmp = keyData.pX;
                tmpLen = keyData.xLen;
                break;
        }

        if (NULL != pTmp)
        {
            status = DIGI_MEMCPY((void *)(pTmpBuf + 1), (const void *)pTmp, tmpLen);
            if (OK != status)
                goto exit;

            status = DER_AddInteger(pSequence, tmpLen + 1, pTmpBuf, NULL);
            if (OK != status)
                goto exit;

            pTmpBuf += tmpLen + 1;
        }
    }

    status = DER_Serialize(pSequence, ppRetKeyDER, pRetKeyDERLength);

exit:
    if (NULL != pBufStart)
        FREE(pBufStart);

    if (NULL != pSequence)
    {
        TREE_DeleteTreeItem( (TreeItem*) pSequence);
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DSA_freeKeyTemplate(pDSAKey, &keyData);
#else
    DSA_freeKeyTemplate(pDSAKey, &keyData);
#endif

    return status;
}
#endif /* __ENABLE_DIGICERT_DSA__ */

#endif /* defined( __ENABLE_DIGICERT_DER_CONVERSION__) || defined(__ENABLE_DIGICERT_PEM_CONVERSION__) */


/*------------------------------------------------------------------*/

#if defined( __ENABLE_DIGICERT_DER_CONVERSION__)

static MSTATUS
PKCS_makePrivateKeyInfo(MOC_ASYM(hwAccelDescr hwAccelCtx)
                        const AsymmetricKey* pKey, ubyte4 paddingTo,
                        ubyte **ppRetKeyDER, ubyte4 *pRetKeyDERLength)
{
    MSTATUS status;
    DER_ITEMPTR   pSequence = 0;
    ubyte* pPKBuffer = 0;
    ubyte* serializeBuffer = 0;
    ubyte4 pkLen = 0;
    ubyte leadZero = 0;

    /* The OID for an RSA key is RSA encryption
    */
    ubyte *pAlgId = NULL;
    ubyte4 algIdLen = 0;

#ifdef __ENABLE_DIGICERT_PQC__
    ubyte *pOid = NULL;
    ubyte4 oidLen = 0;
#endif

    /* create sequence */
    if (OK > (status = DER_AddSequence(NULL, &pSequence)))
        goto exit;

    if (OK > ( status = DER_AddInteger( pSequence, 1, &leadZero, NULL)))
        goto exit;

#ifndef __DISABLE_DIGICERT_RSA__
    if ( akt_rsa == pKey->type || akt_rsa_pss == pKey->type)
    {
        if (NULL != pKey->pAlgoId)
        {
            status = ALG_ID_serializeAlloc(pKey->pAlgoId, &pAlgId, &algIdLen);
            if (OK != status)
                goto exit;

            status = DER_AddDERBufferOwn(pSequence, algIdLen, (const ubyte **)&pAlgId, NULL);
            if (OK != status)
                goto exit;
        }
        else if (akt_rsa_pss == pKey->type)
        {
            if (OK > (status = DER_StoreAlgoOID( pSequence, rsaSsaPss_OID, 0)))
                goto exit;
        }
        else
        {
            if (OK > (status = DER_StoreAlgoOID( pSequence, rsaEncryption_OID, 1)))
                goto exit;
        }


        /* generate the pkcs1 buffer */
        if (OK > (status = PKCS_setPKCS1Key( MOC_RSA(hwAccelCtx) pKey,
                            &pPKBuffer, &pkLen)))
        {
            goto exit;
        }
    }
    else
#endif /* __DISABLE_DIGICERT_RSA__ */
#ifdef __ENABLE_DIGICERT_ECC__
    if ( akt_ecc == pKey->type || akt_ecc_ed == pKey->type)
    {
        const ubyte* curveOID = NULL;
        DER_ITEMPTR pAlgoSeq = NULL;
        intBoolean isPriv = FALSE;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_EC_isKeyPrivate (pKey->key.pECC, &isPriv);
        if (OK != status)
            goto exit;
#else
        isPriv = (intBoolean) pKey->key.pECC->privateKey;
#endif
        if (!isPriv)
        {
            status = ERR_EC_PUBLIC_KEY;
            goto exit;
        }

        if (OK > ( status = DER_AddSequence( pSequence, &pAlgoSeq)))
            goto exit;

        if (OK > ( status = DER_AddOID( pAlgoSeq, ecPublicKey_OID, 0)))
            goto exit;

        /* add oid for the curve */
        if (OK > ( status = CRYPTO_getECCurveOID( pKey->key.pECC, &curveOID)))
            goto exit;

        if (OK > ( status = DER_AddOID( pAlgoSeq, curveOID, 0)))
            goto exit;

        /* generate the SEC buffer */
        if (OK > (status = SEC_setKeyEx( MOC_ASYM(hwAccelCtx) pKey, E_SEC_omitCurveOID, &pPKBuffer, &pkLen)))
        {
            goto exit;
        }

    }
#ifdef __ENABLE_DIGICERT_PQC__
    else if (akt_hybrid == pKey->type)
    {
        DER_ITEMPTR pAlgoSeq = NULL;
        ubyte4 curveId = 0;
        ubyte4 qsAlgId = 0;

        if (!pKey->pQsCtx->isPrivate)
        {
            status = ERR_EC_PUBLIC_KEY;
            goto exit;
        }

        /* get the oid for the hybrid alg in question */
        if (OK > ( status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pKey->key.pECC, &curveId)))
            goto exit;

        if (OK > ( status = CRYPTO_INTERFACE_QS_getAlg(pKey->pQsCtx, &qsAlgId)))
            goto exit;

        if (OK > ( status = CRYPTO_getAlgoOIDAlloc(curveId, qsAlgId, &pOid, &oidLen)))
            goto exit;

        if (OK > ( status = DER_AddSequence( pSequence, &pAlgoSeq)))
            goto exit;

        if (OK > ( status = DER_AddItemOwnData( pAlgoSeq, OID, oidLen, &pOid, NULL)))
            goto exit;

        if (OK > ( status = CRYPTO_serializeAsymKey (MOC_ASYM(hwAccelCtx) (AsymmetricKey *) pKey, privateKeyInfoDer, &pPKBuffer, &pkLen)))
            goto exit;
    }
#endif
    else
#endif /* __ENABLE_DIGICERT_ECC__ */
    {
        status = ERR_BAD_KEY_TYPE;
        goto exit;
    }

    /* add it embedded as an OCTETSTRING */
    if (OK > ( status = DER_AddItem( pSequence, OCTETSTRING, pkLen, pPKBuffer, NULL)))
    {
        goto exit;
    }

    if (paddingTo) /* need to pad to a multiple of paddingTo -> encryption */
    {
        ubyte4 origLen, padding;

        if (OK > ( status = DER_GetLength( pSequence, &origLen)))
            goto exit;

        padding = paddingTo - (origLen % paddingTo);

        origLen += padding;
        *pRetKeyDERLength = origLen; /* return the total allocated length */
        serializeBuffer = (ubyte*) MALLOC( origLen);
        if (!serializeBuffer)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        if ( OK > ( status = DER_SerializeInto( pSequence, serializeBuffer, &origLen)))
            goto exit;

        if (8 == paddingTo)
        {
            /* pad the rest -- origLen was set to the used value by DER_SerializeInto */
            DIGI_MEMSET( serializeBuffer + origLen, (ubyte) padding, (sbyte4) padding);
        }
        else
        {
            ubyte4 i;
            for (i = 0; i < padding; ++i)
            {
                serializeBuffer[origLen+i] = (ubyte) padding;
            }
        }

        *ppRetKeyDER = serializeBuffer;
        serializeBuffer = 0;

    }
    else
    {
        /* serialize now */
        if (OK > ( status = DER_Serialize( pSequence, ppRetKeyDER, pRetKeyDERLength)))
            goto exit;
    }

exit:

    if (serializeBuffer)
    {
        FREE( serializeBuffer);
    }

    if (pPKBuffer)
    {
        /* zeroize */
        DIGI_MEMSET(pPKBuffer, 0x0, pkLen);

        FREE( pPKBuffer);
    }

    if (pSequence)
    {
        TREE_DeleteTreeItem( (TreeItem*) pSequence);
    }

#ifdef __ENABLE_DIGICERT_PQC__
    if (NULL != pOid)
    {
        DIGI_FREE((void **) &pOid);
    }
#endif

    return status;
}


#ifdef __ENABLE_DIGICERT_PKCS5__
/*------------------------------------------------------------------*/

#if defined(__ENABLE_DES_CIPHER__) || defined(__ENABLE_ARC2_CIPHERS__)
static MSTATUS
PKCS_makePKCS5V1PKInfo(MOC_HW(hwAccelDescr hwAccelCtx)
                      const AsymmetricKey* pKey,
                      randomContext* pRandomContext,
                      enum PKCS8EncryptionType encType,
                      const ubyte* password, ubyte4 passwordLen,
                      ubyte **ppRetKeyDER, ubyte4 *pRetKeyDERLength)
{
    MSTATUS status;
    DER_ITEMPTR   pSequence = 0;
    DER_ITEMPTR   pAlgoSequence, pInitSequence;
    ubyte*        pPrivateKeyInfo = 0;
    ubyte4        privateKeyInfoLen;
    ubyte         salt[8];
    ubyte         pkcs5_algo_oid[10]=
    { 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x00 };


    /* create sequence */
    if (OK > ( status = DER_AddSequence(NULL, &pSequence)))
        goto exit;

    /* algo */
    if (OK > ( status = DER_AddSequence(pSequence, &pAlgoSequence)))
        goto exit;

    /* algo oid */
    pkcs5_algo_oid[9] = encType; /* the enum PKCS8EncryptionType values
                                    are set up to allow this */

    if (OK > ( status = DER_AddOID( pAlgoSequence, pkcs5_algo_oid, NULL)))
        goto exit;

    /* init */
    if (OK > ( status = DER_AddSequence(pAlgoSequence, &pInitSequence)))
        goto exit;

    /* generate salt */
    if (OK > (status = RANDOM_numberGenerator( pRandomContext, salt, 8)))
        goto exit;

    if (OK > ( status = DER_AddItem( pInitSequence, OCTETSTRING, 8, salt, NULL)))
        goto exit;

    /* count = 2048 */
    if (OK > ( status = DER_AddIntegerEx( pInitSequence, 2048, NULL)))
        goto exit;

    /* get the private key info in a buffer with padding: DES or RC2 use a 8 byte pad */
    if (OK > ( status = PKCS_makePrivateKeyInfo( MOC_ASYM(hwAccelCtx)
                                                    pKey, 8, &pPrivateKeyInfo,
                                                    &privateKeyInfoLen)))
    {
        goto exit;
    }

    /* encrypt using PKCS5 v1 */
    if (OK > ( status = PKCS5_encryptV1( MOC_SYM( hwAccelCtx)
                                            encType, password, passwordLen,
                                            salt, 8, 2048,
                                            pPrivateKeyInfo, privateKeyInfoLen)))
    {
        goto exit;
    }

    /* add it as OCTETSTRING */
    if (OK > ( status = DER_AddItem(pSequence, OCTETSTRING, privateKeyInfoLen,
                                    pPrivateKeyInfo, NULL)))
    {
        goto exit;
    }

    /* serialize now */
    if (OK > ( status = DER_Serialize( pSequence, ppRetKeyDER, pRetKeyDERLength)))
        goto exit;

exit:

    if (pPrivateKeyInfo)
    {
        FREE( pPrivateKeyInfo);
    }

    if (pSequence)
    {
        TREE_DeleteTreeItem( (TreeItem*) pSequence);
    }

    return status;
}
#endif


/*------------------------------------------------------------------*/

static MSTATUS
PKCS_makePKCS5V2PKInfo(MOC_HW(hwAccelDescr hwAccelCtx)
                       const AsymmetricKey* pKey,
                       randomContext* pRandomContext,
                       enum PKCS8EncryptionType encType,
                       enum PKCS8PrfType prfType,
                       const ubyte* password, ubyte4 passwordLen,
                       ubyte **ppRetKeyDER, ubyte4 *pRetKeyDERLength)
{
    MSTATUS status;
    DER_ITEMPTR   pSequence = 0;
    DER_ITEMPTR   pAlgoSequence, pPBESequence, pKDFSequence;
    DER_ITEMPTR   pInitSequence, pPRFSequence, pEncryptionSequence;
    ubyte*        pPrivateKeyInfo = 0;
    ubyte4        privateKeyInfoLen;
    ubyte         random[MOC_DEFAULT_ENCRYPTED_KEY_SALT_LEN + 16];
    const         ubyte* algoOID = 0;
    const BulkEncryptionAlgo *pAlgo;
    ubyte4        keyLength;
    sbyte4        effectiveKeyBits = -1;
    const         ubyte* prfAlgoOID = 0;
    ubyte         rsaAlgoId;

    /* create sequence */
    if (OK > ( status = DER_AddSequence(NULL, &pSequence)))
        goto exit;

    /* algo */
    if (OK > ( status = DER_AddSequence(pSequence, &pAlgoSequence)))
        goto exit;

    /* PBES2 OID */
    if (OK > ( status = DER_AddOID(pAlgoSequence, pkcs5_PBES2_OID, NULL)))
        goto exit;

    if (OK > ( status = DER_AddSequence(pAlgoSequence, &pPBESequence)))
        goto exit;

    /* Key Derivation Function */
    if (OK > ( status = DER_AddSequence(pPBESequence, &pKDFSequence)))
        goto exit;

    /* PKDEF2 OID */
    if (OK > ( status = DER_AddOID(pKDFSequence, pkcs5_PBKDF2_OID, NULL)))
        goto exit;

    /* Init Sequence */
    if (OK > ( status = DER_AddSequence(pKDFSequence, &pInitSequence)))
        goto exit;

    /* generate salt and IV */
    if (OK > (status = RANDOM_numberGenerator( pRandomContext, random, MOC_DEFAULT_ENCRYPTED_KEY_SALT_LEN + 16)))
        goto exit;

    if (OK > ( status = DER_AddItem( pInitSequence, OCTETSTRING, MOC_DEFAULT_ENCRYPTED_KEY_SALT_LEN, random, NULL)))
        goto exit;

    if (OK > ( status = DER_AddIntegerEx( pInitSequence, 2048, NULL)))
        goto exit;


#ifdef __ENABLE_ARC2_CIPHERS__
    if (PCKS8_EncryptionType_pkcs5_v2_rc2 == encType)
    {
        /* add key size if RC2 */
        if (OK > ( status = DER_AddIntegerEx( pInitSequence, 16, NULL)))
            goto exit;
    }
#endif

    if (PKCS8_PrfType_undefined == prfType)
    {
        /* default algo */
        prfType = PKCS8_PrfType_pkcs5_v2_hmacSHA1Digest;
    }

    switch (prfType)
    {
    case PKCS8_PrfType_pkcs5_v2_hmacSHA1Digest:
        prfAlgoOID = hmacWithSHA1_OID;
        rsaAlgoId = sha1withRSAEncryption;
        break;

#ifndef __DISABLE_DIGICERT_SHA224__
    case PKCS8_PrfType_pkcs5_v2_hmacSHA224Digest:
        prfAlgoOID = hmacWithSHA224_OID;
        rsaAlgoId = sha224withRSAEncryption;
        break;
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
    case PKCS8_PrfType_pkcs5_v2_hmacSHA256Digest:
        prfAlgoOID = hmacWithSHA256_OID;
        rsaAlgoId = sha256withRSAEncryption;
        break;
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
    case PKCS8_PrfType_pkcs5_v2_hmacSHA384Digest:
        prfAlgoOID = hmacWithSHA384_OID;
        rsaAlgoId = sha384withRSAEncryption;
        break;
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
    case PKCS8_PrfType_pkcs5_v2_hmacSHA512Digest:
        prfAlgoOID = hmacWithSHA512_OID;
        rsaAlgoId = sha512withRSAEncryption;
        break;
#endif

    default:
        status = ERR_INTERNAL_ERROR;
        goto exit;
        break;
    }

    if (prfType != (enum PKCS8PrfType) hmacSHA1Digest)
    {
        if (OK > ( status = DER_AddSequence(pInitSequence, &pPRFSequence)))
            goto exit;

        /* prf algo OID */
        if (OK > ( status = DER_AddOID(pPRFSequence, prfAlgoOID, NULL)))
            goto exit;

        if (OK > ( status = DER_AddItem(pPRFSequence, NULLTAG, 0, NULL, NULL)))
            goto exit;
    }

    /* Encryption Scheme */
    if (OK > ( status = DER_AddSequence(pPBESequence, &pEncryptionSequence)))
        goto exit;

    switch (encType)
    {
#ifdef __ENABLE_ARC2_CIPHERS__
    case PCKS8_EncryptionType_pkcs5_v2_rc2:
        algoOID = rc2CBC_OID;
        pAlgo = &CRYPTO_RC2EffectiveBitsSuite;
        keyLength = 16;
        effectiveKeyBits = 128;
        break;
#endif

#ifdef __ENABLE_DES_CIPHER__
    case PCKS8_EncryptionType_pkcs5_v2_des:
        algoOID = desCBC_OID;
        pAlgo = &CRYPTO_DESSuite;
        keyLength = 8;
        break;
#endif

#ifndef __DISABLE_3DES_CIPHERS__
    case PCKS8_EncryptionType_pkcs5_v2_3des:
        algoOID = desEDE3CBC_OID;
        pAlgo = &CRYPTO_TripleDESSuite;
        keyLength = 24;
        break;
#endif

#ifndef __DISABLE_AES128_CIPHER__
    case PCKS8_EncryptionType_pkcs5_v2_aes128:
        algoOID = aes128CBC_OID;
        pAlgo = &CRYPTO_AESSuite;
        keyLength = 16;
        break;
#endif

#ifndef __DISABLE_AES192_CIPHER__
    case PCKS8_EncryptionType_pkcs5_v2_aes192:
        algoOID = aes192CBC_OID;
        pAlgo = &CRYPTO_AESSuite;
        keyLength = 24;
        break;
#endif

#ifndef __DISABLE_AES256_CIPHER__
    case PCKS8_EncryptionType_pkcs5_v2_aes256:
        algoOID = aes256CBC_OID;
        pAlgo = &CRYPTO_AESSuite;
        keyLength = 32;
        break;
#endif

    default:
        status = ERR_INTERNAL_ERROR;
        goto exit;
        break;
    }

    /* encryption algo OID */
    if (OK > ( status = DER_AddOID(pEncryptionSequence, algoOID, NULL)))
        goto exit;

#ifdef __ENABLE_ARC2_CIPHERS__
    /* rc2 special case */
    if (PCKS8_EncryptionType_pkcs5_v2_rc2 == encType)
    {
        DER_ITEMPTR pRC2Params;

        if (OK > ( status = DER_AddSequence(pEncryptionSequence,
                                                &pRC2Params)))
        {
            goto exit;
        }

        /* add effective bits if RC2  --weird : 128 is encoded as 58 */
        if (OK > ( status = DER_AddIntegerEx( pRC2Params, 58, NULL)))
        {
            goto exit;
        }
        if (OK > ( status = DER_AddItem(pRC2Params, OCTETSTRING,
                                         8, random + MOC_DEFAULT_ENCRYPTED_KEY_SALT_LEN, NULL)))
        {
            goto exit;
        }
    }
    else
#endif
    {
        /* DES, 3DES use a 8 byte IV; AES uses a 16 byte IV */
        if (OK > ( status = DER_AddItem(pEncryptionSequence, OCTETSTRING,
                                        ((pAlgo->blockSize == 16) ? 16 : 8),
                                        random + MOC_DEFAULT_ENCRYPTED_KEY_SALT_LEN, NULL)))
        {
            goto exit;
        }
    }

    /* get the private key info in a buffer with padding:
        DES, 3DES or RC2 use a 8 byte pad
        AES uses a 16 byte pad */
    if (OK > ( status = PKCS_makePrivateKeyInfo( MOC_ASYM(hwAccelCtx)
                                                    pKey, ((pAlgo->blockSize == 16) ? 16 : 8), &pPrivateKeyInfo,
                                                    &privateKeyInfoLen)))
    {
        goto exit;
    }

    /* encrypt using PKCS5 v2 */
    if (OK > ( status = PKCS5_encryptV2( MOC_SYM( hwAccelCtx)
                                            pAlgo, rsaAlgoId,
                                            keyLength, effectiveKeyBits,
                                            password, passwordLen,
                                            random, MOC_DEFAULT_ENCRYPTED_KEY_SALT_LEN,
                                            2048, random + MOC_DEFAULT_ENCRYPTED_KEY_SALT_LEN,
                                            pPrivateKeyInfo, privateKeyInfoLen)))
    {
        goto exit;
    }

    /* add it as OCTETSTRING */
    if (OK > ( status = DER_AddItem(pSequence, OCTETSTRING, privateKeyInfoLen,
                                    pPrivateKeyInfo, NULL)))
    {
        goto exit;
    }

    /* serialize now */
    if (OK > ( status = DER_Serialize( pSequence, ppRetKeyDER, pRetKeyDERLength)))
        goto exit;


exit:

    if (pPrivateKeyInfo)
    {
        FREE( pPrivateKeyInfo);
    }

    if (pSequence)
    {
        TREE_DeleteTreeItem( (TreeItem*) pSequence);
    }

    return status;

}
#endif /* __ENABLE_DIGICERT_PKCS5__ */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_PKCS12__) && (!defined(__DISABLE_3DES_CIPHERS__) || defined(__ENABLE_ARC2_CIPHERS__) || (!defined(__DISABLE_ARC4_CIPHERS__))))

static MSTATUS
PKCS_makePKCS12PKInfo(MOC_HW(hwAccelDescr hwAccelCtx)
                                 const AsymmetricKey* pKey,
                                 randomContext* pRandomContext,
                                 enum PKCS8EncryptionType encType,
                                 const ubyte* password, ubyte4 passwordLen,
                                 ubyte **ppRetKeyDER, ubyte4 *pRetKeyDERLength)
{
    MSTATUS status;
    DER_ITEMPTR   pSequence = 0;
    DER_ITEMPTR   pAlgoSequence, pInitSequence;
    ubyte*        pPrivateKeyInfo = 0;
    ubyte4        privateKeyInfoLen;
    ubyte         salt[8];
    ubyte         count[4];
    const         BulkEncryptionAlgo* pBulkAlgo;
    ubyte         pkcs12_algo_oid[11] =
    { 10, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x00 };


    encType -= PKCS8_EncryptionType_pkcs12;
    pBulkAlgo = PKCS12_GetEncryptionAlgo( encType);
    if (!pBulkAlgo)
    {
        return ERR_INTERNAL_ERROR;
    }

    /* create sequence */
    if (OK > ( status = DER_AddSequence(NULL, &pSequence)))
        goto exit;

    /* algo */
    if (OK > ( status = DER_AddSequence(pSequence, &pAlgoSequence)))
        goto exit;

    pkcs12_algo_oid[10] = (ubyte) encType;

    if (OK > ( status = DER_AddOID( pAlgoSequence, pkcs12_algo_oid, NULL)))
        goto exit;

    /* init */
    if (OK > ( status = DER_AddSequence(pAlgoSequence, &pInitSequence)))
        goto exit;

    /* generate salt */
    if (OK > (status = RANDOM_numberGenerator( pRandomContext, salt, 8)))
        goto exit;

    if (OK > ( status = DER_AddItem( pInitSequence, OCTETSTRING, 8, salt, NULL)))
        goto exit;

    /* count = 2048 */
    BIGEND32(count, 2048);
    if (OK > ( status = DER_AddInteger( pInitSequence, 4, count, NULL)))
        goto exit;


    /* get the private key info in a buffer with padding: DES or RC2 uses a 8 byte pad */
    if (OK > ( status = PKCS_makePrivateKeyInfo( MOC_ASYM(hwAccelCtx)
                                                    pKey, 8, &pPrivateKeyInfo,
                                                    &privateKeyInfoLen)))
    {
        goto exit;
    }

    /* encrypt using PKCS5 v1 */
    if (OK > ( status = PKCS12_encrypt( MOC_SYM( hwAccelCtx)
                                        encType, password, passwordLen,
                                        salt, 8, 2048,
                                        pPrivateKeyInfo, privateKeyInfoLen)))
    {
        goto exit;
    }

    /* add it as OCTETSTRING */
    if (OK > ( status = DER_AddItem(pSequence, OCTETSTRING, privateKeyInfoLen,
                                    pPrivateKeyInfo, NULL)))
    {
        goto exit;
    }

    /* serialize now */
    if (OK > ( status = DER_Serialize( pSequence, ppRetKeyDER, pRetKeyDERLength)))
        goto exit;


exit:

    if (pPrivateKeyInfo)
    {
        FREE( pPrivateKeyInfo);
    }

    if (pSequence)
    {
        TREE_DeleteTreeItem( (TreeItem*) pSequence);
    }

    return status;
}

#endif /* (defined(__ENABLE_DIGICERT_PKCS12__) && (!defined(__DISABLE_3DES_CIPHERS__) || defined(__ENABLE_ARC2_CIPHERS__) || (!defined(__DISABLE_ARC4_CIPHERS__)))) */

/*------------------------------------------------------------------*/

static MSTATUS
PKCS_makeEncryptionPrivateKeyInfo(MOC_HW(hwAccelDescr hwAccelCtx)
                                 const AsymmetricKey* pKey,
                                 randomContext* pRandomContext,
                                 enum PKCS8EncryptionType encType,
                                  enum PKCS8PrfType prfType,
                                 const ubyte* password, ubyte4 passwordLen,
                                 ubyte **ppRetKeyDER, ubyte4 *pRetKeyDERLength)
{
    if (!pRandomContext)
    {
        return ERR_NULL_POINTER;
    }

    switch (encType)
    {
#if defined(__ENABLE_DIGICERT_PKCS5__)
#if defined(__ENABLE_DES_CIPHER__)
        case PCKS8_EncryptionType_pkcs5_v1_sha1_des:
            return PKCS_makePKCS5V1PKInfo( MOC_HW(hwAccelCtx)
                                            pKey, pRandomContext,
                                            encType, password, passwordLen,
                                            ppRetKeyDER, pRetKeyDERLength);
#endif

#if defined(__ENABLE_ARC2_CIPHERS__)
        case PCKS8_EncryptionType_pkcs5_v1_sha1_rc2:
            return PKCS_makePKCS5V1PKInfo( MOC_HW(hwAccelCtx)
                                            pKey, pRandomContext,
                                            encType, password, passwordLen,
                                            ppRetKeyDER, pRetKeyDERLength);
#endif

#if defined(__ENABLE_DES_CIPHER__) && defined(__ENABLE_DIGICERT_MD2__)
        case PCKS8_EncryptionType_pkcs5_v1_md2_des:
            return PKCS_makePKCS5V1PKInfo( MOC_HW(hwAccelCtx)
                                            pKey, pRandomContext,
                                            encType, password, passwordLen,
                                            ppRetKeyDER, pRetKeyDERLength);
#endif

#if defined(__ENABLE_ARC2_CIPHERS__) && defined(__ENABLE_DIGICERT_MD2__)
        case PCKS8_EncryptionType_pkcs5_v1_md2_rc2:
            return PKCS_makePKCS5V1PKInfo( MOC_HW(hwAccelCtx)
                                            pKey, pRandomContext,
                                            encType, password, passwordLen,
                                            ppRetKeyDER, pRetKeyDERLength);
#endif

#if defined(__ENABLE_DES_CIPHER__)
        case PCKS8_EncryptionType_pkcs5_v1_md5_des:
            return PKCS_makePKCS5V1PKInfo( MOC_HW(hwAccelCtx)
                                            pKey, pRandomContext,
                                            encType, password, passwordLen,
                                            ppRetKeyDER, pRetKeyDERLength);
#endif

#if defined(__ENABLE_ARC2_CIPHERS__)
        case PCKS8_EncryptionType_pkcs5_v1_md5_rc2:
            return PKCS_makePKCS5V1PKInfo( MOC_HW(hwAccelCtx)
                                            pKey, pRandomContext,
                                            encType, password, passwordLen,
                                            ppRetKeyDER, pRetKeyDERLength);
#endif

#if !defined(__DISABLE_3DES_CIPHERS__)
        case PCKS8_EncryptionType_pkcs5_v2_3des:
            return PKCS_makePKCS5V2PKInfo( MOC_HW(hwAccelCtx)
                                            pKey, pRandomContext,
                                            encType, prfType,
                                            password, passwordLen,
                                            ppRetKeyDER, pRetKeyDERLength);
#endif

#if defined(__ENABLE_DES_CIPHER__)
        case PCKS8_EncryptionType_pkcs5_v2_des:
            return PKCS_makePKCS5V2PKInfo( MOC_HW(hwAccelCtx)
                                            pKey, pRandomContext,
                                            encType, prfType,
                                            password, passwordLen,
                                            ppRetKeyDER, pRetKeyDERLength);
#endif

#if defined(__ENABLE_ARC2_CIPHERS__)
        case PCKS8_EncryptionType_pkcs5_v2_rc2:
            return PKCS_makePKCS5V2PKInfo( MOC_HW(hwAccelCtx)
                                            pKey, pRandomContext,
                                            encType, prfType,
                                            password, passwordLen,
                                            ppRetKeyDER, pRetKeyDERLength);
#endif

#if !defined(__DISABLE_AES_CIPHERS__)

#if !defined(__DISABLE_AES128_CIPHER__)
        case PCKS8_EncryptionType_pkcs5_v2_aes128:
            return PKCS_makePKCS5V2PKInfo( MOC_HW(hwAccelCtx)
                                          pKey, pRandomContext,
                                          encType, prfType,
                                          password, passwordLen,
                                          ppRetKeyDER, pRetKeyDERLength);
#endif

#if !defined(__DISABLE_AES192_CIPHER__)
        case PCKS8_EncryptionType_pkcs5_v2_aes192:
            return PKCS_makePKCS5V2PKInfo( MOC_HW(hwAccelCtx)
                                          pKey, pRandomContext,
                                          encType, prfType,
                                          password, passwordLen,
                                          ppRetKeyDER, pRetKeyDERLength);
#endif

#if !defined(__DISABLE_AES256_CIPHER__)
        case PCKS8_EncryptionType_pkcs5_v2_aes256:
            return PKCS_makePKCS5V2PKInfo( MOC_HW(hwAccelCtx)
                                          pKey, pRandomContext,
                                          encType, prfType,
                                          password, passwordLen,
                                          ppRetKeyDER, pRetKeyDERLength);
#endif

#endif /* !defined(__DISABLE_AES_CIPHERS__) */

#endif /*  __ENABLE_DIGICERT_PKCS5__  */

#if defined(__ENABLE_DIGICERT_PKCS12__)
#if !defined(__DISABLE_3DES_CIPHERS__)
        case PCKS8_EncryptionType_pkcs12_sha_2des:
        case PCKS8_EncryptionType_pkcs12_sha_3des:
            return PKCS_makePKCS12PKInfo( MOC_HW(hwAccelCtx)
                                            pKey, pRandomContext,
                                            encType, password, passwordLen,
                                            ppRetKeyDER, pRetKeyDERLength);
#endif

#if defined(__ENABLE_ARC2_CIPHERS__)
        case PCKS8_EncryptionType_pkcs12_sha_rc2_40:
        case PCKS8_EncryptionType_pkcs12_sha_rc2_128:
            return PKCS_makePKCS12PKInfo( MOC_HW(hwAccelCtx)
                                            pKey, pRandomContext,
                                            encType, password, passwordLen,
                                            ppRetKeyDER, pRetKeyDERLength);
#endif

#if !defined(__DISABLE_ARC4_CIPHERS__)
        case PCKS8_EncryptionType_pkcs12_sha_rc4_40:
        case PCKS8_EncryptionType_pkcs12_sha_rc4_128:
            return PKCS_makePKCS12PKInfo( MOC_HW(hwAccelCtx)
                                            pKey, pRandomContext,
                                            encType, password, passwordLen,
                                            ppRetKeyDER, pRetKeyDERLength);
#endif
#endif /* __ENABLE_DIGICERT_PKCS12__ */

        default:
            return ERR_RSA_UNSUPPORTED_PKCS8_ALGO;
    }
}


/*------------------------------------------------------------------*/

/**
@coming_soon
@ingroup    pkcs_functions

@funcdoc    pkcs_key.c
*/
MOC_EXTERN MSTATUS PKCS_setPKCS8Key(MOC_HW(hwAccelDescr hwAccelCtx)
                                    const AsymmetricKey* pKey,
                                    randomContext* pRandomContext,
                                    enum PKCS8EncryptionType encType,
                                    enum PKCS8PrfType prfType,
                                    const ubyte* password, ubyte4 passwordLen,
                                    ubyte **ppRetKeyDER, ubyte4 *pRetKeyDERLength)
{
    if (!pKey || !ppRetKeyDER || !pRetKeyDERLength)
        return ERR_NULL_POINTER;

#ifdef __ENABLE_DIGICERT_ECC__
#ifdef __ENABLE_DIGICERT_PQC__
    if (akt_rsa != pKey->type && akt_rsa_pss != pKey->type && akt_ecc != pKey->type && akt_ecc_ed != pKey->type && akt_hybrid != pKey->type)
#else
    if (akt_rsa != pKey->type && akt_rsa_pss != pKey->type && akt_ecc != pKey->type && akt_ecc_ed != pKey->type)
#endif
#else
    if (akt_rsa != pKey->type && akt_rsa_pss != pKey->type)
#endif
        return ERR_BAD_KEY_TYPE;

    if (!password || !passwordLen)
    {
         return PKCS_makePrivateKeyInfo(MOC_ASYM(hwAccelCtx)
                            pKey, 0, ppRetKeyDER, pRetKeyDERLength);
    }
    else /* encrypted key */
    {
        return PKCS_makeEncryptionPrivateKeyInfo(MOC_HW(hwAccelCtx)
                                                pKey, pRandomContext,
                                                encType, prfType, password,
                                                passwordLen, ppRetKeyDER,
                                                pRetKeyDERLength);
    }
}

#endif /* defined( __ENABLE_DIGICERT_DER_CONVERSION__) */
