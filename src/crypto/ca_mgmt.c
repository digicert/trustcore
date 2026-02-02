/*
 * ca_mgmt.c
 *
 * Certificate Authority Management Factory
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

/* Doxygen moved to ca_mgmt.h, remaining comments that
 look like doxygen will not be picked up. Just left here
 for legacy purposes.
 */

#include "../common/moptions.h"

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mrtos.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/memory_debug.h"
#include "../common/base64.h"
#include "../common/datetime.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/crypto.h"
#ifdef __ENABLE_DIGICERT_TPM__
#include "../smp/smp_tpm12/tpm12_lib/tpm/tss_defines.h"
#endif
#ifdef __ENABLE_DIGICERT_DSA__
#include "../crypto/dsa.h"
#endif
#include "../crypto/rsa.h"
#include "../crypto/primefld.h"
#include "../crypto/ecc.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/pkcs_key.h"
#include "../crypto/keyblob.h"
#include "../crypto/ca_mgmt.h"
#include "../harness/harness.h"
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"
#include "../asn1/derencoder.h"
#include "../asn1/oiddefs.h"
#include "../crypto/asn1cert.h"
#include "../crypto/sec_key.h"
#include "../common/utils.h"
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/cryptointerface.h"
#ifdef __ENABLE_DIGICERT_DSA__
#include "../crypto_interface/crypto_interface_dsa.h"
#endif
#ifdef __ENABLE_DIGICERT_PQC__
#include "../crypto_interface/crypto_interface_qs.h"
#endif
#endif

#define MOC_CERT_BEGIN_STR "-----BEGIN"
#define MOC_CERT_BEGIN_LEN 10

#if (defined(__ENABLE_DIGICERT_PKCS10__) || defined(__ENABLE_DIGICERT_PEM_CONVERSION__))

/*------------------------------------------------------------------*/

static void
fetchLine(ubyte *pSrc,  ubyte4 *pSrcIndex, ubyte4 srcLength,
          ubyte *pDest, ubyte4 *pDestIndex)
{
    pSrc += (*pSrcIndex);

    if ('-' == *pSrc)
    {
        /* handle '---- XXX ----' lines */
        /* seek CR or LF */
        while ((*pSrcIndex < srcLength) && ((0x0d != *pSrc) && (0x0a != *pSrc)))
        {
            (*pSrcIndex)++;
            pSrc++;
        }

        /* skip CR and LF */
        while ((*pSrcIndex < srcLength) && ((0x0d == *pSrc) || (0x0a == *pSrc)))
        {
            (*pSrcIndex)++;
            pSrc++;
        }
    }
    else
    {
        pDest += (*pDestIndex);

        /* handle base64 encoded data line */
        while ((*pSrcIndex < srcLength) &&
               ((0x20 != *pSrc) && (0x0d != *pSrc) && (0x0a != *pSrc)))
        {
            *pDest = *pSrc;

            (*pSrcIndex)++;
            (*pDestIndex)++;
            pSrc++;
            pDest++;
        }

        /* skip to next line */
        while ((*pSrcIndex < srcLength) &&
               ((0x20 == *pSrc) || (0x0d == *pSrc) || (0x0a == *pSrc) || (0x09 == *pSrc)))
        {
            (*pSrcIndex)++;
            pSrc++;
        }
    }
} /* fetchLine */

#endif /* (defined(__ENABLE_DIGICERT_PKCS10__) || defined(__ENABLE_DIGICERT_PEM_CONVERSION__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_PKCS10__) || defined(__ENABLE_DIGICERT_PEM_CONVERSION__))

extern sbyte4
CA_MGMT_decodeCertificate(ubyte*  pKeyFile, ubyte4 fileSize,
                          ubyte** ppDecodeFile, ubyte4 *pDecodedLength)
{
    /* misleading name: decode any PEM message */
    ubyte*  pBase64Mesg = NULL;
    ubyte4  srcIndex    = 0;
    ubyte4  destIndex   = 0;
    sbyte4  numDelimiters = 0;
    ubyte4 i = 0;
    ubyte found = FALSE;
    ubyte4 size = fileSize;
    ubyte *pData = pKeyFile;
    MSTATUS status;

    if ((!pKeyFile) || (!ppDecodeFile) || (!pDecodedLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Check if the buffer contains a banner */
    if (fileSize > MOC_CERT_BEGIN_LEN)
    {
        /* This looks like it starts with the banner, check to make sure */
        if ('-' == pKeyFile[srcIndex])
        {
            if (0 == DIGI_STRNICMP((const sbyte *)pKeyFile,
                                (const sbyte *)MOC_CERT_BEGIN_STR,
                                MOC_CERT_BEGIN_LEN))
            {
                found = TRUE;
            }
        }

        /* If the first line doesnt start with '-', scan to find the begin string */
        i = 1;
        while( (i < size) && (FALSE == found) )
        {
            if ( (0x0a == pKeyFile[i-1]) && ('-' == pKeyFile[i]) && ((i + MOC_CERT_BEGIN_LEN) < size))
            {
                if (0 == DIGI_STRNICMP((const sbyte *)(pKeyFile + i),
                                    (const sbyte *)MOC_CERT_BEGIN_STR,
                                    MOC_CERT_BEGIN_LEN))
                {
                    found = TRUE;
                    pKeyFile += i;
                    fileSize -= i;
                }
            }

            i++;
        }
    }

    /* Buffer does not contain a banner, restore the original size of the buffer
     * and attempt to decode the entire buffer */
    if (FALSE == found)
    {
        fileSize = size;
        pKeyFile = pData;
    }

    if (NULL == (pBase64Mesg = MALLOC( fileSize)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    while (fileSize > srcIndex && numDelimiters < 2)
    {
        if ('-' == pKeyFile[srcIndex])
        {
            ++numDelimiters;
        }
        fetchLine(pKeyFile, &srcIndex, fileSize, pBase64Mesg, &destIndex);
    }

    status = BASE64_decodeMessage((ubyte *)pBase64Mesg, destIndex, ppDecodeFile, pDecodedLength);

exit:
    if (NULL != pBase64Mesg)
        FREE(pBase64Mesg);

    return (sbyte4)status;
}


#endif /* (defined(__ENABLE_DIGICERT_PKCS10__) || defined(__ENABLE_DIGICERT_PEM_CONVERSION__)) */


#if !(defined(__DISABLE_DIGICERT_KEY_GENERATION__)) || defined(__ENABLE_DIGICERT_PEM_CONVERSION__) || defined(__ENABLE_DIGICERT_DER_CONVERSION__)

/*------------------------------------------------------------------*/

extern MSTATUS
CA_MGMT_makeKeyBlobEx(const AsymmetricKey *pKey,
                      ubyte **ppRetKeyBlob, ubyte4 *pRetKeyLength)
{
    return KEYBLOB_makeKeyBlobEx(pKey, ppRetKeyBlob, pRetKeyLength);
}

#endif


/*------------------------------------------------------------------*/

extern MSTATUS
CA_MGMT_extractKeyBlobEx(const ubyte *pKeyBlob, ubyte4 keyBlobLength,
                         AsymmetricKey* pKey)
{
    return KEYBLOB_extractKeyBlobEx(pKeyBlob, keyBlobLength, pKey);
}


/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_DIGICERT_KEY_GENERATION__))
extern MSTATUS
CA_MGMT_extractPublicKey(const ubyte *pKeyBlob, ubyte4 keyBlobLength,
                         ubyte **ppRetPublicKeyBlob, ubyte4 *pRetPublicKeyBlobLength,
                         ubyte4 *pRetKeyType)
{
    return KEYBLOB_extractPublicKey(pKeyBlob, keyBlobLength, ppRetPublicKeyBlob,
                         pRetPublicKeyBlobLength, pRetKeyType);
}
#endif


/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_DIGICERT_CERTIFICATE_GENERATION__) && !defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__))
#if (!defined(__DISABLE_DIGICERT_KEY_GENERATION__))


static MSTATUS
CA_MGMT_makeKeyFromKeySize( MOC_ASYM(hwAccelDescr hwAccelCtx)
                           ubyte4 keySize, AsymmetricKey* pKey)
{
    MSTATUS status = ERR_INVALID_INPUT;
    vlong* pVlongQueue = NULL;
#if (defined(__ENABLE_DIGICERT_ECC__))
    ubyte4 eccCurveId = 0;
#endif

    switch (keySize)
    {
#if (defined(__ENABLE_DIGICERT_ECC__))
#ifdef __ENABLE_DIGICERT_ECC_P192__
        case 192:
            eccCurveId = cid_EC_P192;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
        case 224:
            eccCurveId = cid_EC_P224;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
        case 256:
            eccCurveId = cid_EC_P256;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
        case 384:
            eccCurveId = cid_EC_P384;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
        case 521:
            eccCurveId = cid_EC_P521;
            break;
#endif
#endif /* defined(__ENABLE_DIGICERT_ECC__) */

        case 1024: case 1536:
        case 2048: case 3072:
        case 4096:
            break;

        default:
            status = ERR_EC_UNSUPPORTED_CURVE;
            goto exit;
            break;
    }
#if (defined(__ENABLE_DIGICERT_ECC__))
    if (eccCurveId) /* ECC */
    {
        ECCKey* pECCKey;

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
        status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc( MOC_ECC(hwAccelCtx)
            eccCurveId, (void **)&pECCKey, RANDOM_rngFun, g_pRandomContext, akt_ecc, NULL);
#else
        status = EC_generateKeyPairAlloc( MOC_ECC(hwAccelCtx)
            eccCurveId, &pECCKey, RANDOM_rngFun, g_pRandomContext);
#endif
        if (OK != status)
            goto exit;

        status = CRYPTO_loadAsymmetricKey(pKey, akt_ecc, (void **) &pECCKey);
        if (OK != status)
            goto exit;
    }
#ifndef __DISABLE_DIGICERT_RSA__
    else /* RSA */
#endif /* __DISABLE_DIGICERT_RSA__ */

#endif /* __ENABLE_DIGICERT_ECC__ */
#ifndef __DISABLE_DIGICERT_RSA__
    {
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
        status = CRYPTO_INTERFACE_RSA_generateKeyAlloc(MOC_RSA(hwAccelCtx)
                                                       g_pRandomContext, (void **)&(pKey->key.pRSA),
                                                       keySize, &pVlongQueue, akt_rsa, NULL);
        if (OK != status)
            goto exit;

        pKey->type = akt_rsa;
#else
        if (OK > (status = CRYPTO_createRSAKey(pKey, &pVlongQueue)))
            goto exit;

        if (OK > (status = RSA_generateKey(MOC_RSA(hwAccelCtx)
                                           g_pRandomContext, pKey->key.pRSA,
                                           keySize, &pVlongQueue)))
        {
            goto exit;
        }
#endif
    }
#endif
exit:

    VLONG_freeVlongQueue(&pVlongQueue);

    return status;
}

MOC_EXTERN sbyte4
CA_MGMT_makeSubjectAltNameExtension( extensions* pExtension,
                                    const SubjectAltNameAttr* nameAttrs,
                                    sbyte4 numNameAttrs)
{
    DER_ITEMPTR pRoot = 0;
    sbyte4 i, retVal = 0;

    if ( (NULL == pExtension) || (NULL == nameAttrs) || (0 == numNameAttrs) )
    {
        retVal = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > ( retVal = DER_AddSequence(NULL, &pRoot)))
        goto exit;

    for (i = 0; i < numNameAttrs; ++i)
    {
        if (OK > (retVal = DER_AddItem(pRoot, (CONTEXT|nameAttrs[i].subjectAltNameType),
                                       (ubyte4) nameAttrs[i].subjectAltNameValue.dataLen,
                                       nameAttrs[i].subjectAltNameValue.data, NULL)))
        {
            goto exit;
        }
    }

    if (OK > ( retVal = DER_Serialize(pRoot, &pExtension->value, &pExtension->valueLen)))
        goto exit;

    pExtension->oid = (ubyte*) subjectAltName_OID;
    pExtension->isCritical = 0;

exit:

    if (pRoot)
    {
        TREE_DeleteTreeItem((TreeItem*) pRoot);
    }

    return retVal;

}

extern sbyte4
CA_MGMT_generateCertificateExType( certDescriptor *pRetCertificate, ubyte4 keyType, ubyte4 keySize,
                                const certDistinguishedName *pCertInfo, ubyte signAlgorithm,
                                const certExtensions* pExtensions,
                                const certDescriptor* pParentCertificate)
{
    hwAccelDescr    hwAccelCtx;
    AsymmetricKey   key;
    MSTATUS         status;
    vlong*          pVlongQueue = NULL;
    MOC_UNUSED(pParentCertificate);

    CRYPTO_initAsymmetricKey (&key);

    status = ERR_NULL_POINTER;
    if ( !pRetCertificate || !pCertInfo) /* the others can be null */
        goto exit;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
       goto exit;

    /* initialize results */
    pRetCertificate->pCertificate  = NULL;
    pRetCertificate->certLength    = 0;
    pRetCertificate->pKeyBlob   = NULL;
    pRetCertificate->keyBlobLength = 0;

    if (akt_ecc == keyType || akt_ecc_ed == keyType)
    {
#if (defined(__ENABLE_DIGICERT_ECC__))
        ubyte4 eccCurveId = 0;

        if (akt_ecc == keyType)
        {
            switch (keySize)
            {
#ifdef __ENABLE_DIGICERT_ECC_P192__
                case 192:
                {
                    eccCurveId = cid_EC_P192;
                    break;
                }
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
                case 224:
                {
                    eccCurveId = cid_EC_P224;
                    break;
                }
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
                case 256:
                {
                    eccCurveId = cid_EC_P256;
                    break;
                }
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
                case 384:
                {
                    eccCurveId = cid_EC_P384;
                    break;
                }
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
                case 521:
                {
                    eccCurveId = cid_EC_P521;
                    break;
                }
#endif
                default:
                {
                    status = ERR_EC_UNSUPPORTED_CURVE;
                    goto exit;
                }
            } /* switch */
        }
        else  /* akt_ecc_ed == keyType */
        {
            switch (keySize)
            {
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
                case 255:
                {
                    eccCurveId = cid_EC_Ed25519;
                    break;
                }
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
                case 448:
                {
                    eccCurveId = cid_EC_Ed448;
                    break;
                }
#endif
                default:
                {
                    status = ERR_EC_UNSUPPORTED_CURVE;
                    goto exit;
                }
            } /* switch */
        }

        if (eccCurveId)
        {
            ECCKey *pEccKey = NULL;

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
            status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc(MOC_ECC(hwAccelCtx)
                eccCurveId, (void **)&pEccKey, RANDOM_rngFun, g_pRandomContext, keyType, NULL);
#else
            status = EC_generateKeyPairAlloc(MOC_ECC(hwAccelCtx)
                eccCurveId, &pEccKey, RANDOM_rngFun, g_pRandomContext);
#endif
            if (OK > status)
                goto exit;

            status = CRYPTO_loadAsymmetricKey(&key, keyType, (void **) &pEccKey);
			if (OK > status)
			{
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
				(void) CRYPTO_INTERFACE_EC_deleteKeyAux(&pEccKey); /* don't change status */
#else
				(void) EC_deleteKeyEx(&pEccKey);
#endif
				goto exit;
			}
        }
#else
        status = ERR_CRYPTO_ECC_DISABLED;
        goto exit;
#endif /* __ENABLE_DIGICERT_ECC__ */
    }
    else if (akt_rsa == keyType)
    {
#ifndef __DISABLE_DIGICERT_RSA__
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
        status = CRYPTO_INTERFACE_RSA_generateKeyAlloc(MOC_RSA(hwAccelCtx)
                                                       g_pRandomContext, (void **)&(key.key.pRSA),
                                                       keySize, &pVlongQueue, akt_rsa, NULL);
        if (OK != status)
            goto exit;

        key.type = akt_rsa;
#else
        if (OK > (status = CRYPTO_createRSAKey(&key, &pVlongQueue)))
            goto exit;

        if (OK > (status = RSA_generateKey(MOC_RSA(hwAccelCtx) g_pRandomContext,
                                           key.key.pRSA, keySize, &pVlongQueue)))
        {
            goto exit;
        }
#endif
#else
        status = ERR_RSA_DISABLED;
        goto exit;
#endif
    }
    else if (akt_dsa == keyType)
    {
#if (defined(__ENABLE_DIGICERT_DSA__))
        if (OK > (status = CRYPTO_createDSAKey(&key, &pVlongQueue)))
            goto exit;
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
        if (OK > (status = CRYPTO_INTERFACE_DSA_generateKeyAux(MOC_DSA(hwAccelCtx) g_pRandomContext, key.key.pDSA, keySize, &pVlongQueue)))
#else
        if (OK > (status = DSA_generateKey(MOC_DSA(hwAccelCtx) g_pRandomContext, key.key.pDSA, keySize, NULL, NULL, NULL, &pVlongQueue)))
#endif
            goto exit;

        if (keySize == 1024)
          signAlgorithm = ht_sha1;
        else
          signAlgorithm = ht_sha256;
#else
        status = ERR_CRYPTO_DSA_DISABLED;
        goto exit;
#endif
	}
    else
    {
        status = ERR_BAD_KEY_TYPE;
        goto exit;
    }

    if (OK > (status = CA_MGMT_makeKeyBlobEx(&key, &pRetCertificate->pKeyBlob,
                                             &pRetCertificate->keyBlobLength)))
    {
        goto exit;
    }

    if (OK > (status = ASN1CERT_generateSelfSignedCertificate(MOC_ASYM(hwAccelCtx) &key, pCertInfo,
							     signAlgorithm, pExtensions,
							     RANDOM_rngFun, g_pRandomContext,
							     &pRetCertificate->pCertificate,
							     &pRetCertificate->certLength)))
    {
       goto exit;
    }

exit:

    if ((OK > status) && (NULL != pRetCertificate))
    {
        if (NULL != pRetCertificate->pCertificate)
        {
            FREE(pRetCertificate->pCertificate);   pRetCertificate->pCertificate = NULL;
        }

        if (NULL != pRetCertificate->pKeyBlob)
        {
            FREE(pRetCertificate->pKeyBlob);    pRetCertificate->pKeyBlob = NULL;
        }
    }

    CRYPTO_uninitAsymmetricKey(&key, 0);
    if (pVlongQueue) VLONG_freeVlongQueue(&pVlongQueue);

    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    return (sbyte4)status;

}

#if (defined(__ENABLE_DIGICERT_PQC__) && defined(__ENABLE_DIGICERT_ECC__))
extern sbyte4 CA_MGMT_generateCertificateHybrid(MOC_ASYM(hwAccelDescr hwAccelCtx)
    certDescriptor *pRetCertificate, ubyte4 clAlg, ubyte4 qsAlg,
    const certDistinguishedName *pCertInfo, const certExtensions* pExtensions,
	const certDescriptor* pParentCertificate)
{
    AsymmetricKey   key = {0};
    MSTATUS         status = OK;
	QS_CTX *pCtx = NULL;
    MOC_UNUSED(pParentCertificate);

    CRYPTO_initAsymmetricKey (&key);

    status = ERR_NULL_POINTER;
    if ( !pRetCertificate || !pCertInfo) /* the others can be null */
        goto exit;

    /* QS Alg will be validated in call to CRYPTO_INTERFACE_QS_newCtx */

    /* initialize results */
    pRetCertificate->pCertificate  = NULL;
    pRetCertificate->certLength    = 0;
    pRetCertificate->pKeyBlob   = NULL;
    pRetCertificate->keyBlobLength = 0;

	status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(hwAccelCtx) &pCtx, qsAlg);
	if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_generateKeyPair(MOC_HASH(hwAccelCtx) pCtx, RANDOM_rngFun, g_pRandomContext);
    if (OK != status)
        goto exit;

    if (clAlg == cid_RSA_2048_PKCS15 || clAlg == cid_RSA_2048_PSS)
    {
        status = CRYPTO_INTERFACE_RSA_generateKeyAlloc(MOC_RSA(hwAccelCtx) g_pRandomContext, (void **)&(key.key.pRSA),
                                                       2048, NULL, akt_rsa, NULL);
    }
    else if (clAlg == cid_RSA_3072_PKCS15 || clAlg == cid_RSA_3072_PSS)
    {
        status = CRYPTO_INTERFACE_RSA_generateKeyAlloc(MOC_RSA(hwAccelCtx) g_pRandomContext, (void **)&(key.key.pRSA),
                                                       3072, NULL, akt_rsa, NULL);
    }
    else if (clAlg == cid_RSA_4096_PKCS15 || clAlg == cid_RSA_4096_PSS)
    {
        status = CRYPTO_INTERFACE_RSA_generateKeyAlloc(MOC_RSA(hwAccelCtx) g_pRandomContext, (void **)&(key.key.pRSA),
                                                       4096, NULL, akt_rsa, NULL);
    }
    else /* ECC */
    {
        status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc(MOC_ECC(hwAccelCtx) clAlg, (void **)&(key.key.pECC), RANDOM_rngFun, g_pRandomContext, akt_ecc, NULL);
    }
    if (OK != status)
        goto exit;

    key.clAlg = clAlg;
    key.type = akt_hybrid;
    key.pQsCtx = pCtx; pCtx = NULL;

    status = CA_MGMT_makeKeyBlobEx(&key, &pRetCertificate->pKeyBlob, &pRetCertificate->keyBlobLength);
	if (OK != status)
        goto exit;

    status = ASN1CERT_generateSelfSignedCertificate(MOC_ASYM(hwAccelCtx) &key, pCertInfo, ht_none, pExtensions,
							     RANDOM_rngFun, g_pRandomContext, &pRetCertificate->pCertificate,
							     &pRetCertificate->certLength);

exit:

    if (NULL != pCtx)
    {
        (void) CRYPTO_INTERFACE_QS_deleteCtx(&pCtx);
    }

    if ((OK > status) && (NULL != pRetCertificate))
    {
        if (NULL != pRetCertificate->pCertificate)
        {
            FREE(pRetCertificate->pCertificate);   pRetCertificate->pCertificate = NULL;
        }

        if (NULL != pRetCertificate->pKeyBlob)
        {
            FREE(pRetCertificate->pKeyBlob);    pRetCertificate->pKeyBlob = NULL;
        }
    }

    CRYPTO_uninitAsymmetricKey(&key, 0);
    return (sbyte4) status;
}
#endif /* #if (defined(__ENABLE_DIGICERT_PQC__) && defined(__ENABLE_DIGICERT_ECC__)) */

extern sbyte4
CA_MGMT_generateCertificateEx( certDescriptor *pRetCertificate, ubyte4 keySize,
                                const certDistinguishedName *pCertInfo, ubyte signAlgorithm,
                                const certExtensions* pExtensions,
                                const certDescriptor* pParentCertificate)
{
    hwAccelDescr    hwAccelCtx;
    AsymmetricKey   key, signKey;
    ASN1_ITEMPTR    pRootItem = 0;
    MSTATUS         status;

    if ( !pRetCertificate || !pCertInfo) /* the others can be null */
        return ERR_NULL_POINTER;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        return status;

    CRYPTO_initAsymmetricKey( &key);
    CRYPTO_initAsymmetricKey( &signKey);

    /* initialize results */
    pRetCertificate->pCertificate  = NULL;
    pRetCertificate->certLength    = 0;
    if (NULL == pRetCertificate->pKey)
    {
        pRetCertificate->pKeyBlob   = NULL;
        pRetCertificate->keyBlobLength = 0;

        if (OK > ( status = CA_MGMT_makeKeyFromKeySize(MOC_ASYM(hwAccelCtx) keySize,
                        &key)))
        {
            goto exit;
        }

        if (OK > (status = CA_MGMT_makeKeyBlobEx(&key, &pRetCertificate->pKeyBlob,
                        &pRetCertificate->keyBlobLength)))
        {
            goto exit;
        }
    }

    /* is there a signing certificate or are we self-signed ? */
    if (pParentCertificate)
    {
        /* need to extract some info */
        ASN1_ITEMPTR pIssuerInfo;
        CStream cs;
        MemFile mf;

        MF_attach( &mf, pParentCertificate->certLength, pParentCertificate->pCertificate);
        CS_AttachMemFile( &cs, &mf);

        if ( OK > ( status = X509_parseCertificate( cs, &pRootItem)))
            goto exit;

        if ( OK > ( status = X509_getCertificateSubject(ASN1_FIRST_CHILD(pRootItem),
                                                        &pIssuerInfo)))
        {
            goto exit;
        }

        if (NULL == pParentCertificate->pKey)
        {
            /* extract the key now */
            if (OK > ( status = CA_MGMT_extractKeyBlobEx(
                            pParentCertificate->pKeyBlob,
                            pParentCertificate->keyBlobLength,
                            &signKey)))
            {
                goto exit;
            }
        }

        /* generate the leaf certificate */
        if (OK > ( status = ASN1CERT_generateCertificate(
                        MOC_ASYM(hwAccelCtx) ((NULL == pRetCertificate->pKey) ? &key : pRetCertificate->pKey),
                        pCertInfo,
                        ((NULL == pParentCertificate->pKey) ? &signKey: pParentCertificate->pKey),
                                                                pIssuerInfo, cs, signAlgorithm,
                                                                pExtensions, RANDOM_rngFun, g_pRandomContext,
                                                                &pRetCertificate->pCertificate,
                                                                &pRetCertificate->certLength)))
        {
            goto exit;
        }
    }
    else
    {
        if (OK > (status = ASN1CERT_generateSelfSignedCertificate(
                        MOC_ASYM(hwAccelCtx) ((NULL == pRetCertificate->pKey) ? &key : pRetCertificate->pKey),
                        pCertInfo,
                                                        signAlgorithm, pExtensions,
                                                        RANDOM_rngFun, g_pRandomContext,
                                                        &pRetCertificate->pCertificate,
                                                        &pRetCertificate->certLength)))
        {
            goto exit;
        }
    }

exit:
    if (OK > status)
    {
        if (NULL != pRetCertificate->pCertificate)
        {
            FREE(pRetCertificate->pCertificate);   pRetCertificate->pCertificate = NULL;
        }

        if (NULL != pRetCertificate->pKeyBlob)
        {
            FREE(pRetCertificate->pKeyBlob);    pRetCertificate->pKeyBlob = NULL;
        }
    }

    if (pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }

    CRYPTO_uninitAsymmetricKey(&signKey, 0);
    CRYPTO_uninitAsymmetricKey(&key, 0);

    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    return (sbyte4)status;
}


extern sbyte4
CA_MGMT_generateCertificateWithProperties( certDescriptor *pRetCertificate,
                                          const certDistinguishedName* pCertInfo,
                                          const CertProperties* properties)
{
    hwAccelDescr    hwAccelCtx;
    AsymmetricKey   key, signKey;
    const AsymmetricKey* pCertKey = 0;
    const AsymmetricKey* pSignKey = 0;
    ASN1_ITEMPTR    pRootItem = 0;
    ASN1_ITEMPTR    pIssuerInfo = 0;
    CStream         cs = { 0 };
    MSTATUS         status;

    if ( !pRetCertificate || !pCertInfo) /* the others can be null */
        return ERR_NULL_POINTER;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        return status;

    /* initialize results */
    pRetCertificate->pCertificate  = NULL;
    pRetCertificate->certLength    = 0;
    pRetCertificate->pKeyBlob   = NULL;
    pRetCertificate->keyBlobLength = 0;

    CRYPTO_initAsymmetricKey( &key);
    CRYPTO_initAsymmetricKey( &signKey);

    switch (properties->keyPropertyType)
    {
        case kp_size:
            if (OK > (status = CA_MGMT_makeKeyFromKeySize(MOC_ASYM(hwAccelCtx)
                                                          properties->keyProperty.keySize,
                                                          &key)))
            {
                goto exit;
            }
            pCertKey = &key;
            break;


        case kp_key:
            if (!properties->keyProperty.pKey)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }
            pCertKey = properties->keyProperty.pKey;
            break;

        case kp_blob:
            if (OK > ( status = CA_MGMT_extractKeyBlobEx(properties->keyProperty.keyBlob.data,
                                                         properties->keyProperty.keyBlob.dataLen,
                                                         &key)))
            {
                goto exit;
            }
            pCertKey = &key;
            break;

        default:
            status = ERR_INVALID_ARG;
            goto exit;
    }

    if (OK > (status = CA_MGMT_makeKeyBlobEx(pCertKey,
                                             &pRetCertificate->pKeyBlob,
                                             &pRetCertificate->keyBlobLength)))
    {
        goto exit;
    }

    /* is there a signing certificate or are we self-signed ? */
    if (properties->pParentCert)
    {
        const certDescriptor* pParentCertificate = properties->pParentCert;
        /* need to extract some info */
        MemFile mf;

        MF_attach( &mf, pParentCertificate->certLength,
                  pParentCertificate->pCertificate);
        CS_AttachMemFile( &cs, &mf);

        if ( OK > ( status = X509_parseCertificate( cs, &pRootItem)))
            goto exit;

        if ( OK > ( status = X509_getCertificateSubject(ASN1_FIRST_CHILD(pRootItem),
                                                        &pIssuerInfo)))
            goto exit;

        /* extract the key now */
        if (OK > ( status = CA_MGMT_extractKeyBlobEx(pParentCertificate->pKeyBlob,
                                                     pParentCertificate->keyBlobLength,
                                                     &signKey)))
        {
            goto exit;
        }

        pSignKey = &signKey;
    }

    /* generate the leaf certificate */
    if (OK > ( status = ASN1CERT_generateCertificateEx( MOC_ASYM(hwAccelCtx)
                                                       pCertKey, pCertInfo,
                                                       pSignKey,
                                                       pIssuerInfo, cs,
                                                       properties->serialNumber.data,
                                                       properties->serialNumber.dataLen,
                                                       properties->signAlgorithm,
                                                       properties->pExtensions,
                                                       RANDOM_rngFun,
                                                       g_pRandomContext,
                                                       &pRetCertificate->pCertificate,
                                                       &pRetCertificate->certLength)))
    {
        goto exit;
    }


exit:
    if (OK > status)
    {
        if (NULL != pRetCertificate->pCertificate)
        {
            FREE(pRetCertificate->pCertificate);   pRetCertificate->pCertificate = NULL;
        }

        if (NULL != pRetCertificate->pKeyBlob)
        {
            FREE(pRetCertificate->pKeyBlob);    pRetCertificate->pKeyBlob = NULL;
        }
    }

    if (pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }

    CRYPTO_uninitAsymmetricKey(&signKey, 0);
    CRYPTO_uninitAsymmetricKey(&key, 0);

    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    return (sbyte4)status;
}


extern sbyte4
CA_MGMT_generateCertificateEx2( certDescriptor *pRetCertificate,
                               struct AsymmetricKey* key,
                               const certDistinguishedName *pCertInfo,
                               ubyte signAlgorithm)
{
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status;

    if ( !pRetCertificate || !pCertInfo) /* the others can be null */
        return ERR_NULL_POINTER;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        return status;

    /* initialize results */
    pRetCertificate->pCertificate  = NULL;
    pRetCertificate->certLength    = 0;
    pRetCertificate->pKeyBlob   = NULL;
    pRetCertificate->keyBlobLength = 0;

    if (OK > (status = ASN1CERT_generateSelfSignedCertificate(MOC_ASYM(hwAccelCtx) key, pCertInfo,
            signAlgorithm, NULL,
            RANDOM_rngFun, g_pRandomContext,
            &pRetCertificate->pCertificate,
            &pRetCertificate->certLength)))
    {
        goto exit;
    }

    exit:
    if (OK > status)
    {
        if (NULL != pRetCertificate->pCertificate)
        {
            FREE(pRetCertificate->pCertificate);   pRetCertificate->pCertificate = NULL;
        }

        if (NULL != pRetCertificate->pKeyBlob)
        {
            FREE(pRetCertificate->pKeyBlob);    pRetCertificate->pKeyBlob = NULL;
        }
    }

    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    return (sbyte4)status;
}

#endif /* __DISABLE_DIGICERT_KEY_GENERATION__ */


/*------------------------------------------------------------------*/

extern sbyte4
CA_MGMT_freeCertificate(certDescriptor *pFreeCertificateDescr)
{
    if (NULL == pFreeCertificateDescr)
        return (sbyte4)ERR_NULL_POINTER;

    if (NULL != pFreeCertificateDescr->pCertificate)
    {
        FREE(pFreeCertificateDescr->pCertificate);   pFreeCertificateDescr->pCertificate = NULL;
    }

    if (NULL != pFreeCertificateDescr->pKeyBlob)
    {
        FREE(pFreeCertificateDescr->pKeyBlob);    pFreeCertificateDescr->pKeyBlob = NULL;
    }

    return (sbyte4)OK;
}

/*------------------------------------------------------------------*/

extern sbyte4
CA_MGMT_returnCertificatePrints(ubyte *pCertificate, ubyte4 certLength,
                                ubyte *pShaFingerPrint, ubyte *pMD5FingerPrint)
{
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status;

    if ((NULL == pCertificate) || (NULL == pShaFingerPrint) || (NULL == pMD5FingerPrint))
        return ERR_NULL_POINTER;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        return status;

    /* generate an MD5 hash of the certificate */
    if (OK > (status = MD5_completeDigest(MOC_HASH(hwAccelCtx) pCertificate, certLength, pMD5FingerPrint)))
        goto exit;

    /* generate a SHA hash of the certificate */
    if (OK > (status = SHA1_completeDigest(MOC_HASH(hwAccelCtx) pCertificate, certLength, pShaFingerPrint)))
        goto exit;

exit:
    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

extern sbyte4
CA_MGMT_extractCertASN1Name(const ubyte *pCertificate, ubyte4 certificateLength,
                              sbyte4 isSubject, sbyte4 includeASN1SeqHeader,
                              ubyte4* pASN1NameOffset, ubyte4* pASN1NameLen)
{
    /* this function is particularly useful when used with PKCS#10 */

    ASN1_ITEMPTR    pRoot           = NULL;
    ASN1_ITEMPTR    pSubject;
    MemFile         certMemFile;
    MSTATUS         status;
    CStream         cs;

    if (!pCertificate || !pASN1NameOffset || !pASN1NameLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == certificateLength)
    {
        status = ERR_CERT_AUTH_BAD_CERT_LENGTH;
        goto exit;
    }

    MF_attach(&certMemFile, certificateLength, (ubyte*) pCertificate);
    CS_AttachMemFile( &cs, &certMemFile);

    /* parse the certificate */
    if (OK > (status = X509_parseCertificate(cs, &pRoot)))
        goto exit;

    /* fetch the data we want to grab */
    if (isSubject)
    {
        if ( OK > ( status = X509_getCertificateSubject(ASN1_FIRST_CHILD(pRoot),
                                                        &pSubject)))
        {
            goto exit;
        }
    }
    else
    {
        if ( OK > ( status = X509_getCertificateIssuerSerialNumber(ASN1_FIRST_CHILD(pRoot),
                                                                   &pSubject, NULL)))
        {
            goto exit;
        }
    }

    *pASN1NameOffset = (ubyte4) pSubject->dataOffset;
    *pASN1NameLen = pSubject->length;

    if (includeASN1SeqHeader)
    {
        *pASN1NameOffset -= pSubject->headerSize;
        *pASN1NameLen    += pSubject->headerSize;
    }

exit:
    if (pRoot)
        TREE_DeleteTreeItem((TreeItem*)pRoot);

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

extern sbyte4
CA_MGMT_extractCertDistinguishedName(ubyte *pCertificate, ubyte4 certificateLength,
                                     intBoolean isSubject, certDistinguishedName *pRetDN)
{
    ASN1_ITEM*  pRoot           = NULL;
    MemFile     certMemFile;
    MSTATUS status;
    CStream     cs;

    if ((NULL == pCertificate) || (NULL == pRetDN))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == certificateLength)
    {
        status = ERR_CERT_AUTH_BAD_CERT_LENGTH;
        goto exit;
    }

    MF_attach(&certMemFile, certificateLength, pCertificate);
    CS_AttachMemFile( &cs, &certMemFile);

    /* parse the certificate */
    if (OK > (status = X509_parseCertificate(cs, &pRoot)))
        goto exit;

    /* fetch the data we want to grab */
    status = X509_extractDistinguishedNames(ASN1_FIRST_CHILD(pRoot),
                                            cs, isSubject, pRetDN);

exit:
    if (pRoot)
        TREE_DeleteTreeItem((TreeItem*)pRoot);

    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_EXTRACT_CERT_BLOB__

extern sbyte4
CA_MGMT_findCertDistinguishedName(ubyte *pCertificate, ubyte4 certificateLength,
                                  intBoolean isSubject,
                                  ubyte **ppRetDistinguishedName, ubyte4 *pRetDistinguishedNameLen)
{
    ASN1_ITEM*  pRoot           = NULL;
    MemFile     certMemFile;
    MSTATUS status;
    CStream     cs;

    if ((NULL == pCertificate) || (NULL == ppRetDistinguishedName) || (NULL == pRetDistinguishedNameLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == certificateLength)
    {
        status = ERR_CERT_AUTH_BAD_CERT_LENGTH;
        goto exit;
    }

    MF_attach(&certMemFile, certificateLength, pCertificate);
    CS_AttachMemFile( &cs, &certMemFile);

    /* parse the certificate */
    if (OK > (status = X509_parseCertificate(cs, &pRoot)))
        goto exit;

    /* fetch the data we want to grab */
    status = X509_extractDistinguishedNamesBlob(ASN1_FIRST_CHILD(pRoot),
                                                cs, isSubject,
                                                ppRetDistinguishedName,
                                                pRetDistinguishedNameLen);

exit:
    if (pRoot)
        TREE_DeleteTreeItem((TreeItem*)pRoot);

    return (sbyte4)status;
}
#endif /* __ENABLE_DIGICERT_EXTRACT_CERT_BLOB__ */



/*------------------------------------------------------------------*/


extern sbyte4
CA_MGMT_extractCertTimes(ubyte *pCertificate, ubyte4 certificateLength,
                         certDistinguishedName *pRetDN)
{
    ASN1_ITEM*  pRoot           = NULL;
    MemFile     certMemFile;
    MSTATUS status;
    CStream     cs;

    if ((NULL == pCertificate) || (NULL == pRetDN))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == certificateLength)
    {
        status = ERR_CERT_AUTH_BAD_CERT_LENGTH;
        goto exit;
    }

    MF_attach(&certMemFile, certificateLength, pCertificate);
    CS_AttachMemFile( &cs, &certMemFile);

    /* parse the certificate */
    if (OK > (status = X509_parseCertificate(cs, &pRoot)))
        goto exit;

    /* fetch the data we want to grab */
    status = X509_extractValidityTime(ASN1_FIRST_CHILD(pRoot), cs, pRetDN);

exit:
    if (pRoot)
        TREE_DeleteTreeItem((TreeItem*)pRoot);

    return (sbyte4)status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
CA_MGMT_verifyCertDate(ubyte *pCert, ubyte4 certLen)
{
    MSTATUS status = OK;
    certDistinguishedName *pCertInfo = NULL;
    TimeDate startTimeDate = {0};
    TimeDate endTimeDate = {0};
    TimeDate gmtTimeDate = {0};
    sbyte4 results = 0;

    if (NULL == pCert)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Get the current time.
     */
    status = RTOS_timeGMT(&gmtTimeDate);
    if (OK != status)
        goto exit;

    status = CA_MGMT_allocCertDistinguishedName(&pCertInfo);
    if (OK != status)
        goto exit;

    /* Extract the certificate start and end date.
     */
    status = CA_MGMT_extractCertTimes(pCert, certLen, pCertInfo);
    if (OK != status)
        goto exit;

    /* Validate the certificate start time.
     */
    status = DATETIME_convertFromValidityString((const sbyte*)pCertInfo->pStartDate, &startTimeDate);
    if (OK != status)
        goto exit;

    results = DIGI_cmpTimeDate(&gmtTimeDate, &startTimeDate);
    if ( results < 0)
    {
        status = ERR_CERT_START_TIME_VALID_IN_FUTURE;
        goto exit;
    }

    /* Validate the certificate end time.
     */
    status = DATETIME_convertFromValidityString((const sbyte*)pCertInfo->pEndDate, &endTimeDate);
    if (OK != status)
        goto exit;

    results = DIGI_cmpTimeDate(&endTimeDate, &gmtTimeDate);
    if ( results <= 0)
    {
        status = ERR_CERT_EXPIRED;
        goto exit;
    }

exit:

    if (pCertInfo != NULL)
    {
        CA_MGMT_freeCertDistinguishedName(&pCertInfo);
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS CA_MGMT_verifyCertAndKeyPair(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pCert,
    ubyte4 certLen,
    struct AsymmetricKey *pAsymKey,
    byteBoolean *pIsGood)
{
    MSTATUS status;
    ASN1_ITEM *pRoot = NULL;
    CStream cs;
    MemFile mf;
    AsymmetricKey certKey;

    CRYPTO_initAsymmetricKey(&certKey);

    if (NULL == pCert || NULL == pAsymKey || NULL == pIsGood)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Default to invalid */
    *pIsGood = FALSE;

    if (0 == certLen)
    {
        status = ERR_CERT_AUTH_BAD_CERT_LENGTH;
        goto exit;
    }

    MF_attach(&mf, certLen, pCert);
    CS_AttachMemFile(&cs, &mf);

    status = X509_parseCertificate(cs, &pRoot);
    if (OK != status)
    {
        goto exit;
    }

    status = X509_setKeyFromSubjectPublicKeyInfo(
        MOC_ASYM(hwAccelCtx) ASN1_FIRST_CHILD(pRoot), cs, &certKey);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_matchPublicKey(pAsymKey, &certKey);
    if (OK == status)
    {
        /* Keys match */
        *pIsGood = TRUE;
    }
    else if (ERR_FALSE == status)
    {
        /* Keys do not match */
        status = OK;
    }

exit:

    CRYPTO_uninitAsymmetricKey(&certKey, NULL);

    if (NULL != pRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pRoot);
    }

    return status;
}

/*------------------------------------------------------------------*/

extern sbyte4
CA_MGMT_verifyCertWithKeyBlob(certDescriptor *pCertificateDescr, sbyte4 *pIsGood)
{
    hwAccelDescr    hwAccelCtx;
    ASN1_ITEM*      pRoot           = NULL;
    MemFile         certMemFile;
    AsymmetricKey   pBlobKey;
    vlong*          pN              = NULL;
    AsymmetricKey   certKey;
    MSTATUS         status;
    CStream         cs;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    byteBoolean cmpRes;
    MRsaKeyTemplate priTemplate = { 0 };
    vlong *pPrime = NULL, *pSubprime = NULL, *pModulus = NULL;
#endif

    CRYPTO_initAsymmetricKey(&certKey);
    CRYPTO_initAsymmetricKey(&pBlobKey);

    if ((NULL == pCertificateDescr) || (NULL == pCertificateDescr->pCertificate) || (NULL == pIsGood))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pIsGood = FALSE;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
       goto exit;

    if (OK > (status = CA_MGMT_extractKeyBlobEx(pCertificateDescr->pKeyBlob, pCertificateDescr->keyBlobLength, &pBlobKey)))
        goto exit;

    if (akt_rsa != pBlobKey.type && akt_ecc != pBlobKey.type && akt_ecc_ed != pBlobKey.type)
    {
        status = ERR_BAD_KEY_TYPE;
        goto exit;
    }

    /* extract the public key of the certificate */
    if (0 == pCertificateDescr->certLength)
    {
        status = ERR_CERT_AUTH_BAD_CERT_LENGTH;
        goto exit;
    }

    MF_attach(&certMemFile, pCertificateDescr->certLength, pCertificateDescr->pCertificate);
    CS_AttachMemFile( &cs, &certMemFile);

    /* parse the certificate */
    if (OK > (status = X509_parseCertificate( cs, &pRoot)))
    {
        goto exit;
    }

    if (OK > (status = X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(hwAccelCtx)
                                                           ASN1_FIRST_CHILD(pRoot),
                                                           cs, &certKey)))
    {
        goto exit;
    }

    if ( akt_rsa == certKey.type)
    {
#ifndef __DISABLE_DIGICERT_RSA__
        /* verify key blob and certificate public keys match */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_RSA_equalKey(MOC_RSA(hwAccelCtx)
            certKey.key.pRSA, pBlobKey.key.pRSA, &cmpRes);
        if ( (OK != status) || (TRUE != cmpRes) )
        {
            status = ERR_CERT_AUTH_MISMATCH_PUBLIC_KEYS;
            goto exit;
        }

        status = CRYPTO_INTERFACE_RSA_getKeyParametersAlloc( MOC_RSA(hwAccelCtx)
            pBlobKey.key.pRSA, &priTemplate, MOC_GET_PRIVATE_KEY_DATA,
            pBlobKey.type);
        if (OK != status)
            goto exit;

        status = VLONG_vlongFromByteString(
            priTemplate.pN, priTemplate.nLen, &pModulus, NULL);
        if (OK != status)
            goto exit;

        status = VLONG_vlongFromByteString(
            priTemplate.pP, priTemplate.pLen, &pPrime, NULL);
        if (OK != status)
            goto exit;

        status = VLONG_vlongFromByteString(
            priTemplate.pQ, priTemplate.qLen, &pSubprime, NULL);
        if (OK != status)
            goto exit;

        /* verify key blob private key matches public key */
        status = VLONG_allocVlong(&pN, NULL);
        if (OK != status)
            goto exit;

        status = VLONG_vlongSignedMultiply(pN, pPrime, pSubprime);
        if (OK > status)
            goto exit;

        if (0 != VLONG_compareSignedVlongs(pN, pModulus))
        {
            status = ERR_CERT_AUTH_KEY_BLOB_CORRUPT;
            goto exit;
        }
#else
        if ((0 != VLONG_compareSignedVlongs(RSA_N(certKey.key.pRSA), RSA_N(pBlobKey.key.pRSA))) ||
            (0 != VLONG_compareSignedVlongs(RSA_E(certKey.key.pRSA), RSA_E(pBlobKey.key.pRSA))))
        {
            status = ERR_CERT_AUTH_MISMATCH_PUBLIC_KEYS;
            goto exit;
        }

        /* verify key blob private key matches public key */
        if (OK > (status = VLONG_allocVlong(&pN, NULL)))
            goto exit;

        DEBUG_RELABEL_MEMORY(pN);

        if (OK > (status = VLONG_vlongSignedMultiply(pN, RSA_P(pBlobKey.key.pRSA), RSA_Q(pBlobKey.key.pRSA))))
            goto exit;

        if (0 != VLONG_compareSignedVlongs(pN, RSA_N(pBlobKey.key.pRSA)))
        {
            status = ERR_CERT_AUTH_KEY_BLOB_CORRUPT;
            goto exit;
        }
#endif
#else
        status = ERR_RSA_DISABLED;
        goto exit;
#endif
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if ( akt_ecc == certKey.type || akt_ecc_ed == certKey.type )
    {
        byteBoolean cmpRes2 = FALSE;

        /* Ensure that both keys are on the same curve and their public points match.
         */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if (OK > (status = CRYPTO_INTERFACE_EC_equalKeyAux(MOC_ECC(hwAccelCtx) pBlobKey.key.pECC, certKey.key.pECC, &cmpRes2)))
#else
        if (OK > (status = EC_equalKeyEx(MOC_ECC(hwAccelCtx) pBlobKey.key.pECC, certKey.key.pECC, &cmpRes2)))
#endif
            goto exit;

        if (!cmpRes2)
        {
            status = ERR_CERT_AUTH_MISMATCH_PUBLIC_KEYS;
            goto exit;
        }

        /* Verify that the private key scalar value is on the curve
         */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_EC_verifyKeyPairAux(MOC_ECC(hwAccelCtx) pBlobKey.key.pECC, NULL, &cmpRes2);
#else
        status = EC_verifyKeyPairEx(MOC_ECC(hwAccelCtx) pBlobKey.key.pECC, NULL, &cmpRes2);
#endif
        if ( (OK > status) || (FALSE == cmpRes2) )
        {
            status = ERR_CERT_AUTH_KEY_BLOB_CORRUPT;
            goto exit;
        }
    }
#endif
    else
    {
        status = ERR_CERT_AUTH_MISMATCH_PUBLIC_KEYS;
        goto exit;
    }

    *pIsGood = TRUE;

exit:

    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    if (pRoot)
        TREE_DeleteTreeItem((TreeItem*)pRoot);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (NULL != pModulus)
        VLONG_freeVlong(&pModulus, NULL);

    if (NULL != pPrime)
        VLONG_freeVlong(&pPrime, NULL);

    if (NULL != pSubprime)
        VLONG_freeVlong(&pSubprime, NULL);

#ifndef __DISABLE_DIGICERT_RSA__
    if (akt_rsa == certKey.type)
    {
        CRYPTO_INTERFACE_RSA_freeKeyTemplate(
            certKey.key.pRSA, &priTemplate, certKey.type);
    }
#endif
#endif

    CRYPTO_uninitAsymmetricKey( &pBlobKey, NULL);
    VLONG_freeVlong(&pN, NULL);
    CRYPTO_uninitAsymmetricKey( &certKey, NULL);

    return (sbyte4)status;
}

#endif /* !defined(__DISABLE_DIGICERT_CERTIFICATE_GENERATION__) && !defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__) */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_DER_CONVERSION__) || defined(__ENABLE_DIGICERT_PEM_CONVERSION__)

/*
@brief      Convert DER file key information to Mocana SoT Platform key blob.

@details    This function converts key information contained in a <em>DER
            file</em>&mdash;distinguished encoding rules file, which some
            applications, such as OpenSSL, use to store their key
            information&mdash;to a Mocana SoT Platform key blob.

This function's conversion operation is helpful for working with SSL
implementations that store their key information as DER-encoded objects.

@ingroup    cert_mgmt_functions

@since 1.41
@version 5.3 and later

@todo_version (internal changes, post-5.3.1...)

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_DER_CONVERSION__
+ \c \__ENABLE_DIGICERT_PEM_CONVERSION__

@inc_file ca_mgmt.h

@param pDerRsaKey           Pointer to the DER key.
@param derRsaKeyLength      Number of bytes in the DER key, \p pDerRsaKey.
@param ppRetKeyBlob         On return, pointer to the SoT Platform key blob.
@param pRetKeyBlobLength    On return, pointer to number of bytes in the
                              SoT Platform key blob (\p pRegKeyBlob).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This is a convenience function provided for your application's
            use; it is not used by Mocana SoT Platform internal code.

@funcdoc    ca_mgmt.c
*/
extern sbyte4
CA_MGMT_convertKeyDER(ubyte *pDerRsaKey, ubyte4 derRsaKeyLength,
                      ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLength)
{
    hwAccelDescr    hwAccelCtx;
    AsymmetricKey   key;
    MSTATUS         status;

    CRYPTO_initAsymmetricKey(&key);

    /* check input */
    if ((NULL == pDerRsaKey) || (NULL == ppRetKeyBlob) || (NULL == pRetKeyBlobLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
       goto exit;

#ifndef __DISABLE_DIGICERT_RSA__
    status = PKCS_getPKCS1Key(MOC_RSA(hwAccelCtx) pDerRsaKey, derRsaKeyLength, &key);
#else
    status = ERR_RSA_INVALID_PKCS1;
#endif
#ifdef __ENABLE_DIGICERT_ECC__
    if (OK > status)
        status = SEC_getKey(MOC_ECC(hwAccelCtx) pDerRsaKey, derRsaKeyLength, &key);
#endif

#ifdef __ENABLE_DIGICERT_DSA__
    if (OK > status)
        status = PKCS_getDSAKey(MOC_DSA(hwAccelCtx) pDerRsaKey, derRsaKeyLength, &key);
#endif

    if (OK > status)
        goto exit;

    status = CA_MGMT_makeKeyBlobEx(&key, ppRetKeyBlob, pRetKeyBlobLength);

exit:

    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    CRYPTO_uninitAsymmetricKey(&key, NULL);

    return (sbyte4)status;

} /* CA_MGMT_convertKeyDER */

extern MSTATUS CA_MGMT_convertRSAPublicKeyInfoDER (
  ubyte *pDerRsaKey,
  ubyte4 derRsaKeyLength,
  ubyte **ppRetKeyBlob,
  ubyte4 *pRetKeyBlobLength
  )
{
  MSTATUS status;
  ubyte4 rsaKeyDataLen;
  ubyte *pRsaKeyData;
  CStream keyStream;
  MemFile keyMemFile;
  ASN1_ITEMPTR pPubKeyInfo = NULL;
  ASN1_ITEMPTR pTemp = NULL;
  ASN1_ITEMPTR pOid = NULL;
  ASN1_ITEMPTR pKey = NULL;

  /* Decode the PublicKeyInfo
   *   PublicKeyInfo ::= SEQUENCE {
   *     algorithm       AlgorithmIdentifier,
   *     PublicKey       BIT STRING  }
   */
  status = DIGI_MEMSET ((void *)&keyStream, 0, sizeof (CStream));
  if (OK != status)
    goto exit;

  status = (MSTATUS)MF_attach (&keyMemFile, derRsaKeyLength, pDerRsaKey);
  if (OK != status)
    goto exit;

  CS_AttachMemFile (&keyStream, &keyMemFile );

  status = ASN1_Parse (keyStream, &pPubKeyInfo);
  if (OK != status)
    goto exit;

  /* The parse routine creates an overall parent before creating the actual
   * tree. So the key's SEQUENCE is actually the first child.
   */
  status = ERR_RSA_INVALID_PKCS1;
  pTemp = ASN1_FIRST_CHILD (pPubKeyInfo);
  if (NULL == pTemp)
    goto exit;

  /* The first child of the key is AlgId.
   *   SEQUENCE {
   *     oid     OBJECT ID,
   *     params  Any }
   * Verify that it is PKCS 1 RSA
   * The OID for RSA public key is the same as RSA encryption. That's probably
   * not what it should be, but that's what the PKCS committee did back in the
   * 80's.
   */
  status = ERR_RSA_INVALID_PKCS1;
  pTemp = ASN1_FIRST_CHILD (pTemp);
  if (NULL == pTemp)
    goto exit;

  pOid = ASN1_FIRST_CHILD (pTemp);
  if (NULL == pOid)
    goto exit;

  status = ERR_RSA_INVALID_KEY;
  if (ERR_FALSE == ASN1_VerifyOID (pOid, keyStream, rsaEncryption_OID))
    goto exit;

  /* This is an RSA public key, so decode the data of the BIT STRING.
   * The BIT STRING is the sibling of the AlgID.
   */
  pKey = ASN1_NEXT_SIBLING (pTemp);
  if (NULL == pKey)
    goto exit;

  rsaKeyDataLen = pKey->length;

  pRsaKeyData = (ubyte *)CS_memaccess (
    keyStream, pKey->dataOffset, rsaKeyDataLen);
  if (NULL == pRsaKeyData)
    goto exit;

  /* Convert the DER of the public key into Mocana key blob format.
   */
  status = CA_MGMT_convertKeyDER (
    pRsaKeyData, rsaKeyDataLen, ppRetKeyBlob, pRetKeyBlobLength);

exit:

  if (NULL != pPubKeyInfo)
  {
    TREE_DeleteTreeItem (&(pPubKeyInfo->treeItem));
  }

  return (status);
}

/*------------------------------------------------------------------*/

/*
@brief      Convert SoT Platform key blob to PKCS&nbsp;\#1 DER-encoded key.

@details    This function converts a Mocana SoT Platform key blob that contains
            RSA private key information to a PKCS&nbsp;\#1 DER-encoded key.

@ingroup    cert_mgmt_functions

@since 3.2
@version 5.3 and later

@todo_version (internal changes, post-5.3.1...)

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_DER_CONVERSION__
+ \c \__ENABLE_DIGICERT_PEM_CONVERSION__

@inc_file ca_mgmt.h

@param pKeyBlob         Pointer to the SoT Platform key blob.
@param keyBlobLength    Number of bytes in the SoT Platform key blob, \p
                          pKeyBlob.
@param ppRetKeyDER      On return, pointer to the PKCS&nbsp;\#1 DER-encoded key.
@param pRetKeyDERLength On return, pointer to the number of bytes in the
                          PKCS&nbsp;\#1 DER-encoded key (\p ppRetKeyDER).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This is a convenience function provided for your application's
            use; it is not used by Mocana SoT Platform internal code.

@funcdoc    ca_mgmt.c
*/
extern MSTATUS
CA_MGMT_keyBlobToDER(const ubyte *pKeyBlob, ubyte4 keyBlobLength,
                     ubyte **ppRetKeyDER, ubyte4 *pRetKeyDERLength)
{
    /* Convert RSA keyblob to PKCS1 DER */
    hwAccelDescr    hwAccelCtx;
    AsymmetricKey   key;
#ifdef __ENABLE_DIGICERT_OPENSSL_PUBKEY_COMPATIBILITY__
    DER_ITEMPTR     pRoot = 0;
    DER_ITEMPTR     pDummySequence = 0;
#endif

    MSTATUS         status = OK;

    CRYPTO_initAsymmetricKey(&key);

    /* check input */
    if ((NULL == pKeyBlob) || (NULL == ppRetKeyDER) || (NULL == pRetKeyDERLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
       goto exit;

    if (OK > (status = CA_MGMT_extractKeyBlobEx(pKeyBlob, keyBlobLength, &key)))
        goto exit;

    status = ERR_BAD_KEY_TYPE;

#ifdef __ENABLE_DIGICERT_ECC__
    if (akt_ecc == key.type || akt_ecc_ed == key.type)
    {
        status = SEC_setKey(MOC_ASYM(hwAccelCtx) &key, ppRetKeyDER, pRetKeyDERLength);
        goto exit;
    }
#endif

#ifdef __ENABLE_DIGICERT_DSA__
    if (akt_dsa == key.type)
    {
        status = PKCS_setDsaDerKey(MOC_DSA(hwAccelCtx) &key, ppRetKeyDER, pRetKeyDERLength);
        goto exit;
    }
#endif

#ifndef __DISABLE_DIGICERT_RSA__
    if (akt_rsa != key.type)
    {
        status = ERR_BAD_KEY_TYPE;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_OPENSSL_PUBKEY_COMPATIBILITY__
    if (key.key.pRSA->privateKey)
#endif
    {
        status = PKCS_setPKCS1Key(MOC_RSA(hwAccelCtx) &key, ppRetKeyDER, pRetKeyDERLength);
    }
#ifdef __ENABLE_DIGICERT_OPENSSL_PUBKEY_COMPATIBILITY__
    else
    {
        if (OK > ( status = DER_AddSequence( NULL, &pDummySequence)))
            goto exit;

        if (OK > (status = ASN1CERT_storePublicKeyInfo(MOC_ASYM(hwAccelCtx) &key, pDummySequence)))
            goto exit;

        if(NULL == (pRoot = DER_FIRST_CHILD(pDummySequence)))
            goto exit;

        if ( OK > ( status = DER_Serialize(pRoot, ppRetKeyDER, pRetKeyDERLength)))
            goto exit;
    }
#endif

    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
#endif /* __DISABLE_DIGICERT_RSA__ */

exit:
    CRYPTO_uninitAsymmetricKey(&key, NULL);

#ifdef __ENABLE_DIGICERT_OPENSSL_PUBKEY_COMPATIBILITY__
    if ( pDummySequence)
    {
        TREE_DeleteTreeItem( (TreeItem*) pDummySequence);
    }
#endif

    return status;
} /* CA_MGMT_keyBlobToDER */

#ifdef __ENABLE_DIGICERT_TPM__
/*------------------------------------------------------------------*/

/*
@brief      Convert SoT Public key blob to PKCS&nbsp;\#8 DER-encoded key.

@details    This function converts a Mocana SoT Platform Public key blob that contains
            RSA public key information to a PKCS&nbsp;\#8 DER-encoded key.

@ingroup    cert_mgmt_functions

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_DER_CONVERSION__
+ \c \__ENABLE_DIGICERT_PEM_CONVERSION__

@inc_file ca_mgmt.h

@param pKeyBlob         Pointer to the SoT Platform Public key blob.
@param keyBlobLength    Number of bytes in the SoT Platform Public key blob, \p
                          pKeyBlob.
@param ppRetKeyDER      On return, pointer to the PKCS&nbsp;\#8 DER-encoded key.
@param pRetKeyDERLength On return, pointer to the number of bytes in the
                          PKCS&nbsp;\#8 DER-encoded key (\p ppRetKeyDER).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ca_mgmt.c
*/
extern MSTATUS
CA_MGMT_publicKeyBlobToDER(const ubyte *pPublicKeyBlob, ubyte4 publicKeyBlobLength,
                     ubyte **ppRetKeyDER, ubyte4 *pRetKeyDERLength)
{
    DER_ITEMPTR     pDummySequence = 0;
    MSTATUS         status = OK;
    ubyte           copyData[MAX_DER_STORAGE];

    /* check input */
    if ((NULL == pPublicKeyBlob) || (NULL == ppRetKeyDER) || (NULL == pRetKeyDERLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > ( status = DER_AddSequence( NULL, &pDummySequence)))
        goto exit;

    copyData[0] = TSS_BLOB_STRUCT_VERSION;
    if (OK > (status = DER_AddItemCopyData(pDummySequence, INTEGER, 1, copyData, NULL)))
        goto exit;

    copyData[0] = TSS_BLOB_TYPE_PUBKEY;
    if (OK > (status = DER_AddItemCopyData(pDummySequence, INTEGER, 1, copyData, NULL)))
        goto exit;

    DIGI_MEMCPY(copyData, &publicKeyBlobLength, sizeof(ubyte4));
    copyData[0] = ((publicKeyBlobLength >> 24) & 0xff);
    copyData[1] = ((publicKeyBlobLength >> 16) & 0xff);
    copyData[2] = ((publicKeyBlobLength >> 8) & 0xff);
    copyData[3] = (publicKeyBlobLength & 0xff);
    if (OK > (status = DER_AddItemCopyData(pDummySequence, INTEGER, 4, copyData, NULL)))
        goto exit;

    if (OK > (status = DER_AddItem(pDummySequence, OCTETSTRING, publicKeyBlobLength, pPublicKeyBlob, NULL)))
        goto exit;

    if ( OK > ( status = DER_Serialize(pDummySequence, ppRetKeyDER, pRetKeyDERLength)))
        goto exit;

exit:

    if ( pDummySequence)
    {
        TREE_DeleteTreeItem( (TreeItem*) pDummySequence);
    }

    return status;
} /* CA_MGMT_publicKeyBlobToDER */
#endif

#endif /* defined(__ENABLE_DIGICERT_DER_CONVERSION__) || defined(__ENABLE_DIGICERT_PEM_CONVERSION__) */

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_PEM_CONVERSION__) || defined(__ENABLE_DIGICERT_DER_CONVERSION__)
#if (defined(__ENABLE_DIGICERT_HW_SECURITY_MODULE__))
#if (defined(__ENABLE_DIGICERT_TPM__))

MOC_EXTERN MSTATUS CA_MGMT_tpm12RsaKeyBlobToDer (
  ubyte *pKeyBlob,
  ubyte4 keyBlobLen,
  vlong *pModulus,
  vlong *pPubExpo,
  ubyte **ppDerEncoding,
  ubyte4 *pDerEncodingLen
  )
{
  MSTATUS status;
  ubyte4 mLen, eLen;
  DER_ITEMPTR pRoot = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKeyBlob) || (NULL == pModulus) || (NULL == pPubExpo) ||
    (NULL == ppDerEncoding) || (NULL == pDerEncodingLen) )
    goto exit;

  /* How big are the exponent and modulus?
   */
  mLen = VLONG_bitLength (pModulus);
  eLen = VLONG_bitLength (pPubExpo);

  if ( (0 == mLen) || (0 == eLen) )
    goto exit;

  /* Add for
   *   SEQ {
   *     OCTET
   *     INT
   *     INT }
   */
  status = DER_AddSequence (NULL, &pRoot);
  if (OK != status)
    goto exit;

  status = DER_AddItem (
    pRoot, OCTETSTRING, keyBlobLen - 12, pKeyBlob + 12, NULL);
  if (OK != status)
    goto exit;

  status = DER_AddVlongInteger (pRoot, pModulus, NULL);
  if (OK != status)
    goto exit;

  status = DER_AddVlongInteger (pRoot, pPubExpo, NULL);
  if (OK != status)
    goto exit;

  status = DER_Serialize (pRoot, ppDerEncoding, pDerEncodingLen);

exit:

  if (NULL != pRoot)
  {
    TREE_DeleteTreeItem ((TreeItem *)pRoot);
  }

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_TPM__)) */
#endif /* (defined(__ENABLE_DIGICERT_HW_SECURITY_MODULE__)) */
#endif /* defined(__ENABLE_DIGICERT_PEM_CONVERSION__) || defined(__ENABLE_DIGICERT_DER_CONVERSION__) */

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PEM_CONVERSION__

/*
@brief      Convert PEM-encoded key file to SoT Platform key blob.

@details    This function converts key information contained in a <em>PEM
            (Privacy Enhanced Mail)-encoded key file</em>&mdash;a DER-encoded
            key file that is Base64-encoded&mdash;to a Mocana SoT Platform
            key blob.

@ingroup    cert_mgmt_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PEM_CONVERSION__

@inc_file ca_mgmt.h

@param pPemRsaKey           Pointer to the PEM-encoded key file to convert.
@param pemRsaKeyLength      Length of the PEM-encoded key file, \p pPemRsaKey.
@param ppRetKeyBlob         On return, pointer to the Mocana SoT Platform key
                              blob.
@param pRetKeyBlobLength    On return, pointer to the size of the Mocana SoT
                              Platform key blob, \p ppRetKeyBlob.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This is a convenience function provided for your application's
            use; it is not used by Mocana SoT Platform internal code.

@funcdoc    ca_mgmt.c
*/
extern sbyte4
CA_MGMT_convertKeyPEM(ubyte *pPemRsaKey, ubyte4 pemRsaKeyLength,
                      ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLength)
{
    ubyte*      pDerRsaKey = 0;
    ubyte4      derRsaKeyLength;
    MSTATUS     status;

    /* check input */
    if ((NULL == pPemRsaKey) || (NULL == ppRetKeyBlob) || (NULL == pRetKeyBlobLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* decode the base64 encoded message */
    if (OK > (status = CA_MGMT_decodeCertificate(pPemRsaKey, pemRsaKeyLength, &pDerRsaKey, &derRsaKeyLength)))
        goto exit;

    status = CA_MGMT_convertKeyDER(pDerRsaKey, derRsaKeyLength, ppRetKeyBlob, pRetKeyBlobLength);

exit:
    if (NULL != pDerRsaKey)
        FREE(pDerRsaKey);

    return (sbyte4)status;
} /* CA_MGMT_convertKeyPEM */


/*------------------------------------------------------------------*/

/**
@brief      Convert SoT Platform key blob to PEM-encoded key buffer.

This function converts a Mocana SoT Platform key blob that contains RSA
private key information to a <em>PEM (Privacy Enhanced Mail)
file</em>-encoded key buffer&mdash;a DER-enocded key that is Base64-encoded.

@ingroup    cert_mgmt_functions

@since 3.2
@version 5.3 and later


@todo_version (internal changes, post-5.3.1...)

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PEM_CONVERSION__

@inc_file ca_mgmt.h

@param pKeyBlob         Pointer to the SoT Platform key blob.
@param keyBlobLength    Number of bytes in the SoT Platform key blob.
@param ppRetKeyPEM      On return, pointer to the PEM-encoded key.
@param pRetKeyPEMLength On return, pointer to the number of bytes in the
                          PEM-encoded key (\p ppRetKeyPEM).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This is a convenience function provided for your application's
            use; it is not used by Mocana SoT Platform internal code.

@funcdoc    ca_mgmt.c
*/
extern MSTATUS
CA_MGMT_keyBlobToPEM(const ubyte *pKeyBlob, ubyte4 keyBlobLength,
                     ubyte **ppRetKeyPEM, ubyte4 *pRetKeyPEMLength)
{
    static sbyte begin_rsa_priv_line[] = "-----BEGIN RSA PRIVATE KEY-----\n";
    static sbyte end_rsa_priv_line[] = "\n-----END RSA PRIVATE KEY-----\n";

    static sbyte begin_rsa_pub_line[] = "-----BEGIN PUBLIC KEY-----\n";
    static sbyte end_rsa_pub_line[] = "\n-----END PUBLIC KEY-----\n";

#ifdef __ENABLE_DIGICERT_ECC__
    static sbyte begin_ec_line[] = "-----BEGIN EC PRIVATE KEY-----\n";
    static sbyte end_ec_line[] = "\n-----END EC PRIVATE KEY-----\n";

#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
    /* As in the examples in RFC 8410 we just use these generic lines */
    static sbyte begin_eced_line[] = "-----BEGIN PRIVATE KEY-----\n";
    static sbyte end_eced_line[] = "\n-----END PRIVATE KEY-----\n";
#endif
#endif

#ifdef __ENABLE_DIGICERT_DSA__
    static sbyte begin_dsa_line[] = "-----BEGIN DSA PRIVATE KEY-----\n";
    static sbyte end_dsa_line[] = "\n-----END DSA PRIVATE KEY-----\n";
#endif

    ubyte4      n;
    ubyte4      i;
    ubyte4      rem;
    ubyte       *pTrav = NULL;
    AsymmetricKey key = {0};
    sbyte       *pHdr, *pFtr;
    sbyte4      hdrLength, ftrLength;
    ubyte*      pBase64Mesg = NULL;
    ubyte*      pKeyDER = NULL;
    ubyte4      keyDERLength;
    MSTATUS     status;

    ubyte*      pTmp;

    /* check input */
    if ((NULL == pKeyBlob) || (NULL == ppRetKeyPEM) || (NULL == pRetKeyPEMLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Convert RSA keyblob to PKCS1 DER */
    if (OK > (status = CA_MGMT_keyBlobToDER(pKeyBlob, keyBlobLength, &pKeyDER, &keyDERLength)))
        goto exit;

    /* get key type */
    CRYPTO_initAsymmetricKey(&key);

    if (OK > (status = CA_MGMT_extractKeyBlobEx(pKeyBlob, keyBlobLength, &key)))
        goto exit;

    /* Init to pub key (the RSA pub key header and footer are actually any alg
     * pub key).
     */
    pHdr = begin_rsa_pub_line; pFtr = end_rsa_pub_line;
    hdrLength = sizeof(begin_rsa_pub_line) - 1;
    ftrLength = sizeof(end_rsa_pub_line) - 1;
    if (akt_rsa == key.type)
    {
        if (key.key.pRSA->privateKey)
        {
            pHdr = begin_rsa_priv_line; pFtr = end_rsa_priv_line;
            hdrLength = sizeof(begin_rsa_priv_line) - 1;
            ftrLength = sizeof(end_rsa_priv_line) - 1;
        }
    }
#if (defined(__ENABLE_DIGICERT_ECC__) || defined(__ENABLE_DIGICERT_DSA__))
#ifdef __ENABLE_DIGICERT_ECC__
    else if (akt_ecc == key.type || akt_ecc_ed == key.type)
    {
        intBoolean privResult;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_EC_isKeyPrivate(key.key.pECC, &privResult);
#else
        status = EC_isKeyPrivate(key.key.pECC, &privResult);
#endif
        if (OK == status && privResult && akt_ecc == key.type)
        {
            pHdr = begin_ec_line; pFtr = end_ec_line;
            hdrLength = sizeof(begin_ec_line) - 1;
            ftrLength = sizeof(end_ec_line) - 1;
        }
#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
        else if (OK == status && privResult && akt_ecc_ed == key.type)
        {
            pHdr = begin_eced_line; pFtr = end_eced_line;
            hdrLength = sizeof(begin_eced_line) - 1;
            ftrLength = sizeof(end_eced_line) - 1;
        }
#endif
    }
#endif
#ifdef __ENABLE_DIGICERT_DSA__
    else if (akt_dsa == key.type)
    {
        pHdr = begin_dsa_line; pFtr = end_dsa_line;
        hdrLength = sizeof(begin_dsa_line) - 1;
        ftrLength = sizeof(end_dsa_line) - 1;
    }
#endif
#endif
    else
    {
        status = ERR_BAD_KEY_TYPE;
        goto exit;
    }

    CRYPTO_uninitAsymmetricKey(&key, NULL);

    /* encode into base64 message */
    if (OK > (status = BASE64_encodeMessage(pKeyDER, keyDERLength, &pBase64Mesg, pRetKeyPEMLength)))
        goto exit;

    /* add '---- XXX ----' lines */
    n = *pRetKeyPEMLength/64;
    rem = (*pRetKeyPEMLength)%64;

    if (NULL == (pTmp = *ppRetKeyPEM = MALLOC(*pRetKeyPEMLength + hdrLength + ftrLength + n)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(pTmp, pHdr, hdrLength);
    pTmp += hdrLength;

    pTrav = pBase64Mesg;

    for (i=0; i < n; i++)
    {
        DIGI_MEMCPY(pTmp, pTrav, 64);
        pTmp += 64;
        pTrav += 64;
        *pTmp++ = '\n';
    }
    if (rem)
    {
        DIGI_MEMCPY(pTmp, pTrav, rem);
        pTmp += rem;
    }

    DIGI_MEMCPY(pTmp, pFtr, ftrLength);

    *pRetKeyPEMLength += hdrLength + ftrLength + n;

exit:
    if (NULL != pBase64Mesg)
        FREE(pBase64Mesg);

    if (NULL != pKeyDER)
        FREE(pKeyDER);

    return status;
} /* CA_MGMT_keyBlobToPEM */

#endif /* __ENABLE_DIGICERT_PEM_CONVERSION__ */

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CERTIFICATE_SEARCH_SUPPORT__

MOC_EXTERN sbyte4
CA_MGMT_extractSerialNum(ubyte*  pCertificate,   ubyte4  certificateLength,
                         ubyte** ppRetSerialNum, ubyte4* pRetSerialNumLength)
{
    ASN1_ITEM*  pRoot           = NULL;
    MemFile     certMemFile;
    CStream     cs;
    MSTATUS status;

    if ((NULL == pCertificate) || (NULL == ppRetSerialNum) || (NULL == pRetSerialNumLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == certificateLength)
    {
        status = ERR_CERT_AUTH_BAD_CERT_LENGTH;
        goto exit;
    }

    MF_attach(&certMemFile, certificateLength, pCertificate);
    CS_AttachMemFile( &cs, &certMemFile);

    /* parse the certificate */
    if (OK > (status = X509_parseCertificate(cs, &pRoot)))
        goto exit;

    status = X509_extractSerialNum(ASN1_FIRST_CHILD(pRoot), cs,
                                   ppRetSerialNum, pRetSerialNumLength);

exit:
    if (pRoot)
        TREE_DeleteTreeItem((TreeItem*)pRoot);

    return (sbyte4)status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CERTIFICATE_SEARCH_SUPPORT__

extern sbyte4
CA_MGMT_freeSearchDetails(ubyte** ppFreeData)
{
    MSTATUS status = OK;

    if ((NULL == ppFreeData) || (NULL == *ppFreeData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    FREE(*ppFreeData);
    *ppFreeData = NULL;

exit:
    return (sbyte4)status;
}
#endif



/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CERTIFICATE_SEARCH_SUPPORT__

typedef struct CA_MGMT_enumItemInfo
{
    void*                   userArg;
    CA_MGMT_EnumItemCBFun   userCb;
    ubyte4                  counter;
} CA_MGMT_enumItemInfo;


static MSTATUS
EnumItemCallbackFun( ASN1_ITEM* pItem, CStream cs, void* userArg)
{
    MSTATUS status;
    CA_MGMT_enumItemInfo* pInfo = (CA_MGMT_enumItemInfo*) userArg;
    const ubyte* value;

    /* extract all info for the user call back */
    value = CS_memaccess( cs, pItem->dataOffset, pItem->length);
    if ( !value)
    {
        return ERR_MEM_ALLOC_FAIL;
    }
    status = pInfo->userCb( value, pItem->length, pItem->tag, pInfo->counter, pInfo->userArg);
    CS_stopaccess( cs, value);

    ++(pInfo->counter);
   return status;
}

MOC_EXTERN sbyte4
CA_MGMT_enumCrl(ubyte* pCertificate, ubyte4 certificateLength,
                CA_MGMT_EnumItemCBFun callbackFunc, void* userArg)
{
    ASN1_ITEM*           pRoot           = NULL;
    MemFile              certMemFile;
    CStream              cs;
    MSTATUS              status;
    CA_MGMT_enumItemInfo info;

    if ((NULL == pCertificate) || (NULL == callbackFunc))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == certificateLength)
    {
        status = ERR_CERT_AUTH_BAD_CERT_LENGTH;
        goto exit;
    }

    MF_attach(&certMemFile, certificateLength, pCertificate);
    CS_AttachMemFile( &cs, &certMemFile);

    /* parse the certificate */
    if (OK > (status = X509_parseCertificate(cs, &pRoot)))
        goto exit;

    info.counter = 0;
    info.userArg = userArg;
    info.userCb = callbackFunc;

    if (OK > (status = X509_enumerateCRL( ASN1_FIRST_CHILD(pRoot), cs,
                                         EnumItemCallbackFun, &info)))
    {
        goto exit;
    }

exit:
    if (pRoot)
        TREE_DeleteTreeItem((TreeItem*)pRoot);

    return (sbyte4)status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN sbyte4
CA_MGMT_enumAltName(ubyte* pCertificate, ubyte4 certificateLength, sbyte4 isSubject,
                    CA_MGMT_EnumItemCBFun callbackFunc, void* userArg)
{
    ASN1_ITEM*           pRoot           = NULL;
    MemFile              certMemFile;
    CStream              cs;
    MSTATUS              status;
    CA_MGMT_enumItemInfo info;

    if ((NULL == pCertificate) || (NULL == callbackFunc))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == certificateLength)
    {
        status = ERR_CERT_AUTH_BAD_CERT_LENGTH;
        goto exit;
    }

    MF_attach(&certMemFile, certificateLength, pCertificate);
    CS_AttachMemFile( &cs, &certMemFile);

    /* parse the certificate */
    if (OK > (status = X509_parseCertificate(cs, &pRoot)))
        goto exit;

    info.counter = 0;
    info.userArg = userArg;
    info.userCb = callbackFunc;

    if (OK > (status = X509_enumerateAltName( ASN1_FIRST_CHILD(pRoot), cs,
                                             isSubject, EnumItemCallbackFun,
                                             &info)))
    {
        goto exit;
    }

exit:
    if (pRoot)
        TREE_DeleteTreeItem((TreeItem*)pRoot);

    return (sbyte4)status;
}
#endif

/*------------------------------------------------------------------*/

extern sbyte4
CA_MGMT_allocCertDistinguishedName(certDistinguishedName **ppNewCertDistName)
{
    certDistinguishedName *pInitCertDistName;
    MSTATUS status;

    if (NULL == ppNewCertDistName)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppNewCertDistName = NULL;

    if (NULL == (pInitCertDistName = (certDistinguishedName*) MALLOC(sizeof(certDistinguishedName))))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_MEMSET((ubyte *)pInitCertDistName, 0x00, sizeof(certDistinguishedName));

    *ppNewCertDistName = pInitCertDistName;

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern sbyte4
CA_MGMT_freeCertDistinguishedName(certDistinguishedName **ppFreeCertDistName)
{
    certDistinguishedName *pFreeCertDistName;
    MSTATUS status = OK;

    if ((NULL == ppFreeCertDistName) || (NULL == *ppFreeCertDistName))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pFreeCertDistName = *ppFreeCertDistName;

    if (NULL != pFreeCertDistName->pDistinguishedName)
    {
        relativeDN *pRDN;
        ubyte4 i = 0;

        for (pRDN = pFreeCertDistName->pDistinguishedName;
            i < pFreeCertDistName->dnCount; pRDN = pFreeCertDistName->pDistinguishedName + i)
        {
            ubyte4 j = 0;
            nameAttr *pNameComponent = pRDN->pNameAttr;
            if (pNameComponent != NULL)
            {
                for (; ((pNameComponent != NULL) && (j < pRDN->nameAttrCount));
                     pNameComponent = pRDN->pNameAttr + j)
                {
                    if (pNameComponent->value && pNameComponent->valueLen > 0)
                    {
                        FREE(pNameComponent->value);
                    }
                    j = j + 1;
                }
                FREE(pRDN->pNameAttr);
            }
            i = i + 1;
        }
        FREE(pFreeCertDistName->pDistinguishedName);
    }
    if (NULL != pFreeCertDistName->pEndDate)
        FREE(pFreeCertDistName->pEndDate);

    if (NULL != pFreeCertDistName->pStartDate)
        FREE(pFreeCertDistName->pStartDate);

    FREE(pFreeCertDistName);
    *ppFreeCertDistName = NULL;

exit:
    return status;
}


/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_DIGICERT_KEY_GENERATION__))

static sbyte4 CA_MGMT_generateAsymKey(ubyte4 keyType, ubyte4 keySizeOrClAlg, ubyte4 qsAlg,
                                      AsymmetricKey *pKey)
{
    hwAccelDescr    hwAccelCtx;
    AsymmetricKey   key;
    vlong*          pVlongQueue = NULL;
    intBoolean      isHwAccelInit = FALSE;
    MSTATUS         status;

#ifdef __ENABLE_DIGICERT_ECC__
    ECCKey *pEccKey = NULL;
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    QS_CTX *pQsCtx = NULL;
#endif

    if (NULL == pKey)
        return ERR_NULL_POINTER;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
       return status;

    isHwAccelInit = TRUE;

    CRYPTO_initAsymmetricKey(&key);

    if (akt_ecc == keyType || akt_ecc_ed == keyType)
    {
#if (defined(__ENABLE_DIGICERT_ECC__))
        if (akt_ecc == keyType)
        {
            switch (keySizeOrClAlg)
            {
#ifdef __ENABLE_DIGICERT_ECC_P192__
                case 192:
                {
                    keySizeOrClAlg = cid_EC_P192;
                    break;
                }
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
                case 224:
                {
                    keySizeOrClAlg = cid_EC_P224;
                    break;
                }
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
                case 256:
                {
                    keySizeOrClAlg = cid_EC_P256;
                    break;
                }
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
                case 384:
                {
                    keySizeOrClAlg = cid_EC_P384;
                    break;
                }
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
                case 521:
                {
                    keySizeOrClAlg = cid_EC_P521;
                    break;
                }
#endif
                default:
                    break;
                    /* do nothing, assume keySizeOrClAlg is an id */
            } /* switch */
        }
        else  /* akt_ecc_ed == keyType */
        {
            switch (keySizeOrClAlg)
            {
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
                case 255:
                {
                    keySizeOrClAlg = cid_EC_Ed25519;
                    break;
                }
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
                case 448:
                {
                    keySizeOrClAlg = cid_EC_Ed448;
                    break;
                }
#endif
                default:
                    break;
                    /* do nothing, assume keySizeOrClAlg is an id */
            } /* switch */
        }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc( MOC_ECC(hwAccelCtx) keySizeOrClAlg, (void **)&pEccKey,
                                                           RANDOM_rngFun, g_pRandomContext, keyType, NULL);
#else
        status = EC_generateKeyPairAlloc( MOC_ECC(hwAccelCtx) keySizeOrClAlg, &pEccKey, RANDOM_rngFun, g_pRandomContext);
#endif
        if (OK > status)
            goto exit;

        status = CRYPTO_loadAsymmetricKey(&key, keyType, (void **) &pEccKey);
        if (OK > status)
            goto exit;

#else
        status = ERR_CRYPTO_ECC_DISABLED;
        goto exit;
#endif /* __ENABLE_DIGICERT_ECC__ */
    }
    else if (akt_rsa == keyType)
    {
        if (cid_RSA_2048_PKCS15 == keySizeOrClAlg || cid_RSA_2048_PSS == keySizeOrClAlg)
        {
            keySizeOrClAlg = 2048;
        }
        else if (cid_RSA_3072_PKCS15 == keySizeOrClAlg || cid_RSA_3072_PSS == keySizeOrClAlg)
        {
            keySizeOrClAlg = 3072;
        }
        else if (cid_RSA_4096_PKCS15 == keySizeOrClAlg || cid_RSA_4096_PSS == keySizeOrClAlg)
        {
            keySizeOrClAlg = 4096;
        }
#ifndef __DISABLE_DIGICERT_RSA__
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
        status = CRYPTO_INTERFACE_RSA_generateKeyAlloc(MOC_RSA(hwAccelCtx)
                                                       g_pRandomContext, (void **)&(key.key.pRSA),
                                                       keySizeOrClAlg, &pVlongQueue, akt_rsa, NULL);
        if (OK != status)
            goto exit;

        key.type = akt_rsa;
#else
        if (OK > (status = CRYPTO_createRSAKey(&key, &pVlongQueue)))
            goto exit;

        if (OK > (status = RSA_generateKey(MOC_RSA(hwAccelCtx) g_pRandomContext,
                                           key.key.pRSA, keySizeOrClAlg, &pVlongQueue)))
        {
            goto exit;
        }
#endif
#else
        status = ERR_RSA_DISABLED;
        goto exit;
#endif
    }
    else if (akt_dsa == keyType)
    {
#if (defined(__ENABLE_DIGICERT_DSA__))
        if (OK > (status = CRYPTO_createDSAKey(&key, &pVlongQueue)))
            goto exit;

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
        if (OK > (status = CRYPTO_INTERFACE_DSA_generateKeyAux(MOC_DSA(hwAccelCtx) g_pRandomContext, key.key.pDSA, keySizeOrClAlg, &pVlongQueue)))
#else
        if (OK > (status = DSA_generateKey(MOC_DSA(hwAccelCtx) g_pRandomContext, key.key.pDSA, keySizeOrClAlg, NULL, NULL, NULL, &pVlongQueue)))
#endif
            goto exit;
#else
        status = ERR_CRYPTO_DSA_DISABLED;
        goto exit;
#endif
    }
#ifdef __ENABLE_DIGICERT_PQC__
    else if (akt_qs == keyType)
    {
        status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(hwAccelCtx) &pQsCtx, qsAlg);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_QS_generateKeyPair(MOC_HASH(hwAccelCtx) pQsCtx, RANDOM_rngFun, g_pRandomContext);
        if (OK != status)
            goto exit;

        key.pQsCtx = pQsCtx; pQsCtx = NULL;
        key.type = akt_qs;
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if (akt_hybrid == keyType)
    {
        if (keySizeOrClAlg <= cid_EC_P521)
        {
            keyType = akt_ecc;
        }
        else if (keySizeOrClAlg <= cid_EC_Ed448)
        {
            keyType = akt_ecc_ed;
        }
        else if (keySizeOrClAlg <= cid_RSA_4096_PSS)
        {
            keyType = akt_rsa;
        }
        else
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        /* use recursion to first generate the classical key */
        status = CA_MGMT_generateAsymKey(keyType, keySizeOrClAlg, 0, &key);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(hwAccelCtx) &pQsCtx, qsAlg);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_QS_generateKeyPair(MOC_HASH(hwAccelCtx) pQsCtx, RANDOM_rngFun, g_pRandomContext);
        if (OK != status)
            goto exit;

        key.pQsCtx = pQsCtx; pQsCtx = NULL;
        key.type = akt_hybrid;
        key.clAlg = keySizeOrClAlg;
    }
#endif
#endif /* __ENABLE_DIGICERT_PQC__*/
    else
    {
        status = ERR_BAD_KEY_TYPE;
        goto exit;
    }

    /* copy content to pKey */
    status = CRYPTO_copyAsymmetricKey(pKey, &key);

exit:
    CRYPTO_uninitAsymmetricKey(&key, 0);
    VLONG_freeVlongQueue(&pVlongQueue);

    if (TRUE == isHwAccelInit)
        (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

#ifdef __ENABLE_DIGICERT_ECC__
    if (NULL != pEccKey)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        (void) CRYPTO_INTERFACE_EC_deleteKeyAux(&pEccKey);
#else
        (void) EC_deleteKeyEx(&pEccKey);
#endif
    }
#endif /* __ENABLE_DIGICERT_ECC__ */
#ifdef __ENABLE_DIGICERT_PQC__
    if (NULL != pQsCtx)
    {
        (void) CRYPTO_INTERFACE_QS_deleteCtx(&pQsCtx);
    }
#endif

    return (sbyte4)status;
}

/*------------------------------------------------------------------*/

extern sbyte4
CA_MGMT_generateNakedKeyPQC(ubyte4 keyType, ubyte4 keySizeOrClAlg, ubyte4 qsAlg,
    ubyte **ppRetNewKeyBlob, ubyte4 *pRetNewKeyBlobLength)
{
    AsymmetricKey   key = {0};
    MSTATUS         status;

    status = CA_MGMT_generateAsymKey(keyType, keySizeOrClAlg, qsAlg, &key);
    if (OK != status)
        goto exit;

    status = CA_MGMT_makeKeyBlobEx(&key, ppRetNewKeyBlob, pRetNewKeyBlobLength);

exit:

    (void) CRYPTO_uninitAsymmetricKey(&key, 0);

    return (sbyte4)status;
}

/*------------------------------------------------------------------*/

extern sbyte4
CA_MGMT_generateNakedKey(ubyte4 keyType, ubyte4 keySize,
                         ubyte **ppRetNewKeyBlob, ubyte4 *pRetNewKeyBlobLength)
{
    return CA_MGMT_generateNakedKeyPQC(keyType, keySize, 0, ppRetNewKeyBlob, pRetNewKeyBlobLength);
}
#endif /* (!defined(__DISABLE_DIGICERT_KEY_GENERATION__)) */

/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_DIGICERT_KEY_GENERATION__))

extern sbyte4
CA_MGMT_freeNakedKey(ubyte **ppFreeKeyBlob)
{
    if ((NULL != ppFreeKeyBlob) && (NULL != *ppFreeKeyBlob))
    {
        FREE(*ppFreeKeyBlob);
        *ppFreeKeyBlob = NULL;
    }

    return OK;
}
#endif

/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__)) && (!(defined(__DISABLE_DIGICERT_KEY_GENERATION__)) || defined(__ENABLE_DIGICERT_PEM_CONVERSION__) || defined(__ENABLE_DIGICERT_DER_CONVERSION__)))

MOC_EXTERN sbyte4
CA_MGMT_convertPKCS8KeyToKeyBlob(const ubyte* pPKCS8DER, ubyte4 pkcs8DERLen,
                                 ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLength)
{
    intBoolean      isHwAccelInit = FALSE;
    hwAccelDescr    hwAccelCtx;
    AsymmetricKey   rsaKey;
    MSTATUS         status;

    CRYPTO_initAsymmetricKey(&rsaKey);

    if (OK > (status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        goto exit;

    isHwAccelInit = TRUE;

    /* convert PKCS #8 encoded key into internal key structure */
    if (OK > (status = PKCS_getPKCS8Key(MOC_ASYM(hwAccelCtx) pPKCS8DER, pkcs8DERLen, &rsaKey)))
        goto exit;

    /* convert internal structure into key blob */
    status = CA_MGMT_makeKeyBlobEx(&rsaKey, ppRetKeyBlob, pRetKeyBlobLength);

exit:
    CRYPTO_uninitAsymmetricKey(&rsaKey, NULL);

    if (TRUE == isHwAccelInit)
        (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    return (sbyte4)status;

} /* CA_MGMT_convertPKCS8KeyToKeyBlob */

#endif


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__)) && (!(defined(__DISABLE_DIGICERT_KEY_GENERATION__)) || defined(__ENABLE_DIGICERT_PEM_CONVERSION__) || defined(__ENABLE_DIGICERT_DER_CONVERSION__)))

MOC_EXTERN sbyte4
CA_MGMT_convertProtectedPKCS8KeyToKeyBlob(const ubyte* pPKCS8DER, ubyte4 pkcs8DERLen,
                                          ubyte *pPassword, ubyte4 passwordLen,
                                          ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLength)
{
    intBoolean      isHwAccelInit = FALSE;
    hwAccelDescr    hwAccelCtx;
    AsymmetricKey   rsaKey;
    MSTATUS         status;

    CRYPTO_initAsymmetricKey(&rsaKey);

    if (OK > (status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        goto exit;

    isHwAccelInit = TRUE;

    /* convert PKCS #8 encoded key into internal key structure */
    if (OK > (status = PKCS_getPKCS8KeyEx(MOC_HW(hwAccelCtx) pPKCS8DER, pkcs8DERLen,
                                          pPassword, passwordLen, &rsaKey)))
    {
        goto exit;
    }

    /* convert internal structure into key blob */
    status = CA_MGMT_makeKeyBlobEx(&rsaKey, ppRetKeyBlob, pRetKeyBlobLength);

exit:
    CRYPTO_uninitAsymmetricKey(&rsaKey, NULL);

    if (TRUE == isHwAccelInit)
        (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    return (sbyte4)status;

} /* CA_MGMT_convertProtectedPKCS8KeyToKeyBlob */

#endif


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__)) && defined( __ENABLE_DIGICERT_DER_CONVERSION__))

MOC_EXTERN sbyte4
CA_MGMT_convertKeyBlobToPKCS8Key(const ubyte *pKeyBlob, ubyte4 keyBlobLength,
                                 enum PKCS8EncryptionType encType,
                                 const ubyte *pPassword, ubyte4 passwordLen,
                                 ubyte **ppRetPKCS8DER, ubyte4 *pRetPkcs8DERLen)
{
    intBoolean      isHwAccelInit = FALSE;
    hwAccelDescr    hwAccelCtx;
    AsymmetricKey   rsaKey;
    MSTATUS         status;

    MOC_UNUSED(hwAccelCtx);

    CRYPTO_initAsymmetricKey(&rsaKey);

    if (OK > (status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        goto exit;

    isHwAccelInit = TRUE;

    /* convert key blob into internal key structure */
    if (OK > (status = CA_MGMT_extractKeyBlobEx(pKeyBlob, keyBlobLength, &rsaKey)))
        goto exit;

    /* convert internal key structure into PKCS #8 encoded key */
    status = PKCS_setPKCS8Key(MOC_HW(hwAccelCtx)
                              &rsaKey, g_pRandomContext, encType,
                              (enum PKCS8PrfType)0,
                              pPassword, passwordLen,
                              ppRetPKCS8DER, pRetPkcs8DERLen);

exit:
    CRYPTO_uninitAsymmetricKey(&rsaKey, NULL);

    if (TRUE == isHwAccelInit)
        (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    return (sbyte4)status;

} /* CA_MGMT_convertProtectedPKCS8KeyToKeyBlob */

#endif /* ((!defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__)) && defined( __ENABLE_DIGICERT_DER_CONVERSION__)) */

/*-----------------------------------------------------------------*/

#if !(defined(__DISABLE_DIGICERT_KEY_GENERATION__)) && !(defined(__DISABLE_DIGICERT_CERTIFICATE_PARSING__))

MOC_EXTERN sbyte4
CA_MGMT_extractPublicKeyInfo(ubyte *pCertificate, ubyte4 certificateLen,
                             ubyte** ppRetKeyBlob, ubyte4 *pRetKeyBlobLen)
{
    MSTATUS         status = OK;
    MemFile         mf;
    CStream         cs;
    ASN1_ITEMPTR    pRoot   = NULL;
    hwAccelDescr    hwAccelCtx;
    AsymmetricKey   pubKey;

    MOC_UNUSED(hwAccelCtx);
    CRYPTO_initAsymmetricKey(&pubKey);

    if (OK > (status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        return status;

    /* Input parameter check */
    if (NULL == pCertificate || NULL == ppRetKeyBlob || NULL == pRetKeyBlobLen)
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

    if (OK > (status = X509_parseCertificate(cs, &pRoot)))
        goto exit;

    if (NULL == pRoot)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(hwAccelCtx)
                                                           ASN1_FIRST_CHILD(pRoot),
                                                           cs, &pubKey)))
    {
        goto exit;
    }

    if (OK > (status = CA_MGMT_makeKeyBlobEx(&pubKey, ppRetKeyBlob, pRetKeyBlobLen)))
        goto exit;

exit:
    CRYPTO_uninitAsymmetricKey(&pubKey, NULL);

    if (pRoot)
        TREE_DeleteTreeItem((TreeItem *) pRoot);

    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    return status;
}

/*-----------------------------------------------------------------*/

MOC_EXTERN sbyte4
CA_MGMT_extractSignature(ubyte* pCertificate, ubyte4 certificateLen,
                         ubyte** ppSignature, ubyte4* pSignatureLen)
{

    MSTATUS         status      = OK;
    MemFile         mf;
    CStream         cs;
    ASN1_ITEMPTR    pCertRoot   = NULL;
    const ubyte*    buffer      = NULL;
    ASN1_ITEMPTR    pSignature  = NULL;
    ubyte*          pTemp       = NULL;

    /* Input parameter check */
    if ((NULL == pCertificate) ||(NULL == ppSignature) || (NULL == pSignatureLen))
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

    if (OK > (status = X509_parseCertificate(cs, &pCertRoot)))
        goto exit;

    if (NULL == pCertRoot)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* get the signature */
    if (OK > ( status = X509_getSignatureItem(ASN1_FIRST_CHILD(pCertRoot),
                                              cs, &pSignature)))
    {
        goto exit;
    }

    /* access the buffer */
    buffer = (const ubyte*) CS_memaccess( cs, (/*FSL*/sbyte4)pSignature->dataOffset,
                                          (/*FSL*/sbyte4)pSignature->length);
    if (NULL == buffer)
    {
        status = ERR_MEM_;
        goto exit;
    }

    /* Copy Signature */
    if (NULL == (pTemp = (ubyte*) MALLOC( pSignature->length)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(pTemp, buffer, pSignature->length);

    *pSignatureLen = pSignature->length;
    *ppSignature   = pTemp;
    pTemp          = NULL;

exit:
    if (pCertRoot)
        TREE_DeleteTreeItem((TreeItem *) pCertRoot);

    return status;

}

/*-----------------------------------------------------------------*/

MOC_EXTERN sbyte4
CA_MGMT_extractBasicConstraint(ubyte* pCertificate, ubyte4 certificateLen,
                               intBoolean* pIsCritical, certExtensions* pCertExtensions)
{

    MSTATUS         status      = OK;
    MemFile         mf;
    CStream         cs;
    ASN1_ITEMPTR    pCertRoot   = NULL;
    ASN1_ITEM*      pExtensions = NULL;
    ASN1_ITEM*      pExtension  = NULL;
    ASN1_ITEM*      pExtPart    = NULL;

    /* Input parameter check */
    if ((NULL == pCertificate) || (NULL == pCertExtensions))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == certificateLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* Explicitely MEMSET pCertExtension to 0x00 */
    if (OK > (status = DIGI_MEMSET((ubyte *)pCertExtensions, 0x00, sizeof(certExtensions))))
        goto exit;

    /* Initialize to negative as non-negative including 0 is a valid path Len */
    pCertExtensions->certPathLen = -1;

    MF_attach(&mf, certificateLen, pCertificate);
    CS_AttachMemFile(&cs, &mf);

    if (OK > (status = X509_parseCertificate(cs, &pCertRoot)))
        goto exit;

    if (NULL == pCertRoot)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* extract extensions */
    if (OK > (status = X509_getCertificateExtensions(ASN1_FIRST_CHILD(pCertRoot),
                                                     &pExtensions)))
    {
        goto exit;
    }

    if (NULL == pExtensions)
    {
        status = ERR_CERT_BASIC_CONSTRAINT_EXTENSION_NOT_FOUND;
        goto exit;
    }

    if (OK > (status = X509_getCertExtension(pExtensions, cs, basicConstraints_OID,
                                             pIsCritical, &pExtension)))
    {
        status = ERR_CERT_BASIC_CONSTRAINT_EXTENSION_NOT_FOUND;
        goto exit;
    }

    if (NULL == pExtension)
    {
        status = ERR_CERT_BASIC_CONSTRAINT_EXTENSION_NOT_FOUND;
        goto exit;
    }

    /* API returns -1 for isCritical and hence the conversion */
    if (-1 == *pIsCritical)
        *pIsCritical = TRUE;

    pCertExtensions->hasBasicConstraints = TRUE;

    /* BasicConstraintsSyntax ::= SEQUENCE {
                            cA                 BOOLEAN DEFAULT FALSE,
                            pathLenConstraint  INTEGER(0..MAX) OPTIONAL }*/

    if ((pExtension->id & CLASS_MASK) != UNIVERSAL ||
            pExtension->tag != SEQUENCE)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    if (pCertExtensions->isCA == 0)
    {
        pCertExtensions->isCA = FALSE;
    }

    if (0 == pExtension->length)
    {
        /* Enter default values as payload is null */
        pCertExtensions->isCA = FALSE;
        pCertExtensions->certPathLen = -1;
        goto exit;
    }

    /* verify that it is for a CA */
    if (NULL == (pExtPart = ASN1_FIRST_CHILD( pExtension)))
    {
        status = ERR_CERT_INVALID_CERT_POLICY; /* cA  BOOLEAN DEFAULT FALSE */
        goto exit;
    }

    if ((pExtPart->id & CLASS_MASK) != UNIVERSAL ||
            pExtPart->tag != BOOLEAN)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    if (pExtPart->data.m_boolVal)
    {
        pCertExtensions->isCA = TRUE;
    }
    else
        pCertExtensions->isCA = FALSE;

    /* verify the maximum chain length if there */
    pExtPart = ASN1_NEXT_SIBLING( pExtPart);
    if (pExtPart)
    {
        if ( (pExtPart->id & CLASS_MASK) != UNIVERSAL ||
                pExtPart->tag != INTEGER)
        {
            status = ERR_CERT_INVALID_STRUCT;
            goto exit;
        }

        pCertExtensions->certPathLen = (sbyte) pExtPart->data.m_intVal;
    }

exit:
    if (pCertRoot)
        TREE_DeleteTreeItem((TreeItem *) pCertRoot);

    return status;
}

/*-----------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CA_MGMT_getCertSignAlgoType(ubyte *pCertificate,
                            ubyte4 certificateLen, ubyte4* pHashType, ubyte4* pPubKeyType)
{
    MSTATUS         status      = OK;
    MemFile         mf;
    CStream         cs;
    ASN1_ITEMPTR    pCertRoot   = NULL;
    ASN1_ITEMPTR    pItem       = NULL;
    ASN1_ITEMPTR    pSeqAlgoId  = NULL;

    /* Input parameter check */
    if ((NULL == pCertificate) || (NULL == pHashType) || (NULL == pPubKeyType))
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

    if (OK > (status = X509_parseCertificate(cs, &pCertRoot)))
        goto exit;

    if (NULL == pCertRoot)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* get the algorithm identifier */
    if ( NULL == (pItem = ASN1_FIRST_CHILD(pCertRoot)))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* algo id is the second child of signed */
    if (OK > (status = ASN1_GetNthChild(pItem, 2, &pSeqAlgoId)))
    {
        goto exit;
    }

    if ( OK > (status = X509_getCertSignAlgoType(pSeqAlgoId, cs,
                                                 pHashType, pPubKeyType)))
    {
        goto exit;
    }

exit:
    if (pCertRoot)
        TREE_DeleteTreeItem((TreeItem *) pCertRoot);

    return status;
}

/*-----------------------------------------------------------------*/

MOC_EXTERN sbyte4
CA_MGMT_verifySignature(const ubyte* pIssuerCertBlob,
                        ubyte4 issuerCertBlobLen, ubyte* pCertificate, ubyte4 certLen)
{
    MSTATUS status = OK;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR    pCertRoot  = NULL;
    AsymmetricKey   derivedKey;
    hwAccelDescr    hwAccelCtx;

    CRYPTO_initAsymmetricKey(&derivedKey);

    if (OK > (status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        return status;

    MF_attach(&mf, certLen, pCertificate);
    CS_AttachMemFile(&cs, &mf);

    if (OK > (status = X509_parseCertificate(cs, &pCertRoot)))
        goto exit;

    if (NULL == pCertRoot)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Convert keyblob to Asymmetric key */
    if (OK > (status = CA_MGMT_extractKeyBlobEx(pIssuerCertBlob,
                                                issuerCertBlobLen,
                                                &derivedKey)))
    {
        goto exit;
    }

    if (OK > (status = X509_verifySignature(MOC_ASYM(hwAccelCtx)
                                            ASN1_FIRST_CHILD(pCertRoot), cs,
                                            &derivedKey)))
    {
        goto exit;
    }

exit:
    if (pCertRoot)
        TREE_DeleteTreeItem((TreeItem *) pCertRoot);
         CRYPTO_uninitAsymmetricKey(&derivedKey, NULL);

    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CA_MGMT_verifySignatureWithAsymKey(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    AsymmetricKey *pAsymKey,
    ubyte *pCertOrCsr,
    ubyte4 certOrCsrLen)
{
    MSTATUS status;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pCertRoot = NULL;
    ubyte *pDecoded = NULL;
    ubyte4 decodedLen = 0;

    if (NULL == pAsymKey || NULL == pCertOrCsr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = CA_MGMT_decodeCertificate(
        pCertOrCsr, certOrCsrLen, &pDecoded, &decodedLen);
    if (OK == status)
    {
        pCertOrCsr = pDecoded;
        certOrCsrLen = decodedLen;
    }

    MF_attach(&mf, certOrCsrLen, pCertOrCsr);
    CS_AttachMemFile(&cs, &mf);

    status = X509_parseCertificate(cs, &pCertRoot);
    if (OK != status)
        goto exit;

    if (NULL == pCertRoot)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = X509_verifySignature(MOC_ASYM(hwAccelCtx)
        ASN1_FIRST_CHILD(pCertRoot), cs, pAsymKey);
    if (OK != status)
        goto exit;

exit:

    if (NULL != pCertRoot)
        TREE_DeleteTreeItem((TreeItem *) pCertRoot);

    DIGI_FREE((void **) &pDecoded);

    return status;
}

#endif

MOC_EXTERN MSTATUS CA_MGMT_convertIpAddress(ubyte *pIpString, ubyte *pIpBytes, ubyte4 *pIpLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 ipStrLen = 0;
    ubyte4 i = 0;
    ubyte4 j = 0;

    if (NULL == pIpString || NULL == pIpBytes || NULL == pIpLen)
        goto exit;

    ipStrLen = DIGI_STRLEN((const sbyte *) pIpString);

    /* check for ip v6 first */
    if (39 == ipStrLen)
    {
        while (i < ipStrLen)
        {
            /* should be groups of 4 hex char followed by a colon */
            status = DIGI_ATOH( &(pIpString[i]), 4, &(pIpBytes[j]));
            if (OK != status)
                goto exit;

            i += 4; j += 2;

            status = ERR_INVALID_INPUT;
            if (i < 39 && ':' != pIpString[i])
                goto exit;

            i++;
        }

        *pIpLen = 16;
    }
    else if (ipStrLen < 16) /* Check for ip v4 */
    {
        sbyte *pStop = NULL;

        while (i < 4)
        {
            pIpBytes[i] = DIGI_ATOL((const sbyte *) pIpString, (const sbyte **) &pStop);

            status = ERR_INVALID_INPUT;
            if (i < 3 && '.' != (char) *pStop)
                goto exit;

            /* move our local copy of pIpString to the next group */
            pIpString = (ubyte *) pStop + 1;
            i++;
        }

        *pIpLen = 4;
    }
    else
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    status = OK;

exit:

    return status;
}
