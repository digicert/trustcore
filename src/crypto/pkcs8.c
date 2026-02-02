/*
 * pkcs8.c
 *
 * PKCS #8
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
@file       pkcs8.c

@brief      C source code file for the SoT Platform PKCS&nbsp;\#8 convenience API.

@details    This file contains the SoT Platform convenience functions that
              support PKCS&nbsp;\#8, as described in RFC&nbsp;5958 (which
              obsoletes RFC&nbsp;5208). For detailed information, refer to:
+ http://tools.ietf.org/html/rfc5208
+ http://tools.ietf.org/html/rfc5958

@flags
To enable the SoT Platform PKCS&nbsp;\#8 convenience API functions, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS8__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_DER_CONVERSION__
+ \c \__ENABLE_DIGICERT_PEM_CONVERSION__

Define the flags according to whether you are working with DER-encoded objects,
PEM-encoded objects, or both.

### External Functions
This API provides the following public (extern) functions for extracting
private key information from a PKCS&nbsp;\#8 asymmetric key package that has
been extracted from a PKCS&nbsp;\#12 PFX object:
+ PKCS8_decodePrivateKeyDER()
+ PKCS8_decodePrivateKeyPEM()

### About PKCS&nbsp;\#8
PKCS&nbsp;\#8 operations use an asymmetric key package, which RFC&nbsp;5958
defines as a container for one or more \c AsymmetricKeyPackage ASN.1
objects. The RFC allows for encapsulating the asymmetric key package in one
or more protecting CMS content types. Before using the PKCS&nbsp;\#8 API
functions, you must process the information to remove the encapsulation. The
callbacks associated with the Mocana SoT Platform PKCS&nbsp;\#12 API
perform this work for you.

@note       The PKCS&nbsp;\#8 API functions require the key package to be
            extracted from a PKCS&nbsp;\#12 PFX object, and therefore assume
            that the key package contains only a single key.
*/

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if (defined(__ENABLE_DIGICERT_PKCS8__) && (defined(__ENABLE_DIGICERT_PEM_CONVERSION__) || defined(__ENABLE_DIGICERT_DER_CONVERSION__)))

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/utils.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/base64.h"
#include "../crypto/sha1.h"
#include "../crypto/rsa.h"
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#include "../crypto/pubcrypto.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../asn1/derencoder.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/pkcs_key.h"
#include "../crypto/pkcs8.h"


/*------------------------------------------------------------------*/

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_PEM_CONVERSION__))
static MSTATUS
fetchLine(const ubyte *pSrc,  ubyte4 *pSrcIndex, const ubyte4 srcLength,
          ubyte *pDest, ubyte4 *pDestIndex)
{
    /* this is here for now... we will want to use the version in crypto/ca_mgmt.c */
    MSTATUS status = OK;

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

    return status;

} /* fetchLine */
#endif /* (defined(__ENABLE_DIGICERT_PEM_CONVERSION__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_PEM_CONVERSION__))

extern MSTATUS
PKCS8_decodePrivateKeyPEM(const ubyte* pFilePemPkcs8, ubyte4 fileSizePemPkcs8,
                          ubyte** ppRsaKeyBlob, ubyte4 *pRsaKeyBlobLength)
{
    /* decode a PKCS #8 private key file */
    AsymmetricKey key;
    ubyte*  pBase64Mesg = NULL;
    ubyte4  srcIndex    = 0;
    ubyte4  destIndex   = 0;
    ubyte*  pDecodeFile = NULL;
    ubyte4  decodedLength;
    MSTATUS status;
    hwAccelDescr hwAccelCtx;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        return status;

    if ( OK >( status = CRYPTO_initAsymmetricKey( &key)))
        return status;

    /* alloc temp memory for base64 decode buffer */
    if (NULL == (pBase64Mesg = MALLOC(fileSizePemPkcs8)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* strip our line feeds and comments lines from base64 text  */
    while (fileSizePemPkcs8 > srcIndex)
    {
        if (OK > (status = fetchLine(pFilePemPkcs8, &srcIndex, fileSizePemPkcs8, pBase64Mesg, &destIndex)))
            goto exit;
    }

    /* decode a contiguous base64 block of text */
    if (OK > (status = BASE64_decodeMessage((ubyte *)pBase64Mesg, destIndex, &pDecodeFile, &decodedLength)))
        goto exit;

    /* extract RSA key from DER private key PKCS8 file */
    if (OK > (status = PKCS_getPKCS8Key(MOC_ASYM(hwAccelCtx) pDecodeFile, decodedLength, &key)))
        goto exit;

    /* return a Digicert RSA key blob */
    status = CA_MGMT_makeKeyBlobEx(&key, ppRsaKeyBlob, pRsaKeyBlobLength);

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    if (NULL != pBase64Mesg)
        FREE(pBase64Mesg);

    if (NULL != pDecodeFile)
        FREE(pDecodeFile);

    CRYPTO_uninitAsymmetricKey(&key, NULL);

    return status;

} /* PKCS8_decodePrivateKeyPEM */

/*------------------------------------------------------------------*/

extern MSTATUS
PKCS8_decodePrivateKeyPEMEx(const ubyte* pFilePemPkcs8, ubyte4 fileSizePemPkcs8, ubyte *pPassword, ubyte4 passwordLen, ubyte** ppKeyBlob, ubyte4 *pKeyBlobLength)
{

    MSTATUS status = OK;
    ubyte4 srcIndex = 0;
    ubyte4 destIndex = 0;
    ubyte *pBase64Mesg = NULL;
    ubyte *pDer = NULL;
    ubyte4 derLen = 0;

    /* alloc temp memory for base64 decode buffer */
    status = DIGI_MALLOC((void **) &pBase64Mesg, fileSizePemPkcs8);
    if (OK != status)
        goto exit;

    /* strip our line feeds and comments lines from base64 text  */
    while (fileSizePemPkcs8 > srcIndex)
    {
        status = fetchLine(pFilePemPkcs8, &srcIndex, fileSizePemPkcs8, pBase64Mesg, &destIndex);
        if (OK != status)
            goto exit;
    }

    /* decode a contiguous base64 block of text */
    status = BASE64_decodeMessage(pBase64Mesg, destIndex, &pDer, &derLen);
    if (OK != status)
        goto exit;

    status = PKCS8_decodePrivateKeyDEREx((const ubyte *) pDer, derLen, pPassword, passwordLen, ppKeyBlob, pKeyBlobLength);
 
exit:

    if (NULL != pBase64Mesg)
    {
        (void) DIGI_MEMSET_FREE(&pBase64Mesg, derLen); 
    }

    if (NULL != pDer)
    {
        (void) DIGI_MEMSET_FREE(&pDer, derLen); 
    }

    return status;

}

/*------------------------------------------------------------------*/

extern MSTATUS
PKCS8_encodePrivateKeyPEM(randomContext *pRandomContext, ubyte* pKeyBlob, ubyte4 keyBlobLen, enum PKCS8EncryptionType encType,
                          enum PKCS8PrfType prfType, ubyte *pPassword, ubyte4 passwordLen, ubyte** ppRetFilePemPkcs8, ubyte4 *pRetFileSizePemPkcs8)
{
    MSTATUS status = OK;
    ubyte *pDer = NULL;
    ubyte4 derLen = 0;

    /* null checks handled by below call */

    status = PKCS8_encodePrivateKeyDER(pRandomContext, pKeyBlob, keyBlobLen, encType, prfType, pPassword, passwordLen, &pDer, &derLen);
    if (OK != status)
        goto exit;

    status = BASE64_makePemMessageAlloc(pPassword ? MOC_PEM_TYPE_ENCR_PRI_KEY : MOC_PEM_TYPE_PRI_KEY, pDer, derLen, ppRetFilePemPkcs8, pRetFileSizePemPkcs8);

exit:

    if (NULL != pDer)
    {
        (void) DIGI_MEMSET_FREE(&pDer, derLen); 
    }

    return status;
}
#endif /* (defined(__ENABLE_DIGICERT_PEM_CONVERSION__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_DER_CONVERSION__))

extern MSTATUS
PKCS8_decodePrivateKeyDER(const ubyte* pFileDerPkcs8, ubyte4 fileSizeDerPkcs8,
                          ubyte** ppRsaKeyBlob, ubyte4 *pRsaKeyBlobLength)
{
    /* decode a PKCS #8 private key file */
    AsymmetricKey key;
    MSTATUS status;
    hwAccelDescr hwAccelCtx;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        return status;

    if (OK > (status = CRYPTO_initAsymmetricKey(&key)))
        return status;

    /* extract RSA key from DER private key PKCS8 file */
    if (OK > (status = PKCS_getPKCS8Key(MOC_ASYM(hwAccelCtx) pFileDerPkcs8, fileSizeDerPkcs8, &key)))
        goto exit;

    /* return a Digicert RSA key blob */
    status = CA_MGMT_makeKeyBlobEx(&key, ppRsaKeyBlob, pRsaKeyBlobLength);

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    CRYPTO_uninitAsymmetricKey(&key, NULL);

    return status;

} /* PKCS8_decodePrivateKeyDER */

/*------------------------------------------------------------------*/

extern MSTATUS
PKCS8_decodePrivateKeyDEREx(const ubyte* pFileDerPkcs8, ubyte4 fileSizeDerPkcs8, ubyte *pPassword, ubyte4 passwordLen, ubyte** ppKeyBlob, ubyte4 *pKeyBlobLength)
{
    MSTATUS status = OK;
    hwAccelDescr hwAccelCtx;
    AsymmetricKey key = {0};

    status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
        goto exit;

    status = CRYPTO_initAsymmetricKey(&key);
        if (OK != status)
        goto exit;

    status = PKCS_getPKCS8KeyEx(MOC_HW(hwAccelCtx) pFileDerPkcs8, fileSizeDerPkcs8, (const ubyte*) pPassword, passwordLen, &key);
    if (OK != status)
        goto exit;

    status = CRYPTO_serializeAsymKey(MOC_ASYM(hwAccelCtx) &key, mocanaBlobVersion2, ppKeyBlob, pKeyBlobLength);

exit:

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    CRYPTO_uninitAsymmetricKey(&key, NULL);

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS 
PKCS8_encodePrivateKeyDER(randomContext *pRandomContext, ubyte* pKeyBlob, ubyte4 keyBlobLen, enum PKCS8EncryptionType encType,
                          enum PKCS8PrfType prfType, ubyte *pPassword, ubyte4 passwordLen, ubyte** ppRetFileDerPkcs8, ubyte4 *pRetFileSizeDerPkcs8)
{
    MSTATUS status = ERR_NULL_POINTER;
    AsymmetricKey key = {0};
    byteBoolean releaseRng = FALSE;
    hwAccelDescr hwAccelCtx;

    if (NULL == pKeyBlob || (NULL == pPassword && passwordLen) || NULL == ppRetFileDerPkcs8 || NULL == pRetFileSizeDerPkcs8)
        goto exit;

    status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
        goto exit;

    /* Attempt to get the global rng if no rng is passed in */
    if (NULL == pRandomContext)
    {
        status = RANDOM_acquireContext(&pRandomContext);
        if (OK != status)
            goto exit;

        releaseRng = TRUE;
    }

    status = CRYPTO_initAsymmetricKey(&key);
    if (OK != status)
        goto exit;

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx) pKeyBlob, keyBlobLen, NULL, &key);
    if (OK != status)
        goto exit;

    status = PKCS_setPKCS8Key(MOC_HW(hwAccelCtx) &key, pRandomContext, encType, prfType, pPassword, passwordLen, ppRetFileDerPkcs8, pRetFileSizeDerPkcs8);

exit:

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    
    (void) CRYPTO_uninitAsymmetricKey(&key, NULL);
    
    if (releaseRng && NULL != pRandomContext)
        (void) RANDOM_releaseContext(&pRandomContext);

    return status;
}
#endif /* (defined(__ENABLE_DIGICERT_DER_CONVERSION__)) */

#endif /* __ENABLE_DIGICERT_PKCS8__*/

