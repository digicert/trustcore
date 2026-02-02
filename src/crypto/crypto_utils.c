/*
 * crypto_utils.c
 *
 * Header file for crypto utility methods.
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

#include <string.h> /* strstr() */

#ifndef __RTOS_WIN32__
#ifndef __RTOS_FREERTOS__
#ifndef __RTOS_AZURE__
#ifndef __RTOS_VXWORKS__
#ifndef __RTOS_ZEPHYR__
#include <termios.h>
#endif /* !__RTOS_ZEPHYR__ */
#endif /* !__RTOS_VXWORKS__ */
#endif /* !__RTOS_AZURE__ */
#endif /* !__RTOS_FREERTOS__ */
#else
#include <Windows.h>
#include <conio.h>
#endif /* !__RTOS_WIN32__ */

#include "../common/moptions.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/base64.h"
#include "../common/mjson.h"
#include "../common/mfmgmt.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/cert_store.h"
#include "../crypto/cert_chain.h"

#if defined(__ENABLE_DIGICERT_TAP__)
#include "../tap/tap.h"
#endif
#include "../crypto/pkcs_key.h"
#include "../crypto/crypto_utils.h"

#include "../crypto/rsa.h"
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_rsa.h"
#include "../crypto_interface/cryptointerface.h"
#endif

#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/ecc.h"
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_ecc.h"
#endif
#endif

#ifdef __ENABLE_DIGICERT_DSA__
#include "../crypto/dsa.h"
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_dsa.h"
#endif
#endif

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
#include "../data_protection/file_protect.h"
#endif

#ifndef TRUSTED_CONFIG_NAME
#define TRUSTED_CONFIG_NAME "tpconf.json"
#endif
#ifndef TRUSTED_CONFIG_NAME_LEN
#define TRUSTED_CONFIG_NAME_LEN 11
#endif

/* Set default path for trusted config */
#ifndef MOCANA_TRUSTED_CONFIG_FILE
    #if defined(__RTOS_WIN32__)
        /* Windows - Full path is not provided. Depending on which drive is used
         * for installation, the path may be different and has to be derived at
         * runtime. */
        #define MOCANA_TRUSTED_CONFIG_FILE "\\Mocana\\" TRUSTED_CONFIG_NAME
    #elif defined(__RTOS_VXWORKS__)
        char *DIGICERT_trustedConfigFile(); /* VxWorks method to get config file path */
        #define MOCANA_TRUSTED_CONFIG_FILE DIGICERT_trustedConfigFile()
    #elif (defined(__RTOS_FREERTOS__) && !defined(__FREERTOS_SIMULATOR__)) || defined(__AZURE_RTOS__)
        #define MOCANA_TRUSTED_CONFIG_FILE "/mocana/trustpoint/" TRUSTED_CONFIG_NAME
    #else
        /* All other platforms, including linux, default to this path */
        #define MOCANA_TRUSTED_CONFIG_FILE "/etc/mocana/" TRUSTED_CONFIG_NAME
    #endif
#endif /* MOCANA_TRUSTED_CONFIG_FILE */

#define KEYDIR_JSTR    "keystore_dir"
#define TRUSTDIR_JSTR  "truststore_dir"
#define CONFDIR_JSTR   "conf_dir"
#define BINDIR_JSTR    "bin_dir"
#define PROXY_SERVER_URL_JSTR "http_proxy"
#define ROOTDIR_JSTR   "root_dir"

#define PEM_EXT         ".pem"
#define DER_EXT         ".der"
#define CRT_EXT         ".crt"

#if defined(__RTOS_WIN32__)
#define CRYPTO_UTILS_DIR_SLASH  '\\'
#else
#define CRYPTO_UTILS_DIR_SLASH  '/'
#endif

/*---------------------------------------------------------------------------*/

/* for FIPS this is not part of mstdlib.c, put it here */
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
extern MSTATUS
DIGI_ATOH(ubyte *pHexString, ubyte4 hexStrLen, ubyte *pOut)
{
    MSTATUS status = ERR_INVALID_INPUT;
    ubyte4 i = 0;
    ubyte4 j = 0;

    /* hexStrLenmust  be even */
    if (hexStrLen & 0x01)
        goto exit;

    for (i = 0; i < hexStrLen; i += 2, j++ )
    {
        if ('0' <= pHexString[i] && '9' >= pHexString[i])
        {
            pOut[j] = pHexString[i] - '0';
        }
        else if ('a' <= pHexString[i] && 'f' >= pHexString[i])
        {
            pOut[j] = pHexString[i] + 10 - 'a';
        }
        else if ('A' <= pHexString[i] && 'F' >= pHexString[i])
        {
            pOut[j] = pHexString[i] + 10 - 'A';
        }
        else
        {
            goto exit;
        }

        pOut[j] <<= 4;

        if ('0' <= pHexString[i+1] && '9' >= pHexString[i+1])
        {
            pOut[j] |= (pHexString[i+1] - '0');
        }
        else if ('a' <= pHexString[i+1] && 'f' >= pHexString[i+1])
        {
            pOut[j] |= (pHexString[i+1] + 10 - 'a');
        }
        else if ('A' <= pHexString[i+1] && 'F' >= pHexString[i+1])
        {
            pOut[j] |= (pHexString[i+1] + 10 - 'A');
        }
        else
        {
            goto exit;
        }
    }

    status = OK;

exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

/*---------------------------------------------------------------------------*/

typedef struct
{
    ubyte *pCert;
    ubyte4 certLen;
    ASN1_ITEMPTR pCertificate;
    CStream cs;
} CryptoUtilsCertInfo;

/*---------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_JSON_VERIFY__) || defined(__ENABLE_DIGICERT_SCRAM_CLIENT__)

MSTATUS digestData(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo *pDigestAlgo,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte **ppDigest,
    ubyte4 *pDigestLen
    )
{
    MSTATUS status;
    ubyte *pDigest = NULL;
    BulkCtx pCtx = NULL;

    /* Allocate memory for the digest buffer.
     */
    status = DIGI_MALLOC((void **) &pDigest, pDigestAlgo->digestSize);
    if (OK != status)
    {
        goto exit;
    }

    /* Allocate the digest context.
     */
    status = pDigestAlgo->allocFunc(MOC_HASH(hwAccelCtx) &pCtx);
    if (OK != status)
    {
        goto exit;
    }

    /* Initialize the digest context.
     */
    status = pDigestAlgo->initFunc(MOC_HASH(hwAccelCtx) pCtx);
    if (OK != status)
    {
        goto exit;
    }

    /* Digest the data provided by the caller.
     */
    status = pDigestAlgo->updateFunc(MOC_HASH(hwAccelCtx) pCtx, pData, dataLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Get the digest output.
     */
    status = pDigestAlgo->finalFunc(MOC_HASH(hwAccelCtx) pCtx, pDigest);
    if (OK != status)
    {
        goto exit;
    }

    /* Return the digest to the caller. The caller must free this data.
     */
    *ppDigest = pDigest;
    *pDigestLen = pDigestAlgo->digestSize;
    pDigest = NULL;

exit:

    if (NULL != pCtx)
    {
        pDigestAlgo->freeFunc(MOC_HASH(hwAccelCtx) &pCtx);
    }

    DIGI_FREE((void **) &pDigest);

    return status;
}

#ifndef __DISABLE_DIGICERT_RSA__
static MSTATUS rsaSignMessageAlloc(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    AsymmetricKey *pAsymKey,
    ubyte *pDigest,
    ubyte4 digestLen,
    ubyte digestId,
    ubyte **ppSignature,
    ubyte4 *pSignatureLen
    )
{
    MSTATUS status;
    ubyte *pSig = NULL, *pDigestInfo = NULL;
    ubyte4 digestInfoLen = 0, cipherLen = 0;

    /* Get the length of the RSA signature.
     */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux( MOC_RSA(hwAccelCtx)
        pAsymKey->key.pRSA, (sbyte4 *) &cipherLen);
#else
    status = RSA_getCipherTextLength( MOC_RSA(hwAccelCtx)
        pAsymKey->key.pRSA, (sbyte4 *) &cipherLen);
#endif
    if (OK != status)
    {
        goto exit;
    }

    /* Create a digest info consisting of an ASN.1 formatted algorithm ID and
     * raw digest.
     */
    status = ASN1_buildDigestInfoAlloc(
        pDigest, digestLen, digestId, &pDigestInfo, &digestInfoLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Allocate memory for the signature.
     */
    status = DIGI_MALLOC((void **) &pSig, cipherLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Sign the digest info and store it in the signature buffer.
     */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_signMessageAux (MOC_RSA(hwAccelCtx) pAsymKey->key.pRSA, pDigestInfo, digestInfoLen, pSig, NULL);
#else
    status = RSA_signMessage(MOC_RSA(hwAccelCtx)
        pAsymKey->key.pRSA, pDigestInfo, digestInfoLen, pSig, NULL);
#endif
    if (OK != status)
    {
        goto exit;
    }

    /* Return the signature to the caller. This caller is responsible for
     * freeing this data.
     */
    *ppSignature = pSig;
    *pSignatureLen = cipherLen;
    pSig = NULL;

exit:

    DIGI_FREE((void **) &pSig);
    DIGI_FREE((void **) &pDigestInfo);

    return status;
}

static MSTATUS rsaVerifySignature(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    AsymmetricKey *pAsymKey,
    ubyte *pDigest,
    ubyte4 digestLen,
    ubyte hashId,
    ubyte *pSignature,
    ubyte4 signatureLen,
    ubyte4 *pVerify
    )
{
    MSTATUS status;
    ubyte *pDigestInfo = NULL, *pDecrypted = NULL;
    ubyte4 digestInfoLen, decryptedLen, rsaKeyLength;
    sbyte4 result = -1;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_getRSACipherTextLength( MOC_RSA(hwAccelCtx)
        pAsymKey->key.pRSA, (sbyte4 *) &rsaKeyLength, pAsymKey->type);
#else
    status = RSA_getCipherTextLength( MOC_RSA(hwAccelCtx)
        pAsymKey->key.pRSA, (sbyte4 *) &rsaKeyLength);
#endif
    if (OK != status)
    {
        goto exit;
    }

    if (rsaKeyLength != signatureLen)
    {
        status = ERR_RSA_INVALID_CIPHERTEXT_LEN;
        goto exit;
    }

    /* Build the digest info from the digest and digest ID. This will be an
     * ASN.1 formatted algorithm ID and raw digest.
     */
    status = ASN1_buildDigestInfoAlloc(
        pDigest, digestLen, hashId, &pDigestInfo, &digestInfoLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Allocated memory for the verify result.
     */
    status = DIGI_MALLOC((void **) &pDecrypted, signatureLen);
    if (OK != status)
    {
        goto exit;
    }

    /* The RSA API returns the data and the caller must perform the comparsion
     * themselves.
     */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_verifySignatureAux(MOC_RSA(hwAccelCtx)
        pAsymKey->key.pRSA, pSignature, pDecrypted, &decryptedLen, NULL);
#else
    status = RSA_verifySignature(MOC_RSA(hwAccelCtx)
        pAsymKey->key.pRSA, pSignature, pDecrypted, &decryptedLen, NULL);
#endif
    if (OK != status)
    {
        goto exit;
    }

    /* Ensure the digest info length matches the decrypted signature.
     */
    if (decryptedLen != digestInfoLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* Compare the signatures.
     */
    status = DIGI_MEMCMP(
        pDecrypted, pDigestInfo, decryptedLen, &result);
    if (OK != status)
    {
        goto exit;
    }

    if (0 != result)
    {
        *pVerify = 1;
    }
    else
    {
        *pVerify = 0;
    }

exit:

    DIGI_FREE((void **) &pDigestInfo);
    DIGI_FREE((void **) &pDecrypted);

    return status;
}
#endif

#ifdef __ENABLE_DIGICERT_ECC__

static MSTATUS eccSignMessageAlloc(
    MOC_ECC(hwAccelDescr hwAccelCtx)
    AsymmetricKey *pAsymKey,
    ubyte *pDigest,
    ubyte4 digestLen,
    ubyte **ppSignature,
    ubyte4 *pSignatureLen
    )
{
    MSTATUS status;
    ubyte *pSig = NULL;
    ubyte4 sigLen = 0;

    /* Get the size of an EC element.
     */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(
        pAsymKey->key.pECC, &sigLen);
#else
    status = EC_getElementByteStringLen(pAsymKey->key.pECC, &sigLen);
#endif
    if (OK != status)
    {
        goto exit;
    }

    /* The signature will be twice as big as the element size.
     */
    sigLen = sigLen * 2;
    status = DIGI_MALLOC((void **) &pSig, sigLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Sign the digest.
     */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_ECDSA_signDigestAux( MOC_ECC(hwAccelCtx)
        pAsymKey->key.pECC, RANDOM_rngFun, g_pRandomContext, pDigest,
        digestLen, pSig, sigLen, &sigLen);
#else
    status = ECDSA_signDigest( MOC_ECC(hwAccelCtx)
        pAsymKey->key.pECC, RANDOM_rngFun, g_pRandomContext, pDigest,
        digestLen, pSig, sigLen, &sigLen);
#endif
    if (OK != status)
    {
        goto exit;
    }

    /* Return the signature to the caller. This caller is responsible for
     * freeing this data.
     */
    *ppSignature = pSig;
    *pSignatureLen = sigLen;
    pSig = NULL;


exit:

    DIGI_FREE((void **) &pSig);

    return status;
}

static MSTATUS eccVerifySignature(
    MOC_ECC(hwAccelDescr hwAccelCtx)
    AsymmetricKey *pAsymKey,
    ubyte *pDigest,
    ubyte4 digestLen,
    ubyte *pSignature,
    ubyte4 signatureLen,
    ubyte4 *pVerify
    )
{
    MSTATUS status;
    ubyte4 elementLen, vfyRes = 1;

    /* Get the ECC element length
     */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(
        pAsymKey->key.pECC, &elementLen);
#else
    status = EC_getElementByteStringLen(pAsymKey->key.pECC, &elementLen);
#endif
    if (OK != status)
    {
        goto exit;
    }

    /* The signature should twice the element length.
     */
    if (elementLen * 2 != signatureLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* Verify the signature.
     */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_ECDSA_verifySignatureDigestAux( MOC_ECC(hwAccelCtx)
        pAsymKey->key.pECC, pDigest, digestLen, pSignature, elementLen,
        pSignature + elementLen, elementLen, &vfyRes);
#else
    status = ECDSA_verifySignatureDigest( MOC_ECC(hwAccelCtx)
        pAsymKey->key.pECC, pDigest, digestLen, pSignature, elementLen,
        pSignature + elementLen, elementLen, &vfyRes);
#endif
    if (OK != status)
    {
        goto exit;
    }

    *pVerify = vfyRes;

exit:

    return status;
}

#endif /* __ENABLE_DIGICERT_ECC__ */

static MSTATUS convertStrToKeyTypeAndHash(
    sbyte *pKeyTypeAndHash,
    ubyte4 length,
    ubyte4 *pKeyType,
    ubyte *pHashId
    )
{
    MSTATUS status = OK;

    /* Compare the key type. It should match one of the supported asymmetric
     * algorithms.
     */
    if ( (DIGI_STRLEN((const sbyte *) "RSA") < length) &&
         (0 == DIGI_STRNICMP(pKeyTypeAndHash, (const sbyte *) "RSA", DIGI_STRLEN((const sbyte *) "RSA"))) )
    {
        *pKeyType = akt_rsa;
        pKeyTypeAndHash += DIGI_STRLEN((const sbyte *) "RSA");
        length -= DIGI_STRLEN((const sbyte *) "RSA");
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if ( (DIGI_STRLEN((const sbyte *) "ECC") < length) &&
              (0 == DIGI_STRNICMP(pKeyTypeAndHash, (const sbyte *) "ECC", DIGI_STRLEN((const sbyte *) "ECC"))) )
    {
        *pKeyType = akt_ecc;
        pKeyTypeAndHash += DIGI_STRLEN((const sbyte *) "ECC");
        length -= DIGI_STRLEN((const sbyte *) "ECC");
    }
#endif /* __ENABLE_DIGICERT_ECC__ */
    else
    {
        status = ERR_BAD_KEY_TYPE;
        goto exit;
    }

    if ('-' != *pKeyTypeAndHash++)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }
    length--;

    /* Check the digest type.
     */
    if ( (DIGI_STRLEN((const sbyte *) "SHA1") <= length) &&
         (0 == DIGI_STRNICMP(pKeyTypeAndHash, (const sbyte *) "SHA1", DIGI_STRLEN((const sbyte *) "SHA1"))) )
    {
        *pHashId = ht_sha1;
    }
    else if ( (DIGI_STRLEN((const sbyte *) "SHA224") <= length) &&
         (0 == DIGI_STRNICMP(pKeyTypeAndHash, (const sbyte *) "SHA224", DIGI_STRLEN((const sbyte *) "SHA224"))) )
    {
        *pHashId = ht_sha224;
    }
    else if ( (DIGI_STRLEN((const sbyte *) "SHA256") <= length) &&
         (0 == DIGI_STRNICMP(pKeyTypeAndHash, (const sbyte *) "SHA256", DIGI_STRLEN((const sbyte *) (const sbyte *) "SHA256"))) )
    {
        *pHashId = ht_sha256;
    }
    else if ( (DIGI_STRLEN((const sbyte *) "SHA384") <= length) &&
         (0 == DIGI_STRNICMP(pKeyTypeAndHash, (const sbyte *) "SHA384", DIGI_STRLEN((const sbyte *) "SHA384"))) )
    {
        *pHashId = ht_sha384;
    }
    else if ( (DIGI_STRLEN((const sbyte *) "SHA512") <= length) &&
         (0 == DIGI_STRNICMP(pKeyTypeAndHash, (const sbyte *) "SHA512", DIGI_STRLEN((const sbyte *) "SHA512"))) )
    {
        *pHashId = ht_sha512;
    }
    else
    {
        status = ERR_INVALID_ARG;
    }

exit:

    if (OK != status)
    {
        *pKeyType = 0;
        *pHashId = 0;
    }

    return status;
}

static MSTATUS convertKeyTypeAndHashToStr(
    ubyte4 keyType,
    ubyte hashId,
    sbyte **ppKeyIdStr,
    sbyte **ppHashIdStr
    )
{
    MSTATUS status = OK;

    switch (keyType & 0xFF)
    {
        case akt_rsa:
            *ppKeyIdStr = (sbyte *) "RSA";
            break;

#ifdef __ENABLE_DIGICERT_ECC__
        case akt_ecc:
            *ppKeyIdStr = (sbyte *) "ECC";
            break;
#endif /* __ENABLE_DIGICERT_ECC__ */

        default:
            *ppKeyIdStr = NULL;
            *ppHashIdStr = NULL;
            status = ERR_BAD_KEY_TYPE;
            goto exit;
    }

    switch (hashId)
    {
        case ht_sha1:
            *ppHashIdStr = (sbyte *) "-SHA1";
            break;

        case ht_sha224:
            *ppHashIdStr = (sbyte *) "-SHA224";
            break;

        case ht_sha256:
            *ppHashIdStr = (sbyte *) "-SHA256";
            break;

        case ht_sha384:
            *ppHashIdStr = (sbyte *) "-SHA384";
            break;

        case ht_sha512:
            *ppHashIdStr = (sbyte *) "-SHA512";
            break;

        default:
            *ppKeyIdStr = NULL;
            *ppHashIdStr = NULL;
            status = ERR_INVALID_ARG;
            goto exit;
    }

exit:

    return status;
}

static MSTATUS escapeNewLineChar(
    ubyte *pData,
    ubyte4 dataLen,
    ubyte **ppRetData,
    ubyte4 *pRetDataLen
    )
{
    MSTATUS status;
    ubyte4 index, count = 0, newDataLen = 0, shift = 0;
    ubyte *pNewData = NULL;

    for (index = 0; index < dataLen; index++)
        if ('\n' == pData[index])
            count++;

    newDataLen = dataLen + count;
    status = DIGI_MALLOC((void **) &pNewData, newDataLen);
    if (OK != status)
    {
        goto exit;
    }

    for (index = 0; index < dataLen; index++)
    {
        if ('\n' == pData[index])
        {
            pNewData[index + shift] = '\\';
            shift++;
            pNewData[index + shift] = 'n';
        }
        else
        {
            pNewData[index + shift] = pData[index];
        }
    }

    *ppRetData = pNewData;
    *pRetDataLen = newDataLen;
    pNewData = NULL;

exit:

    DIGI_FREE((void **) &pNewData);

    return status;
}

static MSTATUS unescapeNewLineChar(
    ubyte *pData,
    ubyte4 *pDataLen
    )
{
    MSTATUS status = OK;
    ubyte4 index, shift = 0;

    index = 0;
    while ((index + shift) < *pDataLen)
    {
        pData[index] = pData[index + shift];
        if ('\\' == pData[index])
        {
            pData[index] = '\n';
            shift++;
        }

        index++;
    }

    *pDataLen = index;

    return status;
}

/*---------------------------------------------------------------------------*/

#define JSON_START          "{\n"
#define JSON_START_LINE     "  \""
#define JSON_MIDDLE_LINE    "\" : \""
#define JSON_END_LINE       "\",\n"
#define JSON_END_LINE_LAST  "\"\n"
#define JSON_END            "}\n"

MSTATUS CRYPTO_UTILS_signJsonFromAsymKey(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pData,
    ubyte4 dataLen,
    AsymmetricKey *pAsymKey,
    ubyte hashAlgo,
    ubyte *pCert,
    ubyte4 certLen,
    ubyte **ppRetSig,
    ubyte4 *pRetSigLen
)
{
    MSTATUS status;
    const BulkHashAlgo *pDigestAlgo = NULL;
    ubyte *pDigest = NULL, *pSignature = NULL, *pJsonSig = NULL;
    ubyte *pBase64Sig = NULL, *pJsonPtr, *pSanitizedCert = NULL;
    sbyte *pKeyIdStr, *pHashIdStr;
    ubyte4 signatureLen = 0, jsonSigLen, digestLen, base64SigLen = 0;
    ubyte4 sanitizedCertLen;
    sbyte4 cmpRes = -1;
    ubyte *pPemCert = NULL;
    ubyte4 pemCertLen;

    if ( (NULL == pData) || (NULL == pAsymKey) || (NULL == pCert) ||
        (NULL == ppRetSig) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ( (0 == dataLen) || (0 == certLen) )
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    if (certLen >= MOC_PEM_CERT_HEADER_LEN)
    {
        status = DIGI_MEMCMP(
            pCert, (ubyte *) MOC_PEM_CERT_HEADER, MOC_PEM_CERT_HEADER_LEN,
            &cmpRes);
        if (OK != status)
        {
            goto exit;
        }
    }

    if (0 != cmpRes)
    {
        status = BASE64_makePemMessageAlloc (
            MOC_PEM_TYPE_CERT, pCert, certLen,
            &pPemCert, &pemCertLen);
        if (OK != status)
        {
            goto exit;
        }
    }
    else
    {
        pPemCert = pCert;
        pemCertLen = certLen;
    }

    /* Get the appropriate hash suite based on the hash ID passed in.
     */
    switch (pAsymKey->type & 0xFF)
    {
        case akt_rsa:
            status = CRYPTO_getRSAHashAlgo(hashAlgo, &pDigestAlgo);
            break;

#ifdef __ENABLE_DIGICERT_ECC__
        case akt_ecc:
            status = CRYPTO_getECCHashAlgo(hashAlgo, (BulkHashAlgo **) &pDigestAlgo);
            break;
#endif /* __ENABLE_DIGICERT_ECC__ */

        default:
            status = ERR_BAD_KEY_TYPE;
    }
    if (OK != status)
    {
        goto exit;
    }

    /* Digest the input data.
     */
    status = digestData(MOC_HASH(hwAccelCtx) pDigestAlgo, pData, dataLen, &pDigest, &digestLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Call the appropriate sign method.
     */
    switch (pAsymKey->type & 0xFF)  /* will work for TAP keys too */
    {
#ifndef __DISABLE_DIGICERT_RSA__
        case akt_rsa:
            status = rsaSignMessageAlloc(MOC_RSA(hwAccelCtx) pAsymKey, pDigest, pDigestAlgo->digestSize,
                                         pDigestAlgo->hashId, &pSignature, &signatureLen);
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC__
        case akt_ecc:
            status = eccSignMessageAlloc(MOC_ECC(hwAccelCtx) pAsymKey, pDigest, pDigestAlgo->digestSize, &pSignature,
                                         &signatureLen);
            break;
#endif

        default:
            status = ERR_BAD_KEY_TYPE;
    }
    if (OK != status)
    {
        goto exit;
    }

    /* BASE 64 encode the signature.
     */
    status = BASE64_encodeMessage(pSignature, signatureLen, &pBase64Sig, &base64SigLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Extract the asymmetric key type and hash ID as strings to put into the
     * JSON signature element.
     */
    status = convertKeyTypeAndHashToStr(pAsymKey->type, hashAlgo, &pKeyIdStr, &pHashIdStr);
    if (OK != status)
    {
        goto exit;
    }

    /* Escape the new line characters in the certificate.
     */
    status = escapeNewLineChar(pPemCert, pemCertLen, &pSanitizedCert, &sanitizedCertLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Length of line 1 */
    jsonSigLen = DIGI_STRLEN((sbyte *) JSON_START);

    /* Length of line 2 */
    jsonSigLen += DIGI_STRLEN((sbyte *) JSON_START_LINE) +
    DIGI_STRLEN((sbyte *) JSON_ALGO_ID) +
    DIGI_STRLEN((sbyte *) JSON_MIDDLE_LINE) +
    DIGI_STRLEN(pKeyIdStr) + DIGI_STRLEN(pHashIdStr) +
    DIGI_STRLEN((sbyte *) JSON_END_LINE);

    /* Length of line 3 */
    jsonSigLen += DIGI_STRLEN((sbyte *) JSON_START_LINE) +
    DIGI_STRLEN((sbyte *) JSON_SIG_VALUE) +
    DIGI_STRLEN((sbyte *) JSON_MIDDLE_LINE) + base64SigLen +
    DIGI_STRLEN((sbyte *) JSON_END_LINE);

    /* Length of line 4 */
    jsonSigLen += DIGI_STRLEN((sbyte *) JSON_START_LINE) +
    DIGI_STRLEN((sbyte *) JSON_SIG_CERT) +
    DIGI_STRLEN((sbyte *) JSON_MIDDLE_LINE) + sanitizedCertLen +
    DIGI_STRLEN((sbyte *) JSON_END_LINE_LAST);

    /* Length of line 5 */
    jsonSigLen += DIGI_STRLEN((sbyte *) JSON_END);

    status = DIGI_MALLOC((void **) &pJsonSig, jsonSigLen);
    if (OK != status)
    {
        goto exit;
    }

    pJsonPtr = pJsonSig;

    /* Line 1 - "{\n" */
    DIGI_MEMCPY(pJsonPtr, JSON_START, DIGI_STRLEN((sbyte *) JSON_START));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_START);

    /* Line 2 - "  \"algo_id\" : \"<algo_id>\"" */
    DIGI_MEMCPY(pJsonPtr, JSON_START_LINE, DIGI_STRLEN((sbyte *) JSON_START_LINE));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_START_LINE);
    DIGI_MEMCPY(pJsonPtr, JSON_ALGO_ID, DIGI_STRLEN((sbyte *) JSON_ALGO_ID));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_ALGO_ID);
    DIGI_MEMCPY(pJsonPtr, JSON_MIDDLE_LINE, DIGI_STRLEN((sbyte *) JSON_MIDDLE_LINE));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_MIDDLE_LINE);
    DIGI_MEMCPY(pJsonPtr, pKeyIdStr, DIGI_STRLEN((sbyte *) pKeyIdStr));
    pJsonPtr += DIGI_STRLEN((sbyte *) pKeyIdStr);
    DIGI_MEMCPY(pJsonPtr, pHashIdStr, DIGI_STRLEN((sbyte *) pHashIdStr));
    pJsonPtr += DIGI_STRLEN((sbyte *) pHashIdStr);
    DIGI_MEMCPY(pJsonPtr, JSON_END_LINE, DIGI_STRLEN((sbyte *) JSON_END_LINE));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_END_LINE);

    /* Line 3 - "  \"sig_value\" : \"<signature>\"" */
    DIGI_MEMCPY(pJsonPtr, JSON_START_LINE, DIGI_STRLEN((sbyte *) JSON_START_LINE));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_START_LINE);
    DIGI_MEMCPY(pJsonPtr, JSON_SIG_VALUE, DIGI_STRLEN((sbyte *) JSON_SIG_VALUE));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_SIG_VALUE);
    DIGI_MEMCPY(pJsonPtr, JSON_MIDDLE_LINE, DIGI_STRLEN((sbyte *) JSON_MIDDLE_LINE));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_MIDDLE_LINE);
    DIGI_MEMCPY(pJsonPtr, pBase64Sig, base64SigLen);
    pJsonPtr += base64SigLen;
    DIGI_MEMCPY(pJsonPtr, JSON_END_LINE, DIGI_STRLEN((sbyte *) JSON_END_LINE));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_END_LINE);

    /* Line 4 - "  \"sig_cert\" : \"<certificate>\"" */
    DIGI_MEMCPY(pJsonPtr, JSON_START_LINE, DIGI_STRLEN((sbyte *) JSON_START_LINE));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_START_LINE);
    DIGI_MEMCPY(pJsonPtr, JSON_SIG_CERT, DIGI_STRLEN((sbyte *) JSON_SIG_CERT));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_SIG_CERT);
    DIGI_MEMCPY(pJsonPtr, JSON_MIDDLE_LINE, DIGI_STRLEN((sbyte *) JSON_MIDDLE_LINE));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_MIDDLE_LINE);
    DIGI_MEMCPY(pJsonPtr, pSanitizedCert, sanitizedCertLen);
    pJsonPtr += sanitizedCertLen;
    DIGI_MEMCPY(pJsonPtr, JSON_END_LINE_LAST, DIGI_STRLEN((sbyte *) JSON_END_LINE_LAST));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_END_LINE_LAST);

    /* Line 5 - "}\n" */
    DIGI_MEMCPY(pJsonPtr, JSON_END, DIGI_STRLEN((sbyte *) JSON_END));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_END);

    *ppRetSig = pJsonSig;
    *pRetSigLen = jsonSigLen;
    pJsonSig = NULL;

exit:

    DIGI_FREE((void **) &pSanitizedCert);
    DIGI_FREE((void **) &pJsonSig);
    DIGI_FREE((void **) &pSignature);
    DIGI_FREE((void **) &pBase64Sig);
    DIGI_FREE((void **) &pDigest);
    if (pPemCert != pCert)
    {
        DIGI_FREE((void **) &pPemCert);
    }

    return status;
}


MSTATUS CRYPTO_UTILS_signJson(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pData,
    ubyte4 dataLen,
    ubyte *pKey,
    ubyte4 keyLen,
    ubyte hashAlgo,
    ubyte *pCert,
    ubyte4 certLen,
    ubyte **ppRetSig,
    ubyte4 *pRetSigLen
    )
{
    MSTATUS status = OK;
    AsymmetricKey asymKey = {0};

    status = CRYPTO_initAsymmetricKey(&asymKey);
    if (OK != status)
        goto exit;

    /* Load the key into an AsymmetricKey. */
    status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx) pKey, keyLen, NULL, &asymKey);
    if (OK != status)
        goto exit;

    status = CRYPTO_UTILS_signJsonFromAsymKey(MOC_ASYM(hwAccelCtx) pData, dataLen, &asymKey, hashAlgo, pCert, certLen, ppRetSig, pRetSigLen);

exit:

    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    return status;
}

extern MSTATUS CRYPTO_UTILS_getIssuerAndSerial(
    ubyte *pCert,
    ubyte4 certLen,
    ubyte **ppIssuer,
    ubyte4 *pIssuerLen,
    ubyte **ppSerial,
    ubyte4 *pSerialLen)
{
    MSTATUS status;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRoot = NULL, pIssuer, pSerial;
    ubyte *pIssuerData = NULL, *pSerialData = NULL;
    const ubyte *pIter;
    ubyte4 issuerDataLen, serialDataLen;
    sbyte4 j;

    MF_attach(&mf, certLen, pCert);
    CS_AttachMemFile(&cs, &mf);

    status = X509_parseCertificate(cs, &pRoot);
    if (OK != status)
    {
        goto exit;
    }

    status = X509_getCertificateIssuerSerialNumber(
        ASN1_FIRST_CHILD(pRoot), &pIssuer, &pSerial);
    if (OK != status)
    {
        goto exit;
    }

    serialDataLen = pSerial->length * 2;
    pIter = CS_memaccess(cs, pSerial->dataOffset, pSerial->length);

    status = DIGI_MALLOC((void **) &pSerialData, serialDataLen);
    if (OK != status)
    {
        goto exit;
    }

    for (j = pSerial->length - 1; j >= 0; j--)
    {
        pSerialData[(2 * j) + 1] = returnHexDigit(pIter[j]);
        pSerialData[2 * j] = returnHexDigit(pIter[j] >> 4);
    }

    status = X509_extractDistinguishedNamesBuffer(
        pIssuer, cs, &pIssuerData, &issuerDataLen);
    if (OK != status)
    {
        goto exit;
    }

    *ppIssuer = pIssuerData;
    *pIssuerLen = issuerDataLen;
    *ppSerial = pSerialData;
    *pSerialLen = serialDataLen;
    pIssuerData = NULL;
    pSerialData = NULL;

exit:

    if (NULL != pRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pRoot);
    }

    if (NULL != pIssuerData)
    {
        DIGI_FREE((void **) &pIssuerData);
    }

    if (NULL != pSerialData)
    {
        DIGI_FREE((void **) &pSerialData);
    }

    return status;
}

MSTATUS CRYPTO_UTILS_signJsonMinFromAsymKey(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pData,
    ubyte4 dataLen,
    AsymmetricKey *pAsymKey,
    ubyte hashAlgo,
    ubyte *pCert,
    ubyte4 certLen,
    ubyte **ppRetSig,
    ubyte4 *pRetSigLen
    )
{
    MSTATUS status;
    const BulkHashAlgo *pDigestAlgo = NULL;
    ubyte *pDigest = NULL, *pSignature = NULL, *pJsonSig = NULL;
    ubyte *pBase64Sig = NULL, *pJsonPtr, *pIssuer = NULL, *pSerial = NULL;
    sbyte *pKeyIdStr, *pHashIdStr;
    ubyte4 signatureLen = 0, jsonSigLen, digestLen, base64SigLen = 0;
    ubyte4 issuerLen, serialLen;
    sbyte4 cmpRes = -1;
    ubyte *pDerCert = NULL;
    ubyte4 derCertLen = 0;

    if ( (NULL == pData) || (NULL == pAsymKey) || (NULL == pCert) ||
        (NULL == ppRetSig) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ( (0 == dataLen) || (0 == certLen) )
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    if (certLen >= MOC_PEM_CERT_HEADER_LEN)
    {
        status = DIGI_MEMCMP(
            pCert, (ubyte *) MOC_PEM_CERT_HEADER, MOC_PEM_CERT_HEADER_LEN,
            &cmpRes);
        if (OK != status)
        {
            goto exit;
        }
    }

    if (0 == cmpRes)
    {
        status = CA_MGMT_decodeCertificate(
            pCert, certLen, &pDerCert, &derCertLen);
        if (OK != status)
        {
            goto exit;
        }
    }
    else
    {
        pDerCert = pCert;
        derCertLen = certLen;
    }

    /* Get the appropriate hash suite based on the hash ID passed in.
     */
    switch (pAsymKey->type & 0xFF)
    {
        case akt_rsa:
            status = CRYPTO_getRSAHashAlgo(hashAlgo, &pDigestAlgo);
            break;

#ifdef __ENABLE_DIGICERT_ECC__
        case akt_ecc:
            status = CRYPTO_getECCHashAlgo(hashAlgo, (BulkHashAlgo **) &pDigestAlgo);
            break;
#endif /* __ENABLE_DIGICERT_ECC__ */

        default:
            status = ERR_BAD_KEY_TYPE;
    }
    if (OK != status)
    {
        goto exit;
    }

    /* Digest the input data.
     */
    status = digestData(MOC_HASH(hwAccelCtx) pDigestAlgo, pData, dataLen, &pDigest, &digestLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Call the appropriate sign method.
     */
    switch (pAsymKey->type & 0xFF)
    {
#ifndef __DISABLE_DIGICERT_RSA__
        case akt_rsa:
            status = rsaSignMessageAlloc(MOC_RSA(hwAccelCtx) pAsymKey, pDigest, pDigestAlgo->digestSize,
                                         pDigestAlgo->hashId, &pSignature, &signatureLen);
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC__
        case akt_ecc:
            status = eccSignMessageAlloc(MOC_ECC(hwAccelCtx) pAsymKey, pDigest, pDigestAlgo->digestSize, &pSignature,
                                         &signatureLen);
            break;
#endif

        default:
            status = ERR_BAD_KEY_TYPE;
    }
    if (OK != status)
    {
        goto exit;
    }

    /* BASE 64 encode the signature.
     */
    status = BASE64_encodeMessage(pSignature, signatureLen, &pBase64Sig, &base64SigLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Extract the asymmetric key type and hash ID as strings to put into the
     * JSON signature element.
     */
    status = convertKeyTypeAndHashToStr(pAsymKey->type, hashAlgo, &pKeyIdStr, &pHashIdStr);
    if (OK != status)
    {
        goto exit;
    }

    /* Escape the new line characters in the certificate.
     */
    status = CRYPTO_UTILS_getIssuerAndSerial(
        pDerCert, derCertLen, &pIssuer, &issuerLen, &pSerial, &serialLen);
    if (OK != status)
    {
        goto exit;
    }


    /* Length of line 1 */
    jsonSigLen = DIGI_STRLEN((sbyte *) JSON_START);

    /* Length of line 2 */
    jsonSigLen += DIGI_STRLEN((sbyte *) JSON_START_LINE) +
    DIGI_STRLEN((sbyte *) JSON_CERT_ISSUER) +
    DIGI_STRLEN((sbyte *) JSON_MIDDLE_LINE) + issuerLen +
    DIGI_STRLEN((sbyte *) JSON_END_LINE);

    /* Length of line 3 */
    jsonSigLen += DIGI_STRLEN((sbyte *) JSON_START_LINE) +
    DIGI_STRLEN((sbyte *) JSON_CERT_SERIAL) +
    DIGI_STRLEN((sbyte *) JSON_MIDDLE_LINE) + serialLen +
    DIGI_STRLEN((sbyte *) JSON_END_LINE);

    /* Length of line 4 */
    jsonSigLen += DIGI_STRLEN((sbyte *) JSON_START_LINE) +
    DIGI_STRLEN((sbyte *) JSON_ALGO_ID_EX) +
    DIGI_STRLEN((sbyte *) JSON_MIDDLE_LINE) +
    DIGI_STRLEN(pKeyIdStr) + DIGI_STRLEN(pHashIdStr) +
    DIGI_STRLEN((sbyte *) JSON_END_LINE);

    /* Length of line 5 */
    jsonSigLen += DIGI_STRLEN((sbyte *) JSON_START_LINE) +
    DIGI_STRLEN((sbyte *) JSON_DIGITAL_SIG) +
    DIGI_STRLEN((sbyte *) JSON_MIDDLE_LINE) + base64SigLen +
    DIGI_STRLEN((sbyte *) JSON_END_LINE_LAST);

    /* Length of line 6 */
    jsonSigLen += DIGI_STRLEN((sbyte *) JSON_END);

    status = DIGI_MALLOC((void **) &pJsonSig, jsonSigLen);
    if (OK != status)
    {
        goto exit;
    }

    pJsonPtr = pJsonSig;

    /* Line 1 - "{\n" */
    DIGI_MEMCPY(pJsonPtr, JSON_START, DIGI_STRLEN((sbyte *) JSON_START));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_START);

    /* Line 2 - "  \"certificateIssuerName\" : \"<issuer>\"" */
    DIGI_MEMCPY(pJsonPtr, JSON_START_LINE, DIGI_STRLEN((sbyte *) JSON_START_LINE));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_START_LINE);
    DIGI_MEMCPY(pJsonPtr, JSON_CERT_ISSUER, DIGI_STRLEN((sbyte *) JSON_CERT_ISSUER));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_CERT_ISSUER);
    DIGI_MEMCPY(pJsonPtr, JSON_MIDDLE_LINE, DIGI_STRLEN((sbyte *) JSON_MIDDLE_LINE));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_MIDDLE_LINE);
    DIGI_MEMCPY(pJsonPtr, pIssuer, issuerLen);
    pJsonPtr += issuerLen;
    DIGI_MEMCPY(pJsonPtr, JSON_END_LINE, DIGI_STRLEN((sbyte *) JSON_END_LINE));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_END_LINE);

    /* Line 4 - "  \"certificateSerialNumber\" : \"<serial_number>\"" */
    DIGI_MEMCPY(pJsonPtr, JSON_START_LINE, DIGI_STRLEN((sbyte *) JSON_START_LINE));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_START_LINE);
    DIGI_MEMCPY(pJsonPtr, JSON_CERT_SERIAL, DIGI_STRLEN((sbyte *) JSON_CERT_SERIAL));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_CERT_SERIAL);
    DIGI_MEMCPY(pJsonPtr, JSON_MIDDLE_LINE, DIGI_STRLEN((sbyte *) JSON_MIDDLE_LINE));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_MIDDLE_LINE);
    DIGI_MEMCPY(pJsonPtr, pSerial, serialLen);
    pJsonPtr += serialLen;
    DIGI_MEMCPY(pJsonPtr, JSON_END_LINE, DIGI_STRLEN((sbyte *) JSON_END_LINE));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_END_LINE);

    /* Line 2 - "  \"algoId\" : \"<algoId>\"" */
    DIGI_MEMCPY(pJsonPtr, JSON_START_LINE, DIGI_STRLEN((sbyte *) JSON_START_LINE));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_START_LINE);
    DIGI_MEMCPY(pJsonPtr, JSON_ALGO_ID_EX, DIGI_STRLEN((sbyte *) JSON_ALGO_ID_EX));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_ALGO_ID_EX);
    DIGI_MEMCPY(pJsonPtr, JSON_MIDDLE_LINE, DIGI_STRLEN((sbyte *) JSON_MIDDLE_LINE));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_MIDDLE_LINE);
    DIGI_MEMCPY(pJsonPtr, pKeyIdStr, DIGI_STRLEN((sbyte *) pKeyIdStr));
    pJsonPtr += DIGI_STRLEN((sbyte *) pKeyIdStr);
    DIGI_MEMCPY(pJsonPtr, pHashIdStr, DIGI_STRLEN((sbyte *) pHashIdStr));
    pJsonPtr += DIGI_STRLEN((sbyte *) pHashIdStr);
    DIGI_MEMCPY(pJsonPtr, JSON_END_LINE, DIGI_STRLEN((sbyte *) JSON_END_LINE));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_END_LINE);

    /* Line 3 - "  \"digitalSignature\" : \"<signature>\"" */
    DIGI_MEMCPY(pJsonPtr, JSON_START_LINE, DIGI_STRLEN((sbyte *) JSON_START_LINE));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_START_LINE);
    DIGI_MEMCPY(pJsonPtr, JSON_DIGITAL_SIG, DIGI_STRLEN((sbyte *) JSON_DIGITAL_SIG));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_DIGITAL_SIG);
    DIGI_MEMCPY(pJsonPtr, JSON_MIDDLE_LINE, DIGI_STRLEN((sbyte *) JSON_MIDDLE_LINE));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_MIDDLE_LINE);
    DIGI_MEMCPY(pJsonPtr, pBase64Sig, base64SigLen);
    pJsonPtr += base64SigLen;
    DIGI_MEMCPY(pJsonPtr, JSON_END_LINE_LAST, DIGI_STRLEN((sbyte *) JSON_END_LINE_LAST));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_END_LINE_LAST);

    /* Line 5 - "}\n" */
    DIGI_MEMCPY(pJsonPtr, JSON_END, DIGI_STRLEN((sbyte *) JSON_END));
    pJsonPtr += DIGI_STRLEN((sbyte *) JSON_END);

    *ppRetSig = pJsonSig;
    *pRetSigLen = jsonSigLen;
    pJsonSig = NULL;

exit:

    DIGI_FREE((void **) &pJsonSig);
    DIGI_FREE((void **) &pSignature);
    DIGI_FREE((void **) &pBase64Sig);
    DIGI_FREE((void **) &pDigest);
    DIGI_FREE((void **) &pIssuer);
    DIGI_FREE((void **) &pSerial);
    if (pDerCert != pCert)
    {
        DIGI_FREE((void **) &pDerCert);
    }

    return status;
}


MSTATUS CRYPTO_UTILS_signJsonMin(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pData,
    ubyte4 dataLen,
    ubyte *pKey,
    ubyte4 keyLen,
    ubyte hashAlgo,
    ubyte *pCert,
    ubyte4 certLen,
    ubyte **ppRetSig,
    ubyte4 *pRetSigLen
    )
{
    MSTATUS status = OK;
    AsymmetricKey asymKey = {0};

    status = CRYPTO_initAsymmetricKey(&asymKey);
    if (OK != status)
        goto exit;

    /* Load the key into an AsymmetricKey. */
    status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx) pKey, keyLen, NULL, &asymKey);
    if (OK != status)
        goto exit;

    status = CRYPTO_UTILS_signJsonMinFromAsymKey(MOC_ASYM(hwAccelCtx) pData, dataLen, &asymKey, hashAlgo, pCert, certLen, ppRetSig, pRetSigLen);

exit:

    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    return status;
}

MSTATUS CRYPTO_UTILS_verifyJson(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pJson,
    ubyte4 jsonLen,
    ubyte *pSig,
    ubyte4 sigLen,
    certStorePtr pCertStore,
    ubyte4 *pVerifyStatus
    )
{
    MSTATUS status;
    TimeDate td;

    /* Get the current time.
     */
    status = RTOS_timeGMT(&td);
    if (OK > status)
    {
        goto exit;
    }

    status = CRYPTO_UTILS_verifyJsonAux(
        MOC_ASYM(hwAccelCtx) pJson, jsonLen, pSig, sigLen, pCertStore, &td,
        pVerifyStatus);
    if (OK != status)
    {
        goto exit;
    }

exit:

    return status;
}

MSTATUS CRYPTO_UTILS_verifyJsonAux(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pJson,
    ubyte4 jsonLen,
    ubyte *pSig,
    ubyte4 sigLen,
    certStorePtr pCertStore,
    TimeDate *pTime,
    ubyte4 *pVerifyStatus
    )
{
    MSTATUS status;
    JSON_ContextType *pJsonCtx = NULL;
    ubyte *pCert = NULL, *pKey = NULL, *pDerCert = NULL, *pDigest = NULL;
    ubyte *pSignature = NULL;
    ubyte4 tokensFound, index, keyType, certLen, keyLen, derCertLen;
    ubyte4 signatureLen, digestLen;
    ubyte hashId;
    certDescriptor certDesc = {0};
    certChainPtr pChain = NULL;
    JSON_TokenType token = { 0 };
    ValidationConfig vc = { 0 };
    AsymmetricKey asymKey = { 0 };
    const BulkHashAlgo *pDigestAlgo = NULL;

    status = CRYPTO_initAsymmetricKey(&asymKey);
    if (OK != status)
    {
        goto exit;
    }

    if ( (NULL == pJson) || (NULL == pSig) || (NULL == pVerifyStatus) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Set the default error status.
     */
    *pVerifyStatus = 1;

    status = JSON_acquireContext(&pJsonCtx);
    if (OK != status)
    {
        goto exit;
    }

    /* Parse the JSON signature element.
     */
    status = JSON_parse(pJsonCtx, (const sbyte *) pSig, sigLen, &tokensFound);
    if (OK != status)
    {
        goto exit;
    }

    /* Get the algorithm ID from the JSON element.
     */
    status = JSON_getObjectIndex(
        pJsonCtx, (const sbyte *) JSON_ALGO_ID, 0, &index, FALSE);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_getToken(pJsonCtx, index + 1, &token);
    if ( (OK != status) || (JSON_String != token.type) )
    {
        status = ERR_CRYPTO_UTIL_JSON_PARSE_FAILED;
        goto exit;
    }

    /* Get the key type and hash ID based on the JSON algorithm ID string.
     */
    status = convertStrToKeyTypeAndHash(
        (sbyte *) token.pStart, token.len, &keyType, &hashId);
    if (OK != status)
    {
        goto exit;
    }

    /* Get the certificate.
     */
    status = JSON_getObjectIndex(
        pJsonCtx, (const sbyte *) JSON_SIG_CERT, 0, &index, FALSE);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_getToken(pJsonCtx, index + 1, &token);
    if ( (OK != status) || (JSON_String != token.type) )
    {
        status = ERR_CRYPTO_UTIL_JSON_PARSE_FAILED;
        goto exit;
    }

    status = DIGI_MALLOC_MEMCPY(
        (void **) &pCert, token.len, (sbyte *) token.pStart, token.len);
    if (OK != status)
    {
        goto exit;
    }

    /* Unescape any newline characters.
     */
    certLen = token.len;
    status = unescapeNewLineChar(pCert, &certLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Convert the certificate into DER format.
     */
    status = CA_MGMT_decodeCertificate(pCert, certLen, &pDerCert, &derCertLen);
    if (OK != status)
    {
        goto exit;
    }

    certDesc.pCertificate = pDerCert;
    certDesc.certLength = derCertLen;

    /* Create a certificate chain from the certificate.
     */
    status = CERTCHAIN_createFromIKE(MOC_ASYM(hwAccelCtx) &pChain, &certDesc, 1);
    if (OK > status)
    {
        goto exit;
    }

    /* Set the time to validate and the certificate store to validate against.
     */
    vc.keyUsage = 0;
    vc.td = pTime;
    vc.pCertStore = pCertStore;

    /* Validate the certificate.
     */
    status = CERTCHAIN_validate(MOC_ASYM(hwAccelCtx) pChain, &vc);
    if (OK > status)
    {
        /* Not Found -> no authentication of certificate */
        goto exit;
    }

    /* Extract the public key from the certificate.
     */
    status = CA_MGMT_extractPublicKeyInfo(pDerCert, derCertLen, &pKey, &keyLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Load the public key into an AsymmetricKey.
     */
    status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx) pKey, keyLen, NULL, &asymKey);
    if (OK != status)
    {
        goto exit;
    }

    /* Get the signature in the JSON element.
     */
    status = JSON_getObjectIndex(
        pJsonCtx, (const sbyte *) JSON_SIG_VALUE, 0, &index, FALSE);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_getToken(pJsonCtx, index + 1, &token);
    if ( (OK != status) || (JSON_String != token.type) )
    {
        status = ERR_CRYPTO_UTIL_JSON_PARSE_FAILED;
        goto exit;
    }

    /* Decode the signature.
     */
    status = BASE64_decodeMessage(
        (const ubyte *) token.pStart, token.len, &pSignature, &signatureLen);
    if (OK != status)
    {
        goto exit;
    }

    if ((asymKey.type & 0xFF) != keyType)
    {
        status = ERR_KEY_TYPE_MISMATCH;
        goto exit;
    }

    /* Get the hash suite based on the hash ID.
     */
    switch (keyType)
    {
        case akt_rsa:
            status = CRYPTO_getRSAHashAlgo(hashId, &pDigestAlgo);
            break;

#ifdef __ENABLE_DIGICERT_ECC__
        case akt_ecc:
            status = CRYPTO_getECCHashAlgo(
                hashId, (BulkHashAlgo **) &pDigestAlgo);
            break;
#endif /* __ENABLE_DIGICERT_ECC__ */

        default:
            status = ERR_BAD_KEY_TYPE;

    }
    if (OK != status)
    {
        goto exit;
    }

    /* Digest the input data.
     */
    status = digestData(MOC_HASH(hwAccelCtx)
        pDigestAlgo, pJson, jsonLen, &pDigest, &digestLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Verify the signature.
     */
    switch (keyType)
    {
#ifndef __DISABLE_DIGICERT_RSA__
        case akt_rsa:
            status = rsaVerifySignature(MOC_RSA(hwAccelCtx)
                &asymKey, pDigest, digestLen, hashId, pSignature, signatureLen,
                pVerifyStatus);
            break;
#endif

#ifdef __ENABLE_DIGICERT_ECC__
        case akt_ecc:
            status = eccVerifySignature(MOC_ECC(hwAccelCtx)
                &asymKey, pDigest, digestLen, pSignature, signatureLen,
                pVerifyStatus);
            break;
#endif /* __ENABLE_DIGICERT_ECC__ */
    }

exit:

    DIGI_FREE((void **) &pSignature);
    DIGI_FREE((void **) &pDigest);
    DIGI_FREE((void **) &pKey);
    DIGI_FREE((void **) &pDerCert);
    DIGI_FREE((void **) &pCert);
    CERTCHAIN_delete(&pChain);
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    JSON_releaseContext(&pJsonCtx);

    return status;
}

MSTATUS CRYPTO_UTILS_verifyJsonMin(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pJson,
    ubyte4 jsonLen,
    ubyte *pCert,
    ubyte4 certLen,
    ubyte *pSig,
    ubyte4 sigLen,
    ubyte4 *pVerifyStatus
    )
{
    MSTATUS status;
    JSON_ContextType *pJsonCtx = NULL;
    ubyte *pKey = NULL, *pDerCert = NULL, *pDigest = NULL;
    ubyte *pSignature = NULL;
    ubyte4 tokensFound, index, keyType, keyLen, derCertLen;
    ubyte4 signatureLen, digestLen;
    ubyte hashId;
    certDescriptor certDesc = {0};
    certChainPtr pChain = NULL;
    JSON_TokenType token = { 0 };
    ValidationConfig vc = { 0 };
    TimeDate td;
    AsymmetricKey asymKey = { 0 };
    const BulkHashAlgo *pDigestAlgo = NULL;
    sbyte4 cmpRes = -1;

    status = CRYPTO_initAsymmetricKey(&asymKey);
    if (OK != status)
    {
        goto exit;
    }

    if ( (NULL == pJson) || (NULL == pSig) || (NULL == pVerifyStatus) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Set the default error status.
     */
    *pVerifyStatus = 1;

    status = JSON_acquireContext(&pJsonCtx);
    if (OK != status)
    {
        goto exit;
    }

    /* Parse the JSON signature element.
     */
    status = JSON_parse(pJsonCtx, (const sbyte *) pSig, sigLen, &tokensFound);
    if (OK != status)
    {
        goto exit;
    }

    /* Get the algorithm ID from the JSON element.
     */
    status = JSON_getObjectIndex(
        pJsonCtx, (const sbyte *) JSON_ALGO_ID_EX, 0, &index, FALSE);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_getToken(pJsonCtx, index + 1, &token);
    if ( (OK != status) || (JSON_String != token.type) )
    {
        status = ERR_CRYPTO_UTIL_JSON_PARSE_FAILED;
        goto exit;
    }

    /* Get the key type and hash ID based on the JSON algorithm ID string.
     */
    status = convertStrToKeyTypeAndHash(
        (sbyte *) token.pStart, token.len, &keyType, &hashId);
    if (OK != status)
    {
        goto exit;
    }

    /* Convert the certificate into DER format.
     */
    if (certLen >= MOC_PEM_CERT_HEADER_LEN)
    {
        status = DIGI_MEMCMP(
            pCert, (ubyte *) MOC_PEM_CERT_HEADER, MOC_PEM_CERT_HEADER_LEN,
            &cmpRes);
        if (OK != status)
        {
            goto exit;
        }
    }

    if (0 == cmpRes)
    {
        status = CA_MGMT_decodeCertificate(
            pCert, certLen, &pDerCert, &derCertLen);
        if (OK != status)
        {
            goto exit;
        }
    }
    else
    {
        pDerCert = pCert;
        derCertLen = certLen;
    }

    certDesc.pCertificate = pDerCert;
    certDesc.certLength = derCertLen;

    /* Create a certificate chain from the certificate.
     */
    status = CERTCHAIN_createFromIKE(MOC_ASYM(hwAccelCtx) &pChain, &certDesc, 1);
    if (OK > status)
    {
        goto exit;
    }

    /* Get the current time.
     */
    status = RTOS_timeGMT(&td);
    if (OK > status)
    {
        goto exit;
    }

    /* Set the time to validate and the certificate store to validate against.
     */
    vc.keyUsage = 0;
    vc.td = &td;
    vc.pCertStore = NULL;

    /* Validate the certificate.
     */
    status = CERTCHAIN_validate(MOC_ASYM(hwAccelCtx) pChain, &vc);
    if (OK > status)
    {
        /* Not Found -> no authentication of certificate */
        goto exit;
    }

    /* Extract the public key from the certificate.
     */
    status = CA_MGMT_extractPublicKeyInfo(pDerCert, derCertLen, &pKey, &keyLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Load the public key into an AsymmetricKey.
     */
    status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx) pKey, keyLen, NULL, &asymKey);
    if (OK != status)
    {
        goto exit;
    }

    /* Get the signature in the JSON element.
     */
    status = JSON_getObjectIndex(
        pJsonCtx, (const sbyte *) JSON_DIGITAL_SIG, 0, &index, FALSE);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_getToken(pJsonCtx, index + 1, &token);
    if ( (OK != status) || (JSON_String != token.type) )
    {
        status = ERR_CRYPTO_UTIL_JSON_PARSE_FAILED;
        goto exit;
    }

    /* Decode the signature.
     */
    status = BASE64_decodeMessage(
        (const ubyte *) token.pStart, token.len, &pSignature, &signatureLen);
    if (OK != status)
    {
        goto exit;
    }

    if ((asymKey.type & 0xFF) != keyType)
    {
        status = ERR_KEY_TYPE_MISMATCH;
        goto exit;
    }

    /* Get the hash suite based on the hash ID.
     */
    switch (keyType)
    {
        case akt_rsa:
            status = CRYPTO_getRSAHashAlgo(hashId, &pDigestAlgo);
            break;

#ifdef __ENABLE_DIGICERT_ECC__
        case akt_ecc:
            status = CRYPTO_getECCHashAlgo(
                hashId, (BulkHashAlgo **) &pDigestAlgo);
            break;
#endif /* __ENABLE_DIGICERT_ECC__ */

        default:
            status = ERR_BAD_KEY_TYPE;

    }
    if (OK != status)
    {
        goto exit;
    }

    /* Digest the input data.
     */
    status = digestData(MOC_HASH(hwAccelCtx)
        pDigestAlgo, pJson, jsonLen, &pDigest, &digestLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Verify the signature.
     */
    switch (keyType)
    {
#ifndef __DISABLE_DIGICERT_RSA__
        case akt_rsa:
            status = rsaVerifySignature( MOC_RSA(hwAccelCtx)
                &asymKey, pDigest, digestLen, hashId, pSignature, signatureLen,
                pVerifyStatus);
            break;
#endif

#ifdef __ENABLE_DIGICERT_ECC__
        case akt_ecc:
            status = eccVerifySignature( MOC_ECC(hwAccelCtx)
                &asymKey, pDigest, digestLen, pSignature, signatureLen,
                pVerifyStatus);
            break;
#endif /* __ENABLE_DIGICERT_ECC__ */
    }

exit:

    DIGI_FREE((void **) &pSignature);
    DIGI_FREE((void **) &pDigest);
    DIGI_FREE((void **) &pKey);
    if (pDerCert != pCert)
    {
        DIGI_FREE((void **) &pDerCert);
    }
    CERTCHAIN_delete(&pChain);
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    JSON_releaseContext(&pJsonCtx);

    return status;
}

static MSTATUS retrieveAlgoId(
    JSON_ContextType *pJsonCtx,
    sbyte *pKeyValue,
    ubyte4 index,
    ubyte4 *pKeyType,
    ubyte *pHashId
    )
{
    MSTATUS status;
    JSON_TokenType token = { 0 };

    status = JSON_getObjectIndex(
        pJsonCtx, (const sbyte *) pKeyValue, index, &index, TRUE);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_getToken(pJsonCtx, index + 1, &token);
    if ( (OK != status) || (JSON_String != token.type) )
    {
        status = ERR_CRYPTO_UTIL_JSON_PARSE_FAILED;
        goto exit;
    }

    status = convertStrToKeyTypeAndHash(
        (sbyte *) token.pStart, token.len, pKeyType, pHashId);
    if (OK != status)
    {
        goto exit;
    }

exit:

    return status;
}

static MSTATUS retrieveSigValue(
    JSON_ContextType *pJsonCtx,
    sbyte *pKeyValue,
    ubyte4 index,
    ubyte **ppRetSig,
    ubyte4 *pRetSigLen
    )
{
    MSTATUS status;
    JSON_TokenType token = { 0 };

    status = JSON_getObjectIndex(
        pJsonCtx, (const sbyte *) pKeyValue, index, &index, TRUE);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_getToken(pJsonCtx, index + 1, &token);
    if ( (OK != status) || (JSON_String != token.type) )
    {
        status = ERR_CRYPTO_UTIL_JSON_PARSE_FAILED;
        goto exit;
    }

    status = BASE64_decodeMessage(
        (const ubyte *) token.pStart, token.len, ppRetSig, pRetSigLen);
    if (OK != status)
    {
        goto exit;
    }

exit:

    return status;
}

static MSTATUS retrievePubKey(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    JSON_ContextType *pJsonCtx,
    sbyte *pKeyValue,
    ubyte4 index,
    certStorePtr pCertStore,
    AsymmetricKey *pAsymKey
    )
{
    MSTATUS status;
    JSON_TokenType token = { 0 };
    ubyte *pCert = NULL;
    ubyte4 certLen;
    certDescriptor certDesc = {0};
    ValidationConfig vc = { 0 };
    TimeDate td;
    certChainPtr pChain = NULL;

    status = JSON_getObjectIndex(
        pJsonCtx, (const sbyte *) pKeyValue, index, &index, TRUE);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_getToken(pJsonCtx, index + 1, &token);
    if ( (OK != status) || (JSON_String != token.type) )
    {
        status = ERR_CRYPTO_UTIL_JSON_PARSE_FAILED;
        goto exit;
    }

    status = DIGI_MALLOC_MEMCPY(
        (void **) &pCert, token.len, (sbyte *) token.pStart, token.len);
    if (OK != status)
    {
        goto exit;
    }

    certLen = token.len;
    status = unescapeNewLineChar(pCert, &certLen);
    if (OK != status)
    {
        goto exit;
    }

    status = CA_MGMT_decodeCertificate(
        pCert, certLen, &(certDesc.pCertificate), &(certDesc.certLength));
    if (OK != status)
    {
        goto exit;
    }

    status = CERTCHAIN_createFromIKE(MOC_ASYM(hwAccelCtx) &pChain, &certDesc, 1);
    if (OK > status)
    {
        goto exit;
    }

    status = RTOS_timeGMT(&td);
    if (OK > status)
    {
        goto exit;
    }

    vc.keyUsage = 0;
    vc.td = &td;
    vc.pCertStore = pCertStore;

    status = CERTCHAIN_validate(MOC_ASYM(hwAccelCtx) pChain, &vc);
    if (OK > status)
    {
        /* Not Found -> no authentication of certificate */
        goto exit;
    }

    status = CERTCHAIN_getKey(MOC_ASYM(hwAccelCtx) pChain, 0, pAsymKey);
    if (OK != status)
    {
        goto exit;
    }

exit:

    DIGI_FREE((void **) &pCert);
    DIGI_FREE((void **) &(certDesc.pCertificate));
    CERTCHAIN_delete(&pChain);

    return status;
}

/* Consolidate logic between this function and CRYPTO_UTILS_verifyJson.
 */
MSTATUS CRYPTO_UTILS_verifyJsonMultiSig(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pJson,
    ubyte4 jsonLen,
    ubyte *pSig,
    ubyte4 sigLen,
    certStorePtr pCertStore,
    ubyte4 *pVerifyStatus
    )
{
    MSTATUS status;
    JSON_ContextType *pJsonCtx = NULL;
    ubyte4 sigCount = 0, digestLen, signatureLen, keyType;
    ubyte4 startIdx = 0, tokensFound, vfy = 1;
    ubyte hashId;
    ubyte *pDigest = NULL, *pSignature = NULL;
    const BulkHashAlgo *pDigestAlgo = NULL;
    AsymmetricKey asymKey = {0};

    if ( (NULL == pJson) || (NULL == pSig) || (NULL == pVerifyStatus) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Set the default error status.
     */
    *pVerifyStatus = 1;

    status = JSON_acquireContext(&pJsonCtx);
    if (OK != status)
    {
        goto exit;
    }

    /* Parse the JSON signature element.
     */
    status = JSON_parse(pJsonCtx, (const sbyte *) pSig, sigLen, &tokensFound);
    if (OK != status)
    {
        goto exit;
    }

    while (startIdx < tokensFound)
    {
        /* start each iteration with a fresh key */
        status = CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
        if (OK != status)
        {
            goto exit;
        }

        status = CRYPTO_initAsymmetricKey(&asymKey);
        if (OK != status)
        {
            goto exit;
        }

        status = retrieveAlgoId(
            pJsonCtx, (sbyte *) JSON_ALGO_ID, startIdx, &keyType, &hashId);
        if (OK != status)
        {
            goto exit;
        }

        DIGI_FREE((void **) &pSignature);

        status = retrieveSigValue(
            pJsonCtx, (sbyte *) JSON_SIG_VALUE, startIdx, &pSignature,
            &signatureLen);
        if (OK != status)
        {
            goto exit;
        }

        status = retrievePubKey( MOC_ASYM(hwAccelCtx)
            pJsonCtx, (sbyte *) JSON_SIG_CERT, startIdx, pCertStore, &asymKey);
        if (OK != status)
        {
            goto exit;
        }

        if ((asymKey.type & 0xFF) != keyType)
        {
            status = ERR_KEY_TYPE_MISMATCH;
            goto exit;
        }

        /* Get the hash suite based on the hash ID.
         */
        switch (keyType)
        {
            case akt_rsa:
                status = CRYPTO_getRSAHashAlgo(hashId, &pDigestAlgo);
                break;

#ifdef __ENABLE_DIGICERT_ECC__
            case akt_ecc:
                status = CRYPTO_getECCHashAlgo(
                    hashId, (BulkHashAlgo **) &pDigestAlgo);
                break;
#endif /* __ENABLE_DIGICERT_ECC__ */

            default:
                status = ERR_BAD_KEY_TYPE;

        }
        if (OK != status)
        {
            goto exit;
        }

        DIGI_FREE((void **) &pDigest);

        /* Digest the input data.
         */
        status = digestData( MOC_HASH(hwAccelCtx)
            pDigestAlgo, pJson, jsonLen, &pDigest, &digestLen);
        if (OK != status)
        {
            goto exit;
        }

        /* Verify the signature.
         */
        switch (keyType)
        {
#ifndef __DISABLE_DIGICERT_RSA__
            case akt_rsa:
                status = rsaVerifySignature( MOC_RSA(hwAccelCtx)
                    &asymKey, pDigest, digestLen, hashId, pSignature, signatureLen,
                    &vfy);
                break;
#endif

#ifdef __ENABLE_DIGICERT_ECC__
            case akt_ecc:
                status = eccVerifySignature( MOC_ECC(hwAccelCtx)
                    &asymKey, pDigest, digestLen, pSignature, signatureLen,
                    &vfy);
                break;
#endif /* __ENABLE_DIGICERT_ECC__ */

            default:
                status = ERR_KEY_TYPE_MISMATCH;
        }
        if ( (OK != status) || (0 != vfy) )
        {
            *pVerifyStatus = vfy;
            goto exit;
        }

        /* Advance the index.
         */
        status = JSON_getLastIndexInObject(pJsonCtx, startIdx, &startIdx);
        if (OK != status)
        {
            goto exit;
        }

        startIdx++;
        sigCount++;
    }

    if (0 == sigCount)
    {
        status = ERR_CRYPTO_UTIL_JSON_NO_SIGNATURE;
        goto exit;
    }

    *pVerifyStatus = vfy;

exit:

    DIGI_FREE((void **) &pSignature);
    DIGI_FREE((void **) &pDigest);
    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    JSON_releaseContext(&pJsonCtx);

    return status;
}

static MSTATUS CRYPTO_UTILS_verifyJsonMultiSigByFile(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    sbyte *pFile,
    sbyte *pSigFile,
    certStorePtr pCertStore,
    ubyte4 *pVerifyStatus
    )
{
    MSTATUS status;
    ubyte *pJsonData = NULL, *pJsonSigData = NULL;
    ubyte4 jsonDataLen, jsonSigDataLen;

    if ( (NULL == pFile) || (NULL == pSigFile) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGICERT_readFile((const char *) pFile, &pJsonData, &jsonDataLen);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGICERT_readFile((const char *) pSigFile, &pJsonSigData, &jsonSigDataLen);
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_UTILS_verifyJsonMultiSig( MOC_ASYM(hwAccelCtx)
        pJsonData, jsonDataLen, pJsonSigData, jsonSigDataLen, pCertStore,
        pVerifyStatus);
    if (OK != status)
    {
        goto exit;
    }

exit:

    DIGI_FREE((void **) &pJsonData);
    DIGI_FREE((void **) &pJsonSigData);

    return status;
}

#define DEFAULT_JSON_SIG_EXT ".sig.json"

MSTATUS CRYPTO_UTILS_verifyJsonMultiSigByFileExt(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    sbyte *pFile,
    certStorePtr pCertStore,
    ubyte4 *pVerifyStatus
    )
{
    MSTATUS status;
    sbyte *pSigFile = NULL, *pIndex;

    status = DIGI_MALLOC(
        (void **) &pSigFile,
        DIGI_STRLEN(pFile) +  DIGI_STRLEN((const sbyte *) DEFAULT_JSON_SIG_EXT) + 1);
    if (OK != status)
    {
        goto exit;
    }

    pIndex = pSigFile;

    status = DIGI_MEMCPY(pIndex, pFile, DIGI_STRLEN(pFile));
    if (OK != status)
    {
        goto exit;
    }
    pIndex += DIGI_STRLEN(pFile);

    status = DIGI_MEMCPY(
        pIndex, DEFAULT_JSON_SIG_EXT, DIGI_STRLEN((const sbyte *) DEFAULT_JSON_SIG_EXT));
    if (OK != status)
    {
        goto exit;
    }
    pIndex += DIGI_STRLEN((const sbyte *) DEFAULT_JSON_SIG_EXT);

    *pIndex = 0x00;

    status = CRYPTO_UTILS_verifyJsonMultiSigByFile( MOC_ASYM(hwAccelCtx)
        pFile, pSigFile, pCertStore, pVerifyStatus);

exit:

    DIGI_FREE((void ** ) &pSigFile);

    return status;
}

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)

static char* CRYPTO_UTILS_getFullPath(const char* directory, const char* name, char **ppFull)
{
    int len = 0;

#if (!defined (__RTOS_OSE__) && !defined(__RTOS_WIN32__))
    /* What size? */
    len = DIGI_STRLEN (directory);
    len += 1;
    len += DIGI_STRLEN (name);
    len += 1;

    /* Create concatenated string */
    *ppFull = MALLOC(len);
    if ( NULL == *ppFull )
        goto exit;

    DIGI_STRCBCPY (*ppFull, len, directory);
    DIGI_STRCAT (*ppFull, "/");
    DIGI_STRCAT (*ppFull, name);
#elif (defined(__RTOS_WIN32__))
    len = (int)DIGI_STRLEN (directory);
    len += 1;
    len += (int)DIGI_STRLEN (name);
    len += 1;

    /* Create concatenated string */
    *ppFull = MALLOC(len);
    if ( NULL == *ppFull )
        goto exit;

    DIGI_STRCBCPY (*ppFull, len, directory);
    DIGI_STRCAT (*ppFull, "\\");
    DIGI_STRCAT (*ppFull, name);
#else
    /* Do not change! */
    len += DIGI_STRLEN (name);
    len += 1;

    /* Create duplicated string */
    *ppFull = MALLOC(len);
    if ( NULL == *ppFull )
        goto exit;

    DIGI_STRCBCPY (*ppFull, len, name);
#endif
exit:
    return *ppFull;
}

/*------------------------------------------------------------------*/

extern MSTATUS CRYPTO_UTILS_readTrustedConfigCerts(
    certStorePtr pStore,
    certStorePtr pExpired,
    sbyte *pTrustedCertsPath,
    intBoolean verifyOnly
    )
{
    MSTATUS status;
    DirectoryEntry ent;
    DirectoryDescriptor dir = NULL;

#ifdef __RTOS_WIN32__
    char *pCACertsFileFindName = NULL;
    const char *fileInDirSearchExpr = "\\*";
    ubyte4 caCertsFileFindNameLen = 0;
#endif /* !__RTOS_WIN32__ */
    byteBoolean isCertEntryValid = FALSE;
    char *pCertPath = (char *) pTrustedCertsPath;
    ubyte *pTempPath = NULL;

    ubyte *pCert = NULL;
    ubyte4 certLen = 0;
    char *pFullPath = NULL;
    ubyte valid = 0;
    ubyte4 verify = 0;
    intBoolean fileExists;
    byteBoolean verifyConfig;

    if (FALSE == verifyOnly)
    {
        /* At least on of the certificate stores must be provided.
         */
        if ( (NULL == pStore) && (NULL == pExpired) )
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }
    }
    else
    {
        /* In verify only, neither of the certificate stores must be provided.
         */
        if ( (NULL != pStore) || (NULL != pExpired) )
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
    }

    if (NULL == pCertPath)
    {
        status = DPM_checkStatus(DPM_CONFIG, &verifyConfig);
        if (OK != status)
        {
            goto exit;
        }

        if (TRUE == verifyConfig)
        {
            status = CRYPTO_UTILS_readTrustedPaths(
                NULL, NULL, (sbyte **) &pCertPath, NULL);
        }
        else
        {
            status = CRYPTO_UTILS_readTrustedPathsNoVerify(
                NULL, NULL, (sbyte **) &pCertPath, NULL);
        }
        if (OK != status)
        {
            goto exit;
        }
    }

#ifdef __RTOS_WIN32__
    caCertsFileFindNameLen = DIGI_STRLEN(pCertPath) + DIGI_STRLEN(fileInDirSearchExpr) + 1;

    status = DIGI_CALLOC(&pCACertsFileFindName,
        caCertsFileFindNameLen,
        sizeof(*pCACertsFileFindName));
    if (OK != status)
    {
        goto exit;
    }

    DIGI_STRCBCPY(pCACertsFileFindName, caCertsFileFindNameLen, pCertPath);
    DIGI_STRCAT(pCACertsFileFindName, fileInDirSearchExpr);
    pTempPath = pCertPath;
    pCertPath = pCACertsFileFindName;
#endif

    status = FMGMT_getFirstFile (pCertPath, &dir, &ent);
    if((OK == status) && (FTNone != ent.type))
    {
        /*Process all certificates present in ca directory.*/
        do
        {
            if(FTFile == ent.type)
            {

                valid = 0;

                if (NULL != pFullPath)
                {
                    DIGI_FREE((void **) &pFullPath);
                }

                if (NULL != pCert)
                {
                    DIGI_FREE((void **) &pCert);
                }

                CRYPTO_UTILS_getFullPath((const char *)pCertPath, ent.pName, &pFullPath);

                if (OK > (status = DIGICERT_readFile(pFullPath, &pCert, &certLen)))
                {
                    goto exit;
                }

                if ((ent.nameLength > 4) && (0 == DIGI_STRNICMP (ent.pName + ent.nameLength - 4, (sbyte *) ".pem", 4)))
                {
                    ubyte *pDecodedData = NULL;
                    ubyte4 decodedDataLen;
                    if (OK > (status = CA_MGMT_decodeCertificate(pCert, certLen, &pDecodedData, &decodedDataLen)))
                    {
                        goto exit;
                    }
                    if(pCert) DIGI_FREE((void **)&pCert);
                    pCert = pDecodedData;
                    certLen = decodedDataLen;
                    valid = 1;
                }

                if ((ent.nameLength > 4) && (0 == DIGI_STRNICMP (ent.pName + ent.nameLength - 4, (sbyte *) ".der", 4)))
                {
                    valid = 1;
                }

                /* Only process .pem and .der files */
                if (1 == valid)
                {

                    status = DIGICERT_checkFile(
                        pFullPath, MOC_FP_SIG_SUFFIX, &fileExists);
                    if (OK != status)
                    {
                        goto exit;
                    }

                    if (TRUE == fileExists)
                    {
                        /* Perform a symmetric verification of the ca cert to be loaded */
                        status = DIGICERT_verifyFile((const char *)pFullPath, TRUE, &verify);
                        if (OK != status)
                        {
                            goto exit;
                        }

                        if (0 != verify)
                        {
                            status = ERR_FP_INVALID_SIG_FILE;
                            goto exit;
                        }
                        if (OK == (CA_MGMT_verifyCertDate(pCert, certLen)))
                        {
                            if (NULL != pStore)
                            {
                                if (OK > (status = CERT_STORE_addTrustPoint(pStore, pCert, certLen)))
                                {
                                    goto exit;
                                }
                            }
                        }
                        else
                        {
                            if (NULL != pExpired)
                            {
                                if (OK > (status = CERT_STORE_addTrustPoint(pExpired, pCert, certLen)))
                                {
                                    goto exit;
                                }
                            }
                        }
                    }
                }
            }

            status = FMGMT_getNextFile (dir, &ent);
            if (OK != status)
                goto exit;

        } while (FTNone != ent.type);

        status = OK;
    }
    else if (OK != status)
    {
        status = ERR_CERT_STORE;
    }

exit:

    if (NULL != dir)
    {
        /* empty directory, close directory handle */
        FMGMT_closeDir (&dir);
    }

    if (NULL != pFullPath)
    {
        DIGI_FREE((void **) &pFullPath);
    }

#ifdef __RTOS_WIN32__
    if (NULL != pCACertsFileFindName)
    {
        DIGI_FREE((void **)&pCACertsFileFindName);
    }
#endif

    if (NULL != pTempPath)
    {
        DIGI_FREE((void **) &pTempPath);
    }

    if ( (NULL != pCertPath) && (pCertPath != (char *)pTrustedCertsPath) )
    {
        DIGI_FREE((void **)&pCertPath);
    }

    if (NULL != pCert)
    {
        DIGI_FREE((void **) &pCert);
    }

    return status;
}

#endif /* __ENABLE_DIGICERT_DATA_PROTECTION__ */

#endif /* __ENABLE_DIGICERT_JSON_VERIFY__ */

/*------------------------------------------------------------------*/

static MSTATUS CRYPTO_UTILS_utilPathJSONtoStr(sbyte* path)
{
    sbyte   *ret_str = NULL;

    while(NULL != (ret_str = (sbyte *)strstr((const char *)path, (const char *)"\\\\")))
    {
        ubyte4 idx = (ubyte4)((ubyte*)ret_str - (ubyte*)path);
        ubyte4 end = idx + DIGI_STRLEN(ret_str);

        /* Overwrite the double slashes by shortening the string by one char */
        for (++idx ; idx < end; ++idx)
        {
            path[idx] = path[idx+1];
        }
    }

    return OK;
}

/*------------------------------------------------------------------*/

static MSTATUS CRYPTO_UTILS_utilReadTrustedConfig(
    ubyte* pData,
    ubyte4 dataLen,
    sbyte **pConfigpath,
    sbyte **pKeypath,
    sbyte **pTrustpath,
    sbyte **pBinpath,
    sbyte **pProxyURL,
    sbyte **pRootpath
    )
{
    MSTATUS          status;
    JSON_ContextType *pJsonConfigCxt = NULL;
    ubyte4           tokensFound;
    JSON_TokenType   token = {0};
    ubyte4           index = 0;
    sbyte            *pConfPath = NULL;

    status = JSON_acquireContext (&pJsonConfigCxt);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_parse (pJsonConfigCxt,
                         (const sbyte *)pData, dataLen,
                         &tokensFound);
    if (OK != status)
    {
        goto exit;
    }

    if (0 < tokensFound)
    {
        /* Read 'keystoreDir' */
        if (NULL != pKeypath)
        {
            status = JSON_getObjectIndex (pJsonConfigCxt,
                                        (sbyte *)KEYDIR_JSTR, 0, &index, FALSE);
            if (OK != status)
            {
                goto exit;
            }

            status = JSON_getToken (pJsonConfigCxt, index + 1, &token);
            if (OK != status)
            {
                goto exit;
            }

            if (JSON_String == token.type)
            {
                status = DIGI_CALLOC ((void**)pKeypath, 1, token.len + 1);
                if (OK != status)
                {
                    goto exit;
                }

                status = DIGI_MEMCPY (*pKeypath, token.pStart, token.len);
                if (OK != status)
                    goto exit;

                status = CRYPTO_UTILS_utilPathJSONtoStr(*pKeypath);
                if (OK != status)
                    goto exit;

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
                if (DIGI_STRNCMP(*pKeypath, MANDATORY_BASE_PATH, DIGI_STRLEN(MANDATORY_BASE_PATH)) != 0)
                {
                    status = ERR_FILE_INSECURE_PATH;
                    goto exit;
                }
#endif
            }
            else
            {
                status = ERR_UM_JSON_PARSE_FAILED;
                goto exit;
            }
        }

        /* Read 'truststoreDir' */
        if (NULL != pTrustpath)
        {
            status = JSON_getObjectIndex (pJsonConfigCxt,
                                        (sbyte *)TRUSTDIR_JSTR, 0, &index, FALSE);
            if (OK != status)
            {
                goto exit;
            }

            status = JSON_getToken (pJsonConfigCxt, index + 1, &token);
            if (OK != status)
            {
                goto exit;
            }

            if (JSON_String == token.type)
            {
                status = DIGI_CALLOC ((void**)pTrustpath, 1, token.len + 1);
                if (OK != status)
                {
                    goto exit;
                }

                status = DIGI_MEMCPY (*pTrustpath, token.pStart, token.len);
                if (OK != status)
                    goto exit;

                status = CRYPTO_UTILS_utilPathJSONtoStr(*pTrustpath);
                if (OK != status)
                    goto exit;

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
                if (DIGI_STRNCMP(*pTrustpath, MANDATORY_BASE_PATH, DIGI_STRLEN(MANDATORY_BASE_PATH)) != 0)
                {
                    status = ERR_FILE_INSECURE_PATH;
                    goto exit;
                }
#endif
            }
            else
            {
                status = ERR_UM_JSON_PARSE_FAILED;
                goto exit;
            }
        }

        /* Derive persist directory based on 'conf_dir' */
        if (NULL != pConfigpath)
        {
            status = JSON_getObjectIndex (pJsonConfigCxt,
                                        (sbyte *)CONFDIR_JSTR, 0, &index, FALSE);
            if (OK != status)
            {
                goto exit;
            }

            status = JSON_getToken (pJsonConfigCxt, index + 1, &token);
            if (OK != status)
            {
                goto exit;
            }

            if (JSON_String == token.type)
            {
                status = DIGI_CALLOC ((void**)&pConfPath, 1, token.len + 1);
                if (OK != status)
                {
                    goto exit;
                }

                status = DIGI_MEMCPY (pConfPath, token.pStart, token.len);
                if (OK != status)
                    goto exit;

                status = CRYPTO_UTILS_utilPathJSONtoStr(pConfPath);
                if (OK != status)
                    goto exit;

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
                if (DIGI_STRNCMP(pConfPath, MANDATORY_BASE_PATH, DIGI_STRLEN(MANDATORY_BASE_PATH)) != 0)
                {
                    status = ERR_FILE_INSECURE_PATH;
                    goto exit;
                }
#endif

                /* Save of config path by itself */
                *pConfigpath = pConfPath;
                pConfPath = NULL;
            }
            else
            {
                status = ERR_UM_JSON_PARSE_FAILED;
                goto exit;
            }
        }

        /* Read 'bin_dir' */
        if (NULL != pBinpath)
        {
            status = JSON_getObjectIndex (pJsonConfigCxt,
                                        (sbyte *)BINDIR_JSTR, 0, &index, FALSE);
            if (OK != status)
            {
                goto exit;
            }

            status = JSON_getToken (pJsonConfigCxt, index + 1, &token);
            if (OK != status)
            {
                goto exit;
            }

            if (JSON_String == token.type)
            {
                status = DIGI_CALLOC ((void**)pBinpath, 1, token.len + 1);
                if (OK != status)
                {
                    goto exit;
                }

                status = DIGI_MEMCPY (*pBinpath, token.pStart, token.len);
                if (OK != status)
                    goto exit;

                status = CRYPTO_UTILS_utilPathJSONtoStr(*pBinpath);
                if (OK != status)
                    goto exit;

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
                if (DIGI_STRNCMP(*pBinpath, MANDATORY_BASE_PATH, DIGI_STRLEN(MANDATORY_BASE_PATH)) != 0)
                {
                    status = ERR_FILE_INSECURE_PATH;
                    goto exit;
                }
#endif

            }
            else
            {
                status = ERR_UM_JSON_PARSE_FAILED;
                goto exit;
            }
        }

        /* Read 'http_proxy' */
        if (NULL != pProxyURL)
        {
            status = JSON_getObjectIndex (pJsonConfigCxt,
                                        (sbyte *)PROXY_SERVER_URL_JSTR, 0, &index, FALSE);
            if (OK != status)
            {
                /* optional field, OK if not found */
                status = OK;
                goto exit;
            }

            status = JSON_getToken (pJsonConfigCxt, index + 1, &token);
            if (OK != status)
            {
                goto exit;
            }

            if (JSON_String == token.type)
            {
                /* empty string gets treated as if there is no proxy server */
                if (token.len > 0)
                {
                    status = DIGI_CALLOC ((void**)pProxyURL, 1, token.len + 1);
                    if (OK != status)
                    {
                        goto exit;
                    }

                    status = DIGI_MEMCPY (*pProxyURL, token.pStart, token.len);
                    if (OK != status)
                        goto exit;
                }
            }
            else if (JSON_Null != token.type) /* null also gets treated as no proxy server */
            {
                status = ERR_UM_JSON_PARSE_FAILED;
                goto exit;
            }
        }

        /* Read 'root_dir' */
        if (NULL != pRootpath)
        {
            status = JSON_getObjectIndex (pJsonConfigCxt,
                                        (sbyte *)ROOTDIR_JSTR, 0, &index, FALSE);
            if (OK != status)
            {
                goto exit;
            }

            status = JSON_getToken (pJsonConfigCxt, index + 1, &token);
            if (OK != status)
            {
                goto exit;
            }

            if (JSON_String == token.type)
            {
                status = DIGI_CALLOC ((void**)pRootpath, 1, token.len + 1);
                if (OK != status)
                {
                    goto exit;
                }

                status = DIGI_MEMCPY (*pRootpath, token.pStart, token.len);
                if (OK != status)
                    goto exit;

                status = CRYPTO_UTILS_utilPathJSONtoStr(*pRootpath);
                if (OK != status)
                    goto exit;

#ifdef __ENABLE_DIGICERT_SECURE_PATH__
                if (DIGI_STRNCMP(*pRootpath, MANDATORY_BASE_PATH, DIGI_STRLEN(MANDATORY_BASE_PATH)) != 0)
                {
                    status = ERR_FILE_INSECURE_PATH;
                    goto exit;
                }
#endif

            }
            else
            {
                status = ERR_UM_JSON_PARSE_FAILED;
                goto exit;
            }
        }

    }

exit:
    DIGI_FREE((void **) &pConfPath);
    JSON_releaseContext (&pJsonConfigCxt);
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS CRYPTO_UTILS_readTrustedPathsInternal(
    sbyte **ppRetConfPath,
    sbyte **ppKeystorePath,
    sbyte **ppTrustStorePath,
    sbyte **ppBinPath,
    sbyte **ppProxyURL,
    sbyte **ppRootPath,
    intBoolean *pPathExists,
    byteBoolean performVerify
    )
{
    MSTATUS status;
    ubyte   *pData = NULL;
    ubyte4  dataLen;
    sbyte *pEnvPath = NULL;
    char *pPath = NULL;
#ifdef __RTOS_WIN32__
    ubyte *pProgramData = NULL;
    ubyte4 programDataLen;
#endif
    ubyte *pConfigFile = NULL;
#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
    char *pFinalPath = NULL;
    ubyte4 verify = 0;
#endif
#if !defined(__RTOS_ANDROID__) && !defined(__RTOS_ZEPHYR__) && (defined(__RTOS_LINUX__) || defined(__RTOS_WIN32__))
    ubyte4 len;
#endif

    if ( (NULL == ppRetConfPath) && (NULL == ppKeystorePath) &&
         (NULL == ppTrustStorePath) && (NULL == ppBinPath) &&
         (NULL == ppRootPath) && (NULL == pPathExists) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pPathExists)
    {
        *pPathExists = FALSE;
    }

    status = DIGI_CALLOC ((void**)&pPath, 1, 1024);
    if (OK != status)
        goto exit;

#ifdef __RTOS_WIN32__
    status = FMGMT_getEnvironmentVariableValueAlloc ("PROGRAMDATA", &pProgramData);
    if (OK != status)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    programDataLen = DIGI_STRLEN ((const sbyte *) pProgramData);
    len = DIGI_STRLEN(MOCANA_TRUSTED_CONFIG_FILE);

    status = DIGI_CALLOC(
        (void **) &pConfigFile, 1, programDataLen + len + 1);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY(
        pConfigFile, pProgramData, programDataLen);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY(
        pConfigFile + programDataLen, MOCANA_TRUSTED_CONFIG_FILE, len);
    if (OK != status)
    {
        goto exit;
    }
    pConfigFile[programDataLen + len] = '\0';
#else
    pConfigFile = (ubyte *)MOCANA_TRUSTED_CONFIG_FILE;
#endif

    if (TRUE == FMGMT_pathExists ((const sbyte *) pConfigFile, NULL))
    {
#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
        pFinalPath = (char *)pConfigFile;
#endif
        /* Read the data from the trusted config file */
        status = DIGICERT_readFile((const char*)pConfigFile, &pData, &dataLen);
        if (OK != status)
        {
            goto exit;
        }
    }
    else
    {
#if !defined(__RTOS_ANDROID__) && !defined(__RTOS_ZEPHYR__) && (defined(__RTOS_LINUX__) || defined(__RTOS_WIN32__))
        sbyte4 i;
        status = FMGMT_getProcessPath ((sbyte *) pPath, 1023, &len);
        if (OK != status)
            goto exit;

        for (i = len - 1; i >= 0; i--)
        {
#ifdef __RTOS_WIN32__
            if (pPath[i] == '\\')
#else
            if (pPath[i] == '/')
#endif
                break;
        }

        if (i < 0)
        {
            status = ERR_PATH_IS_INVALID;
            goto exit;
        }
        len = i + 1;

        if ( (len + TRUSTED_CONFIG_NAME_LEN) > 1023 )
        {
            status = ERR_BAD_LENGTH;
            goto exit;
        }

        status = DIGI_MEMCPY(
            pPath + len, TRUSTED_CONFIG_NAME, TRUSTED_CONFIG_NAME_LEN);
        if (OK != status)
        {
            goto exit;
        }
        pPath[len + TRUSTED_CONFIG_NAME_LEN] = '\0';

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
        pFinalPath = pPath;
#endif
        status = DIGICERT_readFile(
            (const char *) pPath, &pData, &dataLen);
        if (OK != status)
        {
#endif
            status = FMGMT_getEnvironmentVariableValueAlloc ( (sbyte *) "TRUSTPOINT_CONFIG_PATH", &pEnvPath);
            if (OK != status)
            {
                goto exit;
            }

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
            pFinalPath = (char *) pEnvPath;
#endif

            status = DIGICERT_readFile(
                (const char *) pEnvPath, &pData, &dataLen);
            if (OK != status)
            {
                goto exit;
            }
#if !defined(__RTOS_ANDROID__) && !defined(__RTOS_ZEPHYR__) && (defined(__RTOS_LINUX__) || defined(__RTOS_WIN32__))
        }
#endif
    }

    /* At this point we know the file exists */
    if (NULL != pPathExists)
    {
        *pPathExists = TRUE;
    }

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
    if (TRUE == performVerify)
    {
        ubyte4 verify = 0;

        /* Verify the config file */
        status = DIGICERT_verifyFile((const char *)pFinalPath, TRUE, &verify);
        if (OK != status)
        {
            goto exit;
        }

        if (0 != verify)
        {
            status = ERR_FP_INVALID_SIG_FILE;
            goto exit;
        }
    }
#endif

    /* Delegate JSON parsing to utils function */
    if ( (NULL != ppRetConfPath) || (NULL != ppKeystorePath) ||
         (NULL != ppTrustStorePath) || (NULL != ppBinPath) ||
         (NULL != ppRootPath) )
    {
        status = CRYPTO_UTILS_utilReadTrustedConfig(pData, dataLen,
                                        (sbyte **) ppRetConfPath,
                                        (sbyte **) ppKeystorePath,
                                        (sbyte **) ppTrustStorePath,
                                        (sbyte **) ppBinPath,
                                        (sbyte **) ppProxyURL,
                                        (sbyte **) ppRootPath);
        if (OK != status)
        {
            goto exit;
        }
    }

exit:
    if (NULL != pEnvPath)
        DIGI_FREE ((void **) &pEnvPath);

    DIGI_FREE ((void**)&pPath);
    DIGI_FREE ((void**)&pData);
#ifdef __RTOS_WIN32__
    if (NULL != pProgramData)
        DIGI_FREE ((void **) &pProgramData);
    DIGI_FREE((void **) &pConfigFile);
#endif
    return status;
}

/*------------------------------------------------------------------*/

extern char *CRYPTO_UTILS_getTrustedPath()
{
    return MOCANA_TRUSTED_CONFIG_FILE;
}

/*------------------------------------------------------------------*/

extern MSTATUS CRYPTO_UTILS_readTrustedConfig(
    TrustedConfig **ppConfig,
    byteBoolean verify)
{
    MSTATUS status;
    TrustedConfig *pConfig = NULL;

    if (NULL == ppConfig)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_CALLOC((void **) &pConfig, 1, sizeof(TrustedConfig));
    if (OK != status)
    {
        goto exit;
    }

    status = CRYPTO_UTILS_readTrustedPathsInternal(
        &(pConfig->pConfDir), &(pConfig->pKeystoreDir),
        &(pConfig->pTruststoreDir), &(pConfig->pBinDir), &(pConfig->pHttpProxy),
        &(pConfig->pRootDir), NULL, verify);
    if (OK != status)
    {
        goto exit;
    }

    *ppConfig = pConfig;
    pConfig = NULL;

exit:

    if (NULL != pConfig)
    {
        CRYPTO_UTILS_deleteTrustedConfig(&pConfig);
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS CRYPTO_UTILS_deleteTrustedConfig(
    TrustedConfig **ppConfig)
{
    MSTATUS status = OK;
    MSTATUS fstatus;

    if ( (NULL != ppConfig) && (NULL != *ppConfig) )
    {
        if (NULL != (*ppConfig)->pHttpProxy)
        {
            fstatus = DIGI_FREE((void **) &((*ppConfig)->pHttpProxy));
            if (OK == status)
                status = fstatus;
        }
        if (NULL != (*ppConfig)->pRootDir)
        {
            fstatus = DIGI_FREE((void **) &((*ppConfig)->pRootDir));
            if (OK == status)
                status = fstatus;
        }
        if (NULL != (*ppConfig)->pBinDir)
        {
            fstatus = DIGI_FREE((void **) &((*ppConfig)->pBinDir));
            if (OK == status)
                status = fstatus;
        }
        if (NULL != (*ppConfig)->pConfDir)
        {
            fstatus = DIGI_FREE((void **) &((*ppConfig)->pConfDir));
            if (OK == status)
                status = fstatus;
        }
        if (NULL != (*ppConfig)->pKeystoreDir)
        {
            fstatus = DIGI_FREE((void **) &((*ppConfig)->pKeystoreDir));
            if (OK == status)
                status = fstatus;
        }
        if (NULL != (*ppConfig)->pTruststoreDir)
        {
            fstatus = DIGI_FREE((void **) &((*ppConfig)->pTruststoreDir));
            if (OK == status)
                status = fstatus;
        }
        fstatus = DIGI_FREE((void **) ppConfig);
        if (OK == status)
            status = fstatus;
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS CRYPTO_UTILS_readTrustedPaths(
    sbyte **ppRetConfPath,
    sbyte **ppKeystorePath,
    sbyte **ppTrustStorePath,
    sbyte **ppBinPath
    )
{
    return CRYPTO_UTILS_readTrustedPathsInternal(
        ppRetConfPath, ppKeystorePath, ppTrustStorePath, ppBinPath, NULL, NULL,
        NULL, TRUE);
}

/*------------------------------------------------------------------*/

extern MSTATUS CRYPTO_UTILS_readTrustedPathsNoVerify(
    sbyte **ppRetConfPath,
    sbyte **ppKeystorePath,
    sbyte **ppTrustStorePath,
    sbyte **ppBinPath
    )
{
    return CRYPTO_UTILS_readTrustedPathsInternal(
        ppRetConfPath, ppKeystorePath, ppTrustStorePath, ppBinPath, NULL, NULL,
        NULL, FALSE);
}

/*------------------------------------------------------------------*/

extern MSTATUS CRYPTO_UTILS_readTrustedPathsWithProxyURL(
    sbyte **ppRetConfPath,
    sbyte **ppKeystorePath,
    sbyte **ppTrustStorePath,
    sbyte **ppBinPath,
    sbyte **ppProxyURL
    )
{
    return CRYPTO_UTILS_readTrustedPathsInternal(
        ppRetConfPath, ppKeystorePath, ppTrustStorePath, ppBinPath, ppProxyURL,
        NULL,  NULL, TRUE);
}

/*------------------------------------------------------------------*/

extern MSTATUS CRYPTO_UTILS_readTrustedPathsWithProxyURLNoVerify(
    sbyte **ppRetConfPath,
    sbyte **ppKeystorePath,
    sbyte **ppTrustStorePath,
    sbyte **ppBinPath,
    sbyte **ppProxyURL
    )
{
    return CRYPTO_UTILS_readTrustedPathsInternal(
        ppRetConfPath, ppKeystorePath, ppTrustStorePath, ppBinPath, ppProxyURL,
        NULL, NULL, FALSE);
}

/*------------------------------------------------------------------*/

extern intBoolean CRYPTO_UTILS_configFileExists()
{
    intBoolean exists = FALSE;
    (void) CRYPTO_UTILS_readTrustedPathsInternal(
        NULL, NULL, NULL, NULL, NULL, NULL, &exists, TRUE);
    return exists;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_UTILS_getCertificateSizeFromCRTBuffer(
    ubyte *pBuffer, ubyte4 bufferLen, ubyte4 *pCertLen)
{
    MSTATUS status;
    ubyte *pStart;
    sbyte4 cmp;

    if ( (NULL == pBuffer ) || (NULL == pCertLen) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pCertLen = 0;
    pStart = pBuffer;

    /* Find the first '-' character */
    for (; bufferLen > 0; bufferLen--, pBuffer++)
        if ('-' == *pBuffer)
            break;

    /* Reached end of buffer with no certificate */
    if (0 == bufferLen)
    {
        status = OK;
        goto exit;
    }

    if (bufferLen < MOC_PEM_CERT_HEADER_LEN)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* Status check not required */
    DIGI_MEMCMP(pBuffer, (ubyte *) MOC_PEM_CERT_HEADER, MOC_PEM_CERT_HEADER_LEN, &cmp);
    if (0 != cmp)
    {
        status = ERR_BASE64_BAD_INPUT;
        goto exit;
    }

    pBuffer += MOC_PEM_CERT_HEADER_LEN;
    bufferLen -= MOC_PEM_CERT_HEADER_LEN;

    /* Base 64 can't have '-' character, once we find the first one, this
     * should find the end of the certificate */
    for (; bufferLen > 0; bufferLen--, pBuffer++)
        if ('-' == *pBuffer)
            break;

    /* Didn't find end '-' throw error */
    if ('-' != *pBuffer)
    {
        status = ERR_BASE64_BAD_INPUT;
        goto exit;
    }

    if (bufferLen < MOC_PEM_CERT_FOOTER_LEN)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* Status check not required */
    DIGI_MEMCMP(pBuffer, (ubyte *) MOC_PEM_CERT_FOOTER, MOC_PEM_CERT_FOOTER_LEN, &cmp);
    if (0 != cmp)
    {
        status = ERR_BASE64_BAD_INPUT;
        goto exit;
    }

    pBuffer += MOC_PEM_CERT_FOOTER_LEN;

    *pCertLen = pBuffer - pStart;

    status = OK;

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS CRYPTO_UTILS_getCertificateCount(
    ubyte *pBuffer, ubyte4 bufferLen, ubyte4 *pCertCount)
{
    MSTATUS status;
    ubyte4 certLen;

    if ( (NULL == pBuffer) || (0 == bufferLen) || (NULL == pCertCount) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pCertCount = 0;

    while (OK == (status = CRYPTO_UTILS_getCertificateSizeFromCRTBuffer(pBuffer, bufferLen, &certLen)) &&
           0 != certLen)
    {
        (*pCertCount)++;

        pBuffer += certLen;
        bufferLen -= certLen;
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS CRYPTO_UTILS_validateCertificatesOrder(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    SizedBuffer *pCertificates, ubyte4 certCount)
{
    MSTATUS status;
    certDescriptor *pDesc = NULL;
    certChainPtr pChain = NULL;

    ubyte4 i;

    status = DIGI_CALLOC((void **) &pDesc, sizeof(certDescriptor), certCount);
    if (OK != status)
    {
        goto exit;
    }

    for (i = 0; i < certCount; i++)
    {
        (pDesc + i)->pCertificate = (pCertificates + i)->data;
        (pDesc + i)->certLength = (pCertificates + i)->length;
    }

    status = CERTCHAIN_createFromIKE(MOC_ASYM(hwAccelCtx) &pChain, pDesc, certCount);
    if (OK != status)
    {
        goto exit;
    }

exit:
    CERTCHAIN_delete(&pChain);
    DIGI_FREE((void **) &pDesc);
    return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_UTILS_freeCertificates(
    SizedBuffer **ppCerts, ubyte4 certCount)
{
    ubyte4 i;

    if (NULL != ppCerts && NULL != *ppCerts)
    {
        for (i = 0; i < certCount; i++)
        {

            DIGI_FREE((void **) &(((*ppCerts) + i)->data));
        }

        DIGI_FREE((void **) ppCerts);
    }

    return OK;
}

/*---------------------------------------------------------------------------*/

static MSTATUS CRYPTO_UTILS_testAnchor(
    MOC_ASYM(hwAccelDescr hwAccelCtx) const void *pArg, const ubyte *pAnchor,
    ubyte4 anchorLen)
{
    MSTATUS status;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pAnchorRoot = NULL;
    CryptoUtilsCertInfo *pTestArg = (CryptoUtilsCertInfo *) pArg;

    MF_attach(&mf, anchorLen, (ubyte *) pAnchor);
    CS_AttachMemFile(&cs, &mf);

    status = X509_parseCertificate(cs, &pAnchorRoot);
    if (OK != status)
    {
        goto exit;
    }

    status = X509_validateLink(
        MOC_ASYM(hwAccelCtx) ASN1_FIRST_CHILD(pTestArg->pCertificate),
        pTestArg->cs, ASN1_FIRST_CHILD(pAnchorRoot), cs, 1);
    if (OK > status)
    {
        status = ERR_FALSE;
    }

exit:

    if (NULL != pAnchorRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pAnchorRoot);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS CRYPTO_UTILS_retrieveIssuerCertificate(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pCert, ubyte4 certLen, certStorePtr pStore, ubyte **ppIssuer,
    ubyte4 *pIssuerLen)
{
    MSTATUS status;
    MemFile mf;
    CryptoUtilsCertInfo certInfo = { 0 };
    ASN1_ITEMPTR pIssuer;

    *ppIssuer = NULL;
    *pIssuerLen = 0;

    certInfo.pCert = pCert;
    certInfo.certLen = certLen;

    MF_attach(&mf, certInfo.certLen, certInfo.pCert);
    CS_AttachMemFile(&(certInfo.cs), &mf);

    status = X509_parseCertificate(certInfo.cs, &(certInfo.pCertificate));
    if (OK != status)
    {
        goto exit;
    }

    status = X509_getCertificateIssuerSerialNumber(
        ASN1_FIRST_CHILD(certInfo.pCertificate), &pIssuer, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = CERT_STORE_findTrustPointBySubject(
        MOC_ASYM(hwAccelCtx) pStore, certInfo.pCert + pIssuer->dataOffset,
        pIssuer->length, &certInfo, CRYPTO_UTILS_testAnchor,
        (const ubyte **) ppIssuer, pIssuerLen);
    if (OK != status)
    {
        goto exit;
    }

exit:

    if (NULL != certInfo.pCertificate)
    {
        TREE_DeleteTreeItem((TreeItem *) certInfo.pCertificate);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_UTILS_isRootCertificate(ubyte *pCert, ubyte4 certLen)
{
    MSTATUS status;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRoot = NULL;

    if ( (NULL == pCert) || (0 == certLen) )
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    MF_attach(&mf, certLen, pCert);
    CS_AttachMemFile(&cs, &mf);

    status = X509_parseCertificate(cs, &pRoot);
    if (OK != status)
    {
        goto exit;
    }

    status = X509_isRootCertificate(ASN1_FIRST_CHILD(pRoot), cs);

exit:

    TREE_DeleteTreeItem((TreeItem *) pRoot);

    return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_UTILS_getTrustedChain(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pCert, ubyte4 certLen, certStorePtr pStore,
    SizedBuffer **ppRetCerts, ubyte4 *pRetCertCount)
{
    MSTATUS status;
    ubyte *pIssuer = NULL;
    ubyte4 issuerLen = 0;
    SizedBuffer *pRetChain = NULL, *pTempChain = NULL;
    ubyte4 retChainCount = 0, tempChainCount = 0;

    if ( (NULL == pCert) || (0 == certLen) || (NULL == pStore) ||
         (NULL == ppRetCerts) || (NULL == pRetCertCount) )
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    *ppRetCerts = NULL;
    *pRetCertCount = 0;

    while (ERR_FALSE == CRYPTO_UTILS_isRootCertificate(pCert, certLen))
    {
        pIssuer = NULL;
        issuerLen = 0;

        status = CRYPTO_UTILS_retrieveIssuerCertificate(MOC_ASYM(hwAccelCtx)
            pCert, certLen, pStore, &pIssuer, &issuerLen);
        if (OK != status)
        {
            goto exit;
        }

        if (NULL == pIssuer)
        {
            break;
        }

        retChainCount = tempChainCount + 1;
        status = DIGI_MALLOC(
            (void **) &pRetChain, retChainCount * sizeof(SizedBuffer));
        if (OK != status)
        {
            goto exit;
        }

        DIGI_MEMCPY(pRetChain, pTempChain, tempChainCount * sizeof(SizedBuffer));

        status = DIGI_MALLOC_MEMCPY(
            (void **) &((pRetChain + tempChainCount)->data), issuerLen,
            pIssuer, issuerLen);
        if (OK != status)
        {
            goto exit;
        }
        (pRetChain + tempChainCount)->length = issuerLen;

        DIGI_FREE((void **) &pTempChain);
        pTempChain = pRetChain;
        tempChainCount = retChainCount;

        pCert = pIssuer;
        certLen = issuerLen;
    }

    if (OK == status)
    {
        *ppRetCerts = pRetChain;
        *pRetCertCount = retChainCount;
        pRetChain = NULL;
        pTempChain = NULL;
    }

exit:

    if (pTempChain != pRetChain)
    {
        DIGI_FREE((void **) &pTempChain);
    }
    CRYPTO_UTILS_freeCertificates(&pRetChain, retChainCount);

    return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_UTILS_readCertificates(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pCerts, ubyte4 certsLen, SizedBuffer **ppRetCerts, ubyte4 *pRetCount)
{
    MSTATUS status = ERR_INVALID_INPUT;
    ubyte4 certCount = 0, certLen = 0, i = 0, temp = 0;
    SizedBuffer *pCertsBuffer = NULL;

    if ( (NULL == pCerts) || (0 == certsLen) || (NULL == ppRetCerts) ||
         (NULL == pRetCount) )
    {
        goto exit;
    }

    *ppRetCerts = NULL;
    *pRetCount = 0;

    status = CRYPTO_UTILS_getCertificateCount(pCerts, certsLen, &certCount);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_CALLOC(
        (void **) &pCertsBuffer, certCount, sizeof(SizedBuffer));
    if (OK != status)
    {
        goto exit;
    }

    for (i = 0; i < certCount; i++)
    {
        status = CRYPTO_UTILS_getCertificateSizeFromCRTBuffer(
            pCerts, certsLen, &certLen);
        if (OK != status)
        {
            goto exit;
        }

        status = CA_MGMT_decodeCertificate(
            pCerts, certLen, &((pCertsBuffer + i)->data), &temp);
        if (OK != status)
        {
            goto exit;
        }
        if (temp > 0xFFFF)
        {
            status = ERR_BAD_LENGTH;
            goto exit;
        }
        (pCertsBuffer + i)->length = temp;

        pCerts += certLen;
        certsLen -= certLen;
    }

    status = CRYPTO_UTILS_validateCertificatesOrder(MOC_ASYM(hwAccelCtx) pCertsBuffer, certCount);
    if (OK != status)
    {
        goto exit;
    }

    *ppRetCerts = pCertsBuffer;
    *pRetCount = certCount;
    pCertsBuffer = NULL;

exit:

    CRYPTO_UTILS_freeCertificates(&pCertsBuffer, certCount);

    return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_UTILS_createPemChainFromDerChain(
    SizedBuffer *pDerChain, ubyte4 derChainCount, SizedBuffer **ppPemChain)
{
    MSTATUS status;
    SizedBuffer *pRetChain = NULL;
    ubyte4 i;

    if ( (NULL == pDerChain) || (0 == derChainCount) || (NULL == ppPemChain) )
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    status = DIGI_CALLOC(
        (void **) &pRetChain, derChainCount, sizeof(SizedBuffer));
    if (OK != status)
    {
        goto exit;
    }

    for (i = 0; i < derChainCount; i++)
    {
        status = BASE64_makePemMessageAlloc(
            MOC_PEM_TYPE_CERT, pDerChain[i].data, pDerChain[i].length,
            &((pRetChain + i)->data), &((pRetChain + i)->length));
        if (OK != status)
        {
            goto exit;
        }
    }

    *ppPemChain = pRetChain;
    pRetChain = NULL;

exit:

    CRYPTO_UTILS_freeCertificates(&pRetChain, derChainCount);

    return status;
}

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_ECC__

static MSTATUS CRYPTO_UTILS_getEcBitLengthById(
    ubyte4 curveId, ubyte4 *pBitLength)
{
    MSTATUS status;

    if (NULL == pBitLength)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (curveId)
    {
        case cid_EC_P192:
            *pBitLength = 192;
            break;
        case cid_EC_P224:
            *pBitLength = 224;
            break;
        case cid_EC_P256:
            *pBitLength = 256;
            break;
        case cid_EC_P384:
            *pBitLength = 384;
            break;
        case cid_EC_P521:
            *pBitLength = 521;
            break;
        default:
            status = ERR_EC_UNSUPPORTED_CURVE;
            goto exit;
    }

    status = OK;

exit:

    return status;
}

#endif

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_UTILS_getAsymmetricKeyAttributes(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    AsymmetricKey *pAsymKey,
    ubyte4 *pKeyType,
    ubyte4 *pBitLength,
    ubyte2 *pProvider,
    ubyte4 *pModuleId)
{
    MSTATUS status;
    ubyte4 length, curveId;
#ifdef __ENABLE_DIGICERT_TAP__
    TAP_Key *pTapKey = NULL;
#endif

    if ( (NULL == pAsymKey) || (NULL == pKeyType) ||
         (NULL == pBitLength) || (NULL == pProvider) || (NULL == pModuleId) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (pAsymKey->type)
    {
#ifndef __DISABLE_DIGICERT_RSA__
        case akt_rsa:
#ifdef __ENABLE_DIGICERT_TAP__
        case akt_tap_rsa:
#endif
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(
                MOC_RSA(hwAccelCtx) pAsymKey->key.pRSA, (sbyte4 *) &length);
#else
            status = RSA_getCipherTextLength(
                MOC_RSA(hwAccelCtx) pAsymKey->key.pRSA, (sbyte4 *) &length);
#endif
            if (OK != status)
            {
                goto exit;
            }
            length = length * 8;
            break;
#endif /* __DISABLE_DIGICERT_RSA__ */
#ifdef __ENABLE_DIGICERT_ECC__
        case akt_ecc:
#ifdef __ENABLE_DIGICERT_TAP__
        case akt_tap_ecc:
#endif
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(
                pAsymKey->key.pECC, &curveId);
#else
            status = EC_getCurveIdFromKey(
                pAsymKey->key.pECC, &curveId);
#endif
            if (OK != status)
            {
                goto exit;
            }
            status = CRYPTO_UTILS_getEcBitLengthById(curveId, &length);
            if (OK != status)
            {
                goto exit;
            }
            break;
#endif

#ifdef __ENABLE_DIGICERT_DSA__
        case akt_dsa:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_DSA_getCipherTextLength(
                MOC_DSA(hwAccelCtx) pAsymKey->key.pDSA, (sbyte4 *) &length);
#else
            status = DSA_getCipherTextLength(
                MOC_DSA(hwAccelCtx) pAsymKey->key.pDSA, (sbyte4 *) &length);
#endif
            if (OK != status)
            {
                goto exit;
            }
            length = length * 8;
            break;
#endif

#ifdef __ENABLE_DIGICERT_PQC__
        case akt_qs:
            status = CRYPTO_INTERFACE_QS_getPublicKeyLen(pAsymKey->pQsCtx, &length);
            if (OK != status)
                goto exit;

            length = length * 8;

            break;
#endif

        default:
            status = ERR_BAD_KEY_TYPE;
            goto exit;
    }

#ifdef __ENABLE_DIGICERT_TAP__
    if (0x010000 < (pAsymKey->type & 0xff0000))
    {
        status = CRYPTO_INTERFACE_getTapKey(pAsymKey, &pTapKey);
        if (OK != status)
        {
            goto exit;
        }

        *pProvider = (ubyte2) pTapKey->providerObjectData.objectInfo.providerType;
        *pModuleId = (ubyte4) pTapKey->providerObjectData.objectInfo.moduleId;
    }
    else
#endif
    {
        *pProvider = 0;
        *pModuleId = 0;
    }

    *pBitLength = length;
    *pKeyType = pAsymKey->type;

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_UTILS_getAsymmetricKeyInfo(
    MOC_ASYM(hwAccelDescr hwAccelCtx) ubyte *pKey, ubyte4 keyLen,
    ubyte *pPassword, ubyte4 passwordLen, ubyte4 *pKeyType, ubyte4 *pBitLength,
    ubyte2 *pProvider, ubyte4 *pModuleId)
{
    MSTATUS status;
    ubyte *pTemp = NULL;
    ubyte4 tempLen;
    AsymmetricKey asymKey = { 0 };

    if ( (NULL == pKey) || (0 == keyLen) || (NULL == pKeyType) ||
         (NULL == pBitLength) || (NULL == pProvider) || (NULL == pModuleId) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx) pKey, keyLen, NULL, &asymKey);
    if ( (OK != status) && (NULL != pPassword) )
    {
        /* Try to decrypt the key using a password. Need to check if the key is
         * in PEM or DER format first. If its in PEM the convert it to DER.
         */
        status = CA_MGMT_decodeCertificate(pKey, keyLen, &pTemp, &tempLen);
        if (OK == status)
        {
            pKey = pTemp;
            keyLen = tempLen;
        }

        /* Attempt to decrypt the key using the password
         */
        status = PKCS_getPKCS8KeyEx(
            MOC_HW(hwAccelCtx) pKey, keyLen, pPassword, passwordLen, &asymKey);
        if (OK != status)
        {
            goto exit;
        }
    }

    status = CRYPTO_UTILS_getAsymmetricKeyAttributes(
        MOC_ASYM(hwAccelCtx) &asymKey, pKeyType, pBitLength,
        pProvider, pModuleId);

exit:

    if (NULL != pTemp)
    {
        DIGI_MEMSET_FREE(&pTemp, tempLen);
    }

    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    return status;
}

/*---------------------------------------------------------------------------*/

/* Loads certificate file based on the following criteria
 *   - File must end in .pem or .der (case insensitive)
 *   - Certificate must not be expired
 *   - If data protection is enabled then the certificate must contain a valid
 *       signature file
 *
 * If the certificate is expired and an expired certificate store is provided
 * then the certificate will be loaded into that store.
 */
static MSTATUS CRYPTO_UTILS_validateAndLoadCertByFile(
    sbyte *pFile, certStorePtr pStore, certStorePtr pExpiredStore,
    byteBoolean verifySigFile)
{
    MSTATUS status;
    ubyte4 fileLen;
    ubyte *pCert = NULL, *pDecodedCert = NULL;
    ubyte4 certLen = 0, decodedCertLen = 0;
#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
    intBoolean fileExists;
    ubyte4 verify = 0;
#endif

    fileLen = DIGI_STRLEN(pFile);
    if (fileLen < 5)
    {
        status = OK;
        goto exit;
    }

    /* Check for the extension of the file. Must end in either .pem or .der
     * (case insensitive). */
    if ((0 != DIGI_STRNICMP(pFile + fileLen - 4, (sbyte *) PEM_EXT, 4)) &&
        (0 != DIGI_STRNICMP(pFile + fileLen - 4, (sbyte *) DER_EXT, 4)) &&
        (0 != DIGI_STRNICMP(pFile + fileLen - 4, (sbyte *) CRT_EXT, 4)))
    {
        status = OK;
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
    if (TRUE == verifySigFile)
    {
        /* Check if the signature file exists. If the file does not exist then
         * exit with OK status. If an error occured then return the error. */
        status = DIGICERT_checkFile(
            pFile, MOC_FP_SIG_SUFFIX, &fileExists);
        if ( (OK != status) || (FALSE == fileExists) )
        {
            goto exit;
        }

        /* Verify the signature file. */
        status = DIGICERT_verifyFile(pFile, TRUE, &verify);
        if (OK != status)
        {
            goto exit;
        }

        /* If the signature file is invalid then some tampering may have occured,
         * return an error. */
        if (0 != verify)
        {
            status = ERR_FP_INVALID_SIG_FILE;
            goto exit;
        }
    }
#endif

    status = DIGICERT_readFile((const char *) pFile, &pCert, &certLen);
    if (OK != status)
    {
        goto exit;
    }

    status = CA_MGMT_decodeCertificate(
        pCert, certLen, &pDecodedCert, &decodedCertLen);
    if (OK == status)
    {
        DIGI_FREE((void **) &pCert);
        pCert = pDecodedCert;
        certLen = decodedCertLen;
    }

    /* If the certificate date is valid then add it to the main store. If the
     * certificate date is invalid and the caller provided an expired store, add
     * it to the expired store. */
    status = CA_MGMT_verifyCertDate(pCert, certLen);
    if (OK == status)
    {
        status = CERT_STORE_addTrustPoint(pStore, pCert, certLen);
        if (OK != status)
        {
            goto exit;
        }
    }
    else if ( (ERR_CERT_EXPIRED == status) && (NULL != pExpiredStore) )
    {
        status = CERT_STORE_addTrustPoint(pExpiredStore, pCert, certLen);
        if (OK != status)
        {
            goto exit;
        }
    }

    status = OK;

exit:

    if (NULL != pCert)
    {
        DIGI_FREE((void **) &pCert);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_MINIMAL_CA__)

extern MSTATUS CRYPTO_UTILS_addTrustPointCertsByDir(
    certStorePtr pStore, certStorePtr pExpiredStore, sbyte *pDirPath,
    byteBoolean verifySigFile)
{
    MSTATUS status;
    certStoreIssuerPtr pIssuerStore = NULL;
    void *pCookie = NULL;
    ubyte4 index = 0;
    sbyte *pFile = NULL;

    if ( (NULL == pDirPath) || (NULL == pStore) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = CERT_STORE_createIssuerStore(pDirPath, &pIssuerStore);
    if (OK != status)
    {
        goto exit;
    }

    /* Loop through all the child certificates and only load in the valid
     * certificates found. */
    status = CERT_STORE_traverseChildCertsByFile(
        pIssuerStore, &pCookie, &index, &pFile);
    while ( (OK == status) && (NULL != pFile) )
    {
        /* This API will load the certificate if it meets all the criteria,
         * otherwise it will not load the certificate. If a certificate is
         * not loaded OK is still returned.
         */
        status = CRYPTO_UTILS_validateAndLoadCertByFile(
            pFile, pStore, pExpiredStore, verifySigFile);
        if (OK != status)
        {
            goto exit;
        }

        /* Get next child certificate */
        status = CERT_STORE_traverseChildCertsByFile(
            pIssuerStore, &pCookie, &index, &pFile);
    }

exit:

    if (NULL != pIssuerStore)
    {
        CERT_STORE_releaseIssuerStore(&pIssuerStore);
    }

    return status;
}

#else

extern MSTATUS CRYPTO_UTILS_addTrustPointCertsByDir(
    certStorePtr pStore, certStorePtr pExpiredStore, sbyte *pDirPath,
    byteBoolean verifySigFile)
{
    MSTATUS status;
    DirectoryDescriptor dir = NULL;
    DirectoryEntry ent;
    ubyte *pFullpath = NULL;
    ubyte4 dirPathLen;

    if ( (NULL == pDirPath) || (NULL == pStore) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Loop through all certificates in the directory and only load in the valid
     * certificates found. */
    dirPathLen = DIGI_STRLEN(pDirPath);
    status = FMGMT_getFirstFile(pDirPath, &dir, &ent);
    while ( (OK == status) && (FTNone != ent.type) )
    {
        if (FTFile == ent.type)
        {
            status = DIGI_MALLOC(
                (void **) &pFullpath, dirPathLen + 1 + ent.nameLength + 1);
            if (OK != status)
            {
                goto exit;
            }
            DIGI_MEMCPY(pFullpath, pDirPath, dirPathLen);
            pFullpath[dirPathLen] = CRYPTO_UTILS_DIR_SLASH;
            DIGI_MEMCPY(pFullpath + dirPathLen + 1, ent.pName, ent.nameLength);
            pFullpath[dirPathLen + 1 + ent.nameLength] = '\0';

            /* This API will load the certificate if it meets all the criteria,
             * otherwise it will not load the certificate. If a certificate is
             * not loaded OK is still returned.
             */
            status = CRYPTO_UTILS_validateAndLoadCertByFile(
                (sbyte *) pFullpath, pStore, pExpiredStore, verifySigFile);
            if (OK != status)
            {
                goto exit;
            }

            DIGI_FREE((void **) &pFullpath);
        }

        /* Get next entry in the directory */
        status = FMGMT_getNextFile(dir, &ent);
    }

exit:

    if (NULL != pFullpath)
    {
        DIGI_FREE((void **) &pFullpath);
    }

    if (NULL != dir)
    {
        FMGMT_closeDir (&dir);
    }

    return status;
}

#endif /* __ENABLE_DIGICERT_MINIMAL_CA__ */

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_TRUSTPOINT_LOCAL__
#define TP_UPGRADE_FILE     "upgrade.txt"

extern MSTATUS CRYPTO_UTILS_checkForUpgrade(
    sbyte *pConfPath, intBoolean *pUpgrading)
{
    MSTATUS status;
    ubyte4 len, confLen;
    ubyte *pPath = NULL;

    if ((NULL == pConfPath) || (NULL == pUpgrading))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pUpgrading = FALSE;

    confLen = DIGI_STRLEN(pConfPath);
    len = DIGI_STRLEN((const sbyte *) TP_UPGRADE_FILE);

    status = DIGI_MALLOC((void **) &pPath, confLen + 1 + len + 1);
    if (OK != status)
        goto exit;

    DIGI_MEMCPY(pPath, pConfPath, confLen);
    pPath[confLen] = '/';
    DIGI_MEMCPY(pPath + confLen + 1, (ubyte *) TP_UPGRADE_FILE, len);
    pPath[confLen + 1 + len] = '\0';

    *pUpgrading = FMGMT_pathExists((sbyte *) pPath, NULL);

exit:

    DIGI_FREE((void **) &pPath);

    return status;
}
#endif

/*---------------------------------------------------------------------------*/
