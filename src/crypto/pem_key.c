/*
 * pem_key.c
 *
 * Decrypt encrypted private PEM key.
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

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/debug_console.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../crypto/crypto.h"
#include "../common/base64.h"
#include "../crypto/sha1.h"
#include "../crypto/md5.h"
#include "../crypto/des.h"
#include "../crypto/three_des.h"
#include "../crypto/aes.h"

#if defined(__ENABLE_DIGICERT_HARNESS__)
#include "../harness/harness.h"
#endif

#define COMMENT1 "Proc-Type: 4,ENCRYPTED"
#define COMMENT2 "DEK-Info: "

/*------------------------------------------------------------------*/

enum cipherFunc
{
    TriDES_CBC = 0,
    AES128_CBC = 1,
    AES192_CBC = 2,
    AES256_CBC = 3
};

typedef struct CipherToken
{
    const ubyte*     pName;
    sbyte4           nameLen;
    enum cipherFunc  cipherType;
} CipherToken;

static CipherToken gCipherTokens[] =
{
    {(const ubyte*)"DES-EDE3-CBC", 12, TriDES_CBC},
    {(const ubyte*)"AES-128-CBC", 11, AES128_CBC},
    {(const ubyte*)"AES-192-CBC", 11, AES192_CBC},
    {(const ubyte*)"AES-256-CBC", 11, AES256_CBC}
};

#define NUM_CIPHER_TOKENS (sizeof(gCipherTokens)/sizeof(CipherToken))

static BulkHashAlgo MD5Suite =
    { (ubyte4)MD5_RESULT_SIZE, (ubyte4)MD5_BLOCK_SIZE, (BulkCtxAllocFunc)MD5Alloc_m, (BulkCtxFreeFunc)MD5Free_m,
    (BulkCtxInitFunc)MD5Init_m, (BulkCtxUpdateFunc)MD5Update_m, (BulkCtxFinalFunc)MD5Final_m, NULL, NULL, NULL, ht_md5 };

static BulkHashAlgo SHA1Suite =
    { SHA1_RESULT_SIZE, SHA1_BLOCK_SIZE, (BulkCtxAllocFunc)SHA1_allocDigest, (BulkCtxFreeFunc)SHA1_freeDigest,
    (BulkCtxInitFunc)SHA1_initDigest, (BulkCtxUpdateFunc)SHA1_updateDigest, (BulkCtxFinalFunc)SHA1_finalDigest, NULL, NULL, NULL, ht_sha1 };


/*------------------------------------------------------------------*/

static MSTATUS
fetchLine(ubyte *pSrc,  ubyte4 *pSrcIndex, ubyte4 srcLength,
          ubyte *pDest, ubyte4 *pDestIndex, ubyte **ppDekBuf, ubyte4 *pDekBufLen)
{
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
        sbyte4 result;

        DIGI_MEMCMP((ubyte *)pSrc, (ubyte *)COMMENT1, sizeof(COMMENT1)-1, &result);

        if (0 == result)
        {
            /* seek CR and LF */
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

            DIGI_MEMCMP((ubyte *)pSrc, (ubyte *)COMMENT2, sizeof(COMMENT2)-1, &result);

            if (0 == result && NULL != ppDekBuf)
            {
                *ppDekBuf = pSrc;
            }

            /* seek CR and LF */
            while ((*pSrcIndex < srcLength) && ((0x0d != *pSrc) && (0x0a != *pSrc)))
            {
                (*pSrcIndex)++;
                pSrc++;
            }

            if (NULL != ppDekBuf && NULL != *ppDekBuf && NULL != pDekBufLen)
            {
                if (pSrc > *ppDekBuf)
                    *pDekBufLen = (ubyte4)(pSrc - *ppDekBuf);
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
    }

    return status;

} /* fetchLine */


/*------------------------------------------------------------------*/

static MSTATUS
PEM_hexStrToBytes(ubyte *pData, ubyte4 dataLen, ubyte **ppRetBytes, ubyte4 *pRetBytesLen)
{
    ubyte*   pBuf;
    ubyte4   bufLen;
    ubyte4   i;
    ubyte    c;
    MSTATUS  status = OK;

    bufLen = (dataLen % 2) ? (dataLen >> 1) + 1 : (dataLen >> 1);

    if (NULL == (pBuf = (ubyte*) MALLOC(bufLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *ppRetBytes = pBuf;
    *pRetBytesLen = bufLen;

    for (i=0; i<dataLen; i++)
    {
        c = pData[i];

        if ('0' <= c && '9' >= c)
        {
            c = c - '0';
        }
        else if ('A' <= c && 'F' >= c)
        {
            c = c - 'A' + 10;
        }
        else if ('a' <= c && 'f' >= c)
        {
            c = c - 'a' + 10;
        }
        else
        {
            status = ERR_FALSE;
            goto exit;
        }

        if (0 == i && 1 == dataLen%2)
        {
            *pBuf++ = c & 0xf;
            continue;
        }

        if (0 == i%2)
        {
            *pBuf = (c & 0xf) << 4;
        }
        else
        {
            *pBuf++ |= (c & 0xf);
        }
    }

exit:
    if (NULL != pBuf && OK > status)
    {
        FREE(*ppRetBytes);
        *ppRetBytes = NULL;
        *pRetBytesLen = 0;
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
PEM_parseDEK(ubyte *pData, ubyte4 dataLen, sbyte4 *pCipher, ubyte **ppIv, ubyte4 *pIvLen)
{
    /* DEK format: "DEK-Info: <CIPHER_NAME>,<IV>" */
    sbyte4   result;
    ubyte4   i;
    MSTATUS  status = ERR_EOF;

   if ((NULL == pCipher) || (NULL == ppIv) || (NULL == pIvLen))
    {
        return ERR_NULL_POINTER;
    }

    /* skip header "DEK-Info: " */
    while ((0 < dataLen) && (0x20 != *pData))
    {
        dataLen--;
        pData++;
    }

    if (0 == dataLen)
        goto exit;

    /* skip space */
    dataLen--;
    pData++;

    for (i = 0; i < NUM_CIPHER_TOKENS; i++)
    {
        DIGI_MEMCMP(pData, gCipherTokens[i].pName, gCipherTokens[i].nameLen, &result);

        if (0 == result)
        {
            *pCipher = gCipherTokens[i].cipherType;

            /* add 1 to skip comma */
            pData   += (gCipherTokens[i].nameLen + 1);
            dataLen -= (gCipherTokens[i].nameLen + 1);

            status = PEM_hexStrToBytes(pData, dataLen, ppIv, pIvLen);

            break;
        }
    }

exit:

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
PEM_createKey(MOC_HASH(hwAccelDescr hwAccelCtx) ubyte *pSalt, ubyte4 saltLen,
                  ubyte4 iterationCount,
                  ubyte4 hashingFunction,
                  ubyte* pPassword, ubyte4 passwordLen,
                  ubyte4 dkLen,
                  ubyte* pRetDerivedKey)
{
    /*
     *KEY DERIVATION ALGORITHM (from EVP_BytesToKey())
     *
     *The key and IV is derived by concatenating D_1, D_2, etc until enough
     *data is available for the key and IV. D_i is defined as:
     *
     *        D_i = HASH^count(D_(i-1) || data || salt)
     *
     *where || denotes concatentaion, D_0 is empty, HASH is the digest algorithm
     *in use, HASH^1(data) is simply HASH(data), HASH^2(data) is HASH(HASH(data))
     *and so on.
     *
     *The initial bytes are used for the key and the subsequent bytes for the IV.
     */
    BulkHashAlgo*  hashFunc = NULL;
    BulkCtx        ctx = NULL;
    intBoolean     isKeyFilled;
    ubyte*         pDigest = NULL;
    ubyte4         digestLen = 0;
    ubyte4         numBytes;
    MSTATUS        status;
    MOC_UNUSED(iterationCount);

    if ((NULL == pSalt) || (NULL == pPassword) || (NULL == pRetDerivedKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (hashingFunction)
    {
        case(ht_sha1):
            hashFunc = &SHA1Suite;
            break;

        case(ht_md5):
            hashFunc = &MD5Suite;
            break;

        default:
            status = ERR_PKCS5_INVALID_HASH_FUNCTION;
            goto exit;
    }

    digestLen = hashFunc->digestSize;

    if (NULL == (pDigest = (ubyte*) MALLOC(digestLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = hashFunc->allocFunc(MOC_HASH(hwAccelCtx) &ctx)))
        goto exit;

    /* must set to true on first pass */
    isKeyFilled = 1;

    /* continue hash until key buffer is filled */
    while (0 < dkLen)
    {
        if (OK > (status = hashFunc->initFunc(MOC_HASH(hwAccelCtx) ctx)))
            goto exit;

        if (!isKeyFilled)
        {
            if (OK > (status = hashFunc->updateFunc(MOC_HASH(hwAccelCtx) ctx, pDigest, digestLen)))
                goto exit;
        }

        /* digest pPassword */
        if (OK > (status = hashFunc->updateFunc(MOC_HASH(hwAccelCtx) ctx, pPassword, passwordLen)))
            goto exit;

        /* digest pSalt */
        if (OK > (status = hashFunc->updateFunc(MOC_HASH(hwAccelCtx) ctx, pSalt, saltLen)))
            goto exit;

        if (OK > (status = hashFunc->finalFunc(MOC_HASH(hwAccelCtx) ctx, pDigest)))
            goto exit;

        numBytes = (dkLen >= digestLen) ? digestLen : dkLen;

        /* dup the results */
        if (OK > (status = DIGI_MEMCPY(pRetDerivedKey, pDigest, numBytes)))
            goto exit;

        pRetDerivedKey += numBytes;
        dkLen -= numBytes;

        if (1 == isKeyFilled)
        {
            isKeyFilled = 0;
        }
    }

    if (OK > (status = hashFunc->freeFunc(MOC_HASH(hwAccelCtx) &ctx)))
        goto exit;

exit:
    if (NULL != pDigest)
        FREE(pDigest);

    return status;

} /* PEM_createKey */


/*------------------------------------------------------------------*/

static MSTATUS
PEM_decrypt(MOC_SYM(hwAccelDescr hwAccelCtx) enum cipherFunc cipherType,
                ubyte* pPassword, ubyte4 passwordLen,
                ubyte* pIv, ubyte4 ivLen,
                ubyte* pData, ubyte4 dataLen,
                ubyte4* pRetDataLen)
{
    BulkEncryptionAlgo* cipherAlgo;
    BulkCtx             ctx = NULL;
    ubyte4              numPaddingBytes;
    sbyte4              blockSize;
    sbyte4              i;
    sbyte4              isEncrypt = 0;
    ubyte*              pKeyBuf = NULL;
    ubyte4              keyBufLen = 0;
    MSTATUS             status = OK;

    if ((NULL == pIv) || (NULL == pPassword) || (NULL == pData) || (NULL == pRetDataLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch(cipherType)
    {
#ifndef __DISABLE_3DES_CIPHERS__
        case TriDES_CBC:
            cipherAlgo = (BulkEncryptionAlgo *) &CRYPTO_TripleDESSuite;
            keyBufLen = 24;
            break;
#endif

#ifndef __DISABLE_AES_CIPHERS__
        case AES128_CBC:
            cipherAlgo = (BulkEncryptionAlgo *) &CRYPTO_AESSuite;
            keyBufLen = 16;
            break;

        case AES192_CBC:
            cipherAlgo = (BulkEncryptionAlgo *) &CRYPTO_AESSuite;
            keyBufLen = 24;
            break;

        case AES256_CBC:
            cipherAlgo = (BulkEncryptionAlgo *) &CRYPTO_AESSuite;
            keyBufLen = 32;
            break;
#endif

        default:
            goto exit;
    }

    if (NULL == (pKeyBuf = (ubyte*) MALLOC(keyBufLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    blockSize = cipherAlgo->blockSize;

    if ((8 > ivLen) || (blockSize != (sbyte4) ivLen))
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    if (OK > (status = PEM_createKey(MOC_HASH(hwAccelCtx) pIv, 8, 1, ht_md5,
                                        pPassword, passwordLen, keyBufLen, pKeyBuf)))
    {
        goto exit;
    }

    ctx = cipherAlgo->createFunc(MOC_SYM(hwAccelCtx) pKeyBuf, keyBufLen, isEncrypt);

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = cipherAlgo->cipherFunc(MOC_SYM(hwAccelCtx) ctx, pData, dataLen, isEncrypt, pIv)))
        goto exit;

    if (OK > (status = cipherAlgo->deleteFunc(MOC_SYM(hwAccelCtx) &ctx)))
        goto exit;

    /* checking padding, last byte of decrypted data is padding length */
    numPaddingBytes = (ubyte4)pData[dataLen-1];

    if (0 == numPaddingBytes || blockSize < (sbyte4) numPaddingBytes)
    {
        /* bad padding */
        status = ERR_CRYPTO_BAD_PAD;
        goto exit;
    }

    for (i = 0; (ubyte4)i < numPaddingBytes; i++)
    {
        if (pData[dataLen-i-1] != pData[dataLen-1])
        {
            /* bad padding */
            status = ERR_CRYPTO_BAD_PAD;
            goto exit;
        }
    }

    *pRetDataLen = dataLen - numPaddingBytes;

exit:
    if (NULL != pKeyBuf)
    {
        /* clear key */
        for (i=0; (ubyte4)i<keyBufLen; i++)
            pKeyBuf[i] = 0x67;

        FREE(pKeyBuf);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
PEM_getPrivateKey(ubyte* pKeyFile, ubyte4 fileSize,
                  ubyte* pPassword, ubyte4 passwordLen,
                  ubyte** ppDecodeFile, ubyte4 *pDecodedLength)
{
    hwAccelDescr  hwAccelCtx;
    ubyte*  pBase64Mesg = NULL;
    ubyte4  srcIndex    = 0;
    ubyte4  destIndex   = 0;
    ubyte*  pDek        = NULL;
    ubyte4  dekLen     = 0;
    ubyte*  pIv         = NULL;
    ubyte4  ivLen       = 0;
    sbyte4  cipherType  = -1;
    MSTATUS status;

    if (NULL == (pBase64Mesg = (ubyte*) MALLOC(fileSize)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    while (fileSize > srcIndex)
    {
        pDek = NULL;
        dekLen = 0;

        fetchLine(pKeyFile, &srcIndex, fileSize,
                  pBase64Mesg, &destIndex, &pDek, &dekLen);

        if ( (NULL != pDek) && (OK > (status = PEM_parseDEK(pDek, dekLen, &cipherType, &pIv, &ivLen))) )
            goto exit;
    }

    DEBUG_HEXDUMP(DEBUG_CRYPTO, pIv, ivLen);

    if (OK > (status = BASE64_decodeMessage((ubyte *)pBase64Mesg, destIndex, ppDecodeFile, pDecodedLength)))
        goto exit;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
       goto exit;

    status = PEM_decrypt( MOC_SYM(hwAccelCtx) (enum cipherFunc) cipherType, pPassword, passwordLen,
                             pIv, ivLen, *ppDecodeFile, *pDecodedLength,
                             pDecodedLength );

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

exit:
    if (NULL != pIv)
        FREE(pIv);

    if (NULL != pBase64Mesg)
        FREE(pBase64Mesg);

    return status;
}
