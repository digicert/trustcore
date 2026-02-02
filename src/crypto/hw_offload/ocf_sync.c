/*
 * ocf_sync.c
 *
 * OpenBSD Cryptographic Framework Adapter
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


/*------------------------------------------------------------------*/

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"

#if (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) && defined(__ENABLE_OCF_HARDWARE_ACCEL__))

#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/random.h"
#include "../../common/vlong.h"
#include "../../common/debug_console.h"
#include "../../crypto/crypto.h"
#include "../../crypto/md5.h"
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../crypto/rsa.h"
#include "../../crypto/des.h"
#include "../../crypto/three_des.h"
#include "../../crypto/rc4algo.h"
#include "../../crypto/aes.h"
#include "../../crypto/nil.h"
#include "../../crypto/hmac.h"
#include "../../crypto/dh.h"

#if ((defined(__ENABLE_DIGICERT_SSH_SERVER__)) || (defined(__ENABLE_DIGICERT_SSH_CLIENT__)) )
#include "../../crypto/dsa.h"
#endif

#if (defined(__LINUX_RTOS__))
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <linux/cryptodev.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#elif (defined(__OPENBSD_RTOS__))
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#endif


/*------------------------------------------------------------------*/

#ifndef ARC4_MAX_KEY_LEN
#define ARC4_MAX_KEY_LEN                256
#endif

#ifndef CRYPTO_MAX_DATA_LEN
#define CRYPTO_MAX_DATA_LEN             ((64*1024) - 1)
#endif

#ifndef COP_NONE
#define COP_NONE                        0
#endif


/*------------------------------------------------------------------*/

#define OCF_ERROR                       (-1)
#define OCF_RNG_RAND_BUF_SIZE           (2048)


/*------------------------------------------------------------------*/

#ifdef __DISABLE_DIGICERT_RNG__
typedef struct
{
    /* to speed up performance we will create more random bits than needed... */
    int             devRandomFd;
    ubyte           rngBuf[OCF_RNG_RAND_BUF_SIZE];
    ubyte4          rngBufIndex;
    ubyte4          numBytesSinceLastRng;

} ocfAsyncRngCtx;
#endif


/*------------------------------------------------------------------*/

typedef struct
{
    sbyte4              encrypt;                            /* Key used for encrypting or decrypting? */
    ubyte               keyMaterial[ARC4_MAX_KEY_LEN + 16]; /* raw key in this case */
    struct session_op   cipherSession;                      /* contains key material, etc */

} ocfCipherContext;


/*------------------------------------------------------------------*/

extern MSTATUS
OCF_SYNC_init(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
OCF_SYNC_uninit(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
OCF_SYNC_openChannel(enum moduleNames moduleId, hwAccelDescr *pHwAccelCtx)
{
    ocfAccelDescr*      pOcfCtx     = NULL;
    int                 devCryptoFd = OCF_ERROR;
    int                 workerFd    = OCF_ERROR;
    MSTATUS             status      = ERR_HARDWARE_ACCEL_OPEN_SESSION;

    DEBUG_ERROR(DEBUG_CRYPTO, "OCF_openChannel: Mocana module = ", (sbyte4)moduleId);

    if (NULL == pHwAccelCtx)
        goto exit;

    if (OK != DIGI_MALLOC((void **)&pOcfCtx, sizeof(ocfAccelDescr)))
        goto exit;

    if (0 > (devCryptoFd = open("/dev/crypto", O_RDWR, 0)))
        goto exit;

#if 0
    {
        unsigned int capabilities = 0x87654321;

        ioctl(devCryptoFd, CIOCASYMFEAT, &capabilities);

        printf("OCF_SYNC_openChannel: capabilities = 0x%08x\n", capabilities);
    }
#endif

    /* prevent children from inheriting security file descriptors */
    if (OCF_ERROR == fcntl(devCryptoFd, F_SETFD, 1))
    {
        close(devCryptoFd);
        goto exit;
    }

    if (OCF_ERROR == ioctl(devCryptoFd, CRIOGET, &workerFd))
    {
        close(devCryptoFd);
        workerFd = devCryptoFd = OCF_ERROR;
        goto exit;
    }

    /* prevent children from inheriting security file descriptors */
    if (OCF_ERROR == fcntl(workerFd, F_SETFD, 1))
        goto exit;

    /* for return */
    pOcfCtx->devCryptoFd = devCryptoFd;
    pOcfCtx->workerFd = workerFd;
    *pHwAccelCtx = pOcfCtx;

    pOcfCtx = NULL;
    devCryptoFd= OCF_ERROR;
    workerFd = OCF_ERROR;
    status = OK;

exit:
    if (OCF_ERROR != workerFd)
        close(workerFd);

    if (OCF_ERROR != devCryptoFd)
        close(devCryptoFd);

    if (pOcfCtx)
        DIGI_FREE((void **)&pOcfCtx);

    return status;

} /* OCF_openChannel */


/*------------------------------------------------------------------*/

extern MSTATUS
OCF_SYNC_closeChannel(enum moduleNames moduleId, hwAccelDescr *pHwAccelCtx)
{
    MSTATUS status = ERR_HARDWARE_ACCEL_CLOSE_SESSION;

    DEBUG_ERROR(DEBUG_CRYPTO, "OCF_closeChannel: Mocana module = ", (sbyte4)moduleId);

    if ((NULL != pHwAccelCtx) && (NULL != *pHwAccelCtx))
    {
        if (OCF_ERROR != (*pHwAccelCtx)->workerFd)
        {
            close((*pHwAccelCtx)->workerFd);
            (*pHwAccelCtx)->workerFd = OCF_ERROR;
        }

        if (OCF_ERROR != (*pHwAccelCtx)->devCryptoFd)
        {
            close((*pHwAccelCtx)->devCryptoFd);
            (*pHwAccelCtx)->devCryptoFd = OCF_ERROR;
        }

        DIGI_FREE((void **)pHwAccelCtx);
    }

    return status;
}


/*------------------------------------------------------------------*/

static ocfCipherContext *
OCF_SYNC_createCipherCtx(hwAccelDescr hwAccelCtx, u_int32_t cipher,
                         ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    ocfCipherContext*   pOcfCipherCtx = NULL;

    if (OK != DIGI_MALLOC((void **)(&pOcfCipherCtx), sizeof(ocfCipherContext)))
    {
        DEBUG_PRINTNL(DEBUG_TEST, "OCF_SYNC_createCipherCtx: DIGI_MALLOC() failed");
        goto exit;
    }

    DIGI_MEMSET((ubyte *)&(pOcfCipherCtx->cipherSession), 0x00, sizeof(struct session_op));
    DIGI_MEMCPY(pOcfCipherCtx->keyMaterial, keyMaterial, keyLength);

    pOcfCipherCtx->cipherSession.key    = (caddr_t)pOcfCipherCtx->keyMaterial;
    pOcfCipherCtx->cipherSession.keylen = (u_int32_t)keyLength;
    pOcfCipherCtx->cipherSession.cipher = cipher;
    pOcfCipherCtx->encrypt              = encrypt;

    /* open a crypto session */
    if (OCF_ERROR == ioctl(hwAccelCtx->workerFd, CIOCGSESSION, &(pOcfCipherCtx->cipherSession)))
        DIGI_FREE((void **)(&pOcfCipherCtx));

exit:
    return pOcfCipherCtx;
}


/*------------------------------------------------------------------*/

static MSTATUS
OCF_SYNC_deleteCipherCtx(hwAccelDescr hwAccelCtx, ocfCipherContext **ppOcfCtx)
{
    MSTATUS status;

    if (OK > (status = DIGI_FREE((void **)(ppOcfCtx))))
    {
        DEBUG_PRINTNL(DEBUG_TEST, "OCF_SYNC_deleteCipherCtx: DIGI_FREE() failed");
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
OCF_SYNC_doCipherCommon(hwAccelDescr hwAccelCtx, ocfCipherContext* pOcfCipherCtx,
                       ubyte* data, sbyte4 dataLength, sbyte4 encrypt,
                       ubyte* iv, ubyte4 ivLength)
{
    struct crypt_op     cryptoJob;
    ubyte               ivBackup[EALG_MAX_BLOCK_LEN];
    ubyte*              pIv;
    MSTATUS             status = OK;

    DIGI_MEMSET((ubyte *)(&cryptoJob), 0x00, sizeof(struct crypt_op));

    cryptoJob.ses   = pOcfCipherCtx->cipherSession.ses;
    cryptoJob.op    = encrypt ? COP_ENCRYPT : COP_DECRYPT;
    cryptoJob.flags = 0;
    cryptoJob.len   = dataLength;
    cryptoJob.src   = (caddr_t)data;
    cryptoJob.dst   = (caddr_t)data;
    cryptoJob.mac   = 0;
    cryptoJob.iv    = iv;

    if ((0 >= dataLength) || (CRYPTO_MAX_DATA_LEN < dataLength))
    {
        status = ERR_HARDWARE_ACCEL_BAD_LENGTH;
        goto exit;
    }

    if ((ivLength) && (!encrypt))
    {
        /* backup iv before decrypting */
        pIv = data + (dataLength - ivLength);
        DIGI_MEMCPY(ivBackup, pIv, ivLength);
    }

    /* do the crypto operation */
    if (OCF_ERROR == ioctl(hwAccelCtx->workerFd, CIOCCRYPT, &cryptoJob))
    {
        status = ERR_HARDWARE_ACCEL_DO_CRYPTO;
        goto exit;
    }

    /* copy the iv back */
    if (ivLength)
    {
        if (encrypt)
            pIv = data + (dataLength - ivLength);
        else
            pIv = ivBackup;

        DIGI_MEMCPY(iv, pIv, ivLength);
    }

exit:
    return status;

} /* OCF_SYNC_doCipherCommon */


/*------------------------------------------------------------------*/

#ifndef __DISABLE_AES_CIPHERS__

extern BulkCtx
CreateAESCtx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    if ((NULL == hwAccelCtx) || (NULL == keyMaterial) || (!((32 == keyLength) || (24 == keyLength) || (16 == keyLength))))
        return NULL;

    return OCF_SYNC_createCipherCtx(hwAccelCtx, CRYPTO_AES_CBC, keyMaterial, keyLength, encrypt);

} /* CreateAESCtx */


/*------------------------------------------------------------------*/

extern MSTATUS
DeleteAESCtx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    return OCF_SYNC_deleteCipherCtx(hwAccelCtx, (ocfCipherContext **)ctx);

} /* DeleteAESCtx */


/*------------------------------------------------------------------*/

extern MSTATUS
DoAES(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MSTATUS status;

    if ((NULL == hwAccelCtx) || (NULL == ctx))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OCF_ERROR == hwAccelCtx->workerFd)
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    if (0 != (dataLength % AES_BLOCK_SIZE))
    {
        status = ERR_AES_BAD_LENGTH;
        goto exit;
    }

    status = OCF_SYNC_doCipherCommon(hwAccelCtx, (ocfCipherContext *)ctx, data, dataLength, encrypt, iv, AES_BLOCK_SIZE);

#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, "DoAES: cipher failed, error = ", status);
#endif

exit:
    return status;

} /* DoAES */

#endif /* __DISABLE_AES_CIPHERS__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DES_CIPHER__

extern BulkCtx
CreateDESCtx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    if ((NULL == hwAccelCtx) || (NULL == keyMaterial) || (8 != keyLength))
        return NULL;

    return OCF_SYNC_createCipherCtx(hwAccelCtx, CRYPTO_DES_CBC, keyMaterial, keyLength, encrypt);


} /* CreateDESCtx */


/*------------------------------------------------------------------*/

extern MSTATUS
DeleteDESCtx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    return OCF_SYNC_deleteCipherCtx(hwAccelCtx, (ocfCipherContext **)ctx);

} /* DeleteDESCtx */


/*------------------------------------------------------------------*/

extern MSTATUS
DoDES(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MSTATUS status;

    if ((NULL == hwAccelCtx) || (NULL == ctx))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OCF_ERROR == hwAccelCtx->workerFd)
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    if (0 != (dataLength % DES_BLOCK_SIZE))
    {
        status = ERR_DES_BAD_LENGTH;
        goto exit;
    }

    status = OCF_SYNC_doCipherCommon(hwAccelCtx, (ocfCipherContext *)ctx, data, dataLength, encrypt, iv, DES_BLOCK_SIZE);

#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, "DoDES: cipher failed, error = ", status);
#endif

exit:
    return status;

} /* DoDES */

#endif /* __ENABLE_DES_CIPHER__ */


/*------------------------------------------------------------------*/

#ifndef __DISABLE_3DES_CIPHERS__

extern BulkCtx
Create3DESCtx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    if ((NULL == hwAccelCtx) || (NULL == keyMaterial) || (24 != keyLength))
        return NULL;

    return OCF_SYNC_createCipherCtx(hwAccelCtx, CRYPTO_3DES_CBC, keyMaterial, keyLength, encrypt);

} /* Create3DESCtx */


/*------------------------------------------------------------------*/

extern MSTATUS
Delete3DESCtx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    return OCF_SYNC_deleteCipherCtx(hwAccelCtx, (ocfCipherContext **)ctx);

} /* Delete3DESCtx */


/*------------------------------------------------------------------*/

extern MSTATUS
Do3DES(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MSTATUS status;

    if ((NULL == hwAccelCtx) || (NULL == ctx))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OCF_ERROR == hwAccelCtx->workerFd)
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    if (0 != (dataLength % THREE_DES_BLOCK_SIZE))
    {
        status = ERR_3DES_BAD_LENGTH;
        goto exit;
    }

    status = OCF_SYNC_doCipherCommon(hwAccelCtx, (ocfCipherContext *)ctx, data, dataLength, encrypt, iv, THREE_DES_BLOCK_SIZE);

#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, "Do3DES: cipher failed, error = ", status);
#endif

exit:
    return status;

} /* Do3DES */

#endif /* __DISABLE_3DES_CIPHERS__ */


/*------------------------------------------------------------------*/

#ifndef __DISABLE_ARC4_CIPHERS__

extern BulkCtx
CreateRC4Ctx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    if ((NULL == hwAccelCtx) || (NULL == keyMaterial))
        return NULL;

    return OCF_SYNC_createCipherCtx(hwAccelCtx, CRYPTO_ARC4, keyMaterial, keyLength, encrypt);

} /* CreateRC4Ctx */


/*------------------------------------------------------------------*/

extern MSTATUS
DeleteRC4Ctx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    return OCF_SYNC_deleteCipherCtx(hwAccelCtx, (ocfCipherContext **)ctx);

} /* DeleteRC4Ctx */


/*------------------------------------------------------------------*/

extern MSTATUS
DoRC4(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MSTATUS status;

    if ((NULL == hwAccelCtx) || (NULL == ctx))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OCF_ERROR == hwAccelCtx->workerFd)
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    status = OCF_SYNC_doCipherCommon(hwAccelCtx, (ocfCipherContext *)ctx, data, dataLength, encrypt, NULL, 1);

#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, "DoRC4: cipher failed, error = ", status);
#endif

exit:
    return status;

} /* DoRC4 */
#endif /* __DISABLE_ARC4_CIPHERS__ */


/*------------------------------------------------------------------*/

#ifdef __DISABLE_DIGICERT_RNG__
static MSTATUS
OCF_SYNC_readRandomBytes(int workerFd, ubyte *pBuf, size_t numBytesToRead)
{
    size_t  totalBytesRead = 0;
    ssize_t bytesRead;
    MSTATUS status = OK;

    while (totalBytesRead < numBytesToRead)
    {
        if (0 > (bytesRead = read(workerFd, (void *)(pBuf + totalBytesRead), numBytesToRead - totalBytesRead)))
        {
            status = ERR_HARDWARE_ACCEL_DO_RNG;
            break;
        }

        totalBytesRead += bytesRead;
    }

    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __DISABLE_DIGICERT_RNG__
extern MSTATUS
RANDOM_acquireContext(randomContext **pp_randomContext)
{
    int             devRandomFd;
    ocfAsyncRngCtx* pRngCtx = NULL;
    MSTATUS         status = ERR_HARDWARE_ACCEL_OPEN_SESSION;

    if (0 > (devRandomFd = open("/dev/random", O_RDONLY, 0)))
        goto exit;

    if (OK != (status = DIGI_MALLOC((void **)(&pRngCtx), sizeof(ocfAsyncRngCtx))))
    {
        pRngCtx->rngBufIndex          = OCF_RNG_RAND_BUF_SIZE;
        pRngCtx->numBytesSinceLastRng = 0;
        pRngCtx->devRandomFd          = devRandomFd;

        if (OK > (status = OCF_SYNC_readRandomBytes(pRngCtx->devRandomFd, pRngCtx->rngBuf, OCF_RNG_RAND_BUF_SIZE)))
            goto exit;
    }
    else
    {
        close(devRandomFd);
    }

    *pp_randomContext = (randomContext *)pRngCtx;

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __DISABLE_DIGICERT_RNG__
extern MSTATUS
RANDOM_releaseContext(randomContext **pp_randomContext)
{
    return DIGI_FREE((void **)pp_randomContext);
}
#endif


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_ADD_ENTROPY__
extern MSTATUS
RANDOM_addEntropyBit(randomContext *pRandomContext, ubyte entropyBit)
{
    /* do nothing */
    return OK;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __DISABLE_DIGICERT_RNG__
extern MSTATUS
RANDOM_numberGenerator(randomContext *pRandomContext, ubyte *pBuffer, sbyte4 bufSize)
{
    ocfAsyncRngCtx*     pRngCtx = (ocfAsyncRngCtx *)(pRandomContext);
    ubyte4              tmpBufIndex;
    sbyte4              numBytesToCopy;
    MSTATUS             status = OK;

    while (0 < bufSize)
    {
        tmpBufIndex = pRngCtx->rngBufIndex;

        /* set aside our bytes */
        numBytesToCopy = OCF_RNG_RAND_BUF_SIZE - pRngCtx->rngBufIndex;

        if (numBytesToCopy > bufSize)
            numBytesToCopy = bufSize;

        if (0 == numBytesToCopy)
        {
            pRngCtx->rngBufIndex = 0;
            continue;
        }

        /* update counters and indices */
        pRngCtx->numBytesSinceLastRng += numBytesToCopy;
        pRngCtx->rngBufIndex += numBytesToCopy;

        /* pull bytes out of buffered rng data */
        if (pRngCtx->numBytesSinceLastRng >= (OCF_RNG_RAND_BUF_SIZE / 2))
        {
            /* capture bytes */
            status = OCF_SYNC_readRandomBytes(pRngCtx->devRandomFd, pRngCtx->rngBuf, OCF_RNG_RAND_BUF_SIZE);

            if (OK > status)
                break;
        }

        DIGI_MEMCPY(pBuffer, &pRngCtx->rngBuf[tmpBufIndex], numBytesToCopy);
        bufSize = bufSize - numBytesToCopy;
        pBuffer = pBuffer + numBytesToCopy;
    }

    return status;
} /* RANDOM_numberGenerator */
#endif


/*------------------------------------------------------------------*/

extern sbyte4
RANDOM_rngFun(void *rngFunArg, ubyte4 length, ubyte *buffer)
{
    return (sbyte4)RANDOM_numberGenerator((randomContext *)rngFunArg, buffer, (sbyte4)length);
}


/*------------------------------------------------------------------*/

#if (defined(__MD5_ONE_STEP_HARDWARE_HASH__) || defined(__SHA1_ONE_STEP_HARDWARE_HASH__))
static MSTATUS
OCF_SYNC_doHashCommon(hwAccelDescr hwAccelCtx,
                      u_int32_t hashAlgo,
                      ubyte* pData, sbyte4 dataLength,
                      ubyte* pKey, sbyte4 keyLength,
                      ubyte* pResult)
{
    struct session_op   hashSession;
    struct crypt_op     cryptoJob;
    MSTATUS             status = OK;

    if ((0 > dataLength) || (CRYPTO_MAX_DATA_LEN < dataLength))
    {
        status = ERR_HARDWARE_ACCEL_BAD_LENGTH;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)(&hashSession), 0x00, sizeof(struct session_op));

    hashSession.key    = (caddr_t)pKey;
    hashSession.keylen = (u_int32_t)keyLength;
    hashSession.mac    = hashAlgo;

    /* open a crypto session */
    if (OCF_ERROR == ioctl(hwAccelCtx->workerFd, CIOCGSESSION, &hashSession))
    {
        status = ERR_HARDWARE_ACCEL_DO_HASH;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)(&cryptoJob), 0x00, sizeof(struct crypt_op));

    cryptoJob.ses   = hashSession.ses;
    cryptoJob.op    = COP_NONE;
    cryptoJob.flags = 0;
    cryptoJob.len   = dataLength;
    cryptoJob.src   = (caddr_t)pData;
    cryptoJob.dst   = NULL;
    cryptoJob.mac   = pResult;
    cryptoJob.iv    = NULL;

    /* do the crypto operation */
    if (OCF_ERROR == ioctl(hwAccelCtx->workerFd, CIOCCRYPT, &cryptoJob))
    {
        status = ERR_HARDWARE_ACCEL_DO_CRYPTO;
        goto exit;
    }

exit:
    return status;

} /* OCF_SYNC_doHashCommon */
#endif


/*------------------------------------------------------------------*/

#if (defined(__MD5_ONE_STEP_HARDWARE_HASH__))
extern MSTATUS
MD5_completeDigest(hwAccelDescr hwAccelCtx, ubyte *pData, ubyte4 dataLen, ubyte *pMdOutput)
{
    return OCF_SYNC_doHashCommon(hwAccelCtx, CRYPTO_MD5, pData, dataLen, NULL, 0, pMdOutput);
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__SHA1_ONE_STEP_HARDWARE_HASH__))
extern MSTATUS
SHA1_completeDigest(hwAccelDescr hwAccelCtx, ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput)
{
    return OCF_SYNC_doHashCommon(hwAccelCtx, CRYPTO_SHA1, pData, dataLen, NULL, 0, pShaOutput);
}
#endif


/*------------------------------------------------------------------*/

static MSTATUS
OCF_SYNC_convertVlongToOcfInt(const vlong *pValue, caddr_t *ppRetOcfInt, u_int *pRetOcfIntLength, u_int minBytesToUse)
{
    ubyte*  pRetValue = NULL;
    sbyte4  numBytesRequired = 0;
    MSTATUS status;

    if (OK > (status = VLONG_byteStringFromVlong(pValue, NULL, &numBytesRequired)))
        goto exit;

    /* for return value, we may need to pad the buffer */
    if (numBytesRequired < minBytesToUse)
        numBytesRequired = minBytesToUse;

    if (OK != (status = DIGI_MALLOC((void **)&pRetValue, numBytesRequired)))
        goto exit;

    if (OK > (status = VLONG_byteStringFromVlong(pValue, pRetValue, &numBytesRequired)))
        goto exit;

    *pRetOcfIntLength = numBytesRequired;
    *ppRetOcfInt = pRetValue;
    pRetValue = NULL;

exit:
    if (pRetValue)
        DIGI_FREE((void **)(&pRetValue));

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
OCF_SYNC_freeOcfInt(caddr_t *ppRetOcfInt)
{
    return DIGI_FREE((void **)ppRetOcfInt);
}


/*------------------------------------------------------------------*/

static MSTATUS
OCF_SYNC_convertOcfIntToVlong(caddr_t pOcfInt, u_int ocfIntLength, vlong **ppRetVlong, vlong **ppVlongQueue)
{
    return VLONG_vlongFromByteString(pOcfInt, (sbyte4)ocfIntLength, ppRetVlong, ppVlongQueue);
}


/*------------------------------------------------------------------*/

#if (defined(__VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__))
extern MSTATUS
VLONG_modexp(hwAccelDescr hwAccelCtx,
             const vlong *x, const vlong *e, const vlong *m, vlong **ppRetModExp,
             vlong **ppVlongQueue)
{
    /* modexp = (x^e) mod m */
    struct crypt_kop    kop;
    caddr_t             pRetModExp = NULL;
    caddr_t             pX = NULL;
    caddr_t             pE = NULL;
    caddr_t             pM = NULL;
    u_int               xLen = 0;
    u_int               eLen = 0;
    u_int               mLen = 0;
    MSTATUS             status;

    /* convert digicert vlong to ocf integer */
    if (OK > (status = OCF_SYNC_convertVlongToOcfInt(x, &pX, &xLen, mLen)))
        goto exit;

    if (OK > (status = OCF_SYNC_convertVlongToOcfInt(e, &pE, &eLen, 0)))
        goto exit;

    if (OK > (status = OCF_SYNC_convertVlongToOcfInt(m, &pM, &mLen, 0)))
        goto exit;

    /* space for the answer */
    if (OK != (status = DIGI_MALLOC((void **)&pRetModExp, mLen)))
        goto exit;

    /* init kop (key operation) struct */
    DIGI_MEMSET((ubyte *)&kop, 0x00, sizeof(struct crypt_kop));

    kop.crk_op = CRK_MOD_EXP;
    kop.crk_param[0].crp_p = pX;
    kop.crk_param[1].crp_p = pE;
    kop.crk_param[2].crp_p = pM;
    kop.crk_param[3].crp_p = pRetModExp;        /* for result */
    kop.crk_param[0].crp_nbits = xLen * 8;      /* convert to bits */
    kop.crk_param[1].crp_nbits = eLen * 8;
    kop.crk_param[2].crp_nbits = mLen * 8;
    kop.crk_param[3].crp_nbits = mLen * 8;      /* for result */
    kop.crk_iparams = 3;
    kop.crk_oparams = 1;

    /* do modexp calculation */
    if (OCF_ERROR == ioctl(hwAccelCtx->workerFd, CIOCKEY, &kop))
    {
        status = ERR_HARDWARE_ACCEL_DO_ASYM;
        goto exit;
    }

    /* convert answer back to digicert vlong */
    status = OCF_SYNC_convertOcfIntToVlong(pRetModExp,
                                           ((kop.crk_param[kop.crk_iparams].crp_nbits + 7) / 8),
                                           ppRetModExp, ppVlongQueue);

exit:
    if (pRetModExp)
        DIGI_FREE((void **)(&pRetModExp));

    OCF_SYNC_freeOcfInt(&pM);
    OCF_SYNC_freeOcfInt(&pE);
    OCF_SYNC_freeOcfInt(&pX);

    return status;

} /* VLONG_modexp */
#endif

#endif /* (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_OCF_HARDWARE_ACCEL__)) */

