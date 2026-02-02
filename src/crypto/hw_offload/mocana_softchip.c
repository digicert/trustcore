/*
 * mocana_accel_async.c
 *
 * Mocana Soft Chip Acceleration Asynchronous Adapter
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

#if (defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) && defined(__ENABLE_DIGICERT_TESTBED_HARDWARE_ACCEL__))

#include "../../common/mdefs.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mtcp.h"
#include "../../common/mstdlib.h"
#include "../../common/random.h"
#include "../../common/vlong.h"
#include "../../common/debug_console.h"
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

#if ((defined(__ENABLE_DIGICERT_SSL_SERVER__)) || (defined(__ENABLE_DIGICERT_SSL_CLIENT__)) )
#include "../../crypto/ca_mgmt.h"
#endif

#define IPAD                    0x36
#define OPAD                    0x5c


/*------------------------------------------------------------------*/

typedef struct
{
    ubyte key_state[260];
    int   key_state_flag;

} ctx_arc4_struct;


/*------------------------------------------------------------------*/

extern MSTATUS
DIGI_SOFTCHIP_init(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DIGI_SOFTCHIP_uninit(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DIGI_SOFTCHIP_openChannel(enum moduleNames moduleId, sbyte4 *pHwAccelCookie)
{
    MSTATUS status;

    DEBUG_CONSOLE_printError(DEBUG_CRYPTO, "BCM5823_openChannel: Mocana module = ", (sbyte4)moduleId);

    status = *pHwAccelCookie = ubsec_open(UBSEC_CRYPTO_DEVICE);

    /* negative values indicate platform specific error */
    if (0 <= status)
        status = OK;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DIGI_SOFTCHIP_closeChannel(enum moduleNames moduleId, sbyte4 *pHwAccelCookie)
{
    MSTATUS status = OK;

    DEBUG_CONSOLE_printError(DEBUG_CRYPTO, "BCM5823_closeChannel: Mocana module = ", (sbyte4)moduleId);

    if (0 <= *pHwAccelCookie)
    {
        ubsec_close(*pHwAccelCookie);
        *pHwAccelCookie = -1;           /* prevent double closes */
    }
    else
    {
        status = ERR_HARDWARE_ACCEL_CLOSE_SESSION;
    }

    return status;
}


/*------------------------------------------------------------------*/

#ifndef __DISABLE_AES_CIPHERS__

extern BulkCtx
CreateAESCtx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    ubsec_aes_context_t* ctx = MALLOC(sizeof(ubsec_aes_context_t));

    if (NULL != ctx)
    {
        int encr_al_flags = (encrypt) ? UBSEC_ENCODE : UBSEC_DECODE;

        switch (keyLength)
        {
            case 16:    /* 16 * 8 = 128-bits */
                encr_al_flags |= (UBSEC_AES_128BITKEY | UBSEC_AES);
                break;

            case 24:    /* 24 * 8 = 192-bits */
                encr_al_flags |= (UBSEC_AES_192BITKEY | UBSEC_AES);
                break;

            case 32:    /* 32 * 8 = 256-bits */
                encr_al_flags |= (UBSEC_AES_256BITKEY | UBSEC_AES);
                break;

            default:    /* should never happen */
                encr_al_flags  = 0;
                break;
        }

        if ((0 == encr_al_flags) || (0 > ubsec_aes_init(keyMaterial, 0, encr_al_flags, 0, ctx)))
        {
            FREE(ctx); ctx = NULL;
        }
    }

    return ctx;

} /* CreateAESCtx */


/*------------------------------------------------------------------*/

extern MSTATUS
DeleteAESCtx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    MSTATUS status = OK;

    if (*ctx)
    {
        if (0 > ubsec_aes_done((ubsec_aes_context_p)(*ctx)))
            status = ERR_HARDWARE_ACCEL_REMOVE_CTX;

        FREE(*ctx);
        *ctx = NULL;
    }

    return status;

} /* DeleteAESCtx */


/*------------------------------------------------------------------*/

extern MSTATUS
DoAES(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    int                 cmd = (encrypt) ? UBSEC_ENCODE : UBSEC_DECODE;
    ubsec_aes_context_p pAesContext = (ubsec_aes_context_p)ctx;
    MSTATUS             status = OK;

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 > hwAccelCtx)
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    if (0 != (dataLength % AES_BLOCK_SIZE))
    {
        status = ERR_AES_BAD_LENGTH;
        goto exit;
    }

    status = (MSTATUS)ubsec_aes_data_ioctl(hwAccelCtx, cmd, pAesContext, data, iv, dataLength, 0, data, dataLength, 0);

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
    ubsec_crypto_context_t* ctx = MALLOC(sizeof(ubsec_crypto_context_t));
    unsigned char*          k1 = keyMaterial;
    unsigned char*          k2 = NULL;
    unsigned char*          k3 = NULL;

    if (NULL != ctx)
    {
        int encr_al_flags = (encrypt) ? UBSEC_ENCODE : UBSEC_DECODE;

        switch (keyLength)
        {
            case 8:     /*  8 * 8 =  64-bits ( 56-bit DES) */
                encr_al_flags |= UBSEC_DES;
                break;

            default:    /* should never happen */
                encr_al_flags  = 0;
                break;
        }

        if ((0 == encr_al_flags) || (0 > ubsec_crypto_init(k1, k2, k3, 0, encr_al_flags, 0, ctx)))
        {
            FREE(ctx); ctx = NULL;
        }
    }

    return ctx;

} /* CreateDESCtx */


/*------------------------------------------------------------------*/

extern MSTATUS
DeleteDESCtx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    MSTATUS status = OK;

    if (*ctx)
    {
        if (0 > ubsec_crypto_done((ubsec_crypto_context_p)(*ctx)))
            status = ERR_HARDWARE_ACCEL_REMOVE_CTX;

        FREE(*ctx);
        *ctx = NULL;
    }

    return status;

} /* DeleteDESCtx */


/*------------------------------------------------------------------*/

extern MSTATUS
DoDES(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    int                     cmd = (encrypt) ? UBSEC_ENCODE : UBSEC_DECODE;
    ubsec_crypto_context_p  pDesContext = (ubsec_crypto_context_p)ctx;
    MSTATUS                 status = OK;

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 > hwAccelCtx)
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    if (0 != (dataLength % DES_BLOCK_SIZE))
    {
        status = ERR_DES_BAD_LENGTH;
        goto exit;
    }

    status = (MSTATUS)ubsec_crypto_data_ioctl(hwAccelCtx, cmd, pDesContext, data, iv,
                                              (unsigned short)dataLength, 0,
                                              data, (unsigned short)dataLength, 0);

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
    ubsec_crypto_context_t* ctx = MALLOC(sizeof(ubsec_crypto_context_t));
    unsigned char*          k1 = keyMaterial;
    unsigned char*          k2 = NULL;
    unsigned char*          k3 = NULL;

    if (NULL != ctx)
    {
        int encr_al_flags = (encrypt) ? UBSEC_ENCODE : UBSEC_DECODE;

        switch (keyLength)
        {
            case 24:    /* 24 * 8 = 192-bits (168-bit DES) */
                encr_al_flags |= UBSEC_3DES;
                k2 = k1 + DES_KEY_LENGTH;
                k3 = k2 + DES_KEY_LENGTH;
                break;

            default:    /* should never happen */
                encr_al_flags  = 0;
                break;
        }

        if ((0 == encr_al_flags) || (0 > ubsec_crypto_init(k1, k2, k3, 0, encr_al_flags, 0, ctx)))
        {
            FREE(ctx); ctx = NULL;
        }
    }

    return ctx;

} /* Create3DESCtx */


/*------------------------------------------------------------------*/

extern MSTATUS
Delete3DESCtx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    MSTATUS status = OK;

    if (*ctx)
    {
        if (0 > ubsec_crypto_done((ubsec_crypto_context_p)(*ctx)))
            status = ERR_HARDWARE_ACCEL_REMOVE_CTX;

        FREE(*ctx);
        *ctx = NULL;
    }

    return status;

} /* Delete3DESCtx */


/*------------------------------------------------------------------*/

extern MSTATUS
Do3DES(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    int                     cmd = (encrypt) ? UBSEC_ENCODE : UBSEC_DECODE;
    ubsec_crypto_context_p  p3DesContext = (ubsec_crypto_context_p)ctx;
    MSTATUS                 status = OK;

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 > hwAccelCtx)
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    if (0 != (dataLength % THREE_DES_BLOCK_SIZE))
    {
        status = ERR_3DES_BAD_LENGTH;
        goto exit;
    }

    status = (MSTATUS)ubsec_crypto_data_ioctl(hwAccelCtx, cmd, p3DesContext, data, iv,
                                              (unsigned short)dataLength, 0, data,
                                              (unsigned short)dataLength, 0);

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
    ctx_arc4_struct *pKeyDescr = MALLOC(sizeof(ctx_arc4_struct));

    if (NULL != pKeyDescr)
    {
        pKeyDescr->key_state_flag = ARC4_KEY;

        if ((1 > keyLength) || (256 < keyLength) ||
            (0 > ubsec_ssl_arc4_init_ioctl(hwAccelCtx, keyMaterial, keyLength, 0, 0, pKeyDescr->key_state, 260)) )
        {
            FREE(pKeyDescr); pKeyDescr = NULL;
        }
    }

    return pKeyDescr;

} /* CreateRC4Ctx */


/*------------------------------------------------------------------*/

extern MSTATUS
DeleteRC4Ctx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    MSTATUS status = OK;

    if (*ctx)
    {
        FREE(*ctx);
        *ctx = NULL;
    }

    return status;

} /* DeleteRC4Ctx */


/*------------------------------------------------------------------*/

extern MSTATUS
DoRC4(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    ctx_arc4_struct*    pKeyDescr = (ctx_arc4_struct *)ctx;
    MSTATUS             status = OK;

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 > hwAccelCtx)
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    status = (MSTATUS)ubsec_ssl_arc4_process_ioctl(hwAccelCtx,
                                                   data, dataLength,
                                                   pKeyDescr->key_state, pKeyDescr->key_state_flag,
                                                   data, dataLength,
                                                   pKeyDescr->key_state);

    pKeyDescr->key_state_flag = ARC4_STATE;

#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, "DoRC4: cipher failed, error = ", status);
#endif

exit:
    return status;

} /* DoRC4 */

#endif /* __DISABLE_ARC4_CIPHERS__ */


/*------------------------------------------------------------------*/

extern MSTATUS
RANDOM_acquireContext(randomContext **pp_randomContext)
{
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status;

    status = DIGI_SOFTCHIP_openChannel(MOCANA_MSS, &hwAccelCtx);

    *pp_randomContext = (randomContext *)hwAccelCtx;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
RANDOM_releaseContext(randomContext **pp_randomContext)
{
    hwAccelDescr  hwAccelCtx = (sbyte4)(*pp_randomContext);
    MSTATUS status;

    if (0 > hwAccelCtx)
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    status = DIGI_SOFTCHIP_closeChannel(MOCANA_MSS, &hwAccelCtx);

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
RANDOM_addEntropyBit(randomContext *pRandomContext, ubyte entropyBit)
{
    /* do nothing */
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
RANDOM_numberGenerator(randomContext *pRandomContext, ubyte *pBuffer, sbyte4 bufSize)
{
    hwAccelDescr  hwAccelCtx = (sbyte4)pRandomContext;
    MSTATUS status;

    if (0 > hwAccelCtx)
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    /* convert bytes to bits */
    bufSize <<= 3;

    status = (MSTATUS)rng_ioctl(hwAccelCtx, UBSEC_RNG_SHA1, pBuffer, &bufSize);

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
PRIME_generateSizedPrime(randomContext *pRandomContext, vlong **ppRetPrime, ubyte4 numBitsLong)
{
    hwAccelDescr  hwAccelCtx   = (sbyte4)pRandomContext;
    vlong*  pPrime       = NULL;
    int     result_bits  = (int)numBitsLong;
    MSTATUS status;

    if (0 > hwAccelCtx)
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    *ppRetPrime = NULL;

    /* allocate vlong structures */
    if (OK > (status = VLONG_allocVlong(&pPrime)))
        goto exit;

    if (OK > (status = VLONG_reallocVlong(pPrime, ((numBitsLong + 31) / 32))))
        goto exit;

    /* generate a random sized prime */
    if (OK > (status = (MSTATUS)rng_ioctl(hwAccelCtx, UBSEC_RNG_DIRECT, (unsigned char *)(pPrime->pArrayUnits), &result_bits)))
        goto exit;

    /* store the length */
    pPrime->numUnitsUsed = ((result_bits + 31) / 32);

    /* store result */
    *ppRetPrime = pPrime;   pPrime = NULL;

exit:
    if (NULL != pPrime)
        VLONG_freeVlong(&pPrime);

    return status;

} /* PRIME_generateSizedPrime */


/*------------------------------------------------------------------*/

extern MSTATUS
MD5_completeDigest(hwAccelDescr hwAccelCtx, ubyte *pData, ubyte4 dataLen, ubyte *pMdOutput)
{
    return (MSTATUS)ubsec_hash_ioctl(hwAccelCtx, pData, dataLen, UBSEC_MAC_MD5, pMdOutput, MD5_DIGESTSIZE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
SHA1_completeDigest(hwAccelDescr hwAccelCtx, ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput)
{
    return (MSTATUS)ubsec_hash_ioctl(hwAccelCtx, pData, dataLen, UBSEC_MAC_SHA1, pShaOutput, SHA_HASH_RESULT_SIZE);
}


/*------------------------------------------------------------------*/

extern MSTATUS
HMAC_MD5(hwAccelDescr hwAccelCtx, ubyte* key, sbyte4 keyLen, ubyte* text, sbyte4 textLen,
         ubyte* textOpt, sbyte4 textOptLen, ubyte result[MD5_DIGESTSIZE])
{
    MD5_CTX         context;
    unsigned char   kpad[HMAC_BLOCK_SIZE];
    unsigned char   tk[MD5_DIGESTSIZE];
    int             i;
    MSTATUS         status;

    if (0 > hwAccelCtx)
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    /* if key is longer than HMAC_BLOCK_SIZE bytes reset it to key=MD5(key) */
    if (keyLen > HMAC_BLOCK_SIZE)
    {
        if (0 > (status = (MSTATUS)ubsec_hash_ioctl(hwAccelCtx, key, keyLen, UBSEC_MAC_MD5, tk, MD5_DIGESTSIZE)))
            goto exit;

        key = tk;
        keyLen = MD5_DIGESTSIZE;
    }

    /*
     * HMAC_MD5 transform:
     * MD5(K XOR opad, MD5(K XOR ipad, text))
     *
     * where K is an n byte key
     * ipad is the byte 0x36 repeated 64 times
     * opad is the byte 0x5c repeated 64 times
     * and text is the data being protected
     */

    /* XOR key padded with 0 to HMAC_BLOCK_SIZE with 0x36 */
    for (i=0; i < keyLen; ++i)
        kpad[i] = (ubyte)(key[i] ^ IPAD);
    for (; i < HMAC_BLOCK_SIZE; i++)
        kpad[i] = 0 ^ IPAD;

    /*  perform inner MD5 */
    if (OK > (status = MD5Init_m(hwAccelCtx, &context)))
        goto exit;
    if (OK > (status = MD5Update_m(hwAccelCtx, &context, kpad, HMAC_BLOCK_SIZE)))
        goto exit;
    if (OK > (status = MD5Update_m(hwAccelCtx, &context, text, textLen)))
        goto exit;
    if ((NULL != textOpt) && (0 < textOptLen))
        if (OK > (status = MD5Update_m(hwAccelCtx, &context, textOpt, textOptLen)))
            goto exit;
    if (OK > (status = MD5Final_m(hwAccelCtx, &context, result)))
        goto exit;

    /* XOR key padded with 0 to HMAC_BLOCK_SIZE with 0x5C*/
    for (i=0; i < keyLen; i++)
        kpad[i] = (ubyte)(key[i] ^ OPAD);
    for (; i < HMAC_BLOCK_SIZE; i++)
        kpad[i] = (ubyte)(0 ^ OPAD);

    /* perform outer MD5 */
    if (OK > (status = MD5Init_m(hwAccelCtx, &context)))
        goto exit;
    if (OK > (status = MD5Update_m(hwAccelCtx, &context, kpad, HMAC_BLOCK_SIZE)))
        goto exit;
    if (OK > (status = MD5Update_m(hwAccelCtx, &context, result, MD5_DIGESTSIZE)))
        goto exit;
    status = MD5Final_m(hwAccelCtx, &context, result);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/* compute the HMAC output using SHA1 the textOpt can be null */
extern MSTATUS
HMAC_SHA1(hwAccelDescr hwAccelCtx, ubyte* key, sbyte4 keyLen, ubyte* text, sbyte4 textLen,
          ubyte* textOpt, sbyte4 textOptLen, ubyte result[SHA_HASH_RESULT_SIZE])
{
    shaDescr        context;
    unsigned char   kpad[HMAC_BLOCK_SIZE];
    unsigned char   tk[SHA_HASH_RESULT_SIZE];
    int             i;
    MSTATUS         status;

    if (0 > hwAccelCtx)
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }

    /* if key is longer than HMAC_BLOCK_SIZE bytes reset it to key = SHA1(key) */
    if (keyLen > HMAC_BLOCK_SIZE)
    {
        if (0 > (status = (MSTATUS)ubsec_hash_ioctl(hwAccelCtx, key, keyLen, UBSEC_MAC_SHA1, tk, SHA_HASH_RESULT_SIZE)))
            goto exit;

        key = tk;
        keyLen = SHA_HASH_RESULT_SIZE;
    }

    /*
     * HMAC_SHA1 transform:
     * SHA1(K XOR opad, SHA1(K XOR ipad, (text | textOpt)))
     *
     * where K is an n byte key
     * ipad is the byte 0x36 repeated 64 times
     * opad is the byte 0x5c repeated 64 times
     * and text is the data being protected
     */

    /* XOR key padded with 0 to HMAC_BLOCK_SIZE with 0x36 */
    for (i = 0; i < keyLen; i++)
        kpad[i] = (ubyte)(key[i] ^ IPAD);
    for (; i < HMAC_BLOCK_SIZE; i++)
        kpad[i] = (ubyte)(0 ^ IPAD);

    /*  perform inner SHA1 */
    if (OK > (status = SHA1_initDigest(hwAccelCtx, &context)))
        goto exit;
    if (OK > (status = SHA1_updateDigest(hwAccelCtx, &context, kpad, HMAC_BLOCK_SIZE)))
        goto exit;
    if (OK > (status = SHA1_updateDigest(hwAccelCtx, &context, text, textLen)))
        goto exit;
    if ((0 != textOpt) && (0 != textOptLen))
        if (OK > (status = SHA1_updateDigest(hwAccelCtx, &context, textOpt, textOptLen)))
            goto exit;
    if (OK > (status = SHA1_finalDigest(hwAccelCtx, &context, result)))
        goto exit;

    /* XOR key padded with 0 to HMAC_BLOCK_SIZE with 0x5C*/
    for (i = 0; i < keyLen; i++)
        kpad[i] = (ubyte)(key[i] ^ OPAD);
    for (; i < HMAC_BLOCK_SIZE; i++)
        kpad[i] = (ubyte)(0 ^ OPAD);

    /* perform outer SHA1 */
    if (OK > (status = SHA1_initDigest(hwAccelCtx, &context)))
        goto exit;
    if (OK > (status = SHA1_updateDigest(hwAccelCtx, &context, kpad, HMAC_BLOCK_SIZE)))
        goto exit;
    if (OK > (status = SHA1_updateDigest(hwAccelCtx, &context, result, SHA_HASH_RESULT_SIZE)))
        goto exit;
    status = SHA1_finalDigest(hwAccelCtx, &context, result);

exit:
    return status;

} /* HMAC_SHA1 */


/*------------------------------------------------------------------*/


extern MSTATUS
VLONG_operatorModSignedVlongs(hwAccelDescr hwAccelCtx, vlong* a, vlong* n, vlong **ppC)
{
    int     a_bits;
    int     n_bits;
    int     c_bits;
    MSTATUS status;

    /* c = a mod n */
    if ((NULL == a) || (NULL == n) || (NULL == ppC))
    {
        status = ERR_NULL_POINTER;
        goto nocleanup;
    }

    if (0 > hwAccelCtx)
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto nocleanup;
    }

    a_bits = (int)VLONG_bitLength(a);
    c_bits = n_bits = (int)VLONG_bitLength(n);

    if (OK > (status = VLONG_allocVlong(ppC)))
        goto exit;

    if (OK > (status = VLONG_reallocVlong(*ppC, n->numUnitsUsed)))
        goto exit;

    if (0 > (status = (MSTATUS)ubsec_modrem(hwAccelCtx,
                                            (unsigned char *)a->pArrayUnits, &a_bits,
                                            (unsigned char *)n->pArrayUnits, &n_bits,
                                            (unsigned char *)((*ppC)->pArrayUnits), &c_bits)))
    {
        goto exit;
    }

    /* set the length */
    (*ppC)->numUnitsUsed = ((c_bits + 31) / 32);

exit:
    if (OK > status)
        VLONG_freeVlong(ppC);

nocleanup:
    return status;

} /* VLONG_operatorModSignedVlongs */


/*------------------------------------------------------------------*/


extern MSTATUS
VLONG_modularInverse(hwAccelDescr hwAccelCtx, vlong *b, vlong *n, vlong **ppT)
{
    int     n_bits;
    int     b_bits;
    int     t_bits;
    MSTATUS status;

    /* t = (b^-1) mod n */
    if ((NULL == b) || (NULL == n) || (NULL == ppT))
    {
        status = ERR_NULL_POINTER;
        goto nocleanup;
    }

    if (0 > hwAccelCtx)
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto nocleanup;
    }

    n_bits = (int)VLONG_bitLength(n);
    t_bits = b_bits = (int)VLONG_bitLength(b);

    if (OK > (status = VLONG_allocVlong(ppT)))
        goto exit;

    if (OK > (status = VLONG_reallocVlong(*ppT, n->numUnitsUsed)))
        goto exit;

    if (0 > (status = (MSTATUS)ubsec_modinv(hwAccelCtx,
                                            (unsigned char *)n->pArrayUnits, &n_bits,
                                            (unsigned char *)b->pArrayUnits, &b_bits,
                                            (unsigned char *)((*ppT)->pArrayUnits), &t_bits)))
    {
        goto exit;
    }

    /* set the length */
    (*ppT)->numUnitsUsed = ((t_bits + 31) / 32);

exit:
    if (OK > status)
        VLONG_freeVlong(ppT);

nocleanup:
    return status;

} /* VLONG_modularInverse */


/*------------------------------------------------------------------*/

extern MSTATUS
VLONG_modexp(hwAccelDescr hwAccelCtx, vlong *a, vlong *e, vlong *n, vlong **ppResult)
{
    int     Result_len;
    int     ModN_len;
    int     ExpE_len;
    int     ParmA_len;
    MSTATUS status;

    /* ((a^e) mod n) */
    if ((NULL == a) || (NULL == e) || (NULL == n) || (NULL == ppResult))
    {
        status = ERR_NULL_POINTER;
        goto nocleanup;
    }

    if (0 > hwAccelCtx)
    {
        status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto nocleanup;
    }

    Result_len = ModN_len  = (int)VLONG_bitLength(n);
    ExpE_len  = (int)VLONG_bitLength(e);
    ParmA_len = (int)VLONG_bitLength(a);

    if (OK > (status = VLONG_allocVlong(ppResult)))
        goto exit;

    if (OK > (status = VLONG_reallocVlong(*ppResult, n->numUnitsUsed)))
        goto exit;

    if (0 > (status = (MSTATUS)math_accelerate_ioctl(hwAccelCtx, UBSEC_MATH_MODEXP,
                                                     (unsigned char *)n->pArrayUnits, &ModN_len,
                                                     (unsigned char *)e->pArrayUnits, &ExpE_len,
                                                     (unsigned char *)a->pArrayUnits, &ParmA_len,
                                                     0, 0,
                                                     (unsigned char *)((*ppResult)->pArrayUnits), &Result_len)))
    {
        goto exit;
    }

    /* set the length */
    (*ppResult)->numUnitsUsed = ((Result_len + 31) / 32);

exit:
    if (OK > status)
        VLONG_freeVlong(ppResult);

nocleanup:
    return status;

} /* VLONG_modexp */

#endif /*(defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) || defined(__ENABLE_DIGICERT_TESTBED_HARDWARE_ACCEL__))*/



