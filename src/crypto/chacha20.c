/*
 * chacha20.c
 *
 * Chacha20 Implementation
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
 * Derived from the implementation in libsodium
 "chacha-merged.c version 20080118
 D. J. Bernstein
 Public domain."
 */

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_CHACHA20_INTERNAL__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if defined(__ENABLE_DIGICERT_CHACHA20__) && !defined(__CHACHA20_HARDWARE_ACCELERATOR__)

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../crypto/chacha20.h"
#include "../crypto/poly1305.h"

#define U8C(v) (v##U)
#define U32C(v) (v##U)

#define U8V(v) ((ubyte)(v) & U8C(0xFF))
#define U32V(v) ((ubyte4)(v) & U32C(0xFFFFFFFF))

#define ROTL32(v, n) \
(U32V((v) << (n)) | ((v) >> (32 - (n))))

#define U8TO32_LITTLE(p) \
(((ubyte4)((p)[0])      ) | \
((ubyte4)((p)[1]) <<  8) | \
((ubyte4)((p)[2]) << 16) | \
((ubyte4)((p)[3]) << 24))

#define U32TO8_LITTLE(p, v) \
do { \
(p)[0] = U8V((v)      ); \
(p)[1] = U8V((v) >>  8); \
(p)[2] = U8V((v) >> 16); \
(p)[3] = U8V((v) >> 24); \
} while (0)

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
a = PLUS(a,b); d = ROTATE(XOR(d,a),16); \
c = PLUS(c,d); b = ROTATE(XOR(b,c),12); \
a = PLUS(a,b); d = ROTATE(XOR(d,a), 8); \
c = PLUS(c,d); b = ROTATE(XOR(b,c), 7);


/*----------------------------------------------------------------------------*/

/* If values for nonce or counter are set to NULL, initialize with zeroes
 */
static void
CHACHA20_setCounterBlock(ChaCha20Ctx *ctx, const ubyte* counter)
{

    ctx->schedule[12] = ((NULL == counter) ? 0 : U8TO32_LITTLE(counter + 0));
    ctx->schedule[13] = ((NULL == counter) ? 0 : U8TO32_LITTLE(counter + 4));
}


/*----------------------------------------------------------------------------*/

/* https://tools.ietf.org/html/draft-josefsson-ssh-chacha20-poly1305-openssh-00
 * The ChaCha20 context this initializes has an 8 byte counter and an 8 byte nonce.
 */
static void
CHACHA20_setNonceAndCounterEx(ChaCha20Ctx *ctx, const ubyte* nonce,
               const ubyte* counter)
{
    CHACHA20_setCounterBlock(ctx, counter);
    ctx->schedule[14] = ((NULL == nonce) ? 0 : U8TO32_LITTLE(nonce + 0));
    ctx->schedule[15] = ((NULL == nonce) ? 0 : U8TO32_LITTLE(nonce + 4));

    ctx->streamOffset = 0;
}


/*----------------------------------------------------------------------------*/

static void
CHACHA20_setup(ChaCha20Ctx *ctx, const ubyte *k, const ubyte* nonce,
               const ubyte* littleEndianCounter)
{
    ctx->schedule[0] = 0x61707865;
    ctx->schedule[1] = 0x3320646e;
    ctx->schedule[2] = 0x79622d32;
    ctx->schedule[3] = 0x6b206574;
    ctx->schedule[4] = U8TO32_LITTLE(k + 0);
    ctx->schedule[5] = U8TO32_LITTLE(k + 4);
    ctx->schedule[6] = U8TO32_LITTLE(k + 8);
    ctx->schedule[7] = U8TO32_LITTLE(k + 12);
    ctx->schedule[8] = U8TO32_LITTLE(k + 16);
    ctx->schedule[9] = U8TO32_LITTLE(k + 20);
    ctx->schedule[10] = U8TO32_LITTLE(k + 24);
    ctx->schedule[11] = U8TO32_LITTLE(k + 28);
    ctx->schedule[12] = U8TO32_LITTLE(littleEndianCounter);
    ctx->schedule[13] = U8TO32_LITTLE(nonce + 0);
    ctx->schedule[14] = U8TO32_LITTLE(nonce + 4);
    ctx->schedule[15] = U8TO32_LITTLE(nonce + 8);

    ctx->streamOffset = 0;
}


/*----------------------------------------------------------------------------*/

static void CHACHA20_block( ChaCha20Ctx* ctx)
{
    ubyte4 w[16];
    int i;

    for (i = 0; i < 16; ++i)
    {
        w[i] = ctx->schedule[i];
    }
    for (i = 0; i < 10; ++i)
    {
        QUARTERROUND(w[0], w[4], w[8], w[12]);
        QUARTERROUND(w[1], w[5], w[9], w[13]);
        QUARTERROUND(w[2], w[6], w[10], w[14]);
        QUARTERROUND(w[3], w[7], w[11], w[15]);
        QUARTERROUND(w[0], w[5], w[10], w[15]);
        QUARTERROUND(w[1], w[6], w[11], w[12]);
        QUARTERROUND(w[2], w[7], w[8], w[13]);
        QUARTERROUND(w[3], w[4], w[9], w[14]);
    }
    for (i = 0; i < 16; ++i)
    {
        w[i] = PLUS(ctx->schedule[i], w[i]);
    }
    /* serialize w in the key stream */
    for (i = 0; i < 16; ++i)
    {
        U32TO8_LITTLE(ctx->keystream + i*4, w[i]);
    }
}


/*----------------------------------------------------------------------------*/

extern BulkCtx CreateChaCha20Ctx(MOC_SYM(hwAccelDescr hwAccelCtx)
                                      const ubyte *pKeyMaterial,
                                      sbyte4 keyLength,
                                      sbyte4 encrypt)
{
    ChaCha20Ctx *pCtx = NULL;
    MOC_UNUSED(encrypt);

    if (!pKeyMaterial)
    {
        return pCtx;
    }

    /* verify key length */
    if (keyLength != 48) /* 32 byte key, 4 byte counter, 12 bytes nonce */
    {
        return pCtx;
    }

    pCtx = (ChaCha20Ctx*) MALLOC(sizeof(ChaCha20Ctx));
    if (pCtx)
    {
        DIGI_MEMSET((ubyte *)pCtx, 0x00, sizeof(ChaCha20Ctx));

        /* install the key/nonce/counter in the counter block */
        CHACHA20_setup(pCtx, pKeyMaterial, pKeyMaterial + 36, pKeyMaterial + 32);
     }
    return pCtx;
}


/*----------------------------------------------------------------------------*/

extern MSTATUS DeleteChaCha20Ctx(MOC_SYM(hwAccelDescr hwAccelCtx)
                                      BulkCtx *pCtx)
{
    if (NULL == pCtx)
        return ERR_NULL_POINTER;

    if (*pCtx)
    {
       /* Zeroize the sensitive information before deleting the memory */
        DIGI_MEMSET((ubyte*)*pCtx, 0x00, sizeof(ChaCha20Ctx));
        return DIGI_FREE(pCtx);
    }
    return OK;
}

/*----------------------------------------------------------------------------*/

static void
CHACHA20_GetNewKeyStream( ChaCha20Ctx* pCtx)
{
    /* generate new keystream */
    CHACHA20_block( pCtx);

    /* increment the block for next call in a time constant way */
    ++pCtx->schedule[12];
}


/*----------------------------------------------------------------------------*/

extern MSTATUS DoChaCha20(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx,
                               ubyte *pData, sbyte4 dataLength,
                               sbyte4 encrypt, ubyte *pIv)
{
    ChaCha20Ctx* pCtx = (ChaCha20Ctx *)ctx;
    sbyte4 i;

    MOC_UNUSED(encrypt);

    if ((NULL != pIv))
    {
        CHACHA20_setNonceAndCounterEx(pCtx, pIv + 8, pIv);
    }

    /* was there some bytes remaining from last call? */
    if ( pCtx->streamOffset && dataLength > 0)
    {
        while (dataLength > 0 && pCtx->streamOffset > 0)
        {
            *pData++ ^= pCtx->keystream[pCtx->streamOffset];
            dataLength--;
            pCtx->streamOffset++;
            if (CHACHA20_KEYSTREAM_SIZE == pCtx->streamOffset)
            {
                pCtx->streamOffset = 0;
            }
        }
    }

    while ( dataLength >= CHACHA20_KEYSTREAM_SIZE)
    {
        CHACHA20_GetNewKeyStream( pCtx);
        /* XOR it with the data */
        for ( i = 0; i < CHACHA20_KEYSTREAM_SIZE; ++i)
        {
            *pData++ ^= pCtx->keystream[i];
        }
        dataLength -= CHACHA20_KEYSTREAM_SIZE;
    }

    if ( dataLength > 0)
    {
        CHACHA20_GetNewKeyStream( pCtx);
        /* XOR it with the data */
        for ( i = 0; i < dataLength; ++i)
        {
            *pData++ ^= pCtx->keystream[i];
        }
        pCtx->streamOffset = (ubyte)i;
    }

    if ((NULL != pIv))
    {
        U32TO8_LITTLE(pIv,      pCtx->schedule[12]);
        U32TO8_LITTLE(pIv +  4, pCtx->schedule[13]);
        U32TO8_LITTLE(pIv +  8, pCtx->schedule[14]);
        U32TO8_LITTLE(pIv + 12, pCtx->schedule[15]);
    }

    return OK;

}


/*----------------------------------------------------------------------------*/


/* The nonce and counter are assumed to be 8 bytes as specified by
 * https://tools.ietf.org/html/draft-josefsson-ssh-chacha20-poly1305-openssh-00 */
extern MSTATUS CHACHA20_setNonceAndCounterSSH(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx,
    ubyte *pNonce,
    ubyte4 nonceLength,
    ubyte *pCounter,
    ubyte counterLength
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ChaCha20Ctx *pCtx = (ChaCha20Ctx *)ctx;
    MOC_UNUSED(nonceLength);
    MOC_UNUSED(counterLength);

    if (NULL == pCtx)
        goto exit;

    CHACHA20_setNonceAndCounterEx(pCtx, pNonce, pCounter);
    status = OK;

exit:
    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CloneChaCha20Ctx(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    BulkCtx pCtx,
    BulkCtx *ppNewCtx
    )
{
    MSTATUS status;
    ChaCha20Ctx *pNewCtx = NULL;

    if ( (NULL == pCtx) || (NULL == ppNewCtx) )
    {
        return ERR_NULL_POINTER;
    }

    status = DIGI_MALLOC((void **)&pNewCtx, sizeof(ChaCha20Ctx));
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)pNewCtx, (void *)pCtx, sizeof(ChaCha20Ctx));
    if (OK != status)
        goto exit;

    *ppNewCtx = pNewCtx;
    pNewCtx = NULL;

exit:
    if (NULL != pNewCtx)
    {
        DIGI_FREE((void **)&pNewCtx);
    }

    return status;
}

#if defined(__ENABLE_DIGICERT_POLY1305__)
/* ChaCha20Poly1305 AEAD cipher */

static const ubyte gpPadding[15] = {0}; /* zero padding */

/*----------------------------------------------------------------------------*/

extern BulkCtx ChaCha20Poly1305_createCtx( MOC_SYM(hwAccelDescr hwAccelCtx)
                                              ubyte *pKey, sbyte4 keyLength,
                                              sbyte4 encrypt)
{
    ChaCha20Ctx *pCtx = 0;
    ubyte4 zeroes[3] = { 0 };

    if (!pKey)
    {
        return pCtx;
    }
    /* verify key length */
    if (keyLength != 32) /* 32 byte key */
    {
        return pCtx;
    }

    pCtx = (ChaCha20Ctx*) MALLOC(sizeof(ChaCha20Ctx));
    if (pCtx)
    {
        DIGI_MEMSET((ubyte *)pCtx, 0x00, sizeof(ChaCha20Ctx));

        /* install the key in the counter block, nonce/counter is zero */
        CHACHA20_setup(pCtx, pKey, (ubyte*) zeroes, (ubyte*) zeroes);
        /* we cannot do anything with the poly1305 since the nonce
         is required to generate the Poly1305 key */

        pCtx->encrypt = encrypt;
    }
    return pCtx;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS ChaCha20Poly1305_deleteCtx(MOC_SYM(hwAccelDescr hwAccelCtx)
                                              BulkCtx *pCtx)
{
    return DeleteChaCha20Ctx(MOC_SYM(hwAccelCtx) pCtx);
}


/*----------------------------------------------------------------------------*/

/* This implementation is specific to
 * https://tools.ietf.org/html/draft-josefsson-ssh-chacha20-poly1305-openssh-00 */
extern MSTATUS ChaCha20Poly1305_cipherSSH(MOC_SYM(hwAccelDescr hwAccelCtx)
                                           BulkCtx ctx,
                                           ubyte *pNonce, ubyte4 nlen,
                                           ubyte *pAdata, ubyte4 alen,
                                           ubyte *pData,  ubyte4 dlen,
                                           ubyte4 verifyLen, sbyte4 encrypt)
{
    ChaCha20Ctx *pCtx = (ChaCha20Ctx *) ctx;
    ubyte pCounter[] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    ubyte pTag[16];
    ubyte pPolyKey[32];
    ubyte *pExpectedTag = NULL;
    intBoolean res;
    MOC_UNUSED(pAdata);
    MOC_UNUSED(alen);
    MOC_UNUSED(verifyLen);

    if (NULL == pCtx || NULL == pNonce)
        return ERR_NULL_POINTER;

    /* pNonce should be 8 bytes long */
    if (8 != nlen)
        return ERR_INVALID_ARG;

    /* generate the poly1305 key : use pNonce, reset counter to 0, key is set */
    CHACHA20_setNonceAndCounterEx(pCtx, pNonce, NULL);

    /* run block function once to get bytes for poly key */
    CHACHA20_block(pCtx);

    /* store first 32 bytes of keystream */
    DIGI_MEMCPY(pPolyKey, pCtx->keystream, 32);

    /* if decrypting, verify tag before proceeding */
    if (!encrypt)
    {
        pExpectedTag = pData + dlen;
        Poly1305_completeDigest(MOC_HASH(hwAccelCtx) pTag, pData, dlen, pPolyKey);

        /* compare computed tag with pExpectedTag, no need to check return code */
        DIGI_CTIME_MATCH( pTag, pExpectedTag, 16, &res);
        if (0 != res)
        {
            return ERR_CRYPTO_AEAD_FAIL;
        }
    }

    /* set counter byte to little endian version of 1 */
    CHACHA20_setCounterBlock(pCtx, pCounter);

    /* the first 4 bytes are not part of the payload that we encrypt */
    DoChaCha20(MOC_SYM(hwAccelCtx) pCtx, pData + 4, dlen - 4, 0, NULL);

    /* compute authentication tag and append it dlen bytes offset from pData, no need to check return code */
    if (encrypt)
    {
        Poly1305_completeDigest(MOC_HASH(hwAccelCtx) pTag, pData, dlen, pPolyKey);
        DIGI_MEMCPY(pData + dlen, pTag, 16);
    }

    return OK;
}


/*----------------------------------------------------------------------------*/

extern MSTATUS ChaCha20Poly1305_cipher(MOC_SYM(hwAccelDescr hwAccelCtx)
                                           BulkCtx ctx,
                                           ubyte *pNonce, ubyte4 nlen,
                                           ubyte *pAdata, ubyte4 alen,
                                           ubyte *pData,  ubyte4 dlen,
                                           ubyte4 verifyLen, sbyte4 encrypt)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == ctx)
        goto exit;

    /* to keep backwards compatibility we replace the encrypt flag in the ctx */
    ((ChaCha20Ctx *) ctx)->encrypt = encrypt;

    /* input validation done by the below calls */
    status = ChaCha20Poly1305_update_nonce(MOC_SYM(hwAccelCtx) ctx, pNonce, nlen);
    if (OK != status)
        goto exit;

    status = ChaCha20Poly1305_update_aad(MOC_SYM(hwAccelCtx) ctx, pAdata, alen);
    if (OK != status)
        goto exit;

    status = ChaCha20Poly1305_update_data(MOC_SYM(hwAccelCtx) ctx, pData, dlen);
    if (OK != status)
        goto exit;

    /* tag will be stored, or is stored, after dlen bytes of data */
    status = ChaCha20Poly1305_final(MOC_SYM(hwAccelCtx) ctx, pData + dlen, verifyLen);

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

MSTATUS ChaCha20Poly1305_update_nonce(MOC_SYM(hwAccelDescr hwAccelCtx)
                                      BulkCtx ctx,
                                      ubyte *pNonce,
                                      ubyte4 nonceLen
                                      )
{
    ChaCha20Ctx *pCtx = (ChaCha20Ctx *) ctx;

    if (NULL == pCtx || NULL == pNonce)
        return ERR_NULL_POINTER;

    if (12 != nonceLen)
        return ERR_CHACHA20_BAD_NONCE_LENGTH;

    /* generate the poly1305 key : use nonce, reset counter to 0, key is set */
    pCtx->schedule[12] = 0;
    pCtx->schedule[13] = U8TO32_LITTLE(pNonce + 0);
    pCtx->schedule[14] = U8TO32_LITTLE(pNonce + 4);
    pCtx->schedule[15] = U8TO32_LITTLE(pNonce + 8);

    /* reset streamOffset */
    pCtx->streamOffset = 0;
    CHACHA20_GetNewKeyStream(pCtx);

    /* set up the Poly1305 ctx, return code is always OK */
    Poly1305Init(MOC_HASH(hwAccelCtx) &pCtx->tagCtx, pCtx->keystream);

    return OK;
}

/*----------------------------------------------------------------------------*/

MSTATUS ChaCha20Poly1305_update_aad(MOC_SYM(hwAccelDescr hwAccelCtx)
                                    BulkCtx ctx,
                                    ubyte *pAadData,
                                    ubyte4 aadDataLen
                                    )
{
    ChaCha20Ctx *pCtx = (ChaCha20Ctx *) ctx;

    if ( NULL == pCtx || (aadDataLen && NULL == pAadData) )
        return ERR_NULL_POINTER;

    /*
     use the counter in byte 12 (which is non-zero after initialization)
     as a flag for an initialized ctx.
     */
    if (!pCtx->schedule[12])
        return ERR_CHACHA20_UNINITIALIZED_CTX;

    if (pCtx->aadFinalized)
        return ERR_CHACHA20_ALREADY_FINALIZED_AAD;

    /* return code of Poly1305Update is always OK */
    Poly1305Update(MOC_HASH(hwAccelCtx) &pCtx->tagCtx, pAadData, aadDataLen);
    pCtx->aadLen += aadDataLen;

    return OK;
}

/*----------------------------------------------------------------------------*/

MSTATUS ChaCha20Poly1305_update_data(MOC_SYM(hwAccelDescr hwAccelCtx)
                                     BulkCtx ctx,
                                     ubyte *pData,
                                     ubyte4 dataLen
                                     )
{
    ChaCha20Ctx *pCtx = (ChaCha20Ctx *) ctx;

    if (NULL == pCtx || (dataLen && NULL == pData))
        return ERR_NULL_POINTER;

    /*
     use the counter in byte 12 (which is non-zero after initialization)
     as a flag for an initialized ctx.
     */
    if (!pCtx->schedule[12])
        return ERR_CHACHA20_UNINITIALIZED_CTX;

    if (!pCtx->aadFinalized)
    {
        /* finalize the AAD, zero pad the AAD to the 16 byte block length */
        if (pCtx->aadLen & 0x0f)
        {
            /* return code is always OK */
            Poly1305Update(MOC_HASH(hwAccelCtx) &pCtx->tagCtx, gpPadding, 16 - (pCtx->aadLen & 0x0f));
        }
        pCtx->aadFinalized = TRUE;
    }

    if (!pCtx->encrypt)
    {   /* update the tagCtx before decrypting, return code always OK */
        Poly1305Update(MOC_HASH(hwAccelCtx) &pCtx->tagCtx, pData, dataLen);
    }

    /* encrypt or decrypt: return code always OK. */
    DoChaCha20(MOC_SYM(hwAccelCtx) pCtx, pData, dataLen, pCtx->encrypt, NULL);

    if (pCtx->encrypt)
    {
        /* Update the tagCtx after encrypting */
        Poly1305Update(MOC_HASH(hwAccelCtx) &pCtx->tagCtx, pData, dataLen);
    }
    pCtx->dataLen += dataLen;

    return OK;
}

/*----------------------------------------------------------------------------*/

MSTATUS ChaCha20Poly1305_final(MOC_SYM(hwAccelDescr hwAccelCtx)
                               BulkCtx ctx,
                               ubyte *pTag,
                               ubyte4 tagLen
                               )
{
    ChaCha20Ctx *pCtx = (ChaCha20Ctx *) ctx;
    MSTATUS status = OK;
    ubyte pBuffer[16] = {0};

    if (NULL == pCtx || NULL == pTag)
        return ERR_NULL_POINTER;

    if (16 != tagLen)
        return ERR_CHACHA20_BAD_TAG_LENGTH;

    /*
     use the counter in byte 12 (which is non-zero after initialization)
     as a flag for an initialized ctx.
     */
    if (!pCtx->schedule[12])
        return ERR_CHACHA20_UNINITIALIZED_CTX;

    /*
     One may have called update_aad and then not update_data. Make sure to
     still finalize the aad.
     */
    if (!pCtx->aadFinalized)
    {
        /* finalize the AAD, zero pad the AAD to the 16 byte block length */
        if (pCtx->aadLen & 0x0f)
        {
            /* return code is always OK */
            Poly1305Update(MOC_HASH(hwAccelCtx) &pCtx->tagCtx, gpPadding, 16 - (pCtx->aadLen & 0x0f));
        }
        /* done with aadFinalized flag, no need to set to TRUE */
    }

    /* zero pad the data to the 16 byte block length */
    if (pCtx->dataLen & 0x0f)
    {
        /* return code is always OK */
        Poly1305Update(MOC_HASH(hwAccelCtx) &pCtx->tagCtx, gpPadding, 16 - (pCtx->dataLen & 0x0f));
    }

    /* update with the lengths in 8 bytes little endian (upper 4 bytes remain zero) */
    U32TO8_LITTLE(pBuffer, pCtx->aadLen);
    Poly1305Update(MOC_HASH(hwAccelCtx) &pCtx->tagCtx, pBuffer, 8);
    U32TO8_LITTLE(pBuffer, pCtx->dataLen);
    Poly1305Update(MOC_HASH(hwAccelCtx) &pCtx->tagCtx, pBuffer, 8);

    if (pCtx->encrypt)
    {
        /* get the tag and write to pTag, return code is always OK */
        Poly1305Final(MOC_HASH(hwAccelCtx) &pCtx->tagCtx, pTag);
    }
    else
    {
        sbyte4 res = 0;

        /* get the tag and put in pBuffer */
        Poly1305Final(MOC_HASH(hwAccelCtx) &pCtx->tagCtx, pBuffer);

        /* compare with the pTag passed in, no need to check return code */
        DIGI_CTIME_MATCH( pTag, pBuffer, 16, &res);
        if (0 != res)
        {
            status = ERR_CRYPTO_AEAD_FAIL;
        }
    }

    /* Reset the mac part of the context so that the outer chacha context can be reused */
    pCtx->aadFinalized = FALSE;
    pCtx->dataLen = 0;
    pCtx->aadLen = 0;

    DIGI_MEMSET((ubyte *) &(pCtx->tagCtx), 0x00, sizeof(Poly1305Ctx)); /* no return code check needed, don't change status */

    return status;
}

/*----------------------------------------------------------------------------*/

MSTATUS ChaCha20Poly1305_cloneCtx(MOC_SYM(hwAccelDescr hwAccelCtx)
                                  BulkCtx pCtx,
                                  BulkCtx *ppNewCtx
                                  )
{
    return CloneChaCha20Ctx(MOC_SYM(hwAccelCtx) pCtx, ppNewCtx);
}

#endif /* defined(__ENABLE_DIGICERT_POLY1305__) */
#endif /* defined(__ENABLE_DIGICERT_CHACHA20__) && !defined(__CHACHA20_HARDWARE_ACCELERATOR__) */
