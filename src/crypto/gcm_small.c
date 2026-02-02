/*
 * gcm_small.c
 *
 * Galois Counter Mode
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
 * Code derived from public domain code on www.zork.org
 * References:
 *
 * (1) The Galois/Counter mode of Operation (GCM)
 *   http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
 */


/*------------------------------------------------------------------*/

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#endif
#include "../crypto/aes.h"
#include "../crypto/aesalgo.h"
#include "../crypto/aes_ctr.h"
#include "../crypto/gcm.h"

#if ((!defined __RTOS_VXWORKS__) && (!defined __RTOS_FREERTOS__))
#include <memory.h>
#endif

#include <stdlib.h>

#if defined(__ENABLE_DIGICERT_SMALL_AES__) && defined(__ENABLE_DIGICERT_GCM_256B__)

#ifdef HTONL
#undef HTONL
#endif
#if defined(MOC_LITTLE_ENDIAN)
#define HTONL(A) SWAPDWORD(A)
#elif defined(MOC_BIG_ENDIAN)
#define HTONL(A) (A)
#else
#error Must define either MOC_LITTLE_ENDIAN or MOC_BIG_ENDIAN
#endif

#define GHASH_ALPHA 0xe1000000  /*  1 + alpha + alpha ^ 2 + alpha ^ 7 */

#define GHASH_BLK_SZ     (AES_BLOCK_SIZE)
#define GCM_LEFTMOST_BIT (0x80)
#define GCM_NUM_BITS     (0x08)



/*--------------------------------------------------------------------------------*/

static ubyte4 GCM_rtable_256b[16] = {
    0x00000000, 0x1c200000, 0x38400000, 0x24600000, 0x70800000, 0x6ca00000,
    0x48c00000, 0x54e00000, 0xe1000000, 0xfd200000, 0xd9400000, 0xc5600000,
    0x91800000, 0x8da00000, 0xa9c00000, 0xb5e00000
};


/*-----------------------------------------------------------------------*/
/* multiply by alpha --> all coefficients get shifted by one followed
    by a reduction if necessary. Cf (1)
*/

static void GCM_mul_alpha(ubyte4 z[4])
{
    ubyte4 carry = z[3] & 1;

    z[3] >>= 1;
    z[3] |= ((z[2] & 1) << 31);
    z[2] >>= 1;
    z[2] |= ((z[1] & 1) << 31);
    z[1] >>= 1;
    z[1] |= ((z[0] & 1) << 31);
    z[0] >>= 1;

    /* need a reduction -> just add GHASH_ALPHA (cf [1]) */
    if (carry)
        z[0] ^= GHASH_ALPHA;
}

/*--------------------------------------------------------------------------------*/

static ubyte4 SWAPDWORD(ubyte4 a)
{
    return ((a << 24) |
            ((a << 8) & 0x00ff0000) |
            ((a >> 8) & 0x0000ff00) |
            (a >> 24));
}

/*--------------------------------------------------------------------------------*/

static void GCM_build_hash_table_256b(gcm_ctx_256b *c, ubyte4 hkey[4])
{
    int i, j;

    for (i = 0; i < 4; ++i)
    {
        c->table[0][i] = 0;
        c->table[0x4][i] = c->table[0x8][i] = HTONL(hkey[i]);
    }

    GCM_mul_alpha(c->table[0x4]);

    for (i = 0; i < 4; ++i)
    {
        c->table[0x2][i] = c->table[0x4][i];
    }

    GCM_mul_alpha(c->table[0x2]);

    for (i = 0; i < 4; ++i)
    {
        c->table[0x1][i] = c->table[0x2][i];
    }

    GCM_mul_alpha(c->table[0x1]);

    for (j = 0x1; j <= 0x4; j += 0x3)
    {
        const int k = j + 0x2;

        for (i = 0; i < 4; ++i)
        {
            c->table[k][i] = c->table[j][i] ^ c->table[0x2][i];
        }
    }

    for (j = 0x1; j <= 0x3; j += 0x2)
    {
        const int k = j + 0x4;

        for (i = 0; i < 4; ++i)
        {
            c->table[k][i] = c->table[j][i] ^ c->table[0x4][i];
        }
    }

    for (j = 0x1; j <= 0x7; ++j)
    {
        const int k = j + 0x8;

        for (i = 0; i < 4; ++i)
        {
            c->table[k][i] = c->table[j][i] ^ c->table[0x8][i];
        }
    }
}


/*--------------------------------------------------------------------------------*/

static void Shift256B(ubyte4 t[4])
{
    int i;
    ubyte tt = (ubyte) (t[3] & 0xf);
    t[3] >>= 4;

    for (i = 3; i > 0; --i)
    {
        t[i] |= (t[i-1] << 28);
        t[i-1] >>= 4;
    }

    t[0] ^= GCM_rtable_256b[tt];
}

/*--------------------------------------------------------------------------------*/

static void GMulWI256B(ubyte4 in[][4], ubyte4 s, ubyte4 t[4])
{
    ubyte4* e;
    int i;

    e = in[s&0xf];
    memcpy(t, e, sizeof(ubyte4)*4);

    for (i = 4; i <= 28; i+=4)
    {
        Shift256B(t);

        e = in[(s>>i)&0xf];
        t[0] ^= e[0];
        t[1] ^= e[1];
        t[2] ^= e[2];
        t[3] ^= e[3];
    }
}


/*--------------------------------------------------------------------------------*/

static void GMulW256B(ubyte4 in[][4], ubyte4 s, ubyte4 t[4])
{
    ubyte4 *e;
    int i;

    for (i = 0; i <= 28; i+=4)
    {
        Shift256B(t);

        e = in[(s>>i)&0xf];
        t[0] ^= e[0];
        t[1] ^= e[1];
        t[2] ^= e[2];
        t[3] ^= e[3];
    }
}

/*--------------------------------------------------------------------------------*/

static ubyte4 make_be_ubyte4( const ubyte* b)
{
    return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
}

/*--------------------------------------------------------------------------------*/

static void GHB256B( ubyte4 s[4], ubyte4 table[][4], const ubyte* b)
{
    ubyte4 t[4];
    s[0] ^= make_be_ubyte4(b);
    s[1] ^= make_be_ubyte4(b+4);
    s[2] ^= make_be_ubyte4(b+8);
    s[3] ^= make_be_ubyte4(b+12);
    GMulWI256B(table, s[3], t);
    GMulW256B(table, s[2], t);
    GMulW256B(table, s[1], t);
    GMulW256B(table, s[0], t);
    memcpy( s, t, 4*sizeof(ubyte4));
}


/*--------------------------------------------------------------------------------*/

static void
GCM_set_key_256b(gcm_ctx_256b* c, ubyte* key, sbyte4 keylen)
{
    ubyte4 hkgen[4] = {0};
    ubyte4 hkey[4];

    c->pCtx->pCtx->Nr = aesKeySetupEnc(c->pCtx->pCtx->rk, key, c->pCtx->pCtx->keyLen = keylen * 8);
    c->pCtx->pCtx->encrypt=1;
    c->pCtx->pCtx->mode = MODE_ECB;
    aesEncrypt(c->pCtx->pCtx->rk, c->pCtx->pCtx->Nr, (ubyte*) hkgen, (ubyte*) hkey);
    GCM_build_hash_table_256b(c, hkey);
}


/*--------------------------------------------------------------------------------*/

static void
GCM_AESCTR_GetNewBlock( aesCTRCipherContext* pCtx, sbyte4 limit)
{
    sbyte4 i;
    limit = AES_BLOCK_SIZE - limit;
    /* encrypt the current block */
    aesEncrypt(pCtx->pCtx->rk, pCtx->pCtx->Nr, pCtx->u.counterBlock, pCtx->encBlock);
    /* increment the block for next call */
    for ( i = AES_BLOCK_SIZE - 1; i >= limit; --i)
    {
        if ( ++(pCtx->u.counterBlock[i]))
            break;
        /* it overflowed to 0 so carry over to prev byte */
    }
}


/*--------------------------------------------------------------------------------*/

static void
GCM_doAESCTR( gcm_ctx_256b* c, ubyte* data, sbyte4 dataLength, sbyte4 limit)
{
    aesCTRCipherContext* pCtx = c->pCtx;
    int i;

    /* was there some bytes remaining from last call? */
    if ( pCtx->offset && dataLength > 0)
    {
        while (dataLength > 0 && pCtx->offset > 0)
        {
            *data++ ^= pCtx->encBlock[pCtx->offset];
            dataLength--;
            pCtx->offset++;
            if (AES_BLOCK_SIZE == pCtx->offset)
            {
                pCtx->offset = 0;
            }
        }
    }

    while ( dataLength >= AES_BLOCK_SIZE)
    {
        GCM_AESCTR_GetNewBlock( pCtx, limit);
        /* XOR it with the data */
        for ( i = 0; i < AES_BLOCK_SIZE; ++i)
        {
            *data++ ^= pCtx->encBlock[i];
        }
        dataLength -= AES_BLOCK_SIZE;
    }

    if ( dataLength > 0)
    {
        GCM_AESCTR_GetNewBlock( pCtx, limit);
        /* XOR it with the data */
        for ( i = 0; (i < dataLength) && (i < AES_BLOCK_SIZE); ++i)
        {
            *data++ ^= pCtx->encBlock[i];
        }
        pCtx->offset = (ubyte)i;
    }
}


/*--------------------------------------------------------------------------------*/

extern BulkCtx
GCM_createCtx_256b(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* key, sbyte4 keylen, sbyte4 encrypt)
{
    gcm_ctx_256b *ctx = NULL;

    MOC_UNUSED(encrypt);

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    if (OK != getFIPS_powerupStatus(FIPS_ALGO_AES_GCM))
        return NULL;
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

    if (!key)
        goto exit;

    ctx = malloc(sizeof(gcm_ctx_256b));

    if (NULL != ctx)
    {
        /* zero out all the fields */
        memset((ubyte *)ctx, 0x00, sizeof(gcm_ctx_256b));
        GCM_set_key_256b( ctx, key, keylen);
    }

exit:
    return (BulkCtx) ctx;
}


/*---------------------------------------------------------------------------------*/

extern MSTATUS
GCM_deleteCtx_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx)
{
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    if (OK != getFIPS_powerupStatus(FIPS_ALGO_AES_GCM))
        return getFIPS_powerupStatus(FIPS_ALGO_AES_GCM);
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

    if (*ctx)
    {
#ifdef __ZEROIZE_TEST__
        int counter = 0;
        FIPS_PRINT("\nAESGCM256b - Before Zeroization\n");
        for( counter = 0; counter < sizeof(gcm_ctx_256b); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)*ctx+counter));
        }
        FIPS_PRINT("\n");
#endif

        memset((ubyte *)*ctx, 0x00, sizeof(gcm_ctx_256b));

#ifdef __ZEROIZE_TEST__
        FIPS_PRINT("\nAESGCM256b - After Zeroization\n");
        for( counter = 0; counter < sizeof(gcm_ctx_256b); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)*ctx+counter));
        }
        FIPS_PRINT("\n");
#endif

        free(*ctx);
        *ctx = NULL;
    }

    return OK;
}


/*---------------------------------------------------------------------------------*/

extern MSTATUS
GCM_init_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx,
              ubyte* nonce, ubyte4 nlen,
              ubyte* adata, ubyte4 alen)
{
    gcm_ctx_256b *c = (gcm_ctx_256b*)ctx;
    ubyte4 tmp[4] = {0};
    ubyte4 b, l, i;
    ubyte4 s[4] = {0};

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    if (OK != getFIPS_powerupStatus(FIPS_ALGO_AES_GCM))
        return getFIPS_powerupStatus(FIPS_ALGO_AES_GCM);
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

    if (!c || !nonce || (!adata && alen) )
        return ERR_NULL_POINTER;

    /* validate arguments -- since we use ubyte4 for lengths, the other parameters
        are ok */
    if (0 == nlen)
    {
        return ERR_INVALID_ARG;
    }

    /* save the additional data length */
    c->alen = alen;
    /* zero out the other fields */
    c->dlen = 0;
    c->hashBufferIndex = 0;
    c->s[0] = c->s[1] = c->s[2] = c->s[3] = 0;

    /* Process the nonce first. */
    if (nlen != 12)
    {
        b = nlen >> 4;
        l = nlen & 15;
        while (b--)
        {
            GHB256B(s, c->table, nonce);
            nonce += GHASH_BLK_SZ;
        }
        if (l)
        {
            memcpy(tmp, nonce, l);
            GHB256B(s, c->table, (const ubyte*) tmp);
        }
        tmp[0] = tmp[1] = 0;
        tmp[2] = HTONL(nlen >> 29);
        tmp[3] = HTONL(nlen << 3);
        GHB256B(s, c->table, (const ubyte*) tmp);
        c->pCtx->u.ctr[0] = HTONL(s[0]);
        c->pCtx->u.ctr[1] = HTONL(s[1]);
        c->pCtx->u.ctr[2] = HTONL(s[2]);
        c->pCtx->u.ctr[3] = HTONL(s[3]);
        tmp[0] = tmp[1] = tmp[2] = tmp[3] = s[0] = s[1] = s[2] = s[3] = 0;
    }
    else
    {
        memcpy( (ubyte*) c->pCtx->u.ctr, nonce, 12);
        c->pCtx->u.ctr[3] = 0;
        c->pCtx->u.counterBlock[AES_BLOCK_SIZE -1] = 1;
    }

    c->pCtx->offset = 0;

    memset(c->tag4, 0, AES_BLOCK_SIZE);
    GCM_doAESCTR( c,  (ubyte*) c->tag4, AES_BLOCK_SIZE, sizeof(ubyte4));

    /* Hash associated data. */
    if (alen)
    {
        b = alen >> 4;
        l = alen & 15;

        for (i = 0; i < b; i++)
        {
            GHB256B(s, c->table, adata);
            adata += GHASH_BLK_SZ;
        }
        if (l)
        {
            memcpy(tmp, adata, l);
            GHB256B(s, c->table, (const ubyte*) tmp);
        }
    }

    /* save the hash state */
    memcpy( c->s, s, 4 * sizeof(ubyte4));

    return OK;
}


/*---------------------------------------------------------------------------------*/

extern MSTATUS
GCM_update_encrypt_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte *data, ubyte4 dlen)
{
    gcm_ctx_256b *c = (gcm_ctx_256b*)ctx;
    ubyte4 b, l, i;

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    if (OK != getFIPS_powerupStatus(FIPS_ALGO_AES_GCM))
        return getFIPS_powerupStatus(FIPS_ALGO_AES_GCM);
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

    if ( !c || !data )
    {
        return ERR_NULL_POINTER;
    }

    /* encrypt everything */
    GCM_doAESCTR(c, data, dlen, sizeof(ubyte4));

    c->dlen += dlen;

    /* add the cipher text to the hash */
    /* was there something remaining from last round ? */
    if ( c->hashBufferIndex)
    {
        l = AES_BLOCK_SIZE - c->hashBufferIndex;
        if (l > dlen)
        {
            l = dlen;
        }

        memcpy( c->hashBuffer + c->hashBufferIndex, data, l);

        data += l;
        dlen -= l;
        c->hashBufferIndex += l;

        if ( AES_BLOCK_SIZE == c->hashBufferIndex)
        {
            GHB256B(c->s, c->table, c->hashBuffer);
            c->hashBufferIndex = 0;
        }
    }

    /* process the rest */
    b = dlen >> 4;
    l = dlen & 15;

    for ( i = 0; i < b; i++)
    {
        GHB256B(c->s, c->table, data);
        data += GHASH_BLK_SZ;
    }

    if (l)
    {
        memcpy(c->hashBuffer, data, l);
        c->hashBufferIndex = l;
    }

    return OK;
}


/*---------------------------------------------------------------------------------*/

extern MSTATUS
GCM_update_decrypt_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx,
                        ubyte *ct, ubyte4 ctlen)
{
    gcm_ctx_256b *c = (gcm_ctx_256b*)ctx;
    ubyte4 b, l, i;
    ubyte* cipherText;
    ubyte4 cipherTextLen;

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    if (OK != getFIPS_powerupStatus(FIPS_ALGO_AES_GCM))
        return getFIPS_powerupStatus(FIPS_ALGO_AES_GCM);
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

    if ( !c || !ct )
    {
        return ERR_NULL_POINTER;
    }

    cipherText = ct;
    cipherTextLen = ctlen;

    c->dlen += ctlen;

    /* add the cipher text to the hash */
    /* was there something remaining from last round ? */
    if ( c->hashBufferIndex)
    {
        l = AES_BLOCK_SIZE - c->hashBufferIndex;
        if (l > ctlen)
        {
            l = ctlen;
        }

        memcpy( c->hashBuffer + c->hashBufferIndex, ct, l);

        ct += l;
        ctlen -= l;
        c->hashBufferIndex += l;

        if ( AES_BLOCK_SIZE == c->hashBufferIndex)
        {
            GHB256B(c->s, c->table, c->hashBuffer);
            c->hashBufferIndex = 0;
        }
    }

    /* process the rest */
    b = ctlen >> 4;
    l = ctlen & 15;

    for ( i = 0; i < b; i++)
    {
        GHB256B(c->s, c->table, ct);
        ct += GHASH_BLK_SZ;
    }

    if (l)
    {
        memcpy(c->hashBuffer, ct, l);
        c->hashBufferIndex = l;
    }

    /* decrypt everything */
    GCM_doAESCTR( c, cipherText, cipherTextLen, sizeof(ubyte4));

    return OK;
}


/*---------------------------------------------------------------------------------*/

extern MSTATUS
GCM_final_256b( BulkCtx ctx, ubyte tag[/*AES_BLOCK_SIZE*/])
{
    gcm_ctx_256b *c = (gcm_ctx_256b*)ctx;
    ubyte4 tmp[4] = {0};
    ubyte4 i;
    ubyte4 s[4];

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    if (OK != getFIPS_powerupStatus(FIPS_ALGO_AES_GCM))
        return getFIPS_powerupStatus(FIPS_ALGO_AES_GCM);
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

    if ( !c || !tag )
    {
        return ERR_NULL_POINTER;
    }

    s[0] = c->s[0];
    s[1] = c->s[1];
    s[2] = c->s[2];
    s[3] = c->s[3];

    if (c->hashBufferIndex)
    {
        for (i = c->hashBufferIndex; i < AES_BLOCK_SIZE; ++i)
        {
            c->hashBuffer[i] = 0;
        }
        GHB256B(s, c->table, c->hashBuffer);
    }

    /* finish with lengths */
    tmp[0] = HTONL(c->alen>>29);
    tmp[1] = HTONL(c->alen<<3);
    tmp[2] = HTONL(c->dlen>>29);
    tmp[3] = HTONL(c->dlen<<3);

    GHB256B(s, c->table, (const ubyte*) tmp);

    c->tag4[0] ^= HTONL(s[0]);
    c->tag4[1] ^= HTONL(s[1]);
    c->tag4[2] ^= HTONL(s[2]);
    c->tag4[3] ^= HTONL(s[3]);

    memcpy(tag, c->tag4, AES_BLOCK_SIZE);

    return OK;
}

/* assuming data buffer has enough space for a tag as well */
extern MSTATUS
GCM_cipher_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx,
                            ubyte* nonce, ubyte4 nlen,
                            ubyte* adata, ubyte4 alen,
                            ubyte* data, ubyte4 dlen, ubyte4 verifyLen, sbyte4 encrypt)
{
    MSTATUS status = OK;
    ubyte tag[AES_BLOCK_SIZE];

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    if (OK != getFIPS_powerupStatus(FIPS_ALGO_AES_GCM))
        return getFIPS_powerupStatus(FIPS_ALGO_AES_GCM);
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

    if (OK > (status = GCM_init_256b(MOC_SYM(hwAccelCtx) ctx, nonce, nlen, adata, alen)))
        goto exit;

    if (encrypt)
    {
        if (OK > (status = GCM_update_encrypt_256b(MOC_SYM(hwAccelCtx) ctx, data, dlen)))
            goto exit;
    } else
    {
        if (OK > (status = GCM_update_decrypt_256b(MOC_SYM(hwAccelCtx) ctx, data, dlen)))
            goto exit;
    }

    if (OK > (status = GCM_final_256b( ctx, tag)))
        goto exit;

    if (encrypt)
    {
        memcpy(data+dlen, tag, verifyLen);
    }
    else
    {
        if (memcmp( data+dlen, tag, verifyLen))
        {
            status = ERR_CRYPTO_AEAD_FAIL;
        }
    }

exit:
    return status;
}


#endif /* defined(__ENABLE_DIGICERT_SMALL_AES__) && defined(__ENABLE_DIGICERT_GCM_256B__) */
