/*
 * gcm.c
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

/**
@file       gcm.c

@brief      Documentation file for the NanoCrypto GCM API.
@details    This file documents the definitions, enumerations, structures, and
            functions of the NanoCrypto GCM API.

@copydoc    overview_gcm

@flags
To enable the 256&nbsp;Byte, 4&nbsp;KB, and/or 64&nbsp;KB functions in the NanoCrypto GCM API, define the corresponding flags in moptions.h:

+ \c \__ENABLE_DIGICERT_GCM_64K__
+ \c \__ENABLE_DIGICERT_GCM_4K__
+ \c \__ENABLE_DIGICERT_GCM_256B__

@filedoc    gcm.c
*/


/*------------------------------------------------------------------*/

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_GCM_INTERNAL__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif
#include "../crypto/aes.h"
#include "../crypto/aesalgo.h"
#include "../crypto/aes_ctr.h"
#include "../crypto/gcm.h"

#if (defined(__ENABLE_DIGICERT_AES_NI__) || defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__))
#include "../crypto/aesalgo_intel_ni.h"
#endif

#if !defined(__ENABLE_DIGICERT_SMALL_AES__)
#if defined(__ENABLE_DIGICERT_GCM_64K__) || defined(__ENABLE_DIGICERT_GCM_4K__)  || defined(__ENABLE_DIGICERT_GCM_256B__)

#ifdef HTONL
#undef HTONL
#endif

#if !defined(MOC_LITTLE_ENDIAN) && !defined(MOC_BIG_ENDIAN)
#ifdef __RTOS_LINUX__
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define MOC_LITTLE_ENDIAN
#else
#define MOC_BIG_ENDIAN
#endif
#endif


#ifdef __RTOS_QNX__
#if BYTE_ORDER == LITTLE_ENDIAN
#define MOC_LITTLE_ENDIAN
#elif   BYTE_ORDER == BIG_ENDIAN
#define MOC_BIG_ENDIAN
#endif
#endif

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


#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
FIPS_TESTLOG_IMPORT;
#endif



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

#if defined(__ENABLE_DIGICERT_GCM_64K__)

/*-----------------------------------------------------------------------*/
/* build the lookup tables : 16 tables Mi of 256 values
*/

static void GCM_build_hash_table_64k(gcm_ctx_64k *c, ubyte4 hkey[4])
{
    ubyte4 a[4];
    sbyte4 i, j, k, t;

    a[0] = HTONL(hkey[0]);
    a[1] = HTONL(hkey[1]);
    a[2] = HTONL(hkey[2]);
    a[3] = HTONL(hkey[3]);

    /* initialize the tables as described in (1) */
    for (t = 0; t < 16; t++)
    {
        c->table[t][0][0] = c->table[t][0][1] = c->table[t][0][2] =
            c->table[t][0][3] = 0;
        i = 128;
        while (i)
        {
            c->table[t][i][0] = HTONL(a[0]);
            c->table[t][i][1] = HTONL(a[1]);
            c->table[t][i][2] = HTONL(a[2]);
            c->table[t][i][3] = HTONL(a[3]);
            GCM_mul_alpha(a);
            i >>= 1;
        }
    }

    for ( i = 1; i < 256; i <<=1 )
    {
        for ( j = 1; j < i; j++)
        {
            k = i + j;
            for ( t = 0; t < 16; t++)
            {
                c->table[t][k][0] = c->table[t][i][0] ^ c->table[t][j][0];
                c->table[t][k][1] = c->table[t][i][1] ^ c->table[t][j][1];
                c->table[t][k][2] = c->table[t][i][2] ^ c->table[t][j][2];
                c->table[t][k][3] = c->table[t][i][3] ^ c->table[t][j][3];
            }
        }
    }
}

#ifdef MOC_BIG_ENDIAN
#define GMULWI64K(e,t,i,s) \
  e = (ubyte4 *)t[i][s>>24]; t0 = e[0]; t1 = e[1]; t2 = e[2]; t3 = e[3];\
  e = (ubyte4 *)t[i+1][(s>>16)&0xff]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
  e = (ubyte4 *)t[i+2][(s>>8)&0xff]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
  e = (ubyte4 *)t[i+3][s&0xff]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3]

#define GMULW64K(e,t,i,s) \
  e = (ubyte4 *)t[i][s>>24]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
  e = (ubyte4 *)t[i+1][(s>>16)&0xff]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
  e = (ubyte4 *)t[i+2][(s>>8)&0xff]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
  e = (ubyte4 *)t[i+3][s&0xff]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3]
#else
#define GMULWI64K(e,t,i,s) \
  e = (ubyte4 *)t[i][s&0xff]; t0 = e[0]; t1 = e[1]; t2 = e[2]; t3 = e[3];\
  e = (ubyte4 *)t[i+1][(s>>8)&0xff]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
  e = (ubyte4 *)t[i+2][(s>>16)&0xff]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
  e = (ubyte4 *)t[i+3][s>>24]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3]

#define GMULW64K(e,t,i,s) \
  e = (ubyte4 *)t[i][s&0xff]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
  e = (ubyte4 *)t[i+1][(s>>8)&0xff]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
  e = (ubyte4 *)t[i+2][(s>>16)&0xff]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
  e = (ubyte4 *)t[i+3][s>>24]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3]
#endif

#define GHB64K(t, b) \
  s0 ^= ((ubyte4 *)b)[0];        \
  s1 ^= ((ubyte4 *)b)[1];        \
  s2 ^= ((ubyte4 *)b)[2];        \
  s3 ^= ((ubyte4 *)b)[3];        \
  GMULWI64K(entry, t, 0, s0);\
  GMULW64K(entry, t, 4, s1);\
  GMULW64K(entry, t, 8, s2);\
  GMULW64K(entry, t, 12, s3);\
  s0 = t0; \
  s1 = t1; \
  s2 = t2; \
  s3 = t3;


/*--------------------------------------------------------------------------------*/

static MSTATUS
GCM_set_key_64k(MOC_SYM(hwAccelDescr hwAccelCtx) gcm_ctx_64k *c)
{
    ubyte4 hkgen[4] = {0};
    ubyte4 hkey[4];
    MSTATUS status;
    sbyte4 dataLen;

    status = AESALGO_blockEncryptEx (
      MOC_SYM (hwAccelCtx) c->pCtx->pCtx, NULL, (ubyte *)hkgen, AES_BLOCK_SIZE * 8,
      (ubyte *)hkey, &dataLen);
    if (OK != status)
        goto exit;

    GCM_build_hash_table_64k(c, hkey);

exit:
    return status;
}


/*--------------------------------------------------------------------------------*/

extern BulkCtx
GCM_createCtx_64k(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* key, sbyte4 keylen, sbyte4 encrypt)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    AES_CTR_Ctx *pCtx = NULL;
    gcm_ctx_64k *ctx = NULL;
    BulkCtx retVal = NULL;

    ubyte pAesCtrKey[48] = { 0 };

    FIPS_GET_STATUS_RETURN_NULL_IF_BAD(FIPS_ALGO_AES_GCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_GCM,keylen);

#if( defined(__ENABLE_DIGICERT_FIPS_MODULE__) && defined(__FIPS_CMVP_GCM_DEBUG__))
    if (FIPS_TESTLOG_ENABLED)
    {
        FIPS_TESTLOG_FMT(1010, "GCM_createCtx_64k::keylen: %d : key:\n", keylen);
        DEBUG_HEXDUMP(DEBUG_SSL_TRANSPORT, (ubyte*)key, keylen);
        FIPS_TESTLOG(1011, "\n");
    }
#endif /* ( __ENABLE_DIGICERT_FIPS_MODULE__ && __FIPS_CMVP_GCM_DEBUG__ ) */

    switch (keylen)
    {
        default:
            goto exit;

        case 16:
        case 24:
        case 32:
            break;
    }

    status = DIGI_MEMCPY(pAesCtrKey, key, keylen);
    if (OK != status)
        goto exit;

    pCtx = (AES_CTR_Ctx *)CreateAESCTRCtx (
      MOC_SYM(hwAccelCtx) pAesCtrKey, keylen + 16, encrypt);
    if (NULL == pCtx)
        goto exit;

  #if defined(__ENABLE_DIGICERT_AES_NI__)
    /* Do a runtime sanity check */
    /* With ENABLE_DIGICERT_AES_NI defined, we don't have the software option */
    if (!check_for_aes_instructions())
        goto exit;
  #endif

    ctx = MALLOC(sizeof(gcm_ctx_64k));
    if (NULL == ctx)
        goto exit;

    /* zero out all the fields */
    DIGI_MEMSET((ubyte *)ctx, 0x00, sizeof(gcm_ctx_64k));

    ctx->pCtx = pCtx;
    ctx->encrypt = encrypt;

    if (OK > GCM_set_key_64k(MOC_SYM(hwAccelCtx) ctx))
        goto exit;

    retVal = (BulkCtx)ctx;
    pCtx = NULL;
    ctx = NULL;

exit:

    DIGI_MEMSET(pAesCtrKey, 0x00, sizeof(pAesCtrKey));

    if (NULL != pCtx)
    {
        DeleteAESCTRCtx (MOC_SYM(hwAccelCtx) (BulkCtx *)&pCtx);
    }
    if (NULL != ctx)
    {
        FREE(ctx);
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_GCM,keylen);
    return (retVal);
}

/*---------------------------------------------------------------------------------*/

extern MSTATUS
GCM_deleteCtx_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    gcm_ctx_64k *pCtx;
#ifdef __ZEROIZE_TEST__
    int counter = 0;
#endif
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_GCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_GCM,0);

    if (*ctx)
    {
        pCtx = (gcm_ctx_64k *)(*ctx);

        if (NULL != pCtx->pCtx)
        {
            DeleteAESCTRCtx (MOC_SYM(hwAccelCtx) (BulkCtx *)&(pCtx->pCtx));
        }

#ifdef __ZEROIZE_TEST__
        counter = 0;
        FIPS_PRINT("\nAESGCM64k - Before Zeroization\n");
        for( counter = 0; counter < sizeof(gcm_ctx_64k); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)*ctx+counter));
        }
        FIPS_PRINT("\n");
#endif

        DIGI_MEMSET((ubyte *)*ctx, 0x00, sizeof(gcm_ctx_64k));

#ifdef __ZEROIZE_TEST__
        FIPS_PRINT("\nAESGCM64k - After Zeroization\n");
        for( counter = 0; counter < sizeof(gcm_ctx_64k); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)*ctx+counter));
        }
        FIPS_PRINT("\n");
#endif

        FREE(*ctx);
        *ctx = NULL;
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_GCM,0);
    return status;
}

/*---------------------------------------------------------------------------------*/

extern MSTATUS GCM_update_nonce_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pNonce, ubyte4 nonceLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    gcm_ctx_64k *c = (gcm_ctx_64k*)pCtx;
    register ubyte4 t0, t1, t2, t3;
    register ubyte4 *entry;
    register ubyte4 s0 = 0, s1 = 0, s2 = 0, s3 = 0;
    
    if (NULL == pCtx || NULL == pNonce)
        return ERR_NULL_POINTER;
    
    /* validate arguments -- since we use ubyte4 for lengths, the other parameters
     are ok */
    if (0 == nonceLen)
    {
        return ERR_INVALID_ARG;
    }
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_GCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_GCM,0);

    /* zero out the other fields */
    c->dlen = 0;
    c->alen = 0;
    c->hashBufferIndex = 0;
    c->initialized = 0;
    c->aadFinalized = 0;
    c->s[0] = c->s[1] = c->s[2] = c->s[3] = 0;
    
    if (12 != nonceLen)
    {
        ubyte4 tmp[4] = {0};
        ubyte4 b = nonceLen >> 4;
        ubyte4 l = nonceLen & 0x0f;

        while (b--)
        {
            GHB64K(c->table, pNonce);
            pNonce += GHASH_BLK_SZ;
        }
        if (l)
        {
            DIGI_MEMCPY((ubyte*)tmp, pNonce, l);
            GHB64K(c->table, tmp);
        }
        tmp[0] = tmp[1] = 0;
        tmp[2] = HTONL(nonceLen >> 29);
        tmp[3] = HTONL(nonceLen << 3);
        GHB64K(c->table, tmp);
        c->pCtx->u.ctr[0] = s0;
        c->pCtx->u.ctr[1] = s1;
        c->pCtx->u.ctr[2] = s2;
        c->pCtx->u.ctr[3] = s3;
    }
    else
    {
        DIGI_MEMCPY( (ubyte*) c->pCtx->u.ctr, pNonce, 12);

        c->pCtx->u.ctr[3] = 0;
        c->pCtx->u.counterBlock[AES_BLOCK_SIZE -1] = 1;

#if( defined(__ENABLE_DIGICERT_FIPS_MODULE__) && defined(__FIPS_CMVP_GCM_DEBUG__))
	if (FIPS_TESTLOG_ENABLED)
	{
	    FIPS_TESTLOG(1012, "GCM_update_nonce_64k::nonceLen = (12 bytes IV + 4 byte of Counter) : nonce/ctr:\n");
	    DEBUG_HEXDUMP(DEBUG_SSL_TRANSPORT, (ubyte*)c->pCtx->u.ctr, 16);
	    FIPS_TESTLOG(1013, "\n");
	}
#endif /* ( __ENABLE_DIGICERT_FIPS_MODULE__ && __FIPS_CMVP_GCM_DEBUG__ ) */

    }
    c->pCtx->offset = 0;
    
    DIGI_MEMSET((ubyte*)c->tag4, 0, AES_BLOCK_SIZE);
    status = DoAESCTREx(MOC_SYM(hwAccelCtx) c->pCtx, (ubyte*) c->tag4, AES_BLOCK_SIZE, c->encrypt, 0, sizeof(ubyte4));
    if (OK != status)
        goto exit;
    
    /* hashing state is still set to 0 */
    
    c->initialized = 1;
    
exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_AES_GCM,0);
    return status;
}

/*---------------------------------------------------------------------------------*/

extern MSTATUS GCM_update_aad_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pAadData, ubyte4 aadDataLen)
{
    FIPS_LOG_DECL_SESSION;
    gcm_ctx_64k *c = (gcm_ctx_64k*)pCtx;
    ubyte4 b = 0, l = 0, i = 0;
    register ubyte4 t0, t1, t2, t3;
    register ubyte4 *entry;
    register ubyte4 s0, s1, s2, s3;
    

    if (!aadDataLen)  /* Ok no op */
        return OK;
        
    if (NULL == pCtx || NULL == pAadData)
        return ERR_NULL_POINTER;
    
    if (!c->initialized)
        return ERR_AES_UNINITIALIZED_CTX;
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_GCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_GCM,0);

    /* get the hashing state */
    s0 = c->s[0];
    s1 = c->s[1];
    s2 = c->s[2];
    s3 = c->s[3];

    /* update the total aadLen before beginning */
    c->alen += aadDataLen;
    
    /* add the aad data to the hash */
    /* was there something remaining from last round ? */
    if ( c->hashBufferIndex)
    {
        l = AES_BLOCK_SIZE - c->hashBufferIndex;
        if (l > aadDataLen)
        {
            l = aadDataLen;
        }
        
        DIGI_MEMCPY( c->hashBuffer + c->hashBufferIndex, pAadData, l);
        
        pAadData += l;  /* ok to modify passed by value ptr */
        aadDataLen -= l;
        c->hashBufferIndex += l;
        
        if ( AES_BLOCK_SIZE == c->hashBufferIndex)
        {
            ubyte4 *tmp= (ubyte4 *)c->hashBuffer;
            GHB64K(c->table, tmp);
            c->hashBufferIndex = 0;
        }
    }
    
    /* process the rest */
    b = aadDataLen >> 4;
    l = aadDataLen & 0x0f;
    
    for ( i = 0; i < b; i++)
    {
        GHB64K(c->table, pAadData);
        pAadData += GHASH_BLK_SZ;
    }
    
    if (l)
    {
        DIGI_MEMCPY(c->hashBuffer, pAadData, l);
        c->hashBufferIndex = l;
    }

    /* save the hash state */
    c->s[0] = s0;
    c->s[1] = s1;
    c->s[2] = s2;
    c->s[3] = s3;

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_GCM,0);
    return OK;
}

/*---------------------------------------------------------------------------------*/

extern MSTATUS GCM_update_data_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData, ubyte4 dataLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    gcm_ctx_64k *c = (gcm_ctx_64k*)pCtx;
    ubyte4 b = 0, l = 0, i = 0;
    ubyte *pDataStrt = pData;
    ubyte4 origDataLen = dataLen;
    register ubyte4 t0, t1, t2, t3;
    register ubyte4 *entry;
    register ubyte4 s0, s1, s2, s3;
    

    if (!dataLen)
       return OK;  /* ok no-op */

    if ( NULL == pCtx || NULL == pData )
    {
        return ERR_NULL_POINTER;
    }
    
    if (!c->initialized)
        return ERR_AES_UNINITIALIZED_CTX;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_GCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_GCM,0);

    /* get the hashing state */
    s0 = c->s[0];
    s1 = c->s[1];
    s2 = c->s[2];
    s3 = c->s[3];
    
    if (!c->aadFinalized)
    {
        /* pad and process any remaining data in the buffer */
        if (c->hashBufferIndex)
        {
            ubyte4 tmp[4] = {0};
            
            DIGI_MEMCPY((ubyte *) tmp, c->hashBuffer, c->hashBufferIndex);
            GHB64K(c->table, tmp);
            c->hashBufferIndex = 0;
        }
        
        c->aadFinalized = 1;
    }
    
    if (c->encrypt)
    {
        /* encrypt everything */
        if (OK > (status = DoAESCTREx(MOC_SYM(hwAccelCtx) c->pCtx, pDataStrt, dataLen, 1, 0, sizeof(ubyte4))))
        {
            goto exit;
        }
    }
    
    c->dlen += dataLen;
    
    /* add the cipher text to the hash */
    /* was there something remaining from last round ? */
    if ( c->hashBufferIndex)
    {
        l = AES_BLOCK_SIZE - c->hashBufferIndex;
        if (l > dataLen)
        {
            l = dataLen;
        }
        
        DIGI_MEMCPY( c->hashBuffer + c->hashBufferIndex, pData, l);
        
        pData += l;
        dataLen -= l;
        c->hashBufferIndex += l;
        
        if ( AES_BLOCK_SIZE == c->hashBufferIndex)
        {
            ubyte4 *tmp= (ubyte4 *)c->hashBuffer;
            GHB64K(c->table, tmp);
            c->hashBufferIndex = 0;
        }
    }
    
    /* process the rest */
    b = dataLen >> 4;
    l = dataLen & 0x0f;
    
    for ( i = 0; i < b; i++)
    {
        GHB64K(c->table, pData);
        pData += GHASH_BLK_SZ;
    }
    
    if (l)
    {
        DIGI_MEMCPY(c->hashBuffer, pData, l);
        c->hashBufferIndex = l;
    }
    
    /* save the hash state */
    c->s[0] = s0;
    c->s[1] = s1;
    c->s[2] = s2;
    c->s[3] = s3;
    
    if (!c->encrypt)
    {
        /* decrypt everything */
        if (OK > (status = DoAESCTREx(MOC_SYM(hwAccelCtx) c->pCtx, pDataStrt, origDataLen, 0, 0, sizeof(ubyte4))))
        {
            goto exit;
        }
    }

exit:

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_GCM,0);
    return status;
}

/*---------------------------------------------------------------------------------*/

extern MSTATUS GCM_final_ex_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pTag, ubyte4 tagLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    ubyte4 tmp[4] = {0};
    gcm_ctx_64k *c = (gcm_ctx_64k*) pCtx;
    ubyte4 i = 0;
    register ubyte4 t0, t1, t2, t3;
    register ubyte4 *entry;
    register ubyte4 s0, s1, s2, s3;
    ubyte4 *tmp2 = NULL;

    if ( NULL == pCtx || NULL == pTag)
    {
        return ERR_NULL_POINTER;
    }
    
    if (!c->initialized)
        return ERR_AES_UNINITIALIZED_CTX;
    
    if (!tagLen || tagLen > AES_BLOCK_SIZE)
        return ERR_INVALID_ARG;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_GCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_GCM,0);

    s0 = c->s[0];
    s1 = c->s[1];
    s2 = c->s[2];
    s3 = c->s[3];
    
    if (!c->aadFinalized)
    {
        /* pad and process any remaining data in the buffer */
        if (c->hashBufferIndex)
        {
            DIGI_MEMCPY((ubyte *) tmp, c->hashBuffer, c->hashBufferIndex);
            GHB64K(c->table, tmp);
            c->hashBufferIndex = 0;
            tmp[0] = 0; tmp[1] = 0; tmp[2] = 0; tmp[3] = 0;
        }
        
        c->aadFinalized = 1;
    }
    
    if (c->hashBufferIndex)
    {
        for (i = c->hashBufferIndex; i < AES_BLOCK_SIZE; ++i)
        {
            c->hashBuffer[i] = 0;
        }
        tmp2 = (ubyte4 *)c->hashBuffer;
        GHB64K(c->table, tmp2);
    }
    
    /* finish with lengths */
    tmp[0] = HTONL(c->alen>>29);
    tmp[1] = HTONL(c->alen<<3);
    tmp[2] = HTONL(c->dlen>>29);
    tmp[3] = HTONL(c->dlen<<3);
    
    GHB64K(c->table, tmp);
    
    c->tag4[0] ^= (s0);
    c->tag4[1] ^= (s1);
    c->tag4[2] ^= (s2);
    c->tag4[3] ^= (s3);
    
    if (c->encrypt)
    {
        status = DIGI_MEMCPY(pTag, (ubyte *) c->tag4, tagLen);
    }
    else
    {
        sbyte4 cmp = -1;
        DIGI_CTIME_MATCH(pTag, (ubyte *) c->tag4, tagLen, &cmp);
        
        if (cmp)
            status = ERR_CRYPTO_AEAD_FAIL;
        else
            status = OK;
    }
    
    FIPS_LOG_END_ALG(FIPS_ALGO_AES_GCM,0);
    return status;
}

/*---------------------------------------------------------------------------------*/

extern MSTATUS GCM_init_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx,
                            ubyte* nonce, ubyte4 nlen,
                            ubyte* adata, ubyte4 alen)
{
    MSTATUS status = OK;

    /* input validity checked by the below calls */
    status = GCM_update_nonce_64k(MOC_SYM(hwAccelCtx) ctx, nonce, nlen);
    if (OK != status)
        goto exit;
    
    if (alen)
    {
        status = GCM_update_aad_64k(MOC_SYM(hwAccelCtx) ctx, adata, alen);
    }
    
exit:
    
    return status;
}

/*--------------------------------------------------------------------------------*/

extern MSTATUS GCM_update_encrypt_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte *data, ubyte4 dlen)
{
    if (NULL == ctx)
        return ERR_NULL_POINTER;

    if (!((gcm_ctx_64k *) ctx)->encrypt)
        return ERR_INVALID_ARG;
    
    return GCM_update_data_64k(MOC_SYM(hwAccelCtx) ctx, data, dlen);
}

/*--------------------------------------------------------------------------------*/

extern MSTATUS GCM_update_decrypt_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte *ct, ubyte4 ctlen)
{
    if (NULL == ctx)
        return ERR_NULL_POINTER;
    
    if (((gcm_ctx_64k *) ctx)->encrypt)
        return ERR_INVALID_ARG;
    
    return GCM_update_data_64k(MOC_SYM(hwAccelCtx) ctx, ct, ctlen);
}

/*--------------------------------------------------------------------------------*/

extern MSTATUS GCM_final_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte tag[/*AES_BLOCK_SIZE*/])
{
    MSTATUS status = OK;
    
    if (NULL == ctx)
        return ERR_NULL_POINTER;
    
    if (((gcm_ctx_64k *) ctx)->encrypt)
    {
        status = GCM_final_ex_64k(MOC_SYM(hwAccelCtx) ctx, tag, AES_BLOCK_SIZE);
    }
    else
    {
        ubyte dummyTag[AES_BLOCK_SIZE] = {0};
        
        /* pass in dummyTag, expect fail */
        GCM_final_ex_64k(MOC_SYM(hwAccelCtx) ctx, dummyTag, AES_BLOCK_SIZE);
        
        /* copy the internal (correct) tag out */
        status = DIGI_MEMCPY(tag, (ubyte *) ((gcm_ctx_64k *) ctx)->tag4, AES_BLOCK_SIZE);

        /* dummyTag doesn't get set, no need to zero it */
    }
    
    return status;
}

/*--------------------------------------------------------------------------------*/

extern MSTATUS
GCM_clone_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx)
{
    MSTATUS status;
    gcm_ctx_64k *pNewCtx = NULL;
    AES_CTR_Ctx *pCtrCtx = NULL;

    if ( (NULL == pCtx) || (NULL == ppNewCtx) )
    {
        return ERR_NULL_POINTER;
    }

    status = DIGI_MALLOC((void **)&pNewCtx, sizeof(gcm_ctx_64k));
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)pNewCtx, (void *)pCtx, sizeof(gcm_ctx_64k));
    if (OK != status)
        goto exit;

    status = CloneAESCTRCtx(MOC_SYM(hwAccelCtx) ((gcm_ctx_64k *)pCtx)->pCtx, (BulkCtx *)&pCtrCtx);
    if (OK != status)
        goto exit;

    pNewCtx->pCtx = pCtrCtx;
    pCtrCtx = NULL;
    *ppNewCtx = pNewCtx;
    pNewCtx = NULL;

exit:
    if (NULL != pNewCtx)
    {
        DIGI_FREE((void **)&pNewCtx);
    }
    if (NULL != pCtrCtx)
    {
        DeleteAESCTRCtx(MOC_SYM(hwAccelCtx) (BulkCtx *)&pCtrCtx);
    }

    return status;
}

/*--------------------------------------------------------------------------------*/

/* assuming data buffer has enough space for TWO tags as well */
extern MSTATUS
GCM_cipher_64k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx,
                            ubyte* nonce, ubyte4 nlen,
                            ubyte* adata, ubyte4 alen,
                            ubyte* data, ubyte4 dlen, ubyte4 verifyLen, sbyte4 encrypt)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

#if( defined(__ENABLE_DIGICERT_FIPS_MODULE__) && defined(__FIPS_CMVP_GCM_DEBUG__))
    if (FIPS_TESTLOG_ENABLED)
    {
        FIPS_TESTLOG_FMT(1014, "GCM_cipher_64k::nonceLen = %d : nonce:\n", nlen);
        DEBUG_HEXDUMP(DEBUG_SSL_TRANSPORT, nonce, nlen);
        FIPS_TESTLOG(1015, "\n");
    }
#endif /* ( __ENABLE_DIGICERT_FIPS_MODULE__ && __FIPS_CMVP_GCM_DEBUG__ ) */

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_GCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_GCM,0);
    
    if (NULL == ctx)
       return ERR_NULL_POINTER;

    /* set encrypt flag so rest of the calls work correctly */
    ((gcm_ctx_64k *) ctx)->encrypt = encrypt;

    if (OK > (status = GCM_init_64k(MOC_SYM(hwAccelCtx) ctx, nonce, nlen, adata, alen)))
        goto exit;

    if (OK > (status = GCM_update_data_64k(MOC_SYM(hwAccelCtx) ctx, data, dlen)))
        goto exit;

    status = GCM_final_ex_64k(MOC_SYM(hwAccelCtx) ctx, data + dlen, verifyLen);

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_AES_GCM,0);
    return status;
}

#endif /* __ENABLE_DIGICERT_GCM_64K__ */

/*--------------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_GCM_4K__)

/* Beginning of 4K tables implementation. */
static ubyte4 GCM_rtable_4k[256] =
{
    0x00000000, 0x01c20000, 0x03840000, 0x02460000, 0x07080000, 0x06ca0000,
    0x048c0000, 0x054e0000, 0x0e100000, 0x0fd20000, 0x0d940000, 0x0c560000,
    0x09180000, 0x08da0000, 0x0a9c0000, 0x0b5e0000, 0x1c200000, 0x1de20000,
    0x1fa40000, 0x1e660000, 0x1b280000, 0x1aea0000, 0x18ac0000, 0x196e0000,
    0x12300000, 0x13f20000, 0x11b40000, 0x10760000, 0x15380000, 0x14fa0000,
    0x16bc0000, 0x177e0000, 0x38400000, 0x39820000, 0x3bc40000, 0x3a060000,
    0x3f480000, 0x3e8a0000, 0x3ccc0000, 0x3d0e0000, 0x36500000, 0x37920000,
    0x35d40000, 0x34160000, 0x31580000, 0x309a0000, 0x32dc0000, 0x331e0000,
    0x24600000, 0x25a20000, 0x27e40000, 0x26260000, 0x23680000, 0x22aa0000,
    0x20ec0000, 0x212e0000, 0x2a700000, 0x2bb20000, 0x29f40000, 0x28360000,
    0x2d780000, 0x2cba0000, 0x2efc0000, 0x2f3e0000, 0x70800000, 0x71420000,
    0x73040000, 0x72c60000, 0x77880000, 0x764a0000, 0x740c0000, 0x75ce0000,
    0x7e900000, 0x7f520000, 0x7d140000, 0x7cd60000, 0x79980000, 0x785a0000,
    0x7a1c0000, 0x7bde0000, 0x6ca00000, 0x6d620000, 0x6f240000, 0x6ee60000,
    0x6ba80000, 0x6a6a0000, 0x682c0000, 0x69ee0000, 0x62b00000, 0x63720000,
    0x61340000, 0x60f60000, 0x65b80000, 0x647a0000, 0x663c0000, 0x67fe0000,
    0x48c00000, 0x49020000, 0x4b440000, 0x4a860000, 0x4fc80000, 0x4e0a0000,
    0x4c4c0000, 0x4d8e0000, 0x46d00000, 0x47120000, 0x45540000, 0x44960000,
    0x41d80000, 0x401a0000, 0x425c0000, 0x439e0000, 0x54e00000, 0x55220000,
    0x57640000, 0x56a60000, 0x53e80000, 0x522a0000, 0x506c0000, 0x51ae0000,
    0x5af00000, 0x5b320000, 0x59740000, 0x58b60000, 0x5df80000, 0x5c3a0000,
    0x5e7c0000, 0x5fbe0000, 0xe1000000, 0xe0c20000, 0xe2840000, 0xe3460000,
    0xe6080000, 0xe7ca0000, 0xe58c0000, 0xe44e0000, 0xef100000, 0xeed20000,
    0xec940000, 0xed560000, 0xe8180000, 0xe9da0000, 0xeb9c0000, 0xea5e0000,
    0xfd200000, 0xfce20000, 0xfea40000, 0xff660000, 0xfa280000, 0xfbea0000,
    0xf9ac0000, 0xf86e0000, 0xf3300000, 0xf2f20000, 0xf0b40000, 0xf1760000,
    0xf4380000, 0xf5fa0000, 0xf7bc0000, 0xf67e0000, 0xd9400000, 0xd8820000,
    0xdac40000, 0xdb060000, 0xde480000, 0xdf8a0000, 0xddcc0000, 0xdc0e0000,
    0xd7500000, 0xd6920000, 0xd4d40000, 0xd5160000, 0xd0580000, 0xd19a0000,
    0xd3dc0000, 0xd21e0000, 0xc5600000, 0xc4a20000, 0xc6e40000, 0xc7260000,
    0xc2680000, 0xc3aa0000, 0xc1ec0000, 0xc02e0000, 0xcb700000, 0xcab20000,
    0xc8f40000, 0xc9360000, 0xcc780000, 0xcdba0000, 0xcffc0000, 0xce3e0000,
    0x91800000, 0x90420000, 0x92040000, 0x93c60000, 0x96880000, 0x974a0000,
    0x950c0000, 0x94ce0000, 0x9f900000, 0x9e520000, 0x9c140000, 0x9dd60000,
    0x98980000, 0x995a0000, 0x9b1c0000, 0x9ade0000, 0x8da00000, 0x8c620000,
    0x8e240000, 0x8fe60000, 0x8aa80000, 0x8b6a0000, 0x892c0000, 0x88ee0000,
    0x83b00000, 0x82720000, 0x80340000, 0x81f60000, 0x84b80000, 0x857a0000,
    0x873c0000, 0x86fe0000, 0xa9c00000, 0xa8020000, 0xaa440000, 0xab860000,
    0xaec80000, 0xaf0a0000, 0xad4c0000, 0xac8e0000, 0xa7d00000, 0xa6120000,
    0xa4540000, 0xa5960000, 0xa0d80000, 0xa11a0000, 0xa35c0000, 0xa29e0000,
    0xb5e00000, 0xb4220000, 0xb6640000, 0xb7a60000, 0xb2e80000, 0xb32a0000,
    0xb16c0000, 0xb0ae0000, 0xbbf00000, 0xba320000, 0xb8740000, 0xb9b60000,
    0xbcf80000, 0xbd3a0000, 0xbf7c0000, 0xbebe0000
};


/*--------------------------------------------------------------------------------*/

static void GCM_build_hash_table_4k(gcm_ctx_4k *c, ubyte4 hkey[4])
{
    register sbyte4 i = 64, j, k;
    register ubyte4 w, x, y, z, carry;

    c->table[0][0] = c->table[0][1] = c->table[0][2] = c->table[0][3] = 0;
    w = HTONL(hkey[0]);
    x = HTONL(hkey[1]);
    y = HTONL(hkey[2]);
    z = HTONL(hkey[3]);

    c->table[0x80][0] = w;
    c->table[0x80][1] = x;
    c->table[0x80][2] = y;
    c->table[0x80][3] = z;

    while (i)
    {
        carry = z & 1;
        z >>= 1;
        z |= (y & 1) << 31;
        y >>= 1;
        y |= (x & 1) << 31;
        x >>= 1;
        x |= (w & 1) << 31;
        w >>= 1;
        if (carry)
            w ^= GHASH_ALPHA;

        c->table[i][0] = w;
        c->table[i][1] = x;
        c->table[i][2] = y;
        c->table[i][3] = z;

        i >>= 1;
    }
    for (i = 1; i < 256; i <<= 1)
    {
        for (j = 1; j < i; j++)
        {
            k = i + j;
            c->table[k][0] = c->table[i][0] ^ c->table[j][0];
            c->table[k][1] = c->table[i][1] ^ c->table[j][1];
            c->table[k][2] = c->table[i][2] ^ c->table[j][2];
            c->table[k][3] = c->table[i][3] ^ c->table[j][3];
        }
    }
}

#define SHIFT4K() \
 tt = t3 & 0xff; t3 >>= 8; t3 |= (t2 << 24); t2 >>= 8; t2 |= (t1 << 24);\
 t1 >>= 8; t1 |= (t0 << 24); t0 >>=8; t0 ^= GCM_rtable_4k[tt]
#define GMULWI4K(e,t,s) \
  e = (ubyte4 *)t[s&0xff]; t0 = e[0]; t1 = e[1]; t2 = e[2]; t3 = e[3];\
  SHIFT4K();\
  e = (ubyte4 *)t[(s>>8)&0xff];t0 ^= e[0];t1 ^= e[1];t2 ^= e[2];t3 ^= e[3];\
  SHIFT4K();\
  e = (ubyte4 *)t[(s>>16)&0xff];t0 ^= e[0];t1 ^= e[1];t2 ^= e[2];t3 ^= e[3];\
  SHIFT4K();\
  e = (ubyte4 *)t[s>>24];t0 ^= e[0];t1 ^= e[1];t2 ^= e[2];t3 ^= e[3]

#define GMULW4K(e,t,s) \
  SHIFT4K();\
  e = (ubyte4 *)t[s&0xff]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
  SHIFT4K();\
  e = (ubyte4 *)t[(s>>8)&0xff];t0 ^= e[0];t1 ^= e[1];t2 ^= e[2];t3 ^= e[3];\
  SHIFT4K();\
  e = (ubyte4 *)t[(s>>16)&0xff];t0 ^= e[0];t1 ^= e[1];t2 ^= e[2];t3 ^= e[3];\
  SHIFT4K();\
  e = (ubyte4 *)t[s>>24];t0 ^= e[0];t1 ^= e[1];t2 ^= e[2];t3 ^= e[3];

#define GHB4K(t,b)\
  s0 ^= HTONL(((ubyte4 *)b)[0]); \
  s1 ^= HTONL(((ubyte4 *)b)[1]); \
  s2 ^= HTONL(((ubyte4 *)b)[2]); \
  s3 ^= HTONL(((ubyte4 *)b)[3]); \
  GMULWI4K(entry, t, s3); \
  GMULW4K(entry, t, s2);\
  GMULW4K(entry, t, s1);\
  GMULW4K(entry, t, s0);\
  s0 = t0; \
  s1 = t1; \
  s2 = t2; \
  s3 = t3;


/*--------------------------------------------------------------------------------*/

static MSTATUS
GCM_set_key_4k(MOC_SYM(hwAccelDescr hwAccelCtx) gcm_ctx_4k *c)
{
    ubyte4 hkgen[4] = {0};
    ubyte4 hkey[4];
    MSTATUS status;
    sbyte4 dataLen;

    status = AESALGO_blockEncryptEx (
      MOC_SYM (hwAccelCtx) c->pCtx->pCtx, NULL, (ubyte *)hkgen, AES_BLOCK_SIZE * 8,
      (ubyte *)hkey, &dataLen);
    if (OK != status)
        goto exit;

    GCM_build_hash_table_4k(c, hkey);

exit:
    return status;
}

/*--------------------------------------------------------------------------------*/

extern BulkCtx
GCM_createCtx_4k(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* key, sbyte4 keylen, sbyte4 encrypt)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status;

    AES_CTR_Ctx *pCtx = NULL;
    gcm_ctx_4k *ctx = NULL;
    BulkCtx retVal = NULL;

    ubyte pAesCtrKey[48] = { 0 };

    FIPS_GET_STATUS_RETURN_NULL_IF_BAD(FIPS_ALGO_AES_GCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_GCM,keylen);

    switch (keylen)
    {
        default:
            goto exit;

        case 16:
        case 24:
        case 32:
            break;
    }

    status = DIGI_MEMCPY(pAesCtrKey, key, keylen);
    if (OK != status)
        goto exit;

    pCtx = (AES_CTR_Ctx *)CreateAESCTRCtx (
      MOC_SYM(hwAccelCtx) pAesCtrKey, keylen + 16, encrypt);
    if (NULL == pCtx)
        goto exit;

  #if defined(__ENABLE_DIGICERT_AES_NI__)
    /* Do a runtime sanity check */
    /* With ENABLE_DIGICERT_AES_NI defined, we don't have the software option */
    if (!check_for_aes_instructions())
        goto exit;
  #endif

    ctx = MALLOC(sizeof(gcm_ctx_4k));
    if (NULL == ctx)
        goto exit;

    /* zero out all the fields */
    DIGI_MEMSET((ubyte *)ctx, 0x00, sizeof(gcm_ctx_4k));

    ctx->pCtx = pCtx;
    ctx->encrypt = encrypt;

    if (OK > GCM_set_key_4k(MOC_SYM(hwAccelCtx) ctx))
        goto exit;

    retVal = (BulkCtx)ctx;
    pCtx = NULL;
    ctx = NULL;

exit:

    DIGI_MEMSET(pAesCtrKey, 0x00, sizeof(pAesCtrKey));

    if (NULL != pCtx)
    {
        DeleteAESCTRCtx (MOC_SYM(hwAccelCtx) (BulkCtx *)&pCtx);
    }
    if (NULL != ctx)
    {
        FREE(ctx);
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_GCM,keylen);
    return (retVal);
}

/*---------------------------------------------------------------------------------*/

extern MSTATUS
GCM_deleteCtx_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    gcm_ctx_4k *pCtx;
#ifdef __ZEROIZE_TEST__
    int counter = 0;
#endif

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_GCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_GCM,0);

    if (*ctx)
    {
        pCtx = (gcm_ctx_4k *)(*ctx);

        if (NULL != pCtx->pCtx)
        {
            DeleteAESCTRCtx (MOC_SYM(hwAccelCtx) (BulkCtx *)&(pCtx->pCtx));
        }

#ifdef __ZEROIZE_TEST__
        counter = 0;
        FIPS_PRINT("\nAESGCM4k - Before Zeroization\n");
        for( counter = 0; counter < sizeof(gcm_ctx_4k); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)*ctx+counter));
        }
        FIPS_PRINT("\n");
#endif

        DIGI_MEMSET((ubyte *)*ctx, 0x00, sizeof(gcm_ctx_4k));

#ifdef __ZEROIZE_TEST__
        FIPS_PRINT("\nAESGCM4k - After Zeroization\n");
        for( counter = 0; counter < sizeof(gcm_ctx_4k); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)*ctx+counter));
        }
        FIPS_PRINT("\n");
#endif

        FREE(*ctx);
        *ctx = NULL;
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_GCM,0);
    return status;
}

/*--------------------------------------------------------------------------------*/

extern MSTATUS GCM_update_nonce_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pNonce, ubyte4 nonceLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    gcm_ctx_4k *c = (gcm_ctx_4k*)pCtx;
    register ubyte4 t0, t1, t2, t3, tt;
    register ubyte4 *entry;
    register ubyte4 s0 = 0, s1 = 0, s2 = 0, s3 = 0;
    
    if (NULL == pCtx || NULL == pNonce)
        return ERR_NULL_POINTER;
    
    /* validate arguments -- since we use ubyte4 for lengths, the other parameters
     are ok */
    if (0 == nonceLen)
    {
        return ERR_INVALID_ARG;
    }
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_GCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_GCM,0);

    /* zero out the other fields */
    c->dlen = 0;
    c->alen = 0;
    c->hashBufferIndex = 0;
    c->initialized = 0;
    c->aadFinalized = 0;
    c->s[0] = c->s[1] = c->s[2] = c->s[3] = 0;
    
    if (12 != nonceLen)
    {
        ubyte4 tmp[4] = {0};
        ubyte4 b = nonceLen >> 4;
        ubyte4 l = nonceLen & 0x0f;
        
        while (b--)
        {
            GHB4K(c->table, pNonce);
            pNonce += GHASH_BLK_SZ;
        }
        if (l)
        {
            DIGI_MEMCPY((ubyte*)tmp, pNonce, l);
            GHB4K(c->table, tmp);
        }
        tmp[0] = tmp[1] = 0;
        tmp[2] = HTONL(nonceLen >> 29);
        tmp[3] = HTONL(nonceLen << 3);
        GHB4K(c->table, tmp);
        c->pCtx->u.ctr[0] = HTONL(s0);
        c->pCtx->u.ctr[1] = HTONL(s1);
        c->pCtx->u.ctr[2] = HTONL(s2);
        c->pCtx->u.ctr[3] = HTONL(s3);
    }
    else
    {
        DIGI_MEMCPY( (ubyte*) c->pCtx->u.ctr, pNonce, 12);
        c->pCtx->u.ctr[3] = 0;
        c->pCtx->u.counterBlock[AES_BLOCK_SIZE -1] = 1;
    }
    c->pCtx->offset = 0;
    
    DIGI_MEMSET((ubyte*)c->tag4, 0, AES_BLOCK_SIZE);
    status = DoAESCTREx(MOC_SYM(hwAccelCtx) c->pCtx, (ubyte*) c->tag4, AES_BLOCK_SIZE, c->encrypt, 0, sizeof(ubyte4));
    if (OK != status)
        goto exit;
    
    /* hashing state is still set to 0 */
    
    c->initialized = 1;
    
exit:

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_GCM,0);
    return status;
}

/*---------------------------------------------------------------------------------*/

extern MSTATUS GCM_update_aad_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pAadData, ubyte4 aadDataLen)
{
    FIPS_LOG_DECL_SESSION;
    gcm_ctx_4k *c = (gcm_ctx_4k*)pCtx;
    ubyte4 b = 0, l = 0, i = 0;
    register ubyte4 t0, t1, t2, t3, tt;
    register ubyte4 *entry;
    register ubyte4 s0, s1, s2, s3;
    
    if (!aadDataLen)  /* Ok no op */
        return OK;
    
    if (NULL == pCtx || NULL == pAadData)
        return ERR_NULL_POINTER;
    
    if (!c->initialized)
        return ERR_AES_UNINITIALIZED_CTX;
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_GCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_GCM,0);

    /* get the hashing state */
    s0 = c->s[0];
    s1 = c->s[1];
    s2 = c->s[2];
    s3 = c->s[3];
    
    /* update the total aadLen before beginning */
    c->alen += aadDataLen;
    
    /* add the aad data to the hash */
    /* was there something remaining from last round ? */
    if ( c->hashBufferIndex)
    {
        l = AES_BLOCK_SIZE - c->hashBufferIndex;
        if (l > aadDataLen)
        {
            l = aadDataLen;
        }
        
        DIGI_MEMCPY( c->hashBuffer + c->hashBufferIndex, pAadData, l);
        
        pAadData += l;  /* ok to modify passed by value ptr */
        aadDataLen -= l;
        c->hashBufferIndex += l;
        
        if ( AES_BLOCK_SIZE == c->hashBufferIndex)
        {
            ubyte4 *tmp= (ubyte4 *)c->hashBuffer;
            GHB4K(c->table, tmp);
            c->hashBufferIndex = 0;
        }
    }
    
    /* process the rest */
    b = aadDataLen >> 4;
    l = aadDataLen & 0x0f;
    
    for ( i = 0; i < b; i++)
    {
        GHB4K(c->table, pAadData);
        pAadData += GHASH_BLK_SZ;
    }
    
    if (l)
    {
        DIGI_MEMCPY(c->hashBuffer, pAadData, l);
        c->hashBufferIndex = l;
    }
    
    /* save the hash state */
    c->s[0] = s0;
    c->s[1] = s1;
    c->s[2] = s2;
    c->s[3] = s3;
    
    FIPS_LOG_END_ALG(FIPS_ALGO_AES_GCM,0);
    return OK;
}

/*---------------------------------------------------------------------------------*/

extern MSTATUS GCM_update_data_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData, ubyte4 dataLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    gcm_ctx_4k *c = (gcm_ctx_4k*)pCtx;
    ubyte4 b = 0, l = 0, i = 0;
    ubyte *pDataStrt = pData;
    ubyte4 origDataLen = dataLen;
    register ubyte4 t0, t1, t2, t3, tt;
    register ubyte4 *entry;
    register ubyte4 s0, s1, s2, s3;
    
    if (!dataLen)
        return OK;  /* ok no-op */
    
    if ( NULL == pCtx || NULL == pData )
    {
        return ERR_NULL_POINTER;
    }
    
    if (!c->initialized)
        return ERR_AES_UNINITIALIZED_CTX;
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_GCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_GCM,0);

    /* get the hashing state */
    s0 = c->s[0];
    s1 = c->s[1];
    s2 = c->s[2];
    s3 = c->s[3];
    
    if (!c->aadFinalized)
    {
        /* pad and process any remaining data in the buffer */
        if (c->hashBufferIndex)
        {
            ubyte4 tmp[4] = {0};
            
            DIGI_MEMCPY((ubyte *) tmp, c->hashBuffer, c->hashBufferIndex);
            GHB4K(c->table, tmp);
            c->hashBufferIndex = 0;
        }
        
        c->aadFinalized = 1;
    }
    
    if (c->encrypt)
    {
        /* encrypt everything */
        if (OK > (status = DoAESCTREx(MOC_SYM(hwAccelCtx) c->pCtx, pDataStrt, dataLen, 1, 0, sizeof(ubyte4))))
        {
            goto exit;
        }
    }
    
    c->dlen += dataLen;
    
    /* add the cipher text to the hash */
    /* was there something remaining from last round ? */
    if ( c->hashBufferIndex)
    {
        l = AES_BLOCK_SIZE - c->hashBufferIndex;
        if (l > dataLen)
        {
            l = dataLen;
        }
        
        DIGI_MEMCPY( c->hashBuffer + c->hashBufferIndex, pData, l);
        
        pData += l;
        dataLen -= l;
        c->hashBufferIndex += l;
        
        if ( AES_BLOCK_SIZE == c->hashBufferIndex)
        {
            ubyte4 *tmp= (ubyte4 *)c->hashBuffer;
            GHB4K(c->table, tmp);
            c->hashBufferIndex = 0;
        }
    }
    
    /* process the rest */
    b = dataLen >> 4;
    l = dataLen & 0x0f;
    
    for ( i = 0; i < b; i++)
    {
        GHB4K(c->table, pData);
        pData += GHASH_BLK_SZ;
    }
    
    if (l)
    {
        DIGI_MEMCPY(c->hashBuffer, pData, l);
        c->hashBufferIndex = l;
    }
    
    /* save the hash state */
    c->s[0] = s0;
    c->s[1] = s1;
    c->s[2] = s2;
    c->s[3] = s3;
    
    if (!c->encrypt)
    {
        /* decrypt everything */
        if (OK > (status = DoAESCTREx(MOC_SYM(hwAccelCtx) c->pCtx, pDataStrt, origDataLen, 0, 0, sizeof(ubyte4))))
        {
            goto exit;
        }
    }
    
exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_AES_GCM,0);
    return status;
}

/*---------------------------------------------------------------------------------*/

extern MSTATUS GCM_final_ex_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pTag, ubyte4 tagLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    ubyte4 tmp[4] = {0};
    gcm_ctx_4k *c = (gcm_ctx_4k*) pCtx;
    ubyte4 i = 0;
    register ubyte4 t0, t1, t2, t3, tt;
    register ubyte4 *entry;
    register ubyte4 s0, s1, s2, s3;
    ubyte4 *tmp2 = NULL;
    
    if ( NULL == pCtx || NULL == pTag)
    {
        return ERR_NULL_POINTER;
    }
    
    if (!c->initialized)
        return ERR_AES_UNINITIALIZED_CTX;
    
    if (!tagLen || tagLen > AES_BLOCK_SIZE)
        return ERR_INVALID_ARG;
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_GCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_GCM,0);

    s0 = c->s[0];
    s1 = c->s[1];
    s2 = c->s[2];
    s3 = c->s[3];
    
    if (!c->aadFinalized)
    {
        /* pad and process any remaining data in the buffer */
        if (c->hashBufferIndex)
        {
            DIGI_MEMCPY((ubyte *) tmp, c->hashBuffer, c->hashBufferIndex);
            GHB4K(c->table, tmp);
            c->hashBufferIndex = 0;
            tmp[0] = 0; tmp[1] = 0; tmp[2] = 0; tmp[3] = 0;
        }
        
        c->aadFinalized = 1;
    }
    
    if (c->hashBufferIndex)
    {
        for (i = c->hashBufferIndex; i < AES_BLOCK_SIZE; ++i)
        {
            c->hashBuffer[i] = 0;
        }
        tmp2 = (ubyte4 *)c->hashBuffer;
        GHB4K(c->table, tmp2);
    }
    
    /* finish with lengths */
    tmp[0] = HTONL(c->alen>>29);
    tmp[1] = HTONL(c->alen<<3);
    tmp[2] = HTONL(c->dlen>>29);
    tmp[3] = HTONL(c->dlen<<3);
    
    GHB4K(c->table, tmp);
    
    c->tag4[0] ^= HTONL(s0);
    c->tag4[1] ^= HTONL(s1);
    c->tag4[2] ^= HTONL(s2);
    c->tag4[3] ^= HTONL(s3);

    if (c->encrypt)
    {
        status = DIGI_MEMCPY(pTag, (ubyte *) c->tag4, tagLen);
    }
    else
    {
        sbyte4 cmp = -1;
        DIGI_CTIME_MATCH(pTag, (ubyte *) c->tag4, tagLen, &cmp);
        
        if (cmp)
            status = ERR_CRYPTO_AEAD_FAIL;
        else
            status = OK;
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_GCM,0);
    return status;
}

/*---------------------------------------------------------------------------------*/

extern MSTATUS GCM_init_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx,
                            ubyte* nonce, ubyte4 nlen,
                            ubyte* adata, ubyte4 alen)
{
    MSTATUS status = OK;
    
    /* input validity checked by the below calls */
    status = GCM_update_nonce_4k(MOC_SYM(hwAccelCtx) ctx, nonce, nlen);
    if (OK != status)
        goto exit;
    
    if (alen)
    {
        status = GCM_update_aad_4k(MOC_SYM(hwAccelCtx) ctx, adata, alen);
    }
    
exit:
    
    return status;
}

/*--------------------------------------------------------------------------------*/

extern MSTATUS GCM_update_encrypt_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte *data, ubyte4 dlen)
{
    if (NULL == ctx)
        return ERR_NULL_POINTER;
    
    if (!((gcm_ctx_4k *) ctx)->encrypt)
        return ERR_INVALID_ARG;

    return GCM_update_data_4k(MOC_SYM(hwAccelCtx) ctx, data, dlen);
}

/*--------------------------------------------------------------------------------*/

extern MSTATUS GCM_update_decrypt_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte *ct, ubyte4 ctlen)
{
    if (NULL == ctx)
        return ERR_NULL_POINTER;
    
    if (((gcm_ctx_4k *) ctx)->encrypt)
        return ERR_INVALID_ARG;
    
    return GCM_update_data_4k(MOC_SYM(hwAccelCtx) ctx, ct, ctlen);
}

/*--------------------------------------------------------------------------------*/

extern MSTATUS GCM_final_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte tag[/*AES_BLOCK_SIZE*/])
{
    MSTATUS status = OK;
    
    if (NULL == ctx)
        return ERR_NULL_POINTER;
    
    if (((gcm_ctx_4k *) ctx)->encrypt)
    {
        status = GCM_final_ex_4k(MOC_SYM(hwAccelCtx) ctx, tag, AES_BLOCK_SIZE);
    }
    else
    {
        ubyte dummyTag[AES_BLOCK_SIZE] = {0};
        
        /* pass in dummyTag, expect fail */
        GCM_final_ex_4k(MOC_SYM(hwAccelCtx) ctx, dummyTag, AES_BLOCK_SIZE);
        
        /* copy the internal (correct) tag out */
        status = DIGI_MEMCPY(tag, (ubyte *) ((gcm_ctx_4k *) ctx)->tag4, AES_BLOCK_SIZE);
        
        /* dummyTag doesn't get set, no need to zero it */
    }
    
    return status;
}

/*--------------------------------------------------------------------------------*/

extern MSTATUS
GCM_clone_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx)
{
    MSTATUS status;
    gcm_ctx_4k *pNewCtx = NULL;
    AES_CTR_Ctx *pCtrCtx = NULL;
    
    if ( (NULL == pCtx) || (NULL == ppNewCtx) )
    {
        return ERR_NULL_POINTER;
    }
    
    status = DIGI_MALLOC((void **)&pNewCtx, sizeof(gcm_ctx_4k));
    if (OK != status)
        goto exit;
    
    status = DIGI_MEMCPY((void *)pNewCtx, (void *)pCtx, sizeof(gcm_ctx_4k));
    if (OK != status)
        goto exit;

    status = CloneAESCTRCtx(MOC_SYM(hwAccelCtx) ((gcm_ctx_4k *)pCtx)->pCtx, (BulkCtx *)&pCtrCtx);
    if (OK != status)
        goto exit;
    
    pNewCtx->pCtx = pCtrCtx;
    pCtrCtx = NULL;
    *ppNewCtx = pNewCtx;
    pNewCtx = NULL;
    
exit:
    if (NULL != pNewCtx)
    {
        DIGI_FREE((void **)&pNewCtx);
    }
    if (NULL != pCtrCtx)
    {
        DeleteAESCTRCtx(MOC_SYM(hwAccelCtx) (BulkCtx *)&pCtrCtx);
    }
    
    return status;
}

/*--------------------------------------------------------------------------------*/

/* assuming data buffer has enough space for TWO tags as well */
extern MSTATUS
GCM_cipher_4k(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx,
               ubyte* nonce, ubyte4 nlen,
               ubyte* adata, ubyte4 alen,
               ubyte* data, ubyte4 dlen, ubyte4 verifyLen, sbyte4 encrypt)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_GCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_GCM,0);
    
    if (NULL == ctx)
        return ERR_NULL_POINTER;
    
    /* set encrypt flag so rest of the calls work correctly */
    ((gcm_ctx_4k *) ctx)->encrypt = encrypt;
    
    if (OK > (status = GCM_init_4k(MOC_SYM(hwAccelCtx) ctx, nonce, nlen, adata, alen)))
        goto exit;
    
    if (OK > (status = GCM_update_data_4k(MOC_SYM(hwAccelCtx) ctx, data, dlen)))
        goto exit;
    
    status = GCM_final_ex_4k(MOC_SYM(hwAccelCtx) ctx, data + dlen, verifyLen);
    
exit:

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_GCM,0);
    return status;
}
#endif  /*__ENABLE_DIGICERT_GCM_4K__ */

/*--------------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_GCM_256B__)

/* Beginning of 256B implementation */

/*--------------------------------------------------------------------------------*/

static ubyte4 GCM_rtable_256b[16] = {
    0x00000000, 0x1c200000, 0x38400000, 0x24600000, 0x70800000, 0x6ca00000,
    0x48c00000, 0x54e00000, 0xe1000000, 0xfd200000, 0xd9400000, 0xc5600000,
    0x91800000, 0x8da00000, 0xa9c00000, 0xb5e00000
};


/*--------------------------------------------------------------------------------*/

static void GCM_build_hash_table_256b(gcm_ctx_256b *c, ubyte4 hkey[4])
{
    c->table[0][0] = c->table[0][1] = c->table[0][2] = c->table[0][3] = 0;
    c->table[0x8][0] = HTONL(hkey[0]);
    c->table[0x8][1] = HTONL(hkey[1]);
    c->table[0x8][2] = HTONL(hkey[2]);
    c->table[0x8][3] = HTONL(hkey[3]);

    c->table[0x4][0] = c->table[0x8][0];
    c->table[0x4][1] = c->table[0x8][1];
    c->table[0x4][2] = c->table[0x8][2];
    c->table[0x4][3] = c->table[0x8][3];

    GCM_mul_alpha(c->table[0x4]);

    c->table[0x2][0] = c->table[0x4][0];
    c->table[0x2][1] = c->table[0x4][1];
    c->table[0x2][2] = c->table[0x4][2];
    c->table[0x2][3] = c->table[0x4][3];

    GCM_mul_alpha(c->table[0x2]);

    c->table[0x1][0] = c->table[0x2][0];
    c->table[0x1][1] = c->table[0x2][1];
    c->table[0x1][2] = c->table[0x2][2];
    c->table[0x1][3] = c->table[0x2][3];

    GCM_mul_alpha(c->table[0x1]);

    c->table[0x3][0] = c->table[0x1][0] ^ c->table[0x2][0];
    c->table[0x3][1] = c->table[0x1][1] ^ c->table[0x2][1];
    c->table[0x3][2] = c->table[0x1][2] ^ c->table[0x2][2];
    c->table[0x3][3] = c->table[0x1][3] ^ c->table[0x2][3];

    c->table[0x5][0] = c->table[0x1][0] ^ c->table[0x4][0];
    c->table[0x5][1] = c->table[0x1][1] ^ c->table[0x4][1];
    c->table[0x5][2] = c->table[0x1][2] ^ c->table[0x4][2];
    c->table[0x5][3] = c->table[0x1][3] ^ c->table[0x4][3];

    c->table[0x6][0] = c->table[0x4][0] ^ c->table[0x2][0];
    c->table[0x6][1] = c->table[0x4][1] ^ c->table[0x2][1];
    c->table[0x6][2] = c->table[0x4][2] ^ c->table[0x2][2];
    c->table[0x6][3] = c->table[0x4][3] ^ c->table[0x2][3];

    c->table[0x7][0] = c->table[0x4][0] ^ c->table[0x3][0];
    c->table[0x7][1] = c->table[0x4][1] ^ c->table[0x3][1];
    c->table[0x7][2] = c->table[0x4][2] ^ c->table[0x3][2];
    c->table[0x7][3] = c->table[0x4][3] ^ c->table[0x3][3];

    c->table[0x9][0] = c->table[0x1][0] ^ c->table[0x8][0];
    c->table[0x9][1] = c->table[0x1][1] ^ c->table[0x8][1];
    c->table[0x9][2] = c->table[0x1][2] ^ c->table[0x8][2];
    c->table[0x9][3] = c->table[0x1][3] ^ c->table[0x8][3];

    c->table[0xa][0] = c->table[0x2][0] ^ c->table[0x8][0];
    c->table[0xa][1] = c->table[0x2][1] ^ c->table[0x8][1];
    c->table[0xa][2] = c->table[0x2][2] ^ c->table[0x8][2];
    c->table[0xa][3] = c->table[0x2][3] ^ c->table[0x8][3];

    c->table[0xb][0] = c->table[0x3][0] ^ c->table[0x8][0];
    c->table[0xb][1] = c->table[0x3][1] ^ c->table[0x8][1];
    c->table[0xb][2] = c->table[0x3][2] ^ c->table[0x8][2];
    c->table[0xb][3] = c->table[0x3][3] ^ c->table[0x8][3];

    c->table[0xc][0] = c->table[0x4][0] ^ c->table[0x8][0];
    c->table[0xc][1] = c->table[0x4][1] ^ c->table[0x8][1];
    c->table[0xc][2] = c->table[0x4][2] ^ c->table[0x8][2];
    c->table[0xc][3] = c->table[0x4][3] ^ c->table[0x8][3];

    c->table[0xd][0] = c->table[0x5][0] ^ c->table[0x8][0];
    c->table[0xd][1] = c->table[0x5][1] ^ c->table[0x8][1];
    c->table[0xd][2] = c->table[0x5][2] ^ c->table[0x8][2];
    c->table[0xd][3] = c->table[0x5][3] ^ c->table[0x8][3];

    c->table[0xe][0] = c->table[0x6][0] ^ c->table[0x8][0];
    c->table[0xe][1] = c->table[0x6][1] ^ c->table[0x8][1];
    c->table[0xe][2] = c->table[0x6][2] ^ c->table[0x8][2];
    c->table[0xe][3] = c->table[0x6][3] ^ c->table[0x8][3];

    c->table[0xf][0] = c->table[0x7][0] ^ c->table[0x8][0];
    c->table[0xf][1] = c->table[0x7][1] ^ c->table[0x8][1];
    c->table[0xf][2] = c->table[0x7][2] ^ c->table[0x8][2];
    c->table[0xf][3] = c->table[0x7][3] ^ c->table[0x8][3];
}


/*--------------------------------------------------------------------------------*/

#define SHIFT256B() \
  tt = t3 & 0xf; t3 >>= 4; t3 |= (t2 << 28); t2 >>= 4; t2 |= (t1 << 28);\
  t1 >>= 4; t1 |= (t0 << 28); t0 >>=4; t0 ^= GCM_rtable_256b[tt]

#define GMULWI256B(e,t,s) \
  e = (ubyte4 *)t[s&0xf]; t0 = e[0]; t1 = e[1]; t2 = e[2]; t3 = e[3];\
  SHIFT256B();\
  e = (ubyte4 *)t[(s>>4)&0xf]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
  SHIFT256B();\
  e = (ubyte4 *)t[(s>>8)&0xf]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
  SHIFT256B();\
  e = (ubyte4 *)t[(s>>12)&0xf]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
\
  SHIFT256B();\
  e = (ubyte4 *)t[(s>>16)&0xf]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
\
  SHIFT256B();\
  e = (ubyte4 *)t[(s>>20)&0xf]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
\
  SHIFT256B();\
  e = (ubyte4 *)t[(s>>24)&0xf]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
\
  SHIFT256B();\
  e = (ubyte4 *)t[s>>28]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3]

#define GMULW256B(e,t,s) \
  SHIFT256B();\
  e = (ubyte4 *)t[s&0xf]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
  SHIFT256B();\
  e = (ubyte4 *)t[(s>>4)&0xf]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
  SHIFT256B();\
  e = (ubyte4 *)t[(s>>8)&0xf]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
  SHIFT256B();\
  e = (ubyte4 *)t[(s>>12)&0xf]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
\
  SHIFT256B();\
  e = (ubyte4 *)t[(s>>16)&0xf]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
\
  SHIFT256B();\
  e = (ubyte4 *)t[(s>>20)&0xf]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
\
  SHIFT256B();\
  e = (ubyte4 *)t[(s>>24)&0xf]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3];\
\
  SHIFT256B();\
  e = (ubyte4 *)t[s>>28]; t0 ^= e[0]; t1 ^= e[1]; t2 ^= e[2]; t3 ^= e[3]

#define GHB256B(t,b)\
  s0 ^= HTONL(((ubyte4 *)b)[0]); \
  s1 ^= HTONL(((ubyte4 *)b)[1]); \
  s2 ^= HTONL(((ubyte4 *)b)[2]); \
  s3 ^= HTONL(((ubyte4 *)b)[3]); \
  GMULWI256B(entry, t, s3); \
  GMULW256B(entry, t, s2);\
  GMULW256B(entry, t, s1);\
  GMULW256B(entry, t, s0);\
  s0 = t0; \
  s1 = t1; \
  s2 = t2; \
  s3 = t3;


/*--------------------------------------------------------------------------------*/

static MSTATUS
GCM_set_key_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx)
{
    gcm_ctx_256b *c = (gcm_ctx_256b*)ctx;
    ubyte4 hkgen[4] = {0};
    ubyte4 hkey[4];
    MSTATUS status;
    sbyte4 dataLen;

    status = AESALGO_blockEncryptEx (
      MOC_SYM (hwAccelCtx) c->pCtx->pCtx, NULL, (ubyte *)hkgen, AES_BLOCK_SIZE * 8,
      (ubyte *)hkey, &dataLen);
    if (OK != status)
        goto exit;

    GCM_build_hash_table_256b(c, hkey);

exit:
    return status;
}


/*--------------------------------------------------------------------------------*/

extern BulkCtx
GCM_createCtx_256b(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* key, sbyte4 keylen, sbyte4 encrypt)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status;

    AES_CTR_Ctx *pCtx = NULL;
    gcm_ctx_256b *ctx = NULL;
    BulkCtx retVal = NULL;

    ubyte pAesCtrKey[48] = { 0 };

    FIPS_GET_STATUS_RETURN_NULL_IF_BAD(FIPS_ALGO_AES_GCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_GCM,keylen);

    switch (keylen)
    {
        default:
            goto exit;

        case 16:
        case 24:
        case 32:
            break;
    }

    status = DIGI_MEMCPY(pAesCtrKey, key, keylen);
    if (OK != status)
        goto exit;

    pCtx = (AES_CTR_Ctx *)CreateAESCTRCtx (
      MOC_SYM(hwAccelCtx) pAesCtrKey, keylen + 16, encrypt);
    if (NULL == pCtx)
        goto exit;

  #if defined(__ENABLE_DIGICERT_AES_NI__)
    /* Do a runtime sanity check */
    /* With ENABLE_DIGICERT_AES_NI defined, we don't have the software option */
    if (!check_for_aes_instructions())
        goto exit;
  #endif

    ctx = MALLOC(sizeof(gcm_ctx_256b));
    if (NULL == ctx)
        goto exit;

    /* zero out all the fields */
    DIGI_MEMSET((ubyte *)ctx, 0x00, sizeof(gcm_ctx_256b));

    ctx->pCtx = pCtx;
    ctx->encrypt = encrypt;

    if (OK > GCM_set_key_256b(MOC_SYM(hwAccelCtx) ctx))
        goto exit;

    retVal = (BulkCtx)ctx;
    pCtx = NULL;
    ctx = NULL;

exit:

    DIGI_MEMSET(pAesCtrKey, 0x00, sizeof(pAesCtrKey));

    if (NULL != pCtx)
    {
        DeleteAESCTRCtx (MOC_SYM(hwAccelCtx) (BulkCtx *)&pCtx);
    }
    if (NULL != ctx)
    {
        FREE(ctx);
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_GCM,keylen);
    return (retVal);
}

/*---------------------------------------------------------------------------------*/

extern MSTATUS
GCM_deleteCtx_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    gcm_ctx_256b *pCtx;
#ifdef __ZEROIZE_TEST__
    int counter = 0;
#endif

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_GCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_GCM,0);

    if (*ctx)
    {
        pCtx = (gcm_ctx_256b *)(*ctx);

        if (NULL != pCtx->pCtx)
        {
            DeleteAESCTRCtx (MOC_SYM(hwAccelCtx) (BulkCtx *)&(pCtx->pCtx));
        }

#ifdef __ZEROIZE_TEST__
        counter = 0;
        FIPS_PRINT("\nAESGCM256b - Before Zeroization\n");
        for( counter = 0; counter < sizeof(gcm_ctx_256b); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)*ctx+counter));
        }
        FIPS_PRINT("\n");
#endif

        DIGI_MEMSET((ubyte *)*ctx, 0x00, sizeof(gcm_ctx_256b));

#ifdef __ZEROIZE_TEST__
        FIPS_PRINT("\nAESGCM256b - After Zeroization\n");
        for( counter = 0; counter < sizeof(gcm_ctx_256b); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)*ctx+counter));
        }
        FIPS_PRINT("\n");
#endif

        FREE(*ctx);
        *ctx = NULL;
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_GCM,0);
    return status;
}

/*---------------------------------------------------------------------------------*/

extern MSTATUS GCM_update_nonce_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pNonce, ubyte4 nonceLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    gcm_ctx_256b *c = (gcm_ctx_256b*)pCtx;
    register ubyte4 t0, t1, t2, t3, tt;
    register ubyte4 *entry;
    register ubyte4 s0 = 0, s1 = 0, s2 = 0, s3 = 0;

    if (NULL == pCtx || NULL == pNonce)
        return ERR_NULL_POINTER;
    
    /* validate arguments -- since we use ubyte4 for lengths, the other parameters
     are ok */
    if (0 == nonceLen)
    {
        return ERR_INVALID_ARG;
    }
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_GCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_GCM,0);

    /* zero out the other fields */
    c->dlen = 0;
    c->alen = 0;
    c->hashBufferIndex = 0;
    c->initialized = 0;
    c->aadFinalized = 0;
    c->s[0] = c->s[1] = c->s[2] = c->s[3] = 0;
    
    if (12 != nonceLen)
    {
        ubyte4 tmp[4] = {0};
        ubyte4 b = nonceLen >> 4;
        ubyte4 l = nonceLen & 0x0f;
        
        while (b--)
        {
            GHB256B(c->table, pNonce);
            pNonce += GHASH_BLK_SZ;
        }
        if (l)
        {
            DIGI_MEMCPY((ubyte*)tmp, pNonce, l);
            GHB256B(c->table, tmp);
        }
        tmp[0] = tmp[1] = 0;
        tmp[2] = HTONL(nonceLen >> 29);
        tmp[3] = HTONL(nonceLen << 3);
        GHB256B(c->table, tmp);
        c->pCtx->u.ctr[0] = HTONL(s0);
        c->pCtx->u.ctr[1] = HTONL(s1);
        c->pCtx->u.ctr[2] = HTONL(s2);
        c->pCtx->u.ctr[3] = HTONL(s3);
    }
    else
    {
        DIGI_MEMCPY( (ubyte*) c->pCtx->u.ctr, pNonce, 12);
        c->pCtx->u.ctr[3] = 0;
        c->pCtx->u.counterBlock[AES_BLOCK_SIZE -1] = 1;
    }
    c->pCtx->offset = 0;
    
    DIGI_MEMSET((ubyte*)c->tag4, 0, AES_BLOCK_SIZE);
    status = DoAESCTREx(MOC_SYM(hwAccelCtx) c->pCtx, (ubyte*) c->tag4, AES_BLOCK_SIZE, c->encrypt, 0, sizeof(ubyte4));
    if (OK != status)
        goto exit;
    
    /* hashing state is still set to 0 */
    
    c->initialized = 1;
    
exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_AES_GCM,0);
    return status;
}

/*---------------------------------------------------------------------------------*/

extern MSTATUS GCM_update_aad_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pAadData, ubyte4 aadDataLen)
{
    FIPS_LOG_DECL_SESSION;
    gcm_ctx_256b *c = (gcm_ctx_256b*)pCtx;
    ubyte4 b = 0, l = 0, i = 0;
    register ubyte4 t0, t1, t2, t3, tt;
    register ubyte4 *entry;
    register ubyte4 s0, s1, s2, s3;

    if (!aadDataLen)  /* Ok no op */
        return OK;
    
    if (NULL == pCtx || NULL == pAadData)
        return ERR_NULL_POINTER;
    
    if (!c->initialized)
        return ERR_AES_UNINITIALIZED_CTX;
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_GCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_GCM,0);

    /* get the hashing state */
    s0 = c->s[0];
    s1 = c->s[1];
    s2 = c->s[2];
    s3 = c->s[3];
    
    /* update the total aadLen before beginning */
    c->alen += aadDataLen;
    
    /* add the aad data to the hash */
    /* was there something remaining from last round ? */
    if ( c->hashBufferIndex)
    {
        l = AES_BLOCK_SIZE - c->hashBufferIndex;
        if (l > aadDataLen)
        {
            l = aadDataLen;
        }
        
        DIGI_MEMCPY( c->hashBuffer + c->hashBufferIndex, pAadData, l);
        
        pAadData += l;  /* ok to modify passed by value ptr */
        aadDataLen -= l;
        c->hashBufferIndex += l;
        
        if ( AES_BLOCK_SIZE == c->hashBufferIndex)
        {
            ubyte4 *tmp= (ubyte4 *)c->hashBuffer;
            GHB256B(c->table, tmp);
            c->hashBufferIndex = 0;
        }
    }
    
    /* process the rest */
    b = aadDataLen >> 4;
    l = aadDataLen & 0x0f;
    
    for ( i = 0; i < b; i++)
    {
        GHB256B(c->table, pAadData);
        pAadData += GHASH_BLK_SZ;
    }
    
    if (l)
    {
        DIGI_MEMCPY(c->hashBuffer, pAadData, l);
        c->hashBufferIndex = l;
    }
    
    /* save the hash state */
    c->s[0] = s0;
    c->s[1] = s1;
    c->s[2] = s2;
    c->s[3] = s3;
    
    FIPS_LOG_END_ALG(FIPS_ALGO_AES_GCM,0);
    return OK;
}

/*---------------------------------------------------------------------------------*/

extern MSTATUS GCM_update_data_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData, ubyte4 dataLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    gcm_ctx_256b *c = (gcm_ctx_256b*)pCtx;
    ubyte4 b = 0, l = 0, i = 0;
    ubyte *pDataStrt = pData;
    ubyte4 origDataLen = dataLen;
    register ubyte4 t0, t1, t2, t3, tt;
    register ubyte4 *entry;
    register ubyte4 s0, s1, s2, s3;
    
    if (!dataLen)
        return OK;  /* ok no-op */
    
    if ( NULL == pCtx || NULL == pData )
    {
        return ERR_NULL_POINTER;
    }
    
    if (!c->initialized)
        return ERR_AES_UNINITIALIZED_CTX;
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_GCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_GCM,0);

    /* get the hashing state */
    s0 = c->s[0];
    s1 = c->s[1];
    s2 = c->s[2];
    s3 = c->s[3];
    
    if (!c->aadFinalized)
    {
        /* pad and process any remaining data in the buffer */
        if (c->hashBufferIndex)
        {
            ubyte4 tmp[4] = {0};
            
            DIGI_MEMCPY((ubyte *) tmp, c->hashBuffer, c->hashBufferIndex);
            GHB256B(c->table, tmp);
            c->hashBufferIndex = 0;
        }
        
        c->aadFinalized = 1;
    }
    
    if (c->encrypt)
    {
        /* encrypt everything */
        if (OK > (status = DoAESCTREx(MOC_SYM(hwAccelCtx) c->pCtx, pDataStrt, dataLen, 1, 0, sizeof(ubyte4))))
        {
            goto exit;
        }
    }
    
    c->dlen += dataLen;
    
    /* add the cipher text to the hash */
    /* was there something remaining from last round ? */
    if ( c->hashBufferIndex)
    {
        l = AES_BLOCK_SIZE - c->hashBufferIndex;
        if (l > dataLen)
        {
            l = dataLen;
        }
        
        DIGI_MEMCPY( c->hashBuffer + c->hashBufferIndex, pData, l);
        
        pData += l;
        dataLen -= l;
        c->hashBufferIndex += l;
        
        if ( AES_BLOCK_SIZE == c->hashBufferIndex)
        {
            ubyte4 *tmp= (ubyte4 *)c->hashBuffer;
            GHB256B(c->table, tmp);
            c->hashBufferIndex = 0;
        }
    }
    
    /* process the rest */
    b = dataLen >> 4;
    l = dataLen & 0x0f;
    
    for ( i = 0; i < b; i++)
    {
        GHB256B(c->table, pData);
        pData += GHASH_BLK_SZ;
    }
    
    if (l)
    {
        DIGI_MEMCPY(c->hashBuffer, pData, l);
        c->hashBufferIndex = l;
    }
    
    /* save the hash state */
    c->s[0] = s0;
    c->s[1] = s1;
    c->s[2] = s2;
    c->s[3] = s3;
    
    if (!c->encrypt)
    {
        /* decrypt everything */
        if (OK > (status = DoAESCTREx(MOC_SYM(hwAccelCtx) c->pCtx, pDataStrt, origDataLen, 0, 0, sizeof(ubyte4))))
        {
            goto exit;
        }
    }
    
exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_AES_GCM,0);
    return status;
}

/*---------------------------------------------------------------------------------*/

extern MSTATUS GCM_final_ex_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pTag, ubyte4 tagLen)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    ubyte4 tmp[4] = {0};
    gcm_ctx_256b *c = (gcm_ctx_256b*) pCtx;
    ubyte4 i = 0;
    register ubyte4 t0, t1, t2, t3, tt;
    register ubyte4 *entry;
    register ubyte4 s0, s1, s2, s3;
    ubyte4 *tmp2 = NULL;
    
    if ( NULL == pCtx || NULL == pTag )
    {
        return ERR_NULL_POINTER;
    }
    
    if (!c->initialized)
        return ERR_AES_UNINITIALIZED_CTX;
    
    if (!tagLen || tagLen > AES_BLOCK_SIZE)
        return ERR_INVALID_ARG;
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_GCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_GCM,0);

    s0 = c->s[0];
    s1 = c->s[1];
    s2 = c->s[2];
    s3 = c->s[3];
    
    if (!c->aadFinalized)
    {
        /* pad and process any remaining data in the buffer */
        if (c->hashBufferIndex)
        {
            DIGI_MEMCPY((ubyte *) tmp, c->hashBuffer, c->hashBufferIndex);
            GHB256B(c->table, tmp);
            c->hashBufferIndex = 0;
            tmp[0] = 0; tmp[1] = 0; tmp[2] = 0; tmp[3] = 0;
        }
        
        c->aadFinalized = 1;
    }
    
    if (c->hashBufferIndex)
    {
        for (i = c->hashBufferIndex; i < AES_BLOCK_SIZE; ++i)
        {
            c->hashBuffer[i] = 0;
        }
        tmp2 = (ubyte4 *)c->hashBuffer;
        GHB256B(c->table, tmp2);
    }
    
    /* finish with lengths */
    tmp[0] = HTONL(c->alen>>29);
    tmp[1] = HTONL(c->alen<<3);
    tmp[2] = HTONL(c->dlen>>29);
    tmp[3] = HTONL(c->dlen<<3);
    
    GHB256B(c->table, tmp);
    
    c->tag4[0] ^= HTONL(s0);
    c->tag4[1] ^= HTONL(s1);
    c->tag4[2] ^= HTONL(s2);
    c->tag4[3] ^= HTONL(s3);
    
    if (c->encrypt)
    {
        status = DIGI_MEMCPY(pTag, (ubyte *) c->tag4, tagLen);
    }
    else
    {
        sbyte4 cmp = -1;
        DIGI_CTIME_MATCH(pTag, (ubyte *) c->tag4, tagLen, &cmp);
        
        if (cmp)
            status = ERR_CRYPTO_AEAD_FAIL;
        else
            status = OK;
    }
    
    FIPS_LOG_END_ALG(FIPS_ALGO_AES_GCM,0);
    return status;
}

/*---------------------------------------------------------------------------------*/

extern MSTATUS GCM_init_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx,
                           ubyte* nonce, ubyte4 nlen,
                           ubyte* adata, ubyte4 alen)
{
    MSTATUS status = OK;
    
    /* input validity checked by the below calls */
    status = GCM_update_nonce_256b(MOC_SYM(hwAccelCtx) ctx, nonce, nlen);
    if (OK != status)
        goto exit;
    
    if (alen)
    {
        status = GCM_update_aad_256b(MOC_SYM(hwAccelCtx) ctx, adata, alen);
    }
    
exit:
    
    return status;
}

/*--------------------------------------------------------------------------------*/

extern MSTATUS GCM_update_encrypt_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte *data, ubyte4 dlen)
{
    if (NULL == ctx)
        return ERR_NULL_POINTER;
    
    if (!((gcm_ctx_256b *) ctx)->encrypt)
        return ERR_INVALID_ARG;

    return GCM_update_data_256b(MOC_SYM(hwAccelCtx) ctx, data, dlen);
}

/*--------------------------------------------------------------------------------*/

extern MSTATUS GCM_update_decrypt_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte *ct, ubyte4 ctlen)
{
    if (NULL == ctx)
        return ERR_NULL_POINTER;
    
    if (((gcm_ctx_256b *) ctx)->encrypt)
        return ERR_INVALID_ARG;
    
    return GCM_update_data_256b(MOC_SYM(hwAccelCtx) ctx, ct, ctlen);
}

/*--------------------------------------------------------------------------------*/

extern MSTATUS GCM_final_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte tag[/*AES_BLOCK_SIZE*/])
{
    MSTATUS status = OK;
    
    if (NULL == ctx)
        return ERR_NULL_POINTER;
    
    if (((gcm_ctx_256b *) ctx)->encrypt)
    {
        status = GCM_final_ex_256b(MOC_SYM(hwAccelCtx) ctx, tag, AES_BLOCK_SIZE);
    }
    else
    {
        ubyte dummyTag[AES_BLOCK_SIZE] = {0};
        
        /* pass in dummyTag, expect fail */
        GCM_final_ex_256b(MOC_SYM(hwAccelCtx) ctx, dummyTag, AES_BLOCK_SIZE);
        
        /* copy the internal (correct) tag out */
        status = DIGI_MEMCPY(tag, (ubyte *) ((gcm_ctx_256b *) ctx)->tag4, AES_BLOCK_SIZE);
        
        /* dummyTag doesn't get set, no need to zero it */
    }
    
    return status;
}

/*--------------------------------------------------------------------------------*/

extern MSTATUS
GCM_clone_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx)
{
    MSTATUS status;
    gcm_ctx_256b *pNewCtx = NULL;
    AES_CTR_Ctx *pCtrCtx = NULL;
    
    if ( (NULL == pCtx) || (NULL == ppNewCtx) )
    {
        return ERR_NULL_POINTER;
    }
    
    status = DIGI_MALLOC((void **)&pNewCtx, sizeof(gcm_ctx_256b));
    if (OK != status)
        goto exit;
    
    status = DIGI_MEMCPY((void *)pNewCtx, (void *)pCtx, sizeof(gcm_ctx_256b));
    if (OK != status)
        goto exit;

    status = CloneAESCTRCtx(MOC_SYM(hwAccelCtx) ((gcm_ctx_256b *)pCtx)->pCtx, (BulkCtx *)&pCtrCtx);
    if (OK != status)
        goto exit;
    
    pNewCtx->pCtx = pCtrCtx;
    pCtrCtx = NULL;
    *ppNewCtx = pNewCtx;
    pNewCtx = NULL;
    
exit:
    if (NULL != pNewCtx)
    {
        DIGI_FREE((void **)&pNewCtx);
    }
    if (NULL != pCtrCtx)
    {
        DeleteAESCTRCtx(MOC_SYM(hwAccelCtx) (BulkCtx *)&pCtrCtx);
    }
    
    return status;
}

/*--------------------------------------------------------------------------------*/

/* assuming data buffer has enough space for TWO tags as well */
extern MSTATUS
GCM_cipher_256b(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx,
              ubyte* nonce, ubyte4 nlen,
              ubyte* adata, ubyte4 alen,
              ubyte* data, ubyte4 dlen, ubyte4 verifyLen, sbyte4 encrypt)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_GCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_GCM,0);
    
    if (NULL == ctx)
        return ERR_NULL_POINTER;
    
    /* set encrypt flag so rest of the calls work correctly */
    ((gcm_ctx_256b *) ctx)->encrypt = encrypt;
    
    if (OK > (status = GCM_init_256b(MOC_SYM(hwAccelCtx) ctx, nonce, nlen, adata, alen)))
        goto exit;
    
    if (OK > (status = GCM_update_data_256b(MOC_SYM(hwAccelCtx) ctx, data, dlen)))
        goto exit;
    
    status = GCM_final_ex_256b(MOC_SYM(hwAccelCtx) ctx, data + dlen, verifyLen);
    
exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_AES_GCM,0);
    return status;
}
#endif /*__ENABLE_DIGICERT_GCM_256B__ */

#endif /* defined(__ENABLE_DIGICERT_GCM_64K__) || defined(__ENABLE_DIGICERT_GCM_4K__)  || defined(__ENABLE_DIGICERT_GCM_256B__) */
#endif /* !defined(__ENABLE_DIGICERT_SMALL_AES__) */
