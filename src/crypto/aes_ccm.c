/*
 * aes_ccm.c
 *
 * AES-CCM Implementation (RFC 4309)
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
@file       aes_ccm.c
@brief      C source code for the NanoCrypto AES-CCM API.

@details    This file contains the NanoCrypto AES-CCM API functions.

@copydoc    overview_aes_ccm

@flags
No flag definitions are required to use this API.

@filedoc    aes_ccm.c
*/

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if ((!defined(__DISABLE_AES_CIPHERS__)) && (!defined(__DISABLE_AES_CCM__)))

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif
#include "../crypto/aesalgo.h"
#include "../crypto/aes.h"
#include "../crypto/aes_ecb.h"
#include "../crypto/aes_ctr.h"
#include "../crypto/aes_ccm.h"

#if (defined(__ENABLE_DIGICERT_AES_NI__) || defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__))
#include "../crypto/aesalgo_intel_ni.h"
#endif

/*------------------------------------------------------------------*/

static MSTATUS
AESCCM_validateParamsEx( ubyte M, ubyte L,
                        const ubyte* nonce,
                        ubyte* eData, ubyte4 eDataLength,
                        const ubyte output[/*M*/],
                        ubyte* pMp)
{
    ubyte4  tempL;
    ubyte   Mp;

    if ( !pMp || !nonce || !eData || !output)
        return ERR_NULL_POINTER;

    /* eDataLength must be encoded in L bytes at max */
    for (tempL = L; ((tempL) && (eDataLength)); tempL--)
        eDataLength >>= 8;

    if (eDataLength)
        return ERR_INVALID_ARG;

    /* M must be 4,6,8,...., 16 */
    if (M&1)
        return ERR_INVALID_ARG;
    Mp = (M - 2) / 2;

    if ( Mp <= 0 || Mp > 7)
        return ERR_INVALID_ARG;

    /* L must be 2 to 8 */
    if ( L < 2 || L > 8)
        return ERR_INVALID_ARG;

    *pMp = Mp;
    return OK;
}

/*------------------------------------------------------------------*/

static MSTATUS
AESCCM_validateParams( ubyte M, ubyte L,
                        ubyte* keyMaterial, const ubyte* nonce,
                        ubyte* eData, ubyte4 eDataLength,
                        const ubyte output[/*M*/],
                        ubyte* pMp)
{
    if ( !pMp || !keyMaterial || !nonce || !eData || !output)
        return ERR_NULL_POINTER;

    return AESCCM_validateParamsEx(M, L, nonce, eData, eDataLength, output, pMp);

}


/*------------------------------------------------------------------*/

static void
AESCCM_authenticateAux( MOC_SYM(hwAccelDescr hwAccelCtx) aesCipherContext *pCtx,
                        ubyte* B, ubyte* X, const ubyte* data, ubyte4 dataLen)
{
    ubyte4 i;
    sbyte4 outLen;

      while ( dataLen > 16)
      {
          for ( i = 0; i < 16; ++i)
          {
              B[i] = (*data++) ^ X[i];
          }
          dataLen -= 16;
          AESALGO_blockEncryptEx (
            MOC_SYM(hwAccelCtx) pCtx, NULL, B, AES_BLOCK_SIZE * 8, X, &outLen);
      }

      if ( dataLen > 0)
      {
          for (i =0; i < dataLen; ++i)
          {
              B[i] = (*data++) ^ X[i];
          }
          for (; i < 16; ++i)
          {
              B[i] = 0 ^ X[i];
          }
          AESALGO_blockEncryptEx (
            MOC_SYM(hwAccelCtx) pCtx, NULL, B, AES_BLOCK_SIZE * 8, X, &outLen);
      }
}


/*------------------------------------------------------------------*/

static void
AESCCM_doAuthentication( MOC_SYM(hwAccelDescr hwAccelCtx) aesCTRCipherContext* pCtx,
                       ubyte Mp, ubyte L, const ubyte* nonce, const ubyte* eData,
                       ubyte4 eDataLength, const ubyte* aData, ubyte4 aDataLength,
                       ubyte T[16])
{
    ubyte B[16];
    sbyte4 i;
    ubyte4 temp;

    /* construct B_0 */
    /* byte 0 is flags */
    B[0] = 8 * Mp + L - 1;
    if ( aData && aDataLength)
        B[0] |= (1 << 6);

    /* other bytes are nonce + eDataLength */
    DIGI_MEMCPY( B+1, nonce, 15-L);

    /* copy eDataLength in big-endian format */
    temp = eDataLength;
    for ( i = 0; ((i < L) && (i < 16)); ++i)
    {
        B[15-i] = (ubyte)(temp & 0xff);
        temp >>= 8;
    }


    /* X_1 = E(K, B_0) */
    AESALGO_blockEncryptEx (
      MOC_SYM(hwAccelCtx) pCtx->pCtx, NULL, B, AES_BLOCK_SIZE * 8, T, &i);

    if ( aData && aDataLength)
    {
        if ( aDataLength < ( 1 << 16) - (1 << 8))
        {
            B[0] = (ubyte)((aDataLength >> 8) & 0xff);
            B[1] = (ubyte)((aDataLength) & 0xff);
            if ( aDataLength >= 14)
            {
                DIGI_MEMCPY( B + 2, aData, 14);
                aData += 14;
                aDataLength -= 14;
            }
            else /* pad with 0 */
            {
                DIGI_MEMCPY( B + 2, aData, aDataLength);
                DIGI_MEMSET( B + 2 + aDataLength, 0, 14-aDataLength);
                aDataLength = 0;
            }
        }
        else /* if ( aDataLength < ( 1 << 32)) */
        {
            B[0] = 0xFF;
            B[1] = 0xFE;
            BIGEND32( B + 2, aDataLength);
            DIGI_MEMCPY( B + 6, aData, 10);
            aData += 10;
            aDataLength -= 10;
        }
        /* encrypt block */
        for ( i = 0; i < AES_BLOCK_SIZE; ++i)
        {
            B[i] ^= T[i];
        }
        AESALGO_blockEncryptEx (
          MOC_SYM(hwAccelCtx) pCtx->pCtx, NULL, B, AES_BLOCK_SIZE * 8, T, &i);

        AESCCM_authenticateAux( MOC_SYM( hwAccelCtx) pCtx->pCtx,
                            B, T, aData, aDataLength);
    }

    AESCCM_authenticateAux(  MOC_SYM( hwAccelCtx) pCtx->pCtx,
                            B, T, eData, eDataLength);
}


/*------------------------------------------------------------------*/

static MSTATUS
AESCCM_doCTREncryption( MOC_SYM(hwAccelDescr hwAccelCtx) aesCTRCipherContext* pCtx,
                       ubyte M, ubyte L, const ubyte* nonce, ubyte* eData,
                       ubyte4 eDataLength, const ubyte T[/*M*/], ubyte U[/*M*/])

{
    sbyte4 i;
    ubyte* A;
    ubyte S[16];

    /*************************** Encryption ******************************/
    A = pCtx->u.counterBlock;
    A[0] = L-1;
    DIGI_MEMCPY( A+1, nonce, 15-L);
    for ( i = 0; i < L; ++i)
    {
        A[15-i] = 0;
    }
    AESALGO_blockEncryptEx (
      MOC_SYM(hwAccelCtx) pCtx->pCtx, NULL, A, AES_BLOCK_SIZE * 8, S, &i);
    for (i = 0; i < M; ++i)
    {
        U[i] = S[i] ^ T[i]; /* U = S_0 ^ T */
    }

    /* rest of encryption */
    /* increment the block first ! */
    A[15] = 1;
    return DoAESCTR(MOC_SYM( hwAccelCtx) pCtx, eData, eDataLength, 1, NULL);
}


/*------------------------------------------------------------------*/

static MSTATUS
AESCCM_encryptEx(MOC_SYM(hwAccelDescr hwAccelCtx) aesCTRCipherContext *pCtx,
                 ubyte M, ubyte L,
                 const ubyte* nonce, ubyte* eData, ubyte4 eDataLength,
                 const ubyte* aData, ubyte4 aDataLength, ubyte U[/*M*/])
{
    ubyte               T[16];
    ubyte               Mp;
    MSTATUS             status;

    if (OK > (status = AESCCM_validateParamsEx(M, L, nonce,
                                             eData, eDataLength, U, &Mp)))
    {
        goto exit;
    }

    /*************************** Authentication **************************/
    AESCCM_doAuthentication( MOC_SYM(hwAccelCtx) pCtx,
                                Mp, L, nonce, eData, eDataLength, aData, aDataLength, T);

    /*************************** Encryption ******************************/

    status = AESCCM_doCTREncryption(MOC_SYM(hwAccelCtx) pCtx, M, L,
                                    nonce, eData, eDataLength, T, U);

exit:

#ifdef __ZEROIZE_TEST__
    {
        int counter = 0;

        FIPS_PRINT("\nAESCCM - Before Zeroization\n");
        for (counter = 0; counter < sizeof(aesCTRCipherContext); counter++)
        {
            FIPS_PRINT("%02x", *(((ubyte *)pCtx) + counter));
        }
        FIPS_PRINT("\n");
    }
#endif

#ifdef __ZEROIZE_TEST__
    {
        int counter = 0;

        FIPS_PRINT("\nAESCCM - After Zeroization\n");
        for( counter = 0; counter < sizeof(aesCTRCipherContext); counter++)
        {
            FIPS_PRINT("%02x", *(((ubyte *)pCtx) + counter));
        }
        FIPS_PRINT("\n");
    }
#endif

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
AESCCM_encrypt(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte M, ubyte L,
               ubyte* keyMaterial, sbyte4 keyLength,
               const ubyte* nonce, ubyte* eData, ubyte4 eDataLength,
               const ubyte* aData, ubyte4 aDataLength, ubyte U[/*M*/])
{
    FIPS_LOG_DECL_SESSION;
    ubyte               Mp;
    aesCTRCipherContext *pCtx = NULL;
    MSTATUS             status;

    ubyte pTempKey[48] = { 0 };

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_CCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_CCM,keyLength);

    status = ERR_INVALID_ARG;
    if (32 < keyLength)
        goto exit;

    status = DIGI_MEMCPY(pTempKey, keyMaterial, keyLength);
    if (OK != status)
        goto exit;

    if (OK > (status = AESCCM_validateParams(M, L, keyMaterial, nonce,
                                             eData, eDataLength, U, &Mp)))
    {
        goto exit;
    }

    /* create AES context */
    status = ERR_AES;
    pCtx = (BulkCtx)CreateAESCTRCtx (
      MOC_SYM(hwAccelCtx) pTempKey, keyLength + 16, 1);
    if (NULL == pCtx)
        goto exit;

    status = AESCCM_encryptEx(MOC_SYM(hwAccelCtx) pCtx,
                         M, L,
                        nonce, eData, eDataLength,
                        aData, aDataLength, U);

exit:

    DIGI_MEMSET(pTempKey, 0x00, sizeof(pTempKey));

    if (NULL != pCtx)
    {
        DeleteAESCTRCtx (MOC_SYM(hwAccelCtx) (BulkCtx *)&pCtx);
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_CCM,keyLength);
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
AESCCM_decryptEx(MOC_SYM(hwAccelDescr hwAccelCtx)aesCTRCipherContext *pCtx, ubyte M, ubyte L,
                const ubyte* nonce, ubyte* eData, ubyte4 eDataLength,
                const ubyte* aData, ubyte4 aDataLength, const ubyte U[/*M*/])
{
    ubyte               T1[16];
    ubyte               T2[16];
    ubyte               Mp;
    sbyte4              resCmp;
    MSTATUS             status;

    if (OK > (status = AESCCM_validateParamsEx(M, L, nonce,
                                             eData, eDataLength, U, &Mp)))
    {
        goto exit;
    }

    /**************** Decryption *****************************/
    if (OK > (status = AESCCM_doCTREncryption(MOC_SYM(hwAccelCtx) pCtx, M, L,
                       nonce, eData, eDataLength, U, T1)))
    {
        goto exit;
    }


    /**************** Authentication *************************/
    AESCCM_doAuthentication(MOC_SYM(hwAccelCtx) pCtx,
                                    Mp, L, nonce, eData, eDataLength, aData, aDataLength, T2);

    /* verify T1 == T2 */
    DIGI_CTIME_MATCH(T1, T2, M, &resCmp);

    status = (resCmp) ? ERR_AES_CCM_AUTH_FAIL : OK;

exit:
#ifdef __ZEROIZE_TEST__
    {
        int counter = 0;
        FIPS_PRINT("\nAESCCM - Before Zeroization\n");
        for( counter = 0; counter < sizeof(aesCTRCipherContext); counter++)
        {
            FIPS_PRINT("%02x",*(((ubyte *)pCtx) + counter));
        }
        FIPS_PRINT("\n");
    }
#endif

#ifdef __ZEROIZE_TEST__
    {
        int counter = 0;
        FIPS_PRINT("\nAESCCM - After Zeroization\n");
        for( counter = 0; counter < sizeof(aesCTRCipherContext); counter++)
        {
            FIPS_PRINT("%02x",*(((ubyte *)pCtx) + counter));
        }
        FIPS_PRINT("\n");
    }
#endif

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
AESCCM_decrypt(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte M, ubyte L,
               ubyte* keyMaterial, sbyte4 keyLength,
               const ubyte* nonce, ubyte* eData, ubyte4 eDataLength,
               const ubyte* aData, ubyte4 aDataLength, const ubyte U[/*M*/])
{
    FIPS_LOG_DECL_SESSION;
    ubyte               Mp;
    aesCTRCipherContext *pCtx = NULL;
    MSTATUS             status;

    ubyte pTempKey[48] = { 0 };

    status = ERR_INVALID_ARG;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_CCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_CCM,keyLength);

    if (32 < keyLength)
        goto exit;

    status = DIGI_MEMCPY(pTempKey, keyMaterial, keyLength);
    if (OK != status)
        goto exit;


    if (OK > (status = AESCCM_validateParams(M, L, keyMaterial, nonce,
                                             eData, eDataLength, U, &Mp)))
    {
        goto exit;
    }

    /* create AES context */
    status = ERR_AES;
    pCtx = (BulkCtx)CreateAESCTRCtx (
      MOC_SYM(hwAccelCtx) pTempKey, keyLength + 16, 1);
    if (NULL == pCtx)
        goto exit;

    status = AESCCM_decryptEx(MOC_SYM(hwAccelCtx) pCtx, M, L,
                              nonce, eData, eDataLength,
                              aData, aDataLength, U);
exit:

    DIGI_MEMSET(pTempKey, 0x00, sizeof(pTempKey));

    if (NULL != pCtx)
    {
        DeleteAESCTRCtx (MOC_SYM(hwAccelCtx) (BulkCtx *)&pCtx);
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_CCM,keyLength);
    return status;
}

/*------------------------------------------------------------------*/

/**
@private
@internal
@todo_add_ask   (New since 5.3.1; nobody ever documented it.)
@ingroup    aes_ccm_functions
*/
extern BulkCtx
AESCCM_createCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    FIPS_LOG_DECL_SESSION;
    aesCipherContext* ctx = NULL;
    MOC_UNUSED(encrypt);

    FIPS_GET_STATUS_RETURN_NULL_IF_BAD(FIPS_ALGO_AES_CCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_CCM,keyLength);

#if defined(__ENABLE_DIGICERT_AES_NI__)
    /* Do a runtime sanity check */
    /* With ENABLE_DIGICERT_AES_NI defined, we don't have the software option */
    if (!check_for_aes_instructions())
    {
        goto exit; /* Returns NULL ctx */
    }
#endif

    ctx = (aesCipherContext *)CreateAESECBCtx (
      MOC_SYM(hwAccelCtx) keyMaterial, keyLength, 1);

#if defined(__ENABLE_DIGICERT_AES_NI__)
exit:
#endif

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_CCM,keyLength);
    return ((BulkCtx)ctx);
}

/*------------------------------------------------------------------*/

/**
@private
@internal
@todo_add_ask   (New since 5.3.1; nobody ever documented it.)
@ingroup    aes_ccm_functions
*/
extern MSTATUS
AESCCM_deleteCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx* ctx)
{
    FIPS_LOG_DECL_SESSION;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_CCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_CCM,0);

    if (*ctx)
    {
#ifndef __ZEROIZE_TEST__
        DeleteAESECBCtx (MOC_SYM(hwAccelCtx) ctx);
#else
        int counter = 0;
        FIPS_PRINT("\nAES - Before Zeroization\n");
        for( counter = 0; counter < sizeof(aesCipherContext); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)*ctx+counter));
        }
        FIPS_PRINT("\n");

        /* Zeroize the sensitive information before deleting the memory */
        DIGI_MEMSET((ubyte*)*ctx, 0x00, sizeof(aesCipherContext));

        FIPS_PRINT("\nAES - After Zeroization\n");
        for( counter = 0; counter < sizeof(aesCipherContext); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)*ctx+counter));
        }
        FIPS_PRINT("\n");
#endif
        FREE(*ctx);
        *ctx = NULL;
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_CCM,0);
    return OK;
}

/*------------------------------------------------------------------*/

/**
@private
@internal
@todo_add_ask   (New since 5.3.1; nobody ever documented it.)
@ingroup    aes_ccm_functions
*/
extern MSTATUS
AESCCM_cipher(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* nonce, ubyte4 nlen,
                    ubyte* aData, ubyte4 aDataLength, ubyte* data, ubyte4 dataLength, ubyte4 verifyLen, sbyte4 encrypt)
{
    FIPS_LOG_DECL_SESSION;
    aesCTRCipherContext aesCtrctx;
    ubyte               M = (ubyte) verifyLen;
    ubyte               L = (ubyte) (15 - nlen);
    ubyte               output[16];
    MSTATUS             status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_CCM); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_CCM,0);

    /* Create an AES-CTR context */
    DIGI_MEMSET((ubyte *)&aesCtrctx, 0x00, sizeof(aesCtrctx));
    aesCtrctx.pCtx = (aesCipherContext *)ctx;

    if (encrypt)
    {
        if (OK > (status = AESCCM_encryptEx(MOC_SYM(hwAccelCtx) &aesCtrctx,
                                        M, L,
                                        nonce, data, dataLength,
                                        aData, aDataLength, output)))
        goto exit;

        DIGI_MEMCPY(data + dataLength, output, verifyLen);
    }
    else
    {
        DIGI_MEMCPY(output, (data + dataLength), verifyLen);

        status = AESCCM_decryptEx(MOC_SYM(hwAccelCtx)&aesCtrctx, M, L,
                                            nonce, data, dataLength,
                                            aData, aDataLength, output);
    }

exit:
    DIGI_MEMSET((ubyte *)&aesCtrctx, 0x00, sizeof(aesCtrctx));
    FIPS_LOG_END_ALG(FIPS_ALGO_AES_CCM,0);
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
AESCCM_clone(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx)
{
    return CloneAESCtx(MOC_SYM(hwAccelCtx) pCtx, ppNewCtx);
}

#endif /* (!defined(__DISABLE_AES_CIPHERS__) && !defined(__AES_HARDWARE_CIPHER__)) */
