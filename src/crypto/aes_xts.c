/*
 * aes_xts.c
 *
 * AES-XTS Implementation (IEEE P1619)
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_XTS_INTERNAL__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif
#include "../crypto/aes.h"
#include "../crypto/aes_xts.h"

#if ((!defined(__DISABLE_AES_CIPHERS__)) && (!defined(__DISABLE_AES_XTS__)))

#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#include "../crypto/aesalgo.h"
#include "../crypto/aes_ecb.h"

#if (defined(__ENABLE_DIGICERT_AES_NI__) || defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__))
#include "../crypto/aesalgo_intel_ni.h"
#endif

#define GF_128_FDBK 0x87


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
AESXTSInit( MOC_SYM(hwAccelDescr hwAccelCtx) aesXTSCipherContext *pCtx,
            const ubyte *pKey1, const ubyte *pKey2,
            sbyte4 keyLength, sbyte4 encrypt)
{
    return AESXTSInitExt(MOC_SYM(hwAccelCtx) pCtx, pKey1, pKey2, keyLength, encrypt, NULL);
}

MOC_EXTERN MSTATUS
AESXTSInitExt( MOC_SYM(hwAccelDescr hwAccelCtx) aesXTSCipherContext *pCtx,
              const ubyte *pKey1, const ubyte *pKey2,
              sbyte4 keyLength, sbyte4 encrypt, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status;
    BulkCtx pAesKey1 = NULL;
    BulkCtx pAesKey2 = NULL;
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    sbyte4 keysResult = 0;
#endif
    MOC_UNUSED(pExtCtx);
    
    if (NULL == pCtx || NULL == pKey1 || NULL == pKey2)
        return ERR_NULL_POINTER;
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_XTS); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_XTS,keyLength);

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    keysResult = 0;

    /* Must assert pKey1 != pKey2, or it is insecure */
    status = DIGI_MEMCMP( pKey1, pKey2, keyLength, &keysResult);
    if ( (OK != status) || (0 == keysResult) )
    {
        status = ERR_FIPS_INVALID_INPUT;
        goto exit;
    }
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

    /* Only 128 & 256 are valid key sizes for XTS, (Not 192). */
    if ((keyLength != 16) && (keyLength != 32))
    {
        status = ERR_AES_BAD_KEY_LENGTH;
        goto exit;
    }

    status = ERR_AES;
    pAesKey1 = CreateAESECBCtx (
      MOC_SYM(hwAccelCtx) (ubyte *)pKey1, keyLength, encrypt);
    if (NULL == pAesKey1)
      goto exit;

    /* pKey2 is always used in encryption mode */
    pAesKey2 = CreateAESECBCtx (
      MOC_SYM(hwAccelCtx) (ubyte *)pKey2, keyLength, 1);
    if (NULL == pAesKey2)
      goto exit;

    pCtx->pKey1 = pAesKey1;
    pCtx->pKey2 = pAesKey2;

    pAesKey1 = NULL;
    pAesKey2 = NULL;
    status = OK;

exit:

    if (NULL != pAesKey1)
    {
      DeleteAESECBCtx (MOC_SYM(hwAccelCtx) &pAesKey1);
    }
    if (NULL != pAesKey2)
    {
      DeleteAESECBCtx (MOC_SYM(hwAccelCtx) &pAesKey2);
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_XTS,keyLength);
    return status;
}


/*------------------------------------------------------------------*/

MOC_EXTERN BulkCtx
CreateAESXTSCtx(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte *pKeyMaterial,
                sbyte4 keyLength, sbyte4 encrypt)
{
    return CreateAESXTSCtxExt(MOC_SYM(hwAccelCtx) pKeyMaterial, keyLength, encrypt, NULL);
}

MOC_EXTERN BulkCtx
CreateAESXTSCtxExt(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte *pKeyMaterial,
                   sbyte4 keyLength, sbyte4 encrypt, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    aesXTSCipherContext *pCtx = 0;

    FIPS_GET_STATUS_RETURN_NULL_IF_BAD(FIPS_ALGO_AES_XTS); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_XTS,(keyLength/2)); /* See below */

    if (NULL == pKeyMaterial)
        goto exit;

    if (32 != keyLength && 64 != keyLength)
        goto exit;

#if defined(__ENABLE_DIGICERT_AES_NI__)
    /* Do a runtime sanity check */
    /* With ENABLE_DIGICERT_AES_NI defined, we don't have the software option */
    if (!check_for_aes_instructions())
    {
        pCtx = NULL; /* returns NULL ctx */
        goto exit;
    }
#endif

    pCtx = (aesXTSCipherContext *) MALLOC(sizeof(aesXTSCipherContext));
    if (pCtx)
    {
        pCtx->pKey1 = NULL;
        pCtx->pKey2 = NULL;
        if (OK > AESXTSInitExt(MOC_SYM(hwAccelCtx) pCtx, pKeyMaterial,
                            pKeyMaterial + keyLength/2,
                            keyLength/2, encrypt, pExtCtx))
        {
            FREE(pCtx);  pCtx = NULL;
        }
    }
    
exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_AES_XTS,(keyLength/2));
    return pCtx;
}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
DeleteAESXTSCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *pCtx)
{
    return DeleteAESXTSCtxExt(MOC_SYM(hwAccelCtx) pCtx, NULL);
}

MOC_EXTERN MSTATUS
DeleteAESXTSCtxExt(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *pCtx, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;
    aesXTSCipherContext *pAesCtx;
#ifdef __ZEROIZE_TEST__
    int counter = 0;
#endif

    MOC_UNUSED(pExtCtx);
    
    if (NULL == pCtx)
        return ERR_NULL_POINTER;
    
    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_XTS); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_XTS,0);

    if (*pCtx)
    {
      pAesCtx = (aesXTSCipherContext *)(*pCtx);

      if (NULL != pAesCtx->pKey1)
      {
        DeleteAESECBCtx (MOC_SYM(hwAccelCtx) (BulkCtx *)&(pAesCtx->pKey1));
      }
      if (NULL != pAesCtx->pKey2)
      {
        DeleteAESECBCtx (MOC_SYM(hwAccelCtx) (BulkCtx *)&(pAesCtx->pKey2));
      }

#ifdef __ZEROIZE_TEST__
        counter = 0;
        FIPS_PRINT("\nAESXTS - Before Zeroization\n");
        for( counter = 0; counter < (sizeof(aesXTSCipherContext)); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)*pCtx+counter));
        }
        FIPS_PRINT("\n");
#endif
        /* Zeroize the sensitive information before deleting the memory */
        DIGI_MEMSET((ubyte *) *pCtx, 0x00, sizeof(aesXTSCipherContext));
#ifdef __ZEROIZE_TEST__
        FIPS_PRINT("\nAESXTS - After Zeroization\n");
        for( counter = 0; counter < (sizeof(aesXTSCipherContext)); counter++)
        {
            FIPS_PRINT("%02x",*((ubyte*)*pCtx+counter));
        }
        FIPS_PRINT("\n");
#endif
        FREE(*pCtx);
        *pCtx = NULL;
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_XTS,0);
    return status;
}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
AESXTSEncrypt(MOC_SYM(hwAccelDescr hwAccelCtx) aesXTSCipherContext *pCtx,
              ubyte pTweak[AES_BLOCK_SIZE], ubyte *pPlain, ubyte4 plainLen)
{
    return AESXTSEncryptExt(MOC_SYM(hwAccelCtx) pCtx, pTweak, pPlain, plainLen, NULL);
}

MOC_EXTERN MSTATUS
AESXTSEncryptExt(MOC_SYM(hwAccelDescr hwAccelCtx) aesXTSCipherContext *pCtx,
                 ubyte pTweak[AES_BLOCK_SIZE], ubyte *pPlain, ubyte4 plainLen, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    ubyte4 i,j;
    sbyte4 eLen;
    ubyte T[AES_BLOCK_SIZE];
    ubyte x[AES_BLOCK_SIZE];
    ubyte y[AES_BLOCK_SIZE];
    ubyte Cin,Cout = 0; /* carries for LFSR shifting */

    MOC_UNUSED(pExtCtx);
    
    if (NULL == pCtx || NULL == pPlain || NULL == (ubyte *) pTweak || NULL == pCtx->pKey1 || NULL == pCtx->pKey2)
        return ERR_NULL_POINTER;

    if ( plainLen < AES_BLOCK_SIZE || plainLen > 0x1000000)
        return ERR_INVALID_ARG;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_XTS); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_XTS,0);

    /* encrypt the pTweak */
    AESALGO_blockEncryptEx (
      MOC_SYM (hwAccelCtx) pCtx->pKey2, NULL, pTweak, AES_BLOCK_SIZE * 8, T, &eLen);

    for (i = 0; i + AES_BLOCK_SIZE <= plainLen; i += AES_BLOCK_SIZE)
    {
        /* xor encrypted pTweak with input block */
        for ( j = 0; j < AES_BLOCK_SIZE; j++)
        {
            x[j] = pPlain[i+j] ^ T[j];
        }
        /* encrypt the block */
        AESALGO_blockEncryptEx (
          MOC_SYM (hwAccelCtx) pCtx->pKey1, NULL, x, AES_BLOCK_SIZE * 8, y, &eLen);
        /* xor encrypted pTweak with output block */
        for ( j = 0; j < AES_BLOCK_SIZE; j++)
        {
            pPlain[i+j] = y[j] ^ T[j];
        }
        /* LFSR "shift" the pTweak value for the next block */
        Cin = 0;
        for ( j = 0; j < AES_BLOCK_SIZE; j++)
        {
            Cout = (T[j] >> 7) & 1;
            T[j] = ((T[j] << 1) + Cin) & 0xFF;
            Cin = Cout;
        }
        if (Cout)
        {
            T[0] ^= GF_128_FDBK;
        }
    }

    if (i < plainLen) /* is there a final partial block to handle? */
    {
        for ( j = 0; i+j < plainLen; j++)
        {
            /* copy in the final plaintext bytes */
            x[j] = pPlain[i+j] ^ T[j];
            /* copy out the final ciphertext bytes */
            pPlain[i+j] = pPlain[i+j-AES_BLOCK_SIZE];
        }
        /* "steal" ciphertext to complete the block */
        for ( ; j < AES_BLOCK_SIZE; j++)
        {
            x[j] = pPlain[i+j-AES_BLOCK_SIZE] ^ T[j];
        }
        /* encrypt the block */
        AESALGO_blockEncryptEx (
          MOC_SYM (hwAccelCtx) pCtx->pKey1, NULL, x, AES_BLOCK_SIZE * 8, y, &eLen);
        /* merge the pTweak into the output block */
        for (j = 0; j < AES_BLOCK_SIZE; j++)
        {
            pPlain[i+j-AES_BLOCK_SIZE] = y[j] ^ T[j];
        }
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_XTS,0);
    return OK;
}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
AESXTSDecrypt(MOC_SYM(hwAccelDescr hwAccelCtx) aesXTSCipherContext *pCtx,
              ubyte pTweak[AES_BLOCK_SIZE], ubyte *pCipher, ubyte4 cipherLen)
{
    return AESXTSDecryptExt(MOC_SYM(hwAccelCtx) pCtx, pTweak, pCipher, cipherLen, NULL);
}

MOC_EXTERN MSTATUS
AESXTSDecryptExt(MOC_SYM(hwAccelDescr hwAccelCtx) aesXTSCipherContext *pCtx,
                 ubyte pTweak[AES_BLOCK_SIZE], ubyte *pCipher, ubyte4 cipherLen, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    sbyte4 lastBlockSize, limit, eLen;
    ubyte4 i, j;
    ubyte T[AES_BLOCK_SIZE];
    ubyte x[AES_BLOCK_SIZE];
    ubyte y[AES_BLOCK_SIZE];
    ubyte Cin,Cout = 0; /* carries for LFSR shifting */

    MOC_UNUSED(pExtCtx);
    
    if (NULL == pCtx || NULL == pCipher || NULL == (ubyte *) pTweak || NULL == pCtx->pKey1 || NULL == pCtx->pKey2)
        return ERR_NULL_POINTER;
    
    if ( cipherLen < AES_BLOCK_SIZE || cipherLen > 0x1000000)
        return ERR_INVALID_ARG;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_XTS); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_XTS,0);

    /* encrypt the pTweak */
    AESALGO_blockEncryptEx (
      MOC_SYM (hwAccelCtx) pCtx->pKey2, NULL, pTweak, AES_BLOCK_SIZE * 8, T, &eLen);

    lastBlockSize = (sbyte4) (cipherLen % AES_BLOCK_SIZE);
    limit =  (lastBlockSize) ? cipherLen - (lastBlockSize + AES_BLOCK_SIZE) : cipherLen;

    for (i = 0; (sbyte4)i < limit; i += AES_BLOCK_SIZE)
    {
        /* xor encrypted pTweak with input block */
        for ( j = 0; j < AES_BLOCK_SIZE; j++)
        {
            x[j] = pCipher[i+j] ^ T[j];
        }
        /* decrypt the block */
        AESALGO_blockDecryptEx (
          MOC_SYM (hwAccelCtx) pCtx->pKey1, NULL, x, AES_BLOCK_SIZE * 8, y, &eLen);
        /* xor encrypted pTweak with output block */
        for ( j = 0; j < AES_BLOCK_SIZE; j++)
        {
            pCipher[i+j] = y[j] ^ T[j];
        }
        /* LFSR "shift" the pTweak value for the next block */
        Cin = 0;
        for ( j = 0; j < AES_BLOCK_SIZE; j++)
        {
            Cout = (T[j] >> 7) & 1;
            T[j] = ((T[j] << 1) + Cin) & 0xFF;
            Cin = Cout;
        }
        if (Cout)
        {
            T[0] ^= GF_128_FDBK;
        }
    }

    if (lastBlockSize)
    {
        ubyte T_1[AES_BLOCK_SIZE];

        /* save the current version of T (m-1) */
        DIGI_MEMCPY(T_1, T, AES_BLOCK_SIZE);

        /* compute T (m) */
        /* last two blocks */
        /* LFSR "shift" the pTweak value for the next block */
        Cin = 0;
        for ( j = 0; j < AES_BLOCK_SIZE; j++)
        {
            Cout = (T[j] >> 7) & 1;
            T[j] = ((T[j] << 1) + Cin) & 0xFF;
            Cin = Cout;
        }
        if (Cout)
        {
            T[0] ^= GF_128_FDBK;
        }

        /* decrypt C[m-1] with T(m) */
        /* xor encrypted pTweak with input block */
        for ( j = 0; j < AES_BLOCK_SIZE; j++)
        {
            x[j] = pCipher[i+j] ^ T[j];
        }
        /* decrypt the block */
        AESALGO_blockDecryptEx (
          MOC_SYM (hwAccelCtx) pCtx->pKey1, NULL, x, AES_BLOCK_SIZE * 8, y, &eLen);
        /* xor encrypted pTweak with output block */
        for ( j = 0; j < AES_BLOCK_SIZE; j++)
        {
            pCipher[i+j] = y[j] ^ T[j];
        }

        i += AES_BLOCK_SIZE;
        for ( j = 0; i + j < cipherLen; ++j)
        {
            x[j] = pCipher[i+j] ^ T_1[j];
        }
        for (; j < AES_BLOCK_SIZE; ++j)
        {
            x[j] = pCipher[i+j-AES_BLOCK_SIZE] ^ T_1[j];
        }
        /* decrypt the block */
        AESALGO_blockDecryptEx (
          MOC_SYM (hwAccelCtx) pCtx->pKey1, NULL, x, AES_BLOCK_SIZE * 8, y, &eLen);

        for (j = 0; i + j < cipherLen; ++j)
        {
            pCipher[i+j] = pCipher[i+j-AES_BLOCK_SIZE];
        }
        for (j = 0; j < AES_BLOCK_SIZE; ++j)
        {
            pCipher[i+j-AES_BLOCK_SIZE] = y[j] ^ T_1[j];
        }
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_XTS,0);
    return OK;
}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
DoAESXTS(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData,
         sbyte4 dataLen, sbyte4 encrypt, ubyte *pTweak)
{
    return DoAESXTSExt(MOC_SYM(hwAccelCtx) pCtx, pData, dataLen, encrypt, pTweak, NULL);
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
DoAESXTSExt(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData,
            sbyte4 dataLen, sbyte4 encrypt, ubyte *pTweak, void *pExtCtx)
{
    /* below calls will handle input validation */
    aesXTSCipherContext *pAesCtx = (aesXTSCipherContext *) pCtx;
    if (encrypt)
    {
        return AESXTSEncryptExt( MOC_SYM(hwAccelCtx) pAesCtx, pTweak, pData, dataLen, pExtCtx);
    }
    else
    {
        return AESXTSDecryptExt( MOC_SYM(hwAccelCtx) pAesCtx, pTweak, pData, dataLen, pExtCtx);
    }
}

/*------------------------------------------------------------------*/

extern MSTATUS
CloneAESXTSCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx)
{
    MSTATUS status;
    aesXTSCipherContext *pSrc = pCtx;
    aesXTSCipherContext *pNewCtx = NULL;

    if ( (NULL == pSrc) || (NULL == pSrc->pKey1) || (NULL == pSrc->pKey2) ||
         (NULL == ppNewCtx) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_CALLOC((void **) &pNewCtx, 1, sizeof(aesXTSCipherContext));
    if (OK != status)
    {
        goto exit;
    }

    status = CloneAESCtx(
        MOC_SYM(hwAccelCtx) pSrc->pKey1, (BulkCtx *) &(pNewCtx->pKey1));
    if (OK != status)
    {
        goto exit;
    }

    status = CloneAESCtx(
        MOC_SYM(hwAccelCtx) pSrc->pKey2, (BulkCtx *) &(pNewCtx->pKey2));
    if (OK != status)
    {
        goto exit;
    }

    *ppNewCtx = pNewCtx;
    pNewCtx = NULL;

exit:

    if (NULL != pNewCtx)
    {
        (void) DeleteAESXTSCtx(MOC_SYM(hwAccelCtx) (BulkCtx *) &pNewCtx);
    }

    return status;
}

#endif /* (!defined(__DISABLE_AES_CIPHERS__) && !defined(__AES_HARDWARE_CIPHER__)) */
