/*
 * aes_cmac.c
 *
 * AES-CMAC Implementation (RFC 4493)
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
@file   aes_cmac.c

@brief      Documentation file for the NanoCrypto AES-CMAC API.

@details    This file documents the definitions, enumerations, structures, and
            functions of the NanoCrypto AES-CMAC API.


@flags
To enable the functions in the NanoCrypto AES-CMAC API, the following flag must \b not be defined:
+ \c \__DISABLE_AES_CIPHERS__

@filedoc    aes_cmac.c
*/


/*------------------------------------------------------------------*/

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CMAC_INTERNAL__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/merrors.h"

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif
#include "../crypto/aes.h"
#include "../crypto/aes_cmac.h"
#include "../crypto/aes_ecb.h"

#if (!defined(__DISABLE_AES_CIPHERS__)) && (!defined(__DISABLE_AES_CMAC__))

#include "../common/mdefs.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#include "../crypto/aesalgo.h"

#if (defined(__ENABLE_DIGICERT_AES_NI__) || defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__))
#include "../crypto/aesalgo_intel_ni.h"
#endif

/*------------------------------------------------------------------*/

static void
AESCMAC_generateSubKeysAux( ubyte out[AES_BLOCK_SIZE],
                        const ubyte in[AES_BLOCK_SIZE],
                        const ubyte Rb[AES_BLOCK_SIZE])
{
    sbyte4 i;

    for (i = 0; i < AES_BLOCK_SIZE - 1; ++i)
    {
        out[i] = ((in[i] << 1) | (in[i+1] >> 7));
    }
    out[i] = (in[i] << 1);

    if (in[0] & 0x80)  /* need to XOR with the Rb constant */
    {
        for (i = 0; i < AES_BLOCK_SIZE; ++i)
        {
            out[i] ^= Rb[i];
        }
    }
    else
    {
        /* do something equivalent in time and energy
        to prevent side channel attacks */
        for (i = 0; i < AES_BLOCK_SIZE; ++i)
        {
            out[0] ^= Rb[0]; /* xoring one byte an even number of time */
        }
    }
}


/*------------------------------------------------------------------*/

static void AESCMAC_generateSubKeys (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  aesCipherContext *pAESCtx, ubyte K1[AES_BLOCK_SIZE],
  ubyte K2[AES_BLOCK_SIZE])
{
    sbyte4 dataLen;
    ubyte zeroBlock[AES_BLOCK_SIZE] = {0};
    ubyte L[AES_BLOCK_SIZE];

    AESALGO_blockEncryptEx (
      MOC_SYM(hwAccelCtx) pAESCtx, NULL, zeroBlock, AES_BLOCK_SIZE * 8, L, &dataLen);

    zeroBlock[AES_BLOCK_SIZE - 1] = 0x87; /* the Rb constant */

    AESCMAC_generateSubKeysAux( K1, L, zeroBlock);
    AESCMAC_generateSubKeysAux( K2, K1, zeroBlock);
}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
AESCMAC_init(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte *pKeyMaterial, sbyte4 keyLength, AESCMAC_Ctx *pCtx)
{
    return AESCMAC_initExt(MOC_SYM(hwAccelCtx) pKeyMaterial, keyLength, pCtx, NULL);
}

MOC_EXTERN MSTATUS
AESCMAC_initExt(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte *pKeyMaterial, sbyte4 keyLength, AESCMAC_Ctx *pCtx, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status;
    BulkCtx pAesCtx = NULL;

    MOC_UNUSED(pExtCtx);

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_CMAC); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_CMAC,keyLength);

#if defined(__ENABLE_DIGICERT_AES_NI__)
    /* Do a runtime sanity check */
    /* With ENABLE_DIGICERT_AES_NI defined, we don't have the software option */
    if (!check_for_aes_instructions())
    {
        status = ERR_AES_NO_AESNI_SUPPORT;
        goto exit;
    }
#endif

    status = ERR_NULL_POINTER;;
    if ( !pCtx || !pKeyMaterial)
      goto exit;

    DIGI_MEMSET ((void *)pCtx, 0, sizeof (AESCMAC_Ctx));

    /* initialize the AES context */
    status = ERR_AES;
    pAesCtx = CreateAESECBCtx (
      MOC_SYM(hwAccelCtx) (ubyte *)pKeyMaterial, keyLength, 1);
    if (NULL == pAesCtx)
      goto exit;

    pCtx->pAesCtx = pAesCtx;

    AES_OMAC_init( &pCtx->omacCtx);

    pAesCtx = NULL;
    status = OK;

exit:
    if (NULL != pAesCtx)
    {
      DeleteAESECBCtx (MOC_SYM(hwAccelCtx) &pAesCtx);
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_CMAC,keyLength);
    return (status);
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
AESCMAC_update(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte *pData, sbyte4 dataLength,
               AESCMAC_Ctx *pCtx)
{
    return AESCMAC_updateExt(MOC_SYM(hwAccelCtx) pData, dataLength, pCtx, NULL);
}

MOC_EXTERN MSTATUS
AESCMAC_updateExt(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte *pData, sbyte4 dataLength,
                                AESCMAC_Ctx *pCtx, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status = OK;

    MOC_UNUSED(pExtCtx);

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_CMAC); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_CMAC,0);

    if ( !pData || !  pCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = AES_OMAC_update( MOC_SYM(hwAccelCtx) pCtx->pAesCtx,
                                &pCtx->omacCtx, pData, dataLength);
exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_AES_CMAC,0);
    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
AESCMAC_final(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte cmac[CMAC_RESULT_SIZE],
              AESCMAC_Ctx *pCtx)
{
    return AESCMAC_finalExt(MOC_SYM(hwAccelCtx) cmac, pCtx, NULL);
}

MOC_EXTERN MSTATUS
AESCMAC_finalExt(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte cmac[CMAC_RESULT_SIZE],
              AESCMAC_Ctx *pCtx, void *pExtCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_CMAC); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_CMAC,0);

    MOC_UNUSED(pExtCtx);

    if (!cmac || !pCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = AES_OMAC_final(MOC_SYM(hwAccelCtx) pCtx->pAesCtx,
      &pCtx->omacCtx, cmac);

    AESCMAC_clear (MOC_SYM(hwAccelCtx) pCtx);

exit:
    FIPS_LOG_END_ALG(FIPS_ALGO_AES_CMAC,0);
    return status;
}

MOC_EXTERN MSTATUS AESCMAC_clear(MOC_SYM(hwAccelDescr hwAccelCtx) AESCMAC_Ctx *pCtx)
{
  FIPS_LOG_DECL_SESSION;

  if (!pCtx)
    return ERR_NULL_POINTER;

  FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_CMAC); /* may return here */
  FIPS_LOG_START_ALG(FIPS_ALGO_AES_CMAC,0);

  if (NULL != pCtx->pAesCtx)
  {
    DeleteAESECBCtx (MOC_SYM(hwAccelCtx) (BulkCtx *)&(pCtx->pAesCtx));
  }

#ifdef __ZEROIZE_TEST__
  {
    int counter = 0;

    FIPS_PRINT("\nAESCMAC - Before Zeroization\n");
    for( counter = 0; counter < sizeof(AESCMAC_Ctx); counter++)
    {
      FIPS_PRINT("%02x",*((ubyte*)pCtx + counter));
    }
    FIPS_PRINT("\n");
  }
#endif

  /* Zeroize the sensitive information before deleting the memory */
  DIGI_MEMSET((ubyte *)pCtx, 0x00, sizeof(AESCMAC_Ctx));

#ifdef __ZEROIZE_TEST__
  {
    int counter = 0;

    FIPS_PRINT("\nAESCMAC - After Zeroization\n");
    for( counter = 0; counter < sizeof(AESCMAC_Ctx); counter++)
    {
      FIPS_PRINT("%02x",*((ubyte*)pCtx + counter));
    }
    FIPS_PRINT("\n");
  }
#endif

  FIPS_LOG_END_ALG(FIPS_ALGO_AES_CMAC,0);
  return OK;
}

/* implementation */

/*---------------------------------------------------------------------------*/

/**
@private
@internal
@todo_add_ask   (Not sure when this was added, nor why it wasn't documented.)
@ingroup        hashing_ungrouped
*/
MOC_EXTERN MSTATUS
AES_OMAC_init(AES_OMAC_Ctx *pOMACCtx)
{
    FIPS_LOG_DECL_SESSION;

    if ( !pOMACCtx)
        return ERR_NULL_POINTER;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_CMAC); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_CMAC,0);

    pOMACCtx->pendingLen = 0;
    DIGI_MEMSET( pOMACCtx->currBlock, 0, AES_BLOCK_SIZE);

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_CMAC,0);
    return OK;
}


/*---------------------------------------------------------------------------*/

/**
@private
@internal
@todo_add_ask   (Not sure when this was added, nor why it wasn't documented.)
@ingroup        hashing_ungrouped
*/
MOC_EXTERN MSTATUS
AES_OMAC_update(MOC_SYM(hwAccelDescr hwAccelCtx) aesCipherContext *pAESCtx,
                    AES_OMAC_Ctx *pOMACCtx, const ubyte *pData,
                    sbyte4 dataLength)
{
    FIPS_LOG_DECL_SESSION;
    sbyte4 i;

    if (!pAESCtx || !pOMACCtx || !pData)
        return ERR_NULL_POINTER;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_CMAC); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_CMAC,0);

    if ( pOMACCtx->pendingLen > 0 )
    {
        while ( pOMACCtx->pendingLen < AES_BLOCK_SIZE && dataLength > 0)
        {
            pOMACCtx->pending[ pOMACCtx->pendingLen++] = *pData++;
            dataLength--;
        }
        /* should we proceed ? only if full and more to do */
        if ( AES_BLOCK_SIZE == pOMACCtx->pendingLen && dataLength > 0)
        {
            pOMACCtx->pendingLen = 0;
            for (i = 0; i < AES_BLOCK_SIZE; ++i)
            {
                pOMACCtx->pending[i] ^= pOMACCtx->currBlock[i];
            }
            AESALGO_blockEncryptEx (
              MOC_SYM(hwAccelCtx) pAESCtx, NULL, pOMACCtx->pending, AES_BLOCK_SIZE * 8,
              pOMACCtx->currBlock, &i);
        }
    }

    /* process all the bytes if there are more than AES_BLOCK_SIZE */
    while ( dataLength > AES_BLOCK_SIZE)
    {
        for (i = 0; i < AES_BLOCK_SIZE; ++i, dataLength--)
        {
            pOMACCtx->pending[i] = (pOMACCtx->currBlock[i] ^ (*pData++));
        }
        AESALGO_blockEncryptEx (
          MOC_SYM(hwAccelCtx) pAESCtx, NULL, pOMACCtx->pending, AES_BLOCK_SIZE * 8,
          pOMACCtx->currBlock, &i);
    }

    /* at this point, 1 < dataLength <= AES_BLOCK_SIZE */
    /* save the bytes that can't be processed in the pending array */
    while ( dataLength-- > 0)
    {
        pOMACCtx->pending[pOMACCtx->pendingLen++] = *pData++;
    }

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_CMAC,0);
    return OK;
}


/*---------------------------------------------------------------------------*/

/**
@private
@internal
@todo_add_ask   (Not sure when this was added, nor why it wasn't documented.)
@ingroup        hashing_ungrouped
*/
MOC_EXTERN MSTATUS
AES_OMAC_final( MOC_SYM(hwAccelDescr hwAccelCtx) aesCipherContext *pAESCtx,
                AES_OMAC_Ctx *pOMACCtx,
                ubyte cmac[CMAC_RESULT_SIZE])
{
    FIPS_LOG_DECL_SESSION;
    const ubyte *subKey;
    sbyte4 i;
    ubyte K1[AES_BLOCK_SIZE];
    ubyte K2[AES_BLOCK_SIZE];

    if (!pAESCtx || !pOMACCtx || !cmac)
        return ERR_NULL_POINTER;

    FIPS_GET_STATUS_RETURN_IF_BAD(FIPS_ALGO_AES_CMAC); /* may return here */
    FIPS_LOG_START_ALG(FIPS_ALGO_AES_CMAC,0);

    AESCMAC_generateSubKeys(MOC_SYM(hwAccelCtx) pAESCtx, K1, K2);

    /* which case are we in  */
    if ( AES_BLOCK_SIZE == pOMACCtx->pendingLen)
    {
        /* multiple of block size -> use K1 */
        subKey = K1;
    }
    else
    {
        /* pad and use K2 */
        pOMACCtx->pending[ pOMACCtx->pendingLen++] = 0x80;
        while ( pOMACCtx->pendingLen < AES_BLOCK_SIZE)
        {
            pOMACCtx->pending[pOMACCtx->pendingLen++] = 0;
        }
        subKey = K2;
    }

    for (i = 0; i < AES_BLOCK_SIZE; ++i)
    {
        pOMACCtx->pending[i] ^= subKey[i];
        pOMACCtx->pending[i] ^= pOMACCtx->currBlock[i];
    }
    AESALGO_blockEncryptEx (
      MOC_SYM(hwAccelCtx) pAESCtx, NULL, pOMACCtx->pending, AES_BLOCK_SIZE * 8,
      cmac, &i);

    FIPS_LOG_END_ALG(FIPS_ALGO_AES_CMAC,0);
    return OK;
}


#endif /* (!defined(__DISABLE_AES_CIPHERS__) && !defined(__AES_HARDWARE_CIPHER__)) */
