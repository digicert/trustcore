/*
 * aes_xcbc_mac_96.c
 *
 * AES-XCBC-MAC-96 and derived Implementation ( RFC 3566, RFC 3664, RFC 4434)
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_XCBC_INTERNAL__

/*------------------------------------------------------------------*/

#include "../common/moptions.h"

#ifndef __DISABLE_AES_XCBC_MAC_96__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/aes.h"
#include "../crypto/aes_ecb.h"
#include "../crypto/aes_xcbc_mac_96.h"

#if (!defined(__DISABLE_AES_CIPHERS__))

#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#include "../crypto/aesalgo.h"

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif

#if (defined(__ENABLE_DIGICERT_AES_NI__) || defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__))
#include "../crypto/aesalgo_intel_ni.h"
#endif

/*---------------------------------------------------------------------------*/

static void AES_XCBC_MAC_96_genKey (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  aesCipherContext* pCtx,
  ubyte keyType,
  ubyte key[AES_BLOCK_SIZE]
  )
{
    FIPS_LOG_DECL_SESSION;
    sbyte4 outLen;
    ubyte keyGen[AES_BLOCK_SIZE];

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_AES_XCBC,AES_BLOCK_SIZE); /* See code below */

    DIGI_MEMSET( keyGen, keyType, AES_BLOCK_SIZE);
    AESALGO_blockEncryptEx (
      MOC_SYM(hwAccelCtx) pCtx, NULL, keyGen, AES_BLOCK_SIZE * 8, key, &outLen);

    FIPS_LOG_END_ALG(NON_FIPS_ALGO_AES_XCBC,AES_BLOCK_SIZE);
}

/*---------------------------------------------------------------------------*/

extern MSTATUS
AES_XCBC_MAC_96_init(MOC_SYM(hwAccelDescr hwAccelCtx)
                     const ubyte keyMaterial[AES_BLOCK_SIZE],
                     AES_XCBC_MAC_96_Ctx* pCtx)
{
    FIPS_LOG_DECL_SESSION;
    MSTATUS status;
    BulkCtx pAes = NULL;
    BulkCtx pKeyAes = NULL;
    ubyte   key[AES_BLOCK_SIZE];

#if defined(__ENABLE_DIGICERT_AES_NI__)
    /* Do a runtime sanity check */
    /* With ENABLE_DIGICERT_AES_NI defined, we don't have the software option */
    if (!check_for_aes_instructions())
    	return ERR_AES_NO_AESNI_SUPPORT;
#endif

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_AES_XCBC,AES_BLOCK_SIZE); /* See code below */

    status = ERR_NULL_POINTER;
    if ( !pCtx || !keyMaterial)
        goto exit;

    DIGI_MEMSET ((void *)pCtx, 0, sizeof (AES_XCBC_MAC_96_Ctx));

    /* initialize the 1st AES context */
    status = ERR_AES;
    pKeyAes = CreateAESECBCtx (
      MOC_SYM(hwAccelCtx) (ubyte *)keyMaterial, AES_BLOCK_SIZE, 1);
    if (NULL == pKeyAes)
      goto exit;

    /* initialize the 2nd context with K1 (cf. RFC 3566) */
    AES_XCBC_MAC_96_genKey (
      MOC_SYM(hwAccelCtx) (aesCipherContext *)pKeyAes, 1, key);

    pAes = CreateAESECBCtx (
      MOC_SYM(hwAccelCtx) key, AES_BLOCK_SIZE, 1);
    if (NULL == pAes)
      goto exit;

    pCtx->pKeyAesCtx = (aesCipherContext *)pKeyAes;
    pCtx->pAesCtx = (aesCipherContext *)pAes;
    pKeyAes = NULL;
    pAes = NULL;
    status = OK;

exit:

    DIGI_MEMSET ((void *)key, 0, sizeof (key));

    if (NULL != pKeyAes)
    {
      DeleteAESECBCtx (MOC_SYM(hwAccelCtx) &pKeyAes);
    }

    if (NULL != pAes)
    {
      DeleteAESCtx (MOC_SYM(hwAccelCtx) &pAes);
    }

    FIPS_LOG_END_ALG(NON_FIPS_ALGO_AES_XCBC,AES_BLOCK_SIZE);
    return (status);
}

/*---------------------------------------------------------------------------*/

extern MSTATUS
AES_XCBC_MAC_96_reset(MOC_SYM(hwAccelDescr hwAccelCtx) AES_XCBC_MAC_96_Ctx* pCtx)
{
    pCtx->pendingLen = 0;
    DIGI_MEMSET( pCtx->currBlock, 0, AES_BLOCK_SIZE);

    return OK;
}


/*---------------------------------------------------------------------------*/

extern MSTATUS
AES_XCBC_PRF_128_init(MOC_SYM(hwAccelDescr hwAccelCtx)
                      const ubyte keyMaterial[/*keyLength*/],
                      sbyte4 keyLength,
                      AES_XCBC_PRF_128_Ctx* pCtx)
{
    ubyte key[ AES_BLOCK_SIZE];
    sbyte4 i;

    /* basically identical to MAC_96 but allows key shorter or longer
    than 128 bits -- 16 bytes */
    if ( AES_BLOCK_SIZE == keyLength)
    {
        return AES_XCBC_MAC_96_init( MOC_SYM( hwAccelCtx) keyMaterial, pCtx);
    }
    else if ( AES_BLOCK_SIZE > keyLength)
    {
        /* pad with zero */
        for (i = 0; i < keyLength; ++i)
        {
            key[i] = keyMaterial[i];
        }
        for (; i < AES_BLOCK_SIZE; ++i)
        {
            key[i] = 0;
        }
        return AES_XCBC_MAC_96_init( MOC_SYM( hwAccelCtx) key, pCtx);
    }
    else /* AES_BLOCK_SIZE < keyLenth */
    {
        MSTATUS status, fstatus;

        for (i = 0; i < AES_BLOCK_SIZE; ++i)
        {
            key[i] = 0;
        }

        if (OK > (status = AES_XCBC_MAC_96_init( MOC_SYM( hwAccelCtx) key, pCtx)))
            goto clearFirstCtx;

        if ( OK > (status = AES_XCBC_PRF_128_update(MOC_SYM( hwAccelCtx) keyMaterial,
                                                    keyLength, pCtx)))
        {
            goto clearFirstCtx;
        }

        status = AES_XCBC_PRF_128_final( MOC_SYM(hwAccelCtx) key, pCtx);

clearFirstCtx:

        fstatus = AES_XCBC_clear(MOC_SYM(hwAccelCtx) pCtx);
        if (OK == status)
            status = fstatus;

        if (OK > status)
            return status;

        return AES_XCBC_MAC_96_init( MOC_SYM( hwAccelCtx) key, pCtx);
    }
}

extern MSTATUS AES_XCBC_clear (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  AES_XCBC_MAC_96_Ctx *pCtx
  )
{
  FIPS_LOG_DECL_SESSION;

  FIPS_LOG_START_ALG(NON_FIPS_ALGO_AES_XCBC,AES_BLOCK_SIZE);

  if (NULL != pCtx)
  {
    if (NULL != pCtx->pKeyAesCtx)
    {
      DeleteAESCtx (MOC_SYM(hwAccelCtx) (BulkCtx *)&(pCtx->pKeyAesCtx));
    }

    if (NULL != pCtx->pAesCtx)
    {
      DeleteAESCtx (MOC_SYM(hwAccelCtx) (BulkCtx *)&(pCtx->pAesCtx));
    }

    DIGI_MEMSET ((void *)pCtx, 0, sizeof (AES_XCBC_MAC_96_Ctx));
  }

  FIPS_LOG_END_ALG(NON_FIPS_ALGO_AES_XCBC,AES_BLOCK_SIZE);
  return (OK);
}

/*---------------------------------------------------------------------------*/

extern MSTATUS
AES_XCBC_MAC_96_update(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte* data,
                       sbyte4 dataLength, AES_XCBC_MAC_96_Ctx* pCtx)
{
    FIPS_LOG_DECL_SESSION;

    sbyte4 i;

    if ( !data || !  pCtx)
        return ERR_NULL_POINTER;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_AES_XCBC,AES_BLOCK_SIZE);

    if ( pCtx->pendingLen > 0 )
    {
        while ( pCtx->pendingLen < AES_BLOCK_SIZE && dataLength > 0)
        {
            pCtx->pending[ pCtx->pendingLen++] = *data++;
            dataLength--;
        }
        /* should we proceed ? only if full and more to do */
        if ( AES_BLOCK_SIZE == pCtx->pendingLen && dataLength > 0)
        {
            pCtx->pendingLen = 0;
            for (i = 0; i < AES_BLOCK_SIZE; ++i)
            {
                pCtx->pending[i] ^= pCtx->currBlock[i];
            }
            AESALGO_blockEncryptEx (
              MOC_SYM(hwAccelCtx) pCtx->pAesCtx, NULL, pCtx->pending, AES_BLOCK_SIZE * 8,
              pCtx->currBlock, &i);
        }
    }

    /* process all the bytes if there are more than AES_BLOCK_SIZE */
    while ( dataLength > AES_BLOCK_SIZE)
    {
        for (i = 0; i < AES_BLOCK_SIZE; ++i, dataLength--)
        {
            pCtx->pending[i] = (pCtx->currBlock[i] ^ (*data++));
        }
        AESALGO_blockEncryptEx (
          MOC_SYM(hwAccelCtx) pCtx->pAesCtx, NULL, pCtx->pending, AES_BLOCK_SIZE * 8,
          pCtx->currBlock, &i);
    }

    /* at this point, 1 < dataLength <= AES_BLOCK_SIZE */
    /* save the bytes that can't be processed in the pending array */
    while ( dataLength-- > 0)
    {
        pCtx->pending[pCtx->pendingLen++] = *data++;
    }

    FIPS_LOG_END_ALG(NON_FIPS_ALGO_AES_XCBC,AES_BLOCK_SIZE);
    return OK;
}



/*---------------------------------------------------------------------------*/

static MSTATUS
AES_XCBC_MAC_finalAux( MOC_SYM(hwAccelDescr hwAccelCtx)
                      ubyte cmac[/*cmacLen*/],
                      sbyte4 cmacLen,
                      AES_XCBC_MAC_96_Ctx* pCtx)
{
    FIPS_LOG_DECL_SESSION;

    sbyte4  i;
    ubyte   subKey[AES_BLOCK_SIZE];

    if (!cmac || !pCtx)
        return ERR_NULL_POINTER;

    FIPS_LOG_START_ALG(NON_FIPS_ALGO_AES_XCBC,AES_BLOCK_SIZE);

    /* which case are we in  */
    if ( AES_BLOCK_SIZE == pCtx->pendingLen)
    {
        /* multiple of block size -> use K2 */
        AES_XCBC_MAC_96_genKey(MOC_SYM(hwAccelCtx) pCtx->pKeyAesCtx, 2, subKey);
    }
    else
    {
        /* pad and use K3 */
        pCtx->pending[ pCtx->pendingLen++] = 0x80;
        while ( pCtx->pendingLen < AES_BLOCK_SIZE)
        {
            pCtx->pending[pCtx->pendingLen++] = 0;
        }
        AES_XCBC_MAC_96_genKey(MOC_SYM(hwAccelCtx) pCtx->pKeyAesCtx, 3, subKey);
    }

    for (i = 0; i < AES_BLOCK_SIZE; ++i)
    {
        pCtx->pending[i] ^= subKey[i];
        pCtx->pending[i] ^= pCtx->currBlock[i];
    }

    if ( AES_BLOCK_SIZE == cmacLen)
    {
      AESALGO_blockEncryptEx (
        MOC_SYM(hwAccelCtx) pCtx->pAesCtx, NULL, pCtx->pending, AES_BLOCK_SIZE * 8,
        cmac, &i);
    }
    else
    {
      AESALGO_blockEncryptEx (
        MOC_SYM(hwAccelCtx) pCtx->pAesCtx, NULL, pCtx->pending, AES_BLOCK_SIZE * 8,
        subKey, &i);

        /* truncate */
        DIGI_MEMCPY(cmac, subKey, cmacLen);
    }

    FIPS_LOG_END_ALG(NON_FIPS_ALGO_AES_XCBC,AES_BLOCK_SIZE);
    return OK;
}


/*---------------------------------------------------------------------------*/

extern MSTATUS
AES_XCBC_MAC_96_final( MOC_SYM(hwAccelDescr hwAccelCtx)
                      ubyte cmac[AES_XCBC_MAC_96_RESULT_SIZE],
                      AES_XCBC_MAC_96_Ctx* pCtx)
{
    return AES_XCBC_MAC_finalAux( MOC_SYM(hwAccelCtx) cmac,
                                    AES_XCBC_MAC_96_RESULT_SIZE,
                                    pCtx);
}


/*---------------------------------------------------------------------------*/

extern MSTATUS
AES_XCBC_PRF_128_final( MOC_SYM(hwAccelDescr hwAccelCtx)
                      ubyte cmac[AES_XCBC_PRF_128_RESULT_SIZE],
                      AES_XCBC_MAC_96_Ctx* pCtx)
{
    return AES_XCBC_MAC_finalAux( MOC_SYM(hwAccelCtx) cmac,
                                    AES_XCBC_PRF_128_RESULT_SIZE,
                                    pCtx);
}


#endif /* (!defined(__DISABLE_AES_CIPHERS__) && !defined(__AES_HARDWARE_CIPHER__)) */
#endif /* ifndef __DISABLE_AES_XCBC_MAC_96__ */
