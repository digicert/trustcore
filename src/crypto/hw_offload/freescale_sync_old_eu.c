/*
 * freescale_sync_old_eu.c
 *
 * Freescale Coldfire "Old Execution Units" Hardware Acceleration Synchronous Adapter
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

#if (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) && defined(__ENABLE_FREESCALE_COLDFIRE_OLD_EU_HARDWARE_ACCEL__))

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../common/merrors.h"
#include "../../crypto/hw_accel.h"

#include "../../common/mdefs.h"
#include "../../common/mrtos.h"
#include "../../common/mtcp.h"
#include "../../common/mstdlib.h"
#include "../../common/debug_console.h"
#include "../../crypto/crypto.h"
#include "../../crypto/md45.h"
#include "../../crypto/md5.h"
#include "../../crypto/sha1.h"
#include "../../crypto/des.h"
#include "../../crypto/three_des.h"
#include "../../crypto/aes.h"

#include "common.h"

/*------------------------------------------------------------------*/

typedef struct
{
    sbyte4      encrypt;                            /* key used for encrypting or decrypting? */
    ubyte4      key[FSL_CAU_MAX_KEY_SIZE];          /* raw key in this case */
    sbyte4      keyLength;                          /* length of the key (in bytes) */

} fslCipherContext;


/*------------------------------------------------------------------*/

static ubyte parityBitLookup[128] =
{
    1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,
    0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,
    0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,
    1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0
};


/*------------------------------------------------------------------*/

static void
fixupParityBits(ubyte *pKeyMaterial, sbyte4 keyLength)
{
    sbyte4 index;

    for (index = 0; index < keyLength; index++)
        pKeyMaterial[index] = ((pKeyMaterial[index] & 0xfe) | parityBitLookup[pKeyMaterial[index] >> 1]);
}


/*------------------------------------------------------------------*/

static fslCipherContext *
CreateCtxCommon(ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    fslCipherContext* ctx = NULL;

    if (NULL == (ctx = MALLOC(sizeof(fslCipherContext))))
        goto exit;

    DIGI_MEMSET((ubyte *)ctx, 0x00, sizeof(fslCipherContext));

    DIGI_MEMCPY(&(ctx->key[0]), keyMaterial, keyLength);
    ctx->keyLength = keyLength;
    ctx->encrypt = encrypt;

exit:
    return ctx;
}


/*------------------------------------------------------------------*/

static MSTATUS
FSL_SYNC_OLD_EU_blockCipher(fslCipherContext* pContext, ubyte4 mode, ubyte4 *pSrc,
                            ubyte4 *pDest, ubyte4 numBytes, ubyte *pIV)
{
    ubyte4  tempIV[4];
    ubyte4  blocks = numBytes / pContext->blockSize;
    ubyte4  bytesProcessed = 0;
    sbyte4  i;
    MSTATUS status = OK;

    if ((NULL == pContext) || (NULL == pSrc) || (NULL == pDest))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* clone the IV */
    DIGI_MEMCPY((void *)tempIV, (void *)pIV, pContext->blockSize);

    /* reset symmetrical execution unit */
    MCF_SKHA_SKCMR = (MCF_SKHA_SKCMR_SWR);

    /* clear any pending interupts and reinitialize execution unit */
     MCF_SKHA_SKCMR = (MCF_SKHA_SKCMR_CI | MCF_SKHA_SKCMR_RI);

    /* of course, process the data as big endian data */
    MCF_SKHA_SKCR  = (MCF_SKHA_SKCR_ENDIAN);

    /* set algorithm mode */
    MCF_SKHA_SKMR  = mode;

    /* initialize the iv */
    MCF_SKHA_SKC0 = tempIV[0];
    MCF_SKHA_SKC1 = tempIV[1];

    if (8 < pContext->blockSize)
    {
        /* AES */
        MCF_SKHA_SKC2 = tempIV[2];
        MCF_SKHA_SKC3 = tempIV[3];
    }

    /* initialize key */
    MCF_SKHA_SKK0 = pContext->key[0];
    MCF_SKHA_SKK1 = pContext->key[1];

    if (pContext->keyLength >= 128)
    {
        MCF_SKHA_SKK2 = pContext->key[2];
        MCF_SKHA_SKK3 = pContext->key[3];
    }

    if (pContext->keyLength > 128)
    {
        MCF_SKHA_SKK4 = pContext->key[4];
        MCF_SKHA_SKK5 = pContext->key[5];
    }

    /* initialize key size */
    MCF_SKHA_SKKSR = (pContext->keyLength >> 3);

    while (0 < blocks)
    {
        ubyte4 numWords = 32;

        /* initialize data size */
        MCF_SKHA_SKDSR = ((blocks * pContext->blockSize) >= (4 * 32)) ? (4 * 32) : (blocks * pContext->blockSize);

        while ((0 < numBlocks) && (0 < numWords))
        {
            MCF_SKHA_SKIN = *pSrc;

            pSrc++;
            numWords--;
            bytesProcessed += 4;

            if (bytesProcessed == pContext->blockSize)
            {
                bytesProcessed = 0;
                blocks--;
            }
        }

        /* kick off the job */
        MCF_SKHA_SKCMR = (MCF_SKHA_SKCMR_GO);

        /* wait for crypto to complete */
        while (!(MCF_SKHA_SKSR & MCF_SKHA_SKSR_INT))
        {
            ;
        }

        /* get the results */
        while (32 > numWords)
        {
            *pDest = MCF_SKHA_SKOUT;

            pDest++;
            numWords++;
        }
    }

    /* copy out final iv */
    tempIV[0] = MCF_SKHA_SKC0;
    tempIV[1] = MCF_SKHA_SKC1;

    if (8 < pContext->blockSize)
    {
        /* AES */
        tempIV[2] = MCF_SKHA_SKC2;
        tempIV[3] = MCF_SKHA_SKC3;
    }

    /* copy back the IV */
    DIGI_MEMCPY((void *)pIV, (void *)tempIV, pContext->blockSize);

exit:
    return status;

} /* FSL_SYNC_OLD_EU_blockCipher */


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))
extern BulkCtx
CreateAESCtx(ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    if (!(16 == keyLength))
        goto exit;  /* bad key size */

    return (BulkCtx)(CreateCtxCommon(keyMaterial, keyLength, encrypt));
}
#endif /* ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))
extern MSTATUS
DoAES(BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MSTATUS status;

    if (0 != (dataLength % AES_BLOCK_SIZE))
    {
        status = ERR_AES_BAD_LENGTH;
        goto exit;
    }

    if (encrypt)
        status = FSL_SYNC_OLD_EU_blockCipher((fslCipherContext *)ctx, (MCF_SKHA_SKMR_CM_CBC | MCF_SKHA_SKMR_DIR_ENC | MCF_SKHA_SKMR_ALG_AES), data, data, dataLength, iv);
    else
        status = FSL_SYNC_OLD_EU_blockCipher((fslCipherContext *)ctx, (MCF_SKHA_SKMR_CM_CBC | MCF_SKHA_SKMR_DIR_DEC | MCF_SKHA_SKMR_ALG_AES), data, data, dataLength, iv);

#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
        DEBUG_ERROR(DEBUG_CRYPTO, "DoAES: cipher failed, error = ", status);
#endif

exit:
    return status;
}
#endif /* ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))
extern MSTATUS
DeleteAESCtx(BulkCtx* ctx)
{
    if (*ctx)
    {
        FREE(*ctx);
        *ctx = NULL;
    }

    return OK;
}
#endif /* ((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__))
extern BulkCtx
CreateDESCtx(ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    if ((DES_KEY_LENGTH != keyLength) || (NULL == keyMaterial))
        return NULL;  /* bad key size or material */

    fixupParityBits(keyMaterial, keyLength);

    return (BulkCtx)(CreateCtxCommon(keyMaterial, keyLength, encrypt));
}
#endif /* (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__))
extern BulkCtx
Create3DESCtx(ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    if ((THREE_DES_KEY_LENGTH != keyLength) || (NULL == keyMaterial))
        return NULL;  /* bad key size or material */

    fixupParityBits(keyMaterial, keyLength);

    return (BulkCtx)(CreateCtxCommon(keyMaterial, keyLength, encrypt));
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__))
extern MSTATUS
DoDES(BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MSTATUS status;

    if (0 != (dataLength % DES_BLOCK_SIZE))
    {
        status = ERR_DES_BAD_LENGTH;
        goto exit;
    }

    if (encrypt)
        status = FSL_SYNC_OLD_EU_blockCipher((fslCipherContext *)ctx, (MCF_SKHA_SKMR_CM_CBC | MCF_SKHA_SKMR_DIR_ENC | MCF_SKHA_SKMR_ALG_DES), data, data, dataLength, iv);
    else
        status = FSL_SYNC_OLD_EU_blockCipher((fslCipherContext *)ctx, (MCF_SKHA_SKMR_CM_CBC | MCF_SKHA_SKMR_DIR_DEC | MCF_SKHA_SKMR_ALG_DES), data, data, dataLength, iv);

#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
        DEBUG_ERROR(DEBUG_CRYPTO, "DoDES: cipher failed, error = ", status);
#endif

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__))
extern MSTATUS
Do3DES(BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    MSTATUS status;

    if (0 != (dataLength % THREE_DES_BLOCK_SIZE))
    {
        status = ERR_3DES_BAD_LENGTH;
        goto exit;
    }

    if (encrypt)
        status = FSL_SYNC_OLD_EU_blockCipher((fslCipherContext *)ctx, (MCF_SKHA_SKMR_CM_CBC | MCF_SKHA_SKMR_DIR_ENC | MCF_SKHA_SKMR_ALG_TDES), data, data, dataLength, iv);
    else
        status = FSL_SYNC_OLD_EU_blockCipher((fslCipherContext *)ctx, (MCF_SKHA_SKMR_CM_CBC | MCF_SKHA_SKMR_DIR_DEC | MCF_SKHA_SKMR_ALG_TDES), data, data, dataLength, iv);

#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
        DEBUG_ERROR(DEBUG_CRYPTO, "Do3DES: cipher failed, error = ", status);
#endif

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__))
extern MSTATUS
DeleteDESCtx(BulkCtx* ctx)
{
    if (*ctx)
    {
        FREE(*ctx);
        *ctx = NULL;
    }

    return OK;
}
#endif /* (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if ((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__))
extern MSTATUS
Delete3DESCtx(BulkCtx* ctx)
{
    if (*ctx)
    {
        FREE(*ctx);
        *ctx = NULL;
    }

    return OK;
}
#endif


/*------------------------------------------------------------------*/

#ifndef __MD5_ONE_STEP_HARDWARE_HASH__

MOC_EXTERN MSTATUS
MD5_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pMdOutput)
{
    ubyte4  addToHash;
    ubyte4  totalBytesAdded;
    MSTATUS status = OK;

    /* reset message digest execution unit */
    MCF_MDHA_MDCMR = (MCF_MDHA_MDCMR_CI | MCF_MDHA_MDCMR_RI | MCF_MDHA_MDCMR_SWR);

    /* enable big endian mode */
    MCF_MDHA_MDCR = (MCF_MDHA_MDCR_ENDIAN );


    /* choose MD5 complete */
    MCF_MDHA_MDMR = (MCF_MDHA_MDMR_MACFULL | MCF_MDHA_MDMR_MAC(1) | MCF_MDHA_MDMR_PDATA | MCF_MDHA_MDMR_ALG);

    /* set message length */
    MCF_MDHA_MDDSR = dataLen;

    /* write four byte chunks of data to message digest execution unit */
    for (totalBytesAdded = 0; totalBytesAdded < dataLen; totalBytesAdded += 4)
    {
        MCF_MDHA_MDIN = *((ubyte4 *)pData);
        pData += 4;
    }

    /* hash it! */
    MCF_MDHA_MDCMR = (MCF_MDHA_MDCMR_GO );

    /* wait for digest to complete */
    while (!(MCF_MDHA_MDSR & MCF_MDHA_MDSR_INT));

    /* Check for errors! */
    if (MCF_MDHA_MDSR & MCF_MDHA_MDSR_ERR)
    {
        status = ERR_CRYPTO_FAILURE;
        goto exit;
    }

    /* Save result */
    *((ubyte4*)pMdOutput)    = MCF_MDHA_MDA0;
    *((ubyte4*)pMdOutput+4)  = MCF_MDHA_MDB0;
    *((ubyte4*)pMdOutput+8)  = MCF_MDHA_MDC0;
    *((ubyte4*)pMdOutput+12) = MCF_MDHA_MDD0;

exit:
    return status;
}

#endif /* __MD5_ONE_STEP_HARDWARE_HASH__ */


/*------------------------------------------------------------------*/

#ifndef __SHA1_ONE_STEP_HARDWARE_HASH__

MOC_EXTERN MSTATUS
SHA1_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput)
{
    ubyte4  addToHash;
    ubyte4  totalBytesAdded;
    MSTATUS status = OK;

    /* reset message digest execution unit */
    MCF_MDHA_MDCMR = (MCF_MDHA_MDCMR_CI | MCF_MDHA_MDCMR_RI | MCF_MDHA_MDCMR_SWR);

    /* enable big endian mode */
    MCF_MDHA_MDCR = (MCF_MDHA_MDCR_ENDIAN );


    /* choose SHA1 complete */
    MCF_MDHA_MDMR = (MCF_MDHA_MDMR_MACFULL | MCF_MDHA_MDMR_MAC(1) | MCF_MDHA_MDMR_PDATA);

    /* set message length */
    MCF_MDHA_MDDSR = dataLen;

    /* write four byte chunks of data to message digest execution unit */
    for (totalBytesAdded = 0; totalBytesAdded < dataLen; totalBytesAdded += 4)
    {
        MCF_MDHA_MDIN = *((ubyte4 *)pData);
        pData += 4;
    }

    /* hash it! */
    MCF_MDHA_MDCMR = (MCF_MDHA_MDCMR_GO );

    /* wait for digest to complete */
    while (!(MCF_MDHA_MDSR & MCF_MDHA_MDSR_INT));

    /* Check for errors! */
    if (MCF_MDHA_MDSR & MCF_MDHA_MDSR_ERR)
    {
        status = ERR_CRYPTO_FAILURE;
        goto exit;
    }

    /* Save result */
    *((ubyte4*)pShaOutput)    = MCF_MDHA_MDA0;
    *((ubyte4*)pShaOutput+4)  = MCF_MDHA_MDB0;
    *((ubyte4*)pShaOutput+8)  = MCF_MDHA_MDC0;
    *((ubyte4*)pShaOutput+12) = MCF_MDHA_MDD0;
    *((ubyte4*)pShaOutput+16) = MCF_MDHA_MDE0;

exit:
    return status;
}

#endif /* __SHA1_ONE_STEP_HARDWARE_HASH__ */

#endif /* (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) && defined(__ENABLE_FREESCALE_COLDFIRE_OLD_EU_HARDWARE_ACCEL__)) */

