/*
 * aes_mmo.c
 *
 * AES-MMO Implementation
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

#include "../common/moptions.h"

#ifndef __DISABLE_AES_MMO__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/aes.h"

#if (!defined(__DISABLE_AES_CIPHERS__))

#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#include "../crypto/aesalgo.h"
#include "../crypto/aes_mmo.h"

#if (defined(__ENABLE_DIGICERT_AES_NI__) || defined(__ENABLE_DIGICERT_AES_NI_RUNTIME_CHECK__))
#include "../crypto/aesalgo_intel_ni.h"
#endif

/*--------------------------------------------------------------------------------*/

static MSTATUS AES_MMO_blockEncryptDigest(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  ubyte *keyMaterial,
  const ubyte *pDigestBlock,
  ubyte *pResult
  )
{
    aesCipherContext    aesCtx;
    sbyte4              i;
    sbyte4              retLength;
    MSTATUS             status;

#if defined(__ENABLE_DIGICERT_AES_NI__)
    /* Do a runtime sanity check */
    /* With ENABLE_DIGICERT_AES_NI defined, we don't have the software option */
    if (!check_for_aes_instructions())
    	return ERR_AES_NO_AESNI_SUPPORT;
#endif

    if (OK > (status = AESALGO_makeAesKeyEx (
      MOC_SYM(hwAccelCtx) &aesCtx, 128, keyMaterial, TRUE, MODE_ECB)))
        goto exit;

    if (OK > (status = AESALGO_blockEncryptEx (
      MOC_SYM(hwAccelCtx) &aesCtx, NULL, (ubyte *)pDigestBlock, AES_MMO_BLOCK_SIZE << 3, pResult, &retLength)))
        goto exit;

    for (i = 0; i < AES_MMO_BLOCK_SIZE; i++)
        pResult[i] ^= pDigestBlock[i];

exit:
    return status;
}


/*--------------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
AES_MMO_alloc(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return DIGI_MALLOC ((void **)pp_context, sizeof(AES_MMO_CTX));
}


/*--------------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
AES_MMO_free(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *pp_context)
{
    return DIGI_FREE(pp_context);
}


/*--------------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
AES_MMO_init(MOC_SYM(hwAccelDescr hwAccelCtx) AES_MMO_CTX *pAesMmoCtx)
{
    return DIGI_MEMSET((ubyte *)pAesMmoCtx, 0x00, sizeof(AES_MMO_CTX));
}


/*--------------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
AES_MMO_update(MOC_SYM(hwAccelDescr hwAccelCtx) AES_MMO_CTX *pAesMmoCtx, const ubyte *pData, ubyte4 dataLen)
{
    MSTATUS status = OK;

    if ((NULL == pAesMmoCtx) || (NULL == pData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

/*    u8_Incr32(&pAesMmoCtx->mesgLength, dataLen); */
    pAesMmoCtx->mesgLength += (dataLen << 3);

    /* some remaining from last time ?*/
    if (0 < pAesMmoCtx->hashBufferIndex)
    {
        sbyte4 numToCopy = AES_MMO_BLOCK_SIZE - pAesMmoCtx->hashBufferIndex;

        if ((sbyte4)dataLen < numToCopy)
        {
            numToCopy = dataLen;
        }

        DIGI_MEMCPY(pAesMmoCtx->hashBuffer + pAesMmoCtx->hashBufferIndex, pData, numToCopy);

        pData += numToCopy;
        dataLen -= numToCopy;
        pAesMmoCtx->hashBufferIndex += numToCopy;

        if (AES_MMO_BLOCK_SIZE == pAesMmoCtx->hashBufferIndex)
        {
          AES_MMO_blockEncryptDigest(
            MOC_SYM (hwAccelCtx) pAesMmoCtx->hashKey, pAesMmoCtx->hashBuffer, pAesMmoCtx->hashKey);
            pAesMmoCtx->hashBufferIndex = 0;
        }
    }

    /* process as much as possible right now */
    while (AES_MMO_BLOCK_SIZE <= dataLen)
    {
      AES_MMO_blockEncryptDigest (
        MOC_SYM (hwAccelCtx) pAesMmoCtx->hashKey, pData, pAesMmoCtx->hashKey);

      dataLen -= AES_MMO_BLOCK_SIZE;
      pData += AES_MMO_BLOCK_SIZE;
    }

    /* store the rest in the buffer */
    if (dataLen > 0)
    {
        DIGI_MEMCPY(pAesMmoCtx->hashBuffer + pAesMmoCtx->hashBufferIndex, pData, dataLen);
        pAesMmoCtx->hashBufferIndex += dataLen;
    }

exit:
    return status;

} /* AES_MMO_update */


/*--------------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
AES_MMO_final(MOC_SYM(hwAccelDescr hwAccelCtx) AES_MMO_CTX *pAesMmoCtx, ubyte *pHashOutput)
{
    MSTATUS status;

    if (OK > (status = DIGI_MEMSET(pHashOutput, 0x00, AES_MMO_DIGESTSIZE)))
        goto exit;

    pAesMmoCtx->hashBuffer[pAesMmoCtx->hashBufferIndex] = 0x80;

    if (3 > (AES_MMO_BLOCK_SIZE - pAesMmoCtx->hashBufferIndex))
    {
      if (OK > (status = AES_MMO_blockEncryptDigest (
        MOC_SYM (hwAccelCtx) pAesMmoCtx->hashKey, pAesMmoCtx->hashBuffer, pAesMmoCtx->hashKey)))
        goto exit;

      if (OK > (status = DIGI_MEMSET(pAesMmoCtx->hashBuffer, 0x00, AES_MMO_BLOCK_SIZE)))
        goto exit;
    }
    else
    {
        if (OK > (status = DIGI_MEMSET(1 + pAesMmoCtx->hashBufferIndex + pAesMmoCtx->hashBuffer, 0x00, AES_MMO_BLOCK_SIZE - (3 + pAesMmoCtx->hashBufferIndex))))
            goto exit;
    }

    /* ZigBee: only small messages are handled */
    pAesMmoCtx->hashBuffer[AES_MMO_BLOCK_SIZE - 2] = ((pAesMmoCtx->mesgLength >> 8) & 0xff);
    pAesMmoCtx->hashBuffer[AES_MMO_BLOCK_SIZE - 1] = ((pAesMmoCtx->mesgLength) & 0xff);

    if (OK > (status = AES_MMO_blockEncryptDigest (
      MOC_SYM (hwAccelCtx) pAesMmoCtx->hashKey, pAesMmoCtx->hashBuffer, pHashOutput)))
        goto exit;

exit:
    return status;
}


/*--------------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
AES_MMO_completeDigest(MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pHashOutput)
{
    AES_MMO_CTX aesMmoCtx;
    MSTATUS     status;

    if (OK > (status = AES_MMO_init(MOC_SYM(hwAccelCtx) &aesMmoCtx)))
        goto exit;

    if (OK > (status = AES_MMO_update(MOC_SYM(hwAccelCtx) &aesMmoCtx, pData, dataLen)))
        goto exit;

    status = AES_MMO_final(MOC_SYM(hwAccelCtx) &aesMmoCtx, pHashOutput);

exit:
    return status;
}

#endif /* (!defined(__DISABLE_AES_CIPHERS__)) */
#endif /* ifndef __DISABLE_AES_MMO__ */
