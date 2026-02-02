/*
 * crypto_seg.c
 *
 * Cryptographic Methods for Mocana Segments
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

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/merrors.h"

#include "../common/mdefs.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/int64.h"
#include "../common/mem_pool.h"
#include "../common/moc_segment.h"
#include "../crypto/crypto.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/crypto_seg.h"
#include "../harness/harness.h"

/*------------------------------------------------------------------*/

#if (!(defined(__MD5_HARDWARE_HASH__)))
extern MSTATUS
CRYPTO_SEG_md5_updateDigest(MOC_HASH(hwAccelDescr hwAccelCtx) MD5_CTX *pContext, poolHeaderDescr *pPoolMahCellDescr,
                             const mocSegDescr *pSrcSegment, ubyte4 offset, ubyte4 dataLen,
                             intBoolean *pRetIsComplete)
{
    ubyte4  numBytesLeft;
    MSTATUS status = OK;
    const mocSegDescr*  pCurSeg = pSrcSegment;

    MOC_UNUSED(pPoolMahCellDescr);      /* used for linking segments into one DPD request */

    *pRetIsComplete = TRUE;

    offset = SEG_findSegment(&pCurSeg, offset);

    numBytesLeft = GET_SEG_BUFFER_LEN(pCurSeg) - offset;

    if (dataLen >= numBytesLeft)
    {
        status = MD5Update_m(MOC_HASH(hwAccelCtx) pContext, GET_SEG_BUFFER(pCurSeg) + offset, numBytesLeft);
        if (OK != status)
            goto exit;

        dataLen -= numBytesLeft;
    }
    else
    {
        status = MD5Update_m(MOC_HASH(hwAccelCtx) pContext, GET_SEG_BUFFER(pCurSeg) + offset, dataLen);
        goto exit;
    }

    while ( (NULL != (pCurSeg = GET_NEXT_SEG(pCurSeg))) && (0 != dataLen) )
    {
        if (dataLen >= GET_SEG_BUFFER_LEN(pCurSeg))
        {
            status = MD5Update_m(MOC_HASH(hwAccelCtx) pContext, GET_SEG_BUFFER(pCurSeg), GET_SEG_BUFFER_LEN(pCurSeg));
            if (OK != status)
                goto exit;
            
            dataLen -= GET_SEG_BUFFER_LEN(pCurSeg);
        }
        else
        {
            status = MD5Update_m(MOC_HASH(hwAccelCtx) pContext, GET_SEG_BUFFER(pCurSeg), dataLen);
            break;
        }
    }

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

#if (!(defined(__SHA1_HARDWARE_HASH__)))
extern MSTATUS
CRYPTO_SEG_sha1_updateDigest(MOC_HASH(hwAccelDescr hwAccelCtx) shaDescr *pContext, poolHeaderDescr *pPoolMahCellDescr,
                             const mocSegDescr *pSrcSegment, ubyte4 offset, ubyte4 dataLen,
                             intBoolean *pRetIsComplete)
{
    ubyte4  numBytesLeft;
    MSTATUS status = OK;
    const mocSegDescr*  pCurSeg = pSrcSegment;

    MOC_UNUSED(pPoolMahCellDescr);      /* used for linking segments into one DPD request */

    *pRetIsComplete = TRUE;

    offset = SEG_findSegment(&pCurSeg, offset);

    numBytesLeft = GET_SEG_BUFFER_LEN(pCurSeg) - offset;

    if (dataLen >= numBytesLeft)
    {
        (void) SHA1_updateDigest(MOC_HASH(hwAccelCtx) pContext, GET_SEG_BUFFER(pCurSeg) + offset, numBytesLeft);
        dataLen -= numBytesLeft;
    }
    else
    {
        (void) SHA1_updateDigest(MOC_HASH(hwAccelCtx) pContext, GET_SEG_BUFFER(pCurSeg) + offset, dataLen);
        goto exit;
    }

    while ( (NULL != (pCurSeg = GET_NEXT_SEG(pCurSeg))) && (0 != dataLen) )
    {
        if (dataLen >= GET_SEG_BUFFER_LEN(pCurSeg))
        {
            (void) SHA1_updateDigest(MOC_HASH(hwAccelCtx) pContext, GET_SEG_BUFFER(pCurSeg), GET_SEG_BUFFER_LEN(pCurSeg));
            dataLen -= GET_SEG_BUFFER_LEN(pCurSeg);
        }
        else
        {
            (void) SHA1_updateDigest(MOC_HASH(hwAccelCtx) pContext, GET_SEG_BUFFER(pCurSeg), dataLen);
            break;
        }
    }

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
CRYPTO_SEG_cryptoOp(MOC_SYM(hwAccelDescr hwAccelCtx) BulkEncryptionAlgo* pBEA,
                      void* pSymCipherCtx, ubyte* pCipherIV, ubyte4 cipherIVLength,
                      poolHeaderDescr *pPoolMahCellDescr, mocSegDescr *pSrcSegment,
                      ubyte4 offset, ubyte4 dataLen, ubyte4 encrypt)
{
    MSTATUS status = OK;
    ubyte block[16]; /* assume 16 = max block size */
    MOC_UNUSED(pPoolMahCellDescr);

    if ( cipherIVLength > 16)
    {
        status = ERR_INTERNAL_ERROR; /* need to update the code if block size > 16 */
        goto exit;
    }

    if ( pBEA->blockSize && dataLen % pBEA->blockSize )
    {
        status = ERR_SSL_CRYPT_BLOCK_SIZE;
        goto exit;
    }

    while ( dataLen > 0)
    {
        sbyte4 numCopied;
        ubyte4 toCopy;
        mocSegDescr *pNewSegment;
        ubyte4 newOffset;

        /* copy from seg to buffer */
        toCopy = ( sizeof(block) < dataLen) ? sizeof(block) : dataLen;

        numCopied = DIGI_copyFromSegEx(pSrcSegment, offset, block, toCopy,
                              &pNewSegment, &newOffset);
        if ( numCopied < 0)
        {
            status = (MSTATUS) numCopied;
            goto exit;
        }
        if ( (ubyte4)numCopied > dataLen)
        {
            status = ERR_INTERNAL_ERROR;
            goto exit;
        }

        /* decrypt */
        if ( OK > ( status = pBEA->cipherFunc(MOC_SYM(hwAccelCtx) pSymCipherCtx, block, numCopied, encrypt, pCipherIV)))
            goto exit;

        /* put it back in place */
        DIGI_copyToSeg( block, numCopied, pSrcSegment, offset);

        /* advance pointers */
        pSrcSegment = pNewSegment;
        offset = newOffset;
        dataLen -= numCopied;
    }

exit:
    return status;
}

