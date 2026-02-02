/*
 * rc5algo.c
 *
 * RC5 Algorithm
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_RC5_INTERNAL__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mocana.h"
#include "../common/mrtos.h"
#include "../common/mem_part.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../crypto/hw_accel.h"
#include "../crypto/rc5algo.h"
#include "../cap/capdecl.h"

#if defined(__ENABLE_DIGICERT_RC5__)

#if defined(__ENABLE_DIGICERT_WEAK_RC5__)

/* If compiled for weak RC5, then the key can be 0 bytes long and 0...
 */
#define MOC_MIN_RC5_KEY_LEN_BYTES  1
#define MOC_MIN_RC5_ROUND_COUNT    1

#else

/* ... but if not compiled for weak RC5, then the key has to be at least 8 bytes
 * and the round count must be at least 12.
 */
#define MOC_MIN_RC5_KEY_LEN_BYTES  8
#define MOC_MIN_RC5_ROUND_COUNT    12

#endif /* defined(__ENABLE_DIGICERT_WEAK_RC5__) */

#define MOC_MAX_RC5_KEY_LEN_BYTES  255
#define MOC_MAX_RC5_ROUND_COUNT    255

#define MOC_MAX_RC5_BLOCK_SIZE     16

typedef struct
{
  ubyte     *pKeyData;
  ubyte4     keyDataLen;
  ubyte4     roundCount;
  ubyte4     blockSizeBits;
  void      *pKeyTable;
  ubyte4     keyTableSize;
} MocRc5Ctx;

typedef struct
{
  /* first two fields need to match shadow structure
     in crypto_interface_rc5.c */
  MocSymCtx    pMocSymCtx;
  ubyte        enabled;
  MocRc5Ctx    rc5Ctx;
  sbyte4       padding;
  sbyte4       encrypt;
  ubyte       *pInitVector;
  ubyte4       initVectorLen;
  ubyte       *pCurrentVector;
  ubyte       *pLeftovers;
  ubyte4       leftoverLen;
  ubyte4       state;
} MocRc5LocalCtx;

#define MOC_RC5_6_5_STATE_CREATE  1
#define MOC_RC5_6_5_STATE_INIT    2
#define MOC_RC5_6_5_STATE_UPDATE  3
#define MOC_RC5_6_5_STATE_FINAL   4

/* Build the L Array from the key data. This version builds lCount 32-bit words.
 * <p>This assumes the LArray exists, it has lCount words, and each word is init
 * to 0.
 */
void SetLArray32 (
  ubyte *pKeyData,
  ubyte4 keyDataLen,
  ubyte4 *pLArray,
  ubyte4 lCount
  );

/* Build the L Array from the key data. This version builds lCount 64-bit words.
 * <p>This assumes the LArray exists, it has lCount words, and each word is init
 * to 0.
 */
void SetLArray64 (
  ubyte *pKeyData,
  ubyte4 keyDataLen,
  ubyte8 *pLArray,
  ubyte4 lCount
  );

/* Initialize the table with the fixed, pseudo-random values.
 */
void InitKeyTable32 (
  ubyte4 *pTable,
  ubyte4 count
  );

/* Initialize the table with the fixed, pseudo-random values.
 */
void InitKeyTable64 (
  ubyte8 *pTable,
  ubyte4 count
  );

/* Do the key table mixing. This updates the key table using the key data.
 */
void MixKeyTable32 (
  ubyte4 *pTable,
  ubyte4 tableCount,
  ubyte4 *pLArray,
  ubyte4 lCount
  );

/* Do the key table mixing. This updates the key table using the key data.
 */
void MixKeyTable64 (
  ubyte8 *pTable,
  ubyte4 tableCount,
  ubyte8 *pLArray,
  ubyte4 lCount
  );

/* Perform one block of RC5. It will perfomr 32- or 64-bit RC5 depending on the
 * input block size.
 * This function will determine if encrypting or decrypting based on the encrypt
 * flag in pCtx.
 * It will perform CBC if necessary.
 * It will place the output into the given buffer.
 */
void Rc5BlockOperation (
  MocRc5LocalCtx *pCtx,
  ubyte *pInputBlock,
  ubyte4 blockSize,
  ubyte *pOutputBlock
  );

/* Encrypt or decrypt one block.
 */
void Rc5BlockOperation32 (
  ubyte4 cipherFlag,
  ubyte4 roundCount,
  ubyte4 *pKeyTable,
  ubyte *pInputBlock,
  ubyte *pOutputBlock
  );

/* Encrypt or decrypt one block.
 */
void Rc5BlockOperation64 (
  ubyte4 cipherFlag,
  ubyte4 roundCount,
  ubyte8 *pKeyTable,
  ubyte *pInputBlock,
  ubyte *pOutputBlock
  );

/* Build the RC5 key table from the given key.
 * <p>The caller passes in the key, the block size in bits, (64 or 128 are the
 * only allowed block sizes), the round count, and an address where the function
 * will deposit a pointer to the key table.
 * <p>The key table will be an array of 2 * (roundCount + 1) words, where each
 * word is either 32 bits (64-bit blocks) or 64 bits (128-bit blocks).
 * <p>It is the responsibility of the caller to free the memory (using DIGI_FREE).
 * The buffer should be overwritten before freeing, so the function also returns
 * the size of the buffer allocated.
 */
MSTATUS BuildRc5KeyTableAlloc (
  ubyte *pKeyData,
  ubyte4 keyDataLen,
  ubyte4 blockSizeBits,
  ubyte4 roundCount,
  void **ppKeyTable,
  ubyte4 *pKeyTableSize
  );

#define MOC_RC5_P_VALUE_32  0xb7e15163
#define MOC_RC5_Q_VALUE_32  0x9e3779b9

#define MOC_RC5_P_VALUE_64  0xb7e151628aed2a6bULL
#define MOC_RC5_Q_VALUE_64  0x9e3779b97f4a7c15ULL

/* Rotate a 32-bit word left by the given count.
 * _result is a ubyte4.
 * _word is a ubyte4.
 * _count is a ubyte4
 * _shcount is a temp variable and a ubyte4.
 */
#define ROTL_32(_result,_word,_count,_shcount) \
    (_shcount) = (_count) & 31; \
    (_result) = ((_word) << (_shcount)) | ((_word) >> (32 - (_shcount)))

/* rotate right
 */
#define ROTR_32(_result,_word,_count,_shcount) \
    (_shcount) = (_count) & 31; \
    (_result) = ((_word) >> (_shcount)) | ((_word) << (32 - (_shcount)))

/* Rotate a 32-bit word left by the given count.
 * _result is a ubyte8.
 * _word is a ubyte8.
 * _count is a ubyte4
 * _shcount is a temp variable and a ubyte4.
 */
#define ROTL_64(_result,_word,_count,_shcount) \
    (_shcount) = (_count) & 63; \
    (_result) = ((_word) << (_shcount)) | ((_word) >> (64 - (_shcount)))

/* rotate right
 */
#define ROTR_64(_result,_word,_count,_shcount) \
    (_shcount) = (_count) & 63; \
    (_result) = ((_word) >> (_shcount)) | ((_word) << (64 - (_shcount)))

extern MSTATUS MocCreateRC5Ctx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  ubyte *keyMaterial,
  sbyte4 keyLength,
  ubyte *iv,
  sbyte4 ivLen,
  sbyte4 blockSizeBits,
  sbyte4 roundCount,
  sbyte4 padding,
  sbyte4 encrypt,
  BulkCtx *ppBulkCtx
  )
{
  MSTATUS status;
  ubyte4 blockSize, vectorSize, bufSize;
  ubyte *pBuf = NULL;
  MocRc5LocalCtx *pNewCtx = NULL;

  bufSize = 0;

  status = ERR_NULL_POINTER;

#if !defined(__ENABLE_DIGICERT_WEAK_RC5__)
  if (NULL == keyMaterial)
    goto exit;
#endif

  if (NULL == ppBulkCtx)
    goto exit;

  *ppBulkCtx = NULL;

  status = ERR_RC5_INVALID_KEY_LEN;
  if ( (MOC_MIN_RC5_KEY_LEN_BYTES > keyLength) ||
       (MOC_MAX_RC5_KEY_LEN_BYTES < keyLength) )
    goto exit;

  status = ERR_RC5_INVALID_ROUND_COUNT;
  if ( (MOC_MIN_RC5_ROUND_COUNT > roundCount) ||
       (MOC_MAX_RC5_ROUND_COUNT < roundCount) )
    goto exit;

  blockSize = blockSizeBits >> 3;
  status = ERR_RC5_INVALID_BLOCK_SIZE;
  if ( (64 != blockSizeBits) && (128 != blockSizeBits) )
    goto exit;

  vectorSize = 0;

  if (NULL != iv)
  {
    status = ERR_RC5_BAD_IV_LENGTH;
    if (ivLen != (sbyte4) blockSize)
      goto exit;

    vectorSize = 2 * blockSize;
  }

  /* Allocate the LocalCtx with 3 blocks and the key.
   * Or if there is no IV, 1 block and the key.
   */
  bufSize = sizeof (MocRc5LocalCtx) + vectorSize + blockSize + keyLength;
  status = DIGI_CALLOC ((void **)&pBuf, bufSize, 1);
  if (OK != status)
    goto exit;

  /* Set the buffers to point to the space after the struct.
   */
  pNewCtx = (MocRc5LocalCtx *)pBuf;
  pNewCtx->pLeftovers = pBuf + sizeof (MocRc5LocalCtx);
  if (0 != vectorSize)
  {
    pNewCtx->pInitVector = pBuf + sizeof (MocRc5LocalCtx);
    pNewCtx->pCurrentVector = pNewCtx->pInitVector + blockSize;
    pNewCtx->pLeftovers = pNewCtx->pCurrentVector + blockSize;
  }

  pNewCtx->rc5Ctx.pKeyData = pNewCtx->pLeftovers + blockSize;

  /* Copy in the data
   */
  status = DIGI_MEMCPY (
    (void *)(pNewCtx->rc5Ctx.pKeyData), keyMaterial, keyLength);
  if (OK != status)
    goto exit;

  pNewCtx->rc5Ctx.keyDataLen = keyLength;
  pNewCtx->rc5Ctx.roundCount = roundCount;
  pNewCtx->rc5Ctx.blockSizeBits = blockSizeBits;

  if (NULL != iv)
  {
    status = DIGI_MEMCPY (
      (void *)(pNewCtx->pInitVector), (void *)iv, blockSize);
    if (OK != status)
      goto exit;

    pNewCtx->initVectorLen = blockSize;

    status = DIGI_MEMCPY (
      (void *)(pNewCtx->pCurrentVector), (void *)iv, blockSize);
    if (OK != status)
      goto exit;
  }

  pNewCtx->padding = 1;
  if (0 == padding)
    pNewCtx->padding = 0;
  pNewCtx->encrypt = 1;
  if (0 == encrypt)
    pNewCtx->encrypt = 0;

  status = BuildRc5KeyTableAlloc (
    keyMaterial, keyLength, blockSizeBits, roundCount,
    &(pNewCtx->rc5Ctx.pKeyTable), &(pNewCtx->rc5Ctx.keyTableSize));
  if (OK != status)
    goto exit;

  pNewCtx->state = MOC_RC5_6_5_STATE_INIT;

  *ppBulkCtx = (BulkCtx)pNewCtx;
  pBuf = NULL;

exit:

  if (NULL != pBuf)
  {
    if (0 != bufSize)
    {
      DIGI_MEMSET ((void *)pBuf, 0, bufSize);
      DIGI_FREE ((void **)&pBuf);
    }
  }

  return (status);
}

extern MSTATUS MocDeleteRC5Ctx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx *ctx
  )
{
  MSTATUS status, fStatus;
  MocRc5LocalCtx *pRc5Ctx;

  status = OK;
  if (NULL == ctx)
    goto exit;

  if (NULL == *ctx)
    goto exit;

  pRc5Ctx = (MocRc5LocalCtx *)(*ctx);

  if ( (NULL != pRc5Ctx->rc5Ctx.pKeyData) && (0 != pRc5Ctx->rc5Ctx.keyDataLen) )
  {
    fStatus = DIGI_MEMSET (
      (void *)(pRc5Ctx->rc5Ctx.pKeyData), 0, pRc5Ctx->rc5Ctx.keyDataLen);
    if (OK == status)
      status = fStatus;
  }
  if ( (NULL != pRc5Ctx->rc5Ctx.pKeyTable) && (0 != pRc5Ctx->rc5Ctx.keyTableSize) )
  {
    fStatus = DIGI_MEMSET (
      (void *)(pRc5Ctx->rc5Ctx.pKeyTable), 0, pRc5Ctx->rc5Ctx.keyTableSize);
    if (OK == status)
      status = fStatus;

    fStatus = DIGI_FREE ((void **)&(pRc5Ctx->rc5Ctx.pKeyTable));
    if (OK == status)
      status = fStatus;
  }

  fStatus = DIGI_FREE ((void **)ctx);
  if (OK == status)
    status = fStatus;

exit:

  return (status);
}

extern MSTATUS MocReinitRC5Ctx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pBulkCtx
  )
{
  MSTATUS status;
  MocRc5LocalCtx *pCtx = (MocRc5LocalCtx *)pBulkCtx;

  status = ERR_NULL_POINTER;
  if (NULL == pBulkCtx)
    goto exit;

  /* If there is an init vector, set currentVector to the original vector.
   */
  if ( (NULL != pCtx->pInitVector) && (NULL != pCtx->pCurrentVector) &&
       (0 != pCtx->initVectorLen) )
  {
    status = DIGI_MEMCPY (
      (void *)(pCtx->pCurrentVector), (void *)(pCtx->pInitVector),
      pCtx->initVectorLen);
    if (OK != status)
      goto exit;
  }

  pCtx->leftoverLen = 0;
  pCtx->state = MOC_RC5_6_5_STATE_INIT;
  status = OK;

exit:

  return (status);
}

extern MSTATUS MocRC5Update (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pBulkCtx,
  sbyte4 encrypt,
  ubyte *pDataToProcess,
  ubyte4 dataToProcessLen,
  ubyte *pProcessedData,
  ubyte4 bufferSize,
  ubyte4 *pProcessedDataLen
  )
{
  MSTATUS status;
  sbyte4 eFlag;
  ubyte4 bufSize, blockSize, previousLen, newLen, leftoverLen;
  ubyte *pCurrent, *pOutput;
  MocRc5LocalCtx *pCtx = (MocRc5LocalCtx *)pBulkCtx;

  status = ERR_NULL_POINTER;
  if ( (NULL == pBulkCtx) || (NULL == pProcessedDataLen) )
    goto exit;

  if ( (NULL == pDataToProcess) && (0 != dataToProcessLen) )
    goto exit;

  *pProcessedDataLen = 0;

  /* You can call Update only after INIT or UPDATE.
   */
  status = ERR_INVALID_INPUT;
  if ( (MOC_RC5_6_5_STATE_INIT != pCtx->state) &&
       (MOC_RC5_6_5_STATE_UPDATE != pCtx->state) )
    goto exit;

  eFlag = 1;
  if (encrypt == 0)
    eFlag = 0;

  status = ERR_INVALID_ARG;
  if (eFlag != pCtx->encrypt)
    goto exit;

  /* If there's no input, there's nothing to do.
   */
  status = OK;
  if (0 == dataToProcessLen)
    goto exit;

  /* Determine the output length.
   * If encrypting (whether padding or not), just output the complete blocks.
   * If decrypting and not padding, just output the complete blocks.
   * If decrypting and padding, and if there are leftover bytes, output the
   * complete blocks.
   * If decrypting an padding and if there are no leftover bytes, then we need to
   * hold the last block in reserve. Hence, output complete blocks - 1;
   */
  newLen = dataToProcessLen + pCtx->leftoverLen;
  blockSize = pCtx->rc5Ctx.blockSizeBits >> 3;

  pCurrent = pDataToProcess;
  bufSize = 0;

  leftoverLen = newLen & (blockSize - 1);
  pOutput = pProcessedData;

  /* Init previousLen to the number of bytes needed to fill up leftovers. If the
   * current leftovers is 0, we don't want to operate on the leftovers buffer,
   * just operate on the input directly.
   * The exception is if we're decrypting and padding is on. We might get
   * blockSize input with no data in leftovers.
   * So go ahead and determine this value. Later on, if we're not dealing with
   * the special case, we'll mkae a previousLen of blockSize go to 0.
   */
  previousLen = blockSize - pCtx->leftoverLen;
  if (dataToProcessLen <= previousLen)
    previousLen = dataToProcessLen;

  /* We know there is data because if not we would have exited already.
   * If the leftoverLen is 0, there must be at least one block of input.
   * If this is decrypt and padding, we need leftovers (either the 1 or so bytes
   * or a full block)
   * Hence, if leftoverLen is 0 then we need to make sure leftoverLen is one
   * block.
   */
  if ( (0 != pCtx->padding) && (0 == pCtx->encrypt) && (0 == leftoverLen) )
  {
    leftoverLen = blockSize;

    /* There is one special case, if the new input plus the previous leftovers
     * make up one block total. We don't want to do anything except copy
     * leftovers.
     */
    if (newLen == blockSize)
    {
      leftoverLen = previousLen;
      previousLen = 0;
    }
    newLen -= blockSize;
  }
  else
  {
    newLen -= leftoverLen;
    previousLen &= (blockSize - 1);
  }

  if (NULL != pProcessedData)
    bufSize = bufferSize;

  *pProcessedDataLen = newLen;
  status = ERR_BUFFER_TOO_SMALL;
  if (bufSize < newLen)
    goto exit;

  /* Now use newLen to keep track of how much input there is left.
   */
  newLen = dataToProcessLen - (previousLen + leftoverLen);
  status = OK;

  /* Copy bytes to complete a block.
   */
  if (0 != previousLen)
  {
    status = DIGI_MEMCPY (
      (void *)(pCtx->pLeftovers + pCtx->leftoverLen), (void *)pCurrent,
      previousLen);
    if (OK != status)
      goto exit;

    pCtx->leftoverLen += previousLen;
    pCurrent += previousLen;

    /* If this does not complete a block, there's nothing more we need to do.
     */
    if (pCtx->leftoverLen < blockSize)
      goto exit;
  }

  /* It's possible we have a full block in pLeftovers even if we didn't add to it
   * this call.
   * This happens when decrypting with padding and we filled it up last call, but
   * did not process it yet. Now we know it is not padding, so we can process it.
   */
  if (blockSize == pCtx->leftoverLen)
  {
    /* Process this block.
     * If we're decrypting and padding, we need to keep a block in reserve. If
     * there is only one block of total input, we don't want to process. But we
     * took care of that by setting previousLen to 0. Hence, if we are in this
     * code, we want to process.
     */
    Rc5BlockOperation (
      pCtx, pCtx->pLeftovers, blockSize, pOutput);

    pOutput += blockSize;
    pCtx->leftoverLen = 0;
  }

  /* As long as there are complete blocks in the input, process them.
   */
  while (0 != newLen)
  {
    Rc5BlockOperation (
      pCtx, pCurrent, blockSize, pOutput);

    newLen -= blockSize;
    pCurrent += blockSize;
    pOutput += blockSize;
  }

  /* If there are any leftover bytes, copy them into the leftover buffer.
   * It's possible there are bytes in the leftovers buffer, if previousLen is 0
   * and newLen is 0.
   */
  if (0 != leftoverLen)
  {
    status = DIGI_MEMCPY (
      (void *)(pCtx->pLeftovers + pCtx->leftoverLen), (void *)pCurrent,
      leftoverLen);
    if (OK != status)
      goto exit;

    pCtx->leftoverLen += leftoverLen;
  }

exit:

  return (status);
}

extern MSTATUS MocRC5Final (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pBulkCtx,
  sbyte4 encrypt,
  ubyte *pDataToProcess,
  ubyte4 dataToProcessLen,
  ubyte *pProcessedData,
  ubyte4 bufferSize,
  ubyte4 *pProcessedDataLen
  )
{
  MSTATUS status;
  sbyte4 eFlag;
  ubyte4 index, blockSize, bufSize, totalLen, padLen, updateLen;
  MocRc5LocalCtx *pCtx = (MocRc5LocalCtx *)pBulkCtx;

  status = ERR_NULL_POINTER;
  if ( (NULL == pBulkCtx) || (NULL == pProcessedDataLen) )
    goto exit;

  if ( (NULL == pDataToProcess) && (0 != dataToProcessLen) )
    goto exit;

  *pProcessedDataLen = 0;

  /* You can call Final only after INIT or UPDATE.
   */
  status = ERR_INVALID_INPUT;
  if ( (MOC_RC5_6_5_STATE_INIT != pCtx->state) &&
       (MOC_RC5_6_5_STATE_UPDATE != pCtx->state) )
    goto exit;

  eFlag = 1;
  if (encrypt == 0)
    eFlag = 0;

  status = ERR_INVALID_ARG;
  if (eFlag != pCtx->encrypt)
    goto exit;

  /* How big is the output?
   * If no padding, the output length is the total length. Make sure the total
   * length is a multiple of the blockSize.
   * If encrypting and padding, the padLen will fill out a block, or if the total
   * len is altready a block, the padLen will be a complete block.
   * If decrypting and padding, we'll strip some padding, but we don't know
   * whether it will be 1, 2, 3, ..., blockSize bytes. So the max output len is
   * the total len. Make sure the total length is a multiple of the blockSize.
   */
  totalLen = dataToProcessLen + pCtx->leftoverLen;
  padLen = 0;
  blockSize = pCtx->rc5Ctx.blockSizeBits >> 3;

  if ( (0 != pCtx->encrypt) && (0 != pCtx->padding) )
    padLen = blockSize - (totalLen & (blockSize - 1));

  bufSize = 0;
  totalLen += padLen;

  if (NULL != pProcessedData)
    bufSize = bufferSize;

  /* Make sure the totalLen is a multiple of the block size.
   */
  status = ERR_RC5_BAD_LENGTH;
  if (0 != (totalLen & (blockSize - 1)))
    goto exit;

  *pProcessedDataLen = totalLen;
  status = ERR_BUFFER_TOO_SMALL;
  if (bufSize < totalLen)
    goto exit;

  status = OK;

  /* Call Update with any input info.
   */
  updateLen = 0;
  if (0 != dataToProcessLen)
  {
    status = MocRC5Update (
      MOC_SYM(hwAccelCtx) pBulkCtx, encrypt, pDataToProcess, dataToProcessLen,
      pProcessedData, bufSize, &updateLen);
    if (OK != status)
      goto exit;
  }

  /* If there is no padding, we're done.
   */
  if (0 == pCtx->padding)
    goto exit;

  /* If encrypting, append the pad bytes and encrypt that last block.
   * If decrypting, the last block contains the padding, so decrypt and strip the
   * padding.
   */
  if (0 != pCtx->encrypt)
  {
    for (index = pCtx->leftoverLen; index < blockSize; ++index)
      pCtx->pLeftovers[index] = (ubyte)padLen;

    Rc5BlockOperation (
      pCtx, pCtx->pLeftovers, blockSize, pProcessedData + updateLen);
  }
  else
  {
    Rc5BlockOperation (
      pCtx, pCtx->pLeftovers, blockSize, pCtx->pLeftovers);

    padLen = (ubyte4)(pCtx->pLeftovers[blockSize - 1]);

    status = ERR_CRYPTO_BAD_PAD;
    if ( (0 == padLen) || (blockSize < padLen) )
      goto exit;

    for (index = 0; index < blockSize - 1; ++index)
    {
      if (index < (blockSize - padLen))
      {
        pProcessedData[updateLen + index] = pCtx->pLeftovers[index];
      }
      else
      {
        if (pCtx->pLeftovers[index] != (ubyte)padLen)
          goto exit;
      }
    }

    /* If we reach this code, everything worked.
     * Also, decrement the return length by the padLen we stripped.
     */
    *pProcessedDataLen = totalLen - padLen;
    status = OK;
  }

exit:

  return (status);
}

MSTATUS BuildRc5KeyTableAlloc (
  ubyte *pKeyData,
  ubyte4 keyDataLen,
  ubyte4 blockSizeBits,
  ubyte4 roundCount,
  void **ppKeyTable,
  ubyte4 *pKeyTableSize
  )
{
  MSTATUS status;
  ubyte4 wordSize, lCount, tableCount, totalSize;
  void *pTable = NULL;
  void *pLArray = NULL;

  totalSize = 0;
  lCount = 0;
  wordSize = 8;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKeyData) || (NULL == ppKeyTable) || (NULL == pKeyTableSize) )
    goto exit;

  if (128 != blockSizeBits)
    wordSize = 4;

  /* Create the L array. This is the array of words built from the key data.
   * For each wordSize bytes of the key data, build a word.
   * For example, with a 32-bit word, take 4 bytes and build a word.
   * k0 k1 k2 k3 --> k3k2k1k0
   * 0x11 0x22 0x33 0x44 --> 0x44332211
   * If the total number of key bytes is not a multiple of the word size, then
   * the last word will have leading 00 bytes. For example,
   * 0x99 0xAA --> 0x0000AA99
   */
  lCount = (keyDataLen + wordSize - 1) / wordSize;
  status = DIGI_CALLOC (&pLArray, lCount * wordSize, 1);
  if (OK != status)
    goto exit;

  /* Create an array of 2 * (roundCount + 1) words.
   */
  tableCount = 2 * (roundCount + 1);
  totalSize = tableCount * wordSize;
  status = DIGI_MALLOC (&pTable, totalSize);
  if (OK != status)
    goto exit;

  if (4 == wordSize)
  {
    SetLArray32 (pKeyData, keyDataLen, (ubyte4 *)pLArray, lCount);
    InitKeyTable32 ((ubyte4 *)pTable, tableCount);
    MixKeyTable32 ((ubyte4 *)pTable, tableCount, (ubyte4 *)pLArray, lCount);
  }
  else
  {
    SetLArray64 (pKeyData, keyDataLen, (ubyte8 *)pLArray, lCount);
    InitKeyTable64 ((ubyte8 *)pTable, tableCount);
    MixKeyTable64 ((ubyte8 *)pTable, tableCount, (ubyte8 *)pLArray, lCount);
  }

  *ppKeyTable = pTable;
  *pKeyTableSize = totalSize;
  pTable = NULL;

exit:

  if (NULL != pTable)
  {
    DIGI_MEMSET ((void *)pTable, 0, totalSize);
    DIGI_FREE ((void **)&pTable);
  }
  if (NULL != pLArray)
  {
    DIGI_MEMSET ((void *)pLArray, 0, (ubyte4) (lCount * wordSize));
    DIGI_FREE ((void **)&pLArray);
  }

  return (status);
}

void SetLArray32 (
  ubyte *pKeyData,
  ubyte4 keyDataLen,
  ubyte4 *pLArray,
  ubyte4 lCount
  )
{
  ubyte4 indexK, indexL, count, shiftCount;

  count = keyDataLen;
  indexK = 0;
  indexL = 0;

  while (4 <= count)
  {
    pLArray[indexL] =  (ubyte4)(pKeyData[indexK]) +
                      ((ubyte4)(pKeyData[indexK + 1]) << 8) +
                      ((ubyte4)(pKeyData[indexK + 2]) << 16) +
                      ((ubyte4)(pKeyData[indexK + 3]) << 24);

    count -= 4;
    indexK += 4;
    indexL++;
  }

  shiftCount = 0;
  while (indexK < keyDataLen)
  {
    pLArray[indexL] += ((ubyte4)(pKeyData[indexK]) << shiftCount);
    indexK++;
    shiftCount += 8;
  }
}

void SetLArray64 (
  ubyte *pKeyData,
  ubyte4 keyDataLen,
  ubyte8 *pLArray,
  ubyte4 lCount
  )
{
  ubyte4 indexK, indexL, count, shiftCount;

  count = keyDataLen;
  indexK = 0;
  indexL = 0;

  while (8 <= count)
  {
    pLArray[indexL] =  (ubyte8)(pKeyData[indexK]) +
                      ((ubyte8)(pKeyData[indexK + 1]) << 8) +
                      ((ubyte8)(pKeyData[indexK + 2]) << 16) +
                      ((ubyte8)(pKeyData[indexK + 3]) << 24) +
                      ((ubyte8)(pKeyData[indexK + 4]) << 32) +
                      ((ubyte8)(pKeyData[indexK + 5]) << 40) +
                      ((ubyte8)(pKeyData[indexK + 6]) << 48) +
                      ((ubyte8)(pKeyData[indexK + 7]) << 56);

    count -= 8;
    indexK += 8;
    indexL++;
  }

  shiftCount = 0;
  while (indexK < keyDataLen)
  {
    pLArray[indexL] += (((ubyte8)(pKeyData[indexK])) << shiftCount);
    indexK++;
    shiftCount += 8;
  }
}

void InitKeyTable32 (
  ubyte4 *pTable,
  ubyte4 count
  )
{
  ubyte4 index;

  pTable[0] = MOC_RC5_P_VALUE_32;

  for (index = 1; index < count; ++index)
    pTable[index] = pTable[index - 1] + MOC_RC5_Q_VALUE_32;
}

void InitKeyTable64 (
  ubyte8 *pTable,
  ubyte4 count
  )
{
  ubyte4 index;

  pTable[0] = MOC_RC5_P_VALUE_64;

  for (index = 1; index < count; ++index)
    pTable[index] = pTable[index - 1] + MOC_RC5_Q_VALUE_64;
}

void MixKeyTable32 (
  ubyte4 *pTable,
  ubyte4 tableCount,
  ubyte4 *pLArray,
  ubyte4 lCount
  )
{
  ubyte4 count, indexT, indexL, rVal, temp;
  ubyte4 A, B, T;

  count = 3 * lCount;
  if (tableCount > lCount)
    count = 3 * tableCount;

  A = 0;
  B = 0;
  indexT = 0;
  indexL = 0;
  while (count > 0)
  {
    T = pTable[indexT] + A + B;
    ROTL_32 (A, T, 3, temp);
    pTable[indexT] = A;
    rVal = A + B;
    T = pLArray[indexL] + rVal;
    ROTL_32 (B, T, rVal, temp);
    pLArray[indexL] = B;

    indexT++;
    indexL++;
    count--;

    if (indexT >= tableCount)
      indexT = 0;
    if (indexL >= lCount)
      indexL = 0;
  }
}

void MixKeyTable64 (
  ubyte8 *pTable,
  ubyte4 tableCount,
  ubyte8 *pLArray,
  ubyte4 lCount
  )
{
  ubyte4 count, indexT, indexL, rVal, temp;
  ubyte8 A, B, T, R;

  count = 3 * lCount;
  if (tableCount > lCount)
    count = 3 * tableCount;

  A = 0;
  B = 0;
  indexT = 0;
  indexL = 0;
  while (count > 0)
  {
    T = pTable[indexT] + A + B;
    ROTL_64 (A, T, 3, temp);
    pTable[indexT] = A;
    R = A + B;
    rVal = (ubyte4)R;
    T = pLArray[indexL] + R;
    ROTL_64 (B, T, rVal, temp);
    pLArray[indexL] = B;

    indexT++;
    indexL++;
    count--;

    if (indexT >= tableCount)
      indexT = 0;
    if (indexL >= lCount)
      indexL = 0;
  }
}

void Rc5BlockOperation (
  MocRc5LocalCtx *pCtx,
  ubyte *pInputBlock,
  ubyte4 blockSize,
  ubyte *pOutputBlock
  )
{
  ubyte4 index;
  ubyte *pBlock;
  ubyte pSaveBlock[MOC_MAX_RC5_BLOCK_SIZE];

  /* If CBC, do preprocessing.
   * If encrypting, XOR the input with the current vector.
   * If decrypting, save the current ciphertext to become the next vector after
   * the XOR.
   */
  pBlock = pInputBlock;
  if (0 != pCtx->initVectorLen)
  {
    if (0 != pCtx->encrypt)
    {
      for (index = 0; index < blockSize; ++index)
        pSaveBlock[index] = pInputBlock[index] ^ pCtx->pCurrentVector[index];

      pBlock = (ubyte *)pSaveBlock;
    }
    else
    {
      for (index = 0; index < blockSize; ++index)
        pSaveBlock[index] = pInputBlock[index];
    }
  }

  if (64 == pCtx->rc5Ctx.blockSizeBits)
  {
    Rc5BlockOperation32 (
      pCtx->encrypt, pCtx->rc5Ctx.roundCount,
      (ubyte4 *)(pCtx->rc5Ctx.pKeyTable), pBlock, pOutputBlock);
  }
  else
  {
    Rc5BlockOperation64 (
      pCtx->encrypt, pCtx->rc5Ctx.roundCount,
      (ubyte8 *)(pCtx->rc5Ctx.pKeyTable), pBlock, pOutputBlock);
  }

  /* If CBC, do post processing.
   * If encrypting, copy the new output as the vector.
   * If decrypting, XOR the result with the vector and copy the previous
   * cihertext as the next vector.
   */
  if (0 != pCtx->initVectorLen)
  {
    if (0 != pCtx->encrypt)
    {
      for (index = 0; index < blockSize; ++index)
      {
        pCtx->pCurrentVector[index] = pOutputBlock[index];
        pSaveBlock[index] = 0;
      }
    }
    else
    {
      for (index = 0; index < blockSize; ++index)
      {
        pOutputBlock[index] ^= pCtx->pCurrentVector[index];
        pCtx->pCurrentVector[index] = pSaveBlock[index];
        pSaveBlock[index] = 0;
      }
    }
  }
}

void Rc5BlockOperation32 (
  ubyte4 cipherFlag,
  ubyte4 roundCount,
  ubyte4 *pKeyTable,
  ubyte *pInputBlock,
  ubyte *pOutputBlock
  )
{
  ubyte4 A, B, temp, index, lastIndex;

  /* Convert the input into two words A and B.
   */
  A =  (ubyte4)(pInputBlock[0]) +
      ((ubyte4)(pInputBlock[1]) <<  8) +
      ((ubyte4)(pInputBlock[2]) << 16) +
      ((ubyte4)(pInputBlock[3]) << 24);
  B =  (ubyte4)(pInputBlock[4]) +
      ((ubyte4)(pInputBlock[5]) <<  8) +
      ((ubyte4)(pInputBlock[6]) << 16) +
      ((ubyte4)(pInputBlock[7]) << 24);

  lastIndex = (2 * roundCount);
  if (MOC_RC5_ENCRYPT == cipherFlag)
  {
    A += pKeyTable[0];
    B += pKeyTable[1];

    for (index = 2; index <= lastIndex; index += 2)
    {
      A ^= B;
      ROTL_32 (A, A, B, temp);
      A += pKeyTable[index];
      B ^= A;
      ROTL_32 (B, B, A, temp);
      B += pKeyTable[index + 1];
    }
  }
  else
  {
    for (index = lastIndex; index >= 2; index -= 2)
    {
      B -= pKeyTable[index + 1];
      ROTR_32 (B, B, A, temp);
      B ^= A;
      A -= pKeyTable[index];
      ROTR_32 (A, A, B, temp);
      A ^= B;
    }

    A -= pKeyTable[0];
    B -= pKeyTable[1];
  }

  pOutputBlock[0] = (ubyte) A;
  pOutputBlock[1] = (ubyte)(A >>  8);
  pOutputBlock[2] = (ubyte)(A >> 16);
  pOutputBlock[3] = (ubyte)(A >> 24);
  pOutputBlock[4] = (ubyte) B;
  pOutputBlock[5] = (ubyte)(B >>  8);
  pOutputBlock[6] = (ubyte)(B >> 16);
  pOutputBlock[7] = (ubyte)(B >> 24);

  return;
}

void Rc5BlockOperation64 (
  ubyte4 cipherFlag,
  ubyte4 roundCount,
  ubyte8 *pKeyTable,
  ubyte *pInputBlock,
  ubyte *pOutputBlock
  )
{
  ubyte8 A, B, temp, index, lastIndex;

  /* Convert the input into two words A and B.
   */
  A =  (ubyte8)(pInputBlock[ 0]) +
      ((ubyte8)(pInputBlock[ 1]) <<  8) +
      ((ubyte8)(pInputBlock[ 2]) << 16) +
      ((ubyte8)(pInputBlock[ 3]) << 24) +
      ((ubyte8)(pInputBlock[ 4]) << 32) +
      ((ubyte8)(pInputBlock[ 5]) << 40) +
      ((ubyte8)(pInputBlock[ 6]) << 48) +
      ((ubyte8)(pInputBlock[ 7]) << 56);
  B =  (ubyte8)(pInputBlock[ 8]) +
      ((ubyte8)(pInputBlock[ 9]) <<  8) +
      ((ubyte8)(pInputBlock[10]) << 16) +
      ((ubyte8)(pInputBlock[11]) << 24) +
      ((ubyte8)(pInputBlock[12]) << 32) +
      ((ubyte8)(pInputBlock[13]) << 40) +
      ((ubyte8)(pInputBlock[14]) << 48) +
      ((ubyte8)(pInputBlock[15]) << 56);

  lastIndex = (2 * roundCount);
  if (MOC_RC5_ENCRYPT == cipherFlag)
  {
    A += pKeyTable[0];
    B += pKeyTable[1];

    for (index = 2; index <= lastIndex; index += 2)
    {
      A ^= B;
      ROTL_64 (A, A, B, temp);
      A += pKeyTable[index];
      B ^= A;
      ROTL_64 (B, B, A, temp);
      B += pKeyTable[index + 1];
    }
  }
  else
  {
    for (index = lastIndex; index >= 2; index -= 2)
    {
      B -= pKeyTable[index + 1];
      ROTR_64 (B, B, A, temp);
      B ^= A;
      A -= pKeyTable[index];
      ROTR_64 (A, A, B, temp);
      A ^= B;
    }

    A -= pKeyTable[0];
    B -= pKeyTable[1];
  }

  pOutputBlock[ 0] = (ubyte) A;
  pOutputBlock[ 1] = (ubyte)(A >>  8);
  pOutputBlock[ 2] = (ubyte)(A >> 16);
  pOutputBlock[ 3] = (ubyte)(A >> 24);
  pOutputBlock[ 4] = (ubyte)(A >> 32);
  pOutputBlock[ 5] = (ubyte)(A >> 40);
  pOutputBlock[ 6] = (ubyte)(A >> 48);
  pOutputBlock[ 7] = (ubyte)(A >> 56);
  pOutputBlock[ 8] = (ubyte) B;
  pOutputBlock[ 9] = (ubyte)(B >>  8);
  pOutputBlock[10] = (ubyte)(B >> 16);
  pOutputBlock[11] = (ubyte)(B >> 24);
  pOutputBlock[12] = (ubyte)(B >> 32);
  pOutputBlock[13] = (ubyte)(B >> 40);
  pOutputBlock[14] = (ubyte)(B >> 48);
  pOutputBlock[15] = (ubyte)(B >> 56);

  return;
}


MOC_EXTERN MSTATUS MocRC5GetIv (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pBulkCtx,
  ubyte *pIv,
  ubyte4 ivLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MocRc5LocalCtx *pCtx = (MocRc5LocalCtx *) pBulkCtx;
  ubyte4 expIvLen = 0;

  /* we'll return error if no iv. ecb should not call this */
  if (NULL == pCtx || NULL == pCtx->pCurrentVector)
    goto exit;

  status = ERR_BUFFER_TOO_SMALL;
  if (ivLen < (pCtx->rc5Ctx.blockSizeBits)/8)
    goto exit;

  status = DIGI_MEMCPY(pIv, pCtx->pCurrentVector, (pCtx->rc5Ctx.blockSizeBits)/8 );
  
exit:
  
  return status;
}

#endif /* defined(__ENABLE_DIGICERT_RC5__) */
