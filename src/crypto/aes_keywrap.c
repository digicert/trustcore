/*
 * aes_keywrap.c
 *
 * AES-Key Wrap Implementation (RFC 3394 and 5649)
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_KEYWRAP_INTERNAL__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if (!defined(__DISABLE_AES_CIPHERS__))

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#include "../crypto/aesalgo.h"
#include "../crypto/aes.h"
#include "../crypto/aes_ecb.h"
#include "../crypto/aes_keywrap.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_aes.h"
#endif

/*---------------------------------------------------------------------------*/
static const ubyte kIV3394[] = {0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6};
static const unsigned char default_aiv[] = {
    0xA6, 0x59, 0x59, 0xA6
};

enum WrapStyle
{
    WS_3394 = 1,
    WS_5649 = 2,
};

/*---------------------------------------------------------------------------*/

#define MOC_AES_WRAP_OLD_CODE  0
#define MOC_AES_WRAP_NEW_CODE  1

/* Common code.
 * <p>If calling from the original functions (encrypt or encryptEx), pass
 * MOC_AES_WRAP_OLD_CODE as the callFlag. If calling from the new code
 * (encrypt 3394 or encrypt5649), pass MOC_AES_WRAP_NEW_CODE as the callFlag.
 * <p>This call expects the dataLen to be a multiple of 8, so it must be padded
 * first, if the calling function performs the key wrap following 5649.
 */
static MSTATUS AESKWRAP_encryptAux (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  ubyte4 callFlag,
  ubyte* keyMaterial,
  sbyte4 keyLength,
  const ubyte *data,
  ubyte4 dataLen,
  sbyte4 padLen,
  const ubyte *kwIV,
  ubyte *retData,
  ubyte transform
  )
{
    ubyte t0, t1, t2, t3;
    ubyte4 i,j,t;
    ubyte4 n = (dataLen + padLen) / 8;
    ubyte  block[AES_BLOCK_SIZE] ;
    BulkCtx ctx = NULL;
    MSTATUS status = OK;

    if (!retData)
    {
        status = ERR_AES_BAD_ARG;
        goto exit;
    }

    if ((dataLen + padLen) % 8)
    {
        status = ERR_AES_BAD_LENGTH;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    ctx = CRYPTO_INTERFACE_CreateAESECBCtx(MOC_SYM(hwAccelCtx)(ubyte *) keyMaterial, keyLength, (sbyte4)transform);
#else
    ctx = CreateAESECBCtx(MOC_SYM(hwAccelCtx)(ubyte *) keyMaterial, keyLength, (sbyte4)transform);
#endif
    if (!ctx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(block, kwIV, 8);

    if (1 == n && 0x59 == kwIV[1])  /* i.e dataLen + padLen == 8 (RFC5649 special case) */
    {
        DIGI_MEMCPY(block + 8, data, dataLen);
        DIGI_MEMSET(block + 8 + dataLen, 0, padLen);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DoAESECB(MOC_SYM(hwAccelCtx) ctx, block, AES_BLOCK_SIZE, (sbyte4)transform);
#else
        DoAESECB(MOC_SYM(hwAccelCtx) ctx, block, AES_BLOCK_SIZE, (sbyte4)transform);
#endif
        DIGI_MEMCPY(retData, block, AES_BLOCK_SIZE);
    }
    else
    {
        for (i = dataLen - 1; i < dataLen; i--)
        {
            retData[8 + i] = data[i];
        }
        if (padLen)
        {
            DIGI_MEMSET( retData + 8 + dataLen, 0, padLen);
        }

        for (j = 0; j < 6 ; j++)
        {
            for (i = 1; i < n + 1; i++)
            {
                DIGI_MEMCPY(block+8, retData + (i * 8), 8);
                t = (n * j) + i;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                CRYPTO_INTERFACE_DoAESECB(MOC_SYM(hwAccelCtx) ctx, block, AES_BLOCK_SIZE, (sbyte4)transform);
#else
                DoAESECB(MOC_SYM(hwAccelCtx) ctx, block, AES_BLOCK_SIZE, (sbyte4)transform);
#endif
                t0 = (ubyte)(t >> 24);
                t1 = (ubyte)(t >> 16);
                t2 = (ubyte)(t >>  8);
                t3 = (ubyte)(t);
                DIGI_MEMCPY( retData + (i  * 8), block + 8, 8);
                /* The old code XORed the low order byte only. But t can be
                 * longer than one byte. If this is being called from the new
                 * code, XOR them all. If this is called from old code, just XOR
                 * the last byte.
                 * This was the original line of code.
                 *      block[7] ^= (n * j) + i;
                 */
                if (MOC_AES_WRAP_OLD_CODE != callFlag)
                {
                  block[4] ^= t0;
                  block[5] ^= t1;
                  block[6] ^= t2;
                }
                block[7] ^= t3;
            }
        }

        DIGI_MEMCPY(retData, block, 8);
    }

exit:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DeleteAESCtx(MOC_SYM(hwAccelCtx)&ctx);
#else
    DeleteAESECBCtx(MOC_SYM(hwAccelCtx)&ctx);
#endif

    return status;
}


/*---------------------------------------------------------------------------*/

/* Common code.
 * <p>If calling from the original functions (encrypt or encryptEx), pass
 * MOC_AES_WRAP_OLD_CODE as the callFlag. If calling from the new code
 * (encrypt 3394 or encrypt5649), pass MOC_AES_WRAP_NEW_CODE as the callFlag.
 */
static MSTATUS AESKWRAP_decryptAux (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  ubyte4 callFlag,
  ubyte *keyMaterial,
  sbyte4 keyLength,
  const ubyte *data,
  ubyte4 dataLen,
  enum WrapStyle *wrapStyle,
  ubyte *retData /* datalen - 8 */,
  ubyte4* retDataLen,
  ubyte transform
  )
{
    ubyte t0, t1, t2, t3;
    sbyte4 i,j;
    ubyte4 t = 0;
    ubyte4 n = (dataLen / 8) - 1;
    ubyte  block[AES_BLOCK_SIZE];
    BulkCtx ctx = NULL;
    sbyte4 cmp;
    MSTATUS status = OK;

    if (dataLen < 16 || dataLen % 8)
    {
        status = ERR_AES_BAD_LENGTH;
        goto exit;
    }

    if (!retData)
    {
        status = ERR_AES_BAD_ARG;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    ctx = CRYPTO_INTERFACE_CreateAESECBCtx(MOC_SYM(hwAccelCtx)(ubyte *) keyMaterial, keyLength, (sbyte4)transform);
#else
    ctx = CreateAESECBCtx(MOC_SYM(hwAccelCtx)(ubyte *) keyMaterial, keyLength, (sbyte4)transform);
#endif
    if (!ctx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(block, data, 8);
    DIGI_MEMCPY(retData, data + 8, (n* 8));

    for (j = 5; j >=0 ; j--)
    {
        for (i = n; i>= 1; i--)
        {
            t = (n * j) + i;
            t0 = (ubyte)(t >> 24);
            t1 = (ubyte)(t >> 16);
            t2 = (ubyte)(t >>  8);
            t3 = (ubyte)(t);

            /* The old code XORed the low order byte only. But t can be longer
             * than one byte. If this is being called from the new code, XOR them
             * all. If this is called from old code, just XOR the last byte.
             * This was the original line of code.
             *      block[7] = block[7] ^ t;
             */
            if (MOC_AES_WRAP_OLD_CODE != callFlag)
            {
              block[4] ^= t0;
              block[5] ^= t1;
              block[6] ^= t2;
            }
            block[7] ^= t3;

            DIGI_MEMCPY(block + 8, retData + ((i - 1) * 8), 8);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            CRYPTO_INTERFACE_DoAESECB(MOC_SYM(hwAccelCtx) ctx, block, AES_BLOCK_SIZE, (sbyte4)transform);
#else
            DoAESECB(MOC_SYM(hwAccelCtx) ctx, block, AES_BLOCK_SIZE, (sbyte4)transform);
#endif

            DIGI_MEMCPY(retData + ((i -1 ) * 8), block + 8, 8);
        }
    }

    /* verify that the kWIV is valid here */
    DIGI_CTIME_MATCH(kIV3394, block, 8, &cmp);
    if (0 == cmp)
    {
        *wrapStyle = WS_3394;
        *retDataLen = n * 8;
        goto exit;
    }

    /* check for RFC 5649 encoding */
    if (n == 1)  /* different encryption in that case */
    {
        DIGI_MEMCPY(block, data, dataLen);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DoAESECB(MOC_SYM(hwAccelCtx) ctx, block, dataLen, (sbyte4)transform);
#else
        DoAESECB(MOC_SYM(hwAccelCtx) ctx, block, dataLen, (sbyte4)transform);
#endif
        DIGI_MEMCPY( retData, block+8, 8);
    }

    *retDataLen = DIGI_NTOHL(block+4);
    if ( 0xA6 == block[0] && 0x59 == block[1] &&
        0x59 == block[2] && 0xA6 == block[3] &&
        *retDataLen <= n*8 && *retDataLen > (n-1) * 8 )
    {
        cmp = 0;
        for (i = *retDataLen; (ubyte4)i < (n*8); ++i)
        {
            cmp |= ((sbyte4) retData[i]);
        }
        if ( 0 == cmp)
        {
            *wrapStyle = WS_5649;
            goto exit; /* paddding verified -> OK */
        }
    }

    status = ERR_AES_BAD_KEY_MATERIAL;

exit:

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DeleteAESCtx(MOC_SYM(hwAccelCtx)&ctx);
#else
    DeleteAESECBCtx(MOC_SYM(hwAccelCtx)&ctx);
#endif

    return status;
}

static MSTATUS AESKWRAP_decryptSpecial (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  ubyte *keyMaterial,
  sbyte4 keyLength,
  const ubyte *data,
  ubyte4 dataLen,
  ubyte *retData,
  ubyte4* retDataLen,
  ubyte transform
  )
{
    ubyte block[AES_BLOCK_SIZE];
    ubyte aiv[8];
    BulkCtx ctx = NULL;
    sbyte4 cmp;
    ubyte4 retLen = 0;
    static unsigned char zeros[8] = { 0x0 };
    MSTATUS status = OK;
    MOC_UNUSED(dataLen);

    *retDataLen = 0;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    ctx = CRYPTO_INTERFACE_CreateAESECBCtx(MOC_SYM(hwAccelCtx)(ubyte *) keyMaterial, keyLength, (sbyte4)transform);
#else
    ctx = CreateAESECBCtx(MOC_SYM(hwAccelCtx)(ubyte *) keyMaterial, keyLength, (sbyte4)transform);
#endif
    if (!ctx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    status = DIGI_MEMCPY(block, data, 16);
    if (OK != status)
      goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DoAESECB(MOC_SYM(hwAccelCtx) ctx, block, AES_BLOCK_SIZE, (sbyte4)transform);
#else
    DoAESECB(MOC_SYM(hwAccelCtx) ctx, block, AES_BLOCK_SIZE, (sbyte4)transform);
#endif

    status = DIGI_MEMCPY(aiv, block, 8);
    if (OK != status)
      goto exit;

    status = DIGI_MEMCPY(retData, block + 8, 8);
    if (OK != status)
      goto exit;

    status = DIGI_MEMCMP(aiv, default_aiv, 4, &cmp);
    if (OK != status)
      goto exit;

    if (0 != cmp)
    {
      status = ERR_CMP;
      goto exit;
    }

    retLen =  ((unsigned int)aiv[4] << 24)
           |  ((unsigned int)aiv[5] << 16)
           |  ((unsigned int)aiv[6] <<  8)
           |  (unsigned int)aiv[7];
    if (0 >= retLen || retLen > 8)
    {
      status = ERR_AES_BAD_IV_LENGTH;
      goto exit;
    }

    status = DIGI_MEMCMP(retData + retLen, zeros, 8 - retLen, &cmp);
    if (OK != status)
      goto exit;

    if (0 != cmp)
    {
      status = ERR_CMP;
      goto exit;
    }

    status = OK;
    *retDataLen = retLen;

exit:

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DeleteAESCtx(MOC_SYM(hwAccelCtx)&ctx);
#else
    DeleteAESECBCtx(MOC_SYM(hwAccelCtx)&ctx);
#endif

    return status;
}


/*---------------------------------------------------------------------------*/

extern MSTATUS
AESKWRAP_encrypt( MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial,
                 sbyte4 keyLength, const ubyte* data, ubyte4 dataLen,
                 ubyte * retData/* SHould be dataLen + 8 */)
{
  return AESKWRAP_encryptAux (
    MOC_SYM(hwAccelCtx) MOC_AES_WRAP_OLD_CODE, keyMaterial, keyLength,
    data, dataLen, 0, kIV3394, retData, 1);
}


/*---------------------------------------------------------------------------*/

extern MSTATUS
AESKWRAP_decrypt(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial,
                 sbyte4 keyLength, const ubyte* data, ubyte4 dataLen,
                 ubyte * retData /* datalen - 8 */ )
{
    MSTATUS status;
    enum WrapStyle wrapStyle;
    ubyte4 retDataLen;

    if (OK > ( status = AESKWRAP_decryptAux (
      MOC_SYM(hwAccelCtx) MOC_AES_WRAP_OLD_CODE, keyMaterial,
      keyLength, data, dataLen, &wrapStyle, retData, &retDataLen, 0)))
    {
        goto exit;
    }

    /* verify this is indeed a RFC 3394 encoding */
    if (WS_3394 != wrapStyle)
    {
        status = ERR_AES_BAD_KEY_MATERIAL;
    }

exit:

    return status;
}


/*---------------------------------------------------------------------------*/

extern MSTATUS
AESKWRAP_encryptEx( MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial,
                    sbyte4 keyLength, const ubyte* data, ubyte4 dataLen,
                    ubyte** retData, ubyte4* retDataLen)
{
    MSTATUS status;
    ubyte* buffer = NULL;
    sbyte4 padLen = 8 - (dataLen % 8);

    ubyte kwIV[8] = {0xA6, 0x59, 0x59, 0xA6};

    BIGEND32(kwIV+4, dataLen);

    if (8 == padLen) padLen = 0;

    buffer = (ubyte*) MALLOC(8 + dataLen + padLen);
    if (!buffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = AESKWRAP_encryptAux (
      MOC_SYM(hwAccelCtx) MOC_AES_WRAP_OLD_CODE, keyMaterial, keyLength,
      data, dataLen, padLen, kwIV, buffer, 1)))
    {
        goto exit;
    }

    *retData = buffer;
    buffer = 0;
    *retDataLen = 8 + dataLen + padLen;

exit:

    FREE(buffer);

    return status;
}


/*---------------------------------------------------------------------------*/

extern MSTATUS
AESKWRAP_decryptEx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial,
                    sbyte4 keyLength, const ubyte* data, ubyte4 dataLen,
                    ubyte* retData, ubyte4* retDataLen)
{
    enum WrapStyle wrapStyle;

    return AESKWRAP_decryptAux (
      MOC_SYM(hwAccelCtx) MOC_AES_WRAP_OLD_CODE, keyMaterial,
      keyLength, data, dataLen, &wrapStyle, retData, retDataLen, 0);
}

static MSTATUS AESKWRAP_encrypt3394_internal (
  MOC_SYM (hwAccelDescr hwAccelCtx)
  ubyte *pKeyMaterial,
  sbyte4 keyLength,
  ubyte *pDataToEncrypt,
  ubyte4 dataToEncryptLen,
  ubyte *pEncryptedData,
  ubyte4 bufferSize,
  ubyte4 *pEncryptedDataLen,
  ubyte transform
  )
{
  MSTATUS status;
  ubyte4 bufSize;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKeyMaterial) || (NULL == pDataToEncrypt) ||
       (NULL == pEncryptedDataLen) )
    goto exit;

  /* There must be input data and it must be a multiple of 8.
   */
  status = ERR_INVALID_ARG;
  if ( (0 == dataToEncryptLen) || (0 != (dataToEncryptLen & 7)) )
    goto exit;

  /* Make sure the buffer is big enough.
   */
  bufSize = 0;
  if (NULL != pEncryptedData)
    bufSize = bufferSize;

  status = ERR_BUFFER_OVERFLOW;
  *pEncryptedDataLen = dataToEncryptLen + 8;
  if (bufSize < (dataToEncryptLen + 8))
    goto exit;

  status = AESKWRAP_encryptAux (
    MOC_SYM (hwAccelCtx) MOC_AES_WRAP_NEW_CODE, pKeyMaterial,
    keyLength, pDataToEncrypt, dataToEncryptLen, 0, kIV3394, pEncryptedData, transform);

exit:

  return (status);
}

static MSTATUS AESKWRAP_decrypt3394_internal (
  MOC_SYM (hwAccelDescr hwAccelCtx)
  ubyte *pKeyMaterial,
  sbyte4 keyLength,
  ubyte *pEncryptedData,
  ubyte4 encryptedDataLen,
  ubyte *pDecryptedData,
  ubyte4 bufferSize,
  ubyte4 *pDecryptedDataLen,
  ubyte transform
  )
{
  MSTATUS status;
  enum WrapStyle wrapStyle;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKeyMaterial) || (NULL == pEncryptedData) ||
       (NULL == pDecryptedDataLen) )
    goto exit;

  /* There must be input data.
   */
  status = ERR_INVALID_ARG;
  if (0 == encryptedDataLen)
    goto exit;

  /* Make sure the buffer is big enough.
   */
  status = ERR_BUFFER_OVERFLOW;
  *pDecryptedDataLen = encryptedDataLen - 8;
  if (bufferSize < (encryptedDataLen - 8))
    goto exit;

  status = AESKWRAP_decryptAux (
    MOC_SYM (hwAccelCtx) MOC_AES_WRAP_NEW_CODE, pKeyMaterial,
    keyLength, pEncryptedData, encryptedDataLen, &wrapStyle,
    pDecryptedData, pDecryptedDataLen, transform);

exit:

  return (status);
}

static MSTATUS AESKWRAP_encrypt5649_internal (
  MOC_SYM (hwAccelDescr hwAccelCtx)
  ubyte *pKeyMaterial,
  sbyte4 keyLength,
  ubyte *pDataToEncrypt,
  ubyte4 dataToEncryptLen,
  ubyte *pEncryptedData,
  ubyte4 bufferSize,
  ubyte4 *pEncryptedDataLen,
  ubyte transform
  )
{
  MSTATUS status;
  ubyte4 padLen, bufSize;
  ubyte kwIV[8] = {
    0xA6, 0x59, 0x59, 0xA6, 0x00, 0x00, 0x00, 0x00
  };

  status = ERR_NULL_POINTER;
  if ( (NULL == pKeyMaterial) || (NULL == pDataToEncrypt) ||
       (NULL == pEncryptedDataLen) )
    goto exit;

  /* There must be input data.
   */
  status = ERR_INVALID_ARG;
  if (0 == dataToEncryptLen)
    goto exit;

  /* How many pad bytes?
   */
  padLen = dataToEncryptLen & 7;
  if (0 != padLen)
    padLen = 8 - padLen;

  /* Make sure the buffer is big enough.
   */
  bufSize = 0;
  if (NULL != pEncryptedData)
    bufSize = bufferSize;

  status = ERR_BUFFER_OVERFLOW;
  *pEncryptedDataLen = dataToEncryptLen + padLen + 8;
  if (bufSize < (dataToEncryptLen + padLen + 8))
    goto exit;

  BIGEND32 (kwIV + 4, dataToEncryptLen);

  status = AESKWRAP_encryptAux (
    MOC_SYM (hwAccelCtx) MOC_AES_WRAP_NEW_CODE, pKeyMaterial,
    keyLength, pDataToEncrypt, dataToEncryptLen, padLen, kwIV, pEncryptedData, transform);

exit:

  /* Clear the length out of the IV.
   */
  BIGEND32 (kwIV + 4, 0);

  return (status);
}

static MSTATUS AESKWRAP_decrypt5649_internal (
  MOC_SYM (hwAccelDescr hwAccelCtx)
  ubyte *pKeyMaterial,
  sbyte4 keyLength,
  ubyte *pEncryptedData,
  ubyte4 encryptedDataLen,
  ubyte *pDecryptedData,
  ubyte4 bufferSize,
  ubyte4 *pDecryptedDataLen,
  ubyte transform
  )
{
  MSTATUS status;
  enum WrapStyle wrapStyle;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKeyMaterial) || (NULL == pEncryptedData) ||
       (NULL == pDecryptedDataLen) )
    goto exit;

  /* There must be input data.
   */
  status = ERR_INVALID_ARG;
  if (0 == encryptedDataLen)
    goto exit;

  /* Make sure the buffer is big enough.
   */
  status = ERR_BUFFER_OVERFLOW;
  *pDecryptedDataLen = encryptedDataLen - 8;
  if (bufferSize < (encryptedDataLen - 8))
    goto exit;

  /* Handling for special case RFC5649 Section 4.2 */
  if (16 == encryptedDataLen)
  {
    status = AESKWRAP_decryptSpecial (
      MOC_SYM (hwAccelCtx) pKeyMaterial, keyLength, pEncryptedData, 
      encryptedDataLen, pDecryptedData, pDecryptedDataLen, transform);
  }
  else
  {
    status = AESKWRAP_decryptAux (
      MOC_SYM (hwAccelCtx) MOC_AES_WRAP_NEW_CODE, pKeyMaterial,
      keyLength, pEncryptedData, encryptedDataLen, &wrapStyle,
      pDecryptedData, pDecryptedDataLen, transform);
  }

exit:

  return (status);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS AESKWRAP_encrypt3394 (
  MOC_SYM (hwAccelDescr hwAccelCtx)
  ubyte *pKeyMaterial,
  sbyte4 keyLength,
  ubyte *pDataToEncrypt,
  ubyte4 dataToEncryptLen,
  ubyte *pEncryptedData,
  ubyte4 bufferSize,
  ubyte4 *pEncryptedDataLen
  )
{
  return AESKWRAP_encrypt3394_internal(MOC_SYM(hwAccelCtx) pKeyMaterial, keyLength, pDataToEncrypt, 
      dataToEncryptLen, pEncryptedData, bufferSize, pEncryptedDataLen, 1);
}

MOC_EXTERN MSTATUS AESKWRAP_decrypt3394 (
  MOC_SYM (hwAccelDescr hwAccelCtx)
  ubyte *pKeyMaterial,
  sbyte4 keyLength,
  ubyte *pEncryptedData,
  ubyte4 encryptedDataLen,
  ubyte *pDecryptedData,
  ubyte4 bufferSize,
  ubyte4 *pDecryptedDataLen
  )
{
  return AESKWRAP_decrypt3394_internal(MOC_SYM(hwAccelCtx) pKeyMaterial, keyLength, pEncryptedData, 
      encryptedDataLen, pDecryptedData, bufferSize, pDecryptedDataLen, 0);
}

MOC_EXTERN MSTATUS AESKWRAP_encrypt5649 (
  MOC_SYM (hwAccelDescr hwAccelCtx)
  ubyte *pKeyMaterial,
  sbyte4 keyLength,
  ubyte *pDataToEncrypt,
  ubyte4 dataToEncryptLen,
  ubyte *pEncryptedData,
  ubyte4 bufferSize,
  ubyte4 *pEncryptedDataLen
  )
{
  return AESKWRAP_encrypt5649_internal(MOC_SYM(hwAccelCtx) pKeyMaterial, keyLength, pDataToEncrypt, 
      dataToEncryptLen, pEncryptedData, bufferSize, pEncryptedDataLen, 1);
}

MOC_EXTERN MSTATUS AESKWRAP_decrypt5649 (
  MOC_SYM (hwAccelDescr hwAccelCtx)
  ubyte *pKeyMaterial,
  sbyte4 keyLength,
  ubyte *pEncryptedData,
  ubyte4 encryptedDataLen,
  ubyte *pDecryptedData,
  ubyte4 bufferSize,
  ubyte4 *pDecryptedDataLen
  )
{
  return AESKWRAP_decrypt5649_internal(MOC_SYM(hwAccelCtx) pKeyMaterial, keyLength, pEncryptedData, 
      encryptedDataLen, pDecryptedData, bufferSize, pDecryptedDataLen, 0);
}

/*---------------------------------------------------------------------------*/


MOC_EXTERN MSTATUS AESKWRAP_encrypt3394Ex (
  MOC_SYM (hwAccelDescr hwAccelCtx)
  ubyte *pKeyMaterial,
  sbyte4 keyLength,
  ubyte *pDataToEncrypt,
  ubyte4 dataToEncryptLen,
  ubyte *pEncryptedData,
  ubyte4 bufferSize,
  ubyte4 *pEncryptedDataLen,
  ubyte transform
  )
{
  return AESKWRAP_encrypt3394_internal(MOC_SYM(hwAccelCtx) pKeyMaterial, keyLength, pDataToEncrypt, 
      dataToEncryptLen, pEncryptedData, bufferSize, pEncryptedDataLen, transform);
}

MOC_EXTERN MSTATUS AESKWRAP_decrypt3394Ex (
  MOC_SYM (hwAccelDescr hwAccelCtx)
  ubyte *pKeyMaterial,
  sbyte4 keyLength,
  ubyte *pEncryptedData,
  ubyte4 encryptedDataLen,
  ubyte *pDecryptedData,
  ubyte4 bufferSize,
  ubyte4 *pDecryptedDataLen,
  ubyte transform
  )
{
  return AESKWRAP_decrypt3394_internal(MOC_SYM(hwAccelCtx) pKeyMaterial, keyLength, pEncryptedData, 
      encryptedDataLen, pDecryptedData, bufferSize, pDecryptedDataLen, transform);
}

MOC_EXTERN MSTATUS AESKWRAP_encrypt5649Ex (
  MOC_SYM (hwAccelDescr hwAccelCtx)
  ubyte *pKeyMaterial,
  sbyte4 keyLength,
  ubyte *pDataToEncrypt,
  ubyte4 dataToEncryptLen,
  ubyte *pEncryptedData,
  ubyte4 bufferSize,
  ubyte4 *pEncryptedDataLen,
  ubyte transform
  )
{
  return AESKWRAP_encrypt5649_internal(MOC_SYM(hwAccelCtx) pKeyMaterial, keyLength, pDataToEncrypt, 
      dataToEncryptLen, pEncryptedData, bufferSize, pEncryptedDataLen, transform);
}

MOC_EXTERN MSTATUS AESKWRAP_decrypt5649Ex (
  MOC_SYM (hwAccelDescr hwAccelCtx)
  ubyte *pKeyMaterial,
  sbyte4 keyLength,
  ubyte *pEncryptedData,
  ubyte4 encryptedDataLen,
  ubyte *pDecryptedData,
  ubyte4 bufferSize,
  ubyte4 *pDecryptedDataLen,
  ubyte transform
  )
{
  return AESKWRAP_decrypt5649_internal(MOC_SYM(hwAccelCtx) pKeyMaterial, keyLength, pEncryptedData, 
      encryptedDataLen, pDecryptedData, bufferSize, pDecryptedDataLen, transform);
}


#endif /* (!defined(__DISABLE_AES_CIPHERS__) ) */
