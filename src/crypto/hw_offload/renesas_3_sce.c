/*
 * @file renesas_3_sce.c
 *
 * This file contains functions which call down to the Synergy board to perform
 * cryptographic operations. The code uses the 1.7 SCE API to make calls to the
 * Synergy board and the code was tested on the S5D9 Synergy board. The code
 * also assumes the word size of the board is 4 bytes.
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#include "common/moptions.h"
#include "common/mtypes.h"
#include "common/mocana.h"
#include "common/merrors.h"
#include "common/mstdlib.h"
#include "crypto/hw_accel.h"
#include "common/int64.h"
#include "common/random.h"
#include "common/mrtos.h"
#include "common/vlong.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "crypto/aes.h"
#include "crypto/des.h"
#include "crypto/three_des.h"
#include "crypto/nist_rng_types.h"

/* Generate Renesas file - Please update based on your project thread file */
#include "nanocrypto_thread.h"

#include "../hw_accel/renesas_3_sce.h"

#if ( defined(__ENABLE_SYNERGY_3_HARDWARE_ACCEL__) ) && \
    ( defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) )

/******************************************************************************
 * Global Variables
 ******************************************************************************/

/* This global variable is used to determine whether the main crypto driver on
 * the Synergy board has been initialized or not. The possible values for this
 * variables can be
 *
 * 0 - The main crypto driver has not been initialized
 * 1 - The main crypto driver has been initialized
 */
static volatile int cryptoInit = 0;

/* This global variable is used to pass configuration settings during the call
 * which opens the main crypto driver. There are variables that can be set in
 * this variable which will tell the crypto driver how to start itself.
 */
crypto_cfg_t mocConfig;

/******************************************************************************
 * Function Declarations
 ******************************************************************************/

/* "Magic" function needed by Renesas to enable debug printing, needs to be
 * called early in the "task" section before main loop.
 */
extern void initialise_monitor_handles(void);


/******************************************************************************
 * Helper Functions
 ******************************************************************************/

/* Originally intended for convering ubyte array to ubyte4 array for SHA,
 * this function adds padding to SHA blocks which are not multples of 4, and
 * returns the amount of pdding added in the pRetPaddingAdded param. It can
 * also be used in general to convert a ubyte array to a ubyte4 array.
 */
void byteArrayToWordArray(
  const ubyte* source,
  ubyte4* dest,
  ubyte4 byteCount,
  ubyte* pRetPaddedAdded
  )
{
  ubyte4 i = 0;

  if (NULL != pRetPaddedAdded)
    *pRetPaddedAdded = 0;

  ubyte* curWord = source;
  ubyte4 wordCount = byteCount / 4; /* swap in place? */

  for (i = 0; i < wordCount; i++)
  {
    dest[i] = ((ubyte4) (*curWord++) << 24);
    dest[i] |= ((ubyte4) (*curWord++) << 16);
    dest[i] |= ((ubyte4) (*curWord++) << 8);
    dest[i] |= ((ubyte4) (*curWord++));
  }

  /* if the bytes won't make a complete word, start padding them
   */
  if (byteCount % 4)
  {

    if (1 == (byteCount % 4))
    {
      dest[wordCount] = ((ubyte4) (*curWord++) << 24);
      dest[wordCount] |= ((ubyte4) (0x800000));

      if (NULL != pRetPaddedAdded)
        *pRetPaddedAdded = 3;
    }
    else if (2 == byteCount % 4)
    {
      dest[wordCount] = ((ubyte4) (*curWord++) << 24);
      dest[wordCount] |= ((ubyte4) (*curWord++) << 16);
      dest[wordCount] |= ((ubyte8) (0x8000));

      if (NULL != pRetPaddedAdded)
        *pRetPaddedAdded = 2;
    }
    else
    {
      dest[wordCount] = ((ubyte4) (*curWord++) << 24);
      dest[wordCount] |= ((ubyte4) (*curWord++) << 16);
      dest[wordCount] |= ((ubyte4) (*curWord++) << 8);
      dest[wordCount] |= ((ubyte4) (0x80));

      if (NULL != pRetPaddedAdded)
       *pRetPaddedAdded = 1;
    }
  }
}


/******************************************************************************/

/* This function will loop through the words in the source buffer and swap each
 * words byte order. Since the Mocana crypto API takes in canonical integers in
 * the form of byte arrays and the SCE API takes in word arrays, the values must
 * be swapped. The SCE API will also return the result as a word array but the
 * Mocana crypto API will return the canonical integer representation back to
 * the user, so this function can also take care of swapping a word array back.
 */
MSTATUS byteArrayToWordArrayInPlace(
  ubyte *pSource,
  ubyte4 byteCount
  )
{
  MSTATUS status;

  ubyte *pTemp = NULL;
  ubyte pad;

  /* Ensure the input byte array is a multiple of word size
   */
  status = ERR_INVALID_ARG;
  if ( 0 != (byteCount % 4) )
    goto exit;

  /* Create a copy of the source buffer
   */
  status = DIGI_MALLOC((void **) &pTemp, byteCount);
  if (OK != status)
    goto exit;

  status = DIGI_MEMCPY((void *) pTemp, (void *) pSource, byteCount);
  if (OK != status)
    goto exit;

  /* Actually perform the conversion
   */
  byteArrayToWordArray(pTemp, (ubyte4 *) pSource, byteCount, &pad);

exit:

  DIGI_MEMSET(pTemp, 0x00, byteCount);
  DIGI_FREE((void **) &pTemp);

  return status;
}


/******************************************************************************/

MSTATUS ConvertPrivateRsaKeyToRenesasAlloc (
  RSAKey *pRsaKey,
  ubyte4 **ppArray,
  ubyte4 *pArrayLen
  )
{
  MSTATUS status;
  ubyte4 elementLen, offset;
  ubyte4 *pArray = NULL;

  elementLen = 0;

  status = ERR_NULL_POINTER;
  if ( (NULL == pRsaKey) || (NULL == ppArray) || (NULL == pArrayLen) )
    goto exit;

  status = ERR_RSA_INVALID_KEY;
  if (FALSE == pRsaKey->privateKey)
    goto exit;

  /* We are going to take 5 values out, each of them half the size of the key
   * size.
   * RSA_KEYSIZE returns the bit length. so get the word length, then half that
   * is the length of each element.
   */
  elementLen = RSA_KEYSIZE (pRsaKey);
  elementLen = ((elementLen + 31) / 32) / 2;

  status = DIGI_MALLOC ((void **)&pArray, 5 * (elementLen * 4));
  if (OK != status)
    goto exit;

  /* Convert each of these elements in this order
   *  expoQ
   *  q
   *  expoP
   *  p
   *  qInv
   */
  status = ConvertVlongToRenesas (
    RSA_DQ (pRsaKey), pArray, elementLen);
  if (OK != status)
    goto exit;

  offset = elementLen;

  status = ConvertVlongToRenesas (
    RSA_Q (pRsaKey), pArray + offset, elementLen);
  if (OK != status)
    goto exit;

  offset += elementLen;

  status = ConvertVlongToRenesas (
    RSA_DP (pRsaKey), pArray + offset, elementLen);
  if (OK != status)
    goto exit;

  offset += elementLen;

  status = ConvertVlongToRenesas (
    RSA_P (pRsaKey), pArray + offset, elementLen);
  if (OK != status)
    goto exit;

  offset += elementLen;

  status = ConvertVlongToRenesas (
    RSA_QINV (pRsaKey), pArray + offset, elementLen);
  if (OK != status)
    goto exit;

  *ppArray = pArray;
  *pArrayLen = 5 * elementLen;
  pArray = NULL;

exit:

  if (NULL != pArray)
  {
    DIGI_MEMSET ((void *)pArray, 0, 5 * (elementLen * 4));
    DIGI_FREE ((void **)&pArray);
  }

  return (status);
}


/******************************************************************************/

MSTATUS ConvertDsaKeyToRenesasAlloc (
  DSAKey *pDsaKey,
  intBoolean privateKey,
  ubyte4 **ppDomainArray,
  ubyte4 *pDomainLen,
  ubyte4 **ppKeyArray,
  ubyte4 *pArrayLen
  )
{
  MSTATUS status;
  ubyte4 primeLen, subprimeLen, keyLen, offset;
  ubyte4 *pDomain = NULL;
  ubyte4 *pKey = NULL;
  vlong *pKeyVlong;

  status = ERR_NULL_POINTER;
  if ( (NULL == pDsaKey) || (NULL == ppDomainArray) || (NULL == pDomainLen) ||
       (NULL == ppKeyArray) || (NULL == pArrayLen) )
    goto exit;

  pKeyVlong = DSA_X (pDsaKey);
  if (FALSE == privateKey)
    pKeyVlong = DSA_Y (pDsaKey);

  status = ERR_RSA_INVALID_KEY;
  if (NULL == pKeyVlong)
    goto exit;

  /* Get the prime and subprime lengths, that will tell us how big the buffers
   * need to be.
   */
  primeLen = VLONG_bitLength (DSA_P (pDsaKey));
  subprimeLen = VLONG_bitLength (DSA_Q (pDsaKey));
  primeLen = (primeLen + 31) / 32;
  subprimeLen = (subprimeLen + 31) / 32;

  keyLen = subprimeLen;
  if (FALSE == privateKey)
    keyLen = primeLen;

  /* The domain length will be subprimeLen + primeLen + primeLen.
   */
  status = DIGI_MALLOC ((void **)&pDomain, (subprimeLen + (2 * primeLen)) * 4);
  if (OK != status)
    goto exit;

  /* The key length is keyLen
   */
  status = DIGI_MALLOC ((void **)&pKey, keyLen * 4);
  if (OK != status)
    goto exit;

  /* Load the domain params: q || p || g
   */
  status = ConvertVlongToRenesas (
    DSA_Q (pDsaKey), pDomain, subprimeLen);
  if (OK != status)
    goto exit;

  offset = subprimeLen;

  status = ConvertVlongToRenesas (
    DSA_P (pDsaKey), pDomain + offset, primeLen);
  if (OK != status)
    goto exit;

  offset += primeLen;

  status = ConvertVlongToRenesas (
    DSA_G (pDsaKey), pDomain + offset, primeLen);
  if (OK != status)
    goto exit;

  /* Now load the key.
   */
  status = ConvertVlongToRenesas (pKeyVlong, pKey, keyLen);
  if (OK != status)
    goto exit;

  *ppDomainArray = pDomain;
  *pDomainLen = subprimeLen + (2 * primeLen);
  *ppKeyArray = pKey;
  *pArrayLen = keyLen;
  pDomain = NULL;
  pKey = NULL;

exit:

  if (NULL != pDomain)
  {
    DIGI_FREE ((void **)&pDomain);
  }
  if (NULL != pKey)
  {
    DIGI_FREE ((void **)&pKey);
  }

  return (status);
}


/******************************************************************************/

MSTATUS ConvertRenesasDsaSigToVlongs (
  ubyte4 *pSignature,
  ubyte4 signatureLen,
  vlong **ppRVal,
  vlong **ppSVal
  )
{
  MSTATUS status;
  ubyte4 valueLen;

  status = ERR_NULL_POINTER;
  if ( (NULL == pSignature) || (0 == signatureLen) ||
       (NULL == ppRVal) || (NULL == ppSVal) )
    goto exit;

  valueLen = signatureLen / 2;

  /* The signature should be r || s. Hence, it should be 2 * len words long. Make
   * sure the len is even.
   */
  status = ERR_INVALID_INPUT;
  if (0 != (signatureLen & 1))
    goto exit;

  status = ConvertRenesasToVlong (pSignature, valueLen, ppRVal);
  if (OK != status)
    goto exit;

  status = ConvertRenesasToVlong (pSignature + valueLen, valueLen, ppSVal);

exit:

  return (status);
}


/******************************************************************************/

MSTATUS ConvertDsaSigToRenesasAlloc (
  vlong *pSubprime,
  vlong *pRVal,
  vlong *pSVal,
  ubyte4 **ppSignature,
  ubyte4 *pSigLen
  )
{
 MSTATUS status;
  ubyte4 valueLen;
  ubyte4 *pSig = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pSubprime) || (NULL == pRVal) || (NULL == pSVal) ||
       (NULL == ppSignature) || (NULL == pSigLen) )
    goto exit;

  /* How big should each element be?
   */
  valueLen = VLONG_bitLength (pSubprime);
  valueLen = (valueLen + 31) / 32;

  /* The buffer will hold two elements of valueLen words.
   */
  status = DIGI_MALLOC ((void **)&pSig, (valueLen * 2) * 4);
  if (OK != status)
    goto exit;

  /* Load r, then s.
   */
  status = ConvertVlongToRenesas (pRVal, pSig, valueLen);
  if (OK != status)
    goto exit;

  status = ConvertVlongToRenesas (pSVal, pSig + valueLen, valueLen);
  if (OK != status)
    goto exit;

  *ppSignature = pSig;
  *pSigLen = valueLen * 2;
  pSig = NULL;

exit:

  if (NULL != pSig)
  {
    DIGI_FREE ((void **)&pSig);
  }

  return (status);
}


/******************************************************************************/

MSTATUS ConvertVlongToRenesas (
  vlong *pValue,
  ubyte4 *pArray,
  ubyte4 arrayLen
  )
{
  MSTATUS status;
  ubyte4 unitSize, wordLen, indexV, indexA;

  /* How many words make up the vlong?
   */
  wordLen = VLONG_bitLength (pValue);
  unitSize = sizeof (vlong_unit);

  wordLen = (wordLen + 31) / 32;

  status = ERR_RSA_INVALID_KEY;
  if ( (wordLen > arrayLen) || ((4 != unitSize) && (8 != unitSize)) )
    goto exit;

  /* Any prepended 0 words?
   */
  for (indexA = 0; indexA < (arrayLen - wordLen); ++indexA)
    pArray[indexA] = 0;

  for (indexV = pValue->numUnitsUsed; indexV > 0; --indexV)
  {
    if (4 == unitSize)
    {
      pArray[indexA] = (ubyte4)(pValue->pUnits[indexV - 1]);
      indexA++;
    }
    else
    {
      /* If the count is odd, then we don't want the most significant 32-bit half
       * of the most significant 64-bit word.
       * But only on the zeroth element.
       */
      if ( (0 == indexA) && (0 != (arrayLen & 1)) )
      {
        pArray[indexA] = (ubyte4)(pValue->pUnits[indexV - 1]);
        indexA++;
      }
      else
      {
        pArray[indexA] = (ubyte4)(pValue->pUnits[indexV - 1] >> 32);
        pArray[indexA + 1] = (ubyte4)(pValue->pUnits[indexV - 1]);
        indexA += 2;
      }
    }
  }

  status = OK;

exit:

  return (status);
}


/******************************************************************************/

#if (defined (__VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__))

/* The vlong mod exp is done in software for now.
 */
extern MSTATUS VLONG_modexp (
  MOC_MOD (hwAccelDescr hwAccelCtx)
  const vlong *x,
  const vlong *e,
  const vlong *n,
  vlong **ppRet,
  vlong **ppVlongQueue
  )
{
  MSTATUS status;
  ModExpHelper mHelper = NULL;

  status = VLONG_newModExpHelper (
    MOC_MOD (hwAccelCtx) &mHelper, n, ppVlongQueue);
  if (OK != status)
    goto exit;

  status = VLONG_modExp (
    MOC_MOD (hwAccelCtx) mHelper, x, e, ppRet, ppVlongQueue);

exit:

  if (NULL != mHelper)
  {
    VLONG_deleteModExpHelper (&mHelper, ppVlongQueue);
  }

  return (status);
}

#endif /* (defined (__VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__)) */


/******************************************************************************
 * Synergy Driver Functions
 ******************************************************************************/

/* This function will initialize the main crypto driver using the parameters
 * provided by the caller. The caller can specify whether the main crypto driver
 * should initialize itself to treat word arrays as little or big endian. The
 * endian mode passed in by the caller can either be CRYPTO_WORD_ENDIAN_BIG or
 * CRYPTO_WORD_ENDIAN_SMALL. If big endian is specified then ALL the crypto
 * drivers will treat their input and output for word arrays as big endian and
 * vice versa for small endian.
 */
ssp_err_t ssp_crypto_initialize (
  crypto_word_endian_t endianMode
  )
{
  ssp_err_t iret;

  CONSOLE_PRINTF("\nOpening Crypto Layer: ");

  /* Open the common crypto driver. This variable was created in
   * configuration.xml
   */
  iret = g_sce.p_api->open(g_sce.p_ctrl, g_sce.p_cfg);
  if (SSP_SUCCESS != iret)
  {
    CONSOLE_PRINTF ("Failed to open crypto layer\n");
    goto exit;
  }

  /* Set cryptoInit so we don't open drivers twice
   */
  cryptoInit = 1;

  if (CRYPTO_WORD_ENDIAN_BIG == endianMode)
  {
    CONSOLE_PRINTF ("Big-endian mode\n");
  }

  if (CRYPTO_WORD_ENDIAN_LITTLE == endianMode)
  {
    CONSOLE_PRINTF ("Little-endian mode\n");
  }


exit:

  return iret;
}

/* Close the SCE module
 */
ssp_err_t ssp_crypto_close (void)
{
	ssp_err_t iret;

	iret = g_sce.p_api->close (g_sce.p_ctrl);
	if (SSP_SUCCESS != iret)
	{
    CONSOLE_PRINTF ("Failed to close crypto layer\n");
    goto exit;
  }

	cryptoInit = 0;

  CONSOLE_PRINTF("Crypto layer closed\n");


exit:

  return iret;
}

/******************************************************************************/

/* This will initialize the main crypto driver if it hasn't been initialized
 * yet. Then it will open any sub drivers that the Mocana crypto library may
 * require. If the main crypto driver is already initialized then this function
 * will not do anything. If more drivers need to be opened for other operations
 * then they can be opened here. This function will be called during
 * DIGICERT_initDigicert. The equivalent uninit function will be called in
 * DIGICERT_freeDigicert.
 */
extern sbyte4 SYNERGY_init(void)
{
  ssp_err_t iret;
  MSTATUS status;

  if (0 == cryptoInit)
  {
    status = OK;

    /* Open the main crypto driver
     */
    iret = ssp_crypto_initialize(CRYPTO_WORD_ENDIAN_LITTLE);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_INIT;
      goto exit;
    }

    /***************************/
    /*********** AES ***********/
    /***************************/
    /* Open the sub driver for AES-CBC w/ 128 bit keys
     */
    iret = g_sce_aes_128_cbc.p_api->open(
      g_sce_aes_128_cbc.p_ctrl, g_sce_aes_128_cbc.p_cfg);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_AES_CBC_128_INIT;
      goto exit;
    }

    /* Open the sub driver for AES-CBC w/ 192 bit keys
     */
    iret = g_sce_aes_192_cbc.p_api->open(
      g_sce_aes_192_cbc.p_ctrl, g_sce_aes_192_cbc.p_cfg);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_AES_CBC_192_INIT;
      goto exit;
    }

    /* Open the sub driver for AES-CBC w/ 256 bit keys
     */
    iret = g_sce_aes_256_cbc.p_api->open(
      g_sce_aes_256_cbc.p_ctrl, g_sce_aes_256_cbc.p_cfg);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_AES_CBC_256_INIT;
      goto exit;
    }

    /* Open the sub driver for AES-ECB w/ 128 bit keys
     */
    iret = g_sce_aes_128_ecb.p_api->open(
      g_sce_aes_128_ecb.p_ctrl, g_sce_aes_128_ecb.p_cfg);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_AES_ECB_128_INIT;
      goto exit;
    }

    /* Open the sub driver for AES-ECB w/ 192 bit keys
     */
    iret = g_sce_aes_192_ecb.p_api->open(
      g_sce_aes_192_ecb.p_ctrl, g_sce_aes_192_ecb.p_cfg);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_AES_ECB_192_INIT;
      goto exit;
    }

    /* Open the sub driver for AES-ECB w/ 256 bit keys
     */
    iret = g_sce_aes_256_ecb.p_api->open(
      g_sce_aes_256_ecb.p_ctrl, g_sce_aes_256_ecb.p_cfg);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_AES_ECB_256_INIT;
      goto exit;
    }

    /***************************/
    /*********** SHA ***********/
    /***************************/
    /* Open the sub driver for SHA-1
     */
    iret = g_sce_hash_sha1.p_api->open(
      g_sce_hash_sha1.p_ctrl, g_sce_hash_sha1.p_cfg);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_SHA1_INIT;
      goto exit;
    }

    /* Open the sub driver for SHA-224
     */
    iret = g_sce_hash_sha224.p_api->open (
      g_sce_hash_sha224.p_ctrl, g_sce_hash_sha224.p_cfg);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_SHA224_INIT;
      goto exit;
    }

    /* Open the sub driver for SHA-256
     */
    iret = g_sce_hash_sha256.p_api->open (
      g_sce_hash_sha256.p_ctrl, g_sce_hash_sha256.p_cfg);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_SHA256_INIT;
      goto exit;
    }

    /***************************/
    /********** TRNG ***********/
    /***************************/
    /* Open the sub driver for the TRNG
     */
    iret = g_sce_trng.p_api->open(g_sce_trng.p_ctrl, g_sce_trng.p_cfg);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_RANDOM_NO_INIT;
      goto exit;
    }

    /***************************/
    /********** 3DES ***********/
    /***************************/
    /* Open the sub driver for Triple DES
     */
    iret = g_sce_tdes_cbc.p_api->open (
      g_sce_tdes_cbc.p_ctrl, g_sce_tdes_cbc.p_cfg);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_TDES_INIT;
      goto exit;
    }

    /***************************/
    /*********** DSA ***********/
    /***************************/
    /* Open the sub driver for DSA
     * 1024-bit key length w/ SHA-1
     */
    iret = g_sce_dsa_1024_160.p_api->open (
      g_sce_dsa_1024_160.p_ctrl, g_sce_dsa_1024_160.p_cfg);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_DSA_1024_160_INIT;
      goto exit;
    }

    /* Open the sub driver for DSA
     * 2048-bit key length w/ SHA-224
     */
    iret = g_sce_dsa_2048_224.p_api->open (
      g_sce_dsa_2048_224.p_ctrl, g_sce_dsa_2048_224.p_cfg);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_DSA_2048_224_INIT;
      goto exit;
    }

    /* Open the sub driver for DSA
     * 2048-bit key length w/ SHA-256
     */
    iret = g_sce_dsa_2048_256.p_api->open (
      g_sce_dsa_2048_256.p_ctrl, g_sce_dsa_2048_256.p_cfg);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_DSA_2048_256_INIT;
      goto exit;
    }


    /***************************/
    /*********** RSA ***********/
    /***************************/
    /* Open the sub driver for RSA
     * 1024-bit key
     */
    iret = g_sce_rsa_1024.p_api->open (
      g_sce_rsa_1024.p_ctrl, g_sce_rsa_1024.p_cfg);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_RSA_1024_INIT;
      goto exit;
    }

    /* Open the sub driver for RSA
     * 2048-bit key
     */
    iret = g_sce_rsa_2048.p_api->open (
      g_sce_rsa_2048.p_ctrl, g_sce_rsa_2048.p_cfg);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_RSA_2048_INIT;
      goto exit;
    }

  }

  status = OK;

exit:

  return ((sbyte4) status);
}

/******************************************************************************/

/* This function is used to close the sub drivers and the main crypto driver
 * for the Synergy board. This will be called when DIGICERT_freeDigicert is called.
 */
extern sbyte4 SYNERGY_uninit(void)
{
  ssp_err_t iret;
  MSTATUS status = OK;

  /* Close all sub-drivers
   */
  iret = g_sce_trng.p_api->close(g_sce_trng.p_ctrl);
  if (SSP_SUCCESS != iret)
  {
    status = ERR_HARDWARE_ACCEL_RANDOM_NO_DEINIT;
    goto exit;
  }

  iret = g_sce_aes_128_cbc.p_api->close(g_sce_aes_128_cbc.p_ctrl);
  if (SSP_SUCCESS != iret)
  {
    status = ERR_HARDWARE_ACCEL_AES_CBC_128_DEINIT;
    goto exit;
  }

  iret = g_sce_aes_192_cbc.p_api->close(g_sce_aes_192_cbc.p_ctrl);
  if (SSP_SUCCESS != iret)
  {
    status = ERR_HARDWARE_ACCEL_AES_CBC_192_DEINIT;
    goto exit;
  }

  iret = g_sce_aes_256_cbc.p_api->close(g_sce_aes_256_cbc.p_ctrl);
  if (SSP_SUCCESS != iret)
  {
    status = ERR_HARDWARE_ACCEL_AES_CBC_256_DEINIT;
    goto exit;
  }

  iret = g_sce_aes_128_ecb.p_api->close(g_sce_aes_128_ecb.p_ctrl);
  if (SSP_SUCCESS != iret)
  {
    status = ERR_HARDWARE_ACCEL_AES_ECB_128_DEINIT;
    goto exit;
  }

  iret = g_sce_aes_192_ecb.p_api->close(g_sce_aes_192_ecb.p_ctrl);
  if (SSP_SUCCESS != iret)
  {
    status = ERR_HARDWARE_ACCEL_AES_ECB_192_DEINIT;
    goto exit;
  }

  iret = g_sce_aes_256_ecb.p_api->close(g_sce_aes_256_ecb.p_ctrl);
  if (SSP_SUCCESS != iret)
  {
    status = ERR_HARDWARE_ACCEL_AES_ECB_256_DEINIT;
    goto exit;
  }

  iret = g_sce_hash_sha1.p_api->close(g_sce_hash_sha1.p_ctrl);
  if (SSP_SUCCESS != iret)
  {
    status = ERR_HARDWARE_ACCEL_SHA1_DEINIT;
    goto exit;
  }

  iret = g_sce_hash_sha224.p_api->close(g_sce_hash_sha224.p_ctrl);
  if (SSP_SUCCESS != iret)
  {
    status = ERR_HARDWARE_ACCEL_SHA224_DEINIT;
    goto exit;
  }

  iret = g_sce_hash_sha256.p_api->close(g_sce_hash_sha256.p_ctrl);
  if (SSP_SUCCESS != iret)
  {
    status = ERR_HARDWARE_ACCEL_SHA256_DEINIT;
    goto exit;
  }

  iret = g_sce_tdes_cbc.p_api->close(g_sce_tdes_cbc.p_ctrl);
  if (SSP_SUCCESS != iret)
  {
    status = ERR_HARDWARE_ACCEL_TDES_DEINIT;
    goto exit;
  }

  iret = g_sce_dsa_1024_160.p_api->close(g_sce_dsa_1024_160.p_ctrl);
  if (SSP_SUCCESS != iret)
  {
    status = ERR_HARDWARE_ACCEL_DSA_1024_160_DEINIT;
    goto exit;
  }

  iret = g_sce_dsa_2048_224.p_api->close(g_sce_dsa_2048_224.p_ctrl);
  if (SSP_SUCCESS != iret)
  {
    status = ERR_HARDWARE_ACCEL_DSA_2048_224_DEINIT;
    goto exit;
  }

  iret = g_sce_dsa_2048_256.p_api->close(g_sce_dsa_2048_256.p_ctrl);
  if (SSP_SUCCESS != iret)
  {
    status = ERR_HARDWARE_ACCEL_DSA_2048_256_DEINIT;
    goto exit;
  }

  iret = g_sce_rsa_1024.p_api->close(g_sce_rsa_1024.p_ctrl);
  if (SSP_SUCCESS != iret)
  {
    status = ERR_HARDWARE_ACCEL_RSA_1024_DEINIT;
    goto exit;
  }

  iret = g_sce_rsa_2048.p_api->close(g_sce_rsa_2048.p_ctrl);
  if (SSP_SUCCESS != iret)
  {
    status = ERR_HARDWARE_ACCEL_RSA_2048_DEINIT;
    goto exit;
  }

  /* Close global common crypto driver
   */
  iret = ssp_crypto_close();
  if (SSP_SUCCESS != iret)
  {
    status = ERR_HARDWARE_ACCEL_UNINIT;
    goto exit;
  }

  status = OK;

exit:

  return ((sbyte4) status);
}

/******************************************************************************/

/**
 * Open channels to SHA1 and SHA256. We don't open channels to all the AES
 * contexts because we share the control and config structures between them
 * during AES operations, and so we open and close them individually when
 * we use them.
 */

/* The SYNERGY_init will open all the drivers that are ever needed. This
 * function won't do anything. Since all the drivers are global as well, this
 * function does not need to return a hardware accelerator descriptor.
 */
extern sbyte4 SYNERGY_openChannel(
  enum moduleNames moduleId,
  hwAccelDescr *ppHwAccelCookie
  )
{
  MOC_UNUSED(moduleId);
  MOC_UNUSED(ppHwAccelCookie);

  return ((sbyte4) OK);
}

/******************************************************************************/

/* The SYNERGY_uninit will close all the drivers that are ever needed. This
 * function won't do anything.
 */
extern sbyte4 SYNERGY_closeChannel(
  enum moduleNames moduleId,
  hwAccelDescr *pHwAccelCookie
  )
{
  MOC_UNUSED(moduleId);
  MOC_UNUSED(pHwAccelCookie);

  return (sbyte4)OK;
}


/******************************************************************************
 * Cipher Implementations
 ******************************************************************************/

#ifdef __AES_HARDWARE_CIPHER__

/* This function will create a BulkCtx which can be a pointer to any data
 * struct. Any necessary key operations are also performed here. For the Synergy
 * device, this simply means storing the key. This function will set the mode
 * to AES-CBC inside the BulkCtx. The caller can change the AES mode of
 * operation to another mode by calling the AESALGO_makeAesKeyEx function with
 * the MODE_* parameter. The AESALGO_makeAesKeyEx will take care of setting up
 * the BulkCtx for the appropriate AES mode.
 */
extern BulkCtx CreateAESCtx(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  ubyte *pKeyMaterial,
  sbyte4 keyLen,
  sbyte4 cryptFlag
  )
{
  MSTATUS status;
  ssp_err_t iret;

  MAesSynergyCtx *pNewCtx = NULL;

  /* Caller must provide a key
  */
  status = ERR_NULL_POINTER;
  if ( NULL == pKeyMaterial )
    goto exit;

  /* Check if the key length is valid. Also set a pointer to the correct
   * AES-CBC driver.
   */
  status = ERR_AES_BAD_LENGTH;
  switch (keyLen)
  {
    default:
      goto exit;

    case 16:
    case 24:
    case 32:
      break;
  }

  /* Allocate memory for the context Synergy AES context
   */
  status = DIGI_MALLOC(&pNewCtx, sizeof(MAesSynergyCtx));
  if (OK != status)
    goto exit;

  /* Setup the Synergy AES context to perform AES-CBC
   */
  status = AESALGO_makeAesKeyEx(
    MOC_SYM(hwAccelCtx) pNewCtx, keyLen * 8, pKeyMaterial, cryptFlag, MODE_CBC);
  if (OK != status)
    goto exit;

exit:

  /* If an error occured then free the context
   */
  if ( OK != status )
  {
    DIGI_MEMSET(pNewCtx, 0x00, sizeof(MAesSynergyCtx));
    DIGI_FREE((void **) &pNewCtx);
  }

  return pNewCtx;
}

/******************************************************************************/

/* This function will clear out any data in the struct and then free the
 * memory.
 */
extern MSTATUS DeleteAESCtx(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx *ppCtx
  )
{
  MSTATUS status, fstatus;

  status = ERR_NULL_POINTER;
  if (NULL == ppCtx)
    goto exit;

  status = OK;

  /* Clear out the key from memory
   */
  fstatus = DIGI_MEMSET(*ppCtx, 0x00, sizeof(MAesSynergyCtx));
  if (OK == status)
    status = fstatus;

  /* Free up the memory
   */
  fstatus = DIGI_FREE((void **) ppCtx);
  if (OK == status)
    status = fstatus;

exit:

  return status;
}


/******************************************************************************/

/* This function will take care of setting any information inside the AES
 * context. Although the function signature requires that an aesCipherContext
 * pointer is passed in, this function will cast it into a MAesSynergyCtx
 * pointer. The function will then populate the MAesSynergyCtx with values
 * based on the key, key length, encrypt/decrypt flag, and the AES mode of
 * operation.
 */
extern MSTATUS AESALGO_makeAesKeyEx (
  MOC_SYM(hwAccelDescr pHwCtx)
  aesCipherContext *pAesCtx,
  sbyte4 keyLenBits,
  const ubyte *pKeyMaterial,
  sbyte4 cryptFlag,
  sbyte4 mode
  )
{
  MSTATUS status;

  MAesSynergyCtx *pAesHwCtx = (MAesSynergyCtx *) pAesCtx;
  ubyte pad;
  aes_instance_t *pAesInstance[3] = { 0 };

  MOC_UNUSED(cryptFlag);

  /* The pAesHwCtx must be passed in by the caller
   */
  status = ERR_NULL_POINTER;
  if (NULL == pAesHwCtx)
    goto exit;

  /* Figure out the set of drivers that we are dealing with based on the mode
   * that is passed in. Note that AES-OFB and AES-CFB will use the AES-ECB
   * driver on the Synergy board to perform their operations.
   */
  status = ERR_INVALID_ARG;
  if ( (MODE_ECB == mode) || (MODE_OFB == mode) || (MODE_CFB128 == mode) )
  {
    pAesInstance[0] = &g_sce_aes_128_ecb;
    pAesInstance[1] = &g_sce_aes_192_ecb;
    pAesInstance[2] = &g_sce_aes_256_ecb;
  }
  else if (MODE_CBC == mode)
  {
    pAesInstance[0] = &g_sce_aes_128_cbc;
    pAesInstance[1] = &g_sce_aes_192_cbc;
    pAesInstance[2] = &g_sce_aes_256_cbc;
  }
  else
  {
    goto exit;
  }

  /* From the set of drivers, determine which driver to use based on the key
   * size passed in
   */
  status = ERR_AES_BAD_KEY_LENGTH;
  switch (keyLenBits)
  {
    default:
      goto exit;

    case 128:
      pAesHwCtx->pCtx = pAesInstance[0];
      break;
    case 192:
      pAesHwCtx->pCtx = pAesInstance[1];
      break;
    case 256:
      pAesHwCtx->pCtx = pAesInstance[2];
      break;
  }

  /* Clear out the current key just so any partial key values won't be leftover
   * in the key buffer
   */
  status = DIGI_MEMSET(pAesHwCtx->pKey, 0x00, sizeof(pAesHwCtx->pKey));
  if (OK != status)
    goto exit;

  /* Copy the key into the context
   */
  status = DIGI_MEMCPY(pAesHwCtx->pKey, pKeyMaterial, keyLenBits / 8);
  if (OK != status)
    goto exit;

  /* Treat the key buffer as a word array and swap each word in the array
   */
#ifdef MOC_LITTLE_ENDIAN
  status = byteArrayToWordArrayInPlace(
    pAesHwCtx->pKey, keyLenBits / 8);
  if (OK != status)
    goto exit;
#endif

  /* Set the key length inside the hardware context
   */
  pAesHwCtx->keyLen = keyLenBits / 8;

  /* Set the mode as well
   */
  pAesHwCtx->mode = mode;

exit:

  return status;
}

/******************************************************************************/

/* This function will perform the encryption process for the AES context that
 * is passed in. The function will determine what the mode of operation is from
 * the context and perform the necessary steps, calling the Synergy SCE API as
 * needed. There is no hardware descriptor required since all the driver values
 * are global and/or stored in the AES context.
 */
extern MSTATUS AESALGO_blockEncryptEx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  aesCipherContext *pAesCtx,
  ubyte *pIv,
  ubyte *pInput,
  sbyte4 inputLenBits,
  ubyte *pOutput,
  sbyte4 *pRetOutputLen
  )
{
  MSTATUS status;
  ssp_err_t iret;

  ubyte4 aesBlockCount, blockIndex, xorIndex;
  ubyte *pResult = NULL, *pIndex, *pPlainText;
  ubyte pad;
  MAesSynergyCtx *pHwCtx = (MAesSynergyCtx *) pAesCtx;

  /* Caller must provide an AES context
   */
  status = ERR_NULL_POINTER;
  if (NULL == pHwCtx)
    goto exit;

  /* Ensure a valid mode is set in the AES context. The Synergy hardware
   * accelerator does not accept an IV for AES-ECB so if the user provided a
   * non NULL IV then return an error.
   */
  status = ERR_INVALID_ARG;
  switch (pHwCtx->mode)
  {
    default:
      goto exit;

    case MODE_ECB:
      if (NULL != pIv)
        goto exit;
    case MODE_CBC:
    case MODE_OFB:
    case MODE_CFB128:
      break;
  }

  /* Swap the bytes for the input and IV so they're now word arrays
   */
#ifdef MOC_LITTLE_ENDIAN
  status = byteArrayToWordArrayInPlace(
    pInput, inputLenBits / 8);
  if (OK != status)
    goto exit;

  if (NULL != pIv)
  {
    status = byteArrayToWordArrayInPlace(
      pIv, 16);
    if (OK != status)
      goto exit;
  }
#endif

  /* Allocate a temporary buffer that will be used to store the result
   */
  status = DIGI_MALLOC((void **) &pResult, inputLenBits / 8);
  if (OK != status)
    goto exit;

  /* If the mode is not ECB or CBC then it must be OFB or CFB
   */
  if ( (MODE_ECB != pHwCtx->mode) && (MODE_CBC != pHwCtx->mode) )
  {
    /* If we are inside this loop then we must be in either OFB or CFB mode.
     * These modes will call the Synergy hardware accelerator to do AES-ECB in
     * blocks.
     *
     * First step is to calculate the total number of AES blocks that need to
     * be done.
     */
    aesBlockCount = (inputLenBits / 8) / AES_BLOCK_SIZE;

    /* Loop through the blocks and perform AES-ECB. Then determine which mode is
     * being used and perform the operations as required. The Synergy hardware
     * accelerator does not actually provide a driver that performs AES-OFB or
     * AES-CFB in hardware so the post processing, after the core AES-ECB call
     * is made, is done in software.
     */
    pIndex = pResult;
    pPlainText = pInput;
    for (blockIndex = 0; blockIndex < aesBlockCount; ++blockIndex)
    {

      /* Call the encrypt function
       */
      iret = pHwCtx->pCtx->p_api->encrypt(
        pHwCtx->pCtx->p_ctrl, pHwCtx->pKey, NULL, 4, pIv, pIndex);
      if (SSP_SUCCESS != iret)
      {
        status = ERR_HARDWARE_ACCEL_ENCRYPT;
        goto exit;
      }

      /* Depending on the mode of operation perform the post processing
       */
      if (MODE_OFB == pHwCtx->mode)
      {
        status = DIGI_MEMCPY(
          pIv, pIndex, AES_BLOCK_SIZE);
        if (OK != status)
          goto exit;

        for (xorIndex = 0; xorIndex < AES_BLOCK_SIZE; ++xorIndex)
          pIndex[xorIndex] = pIndex[xorIndex] ^ pPlainText[xorIndex];
      }
      else if (MODE_CFB128 == pHwCtx->mode)
      {
        for (xorIndex = 0; xorIndex < AES_BLOCK_SIZE; ++xorIndex)
          pIndex[xorIndex] = pIndex[xorIndex] ^ pPlainText[xorIndex];

        status = DIGI_MEMCPY(
          pIv, pIndex, AES_BLOCK_SIZE);
        if (OK != status)
          goto exit;
      }

      pIndex += AES_BLOCK_SIZE;
      pPlainText += AES_BLOCK_SIZE;
    }
  }
  else
  {
    /* If the mode in the AES context is either ECB or CBC then call the encrypt
     * directly.
     */
    iret = pHwCtx->pCtx->p_api->encrypt(
      pHwCtx->pCtx->p_ctrl, pHwCtx->pKey,
      pIv, ((inputLenBits / 8) / 4), pInput, pResult);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_ENCRYPT;
      goto exit;
    }
  }

  /* Swap the output back into a canonical integer representation. The IV must
   * also be converted since the caller has control of the IV buffer.
   */
#ifdef MOC_LITTLE_ENDIAN
  status = byteArrayToWordArrayInPlace(
    pResult, inputLenBits / 8);
  if (OK != status)
    goto exit;

  status = byteArrayToWordArrayInPlace(
    pInput, inputLenBits / 8);
  if (OK != status)
    goto exit;

  if (NULL != pIv)
  {
    status = byteArrayToWordArrayInPlace(
      pIv, 16);
    if (OK != status)
    goto exit;
  }
#endif

  /* Copy the result into the return buffer provided by the caller.
   */
  status = DIGI_MEMCPY(pOutput, pResult, inputLenBits / 8);
  if (OK != status)
    goto exit;

  /* Set the total amount of bytes procssed
   */
  *pRetOutputLen = inputLenBits / 8;

exit:

  DIGI_MEMSET(pResult, 0x00, inputLenBits / 8);
  DIGI_FREE((void **) &pResult);

  return status;
}

/******************************************************************************/

/* This function will perform block decryption. The hardware descriptor is not
 * required since all the drivers are either global variables and/or stored
 * inside the AES context provided by the caller.
 */
extern MSTATUS AESALGO_blockDecryptEx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  aesCipherContext *pAesCtx,
  ubyte *pIv,
  ubyte *pInput,
  sbyte4 inputLenBits,
  ubyte *pOutput,
  sbyte4 *pRetOutputLen
  )
{
  MSTATUS status;
  ssp_err_t iret;

  ubyte4 aesBlockCount, blockIndex, xorIndex;
  ubyte pad;
  ubyte *pResult = NULL, *pIndex, *pCipherText;
  MAesSynergyCtx *pHwCtx = (MAesSynergyCtx *) pAesCtx;

  status = ERR_NULL_POINTER;
  if (NULL == pHwCtx)
    goto exit;

  /* Convert from canonical byte arrays to word arrays
   */
#ifdef MOC_LITTLE_ENDIAN
  status = byteArrayToWordArrayInPlace(
    pInput, inputLenBits / 8);
  if (OK != status)
    goto exit;

  if (NULL != pIv)
  {
    status = byteArrayToWordArrayInPlace(
      pIv, 16);
    if (OK != status)
      goto exit;
  }
#endif

  /* Allocate memory for a temporary buffer that will hold the result
   */
  status = DIGI_MALLOC((void **) &pResult, inputLenBits / 8);
  if (OK != status)
    goto exit;

  /* If the mode is not ECB or CBC then it must be OFB or CFB which both require
   * a post processing in software. If the mode is ECB or CBC then the function
   * will fall into the else statement and call the decrypt directly.
   */
  if ( (MODE_ECB != pHwCtx->mode) && (MODE_CBC != pHwCtx->mode) )
  {

    /* If we are inside this loop then we must be in either OFB or CFB mode.
     * These modes will call the Renesas hardware accelerator to do AES-ECB in
     * blocks.
     *
     * Calculate the total amount of blocks that will be processed
     */
    aesBlockCount = (inputLenBits / 8) / 16;

    /* Loop through each block and perform any operations as needed
     */
    pIndex = pResult;
    pCipherText = pInput;
    for (blockIndex = 0; blockIndex < aesBlockCount; ++blockIndex)
    {
      /* This will perform AES-ECB encryption in the Synergy hardware
       * accelerator. Both OFB and CFB require the AES-ECB encrypt operation
       * instead of the decrypt operation.
       */
      iret = pHwCtx->pCtx->p_api->encrypt(
        pHwCtx->pCtx->p_ctrl, pHwCtx->pKey, NULL, 4, pIv, pIndex);
      if (SSP_SUCCESS != iret)
      {
        status = ERR_HARDWARE_ACCEL_ENCRYPT;
        goto exit;
      }

      /* Perform mode specific operations here
       */
      if (MODE_OFB == pHwCtx->mode)
      {
        status = DIGI_MEMCPY(
          pIv, pIndex, AES_BLOCK_SIZE);
        if (OK != status)
          goto exit;

        for (xorIndex = 0; xorIndex < AES_BLOCK_SIZE; ++xorIndex)
          pIndex[xorIndex] = pIndex[xorIndex] ^ pCipherText[xorIndex];
      }
      else if (MODE_CFB128 == pHwCtx->mode)
      {
        for (xorIndex = 0; xorIndex < AES_BLOCK_SIZE; ++xorIndex)
          pIndex[xorIndex] = pIndex[xorIndex] ^ pCipherText[xorIndex];

        status = DIGI_MEMCPY(
          pIv, pCipherText, AES_BLOCK_SIZE);
        if (OK != status)
          goto exit;
      }

      pIndex += AES_BLOCK_SIZE;
      pCipherText += AES_BLOCK_SIZE;
    }
  }
  else
  {
    /* If the mode of operation is either ECB or CBC then call the decrypt
     * directly.
     */
    iret = pHwCtx->pCtx->p_api->decrypt(
      pHwCtx->pCtx->p_ctrl, pHwCtx->pKey,
      pIv, ((inputLenBits / 8) / 4), pInput, pResult);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_DECRYPT;
      goto exit;
    }
  }

  /* Convert the word arrays back into canonical byte arrays. Again the IV has
   * to be converted back into a canonical byte array because the user has
   * control over the IV buffer.
   */
#ifdef MOC_LITTLE_ENDIAN
  status = byteArrayToWordArrayInPlace(
    pResult, inputLenBits / 8);
  if (OK != status)
    goto exit;

  status = byteArrayToWordArrayInPlace(
    pInput, inputLenBits / 8);
  if (OK != status)
    goto exit;

  if (NULL != pIv)
  {
    status = byteArrayToWordArrayInPlace(
	  pIv, 16);
    if (OK != status)
	  goto exit;
  }
#endif

  /* Copy the result into the output buffer provided by the caller
   */
  status = DIGI_MEMCPY(pOutput, pResult, inputLenBits / 8);
  if (OK != status)
    goto exit;

  /* Set the amount of bytes processed
   */
  *pRetOutputLen = inputLenBits / 8;

exit:

  DIGI_MEMSET(pResult, 0x00, inputLenBits / 8);
  DIGI_FREE((void **) &pResult);

  return status;
}

/******************************************************************************/

/* This function will perform an AES operation on some data. The caller passes
 * in the AES context, the data to operate on, the data length, the encrypt/
 * decrypt flag, and the IV. The hardware accelerator can be NULL since all the
 * driver values are global and/or stored in the AES context.
 */
extern MSTATUS DoAES(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pCtx,
  ubyte *pData,
  sbyte4 dataLenBytes,
  sbyte4 cryptFlag,
  ubyte *pIv
  )
{
  MSTATUS status;

  MAesSynergyCtx *pHwCtx = (MAesSynergyCtx *) pCtx;
  sbyte4 retLength = 0;

  status = ERR_NULL_POINTER;
  if (NULL == pHwCtx)
    goto exit;

  /* AES-ECB mode does not take in an IV. Return an error if the caller tries
   * to provide an IV while performing AES-ECB.
   */
  status = ERR_INVALID_INPUT;
  if ( (MODE_ECB == pHwCtx->mode) && (NULL != pIv) )
    goto exit;

  /* Ensure the data length is a multiple of block size. This function will only
   * operate on data that is a multiple of block size, even for the AES stream
   * ciphers.
   */
  status = ERR_AES_BAD_LENGTH;
  if (0 != (dataLenBytes % AES_BLOCK_SIZE))
    goto exit;

  /* Depending on the flag passed in by the caller, we will either encrypt
   * or decrypt
   */
  if (FALSE == cryptFlag)
  {
    status = AESALGO_blockDecryptEx(
      MOC_SYM(hwAccelCtx) (aesCipherContext *) pHwCtx,
      pIv, pData, dataLenBytes * 8, pData, &retLength);
  }
  else
  {
    status = AESALGO_blockEncryptEx(
      MOC_SYM(hwAccelCtx) (aesCipherContext *) pHwCtx,
      pIv, pData, dataLenBytes * 8, pData, &retLength);
  }
  if (OK != status)
    goto exit;

exit:

  return status;
}

/******************************************************************************/

/* This function is similar to CreateAESCtx. It will allocate an AES context and
 * it will populate the context with AES-CFB information.
 */
extern BulkCtx CreateAESCFBCtx(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  ubyte *pKey,
  sbyte4 keyLenBytes,
  sbyte4 cryptFlag
  )
{
  MSTATUS status;

  BulkCtx retCtx = NULL;
  MAesSynergyCtx *pHwCtx = NULL;

  /* Ensure the key length is a valid AES key length
   */
  status = ERR_AES_BAD_KEY_LENGTH;
  switch(keyLenBytes)
  {
    default:
      goto exit;

    case 16:
    case 24:
    case 32:
      break;
  }

  /* If the driver has been initialized then allocate memory for a new context
   */
  status = DIGI_MALLOC((void **) &pHwCtx, sizeof(MAesSynergyCtx));
  if (OK != status)
    goto exit;

  /* Perform initialization operation specific to AES-CFB. This function call
   * will set up the AES context with information regarding which AES driver to
   * use on the synergy board and it will copy the key into the context.
   */
  status = AESALGO_makeAesKeyEx(
    MOC_SYM(hwAccelCtx) (aesCipherContext *) pHwCtx,
    keyLenBytes * 8, pKey, cryptFlag, MODE_CFB128);
  if (OK != status)
    goto exit;

  retCtx = pHwCtx;
  pHwCtx = NULL;

exit:

  if (NULL != pHwCtx)
    DIGI_FREE((void **) &pHwCtx);

  return retCtx;
}

/******************************************************************************/

/* Similar to CreateAESCFBCtx. The only difference is when AESALGO_makeAesKeyEx
 * is called. This function will call the make key function with MODE_OFB.
 */
extern BulkCtx CreateAESOFBCtx(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  ubyte *pKey,
  sbyte4 keyLenBytes,
  sbyte4 cryptFlag
  )
{
  MSTATUS status;

  BulkCtx retCtx = NULL;
  MAesSynergyCtx *pHwCtx = NULL;

  /* Ensure a valid key is passed in
   */
  status = ERR_AES_BAD_KEY_LENGTH;
  switch(keyLenBytes)
  {
    default:
      goto exit;

    case 16:
    case 24:
    case 32:
      break;
  }


  /* If the driver has been initialized then allocate memory for a new context
   */
  status = DIGI_MALLOC((void **) &pHwCtx, sizeof(MAesSynergyCtx));
  if (OK != status)
    goto exit;

  /* Set parameters in the AES context specific to AES-OFB
   */
  status = AESALGO_makeAesKeyEx(
    MOC_SYM(hwAccelCtx) (aesCipherContext *) pHwCtx,
    keyLenBytes * 8, pKey, cryptFlag, MODE_OFB);
  if (OK != status)
    goto exit;

  retCtx = pHwCtx;
  pHwCtx = NULL;

exit:

  if (NULL != pHwCtx)
    DIGI_FREE((void **) &pHwCtx);

  return retCtx;
}

/******************************************************************************/

/* Similar to CreateAESCFBCtx. The only difference is when AESALGO_makeAesKeyEx
 * is called. This function will call the make key function with MODE_ECB.
 */
extern BulkCtx CreateAESECBCtx(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  ubyte *pKey,
  sbyte4 keyLenBytes,
  sbyte4 cryptFlag
  )
{
  MSTATUS status;

  BulkCtx retCtx = NULL;
  MAesSynergyCtx *pHwCtx = NULL;

  /* Ensure the key length is correct
   */
  status = ERR_AES_BAD_KEY_LENGTH;
  switch(keyLenBytes)
  {
    default:
      goto exit;

    case 16:
    case 24:
    case 32:
      break;
  }

  /* If the driver has been initialized then allocate memory for a new context
   */
  status = DIGI_MALLOC((void **) &pHwCtx, sizeof(MAesSynergyCtx));
  if (OK != status)
    goto exit;

  /* Set parameters in the AES context specific to AES-ECB
   */
  status = AESALGO_makeAesKeyEx(
    MOC_SYM(hwAccelCtx) (aesCipherContext *) pHwCtx,
    keyLenBytes * 8, pKey, cryptFlag, MODE_ECB);
  if (OK != status)
    goto exit;

  retCtx = pHwCtx;
  pHwCtx = NULL;

exit:

  if (NULL != pHwCtx)
    DIGI_FREE((void **) &pHwCtx);

  return retCtx;
}

/******************************************************************************/

/* This function is the same as the DeleteAESCtx function
 */
extern MSTATUS DeleteAESECBCtx(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx *ppCtx
  )
{
  MSTATUS status, fstatus;

  status = ERR_NULL_POINTER;
  if (NULL == ppCtx)
    goto exit;

  status = OK;

  /* Clear out the key data
   */
  fstatus = DIGI_MEMSET(*ppCtx, 0x00, sizeof(MAesSynergyCtx));
  if (OK == status)
    status = fstatus;

  /* Free the actual memory
   */
  fstatus = DIGI_FREE(ppCtx);
  if (OK == status)
    status = fstatus;

exit:

  return status;
}


/******************************************************************************/

extern MSTATUS AESALGO_clearKey(
  aesCipherContext *pAesContext
  )
{
    MSTATUS status;

    if (NULL == pAesContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_MEMSET((ubyte *)pAesContext, 0, sizeof(aesCipherContext));

exit:
    return status;
}


/******************************************************************************/

/* This function will perform AES-ECB by calling DoAES with a NULL IV
 */
extern MSTATUS DoAESECB(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pCtx,
  ubyte *pData,
  sbyte4 dataLenBytes,
  sbyte4 cryptFlag
  )
{
  return DoAES(MOC_SYM(hwAccelCtx) pCtx, pData, dataLenBytes, cryptFlag, NULL);
}

#endif /* __AES_HARDWARE_CIPHER__ */

/******************************************************************************
 * DSA Implementation
 ******************************************************************************/

#ifdef __DSA_HARDWARE_ACCELERATOR_SIGN__

/* Software implementation of the DSA_computeSignatureEx function defined below.
 * Only gets called if (L, N) pairs are out of the ( (1024, 160), (2048, 224),
 * (2048, 256) ) range the Renesas board supports. */
MSTATUS DSA_computeSignatureExSw (
  MOC_DSA(hwAccelDescr hwAccelCtx)
  RNGFun rngfun,
  void* rngarg,
  const DSAKey *p_dsaDescr,
  vlong* m,
  intBoolean *pVerifySignature,
  vlong **ppR,
  vlong **ppS,
  vlong **ppVlongQueue
  )
{
    /* p, q, g, private, public are all provided by key file */
    /* k is random */
    /* x = private key */
    /* y = public key */
    /* m = digested data */
    /* transmit p,q,g,y(public) */
    ubyte4      privateKeySize = VLONG_bitLength(DSA_X(p_dsaDescr)) / 8;
    ubyte*      p_kBuf    = NULL;
    vlong*      ksrc      = NULL;
    vlong*      k         = NULL;
    vlong*      kinv      = NULL;
    vlong*      x         = NULL;
    vlong*      tmp       = NULL;
    vlong*      tmp1      = NULL;
    MSTATUS     status;

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    if (OK != getFIPS_powerupStatus(FIPS_ALGO_DSA))
        return getFIPS_powerupStatus(FIPS_ALGO_DSA);
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

    if (OK != (status = DIGI_MALLOC((void **)&p_kBuf, 2*privateKeySize)))
        goto exit;

    /* compute a random k, less than q using FIPS 186-2 */
    status = rngfun(rngarg, 2 * privateKeySize, p_kBuf);
    if (OK != status)
      goto exit;

    status = VLONG_vlongFromByteString(
      p_kBuf, 2 * privateKeySize, &ksrc, ppVlongQueue);
    if (OK != status)
      goto exit;

    status = VLONG_operatorModSignedVlongs(
      MOC_MOD(hwAccelCtx)  ksrc, DSA_Q(p_dsaDescr), &k, ppVlongQueue);
    if (OK != status)
      goto exit;

    /* Compute r = (g^k mod p) mod q */
    status = VLONG_modexp(
      MOC_DSA(hwAccelCtx) DSA_G(p_dsaDescr), k, DSA_P(p_dsaDescr), &tmp,
      ppVlongQueue);
    if (OK != status)
      goto exit;

    status = VLONG_operatorModSignedVlongs(
      MOC_MOD(hwAccelCtx) tmp, DSA_Q(p_dsaDescr), ppR, ppVlongQueue);
    if (OK != status)
      goto exit;

    /* Compute s = inv(k) (m + xr) mod q */
    /* tmp = xr */
    status = VLONG_vlongSignedMultiply(tmp, DSA_X(p_dsaDescr), *ppR);
    if (OK != status)
      goto exit;

    /* tmp = (m + xr) */
    status = VLONG_addSignedVlongs(tmp, m, ppVlongQueue);
    if (OK != status)
      goto exit;

    /* tmp1 = (m + xr) mod q */
    status = VLONG_operatorModSignedVlongs(
      MOC_MOD(hwAccelCtx) tmp, DSA_Q(p_dsaDescr), &tmp1, ppVlongQueue);
    if (OK != status)
      goto exit;

    /* kinv = inv(k) mod q */
    status = VLONG_modularInverse(
      MOC_DSA(hwAccelCtx) k, DSA_Q(p_dsaDescr), &kinv, ppVlongQueue);
    if (OK != status)
      goto exit;

    /* tmp = ((m + xr) mod q) * (inv(k) mod q) */
    status = VLONG_vlongSignedMultiply(tmp, tmp1, kinv);
    if (OK != status)
      goto exit;

    /* s = inv(k) (m + xr) mod q */
    status = VLONG_operatorModSignedVlongs(
      MOC_MOD(hwAccelCtx) tmp, DSA_Q(p_dsaDescr), ppS, ppVlongQueue);
    if (OK != status)
      goto exit;

    if (NULL != pVerifySignature)
    {
      DSA_verifySignature(
        MOC_DSA(hwAccelCtx) p_dsaDescr, m, *ppR, *ppS, pVerifySignature,
        ppVlongQueue);
    }


exit:

    VLONG_freeVlong(&ksrc, ppVlongQueue);
    VLONG_freeVlong(&k, ppVlongQueue);
    VLONG_freeVlong(&kinv, ppVlongQueue);
    VLONG_freeVlong(&x, ppVlongQueue);
    VLONG_freeVlong(&tmp, ppVlongQueue);
    VLONG_freeVlong(&tmp1, ppVlongQueue);
    DIGI_FREE((void **)&p_kBuf);

    return status;

} /* DSA_computeSignatureExSw */


/******************************************************************************/

/* This function will generate a DSA signature using the Synergy board. The
 * board being used is the S5D9 board with the 1.3 SCE API. With this board
 * and the 1.3 API, the currently supported DSA sizes are
 *
 * 1024 - 160
 * 2048 - 224
 * 2048 - 256
 *
 * The function used to perform a DSA signature with the Synergy board has the
 * following function declaration.
 *
 * uint32_t sign(
 *   const uint32_t *p_key, const uint32_t *p_domain, uint32_t num_words,
 *   uint32_t *p_paddedHash, uint32_t *p_dest)
 *
 * p_key        - This is the DSA private key as a word array
 * p_domain     - These are the domain parameters as a word array
 * num_words    - This it the length of the data in words
 * p_paddedHash - This is the data that will be signed
 * p_dest       - This is where the result will be stored
 *
 * Each size requires a different length of input into the DSA driver. The
 * DSA driver requirements will be specified below for each size.
 *
 * 1024 - 160
 * ----------
 * p_key - Word array of length 5; Byte array of length 20
 * p_domain - Word array that consists of the subprime, prime, and generator.
 *   Where Q is the subprime, P is the prime, and G is the generator the word
 *   array will be ( Q || P || G ) where Q is 5 words or 20 bytes, and P/G are
 *   both 32 words each or 128 bytes each.
 * num_words - The length of the data in words
 * p_paddedHash - The data that will be signed. It must be word array
 * p_dest - The result buffer. This must be a word array as well that is at
 *   least num_words * 2 words in length
 *
 * 2048 - 224
 * ----------
 * p_key - Word array of length 7; Byte array of length 28
 * p_domain - Word array that consists of the subprime, prime, and generator.
 *   Where Q is the subprime, P is the prime, and G is the generator the word
 *   array will be ( Q || P || G ) where Q is 7 words or 28 bytes, and P/G are
 *   both 64 words each or 256 bytes each.
 * num_words - The length of the data in words
 * p_paddedHash - The data that will be signed. It must be word array
 * p_dest - The result buffer. This must be a word array as well that is at
 *   least num_words * 2 words in length
 *
 * 2048 - 256
 * ----------
 * p_key - Word array of length 8; Byte array of length 32
 * p_domain - Word array that consists of the subprime, prime, and generator.
 *   Where Q is the subprime, P is the prime, and G is the generator the word
 *   array will be ( Q || P || G ) where Q is 8 words or 32 bytes, and P/G are
 *   both 64 words each or 256 bytes each.
 * num_words - The length of the data in words
 * p_paddedHash - The data that will be signed. It must be word array
 * p_dest - The result buffer. This must be a word array as well that is at
 *   least num_words * 2 words in length
 */
MSTATUS DSA_computeSignatureEx (
  MOC_DSA(hwAccelDescr hwAccelCtx)
  RNGFun pRngFunc,
  void *pRngParam,
  const DSAKey *pDsaKey,
  vlong *pVlongData,
  intBoolean *pVfySig,
  vlong **ppRetR,
  vlong **ppRetS,
  vlong **ppVlongQueue
  )
{
  MSTATUS status;
  ssp_err_t iret;

  dsa_instance_t *pDriver = NULL;

  ubyte4 *pDomain = NULL, *pKey = NULL, *pData = NULL, *pDest = NULL;
  ubyte4 domainLen = 0, keyLen = 0, dataWordLen = 0, primeLenBits = 0,
         dataBitLen = 0;

  status = ERR_NULL_POINTER;
  if ( (NULL == pRngFunc) || (NULL == pDsaKey) || (NULL == pVlongData) ||
       (NULL == pVfySig) || (NULL == ppRetR) || (NULL == ppRetS) )
    goto exit;

  primeLenBits = VLONG_bitLength (DSA_P(pDsaKey));

  /* If the length of 'p' is out of the supported range of the Renesas board,
   * just call the software implementation of this function. */
  if (3072 == primeLenBits)
    return DSA_computeSignatureExSw (
      MOC_DSA(hwAccelCtx) pRngFunc, pRngParam, pDsaKey, pVlongData, pVfySig,
      ppRetR, ppRetS, ppVlongQueue);

  status = ERR_INVALID_ARG;
  if ( (1024 != primeLenBits) && (2048 != primeLenBits) )
    goto exit;
  status = OK;

  /* Convert the domain parameters into word arrays
   */
  status = ConvertDsaKeyToRenesasAlloc(
    (DSAKey *) pDsaKey, TRUE, &pDomain, &domainLen, &pKey, &keyLen);
  if (OK != status)
    goto exit;

  /* Get the word length of the data to sign
   */
  dataWordLen = (VLONG_bitLength(pVlongData) + 31) / 32;
  dataBitLen = dataWordLen * 32;

  /* Make sure the length of the prime matches up with it's corresponding
   * data length */
  status = ERR_INVALID_ARG;
  switch (primeLenBits)
  {
    case 1024:
      if (160 == dataBitLen)
      {
        pDriver = &g_sce_dsa_1024_160;
        break;
      }
      goto exit;

    case 2048:
      if (224 == dataBitLen)
      {
        pDriver = &g_sce_dsa_2048_224;
        break;
      }
      else if (256 == dataBitLen)
      {
        pDriver = &g_sce_dsa_2048_256;
        break;
      }

    default:
      goto exit;
  }
  status = OK;


  /* Allocate enough memory for the data to sign
   */
  status = DIGI_MALLOC((void **) &pData, dataWordLen * 4);
  if (OK != status)
    goto exit;

  /* Allocate enough memory for the destination buffer. It must be at least
   * twice as large as the data to sign
   */
  status = DIGI_MALLOC((void **) &pDest, dataWordLen * 8);
  if (OK != status)
    goto exit;

  /* Convert the vlong data into a word array of data
   */
  status = ConvertVlongToRenesas(pVlongData, pData, dataWordLen);
  if (OK != status)
    goto exit;

  /* Call driver to sign data
   */
  if (NULL != pDriver)
  {
    iret = pDriver->p_api->hashSign(
      pDriver->p_ctrl, pKey, pDomain, dataWordLen, pData, pDest);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_HASH_SIGN;
      goto exit;
    }
  }
  else
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  /* Convert the result back into a vlong
   */
  status = ConvertRenesasDsaSigToVlongs(
    pDest, dataWordLen * 2, ppRetR, ppRetS);
  if (OK != status)
    goto exit;

exit:

  if (NULL != pDomain)
  {
    DIGI_FREE ((void **)&pDomain);
  }
  if (NULL != pData)
  {
    DIGI_FREE ((void **)&pData);
  }
  if (NULL != pKey)
  {
    DIGI_MEMSET ((void *)pKey, 0, keyLen * 4);
    DIGI_FREE ((void **)&pKey);
  }
  if (NULL != pDest)
  {
    DIGI_MEMSET((void *) pDest, 0x00, dataWordLen * 8);
    DIGI_FREE((void **) &pDest);
  }

  return status;
}

#endif /* __DSA_HARDWARE_ACCELERATOR_SIGN__ */


/******************************************************************************/

#if (defined(__DSA_HARDWARE_ACCELERATOR_VERIFY__))

/* Software implementation of the DSA_verifySignatureEx function defined below.
 * Only gets called if (L, N) pairs are out of the ( (1024, 160), (2048, 224),
 * (2048, 256) ) range the Renesas board supports. */
MSTATUS DSA_verifySignatureSw (
  MOC_DSA(hwAccelDescr hwAccelCtx)
  const DSAKey *p_dsaDescr,
  vlong *m,
  vlong *pR,
  vlong *pS,
  intBoolean *isGoodSignature,
  vlong **ppVlongQueue
  )
{
  vlong*  w  = NULL;
  vlong*  u1 = NULL;
  vlong*  u2 = NULL;
  vlong*  v  = NULL;
  vlong*  v1 = NULL;
  vlong*  v2 = NULL;
  vlong*  v3 = NULL;
  vlong*  t  = NULL;
  MSTATUS status;

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
  if (OK != getFIPS_powerupStatus(FIPS_ALGO_DSA))
    return getFIPS_powerupStatus(FIPS_ALGO_DSA);
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

  *isGoodSignature = FALSE;

  /* From FIPS-186-2: To verify the signature, the verifier first checks to see
                      that 0 < r < q and 0 < s < q; if either condition is
                      violated the signature shall be rejected. */

  /* verify r and s are greater than zero */
  if ((pR->negative) || (pS->negative) ||
      (VLONG_isVlongZero(pR)) || (VLONG_isVlongZero(pS)) )
  {
    status = ERR_CRYPTO_DSA_SIGN_VERIFY_RS_TEST;
    goto exit;
  }

  /* r and s must be less than q */
  if ((VLONG_compareSignedVlongs(DSA_Q(p_dsaDescr), pR) <= 0) ||
      (VLONG_compareSignedVlongs(DSA_Q(p_dsaDescr), pS) <= 0) )
  {
    status = ERR_CRYPTO_DSA_SIGN_VERIFY_RS_TEST;
    goto exit;
  }

  status = VLONG_allocVlong(&t, ppVlongQueue);
  if (OK != status)
    goto exit;

  /* w = s^-1 mod q */
  status = VLONG_modularInverse(MOC_MOD(hwAccelCtx) pS, DSA_Q(p_dsaDescr), &w, ppVlongQueue);
  if (OK != status)
    goto exit;

  /* t = m * w */
  status = VLONG_vlongSignedMultiply(t, m, w);
  if (OK != status)
    goto exit;

  /* u1 = (m * w) mod q */
  status = VLONG_operatorModSignedVlongs(
    MOC_MOD(hwAccelCtx) t, DSA_Q(p_dsaDescr), &u1, ppVlongQueue);
  if (OK != status)
    goto exit;

  /* t = r * w */
  status = VLONG_vlongSignedMultiply(t, pR, w);
  if (OK != status)
    goto exit;

  /* u2 = (r * w) mod q */
  status = VLONG_operatorModSignedVlongs(
    MOC_MOD(hwAccelCtx) t, DSA_Q(p_dsaDescr), &u2, ppVlongQueue);
  if (OK != status)
    goto exit;

  /* v1 = g^u1 mod p */
  status = VLONG_modexp(
    MOC_MOD(hwAccelCtx) DSA_G(p_dsaDescr), u1, DSA_P(p_dsaDescr), &v1,
    ppVlongQueue);
  if (OK != status)
    goto exit;

  /* v2 = y^u2 mod p */
  status = VLONG_modexp(
    MOC_MOD(hwAccelCtx) DSA_Y(p_dsaDescr), u2, DSA_P(p_dsaDescr), &v2,
    ppVlongQueue);
  if (OK != status)
    goto exit;

  /* t = (g^u1 mod p) * (y^u2 mod p) */
  status = VLONG_vlongSignedMultiply(t, v1, v2);
  if (OK != status)
    goto exit;

  /* v3 = (g^u1 * y^u2) mod p */
  status = VLONG_operatorModSignedVlongs(
    MOC_MOD(hwAccelCtx) t, DSA_P(p_dsaDescr), &v3, ppVlongQueue);
  if (OK != status)
    goto exit;

  /* v = ((g^u1 * y^u2) mod p) mod q */
  status = VLONG_operatorModSignedVlongs(
    MOC_MOD(hwAccelCtx) v3, DSA_Q(p_dsaDescr), &v, ppVlongQueue);
  if (OK != status)
    goto exit;

  if (0 == VLONG_compareSignedVlongs(v, pR))
      *isGoodSignature = TRUE;


exit:

  VLONG_freeVlong(&w, ppVlongQueue);
  VLONG_freeVlong(&u1, ppVlongQueue);
  VLONG_freeVlong(&u2, ppVlongQueue);
  VLONG_freeVlong(&v, ppVlongQueue);
  VLONG_freeVlong(&v1, ppVlongQueue);
  VLONG_freeVlong(&v2, ppVlongQueue);
  VLONG_freeVlong(&v3, ppVlongQueue);
  VLONG_freeVlong(&t, ppVlongQueue);

  return status;

} /* DSA_verifySignatureSw */


/******************************************************************************/

MSTATUS DSA_verifySignature(
  MOC_DSA(hwAccelDescr hwAccelCtx)
  const DSAKey *pDsaKey,
  vlong *pVlongMsg,
  vlong *pR,
  vlong *pS,
  intBoolean *pVfySig,
  vlong **ppVlongQueue
  )
{
  MSTATUS status;
  ssp_err_t iret;

  dsa_instance_t *pDriver = NULL;

  ubyte4 *pDomain = NULL, *pKey = NULL, *pData = NULL, *pSig = NULL;
  ubyte4 domainLen = 0, keyLen = 0, dataWordLen, sigLen = 0, primeLenBits = 0,
         dataBitLen = 0;

  status = ERR_NULL_POINTER;
  if ( (NULL == pDsaKey) || (NULL == pVlongMsg) || (NULL == pR) ||
       (NULL == pS) || (NULL == pVfySig) )
    goto exit;

  primeLenBits = VLONG_bitLength (DSA_P(pDsaKey));

  /* If the length of 'p' is out of the supported range of the Renesas board,
   * just call the software implementation of this function. */
  if (3072 == primeLenBits)
    return DSA_verifySignatureSw (
      MOC_DSA (hwAccelCtx) pDsaKey, pVlongMsg, pR, pS, pVfySig, ppVlongQueue);

  status = ERR_INVALID_ARG;
  if ( (1024 != primeLenBits) && (2048 != primeLenBits) )
    goto exit;
  status = OK;

  status = ConvertDsaKeyToRenesasAlloc(
    (DSAKey *) pDsaKey, FALSE, &pDomain, &domainLen, &pKey, &keyLen);
  if (OK != status)
    goto exit;

  dataWordLen = (VLONG_bitLength(pVlongMsg) + 31) / 32;
  dataBitLen = dataWordLen * 32;

  /* Make sure the length of the prime matches up with it's corresponding
   * data length */
  status = ERR_INVALID_ARG;
  switch (primeLenBits)
  {
    case 1024:
      if (160 == dataBitLen)
      {
        pDriver = &g_sce_dsa_1024_160;
        break;
      }
      goto exit;

    case 2048:
      if (224 == dataBitLen)
      {
        pDriver = &g_sce_dsa_2048_224;
        break;
      }
      else if (256 == dataBitLen)
      {
        pDriver = &g_sce_dsa_2048_256;
        break;
      }

    default:
      goto exit;
  }
  status = OK;

  status = DIGI_MALLOC((void **) &pData, dataWordLen * 4);
  if (OK != status)
    goto exit;

  status = ConvertVlongToRenesas(pVlongMsg, pData, dataWordLen);
  if (OK != status)
    goto exit;

  status = ConvertDsaSigToRenesasAlloc(DSA_Q(pDsaKey), pR, pS, &pSig, &sigLen);
  if (OK != status)
    goto exit;

  /* Call driver to verify signature
   */
  if (NULL != pDriver)
  {
    iret = pDriver->p_api->hashVerify(
      pDriver->p_ctrl, pKey, pDomain, dataWordLen, pSig, pData);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_CRYPTO;
      *pVfySig = 0;
    }
    else
    {
      status = OK;
      *pVfySig = 1;
    }
  }
  else
  {
    status = ERR_NULL_POINTER;
  }

exit:

  if (NULL != pDomain)
  {
    DIGI_FREE ((void **)&pDomain);
  }
  if (NULL != pKey)
  {
    DIGI_MEMSET ((void *)pKey, 0, keyLen * 4);
    DIGI_FREE ((void **)&pKey);
  }
  if (NULL != pData)
  {
    DIGI_FREE((void **) &pData);
  }
  if (NULL != pSig)
  {
    DIGI_MEMSET((ubyte *) pSig, 0x00, sigLen * 4);
    DIGI_FREE((void **) &pSig);
  }

  return status;
}

#endif /* __DSA_HARDWARE_ACCELERATOR_VERIFY__ */


/******************************************************************************
 * RSA Implementation
 ******************************************************************************/

#if (defined (__RSAINT_HARDWARE__))

#ifndef MOCANA_MAX_BLIND_FACTOR_REUSE
#define MOCANA_MAX_BLIND_FACTOR_REUSE (32)
#endif

/* Helper function for RSAINT_decryptSw */
MSTATUS RSAINT_initBlindingFactors (
  MOC_MOD(hwAccelDescr hwAccelCtx)
  const RSAKey* pRSAKey,
  vlong** ppRE,
  vlong** ppR1,
  RNGFun rngFun,
  void* rngFunArg,
  vlong **ppVlongQueue
  )
{
  MSTATUS status;
  vlong*  pR = 0;
  ubyte4 rSize = RSA_N(pRSAKey)->numUnitsUsed-1;

  /* generate a random number < RSA_N(pRSAKey)  */
  if (OK > (status = VLONG_allocVlong( &pR, ppVlongQueue)))
    goto exit;

  /* DEBUG_RELABEL_MEMORY(pR); */

  if (OK > (status = VLONG_reallocVlong( pR, rSize)))
  {
    goto exit;
  }

  pR->numUnitsUsed = rSize;
  rngFun( rngFunArg,  rSize * sizeof(vlong_unit), (ubyte*) pR->pUnits);

  /* RE modular E exponent of R */
  if (OK > (status = VLONG_modexp(MOC_MOD(hwAccelCtx) pR, RSA_E(pRSAKey),
                                  RSA_N(pRSAKey), ppRE, ppVlongQueue)))
  {
    goto exit;
  }

  /* R1 = modular inverse of r */
  if (OK > (status = VLONG_modularInverse(MOC_MOD(hwAccelCtx) pR,
                                          RSA_N(pRSAKey), ppR1,
                                          ppVlongQueue)))
  {
    goto exit;
  }

exit:

  VLONG_freeVlong( &pR, ppVlongQueue);
  return status;
}


/******************************************************************************/

/* Software implementation of the RSAINT_decrypt function defined below.
 * Only gets called if keylen is out of the (1024 & 2048) range the Renesas
 * board supports. */
MSTATUS RSAINT_decryptSw (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  const RSAKey *pRSAKeyInt,
  const vlong *pCipher,
  RNGFun rngFun,
  void* rngFunArg,
  vlong **ppRetDecrypt,
  vlong **ppVlongQueue
  )
{
  vlong *product = NULL;
  vlong *blinded = NULL;
  vlong *savedR1 = NULL;
#ifndef __PSOS_RTOS__
  BlindingHelper *pBH;
#endif
  MSTATUS status;

  if (0 == rngFun) /* no blinding */
  {
    return RSAINT_decryptAux(MOC_RSA(hwAccelCtx) pRSAKeyInt,
                             pCipher, ppRetDecrypt, ppVlongQueue);
  }

  /* support for custom blinding implementation */
#if defined(CUSTOM_RSA_BLIND_FUNC)

  return CUSTOM_RSA_BLIND_FUNC(
    MOC_RSA(hwAccelCtx) pRSAKeyInt, pCipher, rngFun, rngFunArg,
    RSAINT_decryptAux, ppRetDecrypt, ppVlongQueue);

#else

#if !defined(__PSOS_RTOS__)

  /* to defeat constness warnings */
  pBH = (BlindingHelper *)&pRSAKeyInt->blinding;

  /* acquire the lock on the blinding factors */
  if (OK > (status = RTOS_mutexWait(pBH->blindingMutex)))
    goto exit;

  if (pBH->counter >= MOCANA_MAX_BLIND_FACTOR_REUSE)
  {
    VLONG_freeVlong(&pBH->pR1, ppVlongQueue);
    VLONG_freeVlong(&pBH->pRE, ppVlongQueue);
  }

  if (!pBH->pR1 || !pBH->pRE)
  {
    if (OK > (status = RSAINT_initBlindingFactors(MOC_MOD(hwAccelCtx) pRSAKeyInt,
                                                  &pBH->pRE, &pBH->pR1,
                                                  rngFun, rngFunArg,
                                                  ppVlongQueue)))
    {
      goto release_mutex;
    }
    /* reset the counter */
    pBH->counter = 0;
  }
  else
  {
    ++(pBH->counter); /* increment the counter */
  }

  if (OK > (status = VLONG_allocVlong(&product, ppVlongQueue)))
    goto release_mutex;

  /* DEBUG_RELABEL_MEMORY(product); */

  if (OK > (status = VLONG_vlongSignedMultiply(product, pBH->pRE, pCipher)))
    goto release_mutex;

  /* blinded is the blinded cipher text */
  if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) product,
                                                   RSA_N(pRSAKeyInt),
                                                   &blinded,
                                                   ppVlongQueue)))
  {
    goto release_mutex;
  }
  /* savedR1 is a copy of the blinding inverse os we can release the mutex early */
  if (OK > (status = VLONG_makeVlongFromVlong(pBH->pR1, &savedR1, ppVlongQueue)))
    goto release_mutex;

  /* square both blinding factors -- note that if it fails in the middle, the blinding
    factors will be out of sync and all decryption will fail after that !!! */
  if (OK > (VLONG_vlongSignedSquare(product, pBH->pRE)))
  {
    goto release_mutex;
  }

  VLONG_freeVlong(&pBH->pRE, ppVlongQueue);
  if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx) product,
                                                   RSA_N(pRSAKeyInt),
                                                   &pBH->pRE,
                                                   ppVlongQueue)))
  {
    goto release_mutex;
  }

  if (OK > (VLONG_vlongSignedSquare(product, pBH->pR1)))
  {
    goto release_mutex;
  }

  VLONG_freeVlong(&pBH->pR1, ppVlongQueue);
  if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx)
                                                       product,
                                                   RSA_N(pRSAKeyInt),
                                                   &pBH->pR1,
                                                   ppVlongQueue)))
  {
    goto release_mutex;
  }

release_mutex:
  RTOS_mutexRelease(pBH->blindingMutex);
  if (OK > status) /* there was an error i.e. we jumped to release_mutex */
  {
    goto exit;
  }

#else /* __PSOS_RTOS__ -> no mutex */

  if (OK > (status = RSAINT_initBlindingFactors(MOC_MOD(hwAccelCtx)
                                                    pRSAKeyInt,
                                                &blinded, &savedR1,
                                                rngFun, rngFunArg,
                                                ppVlongQueue)))
  {
    goto exit;
  }

  if (OK > (status = VLONG_allocVlong(&product, ppVlongQueue)))
    goto exit;

  if (OK > (status = VLONG_vlongSignedMultiply(product, blinded, pCipher)))
    goto exit;

  VLONG_freeVlong(&blinded, ppVlongQueue);
  /* blinded is now the blinded cipher text */
  if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx)
                                                       product,
                                                   RSA_N(pRSAKeyInt),
                                                   &blinded,
                                                   ppVlongQueue)))
  {
    goto exit;
  }

  /* product -> allocated, can be disposed of
        blinded is blinded cipher text
        savedR1 is inverse blinding factor */

#endif

  VLONG_freeVlong(&product, ppVlongQueue);
  /* call the normal routine */
  if (OK > (status = RSAINT_decryptAux(MOC_RSA(hwAccelCtx) pRSAKeyInt,
                                       blinded, &product, ppVlongQueue)))
  {
    goto exit;
  }

  /* unblind with savedR1 */
  if (OK > (status = VLONG_vlongSignedMultiply(blinded, product, savedR1)))
    goto exit;

  if (OK > (status = VLONG_operatorModSignedVlongs(MOC_MOD(hwAccelCtx)
                                                       blinded,
                                                   RSA_N(pRSAKeyInt),
                                                   ppRetDecrypt,
                                                   ppVlongQueue)))
  {
    goto exit;
  }


exit:

  VLONG_freeVlong(&product, ppVlongQueue);
  VLONG_freeVlong(&blinded, ppVlongQueue);
  VLONG_freeVlong(&savedR1, ppVlongQueue);

  return status;
#endif /* __CUSTOM_RSA_BLINDING__ */
} /* RSAINT_decryptSw */


/******************************************************************************/

MSTATUS RSAINT_decrypt (
  MOC_RSA (hwAccelDescr hwAccelCtx)
  const RSAKey *pRSAKey,
  const vlong *pCipher,
  RNGFun rngFun,
  void* rngFunArg,
  vlong **ppRetDecrypt,
  vlong **ppVlongQueue
  )
{
  MSTATUS status;
  ssp_err_t iret;
  sbyte4 cmpResult;

  ubyte4 keyArrayLen, elementLen, keyLenBits;
  ubyte4 *pKeyArray = NULL;
  ubyte4 *pCiphertext = NULL;
  ubyte4 *pDecryptedData = NULL;

  keyArrayLen = 0;

  rsa_instance_t *pDriver = NULL;

  status = ERR_RSA_KEY_NOT_READY;
  if ( (NULL == RSA_DP(pRSAKey)) || (NULL == RSA_DQ(pRSAKey)) ||
       (NULL == RSA_QINV(pRSAKey)) || (NULL == RSA_MODEXP_P(pRSAKey)) ||
       (NULL == RSA_MODEXP_Q(pRSAKey)) )
    goto exit;

  /* Verify that 0 < c < n
   * where c is the ciphertext and n is the modulus.
   */
  status = ERR_RSA_OUT_OF_RANGE;
  cmpResult = VLONG_compareUnsigned (pCipher, (vlong_unit)0);
  if (0 == cmpResult)
    goto exit;

  /* Compare left to right. If left < right, cmpResult < 0.
   */
  cmpResult = VLONG_compareSignedVlongs (pCipher, RSA_N (pRSAKey));
  if (cmpResult >= 0)
    goto exit;

  /* Get the keylen in bits so we can choose the appropriate driver */
  keyLenBits = RSA_KEYSIZE(pRSAKey);

  status = ERR_RSA_OUT_OF_RANGE;
  switch (keyLenBits)
  {
    case 1024:
      pDriver = &g_sce_rsa_1024;
      break;

    case 2048:
      pDriver = &g_sce_rsa_2048;
      break;

    default:
      /* The Renesas board only supports keysizes of 1024 and 2048, so call our
       * software implementation if the keysize is out-of-range */
      return RSAINT_decryptSw (
        MOC_RSA (hwAccelCtx) pRSAKey, pCipher, rngFun, rngFunArg, ppRetDecrypt,
        ppVlongQueue);
  }
  status = OK;

  status = ConvertPrivateRsaKeyToRenesasAlloc (
    (RSAKey *)pRSAKey, &pKeyArray, &keyArrayLen);
  if (OK != status)
    goto exit;

  /* We need to convert the data to decrypt as well. It is a vlong.
   * It must be the same size as the key.
   */
  elementLen = RSA_KEYSIZE (pRSAKey);
  elementLen = (elementLen + 31) / 32;
  status = DIGI_MALLOC ((void **)&pCiphertext, elementLen * 4);
  if (OK != status)
    goto exit;

  status = ConvertVlongToRenesas ((vlong *)pCipher, pCiphertext, elementLen);
  if (OK != status)
    goto exit;

  /* Malloc our buffer to hold the decrypted data */
  status = DIGI_MALLOC ((void **)&pDecryptedData, elementLen * 4);
  if (OK != status)
    goto exit;

  /* Start hardware decryption */
  iret = pDriver->p_api->decryptCrt(
    pDriver->p_ctrl, pKeyArray, NULL, elementLen, pCiphertext, pDecryptedData);
  if (SSP_SUCCESS != iret)
    return ERR_HARDWARE_ACCEL_DECRYPT_CRT;

  /* Allocate the vlong that will hold the decryped data */
  /* status = VLONG_allocVlong (&pVlngDecrypedData, ppVlongQueue);
  if (OK != status)
    goto exit; */

  status = ConvertRenesasToVlong (pDecryptedData, elementLen, ppRetDecrypt);


exit:

  if (NULL != pKeyArray)
  {
    DIGI_MEMSET ((void *)pKeyArray, 0, keyArrayLen * 4);
    DIGI_FREE ((void **)&pKeyArray);
  }
  if (NULL != pCiphertext)
  {
    DIGI_FREE ((void **)&pCiphertext);
  }
  if (NULL != pDecryptedData)
  {
	DIGI_FREE ((void **)&pDecryptedData);
  }

  /* VLONG_freeVlong (&m1, ppVlongQueue);
  VLONG_freeVlong (&m2, ppVlongQueue);
  VLONG_freeVlong (&h, ppVlongQueue);
  VLONG_freeVlong (&tmp, ppVlongQueue); */

  return (status);
}


/******************************************************************************/

MSTATUS RSA_RSASP1 (
  MOC_RSA (hwAccelDescr hwAccelCtx)
  const RSAKey *pRSAKey,
  const vlong *pMessage,
  RNGFun rngFun,
  void* rngFunArg,
  vlong **ppRetSignature,
  vlong **ppVlongQueue
  )
{
  MSTATUS status;

  status = RSAINT_decrypt (
    MOC_RSA(hwAccelCtx) pRSAKey, pMessage, rngFun, rngFunArg,
    ppRetSignature, ppVlongQueue);

  return (status);
}

#endif /* (defined (__RSAINT_HARDWARE__)) */


/******************************************************************************
 * Random number generation
 ******************************************************************************/

#if defined(__DISABLE_DIGICERT_RNG__)

/* This function will point the random context to a TRNG pointer that will
 * contain function pointers which can be used to make calls to the Synergy
 * TRNG.
 */
MSTATUS RANDOM_acquireContext(
  randomContext **ppRandCtx
  )
{
  *ppRandCtx = &g_sce_trng;

  return OK;
}

/******************************************************************************/

/* This will set the random context to NULL. The actual TRNG driver will be
 * closed when DIGICERT_freeDigicert is called.
 */
MSTATUS RANDOM_releaseContext(
  randomContext **ppRandCtx
  )
{
  *ppRandCtx = NULL;

  return OK;
}

/******************************************************************************/

/* This function will produce random bytes using the Synergy TRNG. The caller
 * should provide a randomContext. To get a random context call
 * RANDOM_acquireContext to get the Synergy context.
 */
MSTATUS RANDOM_numberGenerator(
  randomContext *pRandCtx,
  ubyte *pBuffer,
  sbyte4 bufSize
  )
{
  MSTATUS status;
  ssp_err_t iret;

  ubyte4 temp, leftover;
  trng_instance_t *pTrng = pRandCtx;

  /* Ensure the buffer is not NULL and the TRNG driver is available
   */
  status = ERR_NULL_POINTER;
  if ( (NULL == pTrng) || (NULL == pBuffer) )
    goto exit;

  /* If the buffer size is negative then return an error
   */
  status = ERR_INVALID_ARG;
  if (0 > bufSize)
    goto exit;

  /* If the caller requests for 0 bytes then return OK
   */
  status = OK;
  if (0 == bufSize)
    goto exit;

  /* The TRNG produces word arrays of random bytes, so the smallest amount of
   * random bytes that can be produced at any time is 1 word.
   */

  /* Calculate any leftover bytes
   */
  leftover = bufSize % 4;

  /* Fill in as many words as possible into the buffer
   */
  if (0 != (bufSize / 4) )
  {
    iret = pTrng->p_api->read(
      pTrng->p_ctrl, (uint32_t *) pBuffer, bufSize / 4);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_DO_RNG;
      goto exit;
    }
  }

  /* If any leftover bytes are required, then get a single random word and copy
   * leftover amount of bytes from the word into the buffer.
   */
  if (0 != leftover)
  {
    iret = pTrng->p_api->read(
      pTrng->p_ctrl, (uint32_t *) &temp, 1);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_READ_RANDOM;
      goto exit;
    }

    status = DIGI_MEMCPY(
      (void *) (pBuffer + bufSize - leftover), (void *) &temp, leftover);
    if (OK != status)
      goto exit;
  }

exit:

  temp = 0;

  return status;
}

/******************************************************************************/

/* Call the random number generator. This function will treat the RNG parameter
 * as a randomContext pointer and call RANDOM_numberGenerator.
 */
sbyte4 RANDOM_rngFun(
  void *pRngFunParam,
  ubyte4 length,
  ubyte *pBuffer
  )
{
  return ((sbyte4) RANDOM_numberGenerator(pRngFunParam, pBuffer, length));
}

/******************************************************************************/

/* The Synergy board provides a TRNG (Truly Random Number Generator) so there
 * is no need to add entropy.
 */
MSTATUS RANDOM_addEntropyBit(
  randomContext *pRandCtx,
  ubyte entropyBit
  )
{
  return OK;
}

/******************************************************************************/

MSTATUS RNG_SEED_initDepotState(void)
{
  return OK;
}

/******************************************************************************/

MSTATUS RNG_SEED_freeDepotState(void)
{
  return OK;
}

#endif /* __DISABLE_DIGICERT_RNG__ */

/******************************************************************************
 * Triple DES Implementation
 ******************************************************************************/

#ifdef __3DES_HARDWARE_CIPHER__

BulkCtx Create3DESCtx(
  hwAccelDescr pHwHandle,
  ubyte *pKey,
  sbyte4 keyLenBytes,
  sbyte4 cryptFlag
  )
{
  MSTATUS status;

  BulkCtx pRetCtx = NULL;
  MTDesSynergyCtx *pHwCtx = NULL;
  ubyte pad;

  status = ERR_NULL_POINTER;
  if (NULL == pKey)
    goto exit;

  status = ERR_3DES_BAD_KEY_LENGTH;
  if (THREE_DES_KEY_LENGTH != keyLenBytes)
    goto exit;

  status = DIGI_MALLOC((void **) &pHwCtx, sizeof(MTDesSynergyCtx));
  if (OK != status)
    goto exit;

  byteArrayToWordArray(
    pKey, (ubyte4 *) pHwCtx->pKey, THREE_DES_KEY_LENGTH, &pad);

  /* TODO: Set driver from synergy board here
   */
  pHwCtx->pDriver = &g_sce_tdes_cbc;
  pHwCtx->cryptFlag = cryptFlag;

  pRetCtx = pHwCtx;
  pHwCtx = NULL;

exit:

  if (NULL != pHwCtx)
  {
    DIGI_MEMSET((ubyte *) pHwCtx, 0x00, sizeof(MTDesSynergyCtx));
    DIGI_FREE((void **) &pHwCtx);
  }

  return pRetCtx;
}

MSTATUS Delete3DESCtx(
  hwAccelDescr pHwHandle,
  BulkCtx *ppCtx
  )
{
  MSTATUS status, fstatus;

  status = ERR_NULL_POINTER;
  if (NULL == ppCtx)
    goto exit;

  status = OK;
  if (NULL == *ppCtx)
    goto exit;

  fstatus = DIGI_MEMSET((ubyte *) *ppCtx, 0x00, sizeof(MTDesSynergyCtx));
  if (OK == status)
    status = fstatus;

  fstatus = DIGI_FREE((void **) ppCtx);
  if (OK == status)
    status = fstatus;

exit:

  return status;
}

/* Encrypt function for Triple DES provided by the Synergy board
 *
 * uint32_t encrypt(
 *   const tdes_ctrl_t *p_ctrl, const uint32_t *p_key, uint32_t *p_iv,
 *   uint32_t num_words, uint32_t *p_source, uint32_t *p_dest)
 *
 * p_ctrl - The Triple DES control. This value will be generated by the project.
 * p_key - The key value stored in a 6 word array (24 bytes)
 * p_iv - The IV value stored in a 2 word array (8 bytes)
 * num_words - The number of words that the input data consists of
 * p_source - The input data as a word array
 * p_dest - The output buffer. Must be as big as the source buffer. The value
 *   will be stored as a word array.
 *
 * Decrypt function for Triple DES provided by the Synergy board
 *
 * uint32_t decrypt(
 *   const tdes_ctrl_t *p_ctrl, const uint32_t *p_key, uint32_t *p_iv,
 *   uint32_t num_words, uint32_t *p_source, uint32_t *p_dest)
 *
 * p_ctrl - The Triple DES control. This value will be generated by the project.
 * p_key - The key value stored in a 6 word array (24 bytes)
 * p_iv - The IV value stored in a 2 word array (8 bytes)
 * num_words - The number of words that the input data consists of
 * p_source - The input data as a word array
 * p_dest - The output buffer. Must be as big as the source buffer. The value
 *   will be stored as a word array.
 *
 * This function will perform Triple DES in CBC mode
 */
MSTATUS Do3DES(
  hwAccelDescr pHwHandle,
  BulkCtx pCtx,
  ubyte *pData,
  sbyte4 dataLenBytes,
  sbyte4 cryptFlag,
  ubyte *pIv
  )
{
  MSTATUS status;
  ssp_err_t iret;

  MTDesSynergyCtx *pHwCtx = pCtx;

  status = ERR_NULL_POINTER;
  if ( (NULL == pHwCtx) || (NULL == pIv) )
    goto exit;

  status = ERR_INVALID_ARG;
  if (cryptFlag != pHwCtx->cryptFlag)
    goto exit;

  status = ERR_3DES_BAD_LENGTH;
  if ( 0 != (dataLenBytes % THREE_DES_BLOCK_SIZE) )
    goto exit;

#ifdef MOC_LITTLE_ENDIAN
  status = byteArrayToWordArrayInPlace(pData, dataLenBytes);
  if (OK != status)
    goto exit;

  status = byteArrayToWordArrayInPlace(pIv, THREE_DES_BLOCK_SIZE);
  if (OK != status)
    goto exit;
#endif

  /* Call the boards encrypt and decrypt functions
   */
  if (0 != cryptFlag)
  {
    iret = pHwCtx->pDriver->p_api->encrypt(
      pHwCtx->pDriver->p_ctrl, pHwCtx->pKey, pIv,
      dataLenBytes / 4, pData, pData);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_ENCRYPT;
      goto exit;
    }
  }
  else
  {
    iret = pHwCtx->pDriver->p_api->decrypt(
      pHwCtx->pDriver->p_ctrl, pHwCtx->pKey, pIv,
      dataLenBytes / 4, pData, pData);
    if (SSP_SUCCESS != iret)
    {
      status = ERR_HARDWARE_ACCEL_DECRYPT;
      goto exit;
    }
  }

#ifdef MOC_LITTLE_ENDIAN
  status = byteArrayToWordArrayInPlace(pData, dataLenBytes);
  if (OK != status)
    goto exit;

  status = byteArrayToWordArrayInPlace(pIv, THREE_DES_BLOCK_SIZE);
  if (OK != status)
    goto exit;
#endif

exit:

  return status;
}

#endif /* __3DES_HARDWARE_CIPHER__ */

#endif /* ( defined(__ENABLE_SYNERGY_3_HARDWARE_ACCEL__) ) etc */
