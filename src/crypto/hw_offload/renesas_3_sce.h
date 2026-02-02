/*
 * @file renesas_3_sce.h
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

#include "r_crypto_api.h"
#include "r_hash_api.h"
#include "r_aes_api.h"
#include "r_tdes_api.h"
#include "app_common.h"
#include "common/moptions.h"
#include "common/mtypes.h"
#include "common/mdefs.h"
#include "common/merrors.h"
#include "common/mrtos.h"
#include "common/random.h"
#include "common/vlong.h"
#include "common/mocana.h"
#include "crypto/hw_accel.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "crypto/aes.h"
#include "crypto/dsa.h"
#include "crypto/rsa.h"
#include "crypto/des.h"
#include "crypto/three_des.h"

#ifndef __RENESAS_SCE_3_HEADER__
#define __RENESAS_SCE_3_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#define ENCRYPT 1
#define DECRYPT 0


/*********************************************/
/*************** AES Class *******************/
/*********************************************/
typedef struct
{
  aes_instance_t *pCtx;
  ubyte4 mode;
  ubyte pKey[32];
  ubyte4 keyLen;
} MAesSynergyCtx;


extern MSTATUS byteArrayToWordArrayInPlace(
  ubyte *pSource,
  ubyte4 byteCount
  );

void byteArrayToWordArray(
  const ubyte* source,
  ubyte4* dest,
  ubyte4 byteCount,
  ubyte* pRetPaddedAdded
  );

/** Convert an RSA private key to a Renesas CRT key. The resulting key can be
 * used with the Renesas RSA function decryptCrt.
 * <p>The caller passes in a pointer to an RSAKey struct, the function extracts
 * the key data, allocates memory to hold the Renesas key, and converts the data.
 * It is the repsonsibility of the caller to free the resulting memory using
 * DIGI_FREE.
 * <p>If the key is not a private key, the function returns an error.
 * <p>This function will work with any key size, however, some Renesas devices
 * only support some RSA key sizes (e.g. some devices can only perform RSA with
 * 1024- or 2048-bit keys), so make sure you know how big the key is and whether
 * the device can do anything with it.
 * <p>The Renesas function decryptCrt takes in the private key as a uint32_t
 * array. It is defined as (expoQ || q || expoP || p || coeffQ). See page 1986 of
 * the Renesas Synergy Software Package v1.2.0-b.1 User's Manual.
 * <p>For a 1024-bit key, each of the 5 elements will be 16 words long (each
 * element is 1/2 the size of the modulus, so 512 bits divided into 32-bit words
 * is 16 words). The function will allocate an 16 * 5 ubyte4 array (total of 80
 * words, or 320 bytes), convert each of the RSA CRT elements into the
 * appropriate format and return the buffer. The result can be passed as the
 * p_key arg to decryptCrt.
 * <p>The function allocates memory, and also returns the array length. It will
 * deposit at the address given by pArrayLen the number of 32-bit words that make
 * up the result. Note it is the not the byte size of the buffer, but the count
 * of 32-bit words.
 *
 * @param pRsaKey The private key to convert.
 * @param ppArray The address where the function will deposit the allocated
 * 32-bit word array containing the converted key.
 * @param pArrayLen The address where the function will deposit the length of the
 * array.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MSTATUS ConvertPrivateRsaKeyToRenesasAlloc (
  RSAKey *pRsaKey,
  ubyte4 **ppArray,
  ubyte4 *pArrayLen
  );

/** Convert a DSA signature from Renesas into a pair of vlongs, the format the
 * Mocana DSA signature function returns the result.
 * <p>The Renesas accelerator returns a DSA signature as a single buffer. It is
 * the r and s values represented as 32-bit integer arrays. We are assuming the
 * result is (r || s), although it is not documented in the Synergy User's Manual.
 * <p>The signatureLen is the number of words in the signature. That means each
 * individual value (r and s) in the signature will be signatureLen / 2 words
 * long.
 * <p>This function will create two new vlongs, it is the responsibility of the
 * caller to free them using VLONG_freeVlong.
 *
 * @param pSignature The 32-bit int array containing the signature as returned by
 * a call to the Renesas accelerator.
 * @param signatureLen The number of 32-bit ints that make up the signature (this
 * is the length of the full signature, the length of r plus the length of s).
 * @param ppRVal The address where the function will deposit the created vlong
 * containing the signature's r value.
 * @param ppSVal The address where the function will deposit the created vlong
 * containing the signature's s value.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MSTATUS ConvertRenesasDsaSigToVlongs (
  ubyte4 *pSignature,
  ubyte4 signatureLen,
  vlong **ppRVal,
  vlong **ppSVal
  );

/** Convert a DSA signature into a format that the Renesas accelerator will be
 * able to use in order to verify.
 * <p>The Mocana API takes in a DSA signature as two vlongs, the r value and the
 * s value. The Renesas API requires the signature to be a single 32-bit integer
 * array. This function will convert the r and s values into a single array. It
 * will format the single buffer as (r || s). The Renesas documentation does not
 * specify how the signature is formatted, but r || s is the standard order.
 * <p>This function will allocate the new buffer (the 32-bit int array), it is
 * the responsibility of the caller to free that buffer using DIGI_free.
 * <p>The function also returns the length of the array. This length is the
 * number of 32-bit ints (it is not the size in bytes of the buffer).
 * <p>The first arg is the subprime, just to be extra safe. The length of the
 * signature must be 2 * subprime len. Although it is almost certain that the
 * RVal and SVal will each be the same size as the subprime, the actual value is
 * provided as an extra check to make sure the length of the result is correct.
 *
 * @param pSubprime The vlong containing the subprime, the function will use it
 * to get the length.
 * @param pRVal The Mocana format of the signature's r value.
 * @param pSVal The Mocana format of the signature's s value.
 * @param ppSignature The address where the function will deposit the converted
 * signature, the 32-bit int array.
 * @param pSigLen The address where the function will deposit the length of the
 * signature array. This is the number of 32-bit ints that make up the signature
 * (this is the length of the full signature, the length of r plus the length of
 * s).
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MSTATUS ConvertDsaSigToRenesasAlloc (
  vlong *pSubprime,
  vlong *pRVal,
  vlong *pSVal,
  ubyte4 **ppSignature,
  ubyte4 *pSigLen
  );


/** Convert a vlong into a Renesas uint32_t array.
 * <p>The caller supplies a vlong, along with a ubyte4 array buffer. The function
 * will set the buffer with the data from the vlong.
 * <p>A vlong contains the number as an array of vlong_units, with the least
 * significant word at index 0 and the most significant word at numUnitsUsed - 1.
 * A vlong_unit might be a 32-bit int, or it might be a 64-bit int. It could be a
 * 16- or even 8-bit int if that's the biggest int a device supports. However,
 * all platforms we support are have at least 32-bit integers. If a platform had
 * a 128-bit int, a vlong word could be that as well, but no platform we support
 * has one.
 * <p>The Renesas format is an array of 32-bit integers, with the most
 * significant word at index 0.
 * <p>The caller supplies a pointer to an allocated ubyte4 array, and the number
 * of entries. The function will determine if the array is big enough, and if so,
 * move the data into the array. If not, it will return an error. If the array is
 * longer than it needs to be, the function will prepend 0 words.
 * <p>Note that the arrayLen is the number of ubyte4 elements in the array, it is
 * not the size of the buffer in bytes.
 * <p>For example,
 * <pre>
 * <code>
 *   canonical int (hex):          11 12 13 14 21 22 23 24 31 32 33 34
 *   vlong (32-bit words):         0x31323334 0x21222324 0x11121314
 *   vlong (64-bit words):         0x2122232431323334 0x0000000011121314
 *   result buffer (arrayLen = 3): 0x11121314 0x21222324 0x31323334
 *   result buffer (arrayLen = 4): 0x00000000 0x11121314 0x21222324 0x31323334
 * </code>
 * </pre>
 * <p>NOTE! This function does limited arg checking, it is the responsibility of
 * the caller not to make mistakes.
 *
 * @param pValue The vlong to convert.
 * @param pArray the 32-bit word array buffer into which the result will be
 * placed.
 * @param arrayLen The length of the array.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MSTATUS ConvertVlongToRenesas (
  vlong *pValue,
  ubyte4 *pArray,
  ubyte4 arrayLen
  );

/** To convert a Renesas 32-bit int array into a vlong, call
 * VLONG_vlongFromUByte4String. If you want to use a function name that
 * specifically says RenesasToVlong, this macro will allow you to do so.
 * <p>The function returns MSTATUS.
 * <p>The function creates a new vlong and returns it at the address given.
 * <p>For example,
 * <pre>
 * <code>
 *     MSTATUS status;
 *     vlong *pResult = NULL;
 *
 *     status = ConvertRenesasToVlong (pArrayRenesas, arrayRenesasLen, &pResult);
 *     if (OK != status)
 *       goto exit;
 *
 *         . . .
 *
 *   exit:
 *
 *     if (NULL != pResult) {
 *       VLONG_freeVlong (&pResult, NULL);
 *     }
 *
 * </code>
 * </pre>
 * <p>Note that this takes in a ubyte4 array, not a canonical integer.
 */
#define ConvertRenesasToVlong(_pArray,_arrayLen,_ppVlong) \
    VLONG_vlongFromUByte4String (_pArray, _arrayLen, _ppVlong)


extern MSTATUS VLONG_modexp (
  MOC_MOD (hwAccelDescr hwAccelCtx)
  const vlong *x,
  const vlong *e,
  const vlong *n,
  vlong **ppRet,
  vlong **ppVlongQueue
  );

ssp_err_t ssp_crypto_initialize(crypto_word_endian_t endianMode);

ssp_err_t ssp_crypto_close (void);

extern sbyte4 SYNERGY_init(void);

extern sbyte4 SYNERGY_uninit(void);

/******************************************/
/**************** RSA HW ******************/
/******************************************/

#if ( defined(__ENABLE_SYNERGY_3_HARDWARE_ACCEL__) ) && \
    ( defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) )

extern MSTATUS RSAINT_decrypt (
  MOC_RSA (hwAccelDescr hwAccelCtx)
  const RSAKey *pRSAKey,
  const vlong *pCipher,
  RNGFun rngFun,
  void* rngFunArg,
  vlong **ppRetDecrypt,
  vlong **ppVlongQueue
  );

extern MSTATUS RSA_RSASP1 (
  MOC_RSA (hwAccelDescr hwAccelCtx)
  const RSAKey *pRSAKey,
  const vlong *pMessage,
  RNGFun rngFun,
  void* rngFunArg,
  vlong **ppRetSignature,
  vlong **ppVlongQueue
  );

extern MSTATUS RSAINT_decryptAux (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  const RSAKey *pRSAKey,
  const vlong *c,
  vlong **ppRetDecrypt,
  vlong **ppVlongQueue
  );

#endif

#ifdef __cplusplus
}
#endif

#endif
