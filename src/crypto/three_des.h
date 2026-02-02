/*
 * three_des.h
 *
 * 3DES Header
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
@file       three_des.h

@brief      Header file for the NanoCrypto 3DES API.
@details    Header file for the NanoCrypto 3DES API.

*/

/*------------------------------------------------------------------*/

#ifndef __3DES_HEADER__
#define __3DES_HEADER__

#include "../cap/capdecl.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_tdes_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define THREE_DES_BLOCK_SIZE        (8)
#define THREE_DES_KEY_LENGTH        (24)


/*------------------------------------------------------------------*/

/* IMPORTANT: if the size of ctx3des is modified be sure to modify
   MOC_RAND_CTX_WRAPPER_STORAGE_SIZE appropriately in random.h
 */

typedef struct
{
    des_ctx firstKey;
    des_ctx secondKey;
    des_ctx thirdKey;
    MocSymCtx pMocSymCtx;
    ubyte4 enabled;
} ctx3des;

typedef struct
{
    ctx3des encryptKey;
    ctx3des decryptKey;
    MocSymCtx pMocSymCtx;
    ubyte4 initialized;
    ubyte4 enabled;
} DES3Ctx;


/*------------------------------------------------------------------*/

/**
 * @cond
 */

/* for white box testing */
MOC_EXTERN MSTATUS THREE_DES_initKey(ctx3des *p_3desContext, const ubyte *pKey, sbyte4 keyLen);
MOC_EXTERN MSTATUS THREE_DES_encipher(ctx3des *p_3desContext, ubyte *pSrc, ubyte *pDest, ubyte4 numBytes);
MOC_EXTERN MSTATUS THREE_DES_decipher(ctx3des *p_3desContext, ubyte *pSrc, ubyte *pDest, ubyte4 numBytes);
MOC_EXTERN MSTATUS THREE_DES_clearKey(ctx3des *p_3desContext);

/**
 * @endcond
 */

/* actual APIs */
#ifndef __DISABLE_3DES_CIPHERS__

/**
@brief      Get a new 3DES context data structure (for operations using three
            DES keys) and prepare the key schedule.

@details    This function creates and returns a context data structure for
            3DES operations that use three 3DES keys, and prepares the key
            schedule (intermediate key material). This is the first function
            your application calls when performing 3DES operations (encryption
            or decryption). Your application uses the returned structure in
            subsequent Do3DES() function calls.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_3des.jpg">3DES</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

The 3DES context is an opaque data structure that holds information such as DES
context and keys. To avoid memory leaks, your application code must call the
Delete3DESCtx function after completing 3DES-related operations (because the
3DES context is dynamically allocated by this function during context creation).

@warning    If \c NULL is returned for the context pointer, you cannot use it as
            input to any subsequent Do3DES() function calls.

@ingroup    three_des_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_3DES_CIPHERS__

@inc_file three_des.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
                      @todo_eng_review  But... what does the user specify? In
                      the 5.3.1 docs, we just said that this was "Reserved
                      for future use." Ditto this for all aes_ccm.{c,h}
                      functions.

@param  keyMaterial 3DES keys to use for encryption or decryption. Three
                      keys must be provided.
@param  keyLength   Total umber of bytes in the 3DES keys; must be a valid
                      3DES key length (expected value is 24 bytes total for
                      the three keys).
@param  encrypt     \c TRUE to prepare the key schedule for encryption;
                      \c FALSE to prepare the key schedule for decryption.

@return     \c NULL if any error; otherwise pointer to created 3DES context.

@funcdoc    three_des.h
*/
MOC_EXTERN BulkCtx Create3DESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt);

/**
@brief      Get a new 3DES context data structure (for operations using two
            DES keys) and prepare the key schedule.

@details    This function creates and returns a context data structure for
            3DES operations that use two 3DES keys, and prepares the key
            schedule (intermediate key material). This is the first function
            your application calls when performing 3DES operations (encryption
            or decryption). Your application uses the returned structure in
            subsequent Do3DES() function calls.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_3des.jpg">3DES</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

The 3DES context is an opaque data structure that holds information such as DES
context and keys. To avoid memory leaks, your application code must call the
Delete3DESCtx() function after completing 3DES-related operations (because the
3DES context is dynamically allocated by this function during context creation).

@warning    If \c NULL is returned for the context pointer, you cannot use it as
            input to any subsequent Do3DES() function calls.

@ingroup    three_des_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_3DES_CIPHERS__

@inc_file three_des.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param keyMaterial  3DES keys to use for encryption or decryption. Two keys
                      must be provided.
@param keyLength    Total number of bytes in the 3DES keys; must be a valid
                      3DES key length (expected value is 16 bytes total for
                      the two keys).
@param encrypt      \c TRUE to prepare the key schedule for encryption;
                      \c FALSE to prepare the key schedule for decryption.

@return     \c NULL if any error; otherwise pointer to created 3DES context.

@funcdoc    three_des.h
*/
MOC_EXTERN BulkCtx Create2Key3DESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt);

/**
 * @cond
 */
MOC_EXTERN MSTATUS Reset3DESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx);
/**
 * @endcond
 */

/**
@brief      Delete 3DES context data structure.

@details    This function deletes a 3DES context data structure previously
            created by Create3DESCtx() or Create2Key3DESCtx(). To avoid memory
            leaks, your application must call this function after completing
            3DES-related operations for a given context.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_3des.jpg">3DES</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    three_des_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_3DES_CIPHERS__

@inc_file three_des.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  ctx         Pointer to 3DES context to delete.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    three_des.h
*/
MOC_EXTERN MSTATUS Delete3DESCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx);

/**
@brief      3DES-encrypt or 3DES-decrypt a data buffer.

@details    This function 3DES-encrypts or 3DES-decrypts a data buffer in CBC
            mode. Before calling this function, your application must call
            the Create3DESCtx() or Create2Key3DESCtx() function to dynamically
            create a valid 3DES context.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_3des.jpg">3DES</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    three_des_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_3DES_CIPHERS__

@inc_file three_des.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  ctx         3DES context, previously created by Create3DESCtx() or
                      Create2Key3DESCtx().
@param  data        Data to be encrypted or decrypted.
@param dataLength   Number of bytes of data to be encrypted or decrypted
                      (\p data).
@param  encrypt     \c TRUE to encrypt the data; \c FALSE to decrypt the data.
@param  iv          Unique IV for the 3DES operation (encryption or decryption).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    three_des.h
*/
MOC_EXTERN MSTATUS Do3DES(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv);

/**
 * Clone a TDES context previously created with Create3DESCtx.
 *
 * @param pCtx     Pointer to a BulkCtx returned by Create3DESCtx.
 * @param ppNewCtx Double pointer to the BulkCtx to be created and populated with
 *                 the key data from the source key.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS Clone3DESCtx (MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx);

/**
 * @details This is the similar to Do3DES, except it will pad the data as well, using the
 * method outlined in PKCS #5. That calls for padding with the padLen bytes of
 * the byte padLen. That is, the pad is
 * <pre>
 * <code>
 *     01
 *     02 02
 *     03 03 03
 *      . . .
 *     07 07 07 07 07 07 07
 *     08 08 08 08 08 08 08 08
 * </code>
 * </pre>
 * <p>This processess all the data in one call, it does not process by parts.
 * <p>Note that P5 padding always pads. When encrypting, if the data length is
 * not a multiple of 8, it will pad to make sure the total length is a multiple
 * of 8. If the length is a multiple of 8, it will pad with 8 bytes. In this way,
 * when decrypting, there is always pad. The decryptor can know how many pad
 * bytes there are.
 * <p>If encrypting (the encrypt arg is TRUE), the output will be longer than the
 * input. Hence, we can't encrypt in place. That means you must supply the output
 * buffer. If you want to encrypt in place, make sure the buffer has at least 8
 * bytes beyond the end of dataLength, and pass the same buffer as the
 * processedData arg.
 * <p>You supply a buffer and its size. If the size is not big enough, the
 * function will set *pProcessedData to the size required and return
 * ERR_BUFFER_TOO_SMALL. But you can simply supply an output buffer to be 8 bytes
 * longer than the input when encrypting, and a buffer the same size as the input
 * buffer when decrypting.
 * <p>When decrypting, the actual size of output will be smaller than the input,
 * but the function can't know how many pad bytes will be stripped until it
 * decrypts. However, the function will not decrypt until it knows it has an
 * output buffer big enough. Hence, it will require a buffer that is big enough
 * to handle any possible pad size. For simplicity, the function will simply
 * require an output buffer the same size as the input.
 * <p>The decrypted data will be shorter than the encrypted data. The function
 * will decrypt the last block, strip the padding, and copy only the non-pad
 * bytes into the outpu buffer.
 * <p>When encrypting, the function will use the 8 bytes at iv to XOR with the
 * first block of plaintext before encrypting. It will then XOR the previous
 * block of ciphertext with each next block of plaintext before encrypting.
 * <p>Before calling this function, you must build a BulkCtx by calling
 * Create3DESCtx or Create2Key3DESCtx. Call Delete3DESCtx when done with the
 * BulkCtx.
 * <p>If encrypting, pass in 1 or TRUE for the encryptFlag arg. To decrypt, pass
 * in 0 or FALSE. Note that when you build the BulkCtx, you must specify whether
 * the ctx will be used for encrypting or decrypting.
 */
MOC_EXTERN MSTATUS Do3DesCbcWithPkcs5Pad (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx ctx,
  ubyte *pDataToProcess,
  ubyte4 dataLength,
  ubyte *pProcessedData,
  ubyte4 bufferSize,
  ubyte4 *pProcessedDataLen,
  sbyte4 encryptFlag,
  ubyte *pInitVector
  );
#endif

#ifdef __cplusplus
}
#endif

#endif /* __3DES_HEADER__ */
