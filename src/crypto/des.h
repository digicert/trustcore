/*
 * des.h
 *
 * DES Header
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
@file       des.h

@brief      Header file for the NanoCrypto DES API.
@details    Header file for the NanoCrypto DES API.

*/


/*------------------------------------------------------------------*/

#ifndef __DES_HEADER__
#define __DES_HEADER__

#include "../cap/capdecl.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_des_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define DES_BLOCK_SIZE      (8)
#define DES_KEY_LENGTH      (8)


/*------------------------------------------------------------------*/

/* IMPORTANT: if the size of this context is modified be sure to modify
   MOC_RAND_CTX_WRAPPER_STORAGE_SIZE appropriately in random.h
 */

typedef struct
{
    ubyte4 ek[32];
    ubyte4 dk[32];
    MocSymCtx pMocSymCtx;
    ubyte4 initialized;
    ubyte4 enabled;

} des_ctx, DES_CTX;


/*------------------------------------------------------------------*/

/**
 * @cond
 */
MOC_EXTERN MSTATUS DES_initKey(des_ctx *p_desContext, const ubyte *pKey, sbyte4 keyLen);
MOC_EXTERN MSTATUS DES_encipher(des_ctx *p_desContext, ubyte *pSrc, ubyte *pDest, ubyte4 numBytes);
MOC_EXTERN MSTATUS DES_decipher(des_ctx *p_desContext, ubyte *pSrc, ubyte *pDest, ubyte4 numBytes);
MOC_EXTERN MSTATUS DES_clearKey(des_ctx *p_desContext);
/**
 * @endcond
 */

#ifdef __ENABLE_DES_CIPHER__
/**
@brief      Get a new DES context data structure (for operations using a
            DES key) and prepare the key schedule.

@details    This function creates and returns a context data structure for
            DES operations that use a DES key, and prepares the key schedule
            (intermediate key material). This is the first function your
            application calls when performing DES operations (encryption or
            decryption). Your application uses the returned structure in
            subsequent DoDES() function calls.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_des.jpg">DES</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

The DES context is an opaque data structure that holds information such as DES
context and key. To avoid memory leaks, your application code must call the
DeleteDESCtx() function after completing DES-related operations (because the DES
context is dynamically allocated by this function during context creation).

@warning    If \c NULL is returned for the context pointer, you cannot use it as
            input to any subsequent DoDES() function calls.

@ingroup    aes_des_functions

@flags
To enable this function, the following flag must be defined:
+ \c \__ENABLE_DES_CIPHER__

@inc_file des.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
                      @todo_eng_review  But... what does the user specify? In
                      the 5.3.1 docs, we just said that this was "Reserved
                      for future use." Ditto this for all aes_ccm.{c,h}
                      functions.

@param  keyMaterial DES key to use for encryption or decryption.
@param  keyLength   Number of bytes in the DES key; must be a valid DES key
                      length (expected value is 8 bytes).
@param  encrypt     \c TRUE to prepare the key schedule for encryption;
                      \c FALSE to prepare the key schedule for decryption.

@return     \c NULL if any error; otherwise pointer to created DES context.

@funcdoc    des.h
*/
MOC_EXTERN BulkCtx CreateDESCtx (MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt);

/**
@brief      Delete DES context data structure.

@details    This function deletes a DES context data structure previously
            created by CreateDESCtx(). To avoid memory leaks, your
            application must call this function after completing DES-related
            operations for a given context.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_des.jpg">DES</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    aes_des_functions

@flags
To enable this function, the following flag must be defined:
+ \c \__ENABLE_DES_CIPHER__

@inc_file des.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param ctx          Pointer to DES context to delete.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    des.h
*/
MOC_EXTERN MSTATUS DeleteDESCtx (MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx* ctx);

/**
@brief      DES-encrypt or DES-decrypt a data buffer.

@details    This function DES-encrypts or DES-decrypts a data buffer. Before
            calling this function, your application must call the
            CreateDESCtx() function to dynamically create a valid DES context.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_des.jpg">DES</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    aes_des_functions

@flags
To enable this function, the following flag must be defined:
+ \c \__ENABLE_DES_CIPHER__

@inc_file des.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  ctx         DES context, previously created by CreateDESCtx.
@param  data        Data to be encrypted or decrypted.
@param  dataLength  Number of bytes of data to be encrypted or decrypted
                      (\p data).
@param  encrypt      \c TRUE to encrypt the data; \c FALSE to decrypt the data.
@param  iv           Unique IV for the DES operation (encryption or decryption).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    des.h
*/
MOC_EXTERN MSTATUS DoDES        (MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv);

/**
 * Clone a TDES context previously created with CreateDESCtx.
 *
 * @param pCtx     Pointer to a BulkCtx returned by CreateDESCtx.
 * @param ppNewCtx Double pointer to the BulkCtx to be created and populated with
 *                 the key data from the source key.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CloneDESCtx (MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx);

#endif /* __ENABLE_DES_CIPHER__ */

#ifdef __cplusplus
}
#endif

#endif /* __DES_HEADER__ */
