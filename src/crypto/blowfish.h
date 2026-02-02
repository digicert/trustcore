/*
 * blowfish.h
 *
 * Blowfish Header
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
@file       blowfish.h

@brief      Header file for the NanoCrypto Blowfish API.
@details    Header file for the NanoCrypto Blowfish API.

*/


/*------------------------------------------------------------------*/

#ifndef __BLOWFISH_HEADER__
#define __BLOWFISH_HEADER__

#include "../cap/capdecl.h"

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#include "../crypto_interface/crypto_interface_blowfish_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MAXKEYBYTES             (56)        /* 448 bits */
#define BLOWFISH_BLOCK_SIZE     (8)

typedef struct
{
    ubyte4 S[4][256], P[18];

    MocSymCtx pMocSymCtx;
    ubyte     enabled;
    ubyte     initialized;

} blf_ctx;

/*------------------------------------------------------------------*/

/**
@brief      Get a new Blowfish context data structure (for operations using a
            Blowfish key) and prepare the key schedule.

@details    This function creates and returns a context data structure for
            Blowfish operations, and prepares the key schedule (intermediate
            key material). This is the first function your application calls
            when performing Blowfish operations (encryption or decryption).
            Your application uses the returned structure in subsequent
            DoBlowfish() function calls.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_blowfish.jpg">Blowfish</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

The Blowfish context is an opaque data structure that holds information such as
Blowfish context and key. To avoid memory leaks, your application code must call
the DeleteBlowfishCtx() function after completing Blowfish operations (because
the Blowfish context is dynamically allocated by this function during context
creation).

@warning    If \c NULL is returned for the context pointer, you cannot use it as
            input to any subsequent DoBlowfish() function calls.

@ingroup    blowfish_functions

@flags
To enable this function, the following flag \b must be defined:
+ \c \__ENABLE_BLOWFISH_CIPHERS__

@inc_file blowfish.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
                      @todo_eng_review  But... what does the user specify? In
                      the 5.3.1 docs, we just said that this was "Reserved
                      for future use." Ditto this for all aes_ccm.{c,h}
                      functions.

@param  pKeyMaterial    Blowfish key to use for encryption or decryption.
@param  keyLength   Number of bytes in the Blowfish key; must be a valid
                      Blowfish key length (expected value is 16 bytes).
@param  encrypt     \c TRUE to prepare the key schedule for encryption;
                      \c FALSE to prepare the key schedule for decryption.

@return     \c NULL if any error; otherwise pointer to created Blowfish context.

@funcdoc    blowfish.h
*/
MOC_EXTERN BulkCtx CreateBlowfishCtx(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt);

/**
@brief      Delete Blowfish context data structure.

@details    This function deletes a Blowfish context data structure previously
            created by CreateBlowfishCtx(). To avoid memory leaks, your
            application must call this function after completing
            Blowfish-related operations for a given context.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_blowfish.jpg">Blowfish</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    blowfish_functions

@flags
To enable this function, the following flag \b must be defined:
+ \c \__ENABLE_BLOWFISH_CIPHERS__

@inc_file blowfish.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  ctx         Pointer to Blowfish context to delete.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    blowfish.h
*/
MOC_EXTERN MSTATUS DeleteBlowfishCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx* ctx);

/**
@brief      Blowfish-encrypt or Blowfish-decrypt a data buffer.

@details    This function Blowfish-encrypts or Blowfish-decrypts a data buffer
            in CBC mode. Before calling this function, your application must
            call the CreateBlowfishCtx() function to dynamically create a
            valid Blowfish context.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_blowfish.jpg">Blowfish</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    blowfish_functions

@flags
To enable this function, the following flag \b must be defined:
+ \c \__ENABLE_BLOWFISH_CIPHERS__

@inc_file blowfish.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  ctx         Blowfish context, previously created by CreateBlowfishCtx().
@param  data        Data to encrypt or decrypt.
@param  dataLength  Number of bytes of data to encrypt or decrypt (\p data).
@param  encrypt     \c TRUE to encrypt the data; \c FALSE to decrypt the data.
@param  iv          Unique IV for the Blowfish operation (encryption or
                      decryption).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    blowfish.h
*/
MOC_EXTERN MSTATUS DoBlowfish(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv);


/**
@brief      Clones a Blowfish context.

@details    Clones a Blowfish context. Be sure to free the new contex with
            a call to \c DeleteBlowfishCtx.

@ingroup    blowfish_functions

@flags
To enable this function, the following flag \b must be defined:
+ \c \__ENABLE_BLOWFISH_CIPHERS__

@inc_file blowfish.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pCtx        Source Blowfish context.
@param  ppNewCtx    Will point to the newly allocated copy of the source context.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    blowfish.h
*/
MOC_EXTERN MSTATUS CloneBlowfishCtx(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx);

#ifdef __cplusplus
}
#endif

#endif /* __BLOWFISH_HEADER__ */
