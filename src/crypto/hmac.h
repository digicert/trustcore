/*
 * hmac.h
 *
 * Hash Message Authentication Code
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
@file       hmac.h

@brief      Header file for the Nanocrypto HMAC API.
@details    Header file for the Nanocrypto HMAC API.

*/


/*------------------------------------------------------------------*/

#ifndef __HMAC_H__
#define __HMAC_H__

#include "../cap/capdecl.h"

#if (defined(__ENABLE_MOCANA_CRYPTO_INTERFACE__))
#include "../crypto_interface/crypto_interface_hmac_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ENABLE_MOCANA_SHA3__)
#define HMAC_BLOCK_SIZE            (144) /* Maximum Hash Block Size = SHA3_224_BLOCK_SIZE */
#else
#if defined( __DISABLE_MOCANA_SHA512__) && defined(__DISABLE_MOCANA_SHA384__)
#define HMAC_BLOCK_SIZE            (64)  /* Maximum Hash Block Size = MD5_BLOCK_SIZE = SHA1_BLOCK_SIZE  = SHA256_BLOCK_SIZE */
#else
#define HMAC_BLOCK_SIZE            (128) /* Maximum Hash Block Size = SHA512_BLOCK_SIZE */
#endif
#endif /* __ENABLE_MOCANA_SHA3__ */

/*------------------------------------------------------------------*/

/**
@brief      Calculate (in a single call) the HMAC-MD5.

@details    This function calculates (in a single call) the HMAC-MD5, and
            returns it through the \p result parameter.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_hmac_md5_all.jpg">HMAC-MD5</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__HMAC_MD5_HARDWARE_HASH__

@warning    Before calling this function, be sure that the buffer used for the
            \p result parameter is at least MD5_DIGESTSIZE bytes; otherwise,
            buffer overflow may occur.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
                      @todo_eng_review  But... what does the user specify? In
                      the 5.3.1 docs, we just said that this was "Reserved
                      for future use." Ditto this for all hmac.{c,h} functions.

@param  key         Pointer to key for the HMAC-MD5 operation.
@param  keyLen      Number of bytes in the key (\p key).
@param  text        Pointer to input text for the MD5 operation.
@param  textLen     Number of bytes of input text (\p text).
@param  textOpt     Pointer to optional input text for the MD5 operation;
                      can be NULL.
@param  textOptLen  Number of bytes of optional input text; set to 0 if you
                      set \p textOpt to NULL.
@param  result      On return, buffer containing calculated MD5. <b>(The
                    calling function must allocate at least MD5_DIGESTSIZE
                    bytes for the \p result; otherwise buffer overflow may
                    occur.)</b>

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.h
*/
MOC_EXTERN MSTATUS
HMAC_MD5(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* key, sbyte4 keyLen, const ubyte* text,
            sbyte4 textLen, const ubyte* textOpt, sbyte4 textOptLen, ubyte result[MD5_DIGESTSIZE]);

/**
@brief      Calculate (in a single call) the HMAC-SHA1.

@details    This function calculates (in a single call) the HMAC-SHA1, and
            returns it through the \p result parameter.

@note       This function is the most efficient method to calculate the HMAC-SHA1
            for a single message, saving both memory and time. However, if you
            need to calculate the HMAC-SHA1 for two or more messages, you must
            use the "separate steps" methods, HmacCreate(), HmacKey(),
            HmacReset(), HmacUpdate(), HmacFinal(), and HmacDelete().

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>>
</table>

@ingroup    hmac_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__HMAC_SHA1_HARDWARE_HASH__

@warning    Before calling this function, be sure that the buffer used for the
            \p result parameter is at least SHA_HASH_RESULT_SIZE bytes;
            otherwise, buffer overflow may occur.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  key         Pointer to key for the HMAC-SHA1 operation.
@param  keyLen      Number of bytes in the key (\p key).
@param  text        Pointer to input text for the HMAC-SHA1 operation.
@param  textLen     Number of bytes of input text (\p text).
@param  textOpt     Pointer to optional input text for the HMAC-SHA1
                      operation; can be NULL.
@param  textOptLen  Number of bytes of optional input text; set to 0 if you
                      set \p textOpt to NULL.
@param  result      On return, buffer containing calculated HMAC-SHA1.
                      <b>(The calling function must allocate at least
                      SHA_HASH_RESULT_SIZE bytes for the \p result;
                      otherwise buffer overflow may occur.)</b>

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.h
*/
MOC_EXTERN MSTATUS
HMAC_SHA1(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* key, sbyte4 keyLen,
          const ubyte* text, sbyte4 textLen,
          const ubyte* textOpt, sbyte4 textOptLen, ubyte result[SHA_HASH_RESULT_SIZE]);

#ifndef __DISABLE_MOCANA_SHA256__
/**
@brief      Calculate (in a single call) the HMAC-SHA256.

@details    This function calculates (in a single call) the HMAC-SHA256, and
            returns it through the \p result parameter.

@note       This function is the most efficient method to calculate the HMAC-SHA256
            for a single message, saving both memory and time. However, if you
            need to calculate the HMAC-SHA256 for two or more messages, you must
            use the "separate steps" methods, HmacCreate(), HmacKey(),
            HmacReset(), HmacUpdate(), HmacFinal(), and HmacDelete().

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>>
</table>

@ingroup    hmac_functions

@flags
To enable this function, the following flag \b not must be defined:
+ \c \__DISABLE_MOCANA_SHA256__

@warning    Before calling this function, be sure that the buffer used for the
            \p result parameter is at least SHA256_RESULT_SIZE bytes;
            otherwise, buffer overflow may occur.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  key         Pointer to key for the HMAC-SHA256 operation.
@param  keyLen      Number of bytes in the key (\p key).
@param  text        Pointer to input text for the HMAC-SHA256 operation.
@param  textLen     Number of bytes of input text (\p text).
@param  textOpt     Pointer to optional input text for the HMAC-SHA256
                      operation; can be NULL.
@param  textOptLen  Number of bytes of optional input text; set to 0 if you
                      set \p textOpt to NULL.
@param  result      On return, buffer containing calculated HMAC-SHA256.
                      <b>(The calling function must allocate at least
                      SHA256_RESULT_SIZE bytes for the \p result;
                      otherwise buffer overflow may occur.)</b>

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.h
*/
MOC_EXTERN MSTATUS
HMAC_SHA256(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* key, sbyte4 keyLen,
          const ubyte* text, sbyte4 textLen,
          const ubyte* textOpt, sbyte4 textOptLen, ubyte result[SHA256_RESULT_SIZE]);

#endif /* ifndef __DISABLE_MOCANA_SHA256__ */

#ifndef __DISABLE_MOCANA_SHA512__
/**
@brief      Calculate (in a single call) the HMAC-SHA512.

@details    This function calculates (in a single call) the HMAC-SHA512, and
            returns it through the \p result parameter.

@note       This function is the most efficient method to calculate the HMAC-SHA512
            for a single message, saving both memory and time. However, if you
            need to calculate the HMAC-SHA512 for two or more messages, you must
            use the "separate steps" methods, HmacCreate(), HmacKey(),
            HmacReset(), HmacUpdate(), HmacFinal(), and HmacDelete().

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>>
</table>

@ingroup    hmac_functions

@flags
To enable this function, the following flag \b not must be defined:
+ \c \__DISABLE_MOCANA_SHA512__

@warning    Before calling this function, be sure that the buffer used for the
            \p result parameter is at least SHA512_RESULT_SIZE bytes;
            otherwise, buffer overflow may occur.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  key         Pointer to key for the HMAC-SHA512 operation.
@param  keyLen      Number of bytes in the key (\p key).
@param  text        Pointer to input text for the HMAC-SHA512 operation.
@param  textLen     Number of bytes of input text (\p text).
@param  textOpt     Pointer to optional input text for the HMAC-SHA512
                      operation; can be NULL.
@param  textOptLen  Number of bytes of optional input text; set to 0 if you
                      set \p textOpt to NULL.
@param  result      On return, buffer containing calculated HMAC-SHA512.
                      <b>(The calling function must allocate at least
                      SHA512_RESULT_SIZE bytes for the \p result;
                      otherwise buffer overflow may occur.)</b>

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.h
*/
MOC_EXTERN MSTATUS
HMAC_SHA512(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* key, sbyte4 keyLen,
          const ubyte* text, sbyte4 textLen,
          const ubyte* textOpt, sbyte4 textOptLen, ubyte result[SHA512_RESULT_SIZE]);

#endif /* ifndef __DISABLE_MOCANA_SHA512__ */

/**
@brief      Calculate (in a single call) the HMAC-SHA1 of multiple input buffers.

@details    This function calculates (in a single call) the HMAC-SHA1, and
            returns it through the \p result parameter.

@note       This function is the most efficient method to calculate the HMAC-SHA1
            for a single message, saving both memory and time. However, if you
            need to calculate the HMAC-SHA1 for two or more messages, you must
            use the "separate steps" methods, HmacCreate(), HmacKey(),
            HmacReset(), HmacUpdate(), HmacFinal(), and HmacDelete().

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>>
</table>

@ingroup    hmac_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__HMAC_SHA1_HARDWARE_HASH__

@warning    Before calling this function, be sure that the buffer used for the
            \p result parameter is at least SHA_HASH_RESULT_SIZE bytes;
            otherwise, buffer overflow may occur.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  key         Pointer to key for the HMAC-SHA1 operation.
@param  keyLen      Number of bytes in the key (\p key).
@param  texts       Array of input texts for the HMAC-SHA1 operation.
@param  textLens    Array of the number of bytes of each input text (\p text).
@param  numTexts    Number of input texts.
@param  result      On return, buffer containing calculated HMAC-SHA1.
                      <b>(The calling function must allocate at least
                      SHA_HASH_RESULT_SIZE bytes for the \p result;
                      otherwise buffer overflow may occur.)</b>

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.h
*/
MOC_EXTERN MSTATUS
HMAC_SHA1Ex(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* key, sbyte4 keyLen,
                    const ubyte* texts[], sbyte4 textLens[],
                     sbyte4 numTexts, ubyte result[SHA_HASH_RESULT_SIZE]);

/**
@brief      Calculate HMAC-MD5 (with a single function call).

@details    This function completely calculates an HMAC-MD5, with no need to
            call multiple, "separate steps" methods. The resultant HMAC value
            is returned through the \p result parameter.

@warning    Before calling this function, be sure that the buffer pointed to
            by the \p result parameter is large enough: at least equal to
            MD5_DIGESTSIZE. Otherwise, buffer overflow will occur.

@note       This function is the most efficient method to calculate the HMAC for
            a single message, saving both memory and time. However, if you
            need to calculate the HMAC-MD5 for two or more messages, you must
            use the "separate steps" methods, HmacCreate(), HmacKey(),
            HmacReset(), HmacUpdate(), HmacFinal(), and HmacDelete().

@note       To append optional (extended) input data, use the HmacQuickEx()
            function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/flowchart_hmac_md5_all.jpg">HMAC-MD5</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__HMAC_MD5_HARDWARE_HASH__

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pKey        Pointer to HMAC key to insert.
@param  keyLen      Number of bytes in HMAC key (\p pKey).
@param  pText       Pointer to input data.
@param  textLen     Number of bytes of input data (\p pText).
@param  pResult     On return, pointer to resultant HMAC-MD5 value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.h
*/
MOC_EXTERN MSTATUS HMAC_MD5_quick(MOC_HASH(hwAccelDescr hwAccelCtx)  const ubyte* pKey, sbyte4 keyLen,
                                  const ubyte* pText, sbyte4 textLen, ubyte* pResult /* MD5_DIGESTSIZE */);

/**
@brief      Calculate HMAC-SHA1 (with a single function call).

@details    This function completely calculates an HMAC-SHA1, with no need to
            call multiple, "separate steps" methods. The resultant HMAC value is
            returned through the \p result parameter.

@warning    Before calling this function, be sure that the buffer pointed to
            by the \p result parameter is large enough: at least equal to the
            output size of the underlying hash function (for example, 20 bytes
            for SHA1). Otherwise, buffer overflow will occur.

@note       This function is the most efficient method to calculate the HMAC for
            a single message, saving both memory and time. However, if you
            need to calculate the HMAC-MD5 for two or more messages, you must
            use the "separate steps" methods, HmacCreate(), HmacKey(),
            HmacReset(), HmacUpdate(), HmacFinal(), and HmacDelete().

@note       To append optional (extended) input data, use the HmacQuickEx()
            function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__HMAC_MD5_HARDWARE_HASH__

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pKey        Pointer to HMAC key to insert.
@param  keyLen      Number of bytes in HMAC key (\p pKey).
@param  pText       Pointer to input data.
@param  textLen     Number of bytes of input data (\p pText).
@param  pResult     On return, pointer to resultant HMAC-SHA1 value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.h
*/
MOC_EXTERN MSTATUS HMAC_SHA1_quick(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* pKey, sbyte4 keyLen,
                                   const ubyte* pText, sbyte4 textLen, ubyte* pResult /* SHA_HASH_RESULT_SIZE */);


/*------------------------------------------------------------------*/

/* HMAC context. */
struct HMAC_CTX
{
    const BulkHashAlgo* pBHAlgo;        /* external pointer, not a copy */
    BulkCtx             hashCtxt;

    ubyte4              keyLen;
    ubyte               key[HMAC_BLOCK_SIZE];
    ubyte               kpad[HMAC_BLOCK_SIZE];

    MocSymCtx pMocSymCtx;
    ubyte enabled;

};

typedef struct HMAC_CTX HMAC_CTX;
typedef struct HMAC_CTX _moc_HMAC_CTX;  /* Needed for openssl crypto engine */

/*------------------------------------------------------------------*/

/**
@brief      Create HMAC context.

@details    This function creates an HMAC context and initializes data
            structure fields (function pointers) related to the hash function
            to be used within HMAC operations.

To avoid memory leaks, your application code must call the HmacDelete()
function after HMAC-related operations (because the HMAC context is
dynamically allocated by this function during context creation).

@note       If you need an HMAC value for only a single message, it is more
            efficient to call the HmacQuick() function.

@warning    Be sure to check this function's return status. An unsuccessful
            return causes subsequent HMAC single-step operations to fail.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pctx        On return, pointer to resultant HMAC context.
@param  pBHAlgo     On return, pointer to collection of hash routines to be used
                      within HMAC.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.h
*/
MOC_EXTERN MSTATUS HmacCreate(MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX **pctx, const BulkHashAlgo *pBHAlgo);

/**
@brief      Insert and process HMAC context's key.

@details    This function inserts and processes an HMAC context's key. After
            calling this function, your application should call HmacUpdate().

@note       If you need an HMAC value for only a single message, it is more
            efficient to call the HmacQuick() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  ctx         Pointer to HMAC context.
@param  key         Pointer to HMAC key to insert.
@param  keyLen      Number of bytes in HMAC key (\p key).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.h
*/
MOC_EXTERN MSTATUS HmacKey(MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX *ctx, const ubyte *key, ubyte4 keyLen);

/**
@brief      Reset HMAC context.

@details    This function resets an HMAC context.

@note       If you need an HMAC value for only a single message, it is more
            efficient to call the HmacQuick() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  ctx         Pointer to HMAC context.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.h
*/
MOC_EXTERN MSTATUS HmacReset(MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX *ctx);

/**
@brief      Update intermediate HMAC value.

@details    This function updates the intermediate HMAC value in an HMAC
            context. Applications can repeatedly call this function to
            calculate an HMAC for different data items.

@note       If you need an HMAC value for only a single message, it is more
            efficient to call the HmacQuick() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  ctx         Pointer to HMAC context.
@param  text        Pointer to input data.
@param  textLen     Number of bytes of input data (\p text).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.h
*/
MOC_EXTERN MSTATUS HmacUpdate(MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX *ctx, const ubyte *data, ubyte4 dataLen);

/**
@brief      Get final HMAC value.

@details    This function calculates a final HMAC value, and returns it
            through the \p result parameter.

@warning    Before calling this function, be sure that the buffer pointed to
            by the \p result parameter is large enough: at least equal to the
            output size of the underlying hash function (for example, 20 bytes
            for SHA1). Otherwise, buffer overflow will occur.

@note       If you need an HMAC value for only a single message, it is more
            efficient to call the HmacQuick() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  ctx         Pointer to HMAC context.
@param  result      On return, pointer to resultant HMAC value. <b>(The
                    calling function must allocate sufficient memory for the
                    result: at least equal to the output size of the
                    underlying hash function&mdash;for example, 20 bytes for
                    SHA1. Otherwise buffer overflow will occur.)</b>

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.h
*/
MOC_EXTERN MSTATUS HmacFinal(MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX *ctx, ubyte *result);

/**
@brief      Delete (free) HMAC context.

@details    This function deletes (frees) an HMAC context. Your application
            should call this function as soon as it is done using an HMAC
            context created by HmacCreate().

@note       If you need an HMAC value for only a single message, it is more
            efficient to call the HmacQuick() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pctx        Pointer to HMAC context to delete.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.h
*/
MOC_EXTERN MSTATUS HmacDelete(MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX **pctx);

/**
@brief      Calculate HMAC (with a single function call).

@details    This function completely calculates an HMAC, with no need to call
            multiple, "separate steps" methods. Before calling this function,
            allocate and assign the desired algorithm values to the \p pBHAlgo
            parameter. (Using values for SHA1 is the equivalent to calling the
            HMAC_SHA1() function.) The resultant HMAC value is returned through
            the \p pResult parameter.

@warning    Before calling this function, be sure that the buffer pointed to
            by the \p result parameter is large enough: at least equal to the
            output size of the underlying hash function (for example, 20 bytes
            for SHA1). Otherwise, buffer overflow will occur.

@note       This function is the most efficient method to calculate the HMAC for
            a single message without using a pre-existing context, saving both
            memory and time. However, if you need to calculate the HMAC-MD5 for
            two or more messages, you must use the "separate steps" methods,
            HmacCreate(), HmacKey(), HmacReset(), HmacUpdate(), HmacFinal(),
            and HmacDelete().

@note       To append optional (extended) input data, use the HmacQuickEx()
            function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_hmac_md5_all.jpg">HMAC-MD5</a>, <a href="images/nanocrypto/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pKey        Pointer to HMAC key to insert.
@param  keyLen      Number of bytes in HMAC key (\p pKey).
@param  pText       Pointer to input data.
@param  textLen     Number of bytes of input data (\p pText).
@param  pResult     On return, pointer to resultant HMAC value. <b>(The
                      calling function must allocate sufficient memory for the
                      result: at least equal to the output size of the
                      underlying hash function&mdash;for example, 20 bytes for
                      SHA1. Otherwise buffer overflow will occur.)</b>
@param  pBHAlgo     Pointer to collection of hash routines used within HMAC.
                      (Refer to crypto.h for the structure definition.)

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.h
*/
MOC_EXTERN MSTATUS HmacQuick(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* pKey, sbyte4 keyLen,
                             const ubyte* pText, sbyte4 textLen,
                             ubyte* pResult, const BulkHashAlgo *pBHAlgo);

/**
@brief      Calculate HMAC using an existing context (with a single function call).

@details    This function completely calculates an HMAC, with no need to call
            multiple, "separate steps" methods. Before calling this function,
            allocate and assign the desired algorithm values to the \p pBHAlgo
            parameter. (Using values for SHA1 is the equivalent to calling the
            HMAC_SHA1() function.) The resultant HMAC value is returned through
            the \p pResult parameter.

@warning    Before calling this function, be sure that the buffer pointed to
            by the \p result parameter is large enough: at least equal to the
            output size of the underlying hash function (for example, 20 bytes
            for SHA1). Otherwise, buffer overflow will occur.

@note       This function is the most efficient method to calculate the HMAC for
            a single message, saving both memory and time. However, if you
            need to calculate the HMAC-MD5 for two or more messages, you must
            use the "separate steps" methods, HmacCreate(), HmacKey(),
            HmacReset(), HmacUpdate(), HmacFinal(), and HmacDelete().

@note       To append optional (extended) input data, use the HmacQuickEx()
            function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_hmac_md5_all.jpg">HMAC-MD5</a>, <a href="images/nanocrypto/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pKey        Pointer to HMAC key to insert.
@param  keyLen      Number of bytes in HMAC key (\p pKey).
@param  pText       Pointer to input data.
@param  textLen     Number of bytes of input data (\p pText).
@param  pResult     On return, pointer to resultant HMAC value. <b>(The
                      calling function must allocate sufficient memory for the
                      result: at least equal to the output size of the
                      underlying hash function&mdash;for example, 20 bytes for
                      SHA1. Otherwise buffer overflow will occur.)</b>
@param  pBHAlgo     Pointer to collection of hash routines used within HMAC.
                      (Refer to crypto.h for the structure definition.)
@param  ctx         Pointer to an existing HMAC context to use.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.h
*/
MOC_EXTERN MSTATUS HmacQuicker(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* pKey, sbyte4 keyLen,
                               const ubyte* pText, sbyte4 textLen,
                               ubyte* pResult, const BulkHashAlgo *pBHAlgo,
                               HMAC_CTX *ctx);

/**
@brief      Calculate HMAC (with a single function call) for a message with
            extended data.

@details    This function completely calculates an HMAC for a message with
            extended data, with no need to call multiple, "separate steps"
            methods. Before calling this function, allocate and assign the
            desired algorithm values to the \p pBHAlgo parameter. (Using
            values for SHA1 is the equivalent to calling the HMAC_SHA1()
            function.) The resultant HMAC value is returned through the \p
            pResult parameter.

@warning    Before calling this function, be sure that the buffer pointed to
            by the \p result parameter is large enough: at least equal to the
            output size of the underlying hash function (for example, 20 bytes
            for SHA1). Otherwise, buffer overflow will occur.

@note       This function is the most efficient method to calculate the HMAC for
            a single message, saving both memory and time. However, if you
            need to calculate the HMAC-MD5 for two or more messages, you must
            use the "separate steps" methods, HmacCreate(), HmacKey(),
            HmacReset(), HmacUpdate(), HmacFinal(), and HmacDelete().

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_hmac_md5_all.jpg">HMAC-MD5</a>, <a href="images/nanocrypto/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pKey        Pointer to HMAC key to insert.
@param  keyLen      Number of bytes in HMAC key (\p pKey).
@param  pText       Pointer to input data.
@param  textLen     Number of bytes of input data (\p pText).
@param  pOptText    Pointer to optional (extended) input data to append after
                      (\p pText); may be NULL to indicate none (which makes
                      this function equivalent to the HmacQuick() function).
@param  optTextLen  Number of bytes of optional input data (\p pOptText); may
                      be zero to indicate none.
@param  pResult     On return, pointer to resultant HMAC value. <b>(The
                      calling function must allocate sufficient memory for the
                      result: at least equal to the output size of the
                      underlying hash function&mdash;for example, 20 bytes for
                      SHA1. Otherwise buffer overflow will occur.)</b>
@param  pBHAlgo     Pointer to collection of hash routines used within HMAC.
                      (Refer to crypto.h for the structure definition.)

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.h
*/
MOC_EXTERN MSTATUS HmacQuickEx(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* pKey, sbyte4 keyLen,
                               const ubyte* pText, sbyte4 textLen,
                               const ubyte* pOptText, ubyte4 optTextLen,
                               ubyte* pResult, const BulkHashAlgo *pBHAlgo);

/**
@brief      Calculate HMAC using an existing context (with a single function call)
            for a message with extended data.

@details    This function completely calculates an HMAC for a message with
            extended data, with no need to call multiple, "separate steps"
            methods. Before calling this function, allocate and assign the
            desired algorithm values to the \p pBHAlgo parameter. (Using
            values for SHA1 is the equivalent to calling the HMAC_SHA1()
            function.) The resultant HMAC value is returned through the \p
            pResult parameter.

@warning    Before calling this function, be sure that the buffer pointed to
            by the \p result parameter is large enough: at least equal to the
            output size of the underlying hash function (for example, 20 bytes
            for SHA1). Otherwise, buffer overflow will occur.

@note       This function is the most efficient method to calculate the HMAC for
            a single message with extended data, saving both memory and time.
            However, if you need to calculate the HMAC-MD5 for two or more
            messages, you must use the "separate steps" methods, HmacCreate(),
            HmacKey(), HmacReset(), HmacUpdate(), HmacFinal(), and HmacDelete().

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_hmac_md5_all.jpg">HMAC-MD5</a>, <a href="images/nanocrypto/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pKey        Pointer to HMAC key to insert.
@param  keyLen      Number of bytes in HMAC key (\p pKey).
@param  pText       Pointer to input data.
@param  textLen     Number of bytes of input data (\p pText).
@param  pOptText    Pointer to optional (extended) input data to append after
                      (\p pText); may be NULL to indicate none (which makes
                      this function equivalent to the HmacQuick() function).
@param  optTextLen  Number of bytes of optional input data (\p pOptText); may
                      be zero to indicate none.
@param  pResult     On return, pointer to resultant HMAC value. <b>(The
                      calling function must allocate sufficient memory for the
                      result: at least equal to the output size of the
                      underlying hash function&mdash;for example, 20 bytes for
                      SHA1. Otherwise buffer overflow will occur.)</b>
@param  pBHAlgo     Pointer to collection of hash routines used within HMAC.
                      (Refer to crypto.h for the structure definition.)
@param  ctx         Pointer to an existing HMAC context to use.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.h
*/
MOC_EXTERN MSTATUS HmacQuickerEx(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* pKey, sbyte4 keyLen,
                                 const ubyte* pText, sbyte4 textLen,
                                 const ubyte* pOptText, ubyte4 optTextLen,
                                 ubyte* pResult, const BulkHashAlgo *pBHAlgo,
                                 HMAC_CTX *ctx);

/**
@brief      Calculate HMAC using an existing hash context (with a single function call).
            This function is unique in that it does not call any other Hmac* functions,
            but instead performs the entire computation inline calling only to the
            underlying hash function.

@details    This function completely calculates an HMAC, with no need to call
            multiple, "separate steps" methods. Before calling this function,
            allocate and assign the desired algorithm values to the \p pBHAlgo
            parameter. (Using values for SHA1 is the equivalent to calling the
            HMAC_SHA1() function.) The resultant HMAC value is returned through
            the \p pResult parameter.

@warning    Before calling this function, be sure that the buffer pointed to
            by the \p result parameter is large enough: at least equal to the
            output size of the underlying hash function (for example, 20 bytes
            for SHA1). Otherwise, buffer overflow will occur.

@note       This function is the most efficient method to calculate the HMAC for
            a single message, saving both memory and time. However, if you
            need to calculate the HMAC-MD5 for two or more messages, you must
            use the "separate steps" methods, HmacCreate(), HmacKey(),
            HmacReset(), HmacUpdate(), HmacFinal(), and HmacDelete().

@note       To append optional (extended) input data, use the HmacQuickEx()
            function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_hmac_md5_all.jpg">HMAC-MD5</a>, <a href="images/nanocrypto/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pKey        Pointer to HMAC key to insert.
@param  keyLen      Number of bytes in HMAC key (\p pKey).
@param  pText       Pointer to input data.
@param  textLen     Number of bytes of input data (\p pText).
@param  pResult     On return, pointer to resultant HMAC value. <b>(The
                      calling function must allocate sufficient memory for the
                      result: at least equal to the output size of the
                      underlying hash function&mdash;for example, 20 bytes for
                      SHA1. Otherwise buffer overflow will occur.)</b>
@param  pBHAlgo     Pointer to collection of hash routines used within HMAC.
                      (Refer to crypto.h for the structure definition.)
@param  context     Pointer to an existing hash context to use.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.h
*/
MOC_EXTERN MSTATUS HmacQuickerInline(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* pKey, sbyte4 keyLen,
          	  	  	  	  	  	  	 const ubyte* pText, sbyte4 textLen,
          	  	  	  	  	  	  	 ubyte* pResult, const BulkHashAlgo *pBHAlgo,
          	  	  	  	  	  	  	 BulkCtx context);

/**
@brief      Calculate HMAC with extended data using an existing hash context
            (with a single function call). This function is unique in that it
            does not call any other Hmac* functions, but instead performs the
            entire computation inline calling only to the underlying hash function.

@details    This function completely calculates an HMAC, with no need to call
            multiple, "separate steps" methods. Before calling this function,
            allocate and assign the desired algorithm values to the \p pBHAlgo
            parameter. (Using values for SHA1 is the equivalent to calling the
            HMAC_SHA1() function.) The resultant HMAC value is returned through
            the \p pResult parameter.

@warning    Before calling this function, be sure that the buffer pointed to
            by the \p result parameter is large enough: at least equal to the
            output size of the underlying hash function (for example, 20 bytes
            for SHA1). Otherwise, buffer overflow will occur.

@note       This function is the most efficient method to calculate the HMAC for
            a single message, saving both memory and time. However, if you
            need to calculate the HMAC-MD5 for two or more messages, you must
            use the "separate steps" methods, HmacCreate(), HmacKey(),
            HmacReset(), HmacUpdate(), HmacFinal(), and HmacDelete().

@note       To append optional (extended) input data, use the HmacQuickEx()
            function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocryto/flowchart_hmac_md5_all.jpg">HMAC-MD5</a>, <a href="images/nanocryto/flowchart_hmac_sha_all.jpg">HMAC-SHA*</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    hmac_functions

@flags
There are no flag dependencies to enable this function.

@inc_file   hmac.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pKey        Pointer to HMAC key to insert.
@param  keyLen      Number of bytes in HMAC key (\p pKey).
@param  pText       Pointer to input data.
@param  textLen     Number of bytes of input data (\p pText).
@param  pOptText    Pointer to optional (extended) input data to append after
                      (\p pText); may be NULL to indicate none (which makes
                      this function equivalent to the HmacQuick() function).
@param  optTextLen  Number of bytes of optional input data (\p pOptText); may
                      be zero to indicate none.
@param  pResult     On return, pointer to resultant HMAC value. <b>(The
                      calling function must allocate sufficient memory for the
                      result: at least equal to the output size of the
                      underlying hash function&mdash;for example, 20 bytes for
                      SHA1. Otherwise buffer overflow will occur.)</b>
@param  pBHAlgo     Pointer to collection of hash routines used within HMAC.
                      (Refer to crypto.h for the structure definition.)
@param  context     Pointer to an existing hash context to use.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    hmac.h
*/
MOC_EXTERN MSTATUS HmacQuickerInlineEx(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* key, sbyte4 keyLen,
         	 	 	 	 	 	 	   const ubyte* text, sbyte4 textLen,
         	 	 	 	 	 	 	   const ubyte* textOpt, sbyte4 textOptLen,
         	 	 	 	 	 	 	   ubyte* pResult, const BulkHashAlgo *pBHAlgo,
         	 	 	 	 	 	 	   BulkCtx context);

#ifdef __cplusplus
}
#endif

#endif
