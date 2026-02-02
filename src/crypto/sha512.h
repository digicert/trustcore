/**
 * @file sha512.h
 *
 * @brief SHA512 - Secure Hash Algorithm Header
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

#ifndef __SHA512_HEADER__
#define __SHA512_HEADER__

#include "../cap/capdecl.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_sha384_priv.h"
#include "../crypto_interface/crypto_interface_sha512_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SHA512_CTX  MOC_SHA512_CTX

#define SHA512_RESULT_SIZE    (64)
#define SHA512_BLOCK_SIZE     (128)

#define SHA384_RESULT_SIZE    (48)
#define SHA384_BLOCK_SIZE     (128)


/*------------------------------------------------------------------*/

typedef struct SHA512_CTX
{
    MocSymCtx pMocSymCtx;
    ubyte4 enabled;
    ubyte4 hashId;

    ubyte8  hashBlocks[8];

    ubyte16  msgLength;

    sbyte4  hashBufferIndex;
    ubyte   hashBuffer[SHA512_BLOCK_SIZE];

#ifdef __ENABLE_DIGICERT_MINIMUM_STACK__
    ubyte8  W[80];
#endif

} SHA512_CTX, SHA384_CTX;

typedef SHA512_CTX      sha384Descr;
typedef SHA512_CTX      sha512Descr;

/*------------------------------------------------------------------*/

/* single steps */
#ifndef __DISABLE_DIGICERT_SHA512__

/**
@brief      Allocate SHA512 operation context data structure.

@details    This function allocates a context data structure for SHA512
            operations.

Although applications can allocate the structure directly (stack or heap), it's
recommended that this function be used to ensure future portability.

@note       If you need a SHA512 value for only a single message, it is more
            efficient to call the SHA512_completeDigest() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha512.jpg">SHA512</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha512_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA512__

@inc_file sha512.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
                      @todo_eng_review  But... what does the user specify? In
                      the 5.3.1 docs, we just said that this was "Reserved
                      for future use." Ditto this for all sha512.{c,h}
                      functions.

@param  pp_context  On return, pointer to allocated context data structure.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha512.h
*/
MOC_EXTERN MSTATUS SHA512_allocDigest   (MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_shaContext);

/**
@brief      Free (delete) SHA512 operation context data structure.

@details    This function frees (deletes) an SHA512 operation context data
            structure.

@note       If you need a SHA512 value for only a single message, it is more
            efficient to call the SHA512_completeDigest() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha512.jpg">SHA512</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha512_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA512__

@inc_file sha512.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pp_context  Double pointer to context to free (delete). On return,
                       value is NULL.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha512.h
*/
MOC_EXTERN MSTATUS SHA512_freeDigest    (MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_shaContext);

/**
@brief      Initialize SHA512 operation context data structure.

@details    This function initializes an SHA512 context data structure.
            Applications should call this function \b before beginning the
            hashing operation.

@warning    Be sure to check this function's return status. An unsuccessful
            return will cause subsequent SHA512 operations to fail.

@note       If you need a SHA512 value for only a single message, it is more
            efficient to call the SHA512_completeDigest() function.

@note       Before calling this funciton, typecast the context pointers
            returned by the SHA512_allocDigest() function to (<tt>shaDescr
            *</tt>) before calling this function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha512.jpg">SHA512</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha512_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA512__

@inc_file sha512.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pContext    Pointer to SHA512 context to initialize.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha512.h
*/
MOC_EXTERN MSTATUS SHA512_initDigest    (MOC_HASH(hwAccelDescr hwAccelCtx) SHA512_CTX *pCtx);

/**
@brief      Calculate and update intermediate SHA512 digest value.

@details    This function calculates an intermediate SHA512 digest value.

Applications can repeatedly call this function to calculate digests for
different data items. Every time this function is called, the intermediate
digest value is stored within the SHA512 context data structure.

@note       If you need a SHA512 value for only a single message, it is more
            efficient to call the SHA512_completeDigest() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha512.jpg">SHA512</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha512_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA512__

@inc_file sha512.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pContext    Pointer to SHA512 context.
@param  pData       Pointer to data to hash or digest.
@param  dataLen     Number of bytes of data to hash or digest (\p pData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha512.h
*/
MOC_EXTERN MSTATUS SHA512_updateDigest  (MOC_HASH(hwAccelDescr hwAccelCtx) SHA512_CTX *pCtx, const ubyte *pData, ubyte4 dataLen);

/**
@brief      Calculate final SHA512 digest value.

@details    This function calculates the final SHA512 digest value.
            Applications must call this function after completing their calls
            to SHA512_updateDigest().

@note       If you need a SHA512 value for only a single message, it is more
            efficient to call the SHA512_completeDigest() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha512.jpg">SHA512</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha512_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA512__

@warning    Before calling this function, be sure that the buffer pointed to
            by the \p pOutput parameter is large enough (at least
            SHA512_RESULT_SIZE(64) bytes); otherwise, buffer overflow will
            occur.

@inc_file sha512.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pContext    Pointer to SHA512 context.
@param  pOutput     On return, pointer to final SHA512 digest value. <b>(The
                      calling function must allocate sufficient
                      memory&mdash;at least SHA512_RESULT_SIZE(64)
                      bytes&mdash;for the resulting \p pOutput; otherwise
                      buffer overflow will occur.)</b>

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha512.h
*/
MOC_EXTERN MSTATUS SHA512_finalDigest   (MOC_HASH(hwAccelDescr hwAccelCtx) SHA512_CTX *pCtx, ubyte *pOutput);

/**
@brief      Calculate single item's SHA512 digest value (with a single
            function call).

@details    This function calculates an SHA512 digest value for a single item.

@note       This function is the most efficient method to calculate the SHA512
            value for a single message, saving both memory and time. However,
            if you need to calculate the SHA512 for two or more messages, you
            must use the "separate steps" methods, SHA512_allocDigest(),
            SHA512_initDigest(), SHA512_updateDigest(), SHA512_finalDigest(),
            and SHA512_freeDigest().

@warning    Before calling this function, be sure that the buffer pointed to
            by the \p pShaOutput parameter is large enough (at least
            SHA512_RESULT_SIZE(64) bytes); otherwise, buffer overflow will
            occur.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha512.jpg">SHA512</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha512_functions

@flags
To enable this function, the following flags must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA512__
+ \c \__SHA512_ONE_STEP_HARDWARE_HASH__

@inc_file sha512.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pData       Pointer to data to hash or digest.
@param  dataLen     Number of bytes of data to hash or digest (\p pData).
@param  pShaOutput  On return, pointer to resultant SHA512 digest value.
                      <b>(The calling function must allocate sufficient
                      memory&mdash;at least SHA512_RESULT_SIZE(64)
                      bytes&mdash;for the \p pShaOutput; otherwise buffer
                      overflow may occur.)</b>

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha512.h
*/
MOC_EXTERN MSTATUS SHA512_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput);

/**
 * @brief Makes a clone of a previously allocated \c SHA512_CTX.
 * @details Makes a clone of a previously allocated \c SHA512_CTX.
 *
 * @inc_file sha512.h
 *
 * @param pDest   Pointer to an already allocated destination context.
 * @param pSrc    Pointer to the context to be copied.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS SHA512_cloneCtx(MOC_HASH(hwAccelDescr hwAccelCtx) SHA512_CTX *pDest, SHA512_CTX *pSrc);
#endif

#ifndef __DISABLE_DIGICERT_SHA384__

/**
@brief      Allocate SHA384 operation context data structure.
@details    This function allocates a context data structure for SHA384
            operations.

Although applications can allocate the structure directly, it's recommended that
this function be used to ensure future portability.

@note       If you need a SHA384 value for only a single message, it is more
            efficient to call the SHA384_completeDigest() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/flowchart_sha384.jpg">SHA384</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha384_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA384__

@inc_file sha512.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.

@param  pp_context  On return, pointer to allocated context data structure.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha512.h
*/
MOC_EXTERN MSTATUS SHA384_allocDigest   (MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_shaContext);

/**
@brief      Free (delete) SHA384 operation context data structure.

@details    This function frees (deletes) an SHA384 operation context data
            structure.

@note       If you need a SHA384 value for only a single message, it is more
            efficient to call the SHA384_completeDigest() function.

The sha512.h header file defines \c SHA384_freeDigest as:
<pre>    #define SHA384_freeDigest SHA512_freeDigest</pre>
Therefore, when you call SHA384_freeDigest(), you are actually making a
call to SHA512_freeDigest(). However, to keep your code more readable and
unambiguous when working with SHA384, you should use SHA384_freeDigest(),
not SHA512_freeDigest().

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/flowchart_sha384.jpg">SHA384</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha384_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA384__

@inc_file sha512.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pp_shaContext   Double pointer to context to free (delete). On return,
                          value is NULL.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha512.h
*/
MOC_EXTERN MSTATUS SHA384_freeDigest    (MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_shaContext);

/**
@brief      Calculate and update intermediate SHA384 digest value.

@details    This function calculates an intermediate SHA384 digest value.

Applications can repeatedly call this function to calculate digests for
different data items. Every time this function is called, the intermediate
digest value is stored within the SHA384 context data structure.

@note       If you need a SHA384 value for only a single message, it is more
            efficient to call the SHA384_completeDigest() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/flowchart_sha384.jpg">SHA384</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

The sha512.h header file defines \c SHA384_updateDigest as:
<pre>    #define SHA384_updateDigest SHA512_updateDigest</pre>
Therefore, when you call SHA384_updateDigest(), you are actually making a
call to SHA512_updateDigest(). However, to keep your code more readable and
unambiguous when working with SHA384, you should use SHA384_updateDigest(),
not SHA512_updateDigest().

@ingroup    sha384_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA384__

@inc_file sha512.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pCtx        Pointer to SHA384 context. @todo_eng_review How should this
                      pCtx param be explained given that the function
                      signature has it as a SHA512_CTX?

@param  pData       Pointer to data to hash or digest.
@param  dataLen     Number of bytes of data to hash or digest (\p pData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha512.h
*/
MOC_EXTERN MSTATUS SHA384_updateDigest  (MOC_HASH(hwAccelDescr hwAccelCtx) SHA512_CTX *pCtx, const ubyte *pData, ubyte4 dataLen);

/**
 * @cond
 * These are the real declarations, the SHA224 functions use the same SHA256
 * alloc, free, and update functions.  For the documentation on the SHA224 versions
 * of these functions, see the section above.
 */

MOC_EXTERN MSTATUS SHA512_allocDigest   (MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_shaContext);
MOC_EXTERN MSTATUS SHA512_freeDigest    (MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_shaContext);
MOC_EXTERN MSTATUS SHA512_updateDigest  (MOC_HASH(hwAccelDescr hwAccelCtx) SHA512_CTX *pCtx, const ubyte *pData, ubyte4 dataLen);
#define SHA384_allocDigest  SHA512_allocDigest
#define SHA384_freeDigest   SHA512_freeDigest
#define SHA384_updateDigest SHA512_updateDigest
/**
 * @endcond
 */

/**
@brief      Initialize SHA384 operation context data structure.

@details    This function initializes an SHA384 context data structure.
            Applications should call this function \b before beginning the
            hashing operation.

@warning    Be sure to check this function's return status. An unsuccessful
            return will cause subsequent SHA384 operations to fail.

@note       If you need a SHA384 value for only a single message, it is more
            efficient to call the SHA384_completeDigest() function.

@note       Before calling this funciton, typecast the context pointers
            returned by the SHA384_allocDigest() function to (<tt>shaDescr
            *</tt>) before calling this function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha384.jpg">SHA384</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha384_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA384__

@inc_file sha512.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pContext    Pointer to SHA384 context to initialize.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha512.h
*/
MOC_EXTERN MSTATUS SHA384_initDigest    (MOC_HASH(hwAccelDescr hwAccelCtx) SHA384_CTX *pCtx);

/**
@brief      Calculate final SHA384 digest value.

@details    This function calculates the final SHA384 digest value.
            Applications must call this function after completing their calls
            to SHA384_updateDigest().

@note       If you need a SHA384 value for only a single message, it is more
            efficient to call the SHA384_completeDigest() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha384.jpg">SHA384</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha384_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA384__

@warning    Before calling this function, be sure that the buffer pointed to
            by the \p pOutput parameter is large enough (at least
            SHA384_RESULT_SIZE(64) bytes); otherwise, buffer overflow will
            occur.

@inc_file sha512.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pContext    Pointer to SHA384 context.
@param  pOutput     On return, pointer to final SHA384 digest value. <b>(The
                      calling function must allocate sufficient
                      memory&mdash;at least SHA384_RESULT_SIZE(48)
                      bytes&mdash;for the resulting \p pOutput; otherwise
                      buffer overflow will occur.)</b>

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha512.h
*/
MOC_EXTERN MSTATUS SHA384_finalDigest   (MOC_HASH(hwAccelDescr hwAccelCtx) SHA384_CTX *pCtx, ubyte *pOutput);

/**
@brief      Calculate single item's SHA384 digest value (with a single
            function call).

@details    This function calculates an SHA384 digest value for a single item.

@note       This function is the most efficient method to calculate the SHA384
            value for a single message, saving both memory and time. However,
            if you need to calculate the SHA384 for two or more messages, you
            must use the "separate steps" methods, SHA384_allocDigest(),
            SHA384_initDigest(), SHA384_updateDigest(), SHA384_finalDigest(),
            and SHA384_freeDigest().

@warning    Before calling this function, be sure that the buffer pointed to
            by the \p pShaOutput parameter is large enough (at least
            SHA384_RESULT_SIZE(48) bytes); otherwise, buffer overflow will
            occur.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha384.jpg">SHA384</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha384_functions

@flags
To enable this function, the following flags must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA384__
+ \c \__SHA384_ONE_STEP_HARDWARE_HASH__

@inc_file sha512.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pData       Pointer to data to hash or digest.
@param  dataLen     Number of bytes of data to hash or digest (\p pData).
@param  pShaOutput  On return, pointer to resultant SHA384 digest value.
                      <b>(The calling function must allocate sufficient
                      memory&mdash;at least SHA384_RESULT_SIZE(48)
                      bytes&mdash;for the \p pShaOutput; otherwise buffer
                      overflow may occur.)</b>

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha512.h
*/
MOC_EXTERN MSTATUS SHA384_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput);

/**
 * @brief Makes a clone of a previously allocated \c SHA384_CTX.
 * @details Makes a clone of a previously allocated \c SHA384_CTX.
 *
 * @inc_file sha512.h
 *
 * @param pDest   Pointer to an already allocated destination context.
 * @param pSrc    Pointer to the context to be copied.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS SHA384_cloneCtx(MOC_HASH(hwAccelDescr hwAccelCtx) SHA384_CTX *pDest, SHA384_CTX *pSrc);
#endif

#ifdef __cplusplus
}
#endif

#endif /* __SHA512_HEADER__ */
