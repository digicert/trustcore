/**
 * @file sha256.h
 *
 * @brief SHA - Secure Hash Algorithm Header
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

#ifndef __SHA256_HEADER__
#define __SHA256_HEADER__

#include "../cap/capdecl.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_sha224_priv.h"
#include "../crypto_interface/crypto_interface_sha256_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SHA256_CTX  MOC_SHA256_CTX

/** The size of the SHA256 digest output */
#define SHA256_RESULT_SIZE    (32)
#define SHA256_BLOCK_SIZE     (64)

/** The size of the SHA224 digest output */
#define SHA224_RESULT_SIZE    (28)
#define SHA224_BLOCK_SIZE     (64)

/*------------------------------------------------------------------*/

typedef struct SW_SHA256_CTX
{
    MocSymCtx pMocSymCtx;
    ubyte4 enabled;
    ubyte4 hashId;

    ubyte4  hashBlocks[8];

    ubyte8  mesgLength;

    sbyte4  hashBufferIndex;
    ubyte   hashBuffer[SHA256_BLOCK_SIZE];

#ifdef __ENABLE_DIGICERT_MINIMUM_STACK__
    ubyte4  W[64];
#endif

} SW_SHA256_CTX, SHA224_CTX;

#ifndef __CUSTOM_SHA256_CONTEXT__
typedef struct SW_SHA256_CTX      sha256Descr, sha256DescrHS, SHA256_CTX;
#endif

/*------------------------------------------------------------------*/

/* single steps */
#ifndef __DISABLE_DIGICERT_SHA256__

/**
@brief      Allocate SHA256 operation context data structure.
@details    This function allocates a context data structure for SHA256
            operations.

Although applications can allocate the structure directly, it's recommended that
this function be used to ensure future portability.

@note       If you need a SHA256 value for only a single message, it is more
            efficient to call the SHA256_completeDigest() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha256.jpg">SHA256</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha256_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA256__

@inc_file sha256.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
                      @todo_eng_review  But... what does the user specify? In
                      the 5.3.1 docs, we just said that this was "Reserved
                      for future use." Ditto this for all sha256.{c,h}
                      functions.

@param  pp_context  On return, pointer to allocated context data structure.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha256.h
*/
MOC_EXTERN MSTATUS SHA256_allocDigest   (MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_shaContext);

/**
@brief      Free (delete) SHA256 operation context data structure.

@details    This function frees (deletes) an SHA256 operation context data
            structure.

@note       If you need a SHA256 value for only a single message, it is more
            efficient to call the SHA256_completeDigest() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha256.jpg">SHA256</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha256_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA256__

@inc_file sha256.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pp_context  Pointer to context to free (delete). On return,
                          value is NULL.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha256.h
*/
MOC_EXTERN MSTATUS SHA256_freeDigest    (MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_shaContext);

/**
@brief      Initialize SHA256 operation context data structure.

@details    This function initializes an SHA256 context data structure.
            Applications should call this function \b before beginning the hashing operation.

@warning    Be sure to check this function's return status. An unsuccessful
            return will cause subsequent SHA256 operations to fail.

@note       If you need a SHA256 value for only a single message, it is more
            efficient to call the SHA256_completeDigest() function.

@note       Before calling this function, typecast the context pointers
            returned by the SHA256_allocDigest() function to (<tt>shaDescr
            *</tt>).

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha256.jpg">SHA256</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha256_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA256__

@inc_file sha256.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pContext    Pointer to SHA256 context to initialize.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha256.h
*/
MOC_EXTERN MSTATUS SHA256_initDigest    (MOC_HASH(hwAccelDescr hwAccelCtx) sha256Descr *pCtx);

/**
@brief      Calculate and update intermediate SHA256 digest value.

@details    This function calculates an intermediate SHA256 digest value.

Applications can repeatedly call this function to calculate digests for
different data items. Every time this function is called, the intermediate
digest value is stored within the SHA256 context data structure.

@note       If you need a SHA256 value for only a single message, it is more
            efficient to call the SHA256_completeDigest() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha256.jpg">SHA256</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha256_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA256__

@inc_file sha256.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pContext    Pointer to SHA256 context.
@param  pData       Pointer to data to be hashed or digested.
@param  dataLen     Number of bytes of data to be hashed or digested (\p pData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha256.h
*/
MOC_EXTERN MSTATUS SHA256_updateDigest  (MOC_HASH(hwAccelDescr hwAccelCtx) sha256Descr *pCtx, const ubyte *pData, ubyte4 dataLen);

/**
@brief      Calculate final SHA256 digest value.

@details    This function calculates the final SHA256 digest value.
            Applications must call this function after completing their calls to SHA256_updateDigest().

@note       If you need a SHA256 value for only a single message, it is more
            efficient to call the SHA256_completeDigest() function.

@warning    Before calling this function, be sure that the buffer pointed to
            by the \p pOutput parameter is large enough (at least
            SHA256_RESULT_SIZE(32) bytes); otherwise, buffer overflow will
            occur.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha256.jpg">SHA256</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha256_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA256__

@inc_file sha256.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pContext    Pointer to SHA256 context.
@param  pOutput     On return, pointer to final SHA256 digest value. <b>(The
                      calling function must allocate sufficient
                      memory&mdash;at least SHA256_RESULT_SIZE(32)
                      bytes&mdash;for the resulting \p pOutput; otherwise buffer
                      overflow will occur.)</b>

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha256.h
*/
MOC_EXTERN MSTATUS SHA256_finalDigest   (MOC_HASH(hwAccelDescr hwAccelCtx) sha256Descr *pCtx, ubyte *pOutput);

/**
@brief      Calculate single item's SHA256 digest value (with a single
            function call).

@details    This function calculates an SHA256 digest value for a single item.

@note       This function is the most efficient method to calculate the SHA256
            value for a single message, saving both memory and time. However,
            if you need to calculate the SHA256 for two or more messages, you
            must use the "separate steps" methods, SHA256_allocDigest(),
            SHA256_initDigest(), SHA256_updateDigest(), SHA256_finalDigest(),
            and SHA256_freeDigest().

@warning    Before calling this function, be sure that the buffer pointed to
            by the \p pShaOutput parameter is large enough (at least
            SHA256_RESULT_SIZE(32) bytes); otherwise, buffer overflow will
            occur.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha256.jpg">SHA256</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha256_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA256__

@inc_file sha256.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pData       Pointer to data to hash or digest.
@param  dataLen     Number of bytes of data to hash or digest (\p pData).
@param  pShaOutput  On return, pointer to resultant SHA256 digest value.
                      <b>(The calling function must allocate sufficient
                      memory&mdash;at least SHA256_RESULT_SIZE(32)
                      bytes&mdash;for the \p pShaOutput; otherwise buffer
                      overflow may occur.)</b>

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha256.h
*/
MOC_EXTERN MSTATUS SHA256_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput);

/**
 * @brief Makes a clone of a previously allocated \c SHA256_CTX.
 * @details Makes a clone of a previously allocated \c SHA256_CTX.
 *
 * @inc_file sha256.h
 *
 * @param pDest   Pointer to an already allocated destination context.
 * @param pSrc    Pointer to the context to be copied.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS SHA256_cloneCtx(MOC_HASH(hwAccelDescr hwAccelCtx) SHA256_CTX *pDest, SHA256_CTX *pSrc);

#endif /* __DISABLE_DIGICERT_SHA256__ */

/**
 * @cond
 */
#ifdef __SHA256_HARDWARE_HASH__
MOC_EXTERN MSTATUS SHA256_initDigestHandShake   (MOC_HASH(hwAccelDescr hwAccelCtx) sha256DescrHS *p_shaContext);
MOC_EXTERN MSTATUS SHA256_updateDigestHandShake (MOC_HASH(hwAccelDescr hwAccelCtx) sha256DescrHS *p_shaContext, const ubyte *pData, ubyte4 dataLen);
MOC_EXTERN MSTATUS SHA256_finalDigestHandShake  (MOC_HASH(hwAccelDescr hwAccelCtx) sha256DescrHS *p_shaContext, ubyte *pShaOutput);
#else
#define SHA256_initDigestHandShake      SHA256_initDigest
#define SHA256_updateDigestHandShake    SHA256_updateDigest
#define SHA256_finalDigestHandShake     SHA256_finalDigest
#endif /* __SHA256_HARDWARE_HASH__ */
/**
 * @endcond
 */

#ifndef __DISABLE_DIGICERT_SHA224__

/**
@brief      Allocate SHA224 operation context data structure.
@details    This function allocates a context data structure for SHA224
            operations.

Although applications can allocate the structure directly, it's recommended that
this function be used to ensure future portability.

@note       If you need a SHA224 value for only a single message, it is more
            efficient to call the SHA224_completeDigest() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha224.jpg">SHA224</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha224_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA224__

@inc_file sha256.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.

@param  pp_context  On return, pointer to allocated context data structure.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha256.h
*/
MOC_EXTERN MSTATUS SHA224_allocDigest   (MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_shaContext);

/**
@brief      Free (delete) SHA224 operation context data structure.

@details    This function frees (deletes) an SHA224 operation context data
            structure.

@note       If you need a SHA224 value for only a single message, it is more
            efficient to call the SHA224_completeDigest() function.

The sha512.h header file defines \c SHA224_freeDigest as:
<pre>    #define SHA224_freeDigest SHA256_freeDigest</pre>
Therefore, when you call SHA224_freeDigest(), you are actually making a
call to SHA256_freeDigest(). However, to keep your code more readable and
unambiguous when working with SHA224, you should use SHA224_freeDigest(),
not SHA256_freeDigest().

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/flowchart_sha224.jpg">SHA224</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha224_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA224__

@inc_file sha256.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pp_shaContext   Double pointer to context to free (delete). On return,
                          value is NULL.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha256.h
*/
MOC_EXTERN MSTATUS SHA224_freeDigest    (MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_shaContext);

/**
@brief      Calculate and update intermediate SHA224 digest value.

@details    This function calculates an intermediate SHA224 digest value.

Applications can repeatedly call this function to calculate digests for
different data items. Every time this function is called, the intermediate
digest value is stored within the SHA224 context data structure.

@note       If you need a SHA224 value for only a single message, it is more
            efficient to call the SHA224_completeDigest() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha256.jpg">SHA224</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha256_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA256__

@inc_file sha256.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pContext    Pointer to SHA224 context.
@param  pData       Pointer to data to be hashed or digested.
@param  dataLen     Number of bytes of data to be hashed or digested (\p pData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha256.h
*/
MOC_EXTERN MSTATUS SHA224_updateDigest  (MOC_HASH(hwAccelDescr hwAccelCtx) sha256Descr *pCtx, const ubyte *pData, ubyte4 dataLen);

/**
 * @cond
 * These are the real declarations, the SHA224 functions use the same SHA256
 * alloc, free, and update functions.  For the documentation on the SHA224 versions
 * of these functions, see the section above.
 */

MOC_EXTERN MSTATUS SHA256_allocDigest   (MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_shaContext);
MOC_EXTERN MSTATUS SHA256_freeDigest    (MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_shaContext);
MOC_EXTERN MSTATUS SHA256_updateDigest  (MOC_HASH(hwAccelDescr hwAccelCtx) SHA256_CTX *pCtx, const ubyte *pData, ubyte4 dataLen);
#define SHA224_allocDigest  SHA256_allocDigest
#define SHA224_freeDigest   SHA256_freeDigest
#define SHA224_updateDigest SHA256_updateDigest

/**
 * @endcond
 */

/**
@brief      Initialize an SHA224 operation context data structure.

@details    This function initializes an SHA224 operation context
            data structure. Applications should call this function \b before
            beginning the hashing operation.

The sha256.h header file defines \c SHA224_initDigest as:
<pre>    #define SHA224_initDigest SHA256_initDigest</pre>
Therefore, when you call SHA224_initDigest(), you are actually making a
call to SHA256_initDigest(). However, to keep your code more readable and
unambiguous when working with SHA224, you should use SHA224_initDigest(),
not SHA256_initDigest().

@warning    Be sure to check this function's return status. An unsuccessful
            return will cause subsequent SHA224 operations to fail.

@note       If you need a SHA224 value for only a single message, it is more
            efficient to call the SHA224_completeDigest() function.

@note       Context pointers returned by the SHA224_allocDigest() function
            should be typecast to (<tt>shaDescr *</tt>) before calling this
            function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha224.jpg">SHA224</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha224_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA224__

@inc_file sha256.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pContext    Pointer to SHA224 context to initialize.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha256.h
*/
MOC_EXTERN MSTATUS SHA224_initDigest    (MOC_HASH(hwAccelDescr hwAccelCtx) SHA224_CTX *pCtx);


/**
@brief      Calculate final SHA224 digest value.

@details    This function calculates the final SHA224 digest value.
            Applications must call this function after completing their calls
            to SHA224_updateDigest().

@note       If you need a SHA224 value for only a single message, it is more
            efficient to call the SHA224_completeDigest() function.

@warning    Before calling this function, be sure that the buffer pointed to
            by the \p pOutput parameter is large enough (at least
            SHA224_RESULT_SIZE(28) bytes); otherwise, buffer overflow will
            occur.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha224.jpg">SHA224</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha224_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA224__

@inc_file sha256.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pContext    Pointer to SHA224 context.
@param  pOutput     On return, pointer to final SHA224 digest value. <b>(The
                      calling function must allocate sufficient
                      memory&mdash;at least SHA224_RESULT_SIZE(28)
                      bytes&mdash;for the resulting \p pOutput; otherwise buffer
                      overflow will occur.)</b>

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha256.h
*/
MOC_EXTERN MSTATUS SHA224_finalDigest   (MOC_HASH(hwAccelDescr hwAccelCtx) SHA224_CTX *pCtx, ubyte *pOutput);

/**
@brief      Calculate single item's SHA224 digest value (with a single
            function call).

@details    This function calculates an SHA224 digest value for a single item.

@note       This function is the most efficient method to calculate the SHA224
            value for a single message, saving both memory and time. However,
            if you need to calculate the SHA224 for two or more messages, you
            must use the "separate steps" methods, SHA224_allocDigest(),
            SHA224_initDigest(), SHA224_updateDigest(), SHA224_finalDigest(),
            and SHA224_freeDigest().

@warning    Before calling this function, be sure that the buffer pointed to
            by the \p pShaOutput parameter is large enough (at least
            SHA224_RESULT_SIZE(28) bytes); otherwise, buffer overflow will
            occur.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html check-green.gif ""
          @image latex check-green.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha224.jpg">SHA224</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha224_functions

@flags
To enable this function, the following flag must \b not be defined:
+ \c \__DISABLE_DIGICERT_SHA224__

@inc_file sha256.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pData       Pointer to data to hash or digest.
@param  dataLen     Number of bytes of data to hash or digest (\p pData).
@param  pShaOutput  On return, pointer to resultant SHA224 digest value. <b>(The
                      calling function must allocate sufficient
                      memory&mdash;at least SHA224_RESULT_SIZE(28)
                      bytes&mdash;for the \p pShaOutput; otherwise buffer
                      overflow may occur.)</b>

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha256.h
*/
MOC_EXTERN MSTATUS SHA224_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput);

/**
 * @brief Makes a clone of a previously allocated \c SHA224_CTX.
 * @details Makes a clone of a previously allocated \c SHA224_CTX.
 *
 * @inc_file sha256.h
 *
 * @param pDest   Pointer to an already allocated destination context.
 * @param pSrc    Pointer to the context to be copied.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS SHA224_cloneCtx(MOC_HASH(hwAccelDescr hwAccelCtx) SHA224_CTX *pDest, SHA224_CTX *pSrc);

#endif /* ifndef __DISABLE_DIGICERT_SHA224__ */

#ifdef __cplusplus
}
#endif

#endif /* __SHA256_HEADER__ */
