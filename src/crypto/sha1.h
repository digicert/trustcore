/*
 * sha1.h
 *
 * SHA - Secure Hash Algorithm Header
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
@file       sha1.h

@brief      Header file for the Nanocrypto SHA1 API.

@details    Header file for the Nanocrypto SHA1 API.

For documentation for this file's functions, see sha1.c.
*/


/*------------------------------------------------------------------*/

#ifndef __SHA1_HEADER__
#define __SHA1_HEADER__

#include "../cap/capdecl.h"

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_sha1_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SHA_HASH_RESULT_SIZE    (20)
#define SHA_HASH_BLOCK_SIZE     (64)
/* conventions */
#define SHA1_RESULT_SIZE        (20)
#define SHA1_BLOCK_SIZE         (64)


/*------------------------------------------------------------------*/

typedef struct SW_SHA1_CTX
{
    MocSymCtx pMocSymCtx;
    ubyte4 enabled;
    ubyte4 hashId;

    ubyte4  hashBlocks[5];

    ubyte8  mesgLength;

    sbyte4  hashBufferIndex;
    ubyte   hashBuffer[SHA1_BLOCK_SIZE];

#ifdef __ENABLE_MOCANA_MINIMUM_STACK__
    ubyte4 W[80];
#endif

} SW_SHA1_CTX;

#ifndef __CUSTOM_SHA1_CONTEXT__
typedef struct SW_SHA1_CTX      shaDescr, shaDescrHS, SHA1_CTX;
#endif


/*------------------------------------------------------------------*/

/**
@brief      Allocate SHA1 operation context data structure.

@details    This function allocates a context data structure for SHA1
            operations.

Although applications can allocate the structure directly, it's recommended that
this function be used to ensure future portability.

@note       If you need a SHA1 value for only a single message, it is more
            efficient to call the SHA1_completeDigest() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha1.jpg">SHA1</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha1_functions

@inc_file sha1.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
                      @todo_eng_review  But... what does the user specify? In
                      the 5.3.1 docs, we just said that this was "Reserved
                      for future use." Ditto this for all sha1.{c,h}
                      functions.

@param  pp_context  On return, pointer to address of allocated context data
                      structure.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha1.c
*/
MOC_EXTERN MSTATUS SHA1_allocDigest   (MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context);

/**
@brief      Free (delete) SHA1 operation context data structure.

@details    This function frees (deletes) a SHA1 operation context data
            structure.

@note       If you need a SHA1 value for only a single message, it is more
            efficient to call the SHA1_completeDigest() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha1.jpg">SHA1</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha1_functions

@flags
There are no flag dependencies to enable this function.

@inc_file sha1.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pp_context  Pointer to address of context to free (delete).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha1.c
*/
MOC_EXTERN MSTATUS SHA1_freeDigest    (MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context);

/**
@brief      Initialize SHA1 operation context data structure.

@details    This function initializes an SHA1 context data structure.
            Applications should call this function \b before beginning the
            hashing operation.

@warning    Be sure to check this function's return status. An unsuccessful
            return will cause subsequent SHA1 operations to fail.

@note       If you need a SHA1 value for only a single message, it is more
            efficient to call the SHA1_completeDigest() function.

@note       Context pointers returned by the SHA1_allocDigest() function
            should be typecast to (<tt>shaDescr *</tt>) before calling this
            function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha1.jpg">SHA1</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha1_functions

@flags
There are no flag dependencies to enable this function.

@inc_file sha1.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  p_shaContext    Pointer to SHA1 context to initialize.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha1.c
*/
MOC_EXTERN MSTATUS SHA1_initDigest    (MOC_HASH(hwAccelDescr hwAccelCtx) shaDescr *p_shaContext);

/**
@brief      Calculate and update intermediate SHA1 digest value.

@details    This function calculates an intermediate SHA1 digest value.

Applications can repeatedly call this function to calculate digests for
different data items. Every time this function is called, the intermediate
digest value is stored within the SHA1 context data structure.

@note       If you need a SHA1 value for only a single message, it is more
            efficient to call the SHA1_completeDigest() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha1.jpg">SHA1</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha1_functions

@flags
There are no flag dependencies to enable this function.

@inc_file sha1.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  p_shaContext    Pointer to SHA1 context.
@param  pData           Pointer to data to hash or digest.
@param  dataLen         Number of bytes of data to hash or digest (\p pData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha1.c
*/
MOC_EXTERN MSTATUS SHA1_updateDigest  (MOC_HASH(hwAccelDescr hwAccelCtx) shaDescr *p_shaContext, const ubyte *pData, ubyte4 dataLen);

/**
@brief      Calculate final SHA1 digest value.

@details    This function calculates the final SHA1 digest value.
            Applications must call this function after completing their calls
            to SHA1_updateDigest().

@note       If you need a SHA1 value for only a single message, it is more
            efficient to call the SHA1_completeDigest() function.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha1.jpg">SHA1</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha1_functions

@flags
There are no flag dependencies to enable this function.

@warning    Before calling this function, be sure that the buffer pointed to
            by the \p pShaOutput parameter is large enough (at least
            SHA1_RESULT_SIZE(20) bytes); otherwise, buffer overflow will occur.

@inc_file sha1.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pContext    Pointer to SHA1 context.
@param  pOutput     On return, pointer to final SHA1 digest value. <b>(The
                      calling function must allocate sufficient
                      memory&mdash;at least SHA1_RESULT_SIZE(20)
                      bytes&mdash;for the resulting \p pShaOutput;
                      otherwise buffer overflow will occur.)</b>

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha1.c
*/
MOC_EXTERN MSTATUS SHA1_finalDigest   (MOC_HASH(hwAccelDescr hwAccelCtx) shaDescr *p_shaContext, ubyte *pShaOutput);

/**
@brief      Calculate single item's SHA1 digest value (with a single function
            call).

@details    This function calculates an SHA1 digest value for a single item.

@note       This function is the most efficient method to calculate the SHA1
            value for a single message, saving both memory and time. However,
            if you need to calculate the SHA1 for two or more messages, you
            must use the "separate steps" methods, SHA1_allocDigest(),
            SHA1_initDigest(), SHA1_updateDigest(), SHA1_finalDigest(), and
            SHA1_freeDigest().

@warning    Before calling this function, be sure that the buffer pointed to
            by the \p pShaOutput parameter is large enough (at least
            SHA1_RESULT_SIZE(20) bytes); otherwise, buffer overflow will occur.

<table class="moc_crypto_info">
  <tr><td>FIPS Approved</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Suite B Algorithm</td>
      <td>@image html x-red.gif ""
      @image latex x-red.png "" width=0.25in </td></tr>
  <tr><td>Flowchart</td>
      <td>@htmlonly <a href="images/nanocrypto/flowchart_sha1.jpg">SHA1</a>@endhtmlonly
          @latexonly
          {See \nameref{Flowcharts}.}
          @endlatexonly</td></tr>
</table>

@ingroup    sha1_functions

@flags
There are no flag dependencies to enable this function.

@inc_file sha1.h

@param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                      expands to an additional parameter, "hwAccelDescr
                      hwAccelCtx". Otherwise, this macro resolves to nothing.
@param  pData           Pointer to data to hash or digest.
@param  dataLen         Number of bytes of data to hash or digest (\p pData).
@param  pShaOutput      On return, pointer to resultant SHA1 digest value.
                          <b>(The calling function must allocate sufficient
                          memory&mdash;at least SHA1_RESULT_SIZE(20)
                          bytes&mdash;for the \p pShaOutput; otherwise buffer
                          overflow will occur.)</b>

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    sha1.c
*/
MOC_EXTERN MSTATUS SHA1_completeDigest(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput);

/**
 * @brief Makes a clone of a previously allocated \c SHA1_CTX.
 * @details Makes a clone of a previously allocated \c SHA1_CTX.
 *
 * @inc_file sha1.h
 *
 * @param pDest   Pointer to an already allocated destination context.
 * @param pSrc    Pointer to the context to be copied.
 *
 * @return           \c OK (0) if successful, otherwise a negative number
 *                   error code from merrors.h.
 */
MOC_EXTERN MSTATUS SHA1_cloneCtx(MOC_HASH(hwAccelDescr hwAccelCtx) shaDescr *pDest, shaDescr *pSrc);

/** @cond   Omit the following from Doxygen output. **/

#if (!(defined(__DISABLE_MOCANA_RNG__)))
/* G function used for FIPS 186 RNG change notice section 1 */
MOC_EXTERN MSTATUS SHA1_G(ubyte *pData, ubyte *pShaOutput);
/* G function used for FIPS 186 RNG change notice section 2 */
MOC_EXTERN MSTATUS SHA1_GK(ubyte *pData, ubyte *pShaOutput);
#endif

#ifdef __SHA1_HARDWARE_HASH__
MOC_EXTERN MSTATUS SHA1_initDigestHandShake    (MOC_HASH(hwAccelDescr hwAccelCtx) shaDescrHS *p_shaContext);
MOC_EXTERN MSTATUS SHA1_updateDigestHandShake  (MOC_HASH(hwAccelDescr hwAccelCtx) shaDescrHS*p_shaContext, const ubyte *pData, ubyte4 dataLen);
MOC_EXTERN MSTATUS SHA1_finalDigestHandShake   (MOC_HASH(hwAccelDescr hwAccelCtx) shaDescrHS *p_shaContext, ubyte *pShaOutput);

#else
#define SHA1_initDigestHandShake    SHA1_initDigest
#define SHA1_updateDigestHandShake  SHA1_updateDigest
#define SHA1_finalDigestHandShake   SHA1_finalDigest
#endif

/** @endcond **/

#ifdef __cplusplus
}
#endif

#endif /* __SHA1_HEADER__ */
