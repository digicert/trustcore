/*
 * random.h
 *
 * Random Number FIPS-186 Factory
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

/**
 @file       random.h
 @brief      Random Number Generator (RNG) API header.

 @details    This file documents the definitions, enumerations, structures, and
             function of the Mocana Security of Things (SoT) Platform Random
             Number Generator.

 @flags
 Whether the following flag is defined determines which functions
 are declared:
 + \c \__DISABLE_MOCANA_ADD_ENTROPY__

 @filedoc    random.h
 */

/*------------------------------------------------------------------*/

#ifndef __RANDOM_HEADER__
#define __RANDOM_HEADER__

#include "../crypto/hw_accel.h"

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE_RANDOM__
#include "../crypto_interface/crypto_interface_random_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define RANDOM_CONTEXT(X)       (X)->pRandomContext

#ifdef MOC_EXTERN_RANDOM_H
#undef MOC_EXTERN_RANDOM_H
#endif /* MOC_EXTERN_RANDOM_H */

#ifdef __RTOS_WIN32__

#ifdef WIN_EXPORT_RANDOM_H
#define MOC_EXTERN_RANDOM_H __declspec(dllexport)
#else
#define MOC_EXTERN_RANDOM_H __declspec(dllimport) extern 
#endif /* WIN_EXPORT_RANDOM_H */

#ifdef WIN_STATIC
#undef MOC_EXTERN_RANDOM_H
#define MOC_EXTERN_RANDOM_H extern
#endif /* WIN_STATIC */

#else

#define MOC_EXTERN_RANDOM_H MOC_EXTERN

#endif /* RTOS_WIN32 */

#ifdef MOC_EXTERN_P
#undef MOC_EXTERN_P
#endif /* MOC_EXTERN_P */

#define MOC_EXTERN_P MOC_EXTERN_RANDOM_H

/*------------------------------------------------------------------*/

/**
@private
@internal
@todo_add_ask
*/
typedef void            randomContext;

/**
 * @brief       Function pointer type for a method that produces (pseudo) random bytes.
 *
 * @details     Function pointer type for a method that produces (pseudo) random bytes.
 *
 * @inc_file    random.h
 *
 * @param rngFunArg  Optional argument that may be needed by your implementation. Often
 *                   this will be a random context.
 * @param length     The number of bytes requested.
 * @param buffer     Buffer to hold the resuling output bytes.
 *
 * @return      Must return \c OK (0) if successful and non-zero if unsuccessful.
 *
 * @callbackdoc random.h
 */
typedef sbyte4          (*RNGFun)(void* rngFunArg, ubyte4 length, ubyte *buffer);
MOC_EXTERN_RANDOM_H randomContext*  g_pRandomContext;

typedef enum {
  NIST_FIPS186  = 0,
  NIST_CTR_DRBG = 2,
  MOC_RAND   = 3
} randomContextType;

typedef struct MocRandCtx
{
  void   *pMocSymObj;
} MocRandCtx;

/* The storage within the RandomCtxWrapper is the logical union of a
 * NIST CTR DRBG context, a FIPS186 context, and a Mocana random object.
 * The NIST CTR DRBG context is the largest of those structures with a
 * maximum size of 900 bytes with the crypto interface and 840 bytes otherwise.
 * If that structure is ever modified in a way that increases the size, this
 * value will need to be modified to match.
 * For the export version only the MocRandCtx is supported. The MocRandCtx is
 * really just a container with a pointer to the real context, so we only need
 * a pointers worth of bytes. Just to be safe there is a little extra space to
 * alleviate any potential alignment issues. */

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE_EXPORT__
#define MOC_RAND_CTX_WRAPPER_STORAGE_SIZE 16
#else
#define MOC_RAND_CTX_WRAPPER_STORAGE_SIZE 900
#endif

typedef struct RandomCtxWrapper
{
  hwAccelDescr hwAccelCtx;

  randomContextType WrappedCtxType;
  ubyte4 reseedBitCounter;
  union
  {
    /* We need enough room for a NIST_CTR_DRBG_Ctx */
    ubyte storage[MOC_RAND_CTX_WRAPPER_STORAGE_SIZE];
  } WrappedCtx;
  /* Don't add any fields here, because CTR adds bytes on the end of byteBuff */

} RandomCtxWrapper;

#define IS_MOC_RAND(wrap) \
    ((wrap->WrappedCtxType == MOC_RAND))

#define GET_MOC_RAND_CTX(wrap) \
    ((wrap->WrappedCtxType == MOC_RAND) ? ((MocRandCtx *)(wrap->WrappedCtx.storage)):(NULL))

/*------------------------------------------------------------------*/

/* Default number of bytes of entropy to collect for seed material */
#define MOC_DEFAULT_NUM_ENTROPY_BYTES 48

/*  RNG Entropy source */
#define ENTROPY_SRC_INTERNAL 0         /* Internal entropy threads will be used */
#define ENTROPY_SRC_EXTERNAL 1         /* External entropy will be added to Random contexts */

#if (defined(__DISABLE_MOCANA_RAND_ENTROPY_THREADS__) || defined(__ENABLE_MOCANA_FIPS_MODULE__))
#define ENTROPY_DEFAULT_SRC  ENTROPY_SRC_EXTERNAL
#else
#define ENTROPY_DEFAULT_SRC  ENTROPY_SRC_INTERNAL
#endif

/* Seeding methods */
#define MOC_AUTOSEED MOC_INIT_FLAG_AUTOSEED  /* FIPS approved entropy collection for autoseed */
#define MOC_NO_AUTOSEED MOC_INIT_FLAG_NO_AUTOSEED    /* Simple entropy collection for autoseed */
#define MOC_SEED_FROM_DEV_URANDOM MOC_INIT_FLAG_SEED_FROM_DEV_URANDOM  /* Seed from /dev/urandom */

#ifdef __DISABLE_MOCANA_RAND_ENTROPY_THREADS__
#define MOC_SEED_DEFAULT MOC_NO_AUTOSEED
#else
#define MOC_SEED_DEFAULT MOC_AUTOSEED
#endif

#define MOC_AUTOSEED_MIN_NUM_BYTES 8
#define MOC_AUTOSEED_MAX_NUM_BYTES 64

/* personalization string used by some DRBG. Can be NULL (default)
or set up to be a function */
#ifndef MOCANA_RNG_GET_PERSONALIZATION_STRING
#define MOCANA_RNG_GET_PERSONALIZATION_STRING  GetNullPersonalizationString
#endif

#define NIST_CTRDRBG_DEFAULT_KEY_LEN_BYTES 32
#define NIST_CTRDRBG_DEFAULT_OUT_LEN_BYTES 16

/*------------------------------------------------------------------*/
/*  RNG Algorithm Defines algoId */
#define MODE_RNG_ANY         0         /* Any random number generator will do */
#define MODE_RNG_FIPS186     1         /* Use FIPS186 RNG */
#define MODE_DRBG_CTR        3         /* Use DRBG CTR Mode  */

#define RANDOM_DEFAULT_ALGO  MODE_DRBG_CTR  /* Must be one of the above (FIPS186 or CTR) */

/*------------------------------------------------------------------*/

/**
 @brief      Create an RNG (random number generator) context data structure.

 @details    This function creates a new RNG (random number generator) context
             data structure.

 @ingroup    func_common_rng

 @flags
 There are no flag dependencies to enable this function.

 @inc_file random.h

 @param  pp_randomContext    On return, pointer to new RNG context.

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    random.h
 */
MOC_EXTERN MSTATUS RANDOM_acquireContext(randomContext **pp_randomContext);

MOC_EXTERN MSTATUS RANDOM_acquireContextEx(randomContext **pp_randomContext, ubyte algoId);

/**
 @brief      Delete RNG (random number generator) context data structure.

 @details    This function deletes an RNG (random number generator) context and
             frees associated memory. To avoid memory leaks, your application
             must call this function.

 @ingroup    func_common_rng

 @flags
 There are no flag dependencies to enable this function.

 @inc_file random.h

 @param  pp_randomContext    Pointer to RNG context pointer to free and delete.

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    random.h
 */
MOC_EXTERN MSTATUS RANDOM_releaseContext (randomContext **pp_randomContext);

MOC_EXTERN MSTATUS RANDOM_releaseContextEx (randomContext **pp_randomContext);

#ifndef __DISABLE_MOCANA_ADD_ENTROPY__

/**
 @brief      Add entropy to the RNG (random number generator) module.

 @details    This function adds entropy to the RNG (random number generator)
             module, thereby increasing randomness.

 @ingroup    func_common_rng

 @inc_file random.h

 @flags
 To enable this function, the following flag must \b not be defined:
 + \c \__DISABLE_MOCANA_ADD_ENTROPY__

 @param pRandomContext   Pointer to RNG context.
 @param entropyBit       Entropy to add.

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    random.h
 */
MOC_EXTERN MSTATUS RANDOM_addEntropyBit(randomContext *pRandomContext, ubyte entropyBit);

MOC_EXTERN MSTATUS RANDOM_addEntropyBitEx(randomContext *pRandomContext, ubyte entropyBit);
#endif /*__DISABLE_MOCANA_ADD_ENTROPY__*/


/**
 @brief      Generate the specified number of random bits.

 @details    This function generates a specified number of random bits, which
             can be used as needed by your application code.

 @warning    To avoid buffer overflow, be sure that the buffer pointed to
             by the \p pBuffer parameter is at least \p bufSize bytes long.

 @ingroup    func_common_rng

 @inc_file random.h

 @flags
 There are no flag dependencies to enable this function.

 @param  pRandomContext  Pointer to RNG context.
 @param  pBuffer         Pointer to buffer at least \p bufSize bytes long in
                         which to store the generated random bytes.
 @param  bufSize         Number of random bytes to return.

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    random.h
 */
MOC_EXTERN MSTATUS RANDOM_numberGenerator(randomContext *pRandomContext, ubyte *pBuffer, sbyte4 bufSize);

/**
 * @brief    Determine if a randomContext refers to a MocSym random implementation.
 * @details  This function takes a pointer to a randomContext pointer, determines
 *           if it refers to a MocSym random implementation, and stores the
 *           result in the boolean pointed to by the second parameter.
 *
 * @param ppRandomContext  Pointer to a randomContext pointer.
 * @param pIsMocSym        Pointer to a intBoolean that will recieve the result.
 *
 * @return                 \c OK (0) if successful; otherwise a negative number
 *                         error code definition from merrors.h. To retrieve a
 *                         string containing an English text error identifier
 *                         corresponding to the function's returned error
 *                         status, use the \c DISPLAY_ERROR macro.
 *
 * @par Flags
 * To enable this function, the following flag \b must be defined
 *   + \c \__ENABLE_MOCANA_SYM__
 *   .
 * To enable this function, the following flag must \b not be defined
 *   + \c \__DISABLE_MOCANA_RNG__
 *   .
 *
 * @par Example
 * @code
 *   MSTATUS status = OK;
 *   intBoolean isMocSymRand = FALSE;
 *   status = RANDOM_isMocSymContext(&g_pRandomContext, &isMocSymRand);
 *   if (OK != status)
 *     goto exit;
 *
 *   if (isMocSymRand == TRUE)
 *   {
 *     . . .
 *   }
 *
 *   . . .
 *
 * exit:
 *   return status;
 * @endcode
 */
MOC_EXTERN MSTATUS RANDOM_isMocSymContext(
  randomContext **ppRandomContext,
  intBoolean *pIsMocSym
  );

/**
 * @brief       Seed a random context using the built-in entropy collection.
 * @details     Launch the automatic entropy collection to gather seed
 *              material, then use that material to seed the random context.
 *
 * @param pCtx  Pointer to an allocated random context.
 *
 * @return      \c OK (0) if successful; otherwise a negative number error
 *              code definition from merrors.h. To retrieve a string
 *              containing an English text error identifier corresponding
 *              to the function's returned error status, use the
 *              \c DISPLAY_ERROR macro.
 *
 * @par Flags
 * To enable this function, the following flag must \b not be defined
 *   + \c \__DISABLE_MOCANA_RNG__
 *   .
 */
MOC_EXTERN MSTATUS RANDOM_launchAutoSeed(
  randomContext *pCtx
  );

/**
 * @brief             Collect entropy bytes for seed material.
 *
 * @param pSeedBytes  Pointer to caller allocated buffer that will recieve the
 *                    computed entropy bytes.
 * @param numBytes    Number of bytes to collect, must be a multiple of 8
 *                    between 8 and 64.
 *
 * @return            \c OK (0) if successful; otherwise a negative number error
 *                    code definition from merrors.h. To retrieve a string
 *                    containing an English text error identifier corresponding
 *                    to the function's returned error status, use the
 *                    \c DISPLAY_ERROR macro.
 * @par Flags
 * To enable this function, the following flag must \b not be defined
 *   + \c \__DISABLE_MOCANA_RNG__
 *   .
 *
 * @par Example
 * @code
 *   MSTATUS status = OK;
 *   ubyte entropy[48] = {0};
 *   status = RANDOM_getAutoSeedBytes(entropy, 48);
 *   if (OK != status)
 *     goto exit;
 *
 *   . . .
 *
 * exit:
 *   return status;
 * @endcode
 */
MOC_EXTERN MSTATUS RANDOM_getAutoSeedBytes(
  ubyte *pSeedBytes,
  ubyte4 numBytes
  );

/**
 * @ingroup func_common_rng
 *
 * @brief Function to return a random ASCII character string.
 *
 * @details This function is the same as RANDOM_numberGenerator, except all the output
 * will be ASCII characters.
 * <p>Each byte of output will be a value in the following space.
 * <pre>
 * <code>
 *    numbers     0 - 9    0x30 - 0x39
 *    upper-case  A - Z    0x41 - 0x5a
 *    lower-case  a - z    0x61 - 0x7a
 *
 *    62 possible characters
 * </code>
 * </pre>
 *
 * @note This function will generate numerical values that map to ASCII
 * characters. If you call this function on an EBCDIC platform, you must convert
 * the result to get the actual EBCDIC characters (i.e., map 0x30 to 0xF0, 0x41
 * to 0xC1, and so on).
 * <p>The caller supplies a randomContext. If you called MOCANA_initMocana, you
 * can pass in g_pRandomContext. If you did not call MOCANA_initMocana, you can
 * call RANDOM_acquireContext to get one.
 * <p>The caller provides the buffer into which the function will place the
 * random characters. The caller also specifies how many random ASCII bytes to
 * generate.
 *
 * @param [in] pRandomContext The random object to use to generate.
 * @param [in,out] pBuffer The buffer into which the function will deposit the random
 * ASCII characters.
 * @param [in] bufferLen The number of bytes to generate.
 *
 * @return An MSTATUS, which is an integer type, OK = 0 for no error, or a
 * non-zero error code. See common/merrors.h for more info on the possible values.
 */
MOC_EXTERN MSTATUS RANDOM_generateASCIIString(randomContext *pRandomContext, ubyte *pBuffer, ubyte4 bufferLen);

/**
 @brief      Generate a random number.

 @details    This function generates a random number. (This function provides a
             %common prototype, or wrapper, around the random number generator
             function&mdash;typically the NanoCrypto RANDOM_numberGenerator()
             function.)

 @sa RANDOM_numberGenerator()

 @ingroup    func_common_rng

 @inc_file random.h

 @flags
 There are no flag dependencies to enable this function.

 @param  rngFunArg   Pointer to RNG function argument.
 @param  length      Number of bytes in the output buffer, \p buffer.
 @param  buffer      Pointer to buffer in which to store the resultant random
                     number.

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    random.h
 */
MOC_EXTERN sbyte4 RANDOM_rngFun(void* rngFunArg, ubyte4 length, ubyte *buffer);


/**
 @brief      Sets the global entropy source flag.

 @details    Sets the global entropy source flag.

 @ingroup    func_common_rng

 @inc_file random.h

 @flags      There are no flag dependencies to enable this function
             but if + \c \__DISABLE_MOCANA_RAND_ENTROPY_THREADS__ is
             defined then only the \c ENTROPY_SRC_EXTERNAL flag is allowed.

 @param  EntropySrc  The input flag. This is either \c ENTROPY_SRC_EXTERNAL,
                     or if internal entropy is not disabled, \c ENTROPY_SRC_INTERNAL.

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    random.h
 */
MOC_EXTERN MSTATUS RANDOM_setEntropySource(ubyte EntropySrc);

/**
 @brief      Gets the global entropy source flag.

 @details    Gets the global entropy source flag.

 @ingroup    func_common_rng

 @inc_file random.h

 @return     \c returns the globally stored entropy source flag
             \c ENTROPY_SRC_EXTERNAL or \c ENTROPY_SRC_INTERNAL.

 @funcdoc    random.h
 */
MOC_EXTERN ubyte RANDOM_getEntropySource(void);


/* FIPS 186 specific functions */

MOC_EXTERN MSTATUS RANDOM_KSrcGenerator(randomContext *pRandomContext, ubyte buffer[40]);

/**
 @brief      Generate FIPS-specific RNG context data structure using provided
             seed.

 @details    This function generates a FIPS-specific RNG context data
             structure, using the provided seed.

 @warning    Your application must successfully call this function before
             calling any other function in the random.h header file.

 @ingroup    func_common_rng

 @inc_file random.h

 @flags
 There are no flag dependencies to enable this function.

 @param  ppRandomContext Pointer to address of RNG context.
 @param  b               Number of bytes in the X key (\p pXKey).
 @param  pXKey           X key value.
 @param  seedLen         Number of bytes in the X seed (\p pXSeed).
 @param  pXSeed          X seed value.

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    random.h
 */
MOC_EXTERN MSTATUS RANDOM_newFIPS186Context( randomContext **ppRandomContext, ubyte b, const ubyte pXKey[/*b*/], sbyte4 seedLen, const ubyte pXSeed[/*seedLen*/]);

/**
 @brief      Deletes a FIPS186 RNG context.

 @details    Deletes a FIPS186 RNG context.

 @ingroup    func_common_rng

 @inc_file random.h

 @param ppRandomContext Pointer to the location of the context to be deleted.

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    random.h
 */
MOC_EXTERN MSTATUS RANDOM_deleteFIPS186Context( randomContext **ppRandomContext);

/**
 @brief      Generate the specified number of random bits via FIPS186.

 @details    This function generates a specified number of random bits via FIPS188, which
             can be used as needed by your application code.

 @warning    To avoid buffer overflow, be sure that the buffer pointed to
              by the \p pRetRandomBytes parameter is at least \p numRandomBytes bytes long.

 @ingroup    func_common_rng

 @inc_file random.h

 @flags
 There are no flag dependencies to enable this function.

 @param  pRandomContext   Pointer to a FIPS186 RNG context.
 @param  pRetRandomBytes  Pointer to buffer at least \p numRandomBytes bytes long in
                          which to store the generated random bytes.
 @param  numRandomBytes   Number of random bytes to return.

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    random.h
 */
MOC_EXTERN MSTATUS RANDOM_numberGeneratorFIPS186(randomContext *pRandomContext, ubyte *pRetRandomBytes, sbyte4 numRandomBytes);

/**
 * @brief Seed a previously allocated FIPS186 Random Context.
 *
 * @param pRandomCtx  Pointer to a previously allocated random context.
 * @param seed        Pointer to a buffer containing the new seed material.
 * @param seedLen     Length in bytes of the new seed material, must be
 *                    between 20 and 64 bytes.
 *
 * @return            \c OK (0) if successful; otherwise a negative number error
 *                    code definition from merrors.h. To retrieve a string
 *                    containing an English text error identifier corresponding
 *                    to the function's returned error status, use the
 *                    \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS RANDOM_seedFIPS186Context (
  randomContext *pRandomCtx,
  ubyte *seed,
  ubyte4 seedLen
  );

/**
 * @brief   Seed a random context with bytes from /dev/urandom
 *
 * @param pCtx     Pointer to the random context being seeded.
 * @param numBytes Number of bytes of seed material to collect. Must be <= 64.
 * @return         \c OK (0) if successful; otherwise a negative number error
 *                 code definition from merrors.h. To retrieve a string
 *                 containing an English text error identifier corresponding
 *                 to the function's returned error status, use the
 *                 \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS RANDOM_seedFromDevURandom (
  randomContext *pCtx,
  ubyte4 numBytes
  );

/**
 * @brief    Seeds randomContexts that are not MocSym Operators.
 * @details  This function will seed the random context implementation
 *           pointed to by pWrap with the bytes provided in the pSeedBytes
 *           buffer. Currently there are only two random context
 *           implementations that are not MocSym Operators, the NIST
 *           CTR DRBG and the FIPS186 PRNG. If the random context type is
 *           one of those two this function will call the appropriate
 *           seed function, otherwise it will return an error.

 * @param pCtx        Pointer to a previously allocated randomContext.
 * @param pSeedBytes  Pointer to buffer which contains new seed material.
 * @param seedLen     Length in bytes of the seed material.
 */
MOC_EXTERN MSTATUS RANDOM_seedOldRandom (
  randomContext *pCtx,
  ubyte *pSeedBytes,
  ubyte4 seedLen
  );

/**
 * @brief    Reseed a random context.
 * @details  This function will reseed the provided random context. If the
 *           underlying context does not accept direct entropy material for
 *           reseeding (ie, uses a previously established function pointer
 *           for entropy collection), then the entropy bytes will be unused.
 *
 * @param pCtx              The random context to reseed.
 * @param pEntropy          Entropy input to use for the reseeding. May be NULL
 *                          if the underlying random object does not accept direct
 *                          entropy injection.
 * @param entropyLen        Length in bytes of the entropy material.
 * @param pAdditionalData   Optional additional data.
 * @param additionalDataLen Length in bytes of the additional data.
 *
 * @return            \c OK (0) if successful; otherwise a negative number error
 *                    code definition from merrors.h. To retrieve a string
 *                    containing an English text error identifier corresponding
 *                    to the function's returned error status, use the
 *                    \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS RANDOM_reseedContext (
  randomContext *pCtx,
  ubyte *pEntropy,
  ubyte4 entropyLen,
  ubyte *pAdditionalData,
  ubyte4 additionalDataLen
  );

/**
 * @brief   Generate random bytes with optional additional input.
 *
 * @param pRandomContext    Random context to use for generation.
 * @param pRetRandomBytes   Buffer to place the generated bytes.
 * @param numRandomBytes    Number of random bytes to generate.
 * @param pAdditionalData   Optional additional data.
 * @param additionalDataLen Length in bytes of the additional data.
 *
 * @return            \c OK (0) if successful; otherwise a negative number error
 *                    code definition from merrors.h. To retrieve a string
 *                    containing an English text error identifier corresponding
 *                    to the function's returned error status, use the
 *                    \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS RANDOM_numberGeneratorAdd (
  randomContext *pRandomContext,
  ubyte *pRetRandomBytes,
  ubyte4 numRandomBytes,
  ubyte *pAdditionalData,
  ubyte4 additionalDataLen
  );


/**
 * @brief   Returns a NULL string.
 *
 * @param pLen Contents will be set to the length of a \c NULL string, ie 0.
 *
 * @return \c NULL pointer.
 */
MOC_EXTERN ubyte* GetNullPersonalizationString(ubyte4* pLen);

#ifdef __FIPS_OPS_TEST__
/**
 * @brief   Sets the global RNG fail flag to TRUE (1).
 */
MOC_EXTERN void triggerRNGFail(void);

/**
 * @brief   Resets the global RNG fail flag back to FALSE (0).
 */
MOC_EXTERN void resetRNGFail(void);
#endif

/*----------------------------------------------------------------------------*/
/* Macro Function Definitions */

#ifdef __ENABLE_MOCANA_DEV_URANDOM__

/**
 * @def
 * @details  This macro will call the function to seed from /dev/urandom if it
 *           is available, otherwise it will expand to set the status to an error.
 *
 * @par Flags
 * To enable this macro, the following flag \b must be defined
 * + \c \__ENABLE_MOCANA_DEV_URANDOM__
 */
#define MOC_SEED_FROM_DEV_URAND(_status, _randCtx, _numBytes)                  \
    _status = RANDOM_seedFromDevURandom (_randCtx, _numBytes);                 \
    if (OK != status)                                                          \
      goto exit;

#else

#define MOC_SEED_FROM_DEV_URAND(_status, _randCtx, _numBytes)                  \
    _status = ERR_RAND_SEED_METHOD_NOT_SUPPORTED;                              \
    goto exit;

#endif /* ifdef __ENABLE_MOCANA_DEV_URANDOM__ */

/*----------------------------------------------------------------------------*/

#ifdef __DISABLE_MOCANA_RAND_ENTROPY_THREADS__

/**
 * @def      MOC_VERIFY_AUTOSEED_ENABLED(_status)
 * @details  This macro determines if the autoseed functionality is enabled
 *           by the current build flags. If the
 *           \c \__DISABLE_MOCANA_RAND_ENTROPY_THREADS__ flag is defined then
 *           this will expand to set the status to an error, otherwise it
 *           will expand to nothing.
 *
 * @param _status    The \ref MSTATUS value for return from the calling function.
 *
 * @par Flags
 * To enable this macro, the following flag \b must be defined
 *   + \c \__DISABLE_MOCANA_RAND_ENTROPY_THREADS__
 */
#define MOC_VERIFY_AUTOSEED_ENABLED(_status)                                   \
    _status = ERR_RAND_SEED_METHOD_NOT_SUPPORTED;                              \
    goto exit;
#else
#define MOC_VERIFY_AUTOSEED_ENABLED(_status)

#endif /* ifdef __DISABLE_MOCANA_RAND_ENTROPY_THREADS__ */

/*----------------------------------------------------------------------------*/

#if defined(__MOCANA_FORCE_ENTROPY__) || defined(__ENABLE_MOCANA_CUSTOM_ENTROPY_INJECT__)
#ifndef __DISABLE_MOCANA_ADD_ENTROPY__

/**
 * @def      MOC_ADD_ENTROPY_PRE_INIT(_status)
 * @details  This macro sets the entropy source to external if the proper
 *           build flags are defined.
 *
 * @param _status The \ref MSTATUS value for return from the calling function.
 *
 * @par Flags
 * To enable this macro, the following flag \b must be defined
 *   + \c \__MOCANA_FORCE_ENTROPY__
 *   .
 * To enable this macro, the following flag must \b not be defined
 *   + \c \__DISABLE_MOCANA_ADD_ENTROPY__
 *   .
 */
#define MOC_ADD_ENTROPY_PRE_INIT(_status)                                     \
    _status = RANDOM_setEntropySource(ENTROPY_SRC_EXTERNAL);                  \
    if (OK != _status)                                                        \
      goto exit;

#endif /* ifndef __DISABLE_MOCANA_ADD_ENTROPY__ */
#endif

#if defined(__ENABLE_MOCANA_CUSTOM_ENTROPY_INJECT__)
#ifndef __DISABLE_MOCANA_ADD_ENTROPY__

/**
 * @def      MOC_ADD_ENTROPY_INIT(_status)
 * @details  This macro adds additional external entropy to the global random
 *           context if certain build flags are set.
 *
 * @param _status The \ref MSTATUS value for return from the calling function.
 *
 * @par Flags
 * To enable this macro, the following flag \b must be defined
 *   + \c \__ENABLE_MOCANA_CUSTOM_ENTROPY_INJECT__
 *   .
 * To enable this macro, the following flag must \b not be defined
 *   + \c \__DISABLE_MOCANA_ADD_ENTROPY__
 *   .
 * @sa MOC_ADD_ENTROPY_UNINIT
 */
#define MOC_ADD_ENTROPY_INIT(_status, _pSetupInfo)                             \
    _status = MOCANA_addCustomEntropyInjection();                              \
    if (OK != _status)                                                         \
      goto exit;

#endif /* ifndef __DISABLE_MOCANA_ADD_ENTROPY__ */
#endif /* if defined(__ENABLE_MOCANA_CUSTOM_ENTROPY_INJECT__) */

#if defined(__MOCANA_FORCE_ENTROPY__) && !defined(__ENABLE_MOCANA_CUSTOM_ENTROPY_INJECT__)
#ifndef __DISABLE_MOCANA_ADD_ENTROPY__

/**
 * @def      MOC_ADD_ENTROPY_INIT(_status)
 * @details  This macro adds additional external entropy to the global random
 *           context if certain build flags are set.
 *
 * @param _status The \ref MSTATUS value for return from the calling function.
 *
 * @par Flags
 * To enable this macro, the following flag \b must be defined
 *   + \c \__MOCANA_FORCE_ENTROPY__
 *   .
 * To enable this macro, the following flag must \b not be defined
 *   + \c \__DISABLE_MOCANA_ADD_ENTROPY__
 *   .
 * @sa MOC_ADD_ENTROPY_UNINIT
 */
#define MOC_ADD_ENTROPY_INIT(_status, _pSetupInfo)                             \
    if (NULL != _pSetupInfo)                                                   \
    {                                                                          \
      if (0 != (MOC_NO_AUTOSEED & _pSetupInfo->flags))                         \
      {                                                                        \
        _status = RANDOM_setEntropySource(ENTROPY_SRC_EXTERNAL);               \
        if (OK != _status)                                                     \
          goto exit;                                                           \
      }                                                                        \
    }                                                                          \
    _status = MOCANA_addExternalEntropy(1);                                    \
    if (OK != _status)                                                         \
      goto exit;

/**
 * @def      MOC_ADD_ENTROPY_UNINIT()
 * @details  This macro cancels the adding of additional external entropy to
 *           the global random context.
 *
 * @par Flags
 * To enable this macro, the following flag \b must be defined
 *   + \c \__MOCANA_FORCE_ENTROPY__
 *   .
 * To enable this macro, the following flag must \b not be defined
 *   + \c \__DISABLE_MOCANA_ADD_ENTROPY__
 *   .
 *
 * @note MOCANA_cancelExternalEntropy always returns \c OK so there is no need
 *       to look at the return value.
 * @sa MOC_ADD_ENTROPY_INIT
 */
#define MOC_ADD_ENTROPY_UNINIT() \
    MOCANA_cancelExternalEntropy();

#endif /* ifndef __DISABLE_MOCANA_ADD_ENTROPY__ */
#endif /* ifdef __MOCANA_FORCE_ENTROPY__ */

#ifndef MOC_ADD_ENTROPY_INIT
#define MOC_ADD_ENTROPY_INIT(_status, _pSetupInfo)
#endif
#ifndef MOC_ADD_ENTROPY_UNINIT
#define MOC_ADD_ENTROPY_UNINIT()
#endif
#ifndef MOC_ADD_ENTROPY_PRE_INIT
#define MOC_ADD_ENTROPY_PRE_INIT(_status)
#endif

/*----------------------------------------------------------------------------*/

#ifndef __DISABLE_MOCANA_RNG__

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__

/**
 * @def      MOC_GRNG_DEFAULT_INIT(_status)
 * @details  This macro initializes the default global random context.
 *
 * @param _status The \ref MSTATUS value for return from the calling function.
 *
 * @par Flags
 * To enable this macro, the following flag must \b not be defined
 *   + \c \__DISABLE_MOCANA_RNG__
 */
#define MOC_GRNG_DEFAULT_INIT(_status)                                         \
    if (NULL == g_pRandomContext)                                              \
    {                                                                          \
      _status = CRYPTO_INTERFACE_RANDOM_acquireContextEx (                     \
          &g_pRandomContext, RANDOM_DEFAULT_ALGO);                             \
      if (OK != _status)                                                       \
        goto exit;                                                             \
    }

/**
 * @def      MOC_GRNG_DEFAULT_FREE(_status, _dStatus)
 * @details  This macro frees the default global random context.
 *
 * @param _status   The \ref MSTATUS value for return from the calling function.
 * @param _dStatus  The temporary placeholder status used to check return values.
 *
 * @par Flags
 * To enable this macro, the following flag must \b not be defined
 *   + \c \__DISABLE_MOCANA_RNG__
 */
#define MOC_GRNG_DEFAULT_FREE(_status, _dStatus)                               \
    _dStatus = CRYPTO_INTERFACE_RANDOM_releaseContextEx(&g_pRandomContext);    \
    if (OK != dStatus)                                                         \
      _status = _dStatus;

#else

/**
 * @def      MOC_GRNG_DEFAULT_INIT(_status)
 * @details  This macro initializes the default global random context.
 *
 * @param _status The \ref MSTATUS value for return from the calling function.
 *
 * @par Flags
 * To enable this macro, the following flag must \b not be defined
 *   + \c \__DISABLE_MOCANA_RNG__
 */
#define MOC_GRNG_DEFAULT_INIT(_status)                                         \
    if (NULL == g_pRandomContext)                                              \
    {                                                                          \
      _status = RANDOM_acquireContext(&g_pRandomContext);                      \
      if (OK != _status)                                                       \
        goto exit;                                                             \
    }

/**
 * @def      MOC_GRNG_DEFAULT_FREE(_status, _dStatus)
 * @details  This macro frees the default global random context.
 *
 * @param _status   The \ref MSTATUS value for return from the calling function.
 * @param _dStatus  The temporary placeholder status used to check return values.
 *
 * @par Flags
 * To enable this macro, the following flag must \b not be defined
 *   + \c \__DISABLE_MOCANA_RNG__
 */
#define MOC_GRNG_DEFAULT_FREE(_status, _dStatus)                               \
    _dStatus = RANDOM_releaseContext(&g_pRandomContext);                       \
    if (OK != dStatus)                                                         \
      _status = _dStatus;

#endif /* ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__ */

/**
 * @def      MOC_GRNG_DEPOT_INIT(_status)
 * @details  This macro initializes the entropy depot, this must be done before
 *           any attempts to collect entropy using RNG_SEED_extractDepotBits or
 *           RNG_SEED_extractInitialDepotBits.
 *
 * @param _status   The \ref MSTATUS value for return from the calling function.
 *
 * @par Flags
 * To enable this macro, the following flag must \b not be defined
 *   + \c \__DISABLE_MOCANA_RNG__
 */
#define MOC_GRNG_DEPOT_INIT(_status)                                           \
    _status = RNG_SEED_initDepotState();                                       \
    if (OK != _status)                                                         \
      goto exit;

/**
 * @def      MOC_GRNG_DEPOT_FREE()
 * @details  This macro frees the entropy depot state.
 *
 * @note     RNG_SEED_freeDepotState can not fail so there is no need to check
 *           the return status.
 *
 * @par Flags
 * To enable this macro, the following flag must \b not be defined
 *   + \c \__DISABLE_MOCANA_RNG__
 */
#define MOC_GRNG_DEPOT_FREE() \
    RNG_SEED_freeDepotState();

/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SYM__

/**
 * @def      MOC_GRNG_FULL_INIT(_status, _pSetupInfo, _pMocCtx)
 * @brief    This macro initializes and instantiates the global random context.
 * @details  This macro will check the input parameters to determine if a MocSym
 *           random implementation is to be used instead of the default. If
 *           requested, it creates the MocSym random context and attempts to
 *           seed the new context. If a MocSym random implementation is
 *           not requested then the default random implementation is initialized.
 *           Either way the result is a newly instantiated global random context
 *           at the location pointed to by \c g_pRandomContext.
 *
 * @note     If this macro is enabled and the \c \__ENABLE_MOCANA_SYM__
 *           build flag is \b not defined then this macro will be equal to the
 *           macro MOC_GRNG_DEFAULT_INIT.
 *
 * @param _status      The \ref MSTATUS value for return from the calling function.
 * @param _pSetupInfo  A pointer to an InitMocanaSetupInfo structure.
 * @param _pMocCtx     COntains arrays of Operators.
 *
 * @par Flags
 * To enable this macro, the following flag must \b not be defined
 *   + \c \__DISABLE_MOCANA_RNG__
 *   .
 *
 * To set this macro to the value of MOC_GRNG_DEFAULT_INIT, the following flag
 * \b must be defined
 *   + \c \__ENABLE_MOCANA_SYM__
 *   .
 * @sa MOCANA_initialize
 */
#define MOC_GRNG_FULL_INIT(_status, _pSetupInfo, _pMocCtx)                     \
    if (NULL != _pSetupInfo)                                                   \
    {                                                                          \
      if (0 != (MOC_NO_AUTOSEED & _pSetupInfo->flags))                         \
      {                                                                        \
        _status = RANDOM_setEntropySource(ENTROPY_SRC_EXTERNAL);               \
        if (OK != _status)                                                     \
          goto exit;                                                           \
      }                                                                        \
                                                                               \
      _status = ERR_RAND_CTX_ALREADY_INITIALIZED;                              \
      if (NULL != g_pRandomContext)                                            \
        goto exit;                                                             \
                                                                               \
      if (NULL != _pSetupInfo->MocSymRandOperator)                             \
      {                                                                        \
        intBoolean support = FALSE;                                            \
        MocRandCtx *pRandCtx = NULL;                                           \
        RandomCtxWrapper *pWrap = NULL;                                        \
        MocSymCtx pCtx = NULL;                                                 \
                                                                               \
        _status = CRYPTO_createMocSymRandom(_pSetupInfo->MocSymRandOperator,   \
                                            _pSetupInfo->pOperatorInfo,        \
                                            _pMocCtx, &g_pRandomContext);      \
        if (OK != _status)                                                     \
          goto exit;                                                           \
                                                                               \
        pWrap = (RandomCtxWrapper *) g_pRandomContext;                         \
                                                                               \
        _status = ERR_NULL_POINTER;                                            \
        if (NULL == pWrap)                                                     \
          goto exit;                                                           \
                                                                               \
        pRandCtx = (MocRandCtx *)&(pWrap->WrappedCtx.storage);                 \
        pCtx = (MocSymCtx)(pRandCtx->pMocSymObj);                              \
        if ( (NULL == pCtx) || (NULL == pCtx->SymOperator) )                   \
          goto exit;                                                           \
                                                                               \
        _status = pCtx->SymOperator (                                          \
          pCtx, _pMocCtx, MOC_SYM_OP_RAND_GET_SEED_TYPE, NULL,                 \
          (void *)&support);                                                   \
        if (OK != _status)                                                     \
          goto exit;                                                           \
                                                                               \
        if ( (0 == (MOC_NO_AUTOSEED & _pSetupInfo->flags)) &&                  \
             (MOC_SYM_RAND_SEED_TYPE_DIRECT == support) )                      \
        {                                                                      \
          if (0 != (MOC_SEED_FROM_DEV_URANDOM & _pSetupInfo->flags))           \
          {                                                                    \
            MOC_SEED_FROM_DEV_URAND (                                          \
              _status, g_pRandomContext, MOC_DEFAULT_NUM_ENTROPY_BYTES)        \
          }                                                                    \
          else                                                                 \
          {                                                                    \
          ubyte entropy[MOC_DEFAULT_NUM_ENTROPY_BYTES] = {0};                  \
            _status = RANDOM_getAutoSeedBytes (                                \
              entropy, MOC_DEFAULT_NUM_ENTROPY_BYTES);                         \
          if (OK != _status)                                                   \
            goto exit;                                                         \
                                                                               \
          _status = CRYPTO_seedRandomContext(g_pRandomContext,                 \
                                             NULL,                             \
                                             entropy,                          \
                                             MOC_DEFAULT_NUM_ENTROPY_BYTES);   \
            MOC_MEMSET(entropy, 0, MOC_DEFAULT_NUM_ENTROPY_BYTES);             \
          }                                                                    \
          if (OK != _status)                                                   \
            goto exit;                                                         \
        }                                                                      \
      }                                                                        \
      else                                                                     \
      {                                                                        \
        MOC_GRNG_DEFAULT_INIT(_status)                                         \
        if (0 != (MOC_SEED_FROM_DEV_URANDOM & _pSetupInfo->flags))             \
        {                                                                      \
          MOC_SEED_FROM_DEV_URAND (                                            \
              _status, g_pRandomContext, MOC_DEFAULT_NUM_ENTROPY_BYTES)        \
        }                                                                      \
      }                                                                        \
    }                                                                          \
    else                                                                       \
    {                                                                          \
      MOC_GRNG_DEFAULT_INIT(_status)                                           \
    }

/**
 * @def      MOC_GRNG_FULL_FREE(_status, _dStatus)
 * @brief    This macro will free the global random context.
 * @details  If the context is MocSym then the respective free function will be
 *           called, otherwise the default free will be called.
 *
 * @note     If this macro is enabled and the \c \__ENABLE_MOCANA_SYM__
 *           build flag is \b not defined then this macro will be equal to the
 *           macro MOC_GRNG_DEFAULT_FREE.
 *
 * @param _status   The \ref MSTATUS value for return from the calling function.
 * @param _dStatus  The temporary placeholder status used to check return values.
 *
 * @par Flags
 * To enable this macro, the following flag must \b not be defined
 *   + \c \__DISABLE_MOCANA_RNG__
 *   .
 *
 * To set this macro to the value of MOC_GRNG_DEFAULT_FREE, the following flag
 * \b must be defined
 *   + \c \__ENABLE_MOCANA_SYM__
 */
#define MOC_GRNG_FULL_FREE(_status, _dStatus)                                  \
    intBoolean isMocSymRand = FALSE;                                           \
    _dStatus = RANDOM_isMocSymContext(&g_pRandomContext, &isMocSymRand);       \
    if (OK != _dStatus)                                                        \
      _status = _dStatus;                                                      \
    if (TRUE == isMocSymRand)                                                  \
    {                                                                          \
      _dStatus = CRYPTO_freeMocSymRandom(&g_pRandomContext);                   \
      if (OK != _dStatus)                                                      \
        _status = _dStatus;                                                    \
    }                                                                          \
    else                                                                       \
    {                                                                          \
      MOC_GRNG_DEFAULT_FREE(_status, _dStatus)                                 \
    }

#else /* ifdef __ENABLE_MOCANA_SYM__ */

/* If MocSym is disabled, define macros to handle default RNG only */
#define MOC_GRNG_FULL_INIT(_status, _pSetupInfo, _pMocCtx) \
    MOC_GRNG_DEFAULT_INIT(_status)
#define MOC_GRNG_FULL_FREE(_status, _dStatus) \
    MOC_GRNG_DEFAULT_FREE(_status, _dStatus)

#endif /* ifdef __ENABLE_MOCANA_SYM__ */

/*----------------------------------------------------------------------------*/

/**
 * @def      MOC_GRNG_INIT(_status, _pSetupInfo, _pMocCtx)
 * @details  This macro initializes the global random context, calling other
 *           macros to perform the setup based on build flags.
 *
 * @param _status      The \ref MSTATUS value for return from the calling function.
 * @param _pSetupInfo  A pointer to an InitMocanaSetupInfo structure.
 * @param _pMocCtx     COntains arrays of Operators.
 *
 * @par Flags
 * To enable this macro, the following flag must \b not be defined
 *   + \c \__DISABLE_MOCANA_RNG__
 */
#define MOC_GRNG_INIT(_status, _pSetupInfo, _pMocCtx)                          \
    MOC_ADD_ENTROPY_PRE_INIT(_status)                                          \
    MOC_GRNG_DEPOT_INIT(_status)                                               \
    MOC_GRNG_FULL_INIT(_status, _pSetupInfo, _pMocCtx)                         \
    MOC_ADD_ENTROPY_INIT(_status, _pSetupInfo)

/**
 * @def      MOC_GRNG_FREE(_status, _dStatus)
 * @details  This macro frees the global random context, calling other
 *           macros to perform the deallocation based on build flags.
 *
 * @param _status   The \ref MSTATUS value for return from the calling function.
 * @param _dStatus  The temporary placeholder status used to check return values.
 *
 * @par Flags
 * To enable this macro, the following flag must \b not be defined
 *   + \c \__DISABLE_MOCANA_RNG__
 */
#define MOC_GRNG_FREE(_status, _dStatus)                                       \
    MOC_GRNG_FULL_FREE(_status, _dStatus)                                      \
    MOC_GRNG_DEPOT_FREE()                                                      \
    MOC_ADD_ENTROPY_UNINIT()

#else /* ifndef __DISABLE_MOCANA_RNG__ */

/* If RNG is disabled, define macros to be empty */
#ifndef MOC_GRNG_INIT
#define MOC_GRNG_INIT(_status, _pSetupInfo, _pMocCtx)
#endif
#ifndef MOC_GRNG_FREE
#define MOC_GRNG_FREE(_status, _dStatus)
#endif

#endif /* ifndef __DISABLE_MOCANA_RNG__ */

/*----------------------------------------------------------------------------*/

#ifdef __cplusplus
}
#endif

#endif /* __RANDOM_HEADER__ */
