/**
 * @file  initmocana.h
 * @brief Initialization Routines.
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
#ifndef __INIT_MOCANA_H__
#define __INIT_MOCANA_H__

#include "../cap/capasym.h"

#ifdef __cplusplus
extern "C" {
#endif

/** This function knows how to free the contents of a MocSubCtx and the MocSubCtx
 * itself.
 * <p>If you build a SubCtx, you must build a Free function. When DIGICERT_free is
 * freeing the MocCtx, it will cycle through each of the SubCtx therein, asking
 * each to free itself.
 * <p>The FreeFnct must free the contents and the MocSubCtx shell itself.
 * <p>The caller will pass in the address of a SubCtx pointer. Go to the address
 * and find the SubCtx to free. Free the contents, free the shell, and deposit a
 * NULL at the address.
 */
typedef MSTATUS (*MSubCtxFree) (struct MocSubCtx **ppMocSubCtx);

/** This is a MocSubCtx. A MocCtx contains a link list of these.
 * <p>Each SubCtx will contain the MocCtx parent. That is, the MocCtx in which
 * this SubCtx is loaded.
 * <p>If you create a new kind of SubCtx, you must create a new type. That is
 * simply a flag, defined MOC_LIB_CTX_TYPE_something. Make sure the value for
 * your type is unique. All such flags will be defined in
 * mss/src/common/initmocana.h.
 * <p>The pLocalCtx is whatever you need it to be.
 * <p>You supply a FreeFnct that will be called by DIGICERT_free to free your
 * SubCtx. The FreeFnct must free the contents (the local ctx) and the MocSubCtx
 * shell.
 * <p>Inside the MocCtx is a link list of SubCtx. Build one and call
 * MocLoadNewSubCtx.
 */
typedef struct MocSubCtx {
  ubyte4              type;
  MocCtx              pCtxParent;
  void               *pLocalCtx;
  MSubCtxFree         FreeFnct;
  struct MocSubCtx   *pNext;
} MocSubCtx;

#define MOC_SUB_CTX_TYPE_OP_LIST          1

/** This is the localCtx for a MOC_SUB_CTX_TYPE_OP_LIST.
 * <p>The totalSize is the total amount of space allocated for the MocSubCtx that
 * holds the OpList. When freeing the SubCtx that holds the OpList, we'll be
 * given the SubCtx itself and the Free function knows what the real type of the
 * pLocalCtx is. It must free the localCtx and the SubCtx. However, for the
 * OpList, the SubCtx and OpList are part of a single buffer. The totalSize field
 * is how big that buffer is. When freeing, we can overwrite the memory.
 * <p>There are three kinds of Operators: Digest, SymKey, and AsymKey. However,
 * we put the Digest and SymKey Operators into one array and simply specify the
 * index where the Digest Operators begin. In this way we don't have to build a
 * new array, and we can more easily cycle through all sym Operators. There are
 * times we don't know if we're looking for a digest or sym key Operator, so we
 * want to cycle through all. But there are times we know we are looking for a
 * digest, so skip the non-digest Operators.
 * <p>If there are no digest operators, digestIndex will be the same as
 * symOperatorCount. That way when we do a for loop:
 * <pre>
 * <code>
 *   for (index = digestIndex; index < symOperatorCount; ++index)
 * </code>
 * </pre>
 * we won't actually look at anything.
 */
typedef struct {
  ubyte4                 totalSize;
  MSymOperatorAndInfo   *pSymOperators;
  ubyte4                 symOperatorCount;
  ubyte4                 digestIndex;
  MKeyOperatorAndInfo   *pKeyOperators;
  ubyte4                 keyOperatorCount;
} MSubCtxOpList;

/* This is the Free function to use when building the SubCtxOpList.
 */
MOC_EXTERN MSTATUS MSubCtxOpListFree (struct MocSubCtx **ppMocSubCtx);

/** Build a new MocSubCtx of type MOC_SUB_CTX_TYPE_OP_LIST.
 * <p>This will allocate memory for a new shell of MocSubCtx, and build a
 * localCtx that contains the OperatorList as MSubCtxOpList. It will copy the
 * input Operators into the new localCtx.
 * <p>Note that this creates new OperatorAndInfo arrays (it does not simply copy
 * a reference to the input arrays). However, it only copies the contents of the
 * input arrays into the new arrays. That is, it does not make a deep copy of the
 * associated infos.
 * <p>When copying an Operator, it is really copying a function pointer. So
 * there's no need to make a deep copy. But the associated info for each Operator
 * might be actual data. For example, it could be a hardware handle. However, the
 * function will just copy over the info, there's no way to make a deep copy.
 * Generally, this will not be an issue, because the vast majority of Operators
 * take NULL as the associated info.
 *
 * @param pDigestOperators The list of Operators and associated info that perform
 * digest operations to copy.
 * @param digestOperatorCount The number of Operators in the list.
 * @param pSymOperators The list of Operators and associated info that perform
 * symmetric key operations to copy.
 * @param symOperatorCount The number of Operators in the list.
 * @param pKeyOperators The list of Operators and associated info that perform
 * asymmetric key operations to copy.
 * @param keyOperatorCount The number of Operators in the list.
 * @param ppNewSubCtx The address where the function will deposit the new SubCtx.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MBuildOpListCtx (
  MSymOperatorAndInfo *pDigestOperators,
  ubyte4 digestOperatorCount,
  MSymOperatorAndInfo *pSymOperators,
  ubyte4 symOperatorCount,
  MKeyOperatorAndInfo *pKeyOperators,
  ubyte4 keyOperatorCount,
  MocSubCtx **ppNewSubCtx
  );

/** The MocContext is simply a link list of SubCtx.
 * <p>The DIGICERT_initialize function will create a new MocContext (returning
 * the pointer to it as a MocCtx) and it will be empty.
 * <p>The initialize function will then build the first SubCtx, the first in the
 * link list. This one will contain the arrays of Operators.
 * <p>Later on, if someone wants to build a new SubCtx (containing "global" SSL
 * info, for example), build a new SubCtx and add it to the end of the list by
 * calling MocLoadNewSubCtx. A SubCtx contains the FreeFnct that knows how to
 * free the contents of the SubCtx and the shell of the SubCtx.
 * <p>The DIGICERT_free function is going to go through the link list, freeing each
 * SubCtx by calling the FreeFnct in each. Note that the FreeFnct frees the
 * contents of the SubCtx AND the MocSubCtx shell itself. The DIGICERT_free
 * function will get a SubCtx in the list (saving a reference to the next) and
 * call that context's FreeFnct, passing in the ctx itself. Then DIGICERT_free will
 * move on. The main reason DIGICERT_free does not free the shell is that it
 * doesn't know if that shell is really a MocSubCtx or some other struct (a
 * bigger struct containing more info, but something that can look like a SubCtx,
 * in other words, a subclass), and doesn't know if it needs to overwrite memory.
 * <p>Finally, DIGICERT_free will destroy theMutex and free the memory of the shell.
 * <p>The refCount is there to keep track of how many objects have a reference to
 * the MocCtx. Each time an object wants a reference to the MocCtx, it will
 * acquire it using AqcuireMocCtx. That function will use theMutex to increment
 * the refCount in a thread-safe way. When an object no longer needs the MocCtx,
 * call ReleaseMocCtx. That function will decrement the refCount.
 * <p>If the refCount goes to zero, the MocCtx is destroyed. In fact, DIGICERT_free
 * will not actually free the MocCtx, it will only decrement the refCount. It is
 * a signed int so we can recognize errors if the count goes to negative values.
 */
typedef struct MocContext{
  MocSubCtx     *pSubCtx;
  sbyte4         refCount;
  RTOS_MUTEX     theMutex;
} MocContext;

/** Create a new MocCtx.
 * <p>This function will allocate the shell that is the MocCtx, create the mutex
 * and initialize the refCount to 1.
 * <p>If you call CreateMocCtx, you must call FreeMocCtx when you are done
 * with it.
 *
 * @param isMultiThreaded If TRUE, the Ctx will be built to be thread-safe. If
 * FALSE, it will not employ thread-safety measures, but will be faster.
 * @param ppNewMocCtx The address where the function will deposit the newly
 * created Ctx.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CreateMocCtx (
  intBoolean isMultiThreaded,
  MocCtx *ppNewMocCtx
  );

/** Free the MocCtx.
 * <p>This function will cycle through all the SubCtx inside of it, calling on
 * each of their FreeFncts. Then it will destroy the mutex and free the shell.
 *
 * @param ppMocCtx The address where the function will find the MocCtx to free
 * and where it will deposit a NULL if successful.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS FreeMocCtx (
  MocCtx *ppMocCtx
  );

/** Acquire a reference to the MocCtx.
 * <p>This is generally used when an object or function wants to keep a copy of
 * the MocCtx. An object is built and wants to keep the lists of Operators around
 * for later use, and wants to make sure the MocCtx will not be destroyed
 * underneath it. A function might acquire a reference just for the duration of
 * the function call.
 * <p>For example, a function has as one of its arguments the MocCtx. That
 * function is going to create an object and store the MocCtx inside the object
 * to be available for later operations if needed. The caller will have passed in
 * the MocCtx, the function will acquire a reference to the MocCtx passed in and
 * copy a reference to the MocCtx inside the object. Later on, when the object is
 * being destroyed, the code that frees the object will call the Release function
 * on the MocCtx.
 * <p>If you call AcquireMocCtxRef, you must call ReleaseMocCtxRef when
 * done with it. But you should not call the Release unless the Acquire was
 * successful. It is easy to write your code to know whether you need to call
 * Release or not. For example, if the acquisition works, you store the MocCtx in
 * some field of a struct. Later on, if that field is NULL, don't Release. Or if
 * you are acquiring the reference only for the duration of a function call, init
 * a flag to 0, set it to 1 if the acquisition works, and Release only if flag is
 * non-zero.
 * <pre>
 * <code>
 *   ubyte4 flag = 0;
 *
 *   status = AcquireMocCtxRef (pMocCtx);
 *   if (OK != status)
 *     goto exit;
 *
 *   flag = 1;
 *
 * exit:
 *   if (0 != flag) {
 *     ReleaseMocCtxRef (pMocCtx);
 *   }
 * </code>
 * </pre>
 *
 * @param pMocCtx The ctx for which a reference is requested.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS AcquireMocCtxRef (
  MocCtx pMocCtx
  );

/** Release a reference to the MocCtx.
 * <p>Before using an MocCtx you should acquire a reference to make sure it is
 * not destroyed while you are using it. When done with it, if you called
 * Acquire, you must call this Release function.
 *
 * @param pMocCtx The ctx for which the reference is to be released.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS ReleaseMocCtxRef (
  MocCtx pMocCtx
  );

/** Get a reference to the SubCtx with the given SUB_CTX_TYPE_ value inside the
 * given MocCtx.
 * <p>The caller passes in a MocCtx and a flag, the function returns a reference
 * inside the MocCtx of the SubCtx with that flag. The flag is one of the
 * SUB_CTX_TYPE_ values.
 * <p>The caller must call MocReleaseSubCtxRef when done with it.
 * <p>If there is no SubCtx inside the MocCtx with the given type flag, the
 * function will set *ppSubCtx to NULL and return ERR_NOT_FOUND.
 *
 * @param pMocCtx The MocCtx containing the SubCtx requested.
 * @param subCtxType A flag indicating which SubCtx is requested.
 * @param ppSubCtx The address where the function will deposit a reference to the
 * SubCtx requested.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MocAcquireSubCtxRef (
  MocCtx pMocCtx,
  ubyte4 subCtxType,
  MocSubCtx **ppSubCtx
  );

/** Release the reference to the SubCtx.
 *
 * @param ppSubCtx The address where the function will find the subCtx to release.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MocReleaseSubCtxRef (
  MocSubCtx **ppSubCtx
  );

/** Load a new SubCtx into the MocCtx.
 * <p>This will go to the address given by ppSubCtx and expect to find a new
 * subCtx. It will place it onto the end of the link list in the MocCtx in a
 * thread-safe manor. It will then set *ppSubCtx to NULL to indicate that the
 * MocCtx now has control of this subCtx.
 * <p>Note that it is easy to add a subCtx to a MocCtx, this function just makes
 * sure it is done in a thread-safe manor.
 *
 * @param pMocCtx The MocCtx to which this subCtx will be added.
 * @param ppSubCtx The address where the function will find the subCtx to add.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MocLoadNewSubCtx (
  MocCtx pMocCtx,
  MocSubCtx **ppSubCtx
  );

/**
 * @struct  InitMocanaSetupInfo
 * @details This struct contains setup information to be used during the
 *          initialization process. This includes an Operator function serving
 *          as an implementation of a random number generator and any associated
 *          info the Operator needs to perform its operations.
 *
 * @var InitMocanaSetupInfo::MocSymRandOperator
 *   The Operator function implementing a random number generator. See the
 *   documentation for MSymOperator for more information on this function pointer.
 * @var InitMocanaSetupInfo::pOperatorInfo
 *   The information associated with the Operator.
 * @var InitMocanaSetupInfo::pStaticMem
 *   Pointer to a buffer to be used as a static memory partition.
 * @var InitMocanaSetupInfo::staticMemSize
 *   Size in bytes of the static memory partition.
 * @var InitMocanaSetupInfo::flags
 *   Flags to indicate additional options to the initialization function, this is
 *   a bit field, so OR together among the MOC_INIT_FLAG_ values required.
 *   For example, (MOC_INIT_FLAG_NO_AUTOSEED | MOC_INIT_FLAG_SINGLE_THREAD).
 * @var InitMocanaSeupInfo::pDigestOperators
 *   An array of Operators that perform message digest algorithms (e.g.
 *   SymOperatorSha256Sw). These are all the digest algorithms and
 *   implementations your app is willing to support. See mss/src/crypto/mocsym.h
 *   for more information on buillding an Operator array.
 * @var InitMocanaSeupInfo::digestOperatorCount
 *   The number of Operators in the pDigestOperators array.
 * @var InitMocanaSeupInfo::pSymOperators
 *   An array of Operators that perform symmetric key algorithms (e.g.
 *   SymOpertorHmacSw or SymOperatorAesCbcSw). These are all the symmetric key
 *   algorithms and implementations your app is willing to support. See
 *   mss/src/crypto/mocsym.h for more information on buillding an Operator array.
 * @var InitMocanaSeupInfo::symOperatorCount
 *   The number of Operators in the pSymOperators array.
 * @var InitMocanaSeupInfo::pKeyOperators
 *   An array of Operators that perform asymmetric key algorithms (e.g.
 *   KeyOpertorRsaSw). These are all the asymmetric key algorithms and
 *   implementations your app is willing to support. See mss/src/crypto/mocasym.h
 *   for more information on buillding an Operator array.
 * @var InitMocanaSeupInfo::keyOperatorCount
 *   The number of Operators in the pKeyOperators array.
 */
typedef struct
{
  MSymOperator           MocSymRandOperator;
  void                  *pOperatorInfo;
  ubyte                 *pStaticMem;
  ubyte4                 staticMemSize;
  ubyte4                 flags;
  MSymOperatorAndInfo   *pDigestOperators;
  ubyte4                 digestOperatorCount;
  MSymOperatorAndInfo   *pSymOperators;
  ubyte4                 symOperatorCount;
  MKeyOperatorAndInfo   *pKeyOperators;
  ubyte4                 keyOperatorCount;
} InitMocanaSetupInfo;

/** OR this value into the flags field of InitMocanaSetupInfo if you want the
 * initialize call to run the autoseed operations when building the global random.
 * <p>Note that this is the default behavior. That is, if you do not set this bit
 * and do not set the NO_AUTOSEED bit, the initialize function will autoseed.
 * <p>If both the AUTOSEED and NO_AUTOSEED bits are set, the initialize function
 * will NOT autoseed.
 */
#define MOC_INIT_FLAG_AUTOSEED        0x0001

/** OR this value into the flags field of InitMocanaSetupInfo if you don't want
 * the initialize call to run the autoseed operations when building the global
 * random.
 */
#define MOC_INIT_FLAG_NO_AUTOSEED     0x0002

/** OR this value into the flags field of InitMocanaSetupInfo if you want to 
 * seed the Random Number Generator with bytes from /dev/urandom.  Must have the
 * __ENABLE_DIGICERT_DEV_URANDOM__ build flag set 
 */
#define MOC_INIT_FLAG_SEED_FROM_DEV_URANDOM  0x0004

/** OR this value into the flags field of InitMocanaSetupInfo if your app will be
 * running in a single-threaded environment. This will allow various opeations to
 * be somewhat faster, but they won't be thread-safe. If this bit is not set,
 * some operations will employ thread-safety measures which can slow down
 * operations, although generally the slowdown is minor.
 */
#define MOC_INIT_FLAG_SINGLE_THREAD         0x0008

/**
 * @brief    Initialize Mocana code base.
 * @details  This function will initialize the Mocana code base, it is typically
 *           the first initialization step for any Mocana Security of Things
 *           Platform product.
 *           <p>NOTE! You must call DIGICERT_free if you call this function, when
 *           you are no longer making any NanoCrypto function calls. Generally,
 *           you will call DIGICERT_initialize at the beginning of your app, and
 *           DIGICERT_free right before you exit. You must call DIGICERT_free even if
 *           the call to DIGICERT_initialize returned an error.
 *           <p>This function will build a MocAlgCtx containing the Operators
 *           from the setupInfo, among other information. Some functions will
 *           take this ctx as an argument. You pass in arrays of Operators (an
 *           array of Digest Operators, and Array of Symmetric Key Operators, and
 *           an array of Asymmetric Key Operators) representing the algorithms
 *           and implementations your app is willing to support. If you pass in
 *           NULL for the Operator lists, the initialize will still work, and
 *           there are NanoCrypto functions that you can call, because they don't
 *           require an AlgCtx. However, it does limit your possibilities.
 *           <p>The first call to this function is not thread safe.  Any further
 *           nested calls after the first call are thread safe however any nested
 *           calls much have a matching free call. Nested calls will not
 *           reinitialize data structures or reseed the global PRNG.
 *           <p>This function will allocate and seed a global pseudo random
 *           number generator, the type of PRNG and seeding method are determined
 *           from build flags and flags in the initialization struct passed in as
 *           a parameter. Upon successful return, the PRNG will be instantiated
 *           at the location pointed to by \c g_pRandomContext.
 *           <p>If the build flag \c \__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
 *           is set, a "simple" seed is used which takes only milliseconds to
 *           generate. Otherwise the FIPS approved seed material is computed based
 *           on stack usage and thread wait times, this takes 20 seconds or more
 *           to generate. For more information on this entropy collection see our
 *           FIPS documentation.
 *           <p>If the MocSymRandOperator in the initialization structure is not
 *           \c NULL, attempt to initialize and seed the MocSym random
 *           implementation. The FIPS approved seed method will be used if
 *           available unless the \c MOC_INIT_FLAG_NO_AUTOSEED bit is set in the
 *           flags field of the initialization structure. It should be noted it
 *           is an error to attempt to use the FIPS autoseed method for a MocSym
 *           random operator when the \c \__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
 *           build flag is set.
 *           <p>This function will setup and initialize a static memory partition
 *           if requested, as specified in the setup information structure. In
 *           this case the pointer in the setup structure will specify the memory
 *           region to be used by all Mocana functions. That is, the Mocana
 *           functions will not use "malloc" or any other system memory allocator.
 *           All Mocana memory allocations will simply grab some of the area
 *           inside the buffer provided by the caller. The
 *           \c \__ENABLE_DIGICERT_MEM_PART__ flag must be defined to access this
 *           feature.
 *
 * @param pSetupInfo  Pointer to InitMocanaSetupInfo structure containing
 *                    information on initializing the global PRNG.
 * @param ppAlgCtx    The address where the function will deposit an AlgCtx
 *                    containing the Operators from the setupInfo. If this is
 *                    NULL, the function will not build an AlgCtx, but there are
 *                    many functions that require it.
 *
 * @return            \c OK (0) if successful; otherwise a negative number error
 *                    code definition from merrors.h. To retrieve a string
 *                    containing an English text error identifier corresponding
 *                    to the function's returned error status, use the
 *                    \c DISPLAY_ERROR macro.
 *
 * @par Flags
 * To enable this function, the following flag must \b not be defined
 *   + \c \__DISABLE_DIGICERT_INIT__
 *   .
 * Additionally, whether or not the following flags are defined determines which
 * initialization functions are called
 *  + \c \__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
 *  + \c \__DISABLE_DIGICERT_STARTUP_GUARD__
 *  + \c \__DISABLE_DIGICERT_TCP_INTERFACE__
 *  + \c \__DISABLE_DIGICERT_RNG__
 *  + \c \__DISABLE_DIGICERT_ADD_ENTROPY__
 *  + \c \__ENABLE_DIGICERT_SYM__
 *  + \c \__ENABLE_DIGICERT_MEM_PART__
 *  + \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
 *  + \c \__ENABLE_DIGICERT_IKE_SERVER__
 *  + \c \__ENABLE_DIGICERT_DTLS_CLIENT__
 *  + \c \__ENABLE_DIGICERT_DTLS_SERVER__
 *  + \c \__ENABLE_DIGICERT_DEBUG_CONSOLE__
 *  + \c \__HARDWARE_ACCEL_PROTOTYPES__
 *  + \c \__KERNEL__
 *  + \c \__DIGICERT_FORCE_ENTROPY__
 *  + \c IPCOM_KERNEL
 *  + \c UDP_init
 *
 * @note It is an error to try and instantiate a new MocSym random operator
 *       on a nested call.
 *
 * @warning If you are setting up a static memory partition \b and using the default
 *          random number generator, you \b must be sure to explicitly set the
 *          MocSymRandOperator function pointer to NULL.
 *
 * @par Example
 * <p>An example of a simple initialization:
 * @code
 *   sbyte4 status = 0;
 *   status = DIGICERT_initialize(NULL, NULL);
 *   if (OK != status)
 *     goto exit;
 *
 *   . . .
 *
 * exit:
 *   DIGICERT_free(NULL);
 * @endcode
 *
 * <p>An example of an initialization using a MocSym random operator:
 * @code
 *   sbyte4 status = 0;
 *   InitMocanaSetupInfo setupInfo;
 *   MocAlgCtx pAlgCtx = NULL;
 *   MSymOperatorAndInfo pDigestList[3] = {
 *     { SymOperatorSHA1Sw, NULL, NULL },
 *     { SymOperatorSHA224Sw, NULL, NULL },
 *     { SymOperatorSHA256Sw, NULL, NULL }
 *   };
 *   MSymOperatorAndInfo pSymAlgs[4] = {
 *     { SymOperatorHmacTap, NULL, MocTapOperatorCallback },
 *     { SymOperatorAesCbcTap, NULL, MocTapOperatorCallback },
 *     { SymOperatorHmacSw, NULL, NULL },
 *     { SymOperatorAesCbcSw, NULL, NULL }
 *   };
 *   MKeyOperatorAndInfo pAsymKeys[2] = {
 *     { MKeyOperatorEccSw, EccParamsNistP224r1, NULL },
 *     { MKeyOperatorEccSw, EccParamsNistP256r1, NULL }
 *   };
 *
 *   setupInfo.MocSymRandOperator = MDevUrandOperator;
 *   setupInfo.pOperatorInfo = NULL;
 *   setupInfo.flags = MOC_INIT_FLAG_AUTOSEED; // for verbosity, AUTOSEED is default
 *   setupInfo.pDigestOperators = pDigestList;
 *   setupInfo.digestOperatorCount = 3;
 *   setupInfo.pSymOperators = pSymAlgs;
 *   setupInfo.symOperatorCount = 4;
 *   setupInfo.pKeyOperators = pAsymKeys;
 *   setupInfo.keyOperatorCount = 2;
 *
 *   status = DIGICERT_initialize(&setupInfo, &pAlgCtx);
 *   if (OK != status)
 *     goto exit;
 *
 *   . . .
 *
 * exit:
 *   DIGICERT_free(&pAlgCtx);
 * @endcode
 *
 * <p>An example of an initialization using a static memory partition:
 * @code
 *   sbyte4 status = 0;
 *   MocAlgCtx pAlgCtx = NULL;
 *   ubyte *staticMemPartition = calloc(PARTITION_SIZE_BYTES+1, sizeof(ubyte));
 *   InitMocanaSetupInfo setupInfo;
 *
 *   setupInfo.MocSymRandOperator = NULL; // NOTE must be explicitly set to NULL
 *   setupInfo.pOperatorInfo = NULL;
 *   setupInfo.pStaticMem = staticMemPartition;
 *   setupInfo.staticMemSize = PARTITION_SIZE_BYTES;
 *   setupInfo.flags = MOC_INIT_FLAG_AUTOSEED;
 *   setupInfo.pDigestOperators = pDigestList;
 *   setupInfo.digestOperatorCount = 3;
 *   setupInfo.pSymOperators = pSymAlgs;
 *   setupInfo.symOperatorCount = 4;
 *   setupInfo.pKeyOperators = pAsymKeys;
 *   setupInfo.keyOperatorCount = 2;
 *   status = DIGICERT_initialize(&setupInfo, &pAlgCtx);
 *   if (OK != status)
 *     goto exit;
 *
 *   . . .
 *
 * exit:
 *   DIGICERT_free(&pAlgCtx);
 * @endcode
 * @sa DIGICERT_free()
 */
MOC_EXTERN MSTATUS DIGICERT_initialize(
  InitMocanaSetupInfo *pSetupInfo,
  MocCtx *ppAlgCtx
  );

/**
 * @brief    Release memory allocated by DIGICERT_initialize().
 * @details  This function releases memory previously allocated by a call to
 *           DIGICERT_initialize().  If the init function was called more than
 *           once before a free, this function will decrement the internal
 *           reference count and return \c OK.  When the reference count reaches
 *           zero, all memory allocated by DIGICERT_initialize() will be freed
 *           and any associated tasks will be shut down.
 *           <p>If the original initialization call requested a static memory
 *           partition, this function will uninitialize all internal management
 *           operations for that static memory partition.
 *
 * @param    ppAlgCtx The address where the function will find an AlgCtx to free.
 *           The algCtx was created during the call to DIGICERT_initialize. This
 *           can be NULL if the call to DIGICERT_initialize did not request an
 *           AlgCtx.
 *
 * @return   \c OK (0) if successful; otherwise a negative number error code
 *           definition from merrors.h. To retrieve a string containing an
 *           English text error identifier corresponding to the function's
 *           returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @par Flags
 * To enable this function, the following flag must \b not be defined
 *   + \c \__DISABLE_DIGICERT_INIT__
 *   .
 * Additionally, whether or not the following flags are defined determines which
 * uninitialization functions are called
 *  + \c \__DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
 *  + \c \__DISABLE_DIGICERT_STARTUP_GUARD__
 *  + \c \__DISABLE_DIGICERT_TCP_INTERFACE__
 *  + \c \__DISABLE_DIGICERT_RNG__
 *  + \c \__DISABLE_DIGICERT_ADD_ENTROPY__
 *  + \c \__ENABLE_DIGICERT_SYM__
 *  + \c \__ENABLE_DIGICERT_MEM_PART__
 *  + \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
 *  + \c \__ENABLE_DIGICERT_IKE_SERVER__
 *  + \c \__ENABLE_DIGICERT_DTLS_CLIENT__
 *  + \c \__ENABLE_DIGICERT_DTLS_SERVER__
 *  + \c \__ENABLE_DIGICERT_DEBUG_CONSOLE__
 *  + \c \__HARDWARE_ACCEL_PROTOTYPES__
 *  + \c \__KERNEL__
 *  + \c \__DIGICERT_FORCE_ENTROPY__
 *  + \c IPCOM_KERNEL
 *  + \c UDP_init
 * @sa DIGICERT_initialize().
 */
MOC_EXTERN MSTATUS DIGICERT_free (
  MocCtx *ppAlgCtx
  );

#ifdef __cplusplus
}
#endif

#endif /* __INIT_MOCANA_H__ */
