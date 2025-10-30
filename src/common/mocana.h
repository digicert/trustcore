/**
 * @file mocana.h
 *
 * @ingroup common_tree
 * @ingroup common_nanotap_tree
 *
 * @brief   Mocana SoT Platform initialization header file.
 * @details This header file contains enumerations and initialization function
 *          declarations used by all Mocana SoT Platform components.
 *
 * @flags
 * Whether the following flags are defined determines which additional header files
 * are included:
 *   + \c \__ENABLE_MOCANA_IKE_SERVER__
 *   + \c \__ENABLE_MOCANA_MEM_PART__
 *   + \c \__ENABLE_MOCANA_PEM_CONVERSION__
 *   + \c \__ENABLE_MOCANA_PKCS10__
 *   + \c \__ENABLE_MOCANA_RADIUS_CLIENT__
 *   + \c \__ENABLE_MOCANA_SSH_SERVER__
 *   + \c \__DISABLE_MOCANA_INIT__
 *   + \c \__DISABLE_MOCANA_TCP_INTERFACE__
 *   + \c IPCOM_KERNEL
 *
 * Whether the following flags are defined determines which function declarations
 * are enabled:
 *   + \c \__DISABLE_MOCANA_ADD_ENTROPY__
 *   + \c \__DISABLE_MOCANA_FILE_SYSTEM_HELPER__
 *   + \c \__DISABLE_MOCANA_INIT__
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


/*------------------------------------------------------------------*/

#ifndef __MOCANA_HEADER__
#define __MOCANA_HEADER__

#include "merrors.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef MOC_EXTERN_MOCANA_H
#undef MOC_EXTERN_MOCANA_H
#endif /* MOC_EXTERN_MOCANA_H */

#ifdef __RTOS_WIN32__

#ifdef WIN_EXPORT_INITIALIZE
#define MOC_EXTERN_MOCANA_H __declspec(dllexport)
#else
#define MOC_EXTERN_MOCANA_H __declspec(dllimport) extern
#endif /* WIN_EXPORT_INITIALIZE */

#ifdef WIN_STATIC
#undef MOC_EXTERN_MOCANA_H
#define MOC_EXTERN_MOCANA_H extern
#endif /* WIN_STATIC */

#else

#define MOC_EXTERN_MOCANA_H extern

#endif /* RTOS_WIN32 */

#ifdef MOC_EXTERN_P
#undef MOC_EXTERN_P
#endif /* MOC_EXTERN_P */

#define MOC_EXTERN_P MOC_EXTERN_MOCANA_H

/** @cond */

/**
 * @private
 * @internal
 */
enum moduleNames
{
    MOCANA_MSS,
    MOCANA_SSH,
    MOCANA_SSL,
    MOCANA_SCEP,
    MOCANA_IPSEC,
    MOCANA_IKE,
    MOCANA_RADIUS,
    MOCANA_EAP,
    MOCANA_HTTP,
    MOCANA_TEST,
    MOCANA_FIREWALL,
    MOCANA_OCSP,
    MOCANA_SRTP,
    MOCANA_SYSLOG,
    MOCANA_SECMOD,
    MOCANA_TPM12,
    MOCANA_TAP,
    MOCANA_EST,
    MOCANA_DATA_PROTECT,
    MOCANA_UM,
    MOCANA_DEVICE_PROTECT,
    MOCANA_END
};

/**
 * @private
 * @internal
 */
enum logSeverity
{
    LS_CRITICAL,
    LS_MAJOR,
    LS_MINOR,
    LS_WARNING,
    LS_INFO
};

/** @endcond */

/**
 * @ingroup    common_nanotap_callback_functions
 * @ingroup    common_callback_functions
 *
 * @brief Callback for logging function
 *
 * @details Users can create custom logging functions and register them via MOCANA_initLog(),
 *          provided the custom functions have this signature.
 *         <p> For example, you can define a custom logging function as follows:
 *
 * @code
 *      void MY_logFn(sbyte4 module, sbyte4 severity, sbyte *msg)
 *      {
 *         <custom logging code>
 *      }
 * @endcode
 *
 * You would then register the custom logging function as follows:
 *
 * @code
 *      status = MOCANA_initLog(MY_logFn);
 *      if (OK != status)
 *      {
 *         <error handling code>
 *      }
 * @endcode
 */
typedef void (*logFn)(sbyte4 module, sbyte4 severity, sbyte *msg);

typedef sbyte4 (*ShutdownHandler)(void);

/** @cond */
/**
 * @private
 * @internal
 * @ingroup    common_nanotap_functions
 */
MOC_EXTERN_P volatile sbyte4 gMocanaAppsRunning;
/** @endcond */

MOC_EXTERN_MOCANA_H ShutdownHandler g_sslShutdownHandler;

/*------------------------------------------------------------------*/

/**
 * @cond __INCLUDE_DOXYGEN_FOR_PROTOS_IN_DOT_H__
 */
#ifndef __DISABLE_MOCANA_INIT__

/**
 * @ingroup    common_functions
 * @ingroup    common_nanotap_functions
 *
 * @brief      Initialize Mocana %common code base. This is an older function,
 *             you should use MOCANA_initialize instead (see initmocana.h).
 * @details    This function initializes the Mocana %common code base; it is
 *             typically the first initialization step for any Mocana Security
 *             of Things Platform product.
 *             <p>This will also create and seed a pseudo random number
 *             generator. There are four ways this PRNG can be seeded.
 *             <p>First, if you do not set any build flags for PRNG seed, the
 *             NanoCrypto code will create a PRNG and seed it using the time of
 *             day, some "stack state" (whatever happens to be on the stack at
 *             the time of execution), along with a set of values derived from
 *             thread wait times (our FIPS documentation describes the process
 *             and how it produces entropy). This method will take 20 seconds or
 *             more to generate the seed material.
 *             <p>Second, if you set the __ENABLE_MOCANA_DEV_URANDOM__ build
 *             flag, NanoCrypto will seed using 128 bytes from /dev/urandom
 *             and no bytes from stack state.
 *             <p>Third, if you set the __DISABLE_MOCANA_RAND_ENTROPY_THREADS__
 *             build flag, NanoCrypto will not use its thread wait seed
 *             collection technique (no 20 second wait).
 *             <p>Fourth, you can always add seed material of your own using
 *             RNG_SEED_addEntropyBit, MOCANA_addEntropyBit, or
 *             MOCANA_addEntropy32Bits.
 *             <p>The most secure is using the build flag
 *             __ENABLE_MOCANA_DEV_URANDOM__, and not using
 *             __DISABLE_MOCANA_RAND_ENTROPY_THREADS__. But if you do not want to
 *             wait for the thread wait algorithm to complete, then you should
 *             still use __ENABLE_MOCANA_DEV_URANDOM__ if possible.
 * <pre>
 * <code>
 *    build flags                              NanoCrypto entropy
 *  ---------------------------------------------------------------
 *   no build flags                            20 seconds or more
 *                                             thread wait time
 *                                             time of day
 *                                             stack state
 *
 *   __ENABLE_MOCANA_DEV_URANDOM__             20 seconds or more
 *                                             thread wait time
 *                                             time of day
 *                                             /dev/urandom
 *
 *   __DISABLE_MOCANA_RAND_ENTROPY_THREADS__   milliseconds
 *   __ENABLE_MOCANA_DEV_URANDOM__             time of day
 *                                             /dev/urandom
 *
 *   __DISABLE_MOCANA_RAND_ENTROPY_THREADS__   milliseconds
 *                                             time of day
 *                                             stack state
 * </code>
 * </pre>
 *
 * @flags
 * To enable this function, the following flag must \b not be defined:
 *  + \c \__DISABLE_MOCANA_INIT__
 *
 * Additionally, whether or not the following flags are defined determines which
 * initialization functions are called:
 *  + \c \__DISABLE_MOCANA_RAND_ENTROPY_THREADS__
 *  + \c \__ENABLE_MOCANA_DEV_URANDOM__
 *  + \c \__DISABLE_MOCANA_STARTUP_GUARD__
 *  + \c \__ENABLE_MOCANA_DEBUG_CONSOLE__
 *  + \c \__ENABLE_MOCANA_DTLS_CLIENT__
 *  + \c \__ENABLE_MOCANA_DTLS_SERVER__
 *  + \c \__ENABLE_MOCANA_IKE_SERVER__
 *  + \c \__ENABLE_MOCANA_PEM_CONVERSION__
 *  + \c \__ENABLE_MOCANA_PKCS10__
 *  + \c \__ENABLE_MOCANA_RADIUS_CLIENT__
 *  + \c \__ENABLE_MOCANA_SSH_SERVER__
 *  + \c \__KERNEL__
 *  + \c UDP_init
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @code
 * sbyte4 status = 0;
 * status = MOCANA_initMocana();
 * @endcode
 *
 */
MOC_EXTERN sbyte4  MOCANA_initMocana(void);

/**
 * @brief      Release memory allocated by MOCANA_initMocana.
 * @details    This function releases memory previously allocated by a call to
 *             MOCANA_initMocana().
 *
 * @ingroup    common_functions
 * @ingroup    common_nanotap_functions
 *
 * @flags
 * To enable this function, the following flag must \b not be defined:
 *  + \c \__DISABLE_MOCANA_INIT__
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @code
 * int status = 0;
 * status = MOCANA_freeMocana();
 * @endcode
*/
MOC_EXTERN sbyte4  MOCANA_freeMocana(void);

/**
 * @brief This is the same as initMocana, except it will set up static memory.
 * This is an older function, you should use MOCANA_initialize instead (see
 * initmocana.h).
 *
 * @details The caller passes in a buffer which will be all the memory the Mocana
 * functions will use. That is, the Mocana functions will not use "malloc" or
 * "GlobalAlloc" or any other system memory allocator. All Mocana memory
 * allocations will simply grab some of the area inside the buffer provided by
 * the caller.
 * <p>Whether you call MOCANA_initMocana or MOCANA_initMocanaStaticMem, you must
 * call MOCANA_freeMocana when you are done.
 * <p>See the documentation for MOCANA_initMocana for more information.
 *
 * @ingroup    common_functions
 *
 * @param pStaticMem The buffer that will be used as the source of memory.
 * @param staticMemSize The size, in bytes, of the staticMem buffer.
 *  @inc_file mocana.h
 *
 *  @return     \c OK (0) if successful; otherwise a negative number error code
 *  definition from merrors.h. To retrieve a string containing an
 *  English text error identifier corresponding to the function's
 *  returned error status, use the \c DISPLAY_ERROR macro.
 *
 */
MOC_EXTERN sbyte4  MOCANA_initMocanaStaticMemory (
  ubyte *pStaticMem, ubyte4 staticMemSize);
#endif

/**
 * @brief      Register a callback function for the Mocana logging system.
 * @details    This function registers a callback function for the Mocana SoT
 *             Platform logging system.
 *
 * @ingroup    common_functions
 * @ingroup    common_nanotap_functions
 *
 * @flags
 * To enable this function, the following flag must \b not be defined:
 *  + \c \__DISABLE_MOCANA_FILE_SYSTEM_HELPER__
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @param [in] lFn  Callback function that you want to receive notification of
 *                  Mocana logging events.
 *
 * @code
 * sbyte4 status = 0;
 * status = MOCANA_initLog(myEventHandler);
 * @endcode
 *
 * @remark     This is a convenience function provided for your application's use;
 *             it is not used by Mocana SoT Platform code.
 */
MOC_EXTERN sbyte4  MOCANA_initLog(logFn lFn);


/**
 * @private
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation (regardless of product).
 */
MOC_EXTERN void MOCANA_log(sbyte4 module, sbyte4 severity, sbyte *msg);

#ifndef __DISABLE_MOCANA_ADD_ENTROPY__
/**
 * @brief      Add a random bit to application's random number generator.
 * @details    This function adds a random bit to your application's random number
 *             generator. Before calling this function, your application should
 *             have already initialized the Mocana %common code base by
 *             calling MOCANA_initMocana().
 *
 * @ingroup    common_functions
 *
 *
 * @flags
 * To enable this function, the following flag must \b not be defined:
 *   + \c \__DISABLE_MOCANA_ADD_ENTROPY__
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @param [in] entropyBit   1-bit \c char used to add randomness to your
 *                     application's cryptography.
 *
 * @code
 * sbyte4 status = 0;
 * ubyte ebit;
 * status = MOCANA_addEntropyBit(ebit);
 * @endcode
 */
MOC_EXTERN sbyte4  MOCANA_addEntropyBit(ubyte entropyBit);


/**
 * @brief      Add 32 random bits to application's random number generator.
 * @details    This function adds 32 random bits to your application's random
 *             number generator. Before calling this function, your application
 *             should have already initialized the Mocana %common code base by
 *             calling MOCANA_initMocana().
 *
 * @ingroup    common_functions
 * @ingroup    common_nanotap_functions
 *
 * @flags
 * To enable this function, the following flag must \b not be defined:
 *   + \c \__DISABLE_MOCANA_ADD_ENTROPY__
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @param [in] entropyBits  32-bit \c integer used to add randomness to your
 *                     application's cryptography.
 *
 * @code
 * sbyte4 status = 0;
 * ubyte4 ebit;
 * status = MOCANA_addEntropy32Bits(ebit);
 * @endcode
 */
MOC_EXTERN sbyte4  MOCANA_addEntropy32Bits(ubyte4 entropyBits);
#endif

#ifndef __DISABLE_MOCANA_FILE_SYSTEM_HELPER__

/**
 * @brief      Allocate a buffer and fill with data read from a file.
 * @details    This function allocates a buffer and then fills it with data read
 *             from a file.
 *
 * @ingroup    common_functions
 * @ingroup    common_nanotap_functions
 *
 * @flags
 * To enable this function, the following flag must \b not be defined:
 *  + \c \__DISABLE_MOCANA_FILE_SYSTEM_HELPER__
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @param [in]  pFilename      Name of the file from which to read.
 * @param [out] ppRetBuffer    Reference to the pointer to a data buffer containing
 *                             data read from the file.
 * @param [out] pRetBufLength  Reference to length of the data buffer in bytes.
 *
 * @code
 * sbyte4 status;
 * ubyte *pCertificate = NULL;
 * ubyte4 retCertLength = 0;
 *
 * if (0 > (status = MOCANA_readFile(CERTIFICATE_DER_FILE, &pCertificate, &retCertLength)))
 *     goto exit;
 * @endcode
 *
 * @memory     Memory allocated b this function must be freed by a subsequent call
 *             to MOCANA_freeReadFile().
 *
 * @remark     This is a convenience function provided for your application's use;
 *             it is not used by Mocana SoT Platform code.
 */
MOC_EXTERN sbyte4 MOCANA_readFile(const char* pFilename, ubyte **ppRetBuffer, ubyte4 *pRetBufLength);

/**
 * @brief      Release memory allocated by MOCANA_readFile().
 * @details    This function releases memory previously allocated by a call to
 *             MOCANA_readFile().
 *
 * @ingroup    common_functions
 * @ingroup    common_nanotap_functions
 *
 * @flags
 * To enable this function, the following flag must \b not be defined:
 *  + \c \__DISABLE_MOCANA_FILE_SYSTEM_HELPER__
 *
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @param ppRetBuffer  Reference to the data buffer to free.
 *
 * @code
 * ubyte *pCertificate;
 * ...
 * status = MOCANA_freeReadFile(&pCertificate);
 * @endcode
 *
 * @remark     This is a convenience function provided for your application's use;
 *             it is not used by Mocana SoT Platform code.
 */
MOC_EXTERN sbyte4 MOCANA_freeReadFile(ubyte **ppRetBuffer);

/**
 * @brief      Write a buffer's contents to a file.
 * @details    This function writes a data buffer's contents to a file.
 *
 * @ingroup    common_functions
 * @ingroup    common_nanotap_functions
 *
 * @flags
 * To enable this function, the following flag must \b not be defined:
 *  + \c \__DISABLE_MOCANA_FILE_SYSTEM_HELPER__
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @param [in] pFilename    Pointer to name of the file to write to.
 * @param [in] pBuffer      Pointer to buffer containing data to write to the file.
 * @param [in] bufLength    Number of bytes in \p pBuffer.
 *
 * @code
 * sbyte4 status = 0;
 * status = MOCANA_writeFile(CERTIFICATE_DER_FILE, pCertificate, retCertLength);
 * @endcode
 *
 * @remark     This is a convenience function provided for your application's use;
 *             it is not used by Mocana SoT Platform code.
 */
MOC_EXTERN sbyte4 MOCANA_writeFile(const char* pFilename, const ubyte *pBuffer, ubyte4 bufLength);

/**
 * @brief      Appends a buffer's contents to a file, file is created if
 *             it does not exist.
 * @details    This function appends a data buffer's contents to a file.
 *
 * @ingroup    common_functions
 * @ingroup    common_nanotap_functions
 *
 * @flags
 * To enable this function, the following flag must \b not be defined:
 *  + \c \__DISABLE_MOCANA_FILE_SYSTEM_HELPER__
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @param [in] pFilename    Pointer to name of the file to write to.
 * @param [in] pBuffer      Pointer to buffer containing data to write to the file.
 * @param [in] bufLength    Number of bytes in \p pBuffer.
 *
 * @code
 * sbyte4 status = 0;
 * status = MOCANA_writeFile(CERTIFICATE_DER_FILE, pCertificate, retCertLength);
 * @endcode
 *
 * @remark     This is a convenience function provided for your application's use;
 *             it is not used by Mocana SoT Platform code.
 */
MOC_EXTERN sbyte4 MOCANA_appendFile(const char* pFilename, const ubyte *pBuffer, ubyte4 bufLength);

/**
 * @brief      Copy a file.
 *
 * @flags
 * To enable this function, the following flag must \b not be defined:
 *  + \c \__DISABLE_MOCANA_FILE_SYSTEM_HELPER__
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @param [in] pSrcFilename     Pointer to name of the source file to copy.
 * @param [in] pDestFilename    Pointer to name of the destination file.
 *
 * @remark     This is a convenience function provided for your application's use;
 *             it is not used by Mocana SoT Platform code.
 */
MOC_EXTERN sbyte4 MOCANA_copyFile(const char *pSrcFilename, const char *pDestFilename);

/**
 * @brief      Delete a file from the filesystem.
 *
 * @flags
 * To enable this function, the following flag must \b not be defined:
 *  + \c \__DISABLE_MOCANA_FILE_SYSTEM_HELPER__
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @param [in] pFilename    Pointer to name of the file to delete.
 *
 * @remark     This is a convenience function provided for your application's use;
 *             it is not used by Mocana SoT Platform code.
 */
MOC_EXTERN sbyte4 MOCANA_deleteFile(const char *pFilename);

/**
 * @brief      Check if a file exists on the filesystem.
 *
 * @flags
 * To enable this function, the following flag must \b not be defined:
 *  + \c \__DISABLE_MOCANA_FILE_SYSTEM_HELPER__
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @param [in]  pFilename   Pointer to name of the file to delete.
 * @param [in]  pExt        Optional extension that will be appended onto the
 *                          filename if provided.
 * @param [out] pFileExist  Reference to a pointer that will be set to TRUE if
 *                          the file exists, otherwise it will be FALSE.
 *
 */
MOC_EXTERN sbyte4 MOCANA_checkFile(
    const char *pFilename, const char *pExt, intBoolean *pFileExist);

#endif

/**
 * @private
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation (regardless of product).
 */
MOC_EXTERN MSTATUS MOCANA_opendir(void **pDirInfo, const char *pPath);

/**
 * @private
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation (regardless of product).
 */
MOC_EXTERN MSTATUS MOCANA_readdir(void *pDir, void **pFileInfo);

/**
 * @private
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation (regardless of product).
 */
MOC_EXTERN MSTATUS MOCANA_closedir(void *pDir);

/**
 * @endcond
 */

#ifndef MOC_DP_MAPPING_RELEASE
#define MOC_DP_MAPPING_RELEASE TRUE
#endif

#if ( (defined(__ENABLE_MOCANA_FP_MAPPING_READ__)) && \
      (!defined(__ENABLE_MOCANA_FP_MAPPING_GUARD__)) )

#include "../data_protection/file_protect.h"

#define MOCANA_readFile(_file, _retBuf, _retLen)                              \
    MOCANA_readFileEx(_file, _retBuf, _retLen, MOC_DP_MAPPING_RELEASE)

#endif

#if ( (defined(__ENABLE_MOCANA_FP_MAPPING_WRITE__)) && \
      (!defined(__ENABLE_MOCANA_FP_MAPPING_GUARD__)) )

#include "../data_protection/file_protect.h"

#ifndef __DISABLE_MOCANA_FP_IMMUTABLE_WRITE_BUFFER__

#define MOCANA_writeFile(_file, _buf, _bufLen)                                \
    MOCANA_writeFileEx(_file, _buf, _bufLen, MOC_DP_MAPPING_RELEASE)

#else

#define MOCANA_writeFile(_file, _buf, _bufLen)                                \
    MOCANA_writeFileEx(_file, (ubyte *)_buf, _bufLen, MOC_DP_MAPPING_RELEASE)

#endif /* ifdef __DISABLE_MOCANA_FP_IMMUTABLE_WRITE_BUFFER__ */

#endif /* if (defined(__ENABLE_MOCANA_FP_MAPPING_WRITE__)) && (!defined(__ENABLE_MOCANA_FP_MAPPING_GUARD__)) */

#ifdef __cplusplus
}
#endif

#endif /* __MOCANA_HEADER__ */
