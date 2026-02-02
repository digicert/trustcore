/*
 * mocana.c
 *
 * Mocana Initialization
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
 * @file mocana.c
 */

#define __IN_DIGICERT_C__
#define __ENABLE_DIGICERT_FP_MAPPING_GUARD__

#include "../common/moptions.h"

/* Force Linux file handling for freertos simulator */
#if defined(__FREERTOS_SIMULATOR__) || defined(__RTOS_FREERTOS_ESP32__)
#ifdef __RTOS_FREERTOS__
#undef __RTOS_FREERTOS__
#endif
#ifdef __FREERTOS_RTOS__
#undef __FREERTOS_RTOS__
#endif
#ifndef __LINUX_RTOS__
#define __LINUX_RTOS__
#endif
#ifndef __RTOS_LINUX__
#define __RTOS_LINUX__
#endif
#endif

#if !defined( __RTOS_WIN32__) && !defined(__RTOS_FREERTOS__)
#ifndef __DISABLE_DIGICERT_FILE_SYSTEM_HELPER__
#include <unistd.h>
#ifndef __RTOS_THREADX__
#if defined(__RTOS_ZEPHYR__)
#include <zephyr/fs/fs.h>
#else
#include <dirent.h>
#endif
#include <sys/time.h>
#endif
#if !defined(__RTOS_VXWORKS__) && !defined(__RTOS_THREADX__) && !defined(__RTOS_ZEPHYR__)
#include <termios.h>
#endif /* !__RTOS_VXWORKS__ && !__RTOS_THREADX__ && !__RTOS_ZEPHYR__ */
#endif /* !__DISABLE_DIGICERT_FILE_SYSTEM_HELPER__ */
#endif /* !__RTOS_WIN32__ && !__RTOS_FREERTOS__ */


#include "../common/initmocana.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#if (!defined(__DISABLE_DIGICERT_TCP_INTERFACE__))
#include "../common/mtcp.h"
#endif
#include "../common/utils.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/random.h"
#include "../common/rng_seed.h"

#ifndef __DISABLE_DIGICERT_ADD_ENTROPY__
#include "../crypto/sha1.h"
#include "../crypto/aes.h"
#if !defined(__DISABLE_3DES_CIPHERS__)
#include "../crypto/des.h"
#include "../crypto/three_des.h"
#endif /* ! __DISABLE_3DES_CIPHERS__ */
#include "../crypto/nist_rng.h"
#include "../crypto/nist_rng_ex.h"
#include "../crypto/nist_rng_types.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && (!defined(__DISABLE_DIGICERT_NIST_CTR_DRBG__)))
#include "../crypto_interface/crypto_interface_nist_ctr_drbg.h"
#endif
#endif

#include "../common/debug_console.h"
#if (defined(__ENABLE_DIGICERT_MEM_PART__))
#include "../common/mem_part.h"
#endif
#if (defined(__ENABLE_DIGICERT_HARNESS__))
#include "../harness/harness.h"
#endif

#if defined (__FREERTOS_RTOS__) && !defined(__ENABLE_DIGICERT_NANOPNAC__)
#include "ff.h"
#endif

#if (defined(__ENABLE_DIGICERT_RADIUS_CLIENT__) || defined(__ENABLE_DIGICERT_IKE_SERVER__)) && \
    !(defined(__KERNEL__) || defined(_KERNEL) || defined(IPCOM_KERNEL))
#include "../common/mudp.h"
#endif

#if (defined(__ENABLE_DIGICERT_SSH_SERVER__) || defined(__ENABLE_DIGICERT_PKCS10__) || defined(__ENABLE_DIGICERT_PEM_CONVERSION__))
#include "../common/base64.h"
#endif

#ifdef __DIGICERT_FORCE_ENTROPY__
#include "../common/external_rand_thread.h"
#endif

#ifdef __ENABLE_DIGICERT_CUSTOM_ENTROPY_INJECT__
#include "custom_entropy.h"
#endif

/*------------------------------------------------------------------*/

#ifndef MOC_MAX_BYTES_TO_COPY
#define MOC_MAX_BYTES_TO_COPY 4096
#endif

#ifndef __DISABLE_DIGICERT_ADD_ENTROPY__
#define MOC_ENTROPY_DEPOT_SIZE 64
#ifndef SHA1_RESULT_SIZE
#define SHA1_RESULT_SIZE 20
#endif

#define BITINMODVAL (8 * MOC_ENTROPY_DEPOT_SIZE)
#endif

/*------------------------------------------------------------------*/

/**
@cond
*/
logFn            g_logFn          = NULL;
 MOC_EXTERN_DATA_DEF volatile sbyte4 gMocanaAppsRunning = 0;

#if !defined(__DISABLE_DIGICERT_ADD_ENTROPY__) && !defined(__DISABLE_DIGICERT_NIST_CTR_DRBG__)
static ubyte entropyDepot[MOC_ENTROPY_DEPOT_SIZE + SHA1_RESULT_SIZE];
static ubyte4 entropyIndex = 0;
#endif

/**
 * @endcond
 */


#ifndef __DISABLE_DIGICERT_INIT__
/*------------------------------------------------------------------*/

extern sbyte4 DIGICERT_initDigicertStaticMemory (
  ubyte *pStaticMem,
  ubyte4 staticMemSize
  )
{
  InitMocanaSetupInfo setupInfo;
  setupInfo.MocSymRandOperator = NULL;
  setupInfo.pOperatorInfo = NULL;
  setupInfo.pStaticMem = pStaticMem;
  setupInfo.staticMemSize = staticMemSize;
  setupInfo.flags = MOC_SEED_DEFAULT;
  setupInfo.pDigestOperators = NULL;
  setupInfo.digestOperatorCount = 0;
  setupInfo.pSymOperators = NULL;
  setupInfo.symOperatorCount = 0;
  setupInfo.pKeyOperators = NULL;
  setupInfo.keyOperatorCount = 0;
  return (sbyte4)DIGICERT_initialize(&setupInfo, NULL);
}

/**
@brief      Initialize Mocana %common code base.
@details    This function initializes the Mocana %common code base; it is
            typically the first initialization step for any Mocana Security
            of Things Platform product.
*/
extern sbyte4
DIGICERT_initDigicert(void)
{
  return (sbyte4)DIGICERT_initialize(NULL, NULL);
}
#endif /* __DISABLE_DIGICERT_INIT__ */


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_INIT__
/**
@brief      Release memory allocated by DIGICERT_initDigicert.
@details    This function releases memory previously allocated by a call to
            DIGICERT_initDigicert().
*/
extern sbyte4
DIGICERT_freeDigicert(void)
{
  return (sbyte4)DIGICERT_free(NULL);
}
#endif /* __DISABLE_DIGICERT_INIT__ */

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_ADD_ENTROPY__

#ifndef __DISABLE_DIGICERT_NIST_CTR_DRBG__
static void DIGICERT_SEED_addEntropyBit(ubyte entropyBit)
{
    ubyte4 bitPos;

    bitPos = entropyIndex = ((entropyIndex + 1) % BITINMODVAL);

    if (entropyBit & 1)
    {
        ubyte4  index       = ((bitPos >> 3) % MOC_ENTROPY_DEPOT_SIZE);
        ubyte4  bitIndex    = (bitPos & 7);
        ubyte   byteXorMask = (ubyte) (1 << bitIndex);

        entropyDepot[index] = entropyDepot[index] ^ byteXorMask;
    }
}

/*------------------------------------------------------------------*/

static sbyte4 DIGICERT_addEntropyBitDRBGCTR(randomContext *pRandomContext, ubyte entropyBit)
{
    MSTATUS status = OK;
    RandomCtxWrapper* pWrapper = NULL;
    NIST_CTR_DRBG_Ctx* pCtx = NULL;
    ubyte4 MinBitsNeeded;
    hwAccelDescr hwAccelCtx = 0;

    if (NULL == pRandomContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pWrapper = (RandomCtxWrapper*)pRandomContext;

    pCtx = GET_CTR_DRBG_CTX(pWrapper);
    if (pCtx == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    hwAccelCtx = pWrapper->hwAccelCtx;

    /* Get rid of compiler warnings */
    MOC_UNUSED(hwAccelCtx);

    /* First add the bit into our EntropyDepot */
    DIGICERT_SEED_addEntropyBit(entropyBit);

    pWrapper->reseedBitCounter++;

    /* If we have "enough" new entropy bits, then reseed our context */
    MinBitsNeeded = 48 * 8;

    if (pWrapper->reseedBitCounter < MinBitsNeeded)
    {
        goto exit;
    }

    /* Perform the reseed operation */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_NIST_CTRDRBG_reseed (
        MOC_HASH(hwAccelCtx) pRandomContext, entropyDepot, 48, NULL, 0);
#else
    status = NIST_CTRDRBG_reseed (
        MOC_HASH(hwAccelCtx) pRandomContext, entropyDepot, 48, NULL, 0);
#endif
    if (OK != status)
        goto exit;

    /* Reset the counter */
    pWrapper->reseedBitCounter = 0;

exit:
    return status;
}
#endif /* __DISABLE_DIGICERT_NIST_CTR_DRBG__ */

/*------------------------------------------------------------------*/

/**
@brief      Add a random bit to application's random number generator.
@details    This function adds a random bit to your application's random number
            generator. Before calling this function, your application should
            have already initialized the Mocana %common code base by
            calling DIGICERT_initDigicert().
*/
extern sbyte4
DIGICERT_addEntropyBit(ubyte entropyBit)
{
    MSTATUS status = OK;
    RandomCtxWrapper* pWrapper = NULL;
    ubyte entropySrc = 0;

    if (NULL == g_pRandomContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

/* The kernel module does not export the RANDOM_getEntropySource symbol */
#if !( defined(__KERNEL__) || defined(_KERNEL) || defined(IPCOM_KERNEL) )
    entropySrc = RANDOM_getEntropySource();
#else
    entropySrc = ENTROPY_SRC_EXTERNAL;
#endif

    pWrapper = (RandomCtxWrapper*)g_pRandomContext;

#ifndef __DISABLE_DIGICERT_NIST_CTR_DRBG__
    /* If this is injecting external entropy for a ctr-drbg rng, collect the entropy
     * manually and call the reseed directly */
    if ( (ENTROPY_SRC_EXTERNAL == entropySrc) &&
         (TRUE == IS_CTR_DRBG_CTX(pWrapper)) )
    {
        status = DIGICERT_addEntropyBitDRBGCTR(g_pRandomContext, entropyBit);
    }
    else
#endif
    {
        status = RANDOM_addEntropyBit(g_pRandomContext, entropyBit);
    }

exit:
    return status;
}

#endif /* __DISABLE_DIGICERT_ADD_ENTROPY__ */

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_ADD_ENTROPY__
/**
 * @brief      Add 32 random bits to application's random number generator.
 * @details    This function adds 32 random bits to your application's random
 *             number generator. Before calling this function, your application
 *             should have already initialized the Mocana %common code base by
 *             calling DIGICERT_initDigicert().
 */
extern sbyte4
DIGICERT_addEntropy32Bits(ubyte4 entropyBits)
{
    ubyte4  count;
    MSTATUS status = OK;

    for (count = 32; count > 0; count--)
    {
        if (OK > (status = DIGICERT_addEntropyBit((ubyte)(entropyBits & 1))))
            break;

        entropyBits >>= 1;
    }

    return (sbyte4)status;
}
#endif /* __DISABLE_DIGICERT_ADD_ENTROPY__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CUSTOM_ENTROPY_INJECT__

extern sbyte4
DIGICERT_addCustomEntropyInjection(void)
{
    MSTATUS status;
    ubyte4 i = 0;
    ubyte4 j = 0;
    ubyte byte = 0;
    ubyte pEntropy[MOC_CUSTOM_ENTROPY_LEN] = {0};

    /* Get the custom entropy */
    status = DIGICERT_CUSTOM_getEntropy(pEntropy, MOC_CUSTOM_ENTROPY_LEN);
    if (OK != status)
        goto exit;

    for (i = 0; i < MOC_CUSTOM_ENTROPY_LEN; i++)
    {
        byte = pEntropy[i];
        for (j = 8; j > 0; j--)
        {
            status = DIGICERT_addEntropyBit(byte & 1);
            if (OK != status)
                goto exit;

            byte >>= 1;
        }
    }

exit:
    byte = 0;
    DIGI_MEMSET(pEntropy, 0, MOC_CUSTOM_ENTROPY_LEN);
    return status;
}

#endif /* ifdef __ENABLE_DIGICERT_CUSTOM_ENTROPY_INJECT__ */

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_FILE_SYSTEM_HELPER__
#if !defined(__ENABLE_DIGICERT_NANOPNAC__) && !defined(__RTOS_ZEPHYR__)
int DIGICERT_opendir(void **pDirInfo, const char *pPath)
{
    MSTATUS status = OK;
#if !defined(__WIN32_RTOS__) && !defined(__RTOS_THREADX__)
    DIR *pDir = NULL;
#endif

    if (!pDirInfo || !pPath)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
#if defined (__FREERTOS_RTOS__)
    FRESULT fscode;
    pDir = MC_MALLOC(sizeof(DIR));
    if (!pDir)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    fscode = f_opendir(pDir, pPath);
    if (fscode != FR_OK)
    {
        status = ERR_DIR_OPEN_FAILED;
        goto exit;
    }
    *pDirInfo = (void *)pDir;
#elif (defined (__LINUX_RTOS__) || defined(__RTOS_OSX__))
    pDir = opendir(pPath);
    if (!pDir)
    {
        status = ERR_DIR_OPEN_FAILED;
        goto exit;
    }
    *pDirInfo = (void *)pDir;
#elif defined (__VXWORKS_RTOS__)
    pDir = opendir(pPath);
    if (!pDir)
    {
        status = ERR_DIR_OPEN_FAILED;
        goto exit;
    }
    *pDirInfo = (void *)pDir;
#endif

exit:
    return (int) status;
}

int DIGICERT_readdir(void *pDir, void **pFileInfo)
{
    MSTATUS status = OK;
#if (defined (__LINUX_RTOS__) || defined (__VXWORKS_RTOS__) || defined (__RTOS_OSX__))
    struct dirent *pEnt;
#endif

    if(!pDir || !pFileInfo)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
#if defined (__FREERTOS_RTOS__)
    FRESULT fscode;
    fscode = f_readdir((DIR *)pDir, (FILINFO *)pFileInfo);
    if(fscode != FR_OK)
    {
        status = ERR_DIR_READ_FAILED;
        goto exit;
    }
#elif (defined (__LINUX_RTOS__) || defined(__RTOS_OSX__))
    pEnt = readdir((DIR *)pDir);
    if(!pEnt)
    {
        status = ERR_DIR_READ_FAILED;
        goto exit;
    }
    *pFileInfo = (void *)pEnt;
#elif defined (__VXWORKS_RTOS__)
    pEnt = readdir((DIR *)pDir);
    if(!pEnt)
    {
        status = ERR_DIR_READ_FAILED;
        goto exit;
    }
    *pFileInfo = (void *)pEnt;
#endif
exit:
    return (int) status;
}


int DIGICERT_closedir(void *pDir)
{
    MSTATUS status = OK;
    if(!pDir )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
#if defined (__FREERTOS_RTOS__)
    FRESULT fscode;
    fscode = f_closedir((DIR *)pDir);
    MC_FREE(pDir);
    if(fscode != FR_OK)
    {
        status = ERR_DIR_CLOSE_FAILED;
        goto exit;
    }
#elif (defined (__LINUX_RTOS__) || defined (__RTOS_OSX__))
    if(closedir((DIR *)pDir))
    {
        status = ERR_DIR_CLOSE_FAILED;
        goto exit;
    }
#elif defined (__VXWORKS_RTOS__)
    if(closedir((DIR *)pDir))
    {
        status = ERR_DIR_CLOSE_FAILED;
        goto exit;
    }
#endif
exit:
    return (int) status;
}
#endif

/**
 * @brief      Allocate a buffer and fill with data read from a file.
 * @details    This function allocates a buffer and then fills it with data read
 *             from a file.
 */
MOC_EXTERN sbyte4
DIGICERT_readFile(const char* pFilename, ubyte **ppRetBuffer, ubyte4 *pRetBufLength)
{
    return (sbyte4)UTILS_readFile(pFilename, ppRetBuffer, pRetBufLength);
}
#endif /* __DISABLE_DIGICERT_FILE_SYSTEM_HELPER__ */


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_FILE_SYSTEM_HELPER__
/**
 * @brief      Release memory allocated by DIGICERT_readFile().
 * @details    This function releases memory previously allocated by a call to
 *             DIGICERT_readFile().
 */
extern sbyte4
DIGICERT_freeReadFile(ubyte **ppRetBuffer)
{
    return (sbyte4)UTILS_freeReadFile(ppRetBuffer);
}
#endif /* __DISABLE_DIGICERT_FILE_SYSTEM_HELPER__ */


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_FILE_SYSTEM_HELPER__
/**
 * @brief      Write a buffer's contents to a file.
 * @details    This function writes a data buffer's contents to a file.
 */
extern sbyte4
DIGICERT_writeFile(const char* pFilename, const ubyte *pBuffer, ubyte4 bufLength)
{
    return (sbyte4)UTILS_writeFile(pFilename, pBuffer, bufLength);
}
#endif /* __DISABLE_DIGICERT_FILE_SYSTEM_HELPER__ */

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_FILE_SYSTEM_HELPER__
/**
 * @brief      Appends a buffer's contents to a file, file is created if
 *             it does not exist.
 * @details    This function appends a data buffer's contents to a file.
 */
extern sbyte4
DIGICERT_appendFile(const char* pFilename, const ubyte *pBuffer, ubyte4 bufLength)
{
    return (sbyte4)UTILS_appendFile(pFilename, pBuffer, bufLength);
}
#endif /* __DISABLE_DIGICERT_FILE_SYSTEM_HELPER__ */

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_FILE_SYSTEM_HELPER__

extern sbyte4
DIGICERT_copyFile(const char *pSrcFilename, const char *pDestFilename)
{
    return (sbyte4)UTILS_copyFile(pSrcFilename, pDestFilename, MOC_MAX_BYTES_TO_COPY);
}

#endif /* __DISABLE_DIGICERT_FILE_SYSTEM_HELPER__ */

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_FILE_SYSTEM_HELPER__

extern sbyte4
DIGICERT_deleteFile(const char *pFilename)
{
    return (sbyte4)UTILS_deleteFile(pFilename);
}

#endif /* __DISABLE_DIGICERT_FILE_SYSTEM_HELPER__ */

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_FILE_SYSTEM_HELPER__

extern sbyte4 DIGICERT_checkFile(
    const char *pFilename, const char *pExt, intBoolean *pFileExist)
{
    return (sbyte4) UTILS_checkFile(pFilename, pExt, pFileExist);
}

#endif /* __DISABLE_DIGICERT_FILE_SYSTEM_HELPER__ */

/*------------------------------------------------------------------*/

/**
 * @brief      Register a callback function for the Mocana logging system.
 * @details    This function registers a callback function for the Mocana SoT
 *             Platform logging system.
 */
extern sbyte4
DIGICERT_initLog(logFn lFn)
{
    /* fine to set callback to null, if you wish to disable logging */
    g_logFn = lFn;

    /* New flag __ENABLE_DIGICERT_PRODUCT_DEBUG_CONSOLE__ is added to NOT print this message,
     * when a production system enables Mocana debug logs
     */
#if (defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__) && !defined(__ENABLE_DIGICERT_PRODUCT_DEBUG_CONSOLE__))
    DIGICERT_log(MOCANA_MSS, LS_WARNING, (sbyte *)"NOT A PRODUCTION BUILD: DIGICERT DEBUG CONSOLE HAS BEEN ENABLED.");
#endif

    return (sbyte4)OK;
}

/*------------------------------------------------------------------*/

/**
 * @private
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation (regardless of product).
 */
extern void
DIGICERT_log(sbyte4 module, sbyte4 severity, sbyte *msg)
{
    if ((NULL != g_logFn) && (NULL != msg))
        (*g_logFn)(module, severity, msg);
}

