/*
 * fips_utils.c
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 */

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "fips_utils.h"

#include "../common/debug_console.h"
#include "../crypto/fips.h"
#include "../common/mfmgmt.h"

#if defined(__RTOS_LINUX__) || defined(__RTOS_VXWORKS__)
#ifndef __KERNEL__
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#endif /* __KERNEL__ */
#endif /* __RTOS_LINUX__ or __RTOS_VXWORKS__ */


/* --------------------------------------------
 * RANDOM Context external entropy seeding.
 * Required.
 * Note: The FIPS library requires that all random contexts must have 384 bits of entropy
 * added before random numbers can be generated.
 */
#define NUM_OF_ENTROPY_BITS_REQUIRED  (384/32)  /* Adding 32-bits of data at a time and required entropy is 384 bits */

#define CRYPTO_EXAMPLE_LINUX_RAND_FILE "/dev/urandom"

/* --------------------------------------------
 * __FIPS_UTILS_FORCE_EARLY_FIPS_ALGO_TESTS__ : Force early FIPS Self test completion.
 * Note: FIPS will automatically call the FIPS self test per algorithm upon first use of the algorithm.
 * This is optional, and may not be optimal, but is provided as an example of forcing the early execution of the
 * FIPS self tests, rather than have them execute upon first use per algo.
 */
#define __FIPS_UTILS_FORCE_EARLY_FIPS_ALGO_TESTS__

/*
 * __FIPS_UTILS_SKIP_** : Specifically skip sets of algorithms: (i.e. allow them to run upon first use)
 */
/* #define __FIPS_UTILS_SKIP_KAT_TESTS__ */
/* #define __FIPS_UTILS_SKIP_DH_AND_HMAC_KDF_TESTS__ */
/* #define __FIPS_UTILS_SKIP_ASYM_TESTS__ */

/* --------------------------------------------
 * __FIPS_UTILS_PERSIST_FIPS_ALGO_TESTS_STATE__ : Save the state of the FIPS self test results.
 * This is optional, and may not be optimal, and may have no effect for several reasons:
 *    (e.g. platform does not support saved ALGO state or the calling application does not have write permission
 *     to the saved state file).
 *
 * Ideally, the saved state should be done by a single application during platform O/S initialization, and all
 * other applications that use the FIPS library will not need to perform any FIPS self tests, nor saving of the state.
 *
 */
#define __FIPS_UTILS_PERSIST_FIPS_ALGO_TESTS_STATE__

/*---------------------------------------------------------------------------*/
/* Internal functions */
/*---------------------------------------------------------------------------*/

#if ((defined (__RTOS_LINUX__) || defined(__RTOS_VXWORKS__)) && !defined(__KERNEL__ ) && !defined(__DISABLE_DIGICERT_ADD_ENTROPY__))
/*---------------------------------------------------------------------------*/
/* Entropy related functions */
/*---------------------------------------------------------------------------*/

static sbyte4 addEntropy32Bits(randomContext* pRandomContext, ubyte4 entropyBits)
{
    ubyte4  count;
    MSTATUS status = OK;

    for (count = 32; count > 0; count--)
    {
        status = RANDOM_addEntropyBit(pRandomContext, (entropyBits & 1));
        if (OK != status)
        {
            goto exit;
        }
        entropyBits >>= 1;
    }

    exit:
    return (sbyte4)status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS read32bits(int fd, ubyte4 *val)
{
    unsigned char randReadBuf[8];
    int  remLen = 4, rlen, offs=0, i;

    *val = 0;

    DIGI_MEMSET(randReadBuf, 0x00, 8);
    while (remLen > 0)
    {
        rlen = read(fd, randReadBuf, remLen);
        if (rlen <= 0)
        {
            return ERR_FILE_READ_FAILED;
        }
        remLen -= rlen;
        for (i = 0; i < rlen; ++i)
            *val |= randReadBuf[i] << (8*(offs+i));
        offs += rlen;
    }

    return OK;
}

/*---------------------------------------------------------------------------*/

static MSTATUS addExternalEntropy(
        randomContext* pRandomContext, ubyte4 count)
{
    MSTATUS status = OK;

    int fd=-1, rval=-1;
    ubyte4  randVal=0;
    int i = 0;

    fd = open(CRYPTO_EXAMPLE_LINUX_RAND_FILE, O_RDONLY);
    if (fd < 0)
        goto exit;

    for (i = 0; i < count; i++)
    {
        randVal=0;
        rval = read32bits(fd, &randVal);

        if (OK > rval)
        {
            goto exit;
        }

        status = addEntropy32Bits(pRandomContext, randVal);
        if (OK != status)
        {
            goto exit;
        }
    }

    exit:
    if (0 <= fd)
    {
        close(fd);
    }
    return status;
}

#else
static MSTATUS addExternalEntropy(
        randomContext* pRandomContext, ubyte4 count)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif  /* ((defined (__RTOS_LINUX__) || defined(__RTOS_VXWORKS__)) && !defined(__KERNEL__ ) && !defined(__DISABLE_DIGICERT_ADD_ENTROPY__)) */

/*---------------------------------------------------------------------------*/

static MSTATUS fillAlgoTestConfig(
        FIPS_AlgoTestConfig* testConfig, intBoolean* allTestFinished)
{
    int i = 0;
    MSTATUS status = OK;

    FIPS_AlgoTestConfig curTestConfig = {0};
    *allTestFinished = TRUE;

    status = FIPS_getSelftestAlgosState(&curTestConfig);
    if( OK != status)
    {
        goto exit;
    }

    for (i = FIRST_FIPS_ALGO; i <= LAST_FIPS_ALGO; i++)
    {
        if(FIPS_INCOMPLETE == curTestConfig.test[i].action)
        {
            testConfig->test[i].action = FIPS_FORCE;
        }
        else
        {
            testConfig->test[i].action = FIPS_SKIP;
        }
    }

#ifdef __FIPS_UTILS_SKIP_KAT_TESTS__
    for (i = FIRST_FIPS_ALGO; i <= FIPS_ALGO_3DES; i++)
    {
        testConfig->test[i].action = FIPS_SKIP;
    }
#endif

#ifdef __FIPS_UTILS_SKIP_DH_AND_HMAC_KDF_TESTS__
    testConfig->test[FIPS_ALGO_HMAC_KDF].action = FIPS_SKIP;
    testConfig->test[FIPS_ALGO_DH].action = FIPS_SKIP;
    testConfig->test[FIPS_ALGO_ECDH].action = FIPS_SKIP;
    testConfig->test[FIPS_ALGO_EDDH].action = FIPS_SKIP;
#endif

#ifdef __FIPS_UTILS_SKIP_ASYM_TESTS__
    testConfig->test[FIPS_ALGO_RSA].action = FIPS_SKIP;
    testConfig->test[FIPS_ALGO_DSA].action = FIPS_SKIP;
    testConfig->test[FIPS_ALGO_ECDSA].action = FIPS_SKIP;
    testConfig->test[FIPS_ALGO_EDDSA].action = FIPS_SKIP;
#endif

    for (i = FIRST_FIPS_ALGO; i <= LAST_FIPS_ALGO; i++)
    {
        if(FIPS_FORCE == testConfig->test[i].action)
        {  *allTestFinished = FALSE;
           break;
        }
    }

    exit:
    return status;
}


/*---------------------------------------------------------------------------*/
/* Exported functions */
/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS FIPS_UTILS_getInitialEntropy(randomContext* pRandomContext)
{
    MSTATUS status = OK;
    /*
     * Provide initial entropy to random context.
     */
    if (pRandomContext != NULL)
    {
        status = addExternalEntropy(pRandomContext, NUM_OF_ENTROPY_BITS_REQUIRED);
    }
    else
    {
        status = ERR_NULL_POINTER;
    }
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS FIPS_UTILS_initialize(randomContext* pRandomContext)
{
    MSTATUS status = OK;
#ifdef __FIPS_UTILS_FORCE_EARLY_FIPS_ALGO_TESTS__
    FIPS_AlgoTestConfig test_config = {0};
    intBoolean allTestFinished = TRUE;
#endif
    /*
     * Required: If pRandomContext is provided, the get initial entropy.
     */

    /* We're ignoring NULL pointer to randomContext */
    if (pRandomContext != NULL)
    {
        status = FIPS_UTILS_getInitialEntropy(pRandomContext);
        if (OK != status)
        {
            goto exit;
        }
    }

#ifdef __FIPS_UTILS_FORCE_EARLY_FIPS_ALGO_TESTS__
    /*
     * Optional: For additional algo self-tests to run now.
     */
    status = fillAlgoTestConfig(&test_config, &allTestFinished);
    if( OK != status)
    {
        goto exit;
    }

    if(FALSE == allTestFinished)
    {
        status = FIPS_SelftestAlgos(&test_config);
        if( OK != status)
        {
            goto exit;
        }
#ifdef __FIPS_UTILS_PERSIST_FIPS_ALGO_TESTS_STATE__
        /*
         * Optional: Save the state after forcing algo self-tests.
         */
        status = FIPS_StatusPersist();
        status = OK; /* We may not be able to save it, that's OK */

#endif /*__FIPS_UTILS_PERSIST_FIPS_ALGO_TESTS_STATE__*/
    }
#endif /* __FIPS_UTILS_FORCE_EARLY_FIPS_ALGO_TESTS__ */

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

