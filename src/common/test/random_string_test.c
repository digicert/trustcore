/*
 * random_string_test.c
 *
 * Test function to verify getting a random ASCII string
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

#if !defined(__RTOS_WIN32__)
#include <unistd.h>
#include <sys/time.h>
#endif

#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../crypto/hw_accel.h"
#include "../../common/random.h"
#include "../../common/mocana.h"
#include "../../crypto/sha1.h"
#include "../../common/debug_console.h"


int random_string_test_1()
{
    MSTATUS status;
    ubyte4 randomStringLen = 20;
    ubyte *pRandomString;

#ifdef __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
    struct timeval tv;
#endif
    

    /* Initialize the Digicert structures */
    if(OK != (status = DIGICERT_initDigicert()))
    {
        printf("Failed to initialize the Digicert code! status = %d = %s\n", status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
#ifdef __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
    gettimeofday(&tv, NULL);

    if(OK != (status = DIGICERT_addEntropy32Bits((ubyte4)tv.tv_sec)))
    {
        printf("Failed to add entropy to the RNG! status = %d = %s\n", status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
#endif

    /* Check for global random context */
    if(NULL == g_pRandomContext)
    {
        status = ERR_RAND_CTX_NOT_INITIALIZED;
        printf("Do not have global random context!\n");
        goto exit;
    }

    /* allocate memory for string */
    status = DIGI_MALLOC((void **)&pRandomString, randomStringLen);
    if (OK != status)
    {
        printf("Failed to allocate memory for string! status = %d = %s\n", status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Get random string */
    status = RANDOM_generateASCIIString(g_pRandomContext, pRandomString, randomStringLen);
    if (OK != status)
    {
        printf("Failed to get random string! status %d = %s\n", status, MERROR_lookUpErrorCode(status));
    }
    else
    {
        printf("Random String 1: %s\n", pRandomString);
    }
    DIGI_MEMSET(pRandomString, 0, randomStringLen);

    /* Get second random to show it's actually random */
    status = RANDOM_generateASCIIString(g_pRandomContext, pRandomString, randomStringLen);
    if (OK != status)
    {
        printf("Failed to get random string! status %d = %s\n", status, MERROR_lookUpErrorCode(status));
    }
    else
    {
        printf("Random String 2: %s\n", pRandomString);
    }
 
exit:

    FREE(pRandomString);
    pRandomString = NULL;

    status = DIGICERT_freeDigicert();

    return status;    
}

