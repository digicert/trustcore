/*
 * mem_part_test.c
 *
 * Memory Partition Test
 * Overlays a memory partition over a given memory region
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

#include "../../common/moptions.h"

#ifdef __ENABLE_DIGICERT_MEM_PART__

#include "../../common/mdefs.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mocana.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/mrtos.h"
#include "../../common/mem_part.h"

#include "../../../unit_tests/unittest.h"

#if defined( __RTOS_WIN32__) || defined( __RTOS_LINUX__) || \
    defined(__RTOS_CYGWIN__) || defined(__RTOS_OSX__)
#include <stdio.h>
#define PRINTF2      printf
#define PRINTF3      printf
#else
/* OSes with no printf go here and need to define equivalent functionality*/
/* need to support only %s and %d format strings with no extensions */
#define PRINTF2(X,Y)
#define PRINTF3(X,Y,Z)
#endif


/*---------------------------------------------------------------------------*/

#define TEST_IT(X)      if (X) { error_line = __LINE__; status = (OK > status) ? status : -1; goto exit; } numTests++;


/*---------------------------------------------------------------------------*/

static int error_line;

/*---------------------------------------------------------------------------*/

int mem_test_original()
{
    memPartDescr*   pMemPartition = NULL;
    ubyte*          pMemPartBase  = NULL;
    ubyte*          pPhysicalAddress = NULL;
    ubyte*          pKernelAddress = NULL;
#ifndef __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__
    ubyte*          pRetPhysicalAddress;
    ubyte*          pRetKernelAddress;
    ubyte4          memPartSize   = 10000;
#else
    ubyte4          memPartSize   = 32768;  /* big enough for all tests, 128 * 256 */
#endif
    ubyte*          pMemBlock;
    ubyte*          pMemBlocks[20];
    sbyte4          index;
    ubyte4          numTests = 0;
    MSTATUS         status = ERR_MEM_ALLOC_FAIL;

    TEST_IT(NULL == (pMemPartBase = MALLOC(memPartSize)))

    TEST_IT(OK > (status = MEM_PART_init()))

    TEST_IT(OK > (status = MEM_PART_createPartition(&pMemPartition, pMemPartBase, memPartSize)))

    TEST_IT(OK > (status = MEM_PART_enableMutexGuard(pMemPartition)))

#ifndef __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__
    TEST_IT(OK > (status = MEM_PART_assignOtherAddresses(pMemPartition, pPhysicalAddress, pKernelAddress)))
#endif

    /* simple alloc & free */
    for (index = 0; index < 100; index++)
    {
        TEST_IT(OK > (status = MEM_PART_alloc(pMemPartition, 1, (void **) &pMemBlock)))

        TEST_IT(OK > (status = MEM_PART_free(pMemPartition, (void **) &pMemBlock)))
    }


    /* simple alloc & free */
    for (index = 0; index < 100; index++)
    {
        TEST_IT(OK > (status = MEM_PART_alloc(pMemPartition, 50, (void **) &pMemBlock)))

#ifndef __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__
        TEST_IT(OK > (status = MEM_PART_mapToPhysicalAddress(pMemPartition, pMemBlock, &pRetPhysicalAddress)))

        TEST_IT(OK > (status = MEM_PART_mapToKernelAddress(pMemPartition, pMemBlock, &pRetKernelAddress)))
#endif
        TEST_IT(OK > (status = MEM_PART_free(pMemPartition, (void **) &pMemBlock)))
    }


    /* simple list of alloc / free */
    for (index = 0; index < 10; index++)
    {
        TEST_IT(OK > (status = MEM_PART_alloc(pMemPartition, 100, (void **) &(pMemBlocks[index]))))

        DIGI_MEMSET(pMemBlocks[index], 0xaa, 100);
    }

    for (index = 0; index < 10; index ++)
    {
        TEST_IT(OK > (status = MEM_PART_free(pMemPartition, (void **) &(pMemBlocks[index]))))
    }


    /* forward interlaced frees */
    for (index = 0; index < 10; index++)
    {
        TEST_IT(OK > (status = MEM_PART_alloc(pMemPartition, 100, (void **) &(pMemBlocks[index]))))

        DIGI_MEMSET(pMemBlocks[index], 0xbb, 100);
    }

    for (index = 0; index < 10; index += 2)
    {
        TEST_IT(OK > (status = MEM_PART_free(pMemPartition, (void **) &(pMemBlocks[index]))))
    }

    for (index = 1; index < 10; index += 2)
    {
        TEST_IT(OK > (status = MEM_PART_free(pMemPartition, (void **) &(pMemBlocks[index]))))
    }


    /* forward interlaced frees */
    for (index = 0; index < 20; index++)
    {
        TEST_IT(OK > (status = MEM_PART_alloc(pMemPartition, 100, (void **) &(pMemBlocks[index]))))

        DIGI_MEMSET(pMemBlocks[index], 0xbb, 100);
    }

    for (index = 0; index < 20; index += 3)
    {
        TEST_IT(OK > (status = MEM_PART_free(pMemPartition, (void **) &(pMemBlocks[index]))))
    }

    for (index = 1; index < 20; index += 3)
    {
        TEST_IT(OK > (status = MEM_PART_free(pMemPartition, (void **) &(pMemBlocks[index]))))
    }

    for (index = 2; index < 20; index += 3)
    {
        TEST_IT(OK > (status = MEM_PART_free(pMemPartition, (void **) &(pMemBlocks[index]))))
    }


    /* simple alloc free to make sure table is not corrupted */
    for (index = 0; index < 10; index++)
    {
        TEST_IT(OK > (status = MEM_PART_alloc(pMemPartition, 100, (void **) &(pMemBlocks[index]))))

        DIGI_MEMSET(pMemBlocks[index], 0xaa, 100);

        TEST_IT(OK > (status = MEM_PART_free(pMemPartition, (void **) &(pMemBlocks[index]))))
    }


    /* some big allocs to make sure memory is contiguous */
    TEST_IT(OK > (status = MEM_PART_alloc(pMemPartition, 9900, (void **) &pMemBlock)))

    DIGI_MEMSET(pMemBlock, 0x99, 9900);

    TEST_IT(OK > (status = MEM_PART_free(pMemPartition, (void **) &pMemBlock)))

    TEST_IT(OK > (status = MEM_PART_alloc(pMemPartition, 9900, (void **) &pMemBlock)))

    DIGI_MEMSET(pMemBlock, 0x88, 9900);

    TEST_IT(OK > (status = MEM_PART_free(pMemPartition, (void **) &pMemBlock)))


    /* simple alloc / free, to make sure things are still stable */
    for (index = 0; index < 10; index++)
    {
        TEST_IT(OK > (status = MEM_PART_alloc(pMemPartition, 100, (void **) &(pMemBlocks[index]))))

        DIGI_MEMSET(pMemBlocks[index], 0xaa, 100);
    }

    for (index = 0; index < 10; index += 2)
    {
        TEST_IT(OK > (status = MEM_PART_free(pMemPartition, (void **) &(pMemBlocks[index]))))
    }

    for (index = 0; index < 10; index += 2)
    {
        TEST_IT(OK > (status = MEM_PART_alloc(pMemPartition, 100, (void **) &(pMemBlocks[index]))))

        DIGI_MEMSET(pMemBlocks[index], 0xaa, 100);
    }

    for (index = 0; index < 10; index++)
    {
        TEST_IT(OK > (status = MEM_PART_free(pMemPartition, (void **) &(pMemBlocks[index]))))
    }


    /* try backwards frees */
    for (index = 0; index < 10; index++)
    {
        TEST_IT(OK > (status = MEM_PART_alloc(pMemPartition, 100, (void **) &(pMemBlocks[index]))))

        DIGI_MEMSET(pMemBlocks[index], 0xaa, 100);
    }

    for (index = 9; index >= 0; index--)
    {
        TEST_IT(OK > (status = MEM_PART_free(pMemPartition, (void **) &(pMemBlocks[index]))))
    }


    /* try backwards, interlaced frees */
    for (index = 0; index < 10; index++)
    {
        TEST_IT(OK > (status = MEM_PART_alloc(pMemPartition, 100, (void **) &(pMemBlocks[index]))))

        DIGI_MEMSET(pMemBlocks[index], 0xaa, 100);
    }

    for (index = 9; index >= 0; index -= 2)
    {
        TEST_IT(OK > (status = MEM_PART_free(pMemPartition, (void **) &(pMemBlocks[index]))))
    }

    for (index = 8; index >= 0; index -= 2)
    {
        TEST_IT(OK > (status = MEM_PART_free(pMemPartition,(void **)  &(pMemBlocks[index]))))
    }


    /* try backwards, interlaced frees */
    for (index = 0; index < 20; index++)
    {
        TEST_IT(OK > (status = MEM_PART_alloc(pMemPartition, 100, (void **) &(pMemBlocks[index]))))

        DIGI_MEMSET(pMemBlocks[index], 0xaa, 100);
    }

    for (index = 19; index >= 0; index -= 3)
    {
        TEST_IT(OK > (status = MEM_PART_free(pMemPartition, (void **) &(pMemBlocks[index]))))
    }

    for (index = 18; index >= 0; index -= 3)
    {
        TEST_IT(OK > (status = MEM_PART_free(pMemPartition, (void **) &(pMemBlocks[index]))))
    }

    for (index = 17; index >= 0; index -= 3)
    {
        TEST_IT(OK > (status = MEM_PART_free(pMemPartition, (void **) &(pMemBlocks[index]))))
    }


    /* some big allocs to make sure memory is contiguous */
    TEST_IT(OK > (status = MEM_PART_alloc(pMemPartition, 9900, (void **) &pMemBlock)))

    DIGI_MEMSET(pMemBlock, 0x99, 9900);

    TEST_IT(OK > (status = MEM_PART_free(pMemPartition, (void **) &pMemBlock)))

    TEST_IT(OK > (status = MEM_PART_alloc(pMemPartition, 9900, (void **) &pMemBlock)))

    DIGI_MEMSET(pMemBlock, 0x88, 9900);

    TEST_IT(OK > (status = MEM_PART_free(pMemPartition, (void **) &pMemBlock)))

    TEST_IT(OK > (status = MEM_PART_freePartition(&pMemPartition)))

    /* test completed successfully! */
    status = MEM_PART_uninit();

    FREE(pMemPartBase);

exit:
    /* on error, status will equal digicert error code or negative line number */
    if (OK > status)
    {
        printf("\nmem_part_test_all: status = %d, error at line #%d\n", (int)status, error_line);
        status = 1;
    }

    return status;
}

/* This tests using static memory. To use this feature, call
 * DIGICERT_initDigicertStaticMemory.
 */
#define STATIC_MEM_TEST_BUF_SIZE    65536  /* big enough for all tests, 128 * 256 */
#define STATIC_MEM_TEST_CHECK_SIZE    128
int mem_test_staticMem ()
{
#ifndef __ENABLE_DIGICERT_MEM_PART__
  return (0);
#else
  MSTATUS status;
  int retVal = 0, index, indexS;
  ubyte *pBuffer = NULL;
  ubyte pMemData[STATIC_MEM_TEST_BUF_SIZE];

  /* Init the buffer so we can see if memory we think was allocated in the buffer
   * actually is by looking for it.
   */
  for (index = 0; index < STATIC_MEM_TEST_BUF_SIZE; ++index)
    pMemData[index] = 0xff;

  /* This is how we make sure static memory is used.
   */
  status = (MSTATUS)DIGICERT_initDigicertStaticMemory (
    (ubyte *)pMemData, sizeof (pMemData));
  retVal += UNITTEST_STATUS (__LINE__, status);
  if (OK != status)
    goto exit;

  /* Allocate a buffer, then make sure that buffer was allocated inside the
   * static memory.
   */
  status = DIGI_MALLOC ((void **)&pBuffer, STATIC_MEM_TEST_CHECK_SIZE);
  retVal += UNITTEST_STATUS (__LINE__, status);
  if (OK != status)
    goto exit;

  /* Set the memory to something we can look for.
   */
  for (index = 0; index < STATIC_MEM_TEST_CHECK_SIZE; ++index)
    pBuffer[index] = (ubyte)index;

  /* Now search the static memory buffer to see if the pattern is in there.
   */
  for (index = 0; index <= (STATIC_MEM_TEST_BUF_SIZE - STATIC_MEM_TEST_CHECK_SIZE);
       ++index)
  {
    if (0 != pMemData[index])
      continue;

    /* We have a zero, are the next bytes the next in the sequence?
     */
    for (indexS = 1; indexS < STATIC_MEM_TEST_CHECK_SIZE; ++indexS)
    {
      /* If we find a mismatch, quit looking.
       */
      if (pMemData[index + indexS] != (ubyte)indexS)
        break;
    }
    /* If we broke out early, we found a mismatch, so keep looking.
     * If we went through the entire sequence we found a match, so stop looking.
     */
    if (indexS >= STATIC_MEM_TEST_CHECK_SIZE)
      break;
  }
  /* If we broke out of the outer loop early, we found a match.
   * If not, we didn't and that's an error to report.
   */
  if (index > (STATIC_MEM_TEST_BUF_SIZE - STATIC_MEM_TEST_CHECK_SIZE))
    status = ERR_MEM_PART;
  retVal += UNITTEST_STATUS (__LINE__, status);

  /* Allocate memory that is too large, we should get an error.
   */
  status = DIGI_FREE ((void **)&pBuffer);
  retVal += UNITTEST_STATUS (__LINE__, status);
  if (OK != status)
    goto exit;

  pBuffer = NULL;

  status = DIGI_MALLOC ((void **)&pBuffer, STATIC_MEM_TEST_BUF_SIZE);
  retVal += UNITTEST_INT (__LINE__, status, ERR_MEM_PART_ALLOC_FAIL);

exit:
  
  if (NULL != pBuffer)
  {
    status = DIGI_FREE ((void **)&pBuffer);
    retVal += UNITTEST_STATUS (__LINE__, status);
  }

  status = (MSTATUS) DIGICERT_freeDigicert ();
  retVal += UNITTEST_STATUS (__LINE__, status);

  return (retVal);
#endif  /* __ENABLE_DIGICERT_MEM_PART__ */
}

#ifdef __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__
int mem_test_multipart(byteBoolean withMutex)
{
    int retVal = 0;
    MSTATUS status;
    int i;

    memPartDescr *pMemPartition = NULL;
    memPartDescr *pMemPartMedium = NULL;
    memPartDescr *pMemPartLarge = NULL;
    
    ubyte **pMemBlocksSmall = NULL;
    ubyte **pMemBlocksMedium = NULL;
    ubyte **pMemBlocksLarge = NULL;
    ubyte *pTempBlock = NULL;
    
    uintptr pSmallBlock = 0;
    uintptr pMediumBlock = 0;
    uintptr pLargeBlock = 0;
    uintptr pLargeBlockEnd = 0;
    
/* decide on how many bytes to allocate for each size partition */
#define SMALL_MALLOC 16
#define MEDIUM_MALLOC 2*MOC_PARTITION_SMALL_THRESHOLD
#define LARGE_MALLOC 2*MOC_PARTITION_MEDIUM_THRESHOLD
    
#if MOC_PARTITION_SMALL_THRESHOLD <= SMALL_MALLOC
#error MOC_PARTITION_SMALL_THRESHOLD too small for this test
#endif
    
#if MOC_PARTITION_MEDIUM_THRESHOLD <= MEDIUM_MALLOC
#error MOC_PARTITION_MEDIUM_THRESHOLD too small for this test
#endif
    
    ubyte4 smallLen = MOC_PARTITION_SMALL_PARTS_PER_128 * MOC_MIN_PARTITION_SIZE;
    ubyte4 mediumLen = MOC_PARTITION_MEDIUM_PARTS_PER_128 * MOC_MIN_PARTITION_SIZE;
    ubyte4 largeLen = MOC_PARTITION_LARGE_PARTS_PER_128 * MOC_MIN_PARTITION_SIZE;
    
    ubyte4 maxNumSmalls;
    ubyte4 maxNumMediums;
    ubyte4 maxNumLarges;

    ubyte4 totalLen = 3*((sizeof(memPartDescr) + 15)/16) + smallLen + mediumLen + largeLen + 15; /* + 15 in case not aligned */
    
    ubyte *pMemBuffer = NULL;
    
    pMemBuffer = MALLOC(totalLen); /* no registered partition yet, should default to regular malloc */
    
    if (NULL == pMemBuffer)
    {
        retVal += UNITTEST_STATUS(__LINE__, -1); /* force error */
        goto exit;
    }
    
    status = MEM_PART_createPartition(&pMemPartition, pMemBuffer, totalLen);
    retVal += UNITTEST_STATUS(__LINE__, status);
    if (OK != status)
        goto exit;
    
    if (withMutex)
    {
        status = MEM_PART_enableMutexGuard(pMemPartition);
        retVal += UNITTEST_STATUS(__LINE__, status);
        if (OK != status)
            goto exit;
    }
    
    /* get a the pointers to where each block of memory should lie, readjust to the actual lenght of usable memory */
    pSmallBlock = (uintptr) pMemPartition->pMemStartAddress;
    smallLen = (ubyte4) ((uintptr) pMemPartition->pMemEndAddress - pSmallBlock);
    maxNumSmalls = smallLen/(SMALL_MALLOC + 32);        /* header and magic and roundup accounts for 32 more bytes */
    
    pMemPartMedium = (memPartDescr *) (pMemPartition->pMemEndAddress);
    pMediumBlock = (uintptr) pMemPartMedium->pMemStartAddress;
    mediumLen = (ubyte4) ((uintptr) pMemPartMedium->pMemEndAddress - pMediumBlock);
    maxNumMediums = mediumLen/(MEDIUM_MALLOC + 32);
    
    pMemPartLarge = (memPartDescr *) (pMemPartMedium->pMemEndAddress);
    pLargeBlock = (uintptr) pMemPartLarge->pMemStartAddress;
    largeLen = (ubyte4) ((uintptr) pMemPartLarge->pMemEndAddress - pLargeBlock);
    maxNumLarges = largeLen/(LARGE_MALLOC + 32);
    
    pLargeBlockEnd = (uintptr) pMemPartLarge->pMemEndAddress;
    
    /* allocate a list that will hold the pointers to allocated memory */
    pMemBlocksSmall = (ubyte **) MALLOC(maxNumSmalls * sizeof(ubyte *));
    pMemBlocksMedium = (ubyte **) MALLOC(maxNumMediums * sizeof(ubyte *));
    pMemBlocksLarge = (ubyte **) MALLOC(maxNumLarges * sizeof(ubyte *));
    
    /* allocate as much as possible for each size */
    for (i = 0; i < maxNumSmalls; i++)
    {
        status = MEM_PART_alloc(pMemPartition, SMALL_MALLOC, (void **) &pMemBlocksSmall[i]);
        retVal += UNITTEST_STATUS(__LINE__, status);
        if (OK != status)
            goto exit;
    }
    
    for (i = 0; i < maxNumMediums; i++)
    {
        status = MEM_PART_alloc(pMemPartition, MEDIUM_MALLOC, (void **) &pMemBlocksMedium[i]);
        retVal += UNITTEST_STATUS(__LINE__, status);
        if (OK != status)
            goto exit;
    }
    
    for (i = 0; i < maxNumLarges; i++)
    {
        status = MEM_PART_alloc(pMemPartition, LARGE_MALLOC, (void **) &pMemBlocksLarge[i]);
        retVal += UNITTEST_STATUS(__LINE__, status);
        if (OK != status)
            goto exit;
    }
    
    /* Test that the blocks are in the correct region of memory and
     that the blocks are the correct distance apart from each other */
    for (i = 0; i < maxNumSmalls; ++i)
    {
        if ( (uintptr) pMemBlocksSmall[i] < (uintptr) pSmallBlock )
        {
            retVal += UNITTEST_STATUS(__LINE__, -1); /* force error */
        }
        
        if ( (uintptr) pMemBlocksSmall[i] >= (uintptr) pMediumBlock )
        {
            retVal += UNITTEST_STATUS(__LINE__, -1); /* force error */
        }
        
        if (i > 0)
            retVal += UNITTEST_INT(__LINE__, SMALL_MALLOC + 32, (int) ((uintptr) pMemBlocksSmall[i-1] - (uintptr) pMemBlocksSmall[i]) );
    }
    
    for (i = 0; i < maxNumMediums; ++i)
    {
        if ( (uintptr) pMemBlocksMedium[i] < (uintptr) pMediumBlock )
        {
            retVal += UNITTEST_STATUS(__LINE__, -1); /* force error */
        }
        
        if ( (uintptr) pMemBlocksMedium[i] >= (uintptr) pLargeBlock )
        {
            retVal += UNITTEST_STATUS(__LINE__, -1); /* force error */
        }
        
        if (i > 0)
            retVal += UNITTEST_INT(__LINE__, MEDIUM_MALLOC + 32, (int) ((uintptr) pMemBlocksMedium[i-1] - (uintptr) pMemBlocksMedium[i]) );
    }
    
    for (i = 0; i < maxNumLarges; ++i)
    {
        if ( (uintptr) pMemBlocksLarge[i] < (uintptr) pLargeBlock )
        {
            retVal += UNITTEST_STATUS(__LINE__, -1); /* force error */
        }
        
        if ( (uintptr) pMemBlocksLarge[i] >= (uintptr) pLargeBlockEnd )
        {
            retVal += UNITTEST_STATUS(__LINE__, -1); /* force error */
        }
        
        if (i > 0)
            retVal += UNITTEST_INT(__LINE__, LARGE_MALLOC + 32, (int) ((uintptr) pMemBlocksLarge[i-1] - (uintptr) pMemBlocksLarge[i]) );
    }

    /* try allocating an additional large block, should be nothing left */
    status = MEM_PART_alloc(pMemPartition, LARGE_MALLOC, (void **) &pTempBlock);
    retVal += UNITTEST_INT(__LINE__, status, ERR_MEM_PART_ALLOC_FAIL);
    
    for (i = 0; i < maxNumSmalls; ++i)
    {
        /* free the small blocks */
        status = MEM_PART_free(pMemPartition, (void **) &pMemBlocksSmall[i]);
        retVal += UNITTEST_STATUS(__LINE__, status);
        if (OK != status)
            goto exit;
        
        /* check that the ptr is null */
        if (NULL != pMemBlocksSmall[i])
            retVal += UNITTEST_STATUS(__LINE__, -1); /* force error */
    }
    
    /* try allocating an additional large block, might go in the small section  */
    status = MEM_PART_alloc(pMemPartition, LARGE_MALLOC, (void **) &pTempBlock);
    if (LARGE_MALLOC + 32 >= smallLen)
        retVal += UNITTEST_INT(__LINE__, status, ERR_MEM_PART_ALLOC_FAIL);
    else
    {
        retVal += UNITTEST_STATUS(__LINE__, status);
        if (OK != status)
           goto exit;
        
        /* check it is in the small section */
        if ( (uintptr) pTempBlock < (uintptr) pSmallBlock )
        {
            retVal += UNITTEST_STATUS(__LINE__, -1); /* force error */
        }
        
        if ( (uintptr) pTempBlock >= (uintptr) pMediumBlock )
        {
            retVal += UNITTEST_STATUS(__LINE__, -1); /* force error */
        }
    
        /* free it */
        status = MEM_PART_free(pMemPartition, (void **) &pTempBlock);
        retVal += UNITTEST_STATUS(__LINE__, status);
        if (OK != status)
            goto exit;
        
        /* check that the ptr is NULL */
        if (NULL != pTempBlock)
            retVal += UNITTEST_STATUS(__LINE__, -1); /* force error */
    }

    for (i = 0; i < maxNumMediums; ++i)
    {
        /* free the medium blocks */
        status = MEM_PART_free(pMemPartition, (void **) &pMemBlocksMedium[i]);
        retVal += UNITTEST_STATUS(__LINE__, status);
        if (OK != status)
            goto exit;
        
        /* check that the ptr is null */
        if (NULL != pMemBlocksMedium[i])
            retVal += UNITTEST_STATUS(__LINE__, -1); /* force error */
    }
    
    /* Allocate the small blocks again */
    for (i = 0; i < maxNumSmalls; i++)
    {
        status = MEM_PART_alloc(pMemPartition, SMALL_MALLOC, (void **) &pMemBlocksSmall[i]);
        retVal += UNITTEST_STATUS(__LINE__, status);
        if (OK != status)
            goto exit;
    }
    
    /* try allocating an additional large block, might go in the medium section  */
    status = MEM_PART_alloc(pMemPartition, LARGE_MALLOC, (void **) &pTempBlock);
    if (LARGE_MALLOC + 32 >= mediumLen)
        retVal += UNITTEST_INT(__LINE__, status, ERR_MEM_PART_ALLOC_FAIL);
    else
    {
        retVal += UNITTEST_STATUS(__LINE__, status);
        if (OK != status)
            goto exit;
        
        /* check it is in the medium section */
        if ( (uintptr) pTempBlock < (uintptr) pMediumBlock )
        {
            retVal += UNITTEST_STATUS(__LINE__, -1); /* force error */
        }
        
        if ( (uintptr) pTempBlock >= (uintptr) pLargeBlock )
        {
            retVal += UNITTEST_STATUS(__LINE__, -1); /* force error */
        }
        
        /* free it */
        status = MEM_PART_free(pMemPartition, (void **) &pTempBlock);
        retVal += UNITTEST_STATUS(__LINE__, status);
        if (OK != status)
            goto exit;
        
        /* check that the ptr is NULL */
        if (NULL != pTempBlock)
            retVal += UNITTEST_STATUS(__LINE__, -1); /* force error */
    }

    for (i = 0; i < maxNumLarges; ++i)
    {
        /* free the large blocks */
        status = MEM_PART_free(pMemPartition, (void **) &pMemBlocksLarge[i]);
        retVal += UNITTEST_STATUS(__LINE__, status);
        if (OK != status)
            goto exit;
        
        /* check that the ptr is null */
        if (NULL != pMemBlocksLarge[i])
            retVal += UNITTEST_STATUS(__LINE__, -1); /* force error */
    }
    
    /* check that we can allocate the medium and large blocks again */
    
    for (i = 0; i < maxNumMediums; i++)
    {
        status = MEM_PART_alloc(pMemPartition, MEDIUM_MALLOC, (void **) &pMemBlocksMedium[i]);
        retVal += UNITTEST_STATUS(__LINE__, status);
        if (OK != status)
            goto exit;
    }
    
    for (i = 0; i < maxNumLarges; i++)
    {
        status = MEM_PART_alloc(pMemPartition, LARGE_MALLOC, (void **) &pMemBlocksLarge[i]);
        retVal += UNITTEST_STATUS(__LINE__, status);
        if (OK != status)
            goto exit;
    }
    
    /* free everything again */
    for (i = 0; i < maxNumSmalls; ++i)
    {
        /* free the small blocks */
        status = MEM_PART_free(pMemPartition, (void **) &pMemBlocksSmall[i]);
        retVal += UNITTEST_STATUS(__LINE__, status);
        if (OK != status)
            goto exit;
    }
    
    for (i = 0; i < maxNumMediums; ++i)
    {
        /* free the medium blocks */
        status = MEM_PART_free(pMemPartition, (void **) &pMemBlocksMedium[i]);
        retVal += UNITTEST_STATUS(__LINE__, status);
        if (OK != status)
            goto exit;
    }

    for (i = 0; i < maxNumLarges; ++i)
    {
        /* free the large blocks */
        status = MEM_PART_free(pMemPartition, (void **) &pMemBlocksLarge[i]);
        retVal += UNITTEST_STATUS(__LINE__, status);
        if (OK != status)
            goto exit;
    }

exit:
    
    return retVal;
}
#endif
#endif /* __ENABLE_DIGICERT_MEM_PART__ */

int mem_part_test_all()
{
    int retVal = 0;
	
#ifdef __ENABLE_DIGICERT_MEM_PART__
	
    retVal += mem_test_staticMem();
    retVal += mem_test_original();

#ifdef __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__
    retVal += mem_test_multipart(FALSE);
    retVal += mem_test_multipart(TRUE);
#endif
#endif /* __ENABLE_DIGICERT_MEM_PART__ */
	
exit:
    
    return retVal;
}
