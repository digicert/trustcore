/*
 * memory_debug.c
 *
 * Mocana Memory Leak Detection Code
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

#include "../common/moptions.h"

#ifdef __ENABLE_DIGICERT_DEBUG_MEMORY__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"

#include <stdlib.h>
#include <stdio.h>

#if defined (__LINUX_RTOS__)
#include <pthread.h>
#endif

/* Log the size.
 * Log the size whether performing a malloc (mFlag = 1) or a free (mFlag = 0).
 * This function will look through the list of memStatEntries, finding an entry
 * with the given size. If it finds an entry with that size, it updates that
 * entry.
 * When allocating (mFlag = 1), to log is to increment the totalCount and
 * concurrentCount, then check the maxConcurrentCount. When freeing (mFlag = 0),
 * to log is to decrement the concurrentCount.
 * If allocating, and no entry corresponding to the given size is found, fill in
 * a new entry. Increment the entryListCount. If we run out of entries (if
 * entryListCount is already NUM_MEM_STAT_ENTRIES), don't log anything, but set
 * the memStatError 0 bit to 1 (i.e. memStatError |= 1).
 * If freeing and no entry is found, the function will not fill in a new entry,
 * but it will set the memStatError 1 bit to 1 (i.e. memStatError |= 2).
 * If we find a free for which there is no entry, it is possible we ran out of
 * entries. If so, the memStatError will be 3. But if we don't run out of entries
 * and we still have an error when freeing, the memStatError will be 2.
 */
void LogMemoryStat (ubyte4 size, ubyte4 mFlag);

/*------------------------------------------------------------------*/

#define NUM_MEM_TABLE_ROWS  1000
#define NUM_FREE_TABLE_ROWS 100
/* This is how many memory statistic entries we'll have. Each time we run a
 * program, we'll collect the statistics. Over time, we'll likely get a better
 * idea of how many entries we'll need.
 */
#define NUM_MEM_STAT_ENTRIES 400

#ifndef MEM_DBG_PAD
#define MEM_DBG_PAD         64      /* should be a multiple of 16 */
#endif

#ifndef MEM_DBG_PAD_CHAR
#define MEM_DBG_PAD_CHAR    0xab
#endif

#if (MEM_DBG_PAD % 16)
#error MEM_DBG_PAD must be n * 16 in size, where n is a nonnegative integer, n=0,1,2,3...
#endif

/* This struct contains "statistics" on an allocation size.
 * We will keep track of how many times an allocation of a particular size was
 * made. This is simply an aid to help plan a static memory manager.
 * Each time we allocate, check to see if we have allocated the same amount
 * previously. If not, create a new entry.
 * If so, increment the totalCount and concurrentCount (total number of blocks of
 * this size alive at the same time). If the concurrentCount is greater than the
 * maxConcurrentCount, set the max to the count. Every time we free a block of
 * this size, decrement the concurrentCount.
 * When we dump the dbg info, we'll also print out the list.
 */
typedef struct
{
  ubyte4  size;
  ubyte4  totalCount;
  ubyte4  concurrentCount;
  ubyte4  maxConcurrentCount;
} memStatEntry;

typedef struct
{
    ubyte   rowUsed;
    ubyte*  pMemBlock;
    ubyte4  numBytes;
    ubyte*  pFile;
    ubyte4  lineNum;

} memTableDescr;

static memTableDescr memTable[NUM_MEM_TABLE_ROWS];
static memTableDescr freeTable[NUM_FREE_TABLE_ROWS];
static memStatEntry  entryList[NUM_MEM_STAT_ENTRIES];

#if defined (__LINUX_RTOS__)
static pthread_mutex_t* pMemDbgMutex = 0;
static intBoolean       memDbgMutexEnabled = 0;
#endif

static volatile ubyte4 highWaterMark = 0;
static volatile ubyte4 currentMemoryUsage = 0;
static volatile ubyte4 totalMemoryUsage = 0;
static volatile ubyte4 totalCallsToMalloc = 0;
/* Keep track of how many entries we have used. This will make it easier to loop
 * through (don't have to loop through all) and will help us determine how many
 * entries we'll likely need. If entryListCount ends up being
 * NUM_MEM_STAT_ENTRIES, we'll know we ran out of entries.
 */
static volatile ubyte4 entryListCount = 0;
/* Init this to 0, indicating there has not been an error in logging memory
 * statistics. But if we run out of entries
 */
static volatile ubyte4 memStatError = 0;

/*------------------------------------------------------------------*/

extern void
  dbg_dump_stat(void)
{
  ubyte4 index;

  dbg_dump ();

  if (0 != memStatError)
  {
    printf("Memory stat error: %d\n\n", memStatError);
  }

  index = NUM_MEM_STAT_ENTRIES;
  printf (" %d size entries out of max %d\n\n", entryListCount, index);

  for (index = 0; index < entryListCount; ++index)
  {
    printf ("     Allocation size: %d\n", entryList[index].size);
    printf ("               count: %d\n", entryList[index].totalCount);
    printf ("max concurrent count: %d\n\n", entryList[index].maxConcurrentCount);
  }
}

extern void
dbg_dump(void)
{
    sbyte4 index = 0;
    byteBoolean foundIssue = FALSE;

    printf("\n\nMEMORY LEAKS FOUND =============================\n");

    for (index = 0; index < NUM_MEM_TABLE_ROWS; index++)
    {
        if (1 == memTable[index].rowUsed)
        {
            printf("dbg_dump: memory = %08x, size = %d, line = %d, file = %s\n", (int)(uintptr)(memTable[index].pMemBlock), (int)(memTable[index].numBytes), (int)(memTable[index].lineNum), (char *)memTable[index].pFile);
            foundIssue = TRUE;
        }
    }

    if (!foundIssue)
    {
        printf(".................. None!\n");
    }

    foundIssue = FALSE;
    printf("MEMORY PAD DAMAGE FOUND ========================\n");

    for (index = 0; index < NUM_MEM_TABLE_ROWS; index++)
    {
        if (2 == memTable[index].rowUsed)
        {
            printf("dbg_dump: memory = %08x, size = %d, line = %d, file = %s\n", (int)(uintptr)(memTable[index].pMemBlock), (int)(memTable[index].numBytes), (int)(memTable[index].lineNum), (char *)memTable[index].pFile);
            foundIssue = TRUE;
        }
    }

    if (!foundIssue)
    {
        printf(".................. None!\n");
    }

    foundIssue = FALSE;
    printf("BAD FREES FOUND ================================\n");

    for (index = 0; index < NUM_FREE_TABLE_ROWS; index++)
    {
        if (1 == freeTable[index].rowUsed)
        {
            printf("dbg_dump: memory = %08x, line = %d, file = %s\n", (int)(uintptr)(freeTable[index].pMemBlock), (int)(freeTable[index].lineNum), (char *)freeTable[index].pFile);
            foundIssue = TRUE; 
        }
    }

    if (!foundIssue)
    {
        printf(".................. None!\n");
    }

    printf("================================================\n");
    printf("Memory high water mark: %d\n", highWaterMark);
    printf("Total memory allocated: %d\n", totalMemoryUsage);
    printf("Total calls to  malloc: %d\n\n", totalCallsToMalloc);

    highWaterMark = 0;
    currentMemoryUsage = 0;
    totalMemoryUsage = 0;
    totalCallsToMalloc = 0;
    foundIssue = FALSE;

    return;
}


/*------------------------------------------------------------------*/

extern ubyte4
MEMORY_DEBUG_resetHighWaterMark(void)
{
    ubyte4 oldHighWaterMark = highWaterMark;

    highWaterMark = currentMemoryUsage;

    /* return non-reset high water mark */
    return oldHighWaterMark;
}

#if defined (__LINUX_RTOS__)
/* The memory_debug malloc and free are not thread safe   */
/* On a Linux platform, the application can call these    */
/* functions to enable a mutex that should make it safe   */
/* The mutex is not enabled by default because I'm seeing */
/* segfaults when I start my process with the mutex       */
/* enabled.  If I only enable the mutex during my         */
/* multi-threaded code section, then all works well       */
extern void
MEMORY_DEBUG_enableMutex(void)
{
    if (NULL == pMemDbgMutex)
    {
    	pMemDbgMutex = (pthread_mutex_t*) MALLOC(sizeof(pthread_mutex_t));
    	pthread_mutex_init(pMemDbgMutex, NULL);
    	memDbgMutexEnabled = TRUE;
    }
}

extern void
MEMORY_DEBUG_disableMutex(void)
{
    if (pMemDbgMutex)
    {
    	pthread_mutex_destroy(pMemDbgMutex);
        FREE(pMemDbgMutex);
		pMemDbgMutex = NULL;
    }
	memDbgMutexEnabled = FALSE;

}
#endif

/*------------------------------------------------------------------*/

extern void *
dbg_malloc(ubyte4 numBytes, ubyte *pFile, ubyte4 lineNum)
{
    ubyte*  retBlock;
    sbyte4  findRow;


    if (34000 < numBytes)
    {
//        printf("dbg_malloc: malloc awefully big (%d) bytes @ %s, line = %d.\n", (int)numBytes, (char *)pFile, (int)lineNum);
    }

    if (0 == numBytes)
    {
        printf("dbg_malloc: zero byte malloc @ %s, line = %d.\n", (char *)pFile, (int)lineNum);
        return NULL;
    }

    retBlock = malloc(MEM_DBG_PAD + numBytes + MEM_DBG_PAD);

#if defined (__LINUX_RTOS__)
    if (pMemDbgMutex && memDbgMutexEnabled)
    	pthread_mutex_lock(pMemDbgMutex);
#endif

    if (NULL != retBlock)
    {
        currentMemoryUsage = currentMemoryUsage + numBytes;
        totalMemoryUsage = totalMemoryUsage + numBytes;
        totalCallsToMalloc++;

        if (MEM_DBG_PAD)
        {
            /* we insert pad before and after block */
            DIGI_MEMSET(retBlock, MEM_DBG_PAD_CHAR, MEM_DBG_PAD);
            retBlock = retBlock + MEM_DBG_PAD;
            DIGI_MEMSET(retBlock + numBytes, MEM_DBG_PAD_CHAR, MEM_DBG_PAD);
        }

        for (findRow = 0; findRow < NUM_MEM_TABLE_ROWS; findRow++)
        {
            if (0 == memTable[findRow].rowUsed)
            {
                memTable[findRow].rowUsed   = 1;
                memTable[findRow].numBytes  = numBytes;
                memTable[findRow].pMemBlock = retBlock;
                memTable[findRow].pFile     = pFile;
                memTable[findRow].lineNum   = lineNum;
                break;
            }
        }

        if (NUM_MEM_TABLE_ROWS == findRow)
        {
            printf("dbg_malloc: not able to record address.\n");
        }
    }
    else
    {
        printf("dbg_malloc: malloc(size = %d) failed.\n", numBytes);
    }

    if (highWaterMark < currentMemoryUsage)
        highWaterMark = currentMemoryUsage;

    LogMemoryStat (numBytes, 1);

#ifdef __ENABLE_DIGICERT_TRACE_ALLOC__
    printf("Allocating %d bytes %s:%d\nTotal = %d\n", numBytes, pFile,
           lineNum, currentMemoryUsage);
#endif

#if defined (__LINUX_RTOS__)
    if (pMemDbgMutex && memDbgMutexEnabled)
    	pthread_mutex_unlock(pMemDbgMutex);
#endif

    return retBlock;
}

/*------------------------------------------------------------------*/

extern void *
dbg_malloc_align(ubyte4 numBytes, ubyte4 align, ubyte *pFile, ubyte4 lineNum)
{
    ubyte*  retBlock = NULL;
    sbyte4  findRow;


    if (34000 < numBytes)
    {
/*        printf("dbg_malloc: malloc awefully big (%d) bytes @ %s, line = %d.\n", (int)numBytes, (char *)pFile, (int)lineNum); */
    }

    if (0 == numBytes)
    {
        printf("dbg_malloc: zero byte malloc @ %s, line = %d.\n", (char *)pFile, (int)lineNum);
        return NULL;
    }

#if (defined(__RTOS_CYGWIN__) || defined(__RTOS_SOLARIS__) || defined(__RTOS_ANDROID__) || defined(__RTOS_VXWORKS__))
    retBlock = memalign (align, (size_t)MEM_DBG_PAD + numBytes + MEM_DBG_PAD);
#else
    if (0 != posix_memalign ((void **) &retBlock, align, MEM_DBG_PAD + numBytes + MEM_DBG_PAD))
    {
        retBlock = NULL;
    }
#endif

#if defined (__LINUX_RTOS__)
    if (pMemDbgMutex && memDbgMutexEnabled)
    	pthread_mutex_lock(pMemDbgMutex);
#endif

    if (NULL != retBlock)
    {
        currentMemoryUsage = currentMemoryUsage + numBytes;
        totalMemoryUsage = totalMemoryUsage + numBytes;
        totalCallsToMalloc++;

        if (MEM_DBG_PAD)
        {
            /* we insert pad before and after block */
            DIGI_MEMSET(retBlock, MEM_DBG_PAD_CHAR, MEM_DBG_PAD);
            retBlock = retBlock + MEM_DBG_PAD;
            DIGI_MEMSET(retBlock + numBytes, MEM_DBG_PAD_CHAR, MEM_DBG_PAD);
        }

        for (findRow = 0; findRow < NUM_MEM_TABLE_ROWS; findRow++)
        {
            if (0 == memTable[findRow].rowUsed)
            {
                memTable[findRow].rowUsed   = 1;
                memTable[findRow].numBytes  = numBytes;
                memTable[findRow].pMemBlock = retBlock;
                memTable[findRow].pFile     = pFile;
                memTable[findRow].lineNum   = lineNum;
                break;
            }
        }

        if (NUM_MEM_TABLE_ROWS == findRow)
        {
            printf("dbg_malloc: not able to record address.\n");
        }
    }
    else
    {
        printf("dbg_malloc: malloc(size = %d) failed.\n", numBytes);
    }

    if (highWaterMark < currentMemoryUsage)
        highWaterMark = currentMemoryUsage;

    LogMemoryStat (numBytes, 1);

#ifdef __ENABLE_DIGICERT_TRACE_ALLOC__
    printf("Allocating %d bytes %s:%d\nTotal = %d\n", numBytes, pFile,
           lineNum, currentMemoryUsage);
#endif

#if defined (__LINUX_RTOS__)
    if (pMemDbgMutex && memDbgMutexEnabled)
    	pthread_mutex_unlock(pMemDbgMutex);
#endif

    return retBlock;
}



/*------------------------------------------------------------------*/

static intBoolean
checkPad(ubyte *pBlockToTest, ubyte4 numBytes)
{
    ubyte*      pTest;
    ubyte4      count;
    intBoolean  isDamaged = FALSE;

    pTest = pBlockToTest - MEM_DBG_PAD;

    for (count = 0; count < MEM_DBG_PAD; count++)
    {
        if (MEM_DBG_PAD_CHAR != pTest[count])
        {
            printf("checkPad: pad before alloc block is damaged.\n%04x: ", count);
            for (; count < MEM_DBG_PAD; count++)
                printf("%02x ", pTest[count]);

            isDamaged = TRUE;
            break;
        }
    }

    pTest = pBlockToTest + numBytes;

    for (count = 0; count < MEM_DBG_PAD; count++)
    {
        if (MEM_DBG_PAD_CHAR != pTest[count])
        {
            printf("checkPad: pad after alloc block is damaged.\n%04x: ", count);
            for (; count < MEM_DBG_PAD; count++)
                printf("%02x ", pTest[count]);

            isDamaged = TRUE;
            break;
        }
    }

    return isDamaged;
}


/*------------------------------------------------------------------*/

extern void
dbg_free(void *pBlockToFree1, ubyte *pFile, ubyte4 lineNum)
{
    ubyte*  pBlockToFree = pBlockToFree1;
    sbyte4  findRow = NUM_MEM_TABLE_ROWS;
    ubyte4  numBytes = 0;
    sbyte*  pOrigFilename = NULL;
    sbyte4  origLineNum;

#if defined (__LINUX_RTOS__)
    if (pMemDbgMutex && memDbgMutexEnabled)
    	pthread_mutex_lock(pMemDbgMutex);
#endif

    if (NULL != pBlockToFree)
    {
        for (findRow = 0; findRow < NUM_MEM_TABLE_ROWS; findRow++)
        {
            if ((1 == memTable[findRow].rowUsed) && (pBlockToFree == memTable[findRow].pMemBlock))
            {
                pOrigFilename = (sbyte *)(memTable[findRow].pFile);
                origLineNum   = memTable[findRow].lineNum;
                numBytes      = memTable[findRow].numBytes;

                currentMemoryUsage -= numBytes;
                break;
            }
        }
    }
    else
    {
        printf("dbg_free: bad free!  NULL point!\n");
    }

    /* log bad free */
    if (NUM_MEM_TABLE_ROWS == findRow)
    {
        for (findRow = 0; findRow < NUM_FREE_TABLE_ROWS; findRow++)
        {
            if (0 == freeTable[findRow].rowUsed)
            {
                freeTable[findRow].rowUsed   = 1;
                freeTable[findRow].pMemBlock = pBlockToFree;
                freeTable[findRow].pFile     = pFile;
                freeTable[findRow].lineNum   = lineNum;
                pBlockToFree = NULL;
                break;
            }
        }
    } else
    {
      numBytes = memTable[findRow].numBytes;

#ifdef __ENABLE_DIGICERT_TRACE_ALLOC__
      printf("Releasing %d bytes %s:%d\nTotal = %d\n", numBytes, pFile, lineNum,
          currentMemoryUsage);
#endif
    }

    /* free it */
    if (NULL != pBlockToFree)
    {
        if (FALSE == checkPad(pBlockToFree, memTable[findRow].numBytes))
        {
            memTable[findRow].rowUsed = 0;
            free(pBlockToFree - MEM_DBG_PAD);
        }
        else
        {
            /* mark block damaged, don't bother to free */
            memTable[findRow].rowUsed = 2;
        }
    }

    LogMemoryStat (numBytes, 0);

#if defined (__LINUX_RTOS__)
    if (pMemDbgMutex && memDbgMutexEnabled)
    	pthread_mutex_unlock(pMemDbgMutex);
#endif

    return;
}


/*------------------------------------------------------------------*/

extern void
dbg_relabel_memory(void *pBlockToRelabel, ubyte *pFile, ubyte4 lineNum)
{
    sbyte4  findRow;

    if (NULL != pBlockToRelabel)
    {
        for (findRow = 0; findRow < NUM_MEM_TABLE_ROWS; findRow++)
        {
            if ((1 == memTable[findRow].rowUsed) && (pBlockToRelabel == memTable[findRow].pMemBlock))
            {
                memTable[findRow].pFile = pFile;
                memTable[findRow].lineNum = lineNum;
                break;
            }
        }
    }

    return;
}


/*------------------------------------------------------------------*/

extern void
dbg_check_memory(void *pBlockToCheck, ubyte *pFile, ubyte4 lineNum)
{
    sbyte4  findRow;

    if (NULL != pBlockToCheck)
    {
        for (findRow = 0; findRow < NUM_MEM_TABLE_ROWS; findRow++)
        {
            if ((1 == memTable[findRow].rowUsed) && (pBlockToCheck == memTable[findRow].pMemBlock))
            {
                if (TRUE == checkPad(pBlockToCheck, memTable[findRow].numBytes))
                {
                    /* block damaged */
                    memTable[findRow].rowUsed = 2;

                    /* relabel the memory to the point where the damage was first detected */
                    memTable[findRow].pFile = pFile;
                    memTable[findRow].lineNum = lineNum;
                }

                break;
            }
        }
    }
}

/*------------------------------------------------------------------*/

void
  LogMemoryStat (ubyte4 size, ubyte4 mFlag)
{
  ubyte4 index;

  /* Run through the list of used entries, if we find a match, break out and
   * we'll update it.
   */
  for (index = 0; index < entryListCount; ++index)
  {
    if (entryList[index].size == size)
      break;
  }

  /* If index >= entryListCount, then we did not find a match.
   */
  if (index >= entryListCount)
  {
    /* If this is a free, no entry found means error.
     */
    if (0 == mFlag)
    {
      memStatError |= 2;
      return;
    }

    /* If this is an allocation, add an entry, unless there are not enough
     * entries, in which case, error.
     */
    if (NUM_MEM_STAT_ENTRIES <= entryListCount)
    {
      memStatError |= 1;
      return;
    }

    entryList[entryListCount].size = size;
    entryList[entryListCount].totalCount = 1;
    entryList[entryListCount].concurrentCount = 1;
    entryList[entryListCount].maxConcurrentCount = 1;
    entryListCount++;
    return;
  }

  /* If we reach this code, we found a match. If this is free, all we have to do
   * is decrement concurrentCount.
   */
  if (0 == mFlag)
  {
    if (0 < entryList[index].concurrentCount)
      entryList[index].concurrentCount--;
    return;
  }

  /* This is an allocation, so increment totalCount and concurrentCount, then see
   * if the concurrentCount is greater than the current max.
   */
  entryList[index].totalCount++;
  entryList[index].concurrentCount++;
  if (entryList[index].concurrentCount > entryList[index].maxConcurrentCount)
    entryList[index].maxConcurrentCount = entryList[index].concurrentCount;
}

/*------------------------------------------------------------------*/

extern void
dbg_lookup_memory(void *pBlockToLookup, ubyte **ppRetFile, ubyte4 *pRetLineNum)
{
    sbyte4  findRow;

    if (NULL != pBlockToLookup)
    {
        for (findRow = 0; findRow < NUM_MEM_TABLE_ROWS; findRow++)
        {
            if ((1 == memTable[findRow].rowUsed) && (pBlockToLookup == memTable[findRow].pMemBlock))
            {
                *ppRetFile = memTable[findRow].pFile;
                *pRetLineNum = memTable[findRow].lineNum;
                break;
            }
        }
    }

    return;
}

#endif /* __ENABLE_DIGICERT_DEBUG_MEMORY__ */
