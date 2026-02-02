/*
 * mem_part.c
 *
 * Memory Partition Factory
 * Overlays a memory partition over a given memory region
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

#ifdef __ENABLE_DIGICERT_MEM_PART__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mem_part.h"
#include "../common/debug_console.h"

#if (defined(__KERNEL__) && (defined(__LINUX_RTOS__) || defined(__ANDROID_RTOS__)))
#include <linux/version.h>
#include <linux/hardirq.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26))
#include <asm/semaphore.h>
#else
#include <linux/semaphore.h>
#endif
#endif

#ifdef __ENABLE_DIGICERT_MEM_PART_DEBUG__
#include "../common/mfmgmt.h"
#endif

/*------------------------------------------------------------------*/

#define ROUND_MEM_BLOCK_SIZE(X)     ((0x0f + ((uintptr)X)) & ~0x0f)
#define FLOOR_MEM_BLOCK_SIZE(X)     (((uintptr)X) & ~0x0f)

#define MEM_BLOCK_HEADER_SIZE       ROUND_MEM_BLOCK_SIZE(sizeof(memBlockHeader))


/*------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_MEM_PART__
ubyte4 gInitFlag = 0;

#ifndef __DISABLE_DIGICERT_MEM_PART_MUTEX__
static sbyte4 mMutexCount;
#endif

#endif

#ifdef __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__
static ubyte4 gSmallPoolOverflows = 0;  /* number of times small alloc requests overflow */
static ubyte4 gMediumPoolOverflows = 0; /* number of times medium alloc requests overflow */
static ubyte4 gLargePoolOverflows = 0;  /* number of times large alloc requests overflow */
#endif

/*------------------------------------------------------------------*/

extern MSTATUS
MEM_PART_init(void)
{
    /* If it's already init, don't do anything.
     */
    if (0 != gInitFlag)
        return (OK);
    
    gInitFlag = 1;
    
    return (OK);
}


/*------------------------------------------------------------------*/

extern MSTATUS
MEM_PART_uninit(void)
{
    /* If it's not init, don't do anything.
     */
    if (0 == gInitFlag)
        return (OK);
    
    gInitFlag = 0;
    
    return (OK);
}


/*------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__
static MSTATUS
MEM_PART_createSinglePartition(memPartDescr **ppRetMemPartition, ubyte *pMemPartBaseTemp, usize memPartSize)
#else
extern MSTATUS
MEM_PART_createPartition(memPartDescr **ppRetMemPartition, ubyte *pMemPartBaseTemp, usize memPartSize)
#endif
{
    ubyte*  pMemPartBase;
    ubyte4  memPartHeadSize;
    MSTATUS status = OK;
    
    if ((NULL == ppRetMemPartition) || (NULL == pMemPartBaseTemp))
    {
        status = ERR_MEM_PART_NULL_PTR;
        goto exit;
    }
    
    pMemPartBase = (ubyte*)(ROUND_MEM_BLOCK_SIZE((usize)pMemPartBaseTemp));
    
    /* adjust memory partition size to fit new alignment */
    memPartSize = memPartSize - (usize)(((uintptr)pMemPartBase) - ((uintptr)pMemPartBaseTemp));
    
    /* only deal w/ 16 byte chunks, to keep memory aligned on a safe boundary */
    memPartSize = FLOOR_MEM_BLOCK_SIZE(memPartSize);
    
    if (MOC_MIN_PARTITION_SIZE > memPartSize)
    {
        /* too small of a partition */
        status = ERR_MEM_PART_CREATE;
        goto exit;
    }
    
    memPartHeadSize = ROUND_MEM_BLOCK_SIZE(sizeof(memPartDescr));
    
    /* clear out partition head */
    DIGI_MEMSET(pMemPartBase, 0x00, memPartHeadSize);
    
    *ppRetMemPartition = (memPartDescr *)pMemPartBase;
    
    (*ppRetMemPartition)->isMemPartDamaged  = FALSE;
    (*ppRetMemPartition)->isMemMutexEnabled = FALSE;
    
    (*ppRetMemPartition)->memPartitionSize  = (ubyte4)memPartSize;
    (*ppRetMemPartition)->pMemBaseAddress   = pMemPartBaseTemp;
    (*ppRetMemPartition)->pMemStartAddress  = memPartHeadSize + pMemPartBase;
    (*ppRetMemPartition)->pMemEndAddress    = memPartSize + pMemPartBase;
#if 32 == __DIGICERT_MAX_INT__
    (*ppRetMemPartition)->pPhysicalAddress.lower32 = (ubyte4) pMemPartBaseTemp;
    (*ppRetMemPartition)->pPhysicalAddress.upper32 = 0;
    (*ppRetMemPartition)->pKernelAddress.lower32  = (ubyte4) pMemPartBaseTemp;
    (*ppRetMemPartition)->pKernelAddress.upper32 = 0;
#else
    (*ppRetMemPartition)->pPhysicalAddress  = (ubyte8)((uintptr)pMemPartBaseTemp);
    (*ppRetMemPartition)->pKernelAddress    = (ubyte8)((uintptr)pMemPartBaseTemp);
#endif
    /* initialize head of list */
    (*ppRetMemPartition)->memBlockHead.pNextMemBlock = (struct memBlock_s *)(pMemPartBase + memPartHeadSize);
    (*ppRetMemPartition)->memBlockHead.memBlockSize  = 0;
    
    /* initialize first free memory *ppFreeMemBlock */
    (*ppRetMemPartition)->memBlockHead.pNextMemBlock->pNextMemBlock = NULL;
    (*ppRetMemPartition)->memBlockHead.pNextMemBlock->memBlockSize  =
    (ubyte4)(memPartSize - (usize)memPartHeadSize);
    
exit:
    return status;
}

#ifdef __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__
extern MSTATUS
MEM_PART_createPartition(memPartDescr **ppRetMemPartition, ubyte *pMemPartBaseTemp, usize memPartSize)
{
	MSTATUS status;
	memPartDescr *pTemp = NULL;
	ubyte *pNextBase = NULL;
	
	usize smallSize = (memPartSize >> 7) * MOC_PARTITION_SMALL_PARTS_PER_128;
	usize mediumSize = (memPartSize >> 7) * MOC_PARTITION_MEDIUM_PARTS_PER_128;
	usize largeSize = (memPartSize >> 7) * MOC_PARTITION_LARGE_PARTS_PER_128;
	
	/* validation and NULL checks done by MEM_PART_createSinglePartition */
	
	status = MEM_PART_createSinglePartition(ppRetMemPartition, pMemPartBaseTemp, smallSize);
	if (OK != status)
		goto exit;
	
	pNextBase = (*ppRetMemPartition)->pMemEndAddress;
	
	status = MEM_PART_createSinglePartition(&pTemp, pNextBase, mediumSize);
	if (OK != status)
		goto exit;
	
	pNextBase = pTemp->pMemEndAddress;
	
	/* pTemp is written into memory, no allocation or mutex, done with it, re-use pTemp */
	status = MEM_PART_createSinglePartition(&pTemp, pNextBase, largeSize);
	
	/* done, throw away pTemp again */
	pTemp = NULL;
	
	/* reset the overflow counts */
	gSmallPoolOverflows = 0;
	gLargePoolOverflows = 0;
	gMediumPoolOverflows = 0;
	
exit:
	
	return status;
}
#endif /* __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__ */

/*------------------------------------------------------------------*/

/* Only need an alternate version of MEM_PART_freePartition if mutex's are also enabled */
#if defined(__ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__) && !defined(__DISABLE_DIGICERT_MEM_PART_MUTEX__)
static MSTATUS
MEM_PART_freeSinglePartition(memPartDescr **ppFreeMemPartition)
#else
extern MSTATUS
MEM_PART_freePartition(memPartDescr **ppFreeMemPartition)
#endif
{
    MSTATUS status;
    
    if ((NULL == ppFreeMemPartition) || (NULL == *ppFreeMemPartition))
    {
        status = ERR_MEM_PART_NULL_PTR;
        goto exit;
    }
    
#ifndef __DISABLE_DIGICERT_MEM_PART_MUTEX__
    if (TRUE == (*ppFreeMemPartition)->isMemMutexEnabled)
    {
        if (OK > (status = RTOS_mutexFree(&((*ppFreeMemPartition)->memMutex))))
            goto exit;
    }
#endif
    
    *ppFreeMemPartition = NULL;
    status = OK;
    
exit:
    return status;
}

#if defined(__ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__) && !defined(__DISABLE_DIGICERT_MEM_PART_MUTEX__)
extern MSTATUS
MEM_PART_freePartition(memPartDescr **ppFreeMemPartition)
{
	MSTATUS status = ERR_MEM_PART_NULL_PTR;
	MSTATUS fstatus;
	memPartDescr *pMediumPart;
	memPartDescr *pLargePart;
	
	if (NULL == ppFreeMemPartition || NULL == *ppFreeMemPartition)
		goto exit;
	
	pMediumPart = (memPartDescr *) (*ppFreeMemPartition)->pMemEndAddress;
	pLargePart = (memPartDescr *) pMediumPart->pMemEndAddress;
	
	/* try to free all three partitions regardless of errors */
	status = MEM_PART_freeSinglePartition(&pLargePart);
	
	fstatus = MEM_PART_freeSinglePartition(&pMediumPart);
	if (OK == status)
		status = fstatus;
	
	fstatus = MEM_PART_freeSinglePartition(ppFreeMemPartition);
	if (OK == status)
		status = fstatus;
	
exit:
	
	return status;
}
#endif /* defined(__ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__) && !defined(__DISABLE_DIGICERT_MEM_PART_MUTEX__) */

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__
static MSTATUS
MEM_PART_enableMutexGuardSingle(memPartDescr *pMemPartition)
#else
extern MSTATUS
MEM_PART_enableMutexGuard(memPartDescr *pMemPartition)
#endif
{
    MSTATUS status;
    
#ifndef __DISABLE_DIGICERT_MEM_PART_MUTEX__
    if (OK > (status = RTOS_mutexCreate(&(pMemPartition->memMutex), MEM_PART_MUTEX, mMutexCount++)))
        return status;
#else
    status = OK;
#endif
    
    pMemPartition->isMemMutexEnabled = TRUE;
    
    return status;
}

#ifdef __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__
extern MSTATUS
MEM_PART_enableMutexGuard(memPartDescr *pMemPartition)
{
	MSTATUS status = ERR_MEM_PART_NULL_PTR;
	MSTATUS fstatus;
	memPartDescr *pMediumPart;
	memPartDescr *pLargePart;
	
	if (NULL == pMemPartition)
		goto exit;
	
	pMediumPart = (memPartDescr *) pMemPartition->pMemEndAddress;
	pLargePart = (memPartDescr *) pMediumPart->pMemEndAddress;
	
	/* try to enable all three partitions regardless of errors */
	status = MEM_PART_enableMutexGuardSingle(pLargePart);
	
	fstatus = MEM_PART_enableMutexGuardSingle(pMediumPart);
	if (OK == status)
		status = fstatus;
	
	fstatus = MEM_PART_enableMutexGuardSingle(pMemPartition);
	if (OK == status)
		status = fstatus;
	
exit:
	
	return status;
}
#endif /* __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__ */
/*------------------------------------------------------------------*/

extern MSTATUS
MEM_PART_assignOtherAddresses(memPartDescr *pMemPartition,
                              ubyte8 pPhysicalAddress, ubyte8 pKernelAddress)
{
#ifdef __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__
	return ERR_NOT_IMPLEMENTED;
#else

    pMemPartition->pPhysicalAddress = pPhysicalAddress;
    pMemPartition->pKernelAddress   = pKernelAddress;

    return OK;
#endif /* __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__ */
}


/*------------------------------------------------------------------*/

extern MSTATUS
MEM_PART_mapToPhysicalAddress(memPartDescr *pMemPartition, ubyte *pPartitionAddress,
                              ubyte8 *ppRetPhysicalAddress)
{
#ifdef __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__
	return ERR_NOT_IMPLEMENTED;
#else
    /* converts */
    MSTATUS status = OK;
    
    if ((NULL == pMemPartition) || (NULL == pPartitionAddress) || (NULL == ppRetPhysicalAddress))
    {
        status = ERR_MEM_PART_NULL_PTR;
        goto exit;
    }
    
    if (((uintptr)(pPartitionAddress) < (uintptr)(pMemPartition->pMemStartAddress)) ||
        ((uintptr)(pPartitionAddress) > (uintptr)(pMemPartition->pMemEndAddress)) )
    {
        /* not within partition's address range */
        status = ERR_MEM_PART_BAD_ADDRESS;
        goto exit;
    }
    
    /* calculate offset within partition, add physical address offset */
#if 32 == __DIGICERT_MAX_INT__
    ppRetPhysicalAddress->lower32 = (ubyte4) ((pPartitionAddress - pMemPartition->pMemBaseAddress) + pMemPartition->pPhysicalAddress);
    ppRetPhysicalAddress->upper32 = 0;
#else
    *ppRetPhysicalAddress = (pPartitionAddress - pMemPartition->pMemBaseAddress) + pMemPartition->pPhysicalAddress;
#endif

exit:
    return status;
#endif /* __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__ */
}


/*------------------------------------------------------------------*/

extern MSTATUS
MEM_PART_mapToKernelAddress(memPartDescr *pMemPartition, ubyte *pPartitionAddress,
                            ubyte8 *ppRetKernelAddress)
{
#ifdef __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__
	return ERR_NOT_IMPLEMENTED;
#else
    MSTATUS status = OK;
    
    if ((NULL == pMemPartition) || (NULL == pPartitionAddress) || (NULL == ppRetKernelAddress))
    {
        status = ERR_MEM_PART_NULL_PTR;
        goto exit;
    }
    
    if (((uintptr)(pPartitionAddress) < (uintptr)(pMemPartition->pMemStartAddress)) ||
        ((uintptr)(pPartitionAddress) > (uintptr)(pMemPartition->pMemEndAddress)) )
    {
        /* not within partition's address range */
        status = ERR_MEM_PART_BAD_ADDRESS;
        goto exit;
    }
    
    /* calculate offset within partition, add kernel address offset */
#if 32 == __DIGICERT_MAX_INT__
    ppRetKernelAddress->lower32 = (ubyte4) ((pPartitionAddress - pMemPartition->pMemBaseAddress) + pMemPartition->pKernelAddress);
    ppRetKernelAddress->upper32 = 0;
#else
    *ppRetKernelAddress = (pPartitionAddress - pMemPartition->pMemBaseAddress) + pMemPartition->pKernelAddress;
#endif

exit:
    return status;
#endif /* __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__ */
}


/*------------------------------------------------------------------*/

static MSTATUS
MEM_PART_lock(memPartDescr *pMemPartition)
{
    MSTATUS status = OK;
    
    if (pMemPartition->isMemMutexEnabled)
    {
#ifndef __DISABLE_DIGICERT_MEM_PART_MUTEX__
        RTOS_MUTEX mutex = pMemPartition->memMutex;
        
#if (defined(__KERNEL__) && (defined(__LINUX_RTOS__) || defined(__ANDROID_RTOS__)))
        if (in_atomic())
        {
            if (0 != (status = down_trylock((struct semaphore *)mutex)))
                status = ERR_MEM_PART;
        }
        else
#endif
            status = RTOS_mutexWait(mutex);
#endif
    }
    
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
MEM_PART_unlock(memPartDescr *pMemPartition)
{
    MSTATUS status = OK;
    
    if (pMemPartition->isMemMutexEnabled)
    {
#ifndef __DISABLE_DIGICERT_MEM_PART_MUTEX__
        status = RTOS_mutexRelease(pMemPartition->memMutex);
#endif
    }
    
    return status;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__
static MSTATUS
MEM_PART_allocSingle(memPartDescr *pMemPartition, ubyte4 numBytesToAlloc, void **ppRetNewMemBlock)
#else
extern MSTATUS
MEM_PART_alloc(memPartDescr *pMemPartition, ubyte4 numBytesToAlloc, void **ppRetNewMemBlock)
#endif
{
    ubyte4      magicNumOffset = numBytesToAlloc + MEM_BLOCK_HEADER_SIZE;
    memBlock*   pPrevBlock;
    memBlock*   pCurBlock;
    MSTATUS     status;
    MSTATUS     status1;
    
    if ((NULL == pMemPartition) || (NULL == ppRetNewMemBlock))
    {
        status = ERR_MEM_PART_NULL_PTR;
        goto no_cleanup;
    }
    
    *ppRetNewMemBlock = NULL;
    
    if (OK > (status = MEM_PART_lock(pMemPartition)))
        goto no_cleanup;
    
    if (pMemPartition->isMemPartDamaged)
    {
        /* we previously detected a buffer overflow, which most likely damaged the free list */
        status = ERR_MEM_PART_FREE_LIST_DAMAGED;
        goto exit;
    }
    
    if (0 == numBytesToAlloc)
    {
        status = ERR_MEM_PART_BAD_LENGTH;
        goto exit;
    }
    
    /* increase size to account for malloc header and magic number */
    /* round up the bytes to alloc */
    numBytesToAlloc = (ubyte4)ROUND_MEM_BLOCK_SIZE(MEM_BLOCK_HEADER_SIZE + numBytesToAlloc + sizeof(ubyte4));
    
    /* init link list traversal pointers */
    pPrevBlock = &(pMemPartition->memBlockHead);
    
    /* default to error */
    status = ERR_MEM_PART_ALLOC_FAIL;
    
    if (NULL == (pCurBlock = pMemPartition->memBlockHead.pNextMemBlock))
        goto exit;
    
    while (NULL != pCurBlock)
    {
        if (pCurBlock->memBlockSize >= numBytesToAlloc)
        {
            ubyte *pRetBlock;
            
            if (pCurBlock->memBlockSize == numBytesToAlloc)
            {
                pPrevBlock->pNextMemBlock = pCurBlock->pNextMemBlock;
                pRetBlock = (ubyte *)pCurBlock;
            }
            else
            {
                /* pCurBlock->memBlockSize > numBytesToAlloc */
                /* link up before remaining *ppFreeMemBlock */
                pCurBlock->memBlockSize = pCurBlock->memBlockSize - numBytesToAlloc;
                pRetBlock = ((ubyte *)pCurBlock) + pCurBlock->memBlockSize;
            }
            
            /* add malloc header */
            ((ubyte4 *)pRetBlock)[0] = numBytesToAlloc;
            ((ubyte4 *)pRetBlock)[1] = magicNumOffset;
            
            /* add magic number */
            pRetBlock[magicNumOffset]     = 0xff;
            pRetBlock[magicNumOffset + 1] = 0x5a;
            pRetBlock[magicNumOffset + 2] = 0x4b;
            pRetBlock[magicNumOffset + 3] = 0xff;
            
            /* results */
            *ppRetNewMemBlock = (pRetBlock + MEM_BLOCK_HEADER_SIZE);
            
            status = OK;
            break;
        }
        
        /* advance link list */
        pPrevBlock = pCurBlock;
        pCurBlock  = pCurBlock->pNextMemBlock;
    }
    
exit:
    status1 = MEM_PART_unlock(pMemPartition);
    /* don't obfuscate the first error */
    if (OK <= status)
        status = status1;
    
no_cleanup:
    return status;
    
} /* MEM_PART_alloc */

#ifdef __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__
extern MSTATUS
MEM_PART_alloc(memPartDescr *pMemPartition, ubyte4 numBytesToAlloc, void **ppRetNewMemBlock)
{
    MSTATUS status = ERR_MEM_PART_NULL_PTR;
    memPartDescr *pMedium;
    memPartDescr *pLarge;
    
    if (NULL == pMemPartition) /* ppRetNewMemBlock checked for NULL in below calls */
        goto exit;
    
    pMedium = (memPartDescr *) pMemPartition->pMemEndAddress;
    pLarge = (memPartDescr *) pMedium->pMemEndAddress;
    
    if (numBytesToAlloc <= MOC_PARTITION_SMALL_THRESHOLD)  /* try small, then medium, then large */
    {
        status = MEM_PART_allocSingle(pMemPartition, numBytesToAlloc, ppRetNewMemBlock);
        if (ERR_MEM_PART_ALLOC_FAIL != status)
            goto exit;
        
        gSmallPoolOverflows++;
        
        status = MEM_PART_allocSingle(pMedium, numBytesToAlloc, ppRetNewMemBlock);
        if (ERR_MEM_PART_ALLOC_FAIL != status)
            goto exit;
        
        gMediumPoolOverflows++;
        
        status = MEM_PART_allocSingle(pLarge, numBytesToAlloc, ppRetNewMemBlock);
    }
    else if (numBytesToAlloc <= MOC_PARTITION_MEDIUM_THRESHOLD)  /* try medium, then large, then small */
    {
        status = MEM_PART_allocSingle(pMedium, numBytesToAlloc, ppRetNewMemBlock);
        if (ERR_MEM_PART_ALLOC_FAIL != status)
            goto exit;
        
        gMediumPoolOverflows++;
        
        status = MEM_PART_allocSingle(pLarge, numBytesToAlloc, ppRetNewMemBlock);
        if (ERR_MEM_PART_ALLOC_FAIL != status)
            goto exit;
        
        gLargePoolOverflows++;
        
        status = MEM_PART_allocSingle(pMemPartition, numBytesToAlloc, ppRetNewMemBlock);
    }
    else /* numBytesToAlloc > MOC_PARTITION_MEDIUM_THRESHOLD, try large, then medium, then small */
    {
        status = MEM_PART_allocSingle(pLarge, numBytesToAlloc, ppRetNewMemBlock);
        if (ERR_MEM_PART_ALLOC_FAIL != status)
            goto exit;
        
        gLargePoolOverflows++;
        
        status = MEM_PART_allocSingle(pMedium, numBytesToAlloc, ppRetNewMemBlock);
        if (ERR_MEM_PART_ALLOC_FAIL != status)
            goto exit;
        
        gMediumPoolOverflows++;
        
        status = MEM_PART_allocSingle(pMemPartition, numBytesToAlloc, ppRetNewMemBlock);
    }
    
exit:

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_MEMORY, "MEM_PART_alloc() returns status = ", status);
    }
#endif

    return status;
}
#endif /* __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__ */

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__
static MSTATUS
MEM_PART_freeSingle(memPartDescr *pMemPartition, void **ppFreeMemBlock)
#else
extern MSTATUS
MEM_PART_free(memPartDescr *pMemPartition, void **ppFreeMemBlock)
#endif
{
    memBlock*       pCurBlock;
    memBlock*       pPrevBlock;
    memBlockHeader* pAdjacentBlock;
    memBlockHeader* pFreeBlock;
    ubyte*          pMagicNumber;
    ubyte4          blockSize;
    MSTATUS         status;
    MSTATUS         status1;
    
    if ((NULL == pMemPartition) || (NULL == ppFreeMemBlock))
    {
        status = ERR_MEM_PART_NULL_PTR;
        goto no_cleanup;
    }
    
    pFreeBlock = (memBlockHeader *)(((ubyte *)(*ppFreeMemBlock)) - MEM_BLOCK_HEADER_SIZE);
    
    if (((uintptr)(pFreeBlock) < (uintptr)(pMemPartition->pMemStartAddress)) ||
        ((uintptr)(pFreeBlock) > (uintptr)(pMemPartition->pMemEndAddress)) ||
        (FLOOR_MEM_BLOCK_SIZE((uintptr)pFreeBlock) != (uintptr)pFreeBlock) )
    {
        /* bad free! not within partition's address range */
        status = ERR_MEM_PART_BAD_ADDRESS;
        goto no_cleanup;
    }
    
    if (OK > (status = MEM_PART_lock(pMemPartition)))
        goto no_cleanup;
    
    pMagicNumber = (((ubyte *)pFreeBlock) + pFreeBlock->magicNumOffset);
    
    if (((MEM_BLOCK_HEADER_SIZE * 2) > (blockSize = pFreeBlock->totalMemBlockLength)) ||
        (FLOOR_MEM_BLOCK_SIZE(blockSize) != blockSize) ||
        (0xff != pMagicNumber[0]) || (0x5a != pMagicNumber[1]) ||
        (0x4b != pMagicNumber[2]) || (0xff != pMagicNumber[3]))
    {
        /* impossible for blockSize to be zero or non-multiple 16 bytes! */
        /* and verifies the magic number */
#ifdef __ENABLE_DIGICERT_MEM_PART_IGNORE_LIST_DAMAGE__
        pMemPartition->isMemPartDamaged = TRUE;
#endif
        status = ERR_MEM_PART_FREE_LIST_DAMAGED;
        goto exit;
    }
    
    pPrevBlock = &(pMemPartition->memBlockHead);
    pCurBlock  = pPrevBlock->pNextMemBlock;
    
    while ((NULL != pCurBlock) && ((uintptr)pCurBlock < (uintptr)(pFreeBlock)))
    {
        pPrevBlock = pCurBlock;
        pCurBlock  = pCurBlock->pNextMemBlock;
    }
    
    pAdjacentBlock = (memBlockHeader *)(((ubyte *)pPrevBlock) + pPrevBlock->memBlockSize);
    
    if (((uintptr)(pAdjacentBlock) > (uintptr)(pFreeBlock)) ||
        ((NULL != pCurBlock) && (((uintptr)(pFreeBlock) + blockSize) > (uintptr)(pCurBlock))) )
    {
#ifdef __ENABLE_DIGICERT_MEM_PART_IGNORE_LIST_DAMAGE__
        pMemPartition->isMemPartDamaged = TRUE;
#endif
        status = ERR_MEM_PART_FREE_LIST_DAMAGED;
        goto exit;
    }
    
    if ((uintptr)pAdjacentBlock == (uintptr)pFreeBlock)
    {
        /* easy instances, merge freed block w/ previous block */
        pPrevBlock->memBlockSize += blockSize;
    }
    else
    {
        /* link in free block, after previous block */
        ((memBlock *)(pFreeBlock))->memBlockSize  = blockSize;
        ((memBlock *)(pFreeBlock))->pNextMemBlock = pCurBlock;
        
        pPrevBlock->pNextMemBlock = (struct memBlock_s *)pFreeBlock;
        pPrevBlock = (memBlock *)pFreeBlock;
    }
    
    if ((((ubyte *)pPrevBlock) + pPrevBlock->memBlockSize) == (ubyte *)pCurBlock)
    {
        /* merge current block with previous block */
        pPrevBlock->memBlockSize  = pPrevBlock->memBlockSize  + pCurBlock->memBlockSize;
        pPrevBlock->pNextMemBlock = pCurBlock->pNextMemBlock;
    }
    
    /* clear pointer */
    *ppFreeMemBlock = NULL;
    
exit:
    status1 = MEM_PART_unlock(pMemPartition);
    /* don't obfuscate the first error */
    if (OK <= status)
        status = status1;
    
no_cleanup:
    return status;
    
} /* MEM_PART_freemem */

#ifdef __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__
extern MSTATUS
MEM_PART_free(memPartDescr *pMemPartition, void **ppFreeMemBlock)
{
    MSTATUS status = ERR_MEM_PART_NULL_PTR;
    memPartDescr *pNextPart;
    uintptr nextAddress;
    
    if (NULL == pMemPartition || NULL == ppFreeMemBlock || NULL == *ppFreeMemBlock)
        goto exit;
    
    nextAddress = (uintptr) (pMemPartition->pMemEndAddress);
    
    if ( (uintptr) *ppFreeMemBlock < nextAddress)
    {
        status = MEM_PART_freeSingle(pMemPartition, ppFreeMemBlock);
        goto exit;
    }
    
    pNextPart = (memPartDescr *) nextAddress;
    nextAddress = (uintptr) (pNextPart->pMemEndAddress);
    
    if ( (uintptr) *ppFreeMemBlock < nextAddress)
    {
        status = MEM_PART_freeSingle(pNextPart, ppFreeMemBlock);
        goto exit;
    }
    
    pNextPart = (memPartDescr *) nextAddress;
    nextAddress = (uintptr) (pNextPart->pMemEndAddress);
    
    if ( (uintptr) *ppFreeMemBlock < nextAddress)
    {
        status = MEM_PART_freeSingle(pNextPart, ppFreeMemBlock);
        goto exit;
    }
    
    status = ERR_MEM_PART_BAD_ADDRESS;
    
exit:
 
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_MEMORY, "MEM_PART_free() returns status = ", status);
    }
#endif
   
    return status;
}
#endif /* __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__ */

MOC_EXTERN MSTATUS MEM_PART_getBlockLen(void *pPtr, ubyte4 *pRetBlockLen)
{
    ubyte *pFront = NULL;

    if (NULL == pPtr || NULL == pRetBlockLen)
    {
        return ERR_NULL_POINTER;
    }

    /* Subtract thhe header length to get to the front of the block */
    pFront = ((ubyte *) pPtr) - MEM_BLOCK_HEADER_SIZE;  

    /* The length was embedded there as a ubyte4, but includes the header and 4 byte magic */
    *pRetBlockLen = (*((ubyte4 *) pFront)) - MEM_BLOCK_HEADER_SIZE - (ubyte4) (sizeof(ubyte4));

    return OK;
}

#ifdef __ENABLE_DIGICERT_MEM_PART_DEBUG__

#if __LONG_MAX__ == __INT_MAX__
#define PTR_FORMAT "%08x"
#else
#define PTR_FORMAT "%llx"
#endif

MOC_EXTERN MSTATUS MEM_PART_printMemoryPartitions(memPartDescr *pMemPartition, char *pOutFileName)
{
    memBlock *pCur = NULL;
    ubyte4 i = 0;
    MSTATUS status = OK;
    int retVal = 0;
    FileDescriptor pOutFile = NULL;

    if (NULL == pMemPartition || NULL == pOutFileName)
        return ERR_NULL_POINTER;

    status = FMGMT_fopen (pOutFileName, "w", &pOutFile);
    if (OK != status)
        goto exit;

    pCur = pMemPartition->memBlockHead.pNextMemBlock;
    while (NULL != pCur)
    {
        retVal = FMGMT_fprintf(pOutFile, "Block %d -> ptr at " PTR_FORMAT ", size = %d\n", i, (usize) (uintptr) pCur, pCur->memBlockSize);
        pCur = pCur->pNextMemBlock;
        i++;
    }

    status = FMGMT_fclose (&pOutFile);

exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_MEM_PART_DEBUG__ */

#endif /* __ENABLE_DIGICERT_MEM_PART__ */
