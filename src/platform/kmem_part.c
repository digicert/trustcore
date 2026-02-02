/*************************************************************************
 * File:        kmem_part.c
 * Created:     Tue Nov 14 16:46:59 PST 2006
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
 * Description: Shared kernel/user memory partition
 *************************************************************************/

#include "../common/moptions.h"

#if (defined(__LINUX_RTOS__) || defined(__ANDROID_RTOS__)) && defined(__ENABLE_DIGICERT_MEM_PART__)

#ifdef __KERNEL__
#include <linux/kernel.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#endif

#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/mem_part.h"
#include "../common/debug_console.h"
#include "../harness/memdrv/linux_memdrv.h"
#include "../platform/kmem_part.h"

#ifndef __KERNEL__
#define MEM_DRIVER_NAME "moc_memdrv"

static int memDrvFd = -1;

MSTATUS
/*************************************************************
 *    Function: KMEM_PART_createPartition
 * Description: .
 *************************************************************/
KMEM_PART_createPartition(memPartDescr **ppRetMemPartition,
                          ubyte4 memPartSize)
{
    ubyte            *pMemBlkForPart = NULL;
    MSTATUS          status          = OK;
    memDrvBlockDescr descrMemBuf;

    if (0 > memDrvFd) {
        if (0 > (memDrvFd = open("/dev/" MEM_DRIVER_NAME, O_RDWR, 0))) {
            status = -1;
            goto exit;
        }
    }
    if (0 > memDrvFd) {
        status = -1;
        goto exit;
    }
    descrMemBuf.memAllocSize = memPartSize;
    if (0 > ioctl(memDrvFd, MEMDRV_ALLOC_MEM_BLOCK,
                  (void *)&descrMemBuf)) {
        status = -1;
        goto exit;
    }
    if (0 == (pMemBlkForPart =
        mmap(0, descrMemBuf.memAllocSize, PROT_READ | PROT_WRITE, MAP_SHARED,
             memDrvFd, 0))) {
        status = ERR_HARNESS_MEM_ALLOC;
        goto exit;
    }
    if (0 > (status =
        MEM_PART_createPartition(ppRetMemPartition, pMemBlkForPart,
                                 memPartSize))) {
        status = ERR_HARNESS_MEM_ALLOC;
        goto exit;
    }
    MEM_PART_assignOtherAddresses(*ppRetMemPartition,
                                  descrMemBuf.pPhysicalAddress,
                                  descrMemBuf.pKernelAddress);
exit:
    if (0 > status) {
        if (0 <= memDrvFd) {
            close(memDrvFd);
            memDrvFd = -1;
        }
    }
    return status;
}

MSTATUS
/*************************************************************
 *    Function: KMEM_PART_alloc
 * Description: .
 *************************************************************/
KMEM_PART_alloc(memPartDescr *pMemPart, ubyte4 numBytesToAlloc,
                MemHandle_t *pMemHandle)
{
    MSTATUS status = OK;
    void    *userAddress;
    ubyte8   pPhysAddress, pKernAddress;

    if (0 > (status =
        MEM_PART_alloc(pMemPart, numBytesToAlloc,
                       &userAddress))) {
        goto exit;
    }
    MEM_PART_mapToPhysicalAddress(pMemPart,
                                  userAddress, &pPhysAddress);
    MEM_PART_mapToKernelAddress(pMemPart,
                                userAddress, &pKernAddress);
    pMemHandle->userAddress = (usize)userAddress;
    pMemHandle->kernAddress = pKernAddress;
    pMemHandle->physAddress = pPhysAddress;

exit:
    return status;
}

extern MSTATUS
/*************************************************************
 *    Function: KMEM_PART_free
 * Description: .
 *************************************************************/
KMEM_PART_free(memPartDescr *pMemPart, MemHandle_t *pMemHandle)
{
    MSTATUS status = OK;

    if (0 > (status =
        MEM_PART_free(pMemPart, (void **)&pMemHandle->userAddress))) {
        goto exit;
    }
    pMemHandle->userAddress = 0;
    pMemHandle->kernAddress = 0;
    pMemHandle->physAddress = 0;
exit:
    return status;
}

CircBuffer_t *
/*************************************************************
 *    Function: queue_create
 * Description: .
 *************************************************************/
queue_create(memPartDescr *pMemPart, ubyte4 nentries, ubyte4 entsize)
{
    CircBuffer_t *circBuffer = NULL;
    MSTATUS      status = OK;
    ubyte4       size;

    if (0 > (status =
        MEM_PART_alloc(pMemPart, sizeof(*circBuffer),
                       (void **)&circBuffer))) {
        goto exit;
    }
    DIGI_MEMSET((void *)circBuffer, 0, sizeof(*circBuffer));
    entsize = (entsize + 3) & 0xfffc;
    size    = nentries * entsize;
    if (0 > (status =
        KMEM_PART_alloc(pMemPart, size, &circBuffer->data))) {
        goto exit;
    }
    circBuffer->numEntries = nentries;
    circBuffer->entSize    = entsize;

exit:
    if (0 > status) {
        if (NULL != circBuffer) {
            MEM_PART_free(pMemPart, (void **)&circBuffer);
            circBuffer = NULL;
        }
    }
    return circBuffer;
}

MSTATUS
/*************************************************************
 *    Function: queue_delete
 * Description: .
 *************************************************************/
queue_delete(memPartDescr *pMemPart, CircBuffer_t *aQueue)
{
    KMEM_PART_free(pMemPart, &aQueue->data);
    MEM_PART_free(pMemPart,  (void **)&aQueue);
    return OK;
}
#endif

MSTATUS
/*************************************************************
 *    Function: queue_put_tail
 * Description: .
 *************************************************************/
queue_put_tail(CircBuffer_t *aQueue, ubyte *content, int size)
{
    ubyte4  offset, newtail;
    MSTATUS status = OK;

    newtail = (aQueue->tail + 1) % aQueue->numEntries;
    if (newtail == aQueue->head) {
        return -1;
    }
    offset       = aQueue->tail * aQueue->entSize;
#ifdef __KERNEL__
    DIGI_MEMCPY(&((ubyte *)aQueue->data.kernAddress)[offset], content, aQueue->entSize);
#else
    DIGI_MEMCPY(&((ubyte *)aQueue->data.userAddress)[offset], content, aQueue->entSize);
#endif
    aQueue->tail = newtail;
    DBUG_PRINT(DEBUG_COMMON,("head=%d, tail=%d", aQueue->head, aQueue->tail));
    return status;
}

MSTATUS
/*************************************************************
 *    Function: queue_get_head
 * Description: .
 *************************************************************/
queue_get_head(CircBuffer_t *aQueue, ubyte *content, int size)
{
    ubyte4  offset;
    MSTATUS status = OK;

    if (aQueue->tail == aQueue->head) {
        return -1;                      /* Empty */
    }
    offset       = aQueue->head * aQueue->entSize;
#ifdef __KERNEL__
    DIGI_MEMCPY(content, &((ubyte *)aQueue->data.kernAddress)[offset], aQueue->entSize);
#else
    DIGI_MEMCPY(content, &((ubyte *)aQueue->data.userAddress)[offset], aQueue->entSize);
#endif
    aQueue->head = (aQueue->head + 1) % aQueue->numEntries;
    DBUG_PRINT(DEBUG_COMMON,("head=%d, tail=%d", aQueue->head, aQueue->tail));
    return status;
}

#endif /* defined(__LINUX_RTOS__) && defined(__ENABLE_DIGICERT_MEM_PART__) */

