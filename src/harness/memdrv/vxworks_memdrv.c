/*
 * vxworks_memdrv.c
 *
 * VxWorks Memory Driver
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

#if defined ( __VXWORKS_MEMDRV__ )


/*------------------------------------------------------------------*/

#define MAX_MOC_NUM_PAGES   (60)

#define MEM_DRV_MAJOR       (252)


/*------------------------------------------------------------------*/

typedef struct
{
    void*           pPages;
    unsigned long   order;      /* 0, 1, 2, 3, 4, 5; which translates to 1, 2, 4, 8, 16, 32 */

} pageDescr;

static pageDescr myPages[MAX_MOC_NUM_PAGES];


/*------------------------------------------------------------------*/

static pageDescr *
VXWORKS_MEMDRV_findFreePageDescr(void)
{
    int index;

    for (index = 0; index < MAX_MOC_NUM_PAGES; index++)
        if (NULL == myPages[index].pPages)
            return &(myPages[index]);

    return NULL;
}


/*------------------------------------------------------------------*/

int
VXWORKS_MEMDRV_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{
    memDrvBlockDescr*   pDescrMemBuf = (memDrvBlockDescr *)arg;
    unsigned long       pageAddr;
    int                 retVal = 0;
    int                 isMutexLocked = 0;

#if (defined(__ENABLE_DEBUG_MEMDRV__))
    printf("VXWORKS_MEMDRV_ioctl: cmd = %u, arg = %08x\n", cmd, (int)arg);
#endif

    switch (cmd)
    {
        case MEMDRV_ALLOC_MEM_BLOCK:
        {
            pageDescr*  pPageDescr;
            int         numPages;

            /* lock mutex here */
            isMutexLocked = 1;

            if (NULL != file->private_data)
            {
                /* error! memory has not already been allocated to this file handle */
                retVal = -EACCES;
                break;
            }

            /* find a free location in the 'myPages' table */
            if (NULL == (pPageDescr = VXWORKS_MEMDRV_findFreePageDescr()))
            {
                /* error! table is full */
                retVal = -EMFILE;
                break;
            }

            /* convert size to num pages */
            pPageDescr->order = get_order(pDescrMemBuf->memAllocSize);

            /* allocate num pages */
            if (0 == (pageAddr = __get_free_pages(GFP_USER, pPageDescr->order)))
            {
                /* error! get pages failed */
                retVal = -ENOMEM;
                break;
            }

            /* save results */
            pPageDescr->pPages = (void *)pageAddr;
            pDescrMemBuf->pKernelAddress = (void *)pageAddr;        /* save kernel virtual address */
            pDescrMemBuf->pPhysicalAddress = (void *)__pa(pageAddr);    /* convert to physical address */

#if (defined(__ENABLE_DEBUG_MEMDRV__))
            printf("\nVXWORKS_MEMDRV_ioctl: kernel base address = %08x to %08x to %08x\n", (int)pDescrMemBuf->pKernelAddress, (int)pDescrMemBuf->memAllocSize + (int)pDescrMemBuf->pKernelAddress, (int)(PAGE_SIZE * (1 << pPageDescr->order)) + (int)pDescrMemBuf->pKernelAddress);
            printf("VXWORKS_MEMDRV_ioctl: physical base address = %08x to %08x to %08x\n\n", (int)pDescrMemBuf->pPhysicalAddress, (int)pDescrMemBuf->memAllocSize + (int)pDescrMemBuf->pPhysicalAddress, (int)(PAGE_SIZE * (1 << pPageDescr->order)) + (int)pDescrMemBuf->pPhysicalAddress);
#endif

            /* reserve it! */
            numPages    = 1 << pPageDescr->order;

            while (0 < numPages)
            {
                SetPageReserved(virt_to_page(pageAddr));

                pageAddr = pageAddr + PAGE_SIZE;
                numPages--;
            }

            /* store in file descriptor for future reference */
            file->private_data = pPageDescr;

            break;
        }

        default:
        {
            retVal = -EINVAL;
            break;
        }
    }

    if (0 != isMutexLocked)
    {
        /* unlock mutex here */
    }

    return retVal;
}


/*------------------------------------------------------------------*/

static int
VXWORKS_MEMDRV_open(struct inode *inode, struct file *file)
{
    file->private_data = NULL;

    return 0;
}


/*------------------------------------------------------------------*/

static int
VXWORKS_MEMDRV_release(struct inode *inode, struct file *file)
{
    pageDescr *pFreePages = (pageDescr *)(file->private_data);

    if ((NULL != pFreePages) && (NULL != pFreePages->pPages))
    {
        unsigned long   virtAddr;
        int             numPages = 1 << pFreePages->order;

        virtAddr = (unsigned long)pFreePages->pPages;

        /* return back in the same condition received; */
        /* undo the reserve so that the pages are swap-able */
        while (0 < numPages)
        {
            ClearPageReserved(virt_to_page(virtAddr));
            virtAddr += PAGE_SIZE;
            numPages--;
        }

        /* free the pages back to the kernel */
        free_pages((unsigned long)(pFreePages->pPages), pFreePages->order);

        /* to prevent a double free */
        pFreePages->pPages = NULL;
    }

    return 0;
}


/*------------------------------------------------------------------*/

static int
VXWORKS_MEMDRV_mmap(struct file *file, struct vm_area_struct *vma)
{
    pageDescr*      pFreePages = (pageDescr *)(file->private_data);
    unsigned long   vm_size    = vma->vm_end - vma->vm_start;
    int             result     = 0;

    if (NULL == pFreePages)
    {
        printf("VXWORKS_MEMDRV_mmap: no pages allocated\n");
        result = -EINVAL;
        goto exit;
    }

    if ((PAGE_SIZE * (1 << pFreePages->order)) < vm_size)
    {
        printf("VXWORKS_MEMDRV_mmap: bad size\n");
        result = -ENXIO;
        goto exit;
    }

    if ((vma->vm_flags & VM_WRITE) && !(vma->vm_flags & VM_SHARED))
    {
        printf("VXWORKS_MEMDRV_mmap: bad flags\n");
        result = -EINVAL;
        goto exit;
    }

    /* no swapping allowed, lock it */
    vma->vm_flags |= VM_LOCKED;

    if (remap_pfn_range(vma, vma->vm_start,
                         virt_to_phys(pFreePages->pPages) >> PAGE_SHIFT,
                         vm_size,
                         PAGE_SHARED))
    {
        printf("VXWORKS_MEMDRV_mmap: remap_page_range() returned error\n");
        result = -ENXIO;
    }

exit:
    return result;
}


#endif
