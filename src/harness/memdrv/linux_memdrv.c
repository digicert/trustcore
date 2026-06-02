/*
 * linux_memdrv.c
 *
 * Linux Memory Driver
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

#if defined (__RTOS_LINUX__)

#include <linux/version.h>

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/page-flags.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <asm/io.h>

#ifndef __DISABLE_DIGICERT_AUTO_CREATE_DEV_ENTRIES__
#include <linux/init.h>
#include <linux/device.h>
#include <asm/uaccess.h>
#include <linux/types.h>
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,8))
#include <linux/uaccess.h>
#endif
#include "./linux_memdrv.h"


/*------------------------------------------------------------------*/

#define MAX_MOC_NUM_PAGES   (60)

#define MEM_DRV_MAJOR       (255)

#ifndef __DISABLE_DIGICERT_AUTO_CREATE_DEV_ENTRIES__
static int mMemdrvDevMajor;
static struct class *mMemdrvDevClass;
#endif

/*------------------------------------------------------------------*/

typedef struct
{
    void*           pPages;
    unsigned long   order;      /* 0, 1, 2, 3, 4, 5; which translates to 1, 2, 4, 8, 16, 32 */

} pageDescr;

static pageDescr myPages[MAX_MOC_NUM_PAGES];


/*------------------------------------------------------------------*/

static pageDescr *
LINUX_MEMDRV_findFreePageDescr(void)
{
    int index;

    for (index = 0; index < MAX_MOC_NUM_PAGES; index++)
        if (NULL == myPages[index].pPages)
            return &(myPages[index]);

    return NULL;
}

/*------------------------------------------------------------------*/

extern int
LINUX_MEMDRV_release(struct inode *inode, struct file *file)
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
        file->private_data = NULL;
    }

    return 0;
}


/*------------------------------------------------------------------*/

#if ( (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)) )
long
LINUX_MEMDRV_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
#else
int
LINUX_MEMDRV_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
#endif
{
    memDrvBlockDescr    descrMemBuf = {0};
    unsigned long      pageAddr;
    int                 retVal = 0;
    int                 isMutexLocked = 0;

#if (defined(__ENABLE_DEBUG_MEMDRV__))
    printk("LINUX_MEMDRV_ioctl: cmd = %u, arg = %08x\n", cmd, (int)arg);
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

	    if (0 != copy_from_user(&descrMemBuf, (const void __user *)arg, sizeof(descrMemBuf)))
	    {
                retVal = -EACCES;
                break;
	    }

            /* find a free location in the 'myPages' table */
            if (NULL == (pPageDescr = LINUX_MEMDRV_findFreePageDescr()))
            {
                /* error! table is full */
                retVal = -EMFILE;
                break;
            }

            /* convert size to num pages */
            pPageDescr->order = get_order(descrMemBuf.memAllocSize);

            /* allocate num pages */
            if (0 == (pageAddr = __get_free_pages(GFP_USER, pPageDescr->order)))
            {
                /* error! get pages failed */
                retVal = -ENOMEM;
                break;
            }

            /* save results */
            pPageDescr->pPages = (void *)pageAddr;
            descrMemBuf.pKernelAddress = pageAddr;        /* save kernel virtual address */
            descrMemBuf.pPhysicalAddress = __pa(pageAddr);    /* convert to physical address */

#if (defined(__ENABLE_DEBUG_MEMDRV__))
            printk("\nLINUX_MEMDRV_ioctl: kernel base address = %08x to %08x to %08x\n", (int)descrMemBuf.pKernelAddress, (int)descrMemBuf.memAllocSize + (int)descrMemBuf.pKernelAddress, (int)(PAGE_SIZE * (1 << pPageDescr->order)) + (int)descrMemBuf.pKernelAddress);
            printk("LINUX_MEMDRV_ioctl: physical base address = %08x to %08x to %08x\n\n", (int)descrMemBuf.pPhysicalAddress, (int)descrMemBuf.memAllocSize + (int)descrMemBuf.pPhysicalAddress, (int)(PAGE_SIZE * (1 << pPageDescr->order)) + (int)descrMemBuf.pPhysicalAddress);
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

	    if (0 != copy_to_user((void __user *)arg, &descrMemBuf, sizeof(descrMemBuf)))
	    {
                retVal = -EACCES;
                break;
	    }

#if (defined(__ENABLE_DEBUG_MEMDRV__))
            printk("\nLINUX_MEMDRV_ioctl: kernel base address = %08x to %08x to %08x\n", (int)descrMemBuf.pKernelAddress, (int)descrMemBuf.memAllocSize + (int)descrMemBuf.pKernelAddress, (int)(PAGE_SIZE * (1 << pPageDescr->order)) + (int)descrMemBuf.pKernelAddress);
            printk("LINUX_MEMDRV_ioctl: physical base address = %08x to %08x to %08x\n\n", (int)descrMemBuf.pPhysicalAddress, (int)descrMemBuf.memAllocSize + (int)descrMemBuf.pPhysicalAddress, (int)(PAGE_SIZE * (1 << pPageDescr->order)) + (int)descrMemBuf.pPhysicalAddress);
#endif

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

extern int
LINUX_MEMDRV_open(struct inode *inode, struct file *file)
{
    file->private_data = NULL;

    return 0;
}


/*------------------------------------------------------------------*/

static int
LINUX_MEMDRV_mmap(struct file *file, struct vm_area_struct *vma)
{
    pageDescr*      pFreePages = (pageDescr *)(file->private_data);
    unsigned long   vm_size    = vma->vm_end - vma->vm_start;
    int             result     = 0;

    if (NULL == pFreePages)
    {
        printk("LINUX_MEMDRV_mmap: no pages allocated\n");
        result = -EINVAL;
        goto exit;
    }

    if ((PAGE_SIZE * (1 << pFreePages->order)) < vm_size)
    {
        printk("LINUX_MEMDRV_mmap: bad size\n");
        result = -ENXIO;
        goto exit;
    }

    if ((vma->vm_flags & VM_WRITE) && !(vma->vm_flags & VM_SHARED))
    {
        printk("LINUX_MEMDRV_mmap: bad flags\n");
        result = -EINVAL;
        goto exit;
    }

    /* no swapping allowed, lock it */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0))
    vm_flags_set(vma, VM_LOCKED);
#else
    vma->vm_flags |= VM_LOCKED;
#endif

    if (remap_pfn_range(vma, vma->vm_start,
                         virt_to_phys(pFreePages->pPages) >> PAGE_SHIFT,
                         vm_size,
                         vma->vm_page_prot))
    {
        printk("LINUX_MEMDRV_mmap: remap_page_range() returned error\n");
        result = -ENXIO;
    }

exit:
    return result;
}


/*------------------------------------------------------------------*/

/* table of callbacks */
static struct file_operations mocMemDrvOperations =
{
    .owner   = THIS_MODULE,
    .mmap    = LINUX_MEMDRV_mmap,
#if ( (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)) )
    .unlocked_ioctl = LINUX_MEMDRV_ioctl,
    .compat_ioctl =   LINUX_MEMDRV_ioctl,
#else
    .ioctl = LINUX_MEMDRV_ioctl,
#endif
    .open    = LINUX_MEMDRV_open,
    .release = LINUX_MEMDRV_release
};


/*------------------------------------------------------------------*/

static int __init
LINUX_MEMDRV_load(void)
{
    int index;
    int status = 0;

    printk("LINUX_MEMDRV_load: initializing driver\n");

#ifndef __DISABLE_DIGICERT_AUTO_CREATE_DEV_ENTRIES__
    if (0 > (mMemdrvDevMajor = register_chrdev(0, MEM_DRIVER_NAME, &mocMemDrvOperations)))
#else
    if (0 > (status = register_chrdev(MEM_DRV_MAJOR, MEM_DRIVER_NAME, &mocMemDrvOperations)))
#endif
    {
        printk("LINUX_MEMDRV_load: register_chrdev(), status = %d\n", status);
        status = -EIO;
        goto exit;
    }

#ifndef __DISABLE_DIGICERT_AUTO_CREATE_DEV_ENTRIES__
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0))
    mMemdrvDevClass = class_create(MEM_DRIVER_NAME);
#else
    mMemdrvDevClass = class_create(THIS_MODULE, MEM_DRIVER_NAME);
#endif
    device_create(mMemdrvDevClass, NULL, MKDEV(mMemdrvDevMajor, 1), "%s", MEM_DRIVER_NAME);
#endif

    printk("Memdrv device registration for %s (major=%d) succeed\n",
#ifndef __DISABLE_DIGICERT_AUTO_CREATE_DEV_ENTRIES__
           MEM_DRIVER_NAME, mMemdrvDevMajor);
#else
           MEM_DRIVER_NAME, MEM_DRV_MAJOR);
#endif

    /* initialize table */
    for (index = 0; index < MAX_MOC_NUM_PAGES; index++)
        myPages[index].pPages = NULL;

exit:
    if (0 == status)
        printk("LINUX_MEMDRV_load: driver initialization successful.\n");
    else
        printk("LINUX_MEMDRV_load: driver initialization failed.\n");

    return status;
}


/*------------------------------------------------------------------*/

static void __exit
LINUX_MEMDRV_unload(void)
{
    int index;

    /* iterate for each row of the table... */
    for (index = 0; index < MAX_MOC_NUM_PAGES; index++)
    {
        if (NULL != myPages[index].pPages)
        {
            unsigned long   virtAddr;
            int             numPages = 1 << myPages[index].order;

            virtAddr = (unsigned long)myPages[index].pPages;

            /* return back in the same condition received; */
            /* undo the reserve so that the pages are swap-able */
            while (0 < numPages)
            {
                ClearPageReserved(virt_to_page(virtAddr));
                virtAddr += PAGE_SIZE;
                numPages--;
            }

            /* free the pages back to the kernel */
            free_pages((unsigned long)(myPages[index].pPages), myPages[index].order);

            /* to prevent a miraculous double free */
            myPages[index].pPages = NULL;
        }
    }

    /* unregister the device */
#ifndef __DISABLE_DIGICERT_AUTO_CREATE_DEV_ENTRIES__
    device_destroy(mMemdrvDevClass, MKDEV(mMemdrvDevMajor, 1));
    class_destroy(mMemdrvDevClass);
    unregister_chrdev(mMemdrvDevMajor, MEM_DRIVER_NAME);
#else
    unregister_chrdev(MEM_DRV_MAJOR, MEM_DRIVER_NAME);
#endif

    return;
}


/*------------------------------------------------------------------*/

module_init(LINUX_MEMDRV_load);
module_exit(LINUX_MEMDRV_unload);

MODULE_AUTHOR("www.mocana.com");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Another Device Driver");

EXPORT_SYMBOL(LINUX_MEMDRV_ioctl);
EXPORT_SYMBOL(LINUX_MEMDRV_open);
EXPORT_SYMBOL(LINUX_MEMDRV_release);

#endif

