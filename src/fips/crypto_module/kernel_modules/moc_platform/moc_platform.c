/*************************************************************************
 * File:        moc_platform.c
 * Created:     Fri Apr 22 01:48:34 PST 2011
 * Description:
 *
 * Copyright (C) Mocana Corp 2006-2011. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Linking this program statically or dynamically with other modules is
 * making a combined work based on this program.  Thus, the terms and
 * conditions of the GNU General Public License cover the whole combination.
 *
 * As a special exception, the copyright holders of this program give you
 * permission to link this program with independent modules that
 * communicate with this program solely through the IPSEC_ interface,
 * regardless of the license terms of these independent modules, and to
 * copy and distribute the resulting combined work under terms of your
 * choice, provided that every copy of the combined work is accompanied by
 * a complete copy of the source code of this program (the version of this
 * program used to produce the combined work), being distributed under the
 * terms of the GNU General Public License plus this exception.
 * An independent module is a module which is not derived from or based on
 * this program.
 *
 * Note that people who make modified versions of this program are not
 * obligated to grant this special exception for their modified versions;
 * it is their choice whether to do so.  The GNU General Public License
 * gives permission to release a modified version without this exception;
 * this exception also makes it possible to release a modified version
 * which carries forward this exception.
 *************************************************************************/

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/percpu.h>
#include <linux/version.h>
#include <linux/kthread.h>
#include <linux/spinlock.h>
#include <linux/hardirq.h>
#include <asm/atomic.h>
#include <linux/sched.h>  /* task_pid_nr */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26))
#include <asm/semaphore.h>
#else
#include <linux/semaphore.h>
#endif
#include <linux/time.h>
#include <linux/sched.h>
#include <linux/jiffies.h>

#if defined (MOC_DEBUGGING_MOC_KERNEL_FILE_IO) || defined (__ENABLE_DIGICERT_FIPS_STATUS_MESSAGES__)
#define PRINTDEBUG printk
#else
#define PRINTDEBUG(...)
#endif

#ifdef MOC_USE_VFS_READ
#define USE_VFS_READ
#endif

#define LINUX_KERNEL_DISABLE_SLEEP_MS

/***************
 * From Linux source web-site:
 *     From Version 5.0 thru 5.14 (current): kernel_read parm order has buf first.
 *     From Version 4.2 (at least) thru version 4.13: kernel_read has offset first.
 *
 *     See DIGI_readVFS() for usage...
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0))
#define USE_LINUX_KERNEL_READ_OFFSET_FIRST 1
#else
#define USE_LINUX_KERNEL_READ_BUF_FIRST 1
#endif

/****************************************************
 * Typedefs Need to be kept in-sync with merrors.h & mtypes.h
 */
typedef unsigned char       ubyte;
typedef unsigned short      ubyte2;
typedef unsigned int        ubyte4;
typedef signed int          sbyte4;
typedef unsigned long long  ubyte8;
typedef void*               RTOS_MUTEX;

/* this structure is such that dates can be easily compared with memcmp */
typedef struct TimeDate
{
    ubyte   m_year;     /* year 0 = 1970, 1 =1971 , etc...*/
    ubyte   m_month;    /* 1 = january, ... 12 = december */
    ubyte   m_day;      /* 1 - 31 */
    ubyte   m_hour;     /* 0 - 23 */
    ubyte   m_minute;   /* 0 - 59 */
    ubyte   m_second;   /* 0 - 59 */
} TimeDate;

/* Do not assume anything about the meaning of the fields of
  moctime_t: use the API functions only! */
typedef struct moctime_t
{
    union {
        ubyte4    time[2];
        long long jiffies;              /* Linux kernel mode */
    } u;
} moctime_t;

#ifndef NULL
#define NULL (0)
#endif

#ifndef MOC_UNUSED
#define MOC_UNUSED(X)
#endif

#define NANOS 1000000000
#define _REENTRANT

#define INIT_MUTEX(X)  sema_init(X,1)

/****************************************************
 * Function prototypes
 */
extern void    *DIGI_malloc(size_t size);
extern void     DIGI_ffree(void *data);

extern int      DIGI_rtosInit(void);
extern int      DIGI_rtosShutdown(void);
extern int      DIGI_kernelTaskId(void);
extern int      DIGI_mutexCreate2(RTOS_MUTEX* pMutex, int mutexCount);
extern int      DIGI_mutexWait(RTOS_MUTEX mutex);
extern int      DIGI_mutexRelease(RTOS_MUTEX mutex);
extern int      DIGI_mutexFree(RTOS_MUTEX* pMutex);
extern ubyte4   DIGI_getUpTimeInMS(void);
extern ubyte4   DIGI_deltaMS(const moctime_t *pPrevTime, moctime_t *pRetCurrentTime);
extern void     DIGI_sleepMS(ubyte4 sleepTimeInMS);
extern int      DIGI_timeGMT(TimeDate* td);
extern sbyte4   DIGI_readVFS(void *f, char *b, ubyte4 bLen, ubyte8 *off);

/****************************************************
 * Implementations...
 */
extern void *DIGI_malloc(size_t size)
{
    /* Don't know where I'm from, so do it as atomic to be safe */
    return kmalloc(size, GFP_ATOMIC);
}

void DIGI_ffree(void *data)
{
    return kfree(data);
}

extern int DIGI_rtosInit(void)
{
    return 0;
}

extern int DIGI_rtosShutdown(void)
{
    return 0;
}

extern int DIGI_kernelTaskId(void)
{
    return (int)task_pid_nr(current);
}

typedef struct mocKrnMutex_s {
    spinlock_t krn_lock;
} mocKrnMutex_t ;


extern int DIGI_mutexCreate2(RTOS_MUTEX* pMutex, int mutexCount)
{
    mocKrnMutex_t *sem;
    int status = 0;
    MOC_UNUSED(mutexCount);

    if (NULL == (sem = DIGI_malloc(sizeof(*sem))))
    {
        status = -1;
        goto exit;
    }
    spin_lock_init(&sem->krn_lock);
    *pMutex = (RTOS_MUTEX)sem;

exit:
    return status;
}

extern int DIGI_mutexWait(RTOS_MUTEX mutex)
{
    mocKrnMutex_t *krnMutex = mutex;
    if(krnMutex)
    {
        spin_lock_bh(&krnMutex->krn_lock);
        return 0;
    }
    else
        return -1;
}

extern int DIGI_mutexRelease(RTOS_MUTEX mutex)
{
    mocKrnMutex_t *krnMutex = mutex;
    if(krnMutex)
    {
        spin_unlock_bh(&krnMutex->krn_lock);
        return 0;
    }
    else
        return -1;

}

extern int DIGI_mutexFree(RTOS_MUTEX* pMutex)
{
    int status = 0;

    if ((NULL == pMutex) || (NULL == *pMutex))
    {
        status = -1;
        goto exit;
    }

    DIGI_ffree(*pMutex);
    *pMutex = NULL;

  exit:
    return status;
}

extern ubyte4 DIGI_getUpTimeInMS(void)
{
    long long jiff = get_jiffies_64() * 1000;
    do_div (jiff, HZ);
    return (ubyte4)jiff;
}

extern ubyte4 DIGI_deltaMS(const moctime_t* origin, moctime_t* curtime)
{
    ubyte4 retVal = 0;

    long long jiff = get_jiffies_64();

    /* origin and current can point to the same struct */
    if (origin)
    {
        long long diff;
        diff   = (jiff - origin->u.jiffies) * 1000;
        do_div(diff, HZ);
        retVal = (ubyte4)diff;
    }

    if (curtime)
    {
        curtime->u.jiffies = jiff;
    }

    return retVal;
}

extern void DIGI_sleepMS(ubyte4 sleepTimeInMS)
{
#ifdef LINUX_KERNEL_DISABLE_SLEEP_MS
    /* Kernel mode, no sleeping */
    MOC_UNUSED(sleepTimeInMS);
#else
    int tval = (sleepTimeInMS*HZ+999)/1000;
    schedule_timeout(tval);
#endif
}

extern int DIGI_timeGMT(TimeDate* td)
{
    if (NULL == td)
        return -1;

    /* Do nothing for now */
    memset(td, 0, sizeof(*td));

    return 0;
}

/***************
 * From Linux source web-site:
 *     From Version 5.0 thru 5.14 (current):
 *         ssize_t kernel_read(struct file *file, void *buf, size_t count, loff_t *pos)
 *     From Version 4.2 (at least) thru some 4.13 version Changed between 4.13 & 4.14.
 *         int kernel_read(struct file *file, loff_t offset, char *addr, unsigned long count)
 */

#ifdef MOC_DEBUGGING_VERBOSE_MOC_KERNEL_FILE_IO
static int read_print_counter = 0;
#endif /* MOC_DEBUGGING_VERBOSE_MOC_KERNEL_FILE_IO */

extern sbyte4  DIGI_readVFS(void *f, char *b, ubyte4 bLen, ubyte8 *off)
{
#ifdef USE_VFS_READ
    ssize_t len = 0;
    struct file* fp = (struct file*)f;
    size_t l = (size_t)bLen;
    loff_t o = (loff_t)(*off);

    /* Read the file using kernel_read.
     * We may need to add multiple versions of this code since linux
     * changes it from time to time.
     */

#if (USE_LINUX_KERNEL_READ_BUF_FIRST == 1)
    /* Version 5.0 & above */
    len = kernel_read(fp, b, l, &o);
    *off = (ubyte8)o;
#elif (USE_LINUX_KERNEL_READ_OFFSET_FIRST == 1)
    /* Version 4.x */
    len = kernel_read(fp, o, b, l);
    *off = (ubyte8)(o + len);
#else
    #error (One of these versions must be defined)
#endif

#ifdef MOC_DEBUGGING_VERBOSE_MOC_KERNEL_FILE_IO
    if (read_print_counter++ < 42)
    {
        PRINTDEBUG("DIGI_readVFS(new) : retval = %ld\n",len);
    }
#endif /* MOC_DEBUGGING_VERBOSE_MOC_KERNEL_FILE_IO */

    return (sbyte4)len;

#else /* USE_VFS_READ */

#ifdef MOC_DEBUGGING_VERBOSE_MOC_KERNEL_FILE_IO
    if (read_print_counter++ < 42)
    {
        PRINTDEBUG("USE_VFS_READ is disabled... Returning -EINVAL \n");
    }
#endif /* MOC_DEBUGGING_VERBOSE_MOC_KERNEL_FILE_IO */
    return -EINVAL;

#endif /* USE_VFS_READ */
}

MODULE_AUTHOR("www.mocana.com");
MODULE_DESCRIPTION("Mocana platform code module");
MODULE_LICENSE("GPL");

/*************************************************************
 *    SYMBOLS to be EXPORTED
 *************************************************************/
EXPORT_SYMBOL(DIGI_rtosInit);
EXPORT_SYMBOL(DIGI_rtosShutdown);
EXPORT_SYMBOL(DIGI_kernelTaskId);
EXPORT_SYMBOL(DIGI_mutexCreate2);
EXPORT_SYMBOL(DIGI_mutexWait);
EXPORT_SYMBOL(DIGI_mutexRelease);
EXPORT_SYMBOL(DIGI_mutexFree);
EXPORT_SYMBOL(DIGI_getUpTimeInMS);
EXPORT_SYMBOL(DIGI_deltaMS);
EXPORT_SYMBOL(DIGI_sleepMS);
EXPORT_SYMBOL(DIGI_timeGMT);
EXPORT_SYMBOL(DIGI_ffree);
EXPORT_SYMBOL(DIGI_malloc);
EXPORT_SYMBOL(DIGI_readVFS);

/*************************************************************
 *    Function: main module 
 * Description: .
 *        void:
 *************************************************************/
extern int main_module(void)
{
    int status = 0;
    return status;

} /* main */

/*************************************************************
 *    Function: mss_ipsec_init
 * Description: .
 *        void:
 *************************************************************/

static int __init
moc_platform_init(void)
{
    int status = 0;
    PRINTDEBUG("moc_platform_init.\n");
    main_module();
    return status;

}

static void __exit
moc_platform_fini(void)
{
    PRINTDEBUG("moc_platform_fini.\n");
}

module_init(moc_platform_init);
module_exit(moc_platform_fini);
