/*
 * nf_ipsec_async.c
 *
 * Linux IPsec kernel module async interface
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
 */

#include <linux/types.h>
#include <linux/ip.h>

#ifndef CONFIG_NETFILTER
  #define CONFIG_NETFILTER
  #define _NF_CONFIG_FOR_BUILD_
#endif
#include <linux/netfilter.h>
#ifdef _NF_CONFIG_FOR_BUILD_
  #undef CONFIG_NETFILTER
#endif

#include <linux/netfilter_ipv4.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/percpu.h>
#include <linux/version.h>
#include <linux/kthread.h>
#include <net/checksum.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/hardirq.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/route.h>
#include <asm/io.h>
#include <asm/checksum.h>
#include <asm/atomic.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
#include <net/netfilter/nf_queue.h>
#endif

#if defined(CONFIG_PROC_FS)
#include <linux/proc_fs.h>  /* Necessary because we use proc fs */
#include <asm/uaccess.h>    /* for copy_*_user */
#endif

#include "moptions.h"

#if defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)

#include "mtypes.h"
#include "mocana.h"
#include "hw_accel.h"

#include "mdefs.h"
#include "merrors.h"
#include "mstdlib.h"
#include "mrtos.h"
#include "debug_console.h"
#include "mem_pool.h"
#include "crypto.h"
#include "harness.h"

#include "ipsec.h"
#include "ipsecconf.h"
#include "ipseckey.h"
#include "ipsec_defs.h"
#include "ipsec_utils.h"
#include "ipsec_frag.h"
#include "ipsec_crypto.h"
#include "sadb.h"
#include "spd.h"

#include "nf_ipsec.h"
#include "nf_ipsec_priv.h"


/*------------------------------------------------------------------*/

#define __ENABLE_DIGICERT_LINUX_PROCFS__

#if (defined(__ENABLE_DIGICERT_LINUX_PROCFS__) && defined(CONFIG_PROC_FS))
#define PROC_ENTRY_FILENAME     "harness_timer"
#define PROCFS_MAX_SIZE         64
extern int  harness_timerVal;
#endif


/*------------------------------------------------------------------*/

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14))
  #define NF_REGISTER_QUEUE_HANDLER(a)      nf_register_queue_handler(a, ipsec_queue, NULL)
#else
  #define NF_REGISTER_QUEUE_HANDLER(a)      nf_register_queue_handler(a, &nf_qh)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23))
  #define NF_UNREGISTER_QUEUE_HANDLER(a)    nf_unregister_queue_handler(a)
#else
  #define NF_UNREGISTER_QUEUE_HANDLER(a)    nf_unregister_queue_handler(a, &nf_qh)
#endif

static int ipsec_queue_registered = 0;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25))
  #define NF_REINJECT(s, i, d)              nf_reinject(s, i, d)
#else
  #define NF_REINJECT(s, i, d)              nf_reinject(i, d)
#endif


/*------------------------------------------------------------------*/

#define __ENABLE_CTX_POOL__

#ifdef __ENABLE_CTX_POOL__
#ifdef __ENABLE_DIGICERT_HARNESS_PACKET_DRIVEN__
/* If error in insmod moc_ipsec "undefined symbol (__you_cannot_kmalloc_that_much)", reduce MAX_IPSEC_ASYNC_CTX to 1024) */
#define MAX_IPSEC_ASYNC_CTX     (1024+512)
#else
#define MAX_IPSEC_ASYNC_CTX     1024
#endif

static poolHeaderDescr *asyncCtxPoolId = NULL;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19))
static DEFINE_SPINLOCK(ctxPoolLock);
#else
static spinlock_t ctxPoolLock = SPIN_LOCK_UNLOCKED;
#endif

#define ALLOC_ASYNC_CTX(c, s) \
    spin_lock_bh(&ctxPoolLock); \
    s = MEM_POOL_getPoolObject(asyncCtxPoolId, (void **)&c); \
    spin_unlock_bh(&ctxPoolLock);

#define FREE_ASYNC_CTX(c) \
{\
    spin_lock_bh(&ctxPoolLock);\
    MEM_POOL_putPoolObject(asyncCtxPoolId, (void **)&c);\
    spin_unlock_bh(&ctxPoolLock);\
}

#else
#define ALLOC_ASYNC_CTX(c, s) \
    if (NULL == (c = kmalloc(sizeof(*c), GFP_ATOMIC))) \
        s = ERR_HARDWARE_ACCEL_NO_MEMORY; \
    else s = OK;

#define FREE_ASYNC_CTX(c) kfree(c);
#endif /* __ENABLE_CTX_POOL__ */

#ifndef __IPSEC_SADB_MALLOC__
#error Must define __IPSEC_SADB_MALLOC__
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25))
#define INIT_ASYNC_CTX(_inf, _sk, c, s) \
    ALLOC_ASYNC_CTX(c, s) \
    if (OK > s) c = NULL; \
    if (NULL != c) \
    { \
        /* Note: __IPSEC_SADB_MALLOC__ must be defined! */ \
        memset((ubyte *) c, 0, sizeof(*c)); \
        (c)->bAsyncEnabled = TRUE; \
        (c)->info = _inf; \
        (c)->skb = _sk; \
    }
#else
#define INIT_ASYNC_CTX(_inf, _sk, c, s) \
    ALLOC_ASYNC_CTX(c, s) \
    if (OK > s) c = NULL; \
    if (NULL != c) \
    { \
        /* Note: __IPSEC_SADB_MALLOC__ must be defined! */ \
        memset((ubyte *)c, 0, sizeof(*c)); \
        (c)->bAsyncEnabled = TRUE; \
        (c)->info = _inf; \
    }
#endif


/*------------------------------------------------------------------*/

/*#define YYY*/

extern void
ipsec_async_piggyback_flow(struct sk_buff *skb, void *sp, void *sa)
{
    unsigned char *tail = skb_tail_pointer(skb);

#if defined(YYY)
    if ((ubyte4)tail & 3L) tail += (4 - ((ubyte4)tail & 3L)); /* align */

    *((void**)tail) = sp;
    tail += sizeof(void*);
    *((void**)tail) = sa;
#else
    memcpy(tail, &sp, sizeof(void*));
    tail += sizeof(void*);
    memcpy(tail, &sa, sizeof(void*));
#endif
} /* ipsec_async_piggyback_flow */


/*------------------------------------------------------------------*/

static hwAccelDescr aHwAccelCtx[2] = { 0 };

static void ipsec_taskletfunc(unsigned long data);
static DECLARE_TASKLET(ipsec_tasklet_in, ipsec_taskletfunc, 1);
static DECLARE_TASKLET(ipsec_tasklet_out, ipsec_taskletfunc, 0);

#if !defined(__ENABLE_FREESCALE_8548_HARDWARE_ACCEL__) && \
    !defined(__ENABLE_FREESCALE_8349_HARDWARE_ACCEL__) && \
    !defined(__ENABLE_FREESCALE_8379_HARDWARE_ACCEL__)
  #define USE_IPSEC_THREAD
#endif

#if defined(__ENABLE_DIGICERT_HARNESS__)

#ifdef USE_IPSEC_THREAD

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19))
static DEFINE_SPINLOCK(hwAccelLock_0);
static DEFINE_SPINLOCK(hwAccelLock_1);
static spinlock_t aHwAccelLock[2] = { hwAccelLock_0, hwAccelLock_1 }
#else
static spinlock_t aHwAccelLock[2] = { SPIN_LOCK_UNLOCKED, SPIN_LOCK_UNLOCKED };
#endif

#endif


/*------------------------------------------------------------------*/

static int
ipsec_hw_offload(int i)
{
    hwAccelDescr    hwAccelCtx = aHwAccelCtx[i];
#ifdef USE_IPSEC_THREAD
    spinlock_t *lock = &(aHwAccelLock[i]);
#endif
    int ret = 0;

#if defined(__ENABLE_DIGICERT_HARNESS_PACKET_DRIVEN__)
    hwAccelCtx = aHwAccelCtx[0];
    HARNESS_doWork(hwAccelCtx);
    hwAccelCtx = aHwAccelCtx[1];
    HARNESS_doWork(hwAccelCtx);
    hwAccelCtx = aHwAccelCtx[i];
#endif

    /* get finsihed jobs */
    for (;;)
    {
        mahCompletionDescr* pCompleteDescr;
        IPSECCTX ctx = NULL;
        sbyte4 status = OK;

        struct sk_buff *skb;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25))
        struct nf_info *info;
#else
        struct nf_queue_entry *info;
#endif

        ubyte2 rlen, roff;
        struct iphdr *iph;

        intBoolean bTunneled = FALSE;

#ifdef USE_IPSEC_THREAD
        spin_lock_bh(lock);
#endif
        if (OK > HARNESS_getNorthChannelHead(hwAccelCtx, &pCompleteDescr))
        {
#ifdef USE_IPSEC_THREAD
            spin_unlock_bh(lock);
#endif
            break;
        }

        if (NULL != pCompleteDescr)
        {
            status = pCompleteDescr->hwAccelError;
            ctx = (IPSECCTX) pCompleteDescr->pSecurityStackCtx;

            pCompleteDescr->hwAccelError = 0;
            pCompleteDescr->pSecurityStackCtx = NULL;
        }

        HARNESS_incrementNorthChannelHead(hwAccelCtx);

#ifdef USE_IPSEC_THREAD
        spin_unlock_bh(lock);
#endif
        ret++;

        if (NULL == ctx) /* jic */
        {
#ifdef DEBUG_IPSEC_HW_OFFLOAD
            printk((i ? "{!}" : "<!>"));
#endif
            continue;
        }

        if (OK > status)
        {
            ctx->status = (sbyte4)status;
#ifdef DEBUG_IPSEC_HW_OFFLOAD
            printk((i ? "{!%d}" : "<!%d>"), status);
#endif
        }

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25))
        skb = ctx->skb;
        info = ctx->info;
#else
        info = ctx->info;
        skb = info->skb;
#endif

        if (i) /* de-capsulate */
        {
            status = IPSEC_permitEx(skb->data, (ubyte2)
                                    skb->len, /* unused! */
                                    &rlen, &roff, ctx);
            if (OK <= status)
            {
                if (0 == rlen) continue;
                if (0 != roff)
                {
                    skb_pull(skb, roff);
                    skb_reset_network_header(skb);
                }
                skb_trim(skb, rlen);
            }
        }
        else /* en-capsulate */
        {
            ubyte2 hdrm = 0;
#ifdef CHECK_HEAD_ROOM
            if (SKB_PUSHABLE(skb)) hdrm = HEAD_XTRA;
#endif
            status = IPSEC_applyEx(skb->data - hdrm, (ubyte2)
                                   skb->len, /* original packet size */
                                   &rlen, &roff, ctx);
            if (OK <= status)
            {
                if (0 == rlen) continue;
#ifdef CHECK_HEAD_ROOM
                if (hdrm && (hdrm != roff))
                {
                    unsigned int xhdrlen = hdrm - roff;
                    if (HEAD_XTRA < xhdrlen)
                    {
                        FREE_ASYNC_CTX(ctx)
                        NF_REINJECT(skb, info, NF_DROP);
                        continue;
                    }
                    skb_push(skb, xhdrlen);
                    skb_reset_network_header(skb);
                }
#endif
                skb_put(skb, rlen - skb->len);
            }
        }

        if (IPSEC_MODE_TUNNEL == ctx->pxSp->oMode)
            bTunneled = TRUE;

        FREE_ASYNC_CTX(ctx)

        if (OK > status)
        {
#ifdef DEBUG_IPSEC_HW_OFFLOAD
            printk((i ? "{%d}" : "<%d>"), status);
#endif
            NF_REINJECT(skb, info, NF_DROP);
            continue;
        }

        iph = skb_ip_header(skb);
        skb_set_transport_header(skb, (iph->ihl * 4));

        if (i) /* RX */
        {
            if (bTunneled)
            {
                skb_dst_drop(skb);

                if (ip_route_input(skb, iph->daddr, iph->saddr, iph->tos, skb->dev))
                {
                    NF_REINJECT(skb, info, NF_DROP);
                    continue;
                }

                if (RTCF_LOCAL & skb_rtable(skb)->rt_flags)
                {
                    /* re-assemble if necessary */
                    if (iph->frag_off & htons(IP_MF|IP_OFFSET))
                    {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
                        struct sk_buff *skb1 = ip_defrag(skb, IP_DEFRAG_LOCAL_DELIVER);
                        if (skb1) dst_input(skb1);
#else
                        if (0 != (ip_defrag(skb, IP_DEFRAG_LOCAL_DELIVER)))
#endif
                        {
                            NF_REINJECT(skb, info, NF_STOLEN);
                            continue;
                        }
                    }
                }
                else
                {
#if 0
                    dst_input(skb); /* will invoke NF_IP_FORWARD hook! */
#elif 1
                    dst_output(skb);
#else
                    /* copied from "ip_output()" */
                    if (skb->len > dst_pmtu(skb->dst)/* && !skb_shinfo(skb)->tso_size*/)
                        ip_fragment(skb, ip_finish_output);
                    else
                        ip_finish_output(skb);
#endif
                    NF_REINJECT(skb, info, NF_STOLEN);
                    continue;
                }
            }

            NF_REINJECT(skb, info, NF_ACCEPT);
        }
        else /* TX */
        {
            /* take care of fragmentation */
            if ((iph->frag_off & htons(IP_DF)) &&
                (dst_pmtu(skb_dst(skb)) < rlen))
            {
                skb->local_df = 1; /* hack */
            }
#if 0
            if (NF_IP_FORWARD == info->hook)
            {
                dst_output(skb);
                NF_REINJECT(skb, info, NF_STOLEN);
            }
            else
#endif
            NF_REINJECT(skb, info, NF_ACCEPT);
        }

    } /* for*/

    return ret;
} /* ipsec_hw_offload */


/*------------------------------------------------------------------*/

static void
ipsec_aync_callback(void *cb)
{
    int i = (int)cb;

#if (!defined(__ENABLE_DIGICERT_HARNESS_PACKET_DRIVEN__))
    if (in_irq())
#endif
    {
        if (i)
            tasklet_hi_schedule(&ipsec_tasklet_in);
        else
            tasklet_hi_schedule(&ipsec_tasklet_out);
        return;
    }

    /* get finsihed jobs */
#if (!defined(__ENABLE_DIGICERT_HARNESS_PACKET_DRIVEN__))
    ipsec_hw_offload(i);
#endif
}

#endif /* defined(__ENABLE_DIGICERT_HARNESS__) */


/*------------------------------------------------------------------*/

static int
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14))
ipsec_queue(struct sk_buff *skb, struct nf_info *info, void *data)
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25))
ipsec_queue(struct sk_buff *skb, struct nf_info *info, unsigned int queuenum, void *data)
#else
ipsec_queue(struct nf_queue_entry *info, unsigned int queuenum)
#endif
{
    sbyte4 status = 0;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))
    struct sk_buff *skb = info->skb;
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25))
    int i = (NF_IP_LOCAL_IN == info->hook) ? 1 : 0;
#else
    int i = (NF_INET_LOCAL_IN == info->hook) ? 1 : 0;
#endif

    IPSECCTX ctx = NULL;
    ubyte2 roff = 0;

#if 1
    if (!i) ipsec_hw_offload(0/*i*/);
#endif

    INIT_ASYNC_CTX(info, skb, ctx, status)
    if (OK > status) /* out of memory/mempool */
    {
        /* allow inbound non-IPsec traffic (e.g. udp) to go through!
           (outbound non-IPsec traffic already filtered out)
         */
        if (!i) goto exit;

#ifdef __ENABLE_CTX_POOL__
        ipsec_hw_offload(1/*i*/);
#endif
    }

    if (i) /* RX */
    {
        status = IPSEC_permitEx(skb->data, (ubyte2) skb->len,
                                NULL, &roff, ctx);
        if (STATUS_IPSEC_BYPASS == status)
        {
            if (ctx) FREE_ASYNC_CTX(ctx)

            status = 0;
            NF_REINJECT(skb, info, NF_ACCEPT);
        }
        /*else if (0 > status)
        {
            if (NULL == ctx)
            {
            }
            else
            if (ERR_HARNESS_CIRCULAR_BUF_FULL == status)
            {
                ipsec_hw_offload(i);
            }
            else
            if (ERR_IPSEC_DROP_FINDSA_FAIL != status)
            {
                printk("(%d)", status);
            }
        }*/
    }
    else /* TX */
    {
        unsigned char *tail = skb_tail_pointer(skb);

        ubyte2 hdrm = 0;
        unsigned int bufsize;

#ifdef CHECK_HEAD_ROOM
        if (SKB_PUSHABLE(skb)) hdrm = roff = HEAD_XTRA;
#endif
        bufsize = skb->len + skb_tailroom(skb) + hdrm;

#if defined(YYY)
        if ((ubyte4)tail & 3L) tail += (4 - ((ubyte4)tail & 3L)); /* align */

        ctx->pxSp = *((struct spd **)tail);
        tail += sizeof(struct spd *);
        ctx->axSaUsed[0] = *((struct sadb **)tail);
#else
        memcpy((void*) &ctx->pxSp, tail, sizeof(struct spd *));
        tail += sizeof(struct spd *);
        memcpy((void*) &ctx->axSaUsed[0], tail, sizeof(struct sadb *));
#endif

        status = IPSEC_applyEx(skb->data - hdrm, (ubyte2)
                               ((65535 < bufsize) ? 65535 : bufsize),
                               NULL, &roff, ctx);
        if (0 > status)
        {
            /*if (ERR_HARNESS_CIRCULAR_BUF_FULL == status)
            {
            }
            else
            if ((ERR_IPSEC_DROP_GETSA_FAIL != status) && (-1 != status))
            {
                printk("[%d]", status);
            }*/
        }
    }

exit:
    if (0 > status)
    {
        if (ctx) FREE_ASYNC_CTX(ctx)
    }

#if (defined(__ENABLE_DIGICERT_HARNESS_PACKET_DRIVEN__))
    ipsec_hw_offload(i);
#endif
    return (int)status;
} /* ipsec_queue */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14))
static struct nf_queue_handler nf_qh =
{
    .outfn  = ipsec_queue,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25))
    .data   = NULL,
#endif
    .name   = NULL,
};
#endif


/*------------------------------------------------------------------*/

static void
ipsec_taskletfunc(unsigned long data)
{
    ipsec_hw_offload((int)data);
#if 0
    if (data)
       tasklet_hi_schedule(&ipsec_tasklet_in);
    else
       tasklet_hi_schedule(&ipsec_tasklet_out);
#endif
}


/*------------------------------------------------------------------*/

#ifdef USE_IPSEC_THREAD

static struct task_struct *ipsec_thread = NULL;
static int ipsec_thread_running = 0;

static int
ipsec_threadfn(void *dummy)
{
    /* A single thread for both HW accl. contexts (in and out) */
    /* Note: Using 2 threads results in odd behaviors */
    while (!kthread_should_stop())
    {
        int more = 0;

        int i;
        for (i=0; i < 2; i++)
        {
            more += ipsec_hw_offload(i);
        }

        if (!more) schedule();
    } /* while */

    ipsec_thread_running = 0;

    return 0;
}

#endif /* USE_IPSEC_THREAD */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_LINUX_PROCFS__) && defined(CONFIG_PROC_FS))

/**
 * The buffer (64) for this module
 *
 */
static char procfs_buffer[PROCFS_MAX_SIZE];

/**
 * The size of the data hold in the buffer
 *
 */
static unsigned long procfs_buffer_size = 0;

/**
 * The structure keeping information about the /proc file
 *
 */
static struct proc_dir_entry *Our_Proc_File = NULL;

/**
 * This funtion is called when the /proc file is read
 *
 */
static ssize_t procfs_read(struct file *filp,   /* see include/linux/fs.h   */
                 char *buffer,  /* buffer to fill with data */
                 size_t length, /* length of the buffer     */
                 loff_t * offset)
{
    static int finished = 0;

    /*
     * We return 0 to indicate end of file, that we have
     * no more information. Otherwise, processes will
     * continue to read from us in an endless loop.
     */
    if ( finished ) {
        printk(KERN_INFO "procfs_read: END\n");
        finished = 0;
        return 0;
    }

    finished = 1;

    /*
     * We use put_to_user to copy the string from the kernel's
     * memory segment to the memory segment of the process
     * that called us. get_from_user, BTW, is
     * used for the reverse.
     */
    if ( copy_to_user(buffer, procfs_buffer, procfs_buffer_size) ) {
        return -EFAULT;
    }

    printk(KERN_INFO "procfs_read: read %lu bytes\n", procfs_buffer_size);

    return procfs_buffer_size;  /* Return the number of bytes "read" */
}

static int
kernel_atoi (const char *name)
{
  int val = 0;

  for (;; name++)
    {
      switch (*name)
	{
	case '0'...'9':
	  val = 10 * val + (*name - '0');
	  break;
	default:
	  return val;
	}
    }
}

/*
 * This function is called when /proc is written
 */
static ssize_t
procfs_write(struct file *file, const char *buffer, size_t len, loff_t * off)
{
    int val;
    if ( len > PROCFS_MAX_SIZE )    {
        procfs_buffer_size = PROCFS_MAX_SIZE;
    }
    else    {
        procfs_buffer_size = len;
    }

    if ( copy_from_user(procfs_buffer, buffer, procfs_buffer_size) ) {
        return -EFAULT;
    }

    printk(KERN_INFO "procfs_write: write %lu bytes\n", procfs_buffer_size);
    printk(KERN_INFO "procfs_write: write %lu MS %lu jiffies\n", RTOS_getUpTimeInMS(),jiffies);

    val = kernel_atoi(procfs_buffer);
    if ((val > 100 ) || (val < 1))
        printk(KERN_INFO "procfs_write: Invalid timerVal %d  Can be between 1 to 100\n", val);
    else
    {
        printk(KERN_INFO "procfs_write: timerVal %d  \n", val);
        harness_timerVal = val;
    }

    return procfs_buffer_size;
}

/*
 * This function decides whether to allow an operation
 * (return zero) or not allow it (return a non-zero
 * which indicates why it is not allowed).
 *
 * The operation can be one of the following values:
 * 0 - Execute (run the "file" - meaningless in our case)
 * 2 - Write (input to the kernel module)
 * 4 - Read (output from the kernel module)
 *
 * This is the real function that checks file
 * permissions. The permissions returned by ls -l are
 * for referece only, and can be overridden here.
 */

static int module_permission(struct inode *inode, int op, struct nameidata *foo)
{
    /*
     * We allow everybody to read from our module, but
     * only root (uid 0) may write to it
     */
    if (op == 4 || (op == 2 && current->euid == 0))
        return 0;

    /*
     * If it's anything else, access is denied
     */
    return -EACCES;
}

/*
 * The file is opened - we don't really care about
 * that, but it does mean we need to increment the
 * module's reference count.
 */
int procfs_open(struct inode *inode, struct file *file)
{
    try_module_get(THIS_MODULE);
    return 0;
}

/*
 * The file is closed - again, interesting only because
 * of the reference count.
 */
int procfs_close(struct inode *inode, struct file *file)
{
    module_put(THIS_MODULE);
    return 0;       /* success */
}

static struct file_operations File_Ops_4_Our_Proc_File = {
    .read    = procfs_read,
    .write   = procfs_write,
    .open    = procfs_open,
    .release = procfs_close,
};

/*
 * Inode operations for our proc file. We need it so
 * we'll have some place to specify the file operations
 * structure we want to use, and the function we use for
 * permissions. It's also possible to specify functions
 * to be called for anything else which could be done to
 * an inode (although we don't bother, we just put
 * NULL).
 */

static struct inode_operations Inode_Ops_4_Our_Proc_File = {
    .permission = module_permission,    /* check for permissions */
};

/*
 * Module initialization and cleanup
 */
static int proc_init_module()
{
    /* create the /proc file */
    Our_Proc_File = create_proc_entry(PROC_ENTRY_FILENAME, 0644, NULL);

    /* check if the /proc file was created successfuly */
    if (Our_Proc_File == NULL){
        printk(KERN_ALERT "Error: Could not initialize /proc/%s\n",
               PROC_ENTRY_FILENAME);
        return -ENOMEM;
    }

    Our_Proc_File->owner = THIS_MODULE;
    Our_Proc_File->proc_iops = &Inode_Ops_4_Our_Proc_File;
    Our_Proc_File->proc_fops = &File_Ops_4_Our_Proc_File;
    Our_Proc_File->mode = S_IFREG | S_IRUGO | S_IWUSR;
    Our_Proc_File->uid = 0;
    Our_Proc_File->gid = 0;
    Our_Proc_File->size = 80;

    printk(KERN_INFO "/proc/%s created\n", PROC_ENTRY_FILENAME);

    return 0;   /* success */
}

static void proc_cleanup_module()
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26))
    remove_proc_entry(PROC_ENTRY_FILENAME, &proc_root);
#else
    remove_proc_entry(PROC_ENTRY_FILENAME, NULL);
#endif
    printk(KERN_INFO "/proc/%s removed\n", PROC_ENTRY_FILENAME);
}

#endif /* (defined(__ENABLE_DIGICERT_LINUX_PROCFS__) && defined(CONFIG_PROC_FS)) */


/*------------------------------------------------------------------*/

extern int
ipsec_async_initialize(void)
{
    int status = 0, i;

#ifdef __ENABLE_CTX_POOL__
    void *pTempMemBuffer =
        kmalloc(sizeof(struct ipsecCtx) * MAX_IPSEC_ASYNC_CTX, GFP_ATOMIC);

    if (NULL == pTempMemBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = MEM_POOL_createPool(&asyncCtxPoolId, pTempMemBuffer,
                        sizeof(struct ipsecCtx) * MAX_IPSEC_ASYNC_CTX,
                        sizeof(struct ipsecCtx))))
    {
        kfree(pTempMemBuffer);
        goto exit;
    }
#endif

    for (i=0; i < 2; i++)
    {
        hwAccelDescr hwAccelCtx;

        if (OK > (status = IPSEC_getHwAccelChannel(&hwAccelCtx, i)))
            goto cleanup;

        aHwAccelCtx[i] = hwAccelCtx;
#ifdef __ENABLE_DIGICERT_HARNESS__
        HARNESS_enableAsyncMode(hwAccelCtx);
        HARNESS_assignCallbackCtx(hwAccelCtx, (void*)i);
        HARNESS_assignAsyncCallback(hwAccelCtx, ipsec_aync_callback);
#endif
        printk("Async. HW Accel. context[%s]: %d\n", (i ? "in" : "out"), hwAccelCtx);
    }

#ifdef USE_IPSEC_THREAD
    ipsec_thread = kthread_create(ipsec_threadfn, 0, "IPsec Async HW Offload");
    if (IS_ERR(ipsec_thread))
    {
        printk("%s: can't create thread\n", __FUNCTION__);
        ipsec_thread = NULL;
        status = ERR_IPSEC;
        goto cleanup;
    }
#endif

    if (0 > (status = NF_REGISTER_QUEUE_HANDLER(PF_INET)))
    {
        printk("%s: can't register queue handler (%d)\n", __FUNCTION__, status);
        goto cleanup;
    }
    ipsec_queue_registered = 1;

#ifdef USE_IPSEC_THREAD
    ipsec_thread_running = 1;
    wake_up_process(ipsec_thread);
#endif

    tasklet_hi_schedule(&ipsec_tasklet_in);
    tasklet_hi_schedule(&ipsec_tasklet_out);

#if (defined(__ENABLE_DIGICERT_LINUX_PROCFS__) && defined(CONFIG_PROC_FS))
    status = proc_init_module();
#endif

cleanup:
    if (0 > status)
        ipsec_async_cleanup();

exit:
    return status;
} /* ipsec_async_initialize */


/*------------------------------------------------------------------*/

extern void
ipsec_async_cleanup(void)
{
    int i;

#if (defined(__ENABLE_DIGICERT_LINUX_PROCFS__) && defined(CONFIG_PROC_FS))
    if (NULL != Our_Proc_File)
    {
        proc_cleanup_module();
        Our_Proc_File = NULL;
    }
#endif

    if (ipsec_queue_registered)
    {
        NF_UNREGISTER_QUEUE_HANDLER(PF_INET);
        ipsec_queue_registered = 0;
    }

    tasklet_disable(&ipsec_tasklet_in);
    tasklet_disable(&ipsec_tasklet_out);

#ifdef USE_IPSEC_THREAD
    if (NULL != ipsec_thread)
    {
        kthread_stop(ipsec_thread);
        while (ipsec_thread_running);
        ipsec_thread = NULL;
    }
#endif

    for (i=0; i < 2; i++)
    {
        hwAccelDescr hwAccelCtx = aHwAccelCtx[i];
        if (hwAccelCtx)
        {
#ifdef __ENABLE_DIGICERT_HARNESS__
            HARNESS_assignAsyncCallback(hwAccelCtx, NULL);
#endif
            IPSEC_releaseHwAccelChannel(&hwAccelCtx);
            aHwAccelCtx[i] = 0;
        }
    }

#ifdef __ENABLE_CTX_POOL__
    if (NULL != asyncCtxPoolId)
    {
        void *pTempMemBuffer;
        if (OK <= MEM_POOL_uninitPool(asyncCtxPoolId, &pTempMemBuffer))
            kfree(pTempMemBuffer);

        asyncCtxPoolId = NULL;
    }
#endif

    return;
} /* ipsec_async_cleanup */


#endif /* defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) */
