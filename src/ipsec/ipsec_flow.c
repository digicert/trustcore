/**
 * @file  ipsec_flow.c
 * @brief NanoSec IPsec SA flow cache implementation.
 *
 * @details    This file contains IPsec Security Association flow cache implementation.
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IPSEC_SERVICE__
 *     +   \c \__ENABLE_IPSEC_FLOW__
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
 *
 */

#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_IPSEC_SERVICE__) && defined(__ENABLE_IPSEC_FLOW__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/random.h"
#include "../common/debug_console.h"
#include "../crypto/crypto.h"
#include "../harness/harness.h"

#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec6.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsec_crypto.h"
#include "../ipsec/ipsec_utils.h"
#include "../ipsec/ipsec_protos.h"
#include "../ipsec/ipsecconf.h"
#include "../ipsec/ipseckey.h"
#include "../ipsec/spd.h"
#include "../ipsec/sadb.h"
#include "../ipsec/ipsec_flow.h"


/*------------------------------------------------------------------*/

#if defined(__LINUX_RTOS__) && defined(__KERNEL__)
#include <linux/interrupt.h>
#include <linux/spinlock.h>


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19))
static DEFINE_SPINLOCK(flowLock_in);
static DEFINE_SPINLOCK(flowLock_out);
#else
static spinlock_t flowLock_in = SPIN_LOCK_UNLOCKED;
static spinlock_t flowLock_out = SPIN_LOCK_UNLOCKED;
#endif

#define LOCK_FLOW_TABLE(_out) \
{\
    spinlock_t *_lock = (_out ? &flowLock_out : &flowLock_in);\
    spin_lock_bh(_lock);\


#define UNLOCK_FLOW_TABLE(_o) \
    spin_unlock_bh(_lock);\
}

#elif defined(__QNX_RTOS__)
#include <pthread.h>

static pthread_spinlock_t flowLock_in;
static pthread_spinlock_t flowLock_out;

#define INIT_FLOW_TABLE_LOCK \
    pthread_spin_init(&flowLock_out, PTHREAD_PROCESS_SHARED); \
    pthread_spin_init(&flowLock_in, PTHREAD_PROCESS_SHARED);

#define DEL_FLOW_TABLE_LOCK \
    pthread_spin_destroy(&flowLock_in); \
    pthread_spin_destroy(&flowLock_out);

#define LOCK_FLOW_TABLE(_o) \
{\
    pthread_spinlock_t *_lock = (_o ? &flowLock_out : &flowLock_in);\
    pthread_spin_lock(_lock);\


#define UNLOCK_FLOW_TABLE(_o) \
    pthread_spin_unlock(_lock);\
}

#elif defined(__VXWORKS_RTOS__) && !defined(INCLUDE_IPNET_STACK)
static RTOS_MUTEX flowLock_in;
static RTOS_MUTEX flowLock_out;

#define INIT_FLOW_TABLE_LOCK \
    RTOS_mutexCreate(&flowLock_out, 0, 0); \
    RTOS_mutexCreate(&flowLock_in, 0, 0);

#define DEL_FLOW_TABLE_LOCK \
    RTOS_mutexFree(&flowLock_in); \
    RTOS_mutexFree(&flowLock_out);

#define LOCK_FLOW_TABLE(_o) \
{\
    RTOS_MUTEX _lock = (_o ? flowLock_out : flowLock_in);\
    RTOS_mutexWait(_lock);\


#define UNLOCK_FLOW_TABLE(_o) \
    RTOS_mutexRelease(_lock);\
}

#elif defined(__OSE_RTOS__) || defined(__VXWORKS_RTOS__)
#ifndef IPCOM_KERNEL
#define IPCOM_KERNEL
#endif
#include <ipcom_os.h>

static Ipcom_mutex flowLock_in;
static Ipcom_mutex flowLock_out;

#define INIT_FLOW_TABLE_LOCK \
    ipcom_mutex_create(&flowLock_out); \
    ipcom_mutex_create(&flowLock_in);

#define DEL_FLOW_TABLE_LOCK \
    ipcom_mutex_delete(&flowLock_in); \
    ipcom_mutex_delete(&flowLock_out);

#define LOCK_FLOW_TABLE(_o) \
{\
    Ip_u32 msr = ipcom_interrupt_disable();\
    Ipcom_mutex *_lock = (_o ? &flowLock_out : &flowLock_in);\
    ipcom_mutex_lock(*_lock);\


#define UNLOCK_FLOW_TABLE(_o) \
    ipcom_mutex_unlock(*_lock);\
    ipcom_interrupt_enable(msr);\
}

#endif

#ifndef LOCK_FLOW_TABLE
#define LOCK_FLOW_TABLE(_o)
#endif
#ifndef UNLOCK_FLOW_TABLE
#define UNLOCK_FLOW_TABLE(_o)
#endif
#ifndef INIT_FLOW_TABLE_LOCK
#define INIT_FLOW_TABLE_LOCK
#endif
#ifndef DEL_FLOW_TABLE_LOCK
#define DEL_FLOW_TABLE_LOCK
#endif

#define _IN     0
#define _OUT    1


/*------------------------------------------------------------------*/

MOC_EXTERN_DATA_DECL moctime_t gStartTime;


/*------------------------------------------------------------------*/

#ifndef IPSEC_FLOW_MAX
#define IPSEC_FLOW_MAX 4
#endif

struct flow
{
    SADB pxSa;
    ubyte4 dwSaId;

    SPD pxSp;
    ubyte4 dwSpId;

    MOC_IP_ADDRESS_S destAddr;
    MOC_IP_ADDRESS_S srcAddr;
    ubyte oProtocol;
    ubyte2 wDestPort;
    ubyte2 wSrcPort;

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    ubyte oMode; /* manual key; inbound */
#endif
};

static struct flow m_flowOut[IPSEC_FLOW_MAX] = { { NULL } };
static sbyte4 m_flowOutIndex = -1;

static struct flow m_flowIn[IPSEC_FLOW_MAX] = { { NULL } };
static sbyte4 m_flowInIndex = -1;


/*------------------------------------------------------------------*/

#ifdef __IPSEC_FLOW_COUNTERS__

#include <stdio.h>

static ubyte4 m_flowUsedOut = 0;
static ubyte4 m_flowUsedIn = 0;
static ubyte4 m_flowSaveOut = 0;
static ubyte4 m_flowSaveIn = 0;

extern void
IPSEC_flowPrint(void)
{
    sbyte4 i, count;

    printf("IPSEC_FLOW_MAX = %d\n", IPSEC_FLOW_MAX);

    printf("TX==> %u saved; used %u times\n", m_flowSaveOut, m_flowUsedOut);
    if (-1 <= (i = (m_flowOutIndex - 1))) /* most recently cached flow */
    {
        for (count = 0; count < IPSEC_FLOW_MAX; count++, i--)
        {
            struct flow *fl = &m_flowOut[(0<=i) ? i : (i=(IPSEC_FLOW_MAX-1))];

            SADB pxSa;
            if (NULL == (pxSa = fl->pxSa)) continue;

            printf("    %x[%d] -> %x[%d] ulp=%d SA=%p SP=%p\n",
                fl->srcAddr, (int) fl->wSrcPort,
                fl->destAddr, (int) fl->wDestPort,
                (int) fl->oProtocol,
                pxSa, fl->pxSp);
        }
    }

    printf("==>RX %u saved; used %u times\n", m_flowSaveIn, m_flowUsedIn);
    if (-1 <= (i = (m_flowInIndex - 1))) /* most recently cached flow */
    {
        for (count = 0; count < IPSEC_FLOW_MAX; count++, i--)
        {
            struct flow *fl = &m_flowIn[(0<=i) ? i : (i=(IPSEC_FLOW_MAX-1))];

            SADB pxSa;
            if (NULL == (pxSa = fl->pxSa)) continue;

            printf("    %x[%d] -> %x[%d] ulp=%d SA=%p SP=%p\n",
                fl->srcAddr, (int) fl->wSrcPort,
                fl->destAddr, (int) fl->wDestPort,
                (int) fl->oProtocol,
                pxSa, fl->pxSp);
        }
    }

    return;
} /* IPSEC_flowPrint */

#endif


/*------------------------------------------------------------------*/

extern MSTATUS
IPSEC_flowInit(void)
{
    INIT_FLOW_TABLE_LOCK

    m_flowOutIndex = 0;
    m_flowInIndex = 0;

    return OK;
} /* IPSEC_flowInit */


/*------------------------------------------------------------------*/

extern MSTATUS
IPSEC_flowFlush(void)
{
    DEL_FLOW_TABLE_LOCK

    DIGI_MEMSET((ubyte *)m_flowOut, 0x00, IPSEC_FLOW_MAX * sizeof(struct flow));
    m_flowOutIndex = -1;

    DIGI_MEMSET((ubyte *)m_flowIn, 0x00, IPSEC_FLOW_MAX * sizeof(struct flow));
    m_flowInIndex = -1;

#ifdef __IPSEC_FLOW_COUNTERS__
    m_flowUsedOut = 0;
    m_flowUsedIn = 0;
    m_flowSaveOut = 0;
    m_flowSaveIn = 0;
#endif

    return OK;
} /* IPSEC_flowFlush */


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_flowDel(MOC_IP_ADDRESS destAddr, MOC_IP_ADDRESS srcAddr,
              ubyte oProtocol, ubyte2 wDestPort, ubyte2 wSrcPort)
{
    LOCK_FLOW_TABLE(_OUT)

    if (0 <= m_flowOutIndex)
    {
        sbyte4 i;
        for (i=0; IPSEC_FLOW_MAX > i; i++)
        {
            struct flow *fl = &m_flowOut[i];

            if (NULL == fl->pxSa) continue;

            if ((!oProtocol || (oProtocol == fl->oProtocol)) &&
                (!wDestPort || (wDestPort == fl->wDestPort)) &&
                (!wSrcPort || (wSrcPort == fl->wSrcPort)) &&
                ((0 == destAddr) || SAME_MOC_IPADDR(destAddr, fl->destAddr)) &&
                ((0 == srcAddr) || SAME_MOC_IPADDR(srcAddr, fl->srcAddr)))
            {
                /* found */
                DIGI_MEMSET((ubyte *)fl, 0x00, sizeof(struct flow));
            }
        }
    }

    UNLOCK_FLOW_TABLE(_OUT)

    return OK;
} /* IPSEC_flowDel */


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_flowGet(SADB *ppxSa, SPD *ppxSp,
              MOC_IP_ADDRESS destAddr, MOC_IP_ADDRESS srcAddr,
              ubyte oProtocol, ubyte2 wDestPort, ubyte2 wSrcPort)
{
    MSTATUS status = OK;

    SADB pxSa = NULL;
    SPD pxSp = NULL;

    sbyte4 i;

    if ((NULL == ppxSa) || (NULL == ppxSp))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    LOCK_FLOW_TABLE(_OUT)

    if (-1 <= (i = (m_flowOutIndex - 1))) /* most recently cached flow */
    {
        sbyte4 count;
        for (count = 0; count < IPSEC_FLOW_MAX; count++, pxSa = NULL, i--)
        {
            struct flow *fl = &m_flowOut[(0<=i) ? i : (i=(IPSEC_FLOW_MAX-1))];

            if (NULL == (pxSa = fl->pxSa)) continue;

            if ((oProtocol == fl->oProtocol) &&
                (wDestPort == fl->wDestPort) && (wSrcPort == fl->wSrcPort) &&
                SAME_MOC_IPADDR(destAddr, fl->destAddr) &&
                SAME_MOC_IPADDR(srcAddr, fl->srcAddr))
            {
                if ((fl->dwSaId != pxSa->dwId) ||
                    !(IPSEC_SA_FLAG_INUSE & pxSa->saFlags) ||
                    (IPSEC_SA_FLAG_DELETED & pxSa->saFlags))
                {
                    fl->pxSa = pxSa = NULL;
                    break;
                }

                if (NULL == (pxSp = fl->pxSp)) /* jic */
                {
                    fl->pxSa = pxSa = NULL;
                    break;
                }

                if (fl->dwSpId != pxSp->dwId)
                {
                    fl->pxSa = pxSa = NULL;
                    pxSp = NULL;
                    break;
                }

                if (IPSEC_expireSa(RTOS_deltaMS(&gStartTime, NULL), pxSa))
                {
                    fl->pxSa = pxSa = NULL;
                    pxSp = NULL;
                    break;
                }

#ifdef __IPSEC_FLOW_COUNTERS__
                m_flowUsedOut++;
#endif
                break;
            }
        }
    }

    UNLOCK_FLOW_TABLE(_OUT)

    *ppxSp = pxSp;
    *ppxSa = pxSa;

exit:
    return (sbyte4)status;
} /* IPSEC_flowGet */


/*------------------------------------------------------------------*/

extern MSTATUS
IPSEC_flowPut(SADB pxSa, SPD pxSp,
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
              ubyte oMode,
#endif
              MOC_IP_ADDRESS destAddr, MOC_IP_ADDRESS srcAddr,
              ubyte oProtocol, ubyte2 wDestPort, ubyte2 wSrcPort)
{
    MSTATUS status = OK;

    if ((NULL == pxSa) || (NULL == pxSp)) /* jic */
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __ENABLE_IPSEC_NAT_T__
    /*  special case: If peer is behind NAT, don't save Transport-Mode flow!!! */
    if ((0 != pxSa->wSaUdpEncPort) &&
        (IPSEC_SA_FLAG_NAT_PEER & pxSa->saFlags))
    {
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if (IPSEC_MODE_TUNNEL != oMode)
#endif
            goto exit;
    }
#endif

    if (IPSEC_SP_FLAG_INBOUND & pxSp->flags)
    {
        LOCK_FLOW_TABLE(_IN)

        if (0 <= m_flowInIndex)
        {
            struct flow *fl = &m_flowIn[m_flowInIndex];

            fl->pxSa = pxSa;
            fl->dwSaId = pxSa->dwId;

            fl->pxSp = pxSp;
            fl->dwSpId = pxSp->dwId;

            COPY_MOC_IPADDR(fl->destAddr, destAddr);
            COPY_MOC_IPADDR(fl->srcAddr, srcAddr);

            fl->oProtocol = oProtocol;
            fl->wDestPort = wDestPort;
            fl->wSrcPort = wSrcPort;

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
            fl->oMode = oMode;
#endif
            m_flowInIndex = (m_flowInIndex + 1) % IPSEC_FLOW_MAX;

#ifdef __IPSEC_FLOW_COUNTERS__
            m_flowSaveIn++;
#endif
        }

        UNLOCK_FLOW_TABLE(_IN)
    }
    else
    {
        LOCK_FLOW_TABLE(_OUT)

        if (0 <= m_flowOutIndex)
        {
            struct flow *fl = &m_flowOut[m_flowOutIndex];

            fl->pxSa = pxSa;
            fl->dwSaId = pxSa->dwId;

            fl->pxSp = pxSp;
            fl->dwSpId = pxSp->dwId;

            COPY_MOC_IPADDR(fl->destAddr, destAddr);
            COPY_MOC_IPADDR(fl->srcAddr, srcAddr);

            fl->oProtocol = oProtocol;
            fl->wDestPort = wDestPort;
            fl->wSrcPort = wSrcPort;

            m_flowOutIndex = (m_flowOutIndex + 1) % IPSEC_FLOW_MAX;

#ifdef __IPSEC_FLOW_COUNTERS__
            m_flowSaveOut++;
#endif
        }

        UNLOCK_FLOW_TABLE(_OUT)
    }

exit:
    return status;
} /* IPSEC_flowPut */


/*------------------------------------------------------------------*/

extern MSTATUS
IPSEC_flowCheck(SADB pxSa0, SPD *ppxSp,
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                ubyte oMode,
#endif
                MOC_IP_ADDRESS destAddr, MOC_IP_ADDRESS srcAddr,
                ubyte oProtocol, ubyte2 wDestPort, ubyte2 wSrcPort)
{
    MSTATUS status = ERR_IPSEC;

    SPD pxSp = NULL;

    sbyte4 i;

    if ((NULL == pxSa0) || (NULL == ppxSp))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    LOCK_FLOW_TABLE(_IN)

    if (-1 <= (i = (m_flowInIndex - 1))) /* most recently cached flow */
    {
        sbyte4 count;
        for (count = 0; count < IPSEC_FLOW_MAX; count++, i--)
        {
            struct flow *fl = &m_flowIn[(0<=i) ? i : (i=(IPSEC_FLOW_MAX-1))];

            SADB pxSa;
            if (NULL == (pxSa = fl->pxSa)) continue;

            if ((oProtocol == fl->oProtocol) &&
                (wDestPort == fl->wDestPort) && (wSrcPort == fl->wSrcPort) &&
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                (oMode == fl->oMode) &&
#endif
                SAME_MOC_IPADDR(destAddr, fl->destAddr) &&
                SAME_MOC_IPADDR(srcAddr, fl->srcAddr))
            {
                if (pxSa0 != pxSa) break;

                if (fl->dwSaId != pxSa->dwId)
                {
                    fl->pxSa = NULL;
                    break;
                }

                if (NULL == (pxSp = fl->pxSp)) /* jic */
                {
                    fl->pxSa = NULL;
                    break;
                }

                if (fl->dwSpId != pxSp->dwId)
                {
                    fl->pxSa = NULL;
                    pxSp = NULL;
                    break;
                }

#ifdef __IPSEC_FLOW_COUNTERS__
                m_flowUsedIn++;
#endif
                status = OK; /* match !!! */
                break;
            }
        }
    }

    UNLOCK_FLOW_TABLE(_IN)

    *ppxSp = pxSp;

exit:
    return status;
} /* IPSEC_flowCheck */


#endif /* defined(__ENABLE_DIGICERT_IPSEC_SERVICE__) && defined(__ENABLE_IPSEC_FLOW__) */

