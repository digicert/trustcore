/*
 * moc_ipsec_bridge.c
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

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/semaphore.h>
#include <linux/time.h>
#include <linux/jiffies.h>

typedef unsigned char       ubyte;
typedef unsigned short      ubyte2;
typedef unsigned int        ubyte4;
typedef signed int          sbyte4;
typedef unsigned long long  ubyte8;
typedef void               *RTOS_MUTEX;

typedef struct TimeDate {
    ubyte m_year;
    ubyte m_month;
    ubyte m_day;
    ubyte m_hour;
    ubyte m_minute;
    ubyte m_second;
} TimeDate;

typedef struct moctime_t {
    union {
        ubyte4    time[2];
        long long jiffies;
    } u;
} moctime_t;

/* ---------------------------------------------------------------
 * Declare the MOC_* symbols imported from moc_platform_mod.ko
 * --------------------------------------------------------------- */
extern void    *MOC_malloc(size_t size);
extern void     MOC_ffree(void *data);
extern int      MOC_rtosInit(void);
extern int      MOC_rtosShutdown(void);
extern int      MOC_kernelTaskId(void);
extern int      MOC_mutexCreate2(RTOS_MUTEX *pMutex, int mutexCount);
extern int      MOC_mutexWait(RTOS_MUTEX mutex);
extern int      MOC_mutexRelease(RTOS_MUTEX mutex);
extern int      MOC_mutexFree(RTOS_MUTEX *pMutex);
extern ubyte4   MOC_getUpTimeInMS(void);
extern ubyte4   MOC_deltaMS(const moctime_t *pPrevTime, moctime_t *pRetCurrentTime);
extern void     MOC_sleepMS(ubyte4 sleepTimeInMS);
extern int      MOC_timeGMT(TimeDate *td);
extern sbyte4   MOC_readVFS(void *f, char *b, ubyte4 bLen, ubyte8 *off);

/* ---------------------------------------------------------------
 * DIGI_* wrappers that calls MOC_*
 * --------------------------------------------------------------- */
void *DIGI_malloc(size_t size)       { return MOC_malloc(size); }
void  DIGI_ffree(void *data)         { MOC_ffree(data); }
int   DIGI_rtosInit(void)            { return MOC_rtosInit(); }
int   DIGI_rtosShutdown(void)        { return MOC_rtosShutdown(); }
int   DIGI_kernelTaskId(void)        { return MOC_kernelTaskId(); }
int   DIGI_mutexCreate2(RTOS_MUTEX *pMutex, int mutexCount)
                                     { return MOC_mutexCreate2(pMutex, mutexCount); }
int   DIGI_mutexWait(RTOS_MUTEX mutex)    { return MOC_mutexWait(mutex); }
int   DIGI_mutexRelease(RTOS_MUTEX mutex) { return MOC_mutexRelease(mutex); }
int   DIGI_mutexFree(RTOS_MUTEX *pMutex)  { return MOC_mutexFree(pMutex); }
ubyte4 DIGI_getUpTimeInMS(void)      { return MOC_getUpTimeInMS(); }
ubyte4 DIGI_deltaMS(const moctime_t *p, moctime_t *c) { return MOC_deltaMS(p, c); }
void  DIGI_sleepMS(ubyte4 ms)        { MOC_sleepMS(ms); }
int   DIGI_timeGMT(TimeDate *td)     { return MOC_timeGMT(td); }
sbyte4 DIGI_readVFS(void *f, char *b, ubyte4 bLen, ubyte8 *off)
                                     { return MOC_readVFS(f, b, bLen, off); }

EXPORT_SYMBOL(DIGI_malloc);
EXPORT_SYMBOL(DIGI_ffree);
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
EXPORT_SYMBOL(DIGI_readVFS);

static int __init moc_ipsec_bridge_init(void) { return 0; }
static void __exit moc_ipsec_bridge_exit(void) {}

module_init(moc_ipsec_bridge_init);
module_exit(moc_ipsec_bridge_exit);

MODULE_AUTHOR("www.mocana.com");
MODULE_DESCRIPTION("ipsec bridge for FIPS build");
MODULE_LICENSE("GPL");
