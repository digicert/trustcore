/*
 * timer.h
 *
 * Timer Functions
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

#ifndef __TIMER_H__
#define __TIMER_H__

MOC_EXTERN MSTATUS TIMER_initTimer(void);
MOC_EXTERN MSTATUS TIMER_deInitTimer(void);
MOC_EXTERN MSTATUS TIMER_createTimer( void (*callback_Fn)(void *, ubyte*), ubyte **timer);
MOC_EXTERN MSTATUS TIMER_destroyTimer(ubyte* timer);

/* For any created timer, use exclusively one group of API's (see below)!!! */

/* Original API's */
MOC_EXTERN MSTATUS TIMER_queueTimer(void * arg, ubyte* timer, ubyte4 tv_sec, ubyte4 tv_usec);
MOC_EXTERN MSTATUS TIMER_unTimer(void *arg, ubyte* timer);
MOC_EXTERN MSTATUS TIMER_unTimerEx(void *s, ubyte *timer, intBoolean (*matchTest_Fn)(void *,void*));
MOC_EXTERN MSTATUS TIMER_checkTimer(ubyte *timer);
MOC_EXTERN MSTATUS TIMER_getTimerElapsed(void *s, ubyte *timer, ubyte4 *pElapsedMs);
MOC_EXTERN MSTATUS TIMER_destroyTimerEx (ubyte *timer, void (*cleanUpQueuedTimer_Fn)(void *));

/* New API's */
#if defined(RTOS_timeCompare) && defined(RTOS_timerAddMS) /* must implement */
MOC_EXTERN MSTATUS TIMER_schedule(ubyte *timer, ubyte4 ms_timeout,
                                  sbyte4 cookie, ubyte4 cookie1, void *data,
                                  void (*callback_func)(sbyte4 cookie, ubyte4 cookie1,
                                                        void *data, ubyte4 id),
                                  /*void (*free_func)(void *data),*/
                                  sbyte *name, /* must be static */
                                  void **handle, ubyte4 *id);
MOC_EXTERN MSTATUS TIMER_unschedule(void *handle);
MOC_EXTERN MSTATUS TIMER_progress(ubyte *timer);
MOC_EXTERN MSTATUS TIMER_getNextTimeout(ubyte *timer, ubyte4 *ms_timeout);
#endif

#endif /* __TIMER_H__ */
