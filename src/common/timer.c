/*
 * timer.c
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

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/random.h"
#include "../common/debug_console.h"
#include "../common/sizedbuffer.h"
#include "../common/mbitmap.h"
#include "../common/redblack.h"
#include "../common/timer.h"

typedef void (*timeout_callbackFn) (void *,ubyte*);

/* original API's */
typedef struct
{
    ubyte4 tv_sec;
    ubyte4 tv_usec;

} MO_TIMEVAL;

typedef struct moc_timer_t
{
    void *s;
    ubyte *type;
    MO_TIMEVAL timeout;
    moctime_t startTime;
    struct moc_timer_t *next;

} stimer_t;

typedef struct timerCb_s
{
    RTOS_MUTEX timer_semid;

#ifdef  __ENABLE_DIGICERT_DEBUG_CONSOLE__
    ubyte4 timer_id;
#endif
    ubyte4 next_event_id;
    ubyte4 num_events;

    timeout_callbackFn cbFn;
    stimer_t          *timer_head;  /* original API's */
#ifdef RTOS_timeCompare
    redBlackTreeDescr *timer_tree;  /* new API's */
#endif
} timerCb_t;

/* new API's */
typedef struct timerEvt_s
{
    timerCb_t *timer_cb;

#ifdef  __ENABLE_DIGICERT_DEBUG_CONSOLE__
    sbyte *name;
#endif
    ubyte4 event_id;
    void (*callback_func)(sbyte4 cookie, ubyte4 cookie1, void *data, ubyte4 id);
    sbyte4 cookie;
    ubyte4 cookie1;
    void *data;
    /*void (*free_func)(void *data);*/ /* TIMER_unschedule, TIMER_destroyTimer */

    ubyte4 timeout; /* ms */
    moctime_t start_time, end_time;

} timerEvt_t;

typedef struct timerGlobals_s
{
    RTOS_MUTEX  gSemid;
#ifdef  __ENABLE_DIGICERT_DEBUG_CONSOLE__
    ubyte4      gNextTimerid;
#endif
    ubyte4      gNumTimers;

} timerGlobals_t;

static timerGlobals_t gTimerGlobalState = { 0 };


/*------------------------------------------------------------------*/
/******************************************************************************

    Queue the timer as per its relative expiring time into the queue
    of the specific timer

******************************************************************************/

extern MSTATUS
TIMER_queueTimer(void *s, ubyte *timer, ubyte4 timeout, ubyte4 u_timeout )
{
    stimer_t  *t = NULL, *p, **head;
    ubyte4    msNew,msDiff;
    ubyte4    msPrev;
    timerCb_t *timerCb = (timerCb_t *)timer;
    MSTATUS   status = OK;

    if (!timerCb)
    {
        status = ERR_TIMER_NO_CONTBL;
        goto exit;
    }

    if (!timerCb->cbFn)
    {
        status = ERR_TIMER_NO_CALLBACKFN;
        goto exit;
    }

    if (!timeout && u_timeout < 100000)
    {
        DEBUG_ERROR(DEBUG_TIMER_MESSAGE, (sbyte*)"timeout value is very small Sec", (sbyte4)timeout);
        DEBUG_ERROR(DEBUG_TIMER_MESSAGE, (sbyte*)"usec", (sbyte4)u_timeout);
        status =  ERR_TIMER_INVALID_TIMEOUT;
        goto exit;
    }

    if (!s)
    {
        status = ERR_TIMER_NO_CONTBL;
        goto exit;
    }

    t = (stimer_t *)MALLOC(sizeof(stimer_t));

    if (!t)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET ((ubyte *)t, 0, sizeof(stimer_t));
    t->s = s;
    t->type = (ubyte *)timerCb;

    msNew = RTOS_deltaMS (NULL,&t->startTime);

    t->timeout.tv_sec = (timeout);
    t->timeout.tv_usec =  u_timeout;

    if( t->timeout.tv_usec >= 1000000 )
    {
        t->timeout.tv_sec += (t->timeout.tv_usec/1000000);
        t->timeout.tv_usec %= 1000000;
    }

    DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)"Timer ");
    DEBUG_UINT(DEBUG_TIMER_MESSAGE, timerCb->timer_id);
    DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)": Insert ");
    DEBUG_PTR(DEBUG_TIMER_MESSAGE, s);
    DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)" Sec ");
    DEBUG_INT(DEBUG_TIMER_MESSAGE, t->timeout.tv_sec);
    DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)" uSec ");
    DEBUG_INT(DEBUG_TIMER_MESSAGE, t->timeout.tv_usec);
    DEBUG_PRINTNL(DEBUG_TIMER_MESSAGE, (sbyte*)"");

    RTOS_mutexWait(timerCb->timer_semid);
    if (0 == (timerCb->num_events + 1))
    {
        status = ERR_TIMER;
    }
    else
    {
        for (head = &timerCb->timer_head; (0 != (p = *head)); head = &p->next)
        {
            msPrev = RTOS_deltaMS (&p->startTime,NULL);
            msDiff = msPrev - msNew;

            if (((msDiff - msDiff%1000)/1000  + t->timeout.tv_sec < p->timeout.tv_sec) ||
               (((msDiff - msDiff%1000)/1000  + t->timeout.tv_sec == p->timeout.tv_sec) &&
             ((msDiff%1000)*1000 + t->timeout.tv_usec < p->timeout.tv_usec)))
            {
                break;
            }
        }
        t->next = p;
        *head = t;
        timerCb->num_events++;
    }
    RTOS_mutexRelease(timerCb->timer_semid);

exit:
    if ((OK > status) && (t))
        FREE(t);
    return status;
}

/*------------------------------------------------------------------*/

/**********
 Delete a specific Timer Type for a session form the Timer Queue

**********/

extern MSTATUS
TIMER_unTimer(void *s, ubyte *timer)
{
    return TIMER_unTimerEx(s, timer, NULL);
}

/*------------------------------------------------------------------*/

extern MSTATUS
TIMER_unTimerEx(void *s, ubyte *timer, intBoolean (*matchTest_Fn)(void *,void*))
{
    stimer_t **copp, *freep;
    timerCb_t * timerCb = (timerCb_t*)timer;
    MSTATUS status = OK;

    if (!timerCb)
        goto exit;

    DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)"Timer ");
    DEBUG_UINT(DEBUG_TIMER_MESSAGE, timerCb->timer_id);
    DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)": Delete ");
    DEBUG_PTR(DEBUG_TIMER_MESSAGE, s);
    DEBUG_PRINTNL(DEBUG_TIMER_MESSAGE, (sbyte*)"");

    {
        RTOS_mutexWait(timerCb->timer_semid);
        for (copp = &timerCb->timer_head; (0 != (freep = *copp)); copp = &freep->next)
        {
            intBoolean isMatch;

            if (matchTest_Fn)
            {
                isMatch = matchTest_Fn(freep->s, s);
            } else
            {
                isMatch = (freep->s == s);
            }

            if (isMatch)
            {
                *copp = freep->next;
                FREE(freep);
                timerCb->num_events--;
                break;
            }
        }
        RTOS_mutexRelease(timerCb->timer_semid);
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*********************
 Check whether the Timer has expired
 If the current time is more than the
 expiry time of the top timer in the list, it is popped and presented to the
 calling module.

 If multiple timers expire then they are popped one after the other
 This has to be called by the main modules clock function every secondor 100 Millisecond

*******************/

extern MSTATUS
TIMER_checkTimer(ubyte *timer)
{
    timerCb_t * timerCb = (timerCb_t *)timer;
    stimer_t *p;
    ubyte4 msDiff;

    if (!timerCb)
        goto exit;

    RTOS_mutexWait(timerCb->timer_semid);
    while (timerCb->timer_head != NULL)
    {
        p = timerCb->timer_head;
        msDiff = RTOS_deltaMS(&p->startTime,NULL);
        if (!((p->timeout.tv_sec < msDiff/1000) ||
              ((p->timeout.tv_sec == msDiff/1000) &&
               (p->timeout.tv_usec <=  (msDiff%1000)*1000))))
        {
            break;      /* no, it's not time yet */
        }

        DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)"Timer ");
        DEBUG_UINT(DEBUG_TIMER_MESSAGE, timerCb->timer_id);
        DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)": Expired ");
        DEBUG_PTR(DEBUG_TIMER_MESSAGE, p->s);
        DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)" Current Time ");
        DEBUG_INT(DEBUG_TIMER_MESSAGE, msDiff/1000 );
        DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)" uSec ");
        DEBUG_INT(DEBUG_TIMER_MESSAGE, (msDiff % 1000)* 1000);
        DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)" Timeout Time ");
        DEBUG_INT(DEBUG_TIMER_MESSAGE, p->timeout.tv_sec);
        DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)" uSec ");
        DEBUG_INT(DEBUG_TIMER_MESSAGE, p->timeout.tv_usec);
        DEBUG_PRINTNL(DEBUG_TIMER_MESSAGE, (sbyte*)"");

        timerCb->timer_head = p->next;
        timerCb->num_events--;
        RTOS_mutexRelease(timerCb->timer_semid);
        timerCb->cbFn (p->s,p->type);
        FREE(p);
        RTOS_mutexWait(timerCb->timer_semid);
    }
    RTOS_mutexRelease(timerCb->timer_semid);

exit:
    return OK;
}


#ifdef RTOS_timeCompare

/*------------------------------------------------------------------*/

extern MSTATUS
TIMER_schedule(ubyte *timer, ubyte4 timeout /* ms */,
               sbyte4 cookie, ubyte4 cookie1, void *data,
               void (*callback_func)(sbyte4, ubyte4, void *, ubyte4),
               /*void (*free_func)(void *),*/
               sbyte *name,
               void **handle, ubyte4 *id)
{
    MSTATUS status = OK;

    timerCb_t *timerCb = (timerCb_t *)timer;
    timerEvt_t *t = NULL, *p = NULL;

    if (!timerCb)
    {
        status = ERR_TIMER_NO_CONTBL;
        goto exit;
    }

    if (!timeout)
    {
        DEBUG_ERROR(DEBUG_TIMER_MESSAGE, (sbyte*)"timeout value is very small (ms): ", (sbyte4)timeout);
        status =  ERR_TIMER_INVALID_TIMEOUT;
        goto exit;
    }

#if 0
    if (!data)
    {
        status = ERR_TIMER_NO_CONTBL;
        goto exit;
    }
#endif

    if (!(callback_func || timerCb->cbFn))
    {
        status = ERR_TIMER_NO_CALLBACKFN;
        goto exit;
    }

    t = (timerEvt_t *) MALLOC(sizeof(timerEvt_t)); /* TODO: pool? */
    if (!t)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMSET((ubyte *)t, 0x00, sizeof(timerEvt_t));

    t->timer_cb = timerCb;
    t->cookie = cookie;
    t->cookie1 = cookie1;
    t->data = data;
    t->callback_func = callback_func;
    /*t->free_func = free_func;*/
    t->timeout = timeout;
#ifdef  __ENABLE_DIGICERT_DEBUG_CONSOLE__
    t->name = name;
#endif
    RTOS_deltaMS(NULL, &t->start_time);
    t->end_time = t->start_time;
    RTOS_timerAddMS(&t->end_time, timeout);

    RTOS_mutexWait(timerCb->timer_semid);

    if (0 == (timerCb->num_events + 1))
    {
        RTOS_mutexRelease(timerCb->timer_semid);
        status = ERR_TIMER;
        goto exit;
    }

    status = REDBLACK_findOrInsert(timerCb->timer_tree, t, (const void **)&p);
    if ((OK > status) || p)
    {
        if (OK <= status)
        {
            status = ERR_RBTREE_INSERT_FAILED;
        }
        RTOS_mutexRelease(timerCb->timer_semid);
        goto exit;
    }
    t->event_id = ++timerCb->next_event_id;
    if (0 == t->event_id) t->event_id = 1; /* !!! */
    timerCb->num_events++;

    DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte *)"Timer ");
    DEBUG_UINT(DEBUG_TIMER_MESSAGE, timerCb->timer_id);
    DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte *)": +[");
    DEBUG_UINT(DEBUG_TIMER_MESSAGE, t->event_id);
    DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte *)"] ");
    DEBUG_INT(DEBUG_TIMER_MESSAGE, t->timeout / 1000);
    DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte *)" secs");
#ifdef  __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (t->timeout % 1000)
    {
        DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte *)" ");
        DEBUG_INT(DEBUG_TIMER_MESSAGE, t->timeout % 1000);
        DEBUG_PRINTNL(DEBUG_TIMER_MESSAGE, (sbyte *)" ms.");
    }
    else
#endif
    DEBUG_PRINTNL(DEBUG_TIMER_MESSAGE, (sbyte *)".");

    RTOS_mutexRelease(timerCb->timer_semid);

    if (handle)
    {
        *handle = (void *)t;
    }
    if (id)
    {
        *id = t->event_id;
    }

exit:
    if ((OK > status) && t)
    {
        FREE(t);
    }
    return status;
} /* TIMER_schedule */


/*------------------------------------------------------------------*/

extern MSTATUS
TIMER_unschedule(void *handle)
{
    MSTATUS status = OK;

    timerEvt_t *t = (timerEvt_t *)handle;
    timerCb_t *timerCb;
    void *p = NULL;

    if (!t)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    timerCb = (timerCb_t *) t->timer_cb;
    if (!timerCb)
    {
        status = ERR_TIMER_NO_CONTBL;
        goto exit;
    }

    RTOS_mutexWait(timerCb->timer_semid);

    DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte *)"Timer ");
    DEBUG_UINT(DEBUG_TIMER_MESSAGE, timerCb->timer_id);
    DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte *)": -[");
    DEBUG_UINT(DEBUG_TIMER_MESSAGE, t->event_id);
    DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte *)"]");

    status = REDBLACK_delete(timerCb->timer_tree, handle, (const void **)&p);
    if ((OK > status) || (p != handle))
    {
        DEBUG_PRINTNL(DEBUG_TIMER_MESSAGE, (sbyte*)" Failed.");
        if (OK <= status)
        {
            status = ERR_RBTREE; /* for now */
        }
    }
    else
    {
        DEBUG_PRINTNL(DEBUG_TIMER_MESSAGE, (sbyte*)".");
        timerCb->num_events--;
    }

    RTOS_mutexRelease(timerCb->timer_semid);

    if (OK <= status)
    {
        /*if (t->free_func)
        {
            t->free_func(t->data);
        }*/
        DIGI_MEMSET((ubyte *)handle, 0x00, sizeof(timerEvt_t));
        FREE(handle);
    }

exit:
    return status;
} /* TIMER_unschedule */


/*--------------------------------------------------------------------------*/

#define USE_COND_DEL_FIRST

#ifdef USE_COND_DEL_FIRST

static intBoolean
checkTimerEvent(const void *pKey)
{
    intBoolean bRet = FALSE;

    timerEvt_t *p;
    ubyte4 msDiff;
#ifdef  __ENABLE_DIGICERT_DEBUG_CONSOLE__
    timerCb_t *timerCb;
#endif

    if (NULL == pKey) /* jic */
    {
        bRet = TRUE;
        goto exit;
    }

    p = (timerEvt_t *)pKey;
    msDiff = RTOS_deltaMS(&p->start_time, NULL);

    if (msDiff < p->timeout)
    {
        goto exit; /* no, it's not time yet */
    }

#ifdef  __ENABLE_DIGICERT_DEBUG_CONSOLE__
    timerCb = (timerCb_t *) p->timer_cb;
#endif
    DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)"Timer ");
    DEBUG_UINT(DEBUG_TIMER_MESSAGE, timerCb->timer_id);
    DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte *)":     -[");
    DEBUG_UINT(DEBUG_TIMER_MESSAGE, p->event_id);
    DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)"] ");
    DEBUG_INT(DEBUG_TIMER_MESSAGE, msDiff / 1000 );
    DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)" secs");
#ifdef  __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (msDiff % 1000)
    {
        DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte *)" ");
        DEBUG_INT(DEBUG_TIMER_MESSAGE, msDiff % 1000);
        DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte *)" ms");
    }
#endif
    DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)" (> ");
    DEBUG_INT(DEBUG_TIMER_MESSAGE, p->timeout / 1000);
    DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)" secs");
#ifdef  __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (p->timeout % 1000)
    {
        DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte *)" ");
        DEBUG_INT(DEBUG_TIMER_MESSAGE, p->timeout % 1000);
        DEBUG_PRINTNL(DEBUG_TIMER_MESSAGE, (sbyte *)" ms).");
    }
    else
#endif
    DEBUG_PRINTNL(DEBUG_TIMER_MESSAGE, (sbyte *)").");

    bRet = TRUE;

exit:
    return bRet;
} /* checkTimerEvent */

#endif


/*--------------------------------------------------------------------------*/

#define IS_RB_NULL(_n)  (((_n)->pLeft == (_n)->pRight) && \
                         ((_n)->pRight == (_n)->pParent) && \
                         (NULL == (_n)->pKey) && (BLACK == (_n)->color))

extern MSTATUS
TIMER_progress(ubyte *timer)
{
    MSTATUS status = OK;

    timerCb_t *timerCb = (timerCb_t *)timer;
    redBlackTreeDescr *pTree;

    if (!timerCb)
    {
        status = ERR_TIMER_NO_CONTBL;
        goto exit;
    }

    RTOS_mutexWait(timerCb->timer_semid);
    pTree = timerCb->timer_tree;

    for (;;)
    {
#ifdef USE_COND_DEL_FIRST
        timerEvt_t *p = NULL;
        intBoolean bDeleted = FALSE;

        /* check 1st timer event */
        status = REDBLACK_condDeleteFirst(pTree, (const void **)&p,
                                          checkTimerEvent, &bDeleted);
        if (OK > status)
        {
            DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)"Timer ");
            DEBUG_UINT(DEBUG_TIMER_MESSAGE, timerCb->timer_id);
            DEBUG_PRINTNL(DEBUG_TIMER_MESSAGE, (sbyte *)":  Lookup Failed.");
            break;
        }

        if (!bDeleted)
        {
            break;
        }
#else
        timerEvt_t *p, *q;
        ubyte4 msDiff;

        /* get 1st timer event */
        redBlackNodeDescr *pNode = pTree->pRoot;
        if (IS_RB_NULL(pNode))
        {
            break;
        }
        while (!IS_RB_NULL(pNode->pLeft))
        {
            pNode = pNode->pLeft;
        }

        /* check timeout */
        p = (timerEvt_t *) pNode->pKey;
        msDiff = RTOS_deltaMS(&p->start_time, NULL);
        if (msDiff < p->timeout)
        {
            break; /* no, it's not time yet */
        }

        DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)"Timer ");
        DEBUG_UINT(DEBUG_TIMER_MESSAGE, timerCb->timer_id);
        DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte *)":  [");
        DEBUG_UINT(DEBUG_TIMER_MESSAGE, p->event_id);
        DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)"] ");
        DEBUG_INT(DEBUG_TIMER_MESSAGE, msDiff / 1000 );
        DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)" secs (+");
        DEBUG_INT(DEBUG_TIMER_MESSAGE, msDiff % 1000);
        DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)" ms) Timeout ");
        DEBUG_INT(DEBUG_TIMER_MESSAGE, p->timeout / 1000);
        DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)" secs (+");
        DEBUG_INT(DEBUG_TIMER_MESSAGE, p->timeout % 1000);
        DEBUG_PRINTNL(DEBUG_TIMER_MESSAGE, (sbyte*)" ms).");

        /* remove timer event */
        if ((OK > REDBLACK_delete(pTree, (const void *)p, (const void **)&q)) ||
            (p != q))
        {
            DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)"Timer ");
            DEBUG_UINT(DEBUG_TIMER_MESSAGE, timerCb->timer_id);
            DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte *)":  [");
            DEBUG_UINT(DEBUG_TIMER_MESSAGE, p->event_id);
            DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)"] ");
            DEBUG_PRINTNL(DEBUG_TIMER_MESSAGE, (sbyte *)" Deletion Failed.");
            RTOS_mutexRelease(timerCb->timer_semid);
            p->data = NULL; /* !!! */
            break;
        }
#endif
        timerCb->num_events--;
        RTOS_mutexRelease(timerCb->timer_semid);

        if (NULL != p) /* jic */
        {
            /* may modify the RB tree! */
            if (p->callback_func)
            {
                p->callback_func(p->cookie, p->cookie1, p->data, p->event_id);
            }
            else
            {
                timerCb->cbFn(p->data, (ubyte *)timerCb);
            }
            DIGI_MEMSET((ubyte *)p, 0x00, sizeof(timerEvt_t));
            FREE(p);
        }

        RTOS_mutexWait(timerCb->timer_semid);
    }

    RTOS_mutexRelease(timerCb->timer_semid);

exit:
    return status;
} /* TIMER_progress */


/*------------------------------------------------------------------*/

extern MSTATUS
TIMER_getNextTimeout(ubyte *timer, ubyte4 *timeout)
{
    MSTATUS status = OK;

    timerCb_t *timerCb = (timerCb_t *)timer;
    redBlackTreeDescr *pTree;
    redBlackNodeDescr *pNode;

    if (!timerCb)
    {
        status = ERR_TIMER_NO_CONTBL;
        goto exit;
    }

    if (!timeout)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *timeout = (ubyte4)(-1); /* a long time */

    RTOS_mutexWait(timerCb->timer_semid);

    /* get 1st timer event */
    pTree = timerCb->timer_tree;
    pNode = pTree->pRoot;

    if (!IS_RB_NULL(pNode))
    {
        timerEvt_t *p;
        ubyte4 msDiff;

        while (!IS_RB_NULL(pNode->pLeft))
        {
            pNode = pNode->pLeft;
        }

        /* check timeout */
        p = (timerEvt_t *) pNode->pKey;
        msDiff = RTOS_deltaMS(&p->start_time, NULL);
        if (msDiff < p->timeout)
        {
            *timeout = p->timeout - msDiff;
        }
        else
        {
            *timeout = 0;
        }
    }

    RTOS_mutexRelease(timerCb->timer_semid);

exit:
    return status;
} /* TIMER_getNextTimeout */


/*------------------------------------------------------------------*/

static MSTATUS
timerCompare(const void *config, const void *p1, const void *p2,
             sbyte4 *compareResult)
{
    MOC_UNUSED(config);

    if (p1 == p2)
    {
        *compareResult = 0;
    }
    else
    {
        if (0 == (*compareResult = RTOS_timeCompare(
                                                    &(((timerEvt_t *)p1)->end_time),
                                                    &(((timerEvt_t *)p2)->end_time))))
        {
            if (p1 > p2)
            {
                *compareResult = 1;
            }
            else /*if (p1 < p2)*/
            {
                *compareResult = -1;
            }
        }
    }

    return OK;
} /* timerCompare */


/*------------------------------------------------------------------*/

static MSTATUS
freeTreeData(const void **ppFreeKey)
{
    MSTATUS status = OK;

    if (NULL != ppFreeKey)
    {
        timerEvt_t *p = (timerEvt_t *) *ppFreeKey;
        if (NULL != p)
        {
            timerCb_t *timerCb = (timerCb_t *) p->timer_cb;
            if (!timerCb)
            {
                status = ERR_TIMER_NO_CONTBL;
                goto exit;
            }
            timerCb->num_events--;

            /*if (p->free_func)
            {
                p->free_func(p->data);
            }*/
            DIGI_MEMSET((ubyte *)p, 0x00, sizeof(timerEvt_t));
            FREE(p);

            *ppFreeKey = NULL;
        }
    }

exit:
    return status;
} /* freeTreeData */

#endif /* RTOS_timeCompare */


/*------------------------------------------------------------------*/
/*
   TIMER_initTimer ()
   initialize the semaphores
*/

extern MSTATUS
TIMER_initTimer()
{
    MSTATUS status = OK;

    /* Check if already inited */
    if (gTimerGlobalState.gSemid)
    {
        goto exit;
    }

    DIGI_MEMSET((ubyte *)&gTimerGlobalState, 0, sizeof(gTimerGlobalState));

    if (RTOS_mutexCreate(&gTimerGlobalState.gSemid, (enum mutexTypes) 0, 1) != OK)
    {
        DEBUG_PRINTNL(DEBUG_TIMER_MESSAGE, (sbyte*)"Semaphore initialization failed");
        status = ERR_TIMER_SEMINIT_FAILED;
        gTimerGlobalState.gSemid = NULL;
        goto exit;
    }

    DEBUG_PRINTNL(DEBUG_TIMER_MESSAGE, (sbyte*)"Initialized Timers");

exit:
    return status;
}


/*------------------------------------------------------------------*/
/*
   TIMER_deInitTimer ()
   Clean up the Timer Library  if not in Use
*/

extern MSTATUS
TIMER_deInitTimer()
{
    MSTATUS status = OK;

    if (gTimerGlobalState.gNumTimers)
    {
        status = ERR_TIMER_TIMERS_IN_USE;
        goto exit;
    }

    DEBUG_PRINTNL(DEBUG_TIMER_MESSAGE, (sbyte*)"DeInitialized Timers");

    if (gTimerGlobalState.gSemid)
    {
        RTOS_mutexFree(&gTimerGlobalState.gSemid);
        gTimerGlobalState.gSemid = NULL;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/
/*
   TIMER_createTimer (CallBackFn, ubyte** timer)
   Define the callback function and initialize the semaphores for a timer
*/

extern MSTATUS
TIMER_createTimer(timeout_callbackFn cbFn, ubyte **timerId )
{
    MSTATUS status  = OK;
    MSTATUS status2 = OK;

    timerCb_t *timerCb = NULL;

    if (!timerId)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    timerCb = (timerCb_t*) MALLOC(sizeof(timerCb_t));

    if (!timerCb)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMSET((ubyte *)timerCb, 0x00, sizeof(timerCb_t));

#ifdef RTOS_timeCompare
    if (OK > (status = REDBLACK_allocTree(&timerCb->timer_tree,
                                          NULL, NULL, timerCompare, NULL, NULL)))
    {
        goto exit;
    }
#endif
    if (OK > (status = RTOS_mutexCreate(&timerCb->timer_semid, (enum mutexTypes) 0, 1)))
    {
        DEBUG_PRINTNL(DEBUG_TIMER_MESSAGE, (sbyte*)"Semaphore initialization failed");
        status = ERR_TIMER_SEMINIT_FAILED;
        goto exit;
    }

   if (OK > (status = RTOS_mutexWait(gTimerGlobalState.gSemid)))
       goto exit1;

    timerCb->cbFn = cbFn;
#ifdef  __ENABLE_DIGICERT_DEBUG_CONSOLE__
    timerCb->timer_id = gTimerGlobalState.gNextTimerid++;
#endif
    DEBUG_PRINT(DEBUG_TIMER_MESSAGE, (sbyte*)"Timer ");
    DEBUG_UINT(DEBUG_TIMER_MESSAGE, timerCb->timer_id);
    DEBUG_PRINTNL(DEBUG_TIMER_MESSAGE, (sbyte*)": Initialized.");

    gTimerGlobalState.gNumTimers++;
    RTOS_mutexRelease(gTimerGlobalState.gSemid);

    *timerId = (ubyte *)timerCb;

exit1:
    if (OK > status)
    {
        if (OK > (status2 = RTOS_mutexFree(&timerCb->timer_semid)))
        {
            DEBUG_ERROR(DEBUG_PLATFORM, (sbyte*)"Timer_createTimer: RTOS_mutexFree failed : ", status2);
        }
    }

exit:
    if (OK > status)
    {
        if (timerCb)
        {
#ifdef RTOS_timeCompare
            REDBLACK_freeTree(&timerCb->timer_tree, NULL, NULL, NULL);
#endif
            FREE(timerCb);
        }
    }

    return status;

}

/*------------------------------------------------------------------*/

extern MSTATUS
TIMER_destroyTimerEx (ubyte *timerId, void (*cleanUpQueuedTimer_Fn)(void *))
{
    stimer_t **copp, *freep;
    timerCb_t * timerCb = (timerCb_t *)timerId;

    if (0 != timerCb->num_events)
    {
        RTOS_mutexWait(timerCb->timer_semid);
        for (copp = &timerCb->timer_head; (0 != (freep = *copp)); )
        {
            *copp = freep->next;
            if (cleanUpQueuedTimer_Fn)
            {
                cleanUpQueuedTimer_Fn(freep->s);
            }
            FREE(freep);
            timerCb->num_events--;
        }
        RTOS_mutexRelease(timerCb->timer_semid);
    }
    return TIMER_destroyTimer(timerId);

}


/*------------------------------------------------------------------*/

extern MSTATUS
TIMER_destroyTimer (ubyte *timerId)
{
    timerCb_t * timerCb = (timerCb_t *)timerId;
    MSTATUS     status = OK;

    if (!timerCb)
        goto exit;

    RTOS_mutexWait(timerCb->timer_semid);

#ifdef RTOS_timeCompare
    REDBLACK_freeTree(&timerCb->timer_tree, freeTreeData, NULL, NULL);
#endif

    if ( 0 != timerCb->num_events)
    {
        DEBUG_PRINT(DEBUG_TIMER_MESSAGE,(sbyte*)"Timer ID: ");
        DEBUG_UINT(DEBUG_TIMER_MESSAGE,timerCb->timer_id);
        DEBUG_PRINTNL(DEBUG_TIMER_MESSAGE,(sbyte*)" Being Deleted  Has Sessions ");
        DEBUG_UINT(DEBUG_TIMER_MESSAGE,timerCb->num_events);
        DEBUG_PRINTNL(DEBUG_TIMER_MESSAGE,(sbyte*)" ");
    }

    RTOS_mutexRelease(timerCb->timer_semid);

    RTOS_mutexWait(gTimerGlobalState.gSemid);
    RTOS_mutexFree(&timerCb->timer_semid);
    DEBUG_PRINT(DEBUG_TIMER_MESSAGE,(sbyte*)"Timer ");
    DEBUG_UINT(DEBUG_TIMER_MESSAGE,timerCb->timer_id);
    DEBUG_PRINTNL(DEBUG_TIMER_MESSAGE,(sbyte*)": Deleted.");

    DIGI_MEMSET((ubyte *)timerCb, 0x00, sizeof(timerCb_t));
    FREE(timerCb);

    gTimerGlobalState.gNumTimers--;

    RTOS_mutexRelease(gTimerGlobalState.gSemid);
exit:
    return status;
}


/*------------------------------------------------------------------*/

/**********
 Get the elapsed time in ms for a specific Timer Type for a session form the Timer Queue

**********/

extern MSTATUS
TIMER_getTimerElapsed(void *s, ubyte *timer, ubyte4 *pElapsedMs)
{
    stimer_t **copp, *p;
    timerCb_t * timerCb = (timerCb_t*)timer;
    MSTATUS status = OK;

    if (!timerCb || !pElapsedMs)
        goto exit;

    {
        RTOS_mutexWait(timerCb->timer_semid);
        for (copp = &timerCb->timer_head; (0 != (p = *copp)); copp = &p->next)
        {
            if (p->s == s)
            {
                *pElapsedMs = RTOS_deltaMS(&p->startTime,NULL);
                break;
            }
        }
        RTOS_mutexRelease(timerCb->timer_semid);
    }

exit:
    return status;
}
