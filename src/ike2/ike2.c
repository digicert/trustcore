/**
 * @file  ike2.c
 * @brief IKEv2 IKEv2 Developer API
 *
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
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

#if defined(__ENABLE_DIGICERT_IKE_SERVER__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../common/random.h"
#include "../common/vlong.h"
#ifdef __IKE_UPDATE_TIMER__
#include "../common/timer.h"
#endif
#include "../crypto/md5.h"
#include "../crypto/dh.h"
#include "../crypto/rsa.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/crypto.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../harness/harness.h"
#ifdef __ENABLE_DIGICERT_PFKEY__
#include "../pfkey/pfkey.h"
#endif
#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsecconf.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ike_crypto.h"
#include "../ike/ikesa.h"
#include "../ike/ikekey.h"
#include "../ike/ike_state.h"
#include "../ike/ike_event.h"
#include "../ike/ike_cert.h"
#include "../ike/ike_utils.h"
#include "../ike/ike_status.h"


/*------------------------------------------------------------------*/

MOC_EXTERN_DATA_DECL moctime_t gStartTime;
extern ikeSettings m_ikeSettings;
extern IKE_MUTEX g_ikeMtx;

#ifdef __IKE_UPDATE_TIMER__
extern ubyte *m_ikeTimer;
#endif

#ifdef __ENABLE_IKE_REDIRECT__
extern ubyte4 g_ikeRedirectCount;
#endif

#ifdef __IKE_MULTI_THREADED__
extern RTOS_RWLOCK m_ikeSaRwLock;
#endif


/*------------------------------------------------------------------*/

#define _I 0
#define _R 1

#define DBG_ERRCODE(_s) debug_print_status((sbyte *)__FILE__, __LINE__, (sbyte4)_s);
#define DBG_STATUS      DBG_ERRCODE(status)
#define DBG_EXIT        { DBG_STATUS goto exit; }
#define DBG_ABORT       { DBG_STATUS goto abort; }

#ifdef __ENABLE_DIGICERT_HARNESS__
#define __crypto__(_d, _s) * _d = NULL
#define _CRYPTO_FREE_(_h, _d) if (_d) CRYPTO_FREE(_h, TRUE, (void**) &(_d));
#else
#define __crypto__(_d, _s) _d[_s]
#define _CRYPTO_FREE_(_h, _d)
#endif


#ifdef __IKE_UPDATE_TIMER__

#ifdef __IKE_MULTI_THREADED__
#define EXIT_SA goto exit_sa;
#else
#define EXIT_SA goto exit;
#endif

/*------------------------------------------------------------------*/

static void
RtxTimerEvent(sbyte4 i, ubyte4 saId, void *data, ubyte4 timerId)
{
    IKESA pxSa = (IKESA)data;
    IKE2XG pxXg;

    struct ike_context ctx = { NULL };
    sbyte4 count, timeout;

    IKE_LOCK_R;
    if (!pxSa) goto exit; /* jic */

#ifndef __IKE_MULTI_THREADED__
    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId))
    {
        EXIT_SA
    }

#else
    RTOS_rwLockWaitR(m_ikeSaRwLock);

    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId))
    {
        EXIT_SA
    }
#endif

    pxXg = &(pxSa->u.v2.pxXg[_I][i]);
    if (!IS_VALID_XCHG(pxXg))
    {
        EXIT_SA
    }

    if (timerId != pxXg->rtxTimerId)
    {
        EXIT_SA
    }

#ifdef __IKE_MULTI_THREADED__
    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* relay this call to the proper thread */
        if (m_ikeSettings.funcPtrIkeThreadSend)
        {
            struct dpcTimerEvent evt;
            evt.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcTimerEvent;
            evt.hdr.dpc_len = (ubyte2)sizeof(evt);
            evt.func = RtxTimerEvent;
            evt.cookie = i;
            evt.saId = saId;
            evt.sa = data;
            evt.timerId = timerId;
            m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid,
                                            (ubyte *)&evt, (ubyte4)sizeof(evt));
        }
        EXIT_SA
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif

    pxXg->rtxTimerId = (IKE_TIMER_EVT_T)0; /* !!! */
    pxXg->rtxTimerHdl = (IKE_TIMER_HDL_T)NULL; /* !!! */

    if (!pxXg->numMsgs) /* jic */
    {
        goto exit;
    }

    ctx.pxSa = pxSa;
    ctx.pxXg = pxXg;
    if (OK > IKE2_xchgOut(&ctx))
    {
        goto exit;
    }

    ++pxXg->rtxCount; /* for next timeout */

    for (count=0, timeout=1; count < pxXg->rtxCount; count++)
    {
        timeout *= 2;
    }

    if (OK > IKE_ADD_TIMER_EVT((1000 * timeout), i, pxSa,
                               RtxTimerEvent, "RTX",
                               pxXg->rtxTimerId, pxXg->rtxTimerHdl))
    {
        debug_printnl("Failed to schedule timer for retransmission.");
        goto exit;
    }

exit:
    IKE_UNLOCK_R;
    return;

#ifdef __IKE_MULTI_THREADED__
exit_sa:
    RTOS_rwLockReleaseR(m_ikeSaRwLock);
    IKE_UNLOCK_R;
    return;
#endif
} /* RtxTimerEvent */


/*------------------------------------------------------------------*/

static void
DoRekey(IKESA pxSa)
{
    IKESA pxSaRekey;
    ubyte4 timeout;
    MSTATUS status;

    if (pxSa->flags & IKE_SA_FLAG_DPD)
    {
        goto exit;
    }

    if (NULL != (pxSaRekey = pxSa->pxSaRekey))
    {
#ifdef __IKE_MULTI_THREADED__
        RTOS_rwLockWaitR(m_ikeSaRwLock);
#endif
        if (IS_VALID(pxSaRekey) &&
            (pxSaRekey->dwId0 == pxSa->dwId0))
        {
            /* being rekeyed */
#ifdef __IKE_MULTI_THREADED__
            RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
            goto exit;
        }
#ifdef __IKE_MULTI_THREADED__
        RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
    }

#ifdef CUSTOM_IKE_GET_DPD_TIMEOUT
    if (OK <= CUSTOM_IKE_GET_DPD_TIMEOUT(&timeout,
                                         REF_MOC_IPADDR(pxSa->dwPeerAddr),
                                         0, IS_INITIATOR(pxSa)
                                         MOC_MTHM_REQ_VALUE(pxSa->serverInstance)))
    {
        timeout = 1000 * timeout;
    }
    else
#endif
    timeout = 1000 * pxSa->ikePeerConfig->ikeTimeoutDpd;
    if (timeout)
    {
        ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
        ubyte4 timeidled = timenow - pxSa->dwTimeStamp;
        if (timeidled > timeout)
        {
            /* idle too long */
            goto exit;
        }
    }

    /* new IKE_SA */
    if (NULL != (pxSaRekey = IKE2_newSa(pxSa->ikePeerConfig,
                                        REF_MOC_IPADDR(pxSa->dwPeerAddr),
                                        pxSa->wPeerPort, NULL, pxSa
                                        MOC_NATT_VALUE(USE_NATT_PORT(pxSa))
                                        MOC_MTHM_VALUE(pxSa->serverInstance))))
    {
        /* new REKEY_SA exchange */
        IKE2XG pxXg;
        if (OK > (status = IKE2_newXchg(pxSa, IKE_XCHG_CHILD, 0, TRUE, &pxXg)))
        {
            //DBG_STATUS
            IKE2_delSa(pxSaRekey, FALSE, status);
        }
        else
        {
            struct ike_context ctx = { NULL };

            pxXg->pxSa = pxSaRekey;
            pxXg->dwSaId = pxSaRekey->dwId;

            pxSa->pxSaRekey = pxSaRekey;

            ctx.pxSa = pxSa;
            ctx.pxXg = pxXg;
            if (OK > (status = IKE2_xchgOut(&ctx)))
            {
                //DBG_STATUS
                pxSa->pxSaRekey = NULL;
            }
        }
    }

exit:
    return;
} /* DoRekey */


/*------------------------------------------------------------------*/

/* auto. rekeying - lifetime kbytes */
#define KB_REKEY(pxSa) \
    if (pxSa->dwExpKBytes && \
        IS_IKE2_SA_AUTHED(pxSa) && \
        (IKE_SA_FLAG_ORIG_INITR & pxSa->flags) && \
        !((IKE_SA_FLAG_DELETING | IKE_SA_FLAG_REKEYED) & pxSa->flags)) \
    {\
        ubyte4 warning = 25; /* 25K - FOR NOW */\
        if ((pxSa->dwCurKBytes > (ubyte4)(pxSa->dwExpKBytes/2)) && /* old enough */\
            ((pxSa->dwExpKBytes < (pxSa->dwCurKBytes + warning)) || /* expiring soon */\
             (pxSa->dwCurKBytes > (pxSa->dwCurKBytes + warning)))) /* jic KBytes wraps back to 0 */\
        {\
            DoRekey(pxSa);\
        }\
    }\


/*------------------------------------------------------------------*/

static void
RekeyingTimerEvent(sbyte4 cookie, ubyte4 saId, void *data, ubyte4 timerId)
{
    IKESA pxSa = (IKESA)data;

    ubyte4 timeout;
    MSTATUS status;

    IKE_LOCK_R;
    if (!pxSa) goto exit; /* jic */

#ifndef __IKE_MULTI_THREADED__
    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_NEWSA]))
    {
        EXIT_SA
    }

#else
    RTOS_rwLockWaitR(m_ikeSaRwLock);

    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_NEWSA]))
    {
        EXIT_SA
    }

    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* relay this call to the proper thread */
        if (m_ikeSettings.funcPtrIkeThreadSend)
        {
            struct dpcTimerEvent evt;
            evt.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcTimerEvent;
            evt.hdr.dpc_len = (ubyte2)sizeof(evt);
            evt.func = RekeyingTimerEvent;
            evt.cookie = cookie;
            evt.saId = saId;
            evt.sa = data;
            evt.timerId = timerId;
            m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid,
                                            (ubyte *)&evt, (ubyte4)sizeof(evt));
        }
        EXIT_SA
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif

    pxSa->timerIDs[IKESA_TIMER_NEWSA] = (IKE_TIMER_EVT_T)0; /* !!! */
    pxSa->timerHdls[IKESA_TIMER_NEWSA] = (IKE_TIMER_HDL_T)NULL; /* !!! */

    if ((IKE_SA_FLAG_DELETING | IKE_SA_FLAG_REKEYED) & pxSa->flags)
    {
        goto exit;
    }

    DoRekey(pxSa); /* attempt rekeying */

    timeout = (ubyte4)(cookie/2);

    if (OK > (status = IKE_ADD_TIMER_EVT(timeout, timeout, pxSa,
                                         RekeyingTimerEvent, "NEW",
                                         pxSa->timerIDs[IKESA_TIMER_NEWSA],
                                         pxSa->timerHdls[IKESA_TIMER_NEWSA])))
    {
        DBG_STATUS
    }

exit:
    IKE_UNLOCK_R;
    return;

#ifdef __IKE_MULTI_THREADED__
exit_sa:
    RTOS_rwLockReleaseR(m_ikeSaRwLock);
    IKE_UNLOCK_R;
    return;
#endif
} /* RekeyingTimerEvent */


/*------------------------------------------------------------------*/

static void
ExpTimerEvent(sbyte4 cookie, ubyte4 saId, void *data, ubyte4 timerId)
{
    IKESA pxSa = (IKESA)data;

    IKE_LOCK_R;
    if (!pxSa) goto exit; /* jic */

#ifndef __IKE_MULTI_THREADED__
    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_EXPIRATION]))
    {
        EXIT_SA
    }

    MOC_UNUSED(cookie);
#else
    RTOS_rwLockWaitR(m_ikeSaRwLock);

    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_EXPIRATION]))
    {
        EXIT_SA
    }

    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* relay this call to the proper thread */
        if (m_ikeSettings.funcPtrIkeThreadSend)
        {
            struct dpcTimerEvent evt;
            evt.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcTimerEvent;
            evt.hdr.dpc_len = (ubyte2)sizeof(evt);
            evt.func = ExpTimerEvent;
            evt.cookie = cookie;
            evt.saId = saId;
            evt.sa = data;
            evt.timerId = timerId;
            m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid,
                                            (ubyte *)&evt, (ubyte4)sizeof(evt));
        }
        EXIT_SA
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif

    pxSa->timerIDs[IKESA_TIMER_EXPIRATION] = (IKE_TIMER_EVT_T)0; /* !!! */
    pxSa->timerHdls[IKESA_TIMER_EXPIRATION] = (IKE_TIMER_HDL_T)NULL; /* !!! */
    IKE2_delSa(pxSa, TRUE, OK);

exit:
    IKE_UNLOCK_R;
    return;

#ifdef __IKE_MULTI_THREADED__
exit_sa:
    RTOS_rwLockReleaseR(m_ikeSaRwLock);
    IKE_UNLOCK_R;
    return;
#endif
} /* ExpTimerEvent */


/*------------------------------------------------------------------*/

static void
DpdTimerEvent(sbyte4 cookie, ubyte4 saId, void *data, ubyte4 timerId)
{
    IKESA pxSa = (IKESA)data;
    ubyte4 timeoutDpd = (ubyte4)cookie;

    ubyte4 timenow, timeidled;
    sbyte4 i;
    IKE2XG pxXg;
    MSTATUS status;

    IKE_LOCK_R;
    if (!pxSa) goto exit; /* jic */

#ifndef __IKE_MULTI_THREADED__
    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_DPD]))
    {
        EXIT_SA
    }

#else
    RTOS_rwLockWaitR(m_ikeSaRwLock);

    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_DPD]))
    {
        EXIT_SA
    }

    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* relay this call to the proper thread */
        if (m_ikeSettings.funcPtrIkeThreadSend)
        {
            struct dpcTimerEvent evt;
            evt.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcTimerEvent;
            evt.hdr.dpc_len = (ubyte2)sizeof(evt);
            evt.func = DpdTimerEvent;
            evt.cookie = cookie;
            evt.saId = saId;
            evt.sa = data;
            evt.timerId = timerId;
            m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid,
                                            (ubyte *)&evt, (ubyte4)sizeof(evt));
        }
        EXIT_SA
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif

    pxSa->timerIDs[IKESA_TIMER_DPD] = (IKE_TIMER_EVT_T)0; /* !!! */
    pxSa->timerHdls[IKESA_TIMER_DPD] = (IKE_TIMER_HDL_T)NULL; /* !!! */

    if ((IKE_SA_FLAG_DELETING | IKE_SA_FLAG_REKEYED) & pxSa->flags)
    {
        goto exit;
    }

    timenow = RTOS_deltaMS(&gStartTime, NULL);
    timeidled = timenow - pxSa->dwTimeStamp;

    if (timeidled < timeoutDpd)
    {
        /* not idle long enough */
        timeoutDpd -= timeidled;
        goto sched;
    }

    /* find ongoing request(s) */
    for (i = pxSa->u.v2.dwWndLen[_I]; 0 != i; i--)
    {
        pxXg = &(pxSa->u.v2.pxXg[_I][i-1]);
        if (IS_VALID_XCHG(pxXg))
        {
            if ((timeidled - timeoutDpd) > (timenow - pxXg->dwTimeStamp))
            {
                /* exchange occurred after DPD was triggered */
                goto sched;
            }
        }
    }

    /* send (empty) request message */
    if (OK > (status = IKE2_newXchg(pxSa, IKE_XCHG_INFO, 0, TRUE, &pxXg)))
    {
        /* jic - unlikely though */
        //DBG_STATUS
    }
    else
    {
        struct ike_context ctx = { NULL };
        ctx.pxSa = pxSa;
        ctx.pxXg = pxXg;

#if defined(__ENABLE_MOBIKE__) && defined(__ENABLE_IPSEC_NAT_T__)
        if ((IKE_SA_FLAG_MOBILE & pxSa->flags) &&
            (IKE_NATT_FLAG_D & pxSa->natt_flags) &&
            !(IKE_NATT_FLAG_NOT_ALLOWED & pxSa->natt_flags))
        {
            ctx.flags = (IKE_CNTXT_FALG_NAT_D_SRC | IKE_CNTXT_FALG_NAT_D_DST);
        }
#endif
        if (OK > (status = IKE2_xchgOut(&ctx)))
        {
            //DBG_STATUS
        }
    }

sched:
    if (OK > (status = IKE_ADD_TIMER_EVT(timeoutDpd, cookie, pxSa,
                                         DpdTimerEvent, "DPD",
                                         pxSa->timerIDs[IKESA_TIMER_DPD],
                                         pxSa->timerHdls[IKESA_TIMER_DPD])))
    {
        DBG_STATUS
    }

exit:
    IKE_UNLOCK_R;
    return;

#ifdef __IKE_MULTI_THREADED__
exit_sa:
    RTOS_rwLockReleaseR(m_ikeSaRwLock);
    IKE_UNLOCK_R;
    return;
#endif
} /* DpdTimerEvent */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_IPSEC_NAT_T__
static void
KeepaliveTimerEvent(sbyte4 cookie, ubyte4 saId, void *data, ubyte4 timerId)
{
    IKESA pxSa = (IKESA)data;
    ubyte4 timeout = (ubyte4)cookie;

    ubyte4 timenow, timediff;
    MSTATUS status;

    IKE_LOCK_R;
    if (!pxSa) goto exit; /* jic */

#ifndef __IKE_MULTI_THREADED__
    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_KEEPALIVE]))
    {
        EXIT_SA
    }

#else
    RTOS_rwLockWaitR(m_ikeSaRwLock);

    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_KEEPALIVE]))
    {
        EXIT_SA
    }

    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* relay this call to the proper thread */
        if (m_ikeSettings.funcPtrIkeThreadSend)
        {
            struct dpcTimerEvent evt;
            evt.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcTimerEvent;
            evt.hdr.dpc_len = (ubyte2)sizeof(evt);
            evt.func = KeepaliveTimerEvent;
            evt.cookie = cookie;
            evt.saId = saId;
            evt.sa = data;
            evt.timerId = timerId;
            m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid,
                                            (ubyte *)&evt, (ubyte4)sizeof(evt));
        }
        EXIT_SA
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif

    pxSa->timerIDs[IKESA_TIMER_KEEPALIVE] = (IKE_TIMER_EVT_T)0; /* !!! */
    pxSa->timerHdls[IKESA_TIMER_KEEPALIVE] = (IKE_TIMER_HDL_T)NULL; /* !!! */

    if ((IKE_SA_FLAG_DELETING | IKE_SA_FLAG_REKEYED) & pxSa->flags)
    {
        goto exit;
    }

    timenow = RTOS_deltaMS(&gStartTime, NULL);
    timediff = timenow - pxSa->dwTimeStampOut;

    if (timediff < timeout)
    {
        timeout -= timediff; /* not quite the time yet */
    }
    else if (NULL != m_ikeSettings.funcPtrIkeXchgSend) /* jic */
    {
        ubyte b = 0xFF;
        m_ikeSettings.
            funcPtrIkeXchgSend(REF_MOC_IPADDR(pxSa->dwPeerAddr), pxSa->wPeerPort,
                               (ubyte *)&b, sizeof(ubyte)
                               MOC_MTHM_REQ_VALUE(pxSa->serverInstance),
                               TRUE);
        pxSa->dwTimeStampOut = timenow;
    }

    if (OK > (status = IKE_ADD_TIMER_EVT(timeout, cookie, pxSa,
                                         KeepaliveTimerEvent, "KAL",
                                         pxSa->timerIDs[IKESA_TIMER_KEEPALIVE],
                                         pxSa->timerHdls[IKESA_TIMER_KEEPALIVE])))
    {
        DBG_STATUS
    }

exit:
    IKE_UNLOCK_R;
    return;

#ifdef __IKE_MULTI_THREADED__
exit_sa:
    RTOS_rwLockReleaseR(m_ikeSaRwLock);
    IKE_UNLOCK_R;
    return;
#endif
} /* KeepaliveTimerEvent */
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
IKE2_setupMatureTimers(IKESA pxSa)
{
    MSTATUS status = OK;

    MSTATUS st;
    ubyte4 timeout;

    IKE_DEL_TIMER_EVT(pxSa->timerIDs[IKESA_TIMER_EXPIRATION], pxSa->timerHdls[IKESA_TIMER_EXPIRATION])

    if (pxSa->dwExpSecs)
    {
        timeout = 1000 * pxSa->dwExpSecs;

        /* auto. rekeying */
        if (IKE_SA_FLAG_ORIG_INITR & pxSa->flags) /* original initiator */
        {
            ubyte4 warning = 3 * 1000 * pxSa->ikePeerConfig->ikeTimeoutNegotiation;
            if (warning > (timeout/2))
            {
                warning = (timeout/2); /* don't rekey too soon */
            }

            if (OK > (st = IKE_ADD_TIMER_EVT((timeout - warning), warning, pxSa,
                                             RekeyingTimerEvent, "NEW",
                                             pxSa->timerIDs[IKESA_TIMER_NEWSA],
                                             pxSa->timerHdls[IKESA_TIMER_NEWSA])))
            {
                DBG_ERRCODE(st)
            }
        }

        /* lifetime seconds */
        if (OK > (st = IKE_ADD_TIMER_EVT(timeout, 0, pxSa,
                                         ExpTimerEvent, "EXP",
                                         pxSa->timerIDs[IKESA_TIMER_EXPIRATION],
                                         pxSa->timerHdls[IKESA_TIMER_EXPIRATION])))
        {
            DBG_ERRCODE(st)
        }
    }

    /* DPD timer */
#ifdef CUSTOM_IKE_GET_DPD_TIMEOUT
    if (OK <= CUSTOM_IKE_GET_DPD_TIMEOUT(&timeout,
                                         REF_MOC_IPADDR(pxSa->dwPeerAddr),
                                         0, IS_INITIATOR(pxSa)
                                         MOC_MTHM_REQ_VALUE(pxSa->serverInstance)))
    {
        timeout = 1000 * timeout;
    }
    else
#endif
    timeout = 1000 * pxSa->ikePeerConfig->ikeTimeoutDpd;

    if (timeout && /* NOT passive */
        (OK > (st = IKE_ADD_TIMER_EVT(timeout, timeout, pxSa,
                                      DpdTimerEvent, "DPD",
                                      pxSa->timerIDs[IKESA_TIMER_DPD],
                                      pxSa->timerHdls[IKESA_TIMER_DPD]))))
    {
        DBG_ERRCODE(st)
    }

    /* NAT-T KeepAlive timer */
#ifdef __ENABLE_IPSEC_NAT_T__
    if (IS_HOST_BEHIND_NAT(pxSa))
    {
        timeout = 1000 * m_ikeSettings.ikeIntervalKeepalive;

        if (timeout &&
            (OK > (st = IKE_ADD_TIMER_EVT(timeout, timeout, pxSa,
                                          KeepaliveTimerEvent, "KAL",
                                          pxSa->timerIDs[IKESA_TIMER_KEEPALIVE],
                                          pxSa->timerHdls[IKESA_TIMER_KEEPALIVE]))))
        {
            DBG_ERRCODE(st)
        }
    }
#endif

    return status;
} /* IKE2_setupMatureTimers */

#endif /* __IKE_UPDATE_TIMER__ */


/*------------------------------------------------------------------*/

static MSTATUS
SendMessage(ubyte *poMsg, ubyte4 dwMsgLen,
            MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort,
            IKESA pxSa, IKE2XG pxXg, intBoolean bResponse
            MOC_MTHM(serverInstance)
            MOC_NATT(bUseNattPort))
{
    MSTATUS status = OK;

    /* transmit message */
#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
    if (!bResponse)
    {
#ifdef __ENABLE_IPSEC_NAT_T__
        if (bUseNattPort)
        {
            debug_print_ikehdr(poMsg+4);
        }
        else
#endif
        {
            debug_print_ikehdr(poMsg);
        }
    }
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
    if (bUseNattPort)
    {
        debug_print("#");
    }
#endif
    debug_print("SEND ");
    debug_uint(dwMsgLen);
    debug_print(" bytes to ");
    debug_print_ip(peerAddr);
    debug_print("[");
    debug_int(wPeerPort);
    debug_print("]");
    debug_uptime();
    debug_printnl("");

    if (OK > m_ikeSettings.funcPtrIkeXchgSend(peerAddr, wPeerPort,
                                              poMsg, dwMsgLen
                                              MOC_MTHM_REQ_VALUE(serverInstance)
                                              MOC_NATT_REQ_VALUE(bUseNattPort)))
    {
        /* debugging info */
        goto exit;
    }

    if (pxXg)
    {
        ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
        pxXg->dwTimeStamp = timenow;
#ifdef __ENABLE_IPSEC_NAT_T__
        pxSa->dwTimeStampOut = timenow;
#endif
    }

exit:
    return status;
} /* SendMessage */


/*------------------------------------------------------------------*/

static MSTATUS
DoXchgOut(IKE_context ctx,
          MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort,
          intBoolean bSK, intBoolean bResponse,
          ubyte **ppoRtxMsg, ubyte4 *pdwRtxMsgLen
          MOC_MTHM(serverInstance)
          MOC_NATT(bUseNattPort))
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    IKE2XG pxXg = ctx->pxXg;

    struct ikeHdr *pxHdr = (struct ikeHdr *) ctx->pHdrParent;
    ubyte4 dwLength = ctx->dwLength;

    /* DEBUG: dump message (i.e. pxHdr) here (before encryption) */

    /* process SK{...} */
    if (bSK/* && pxSa && pxXg */)
    {
        if (OK > (status = IKE2_outSK(ctx)))
        {
            goto exit;
        }
        dwLength = ctx->dwLength;

        /* book-keeping */
        pxSa->dwCurBytes += dwLength;
        if (1024 <= pxSa->dwCurBytes)
        {
            ubyte4 dwNewKBytes = pxSa->dwCurKBytes + (pxSa->dwCurBytes / 1024);
            pxSa->dwCurBytes = (pxSa->dwCurBytes % 1024);

            /* jic KBytes wraps back to 0 */
            if (pxSa->dwExpKBytes && (pxSa->dwCurKBytes > dwNewKBytes))
            {
                pxSa->dwCurBytes += (ubyte4)((dwNewKBytes + 1) * 1024);
                dwNewKBytes = ~((ubyte4)0);
            }
            pxSa->dwCurKBytes = dwNewKBytes;
        }
#ifdef __IKE_UPDATE_TIMER__
        KB_REKEY(pxSa) /* auto. rekeying - lifetime kbytes */
#endif
    } /* if (bSK) */

    /* transmit message */
#ifdef __ENABLE_IPSEC_NAT_T__
    if (bUseNattPort)
    {
        pxHdr = (struct ikeHdr *)((ubyte *)pxHdr - 4);
        dwLength = dwLength + 4;
    }
#endif
    SendMessage((ubyte *)pxHdr, dwLength,
                peerAddr, wPeerPort,
                pxSa, pxXg, bResponse
                MOC_MTHM_VALUE(serverInstance)
                MOC_NATT_VALUE(bUseNattPort));

    /* save for re-transmission */
    if (ppoRtxMsg)
    {
        ubyte *poRtxMsg;
        if (NULL == (poRtxMsg = (ubyte *) MALLOC(dwLength)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            DBG_EXIT
        }
        DIGI_MEMCPY(poRtxMsg, (ubyte *)pxHdr, dwLength);
        *ppoRtxMsg = poRtxMsg;

        if (pdwRtxMsgLen)
        {
            *pdwRtxMsgLen = dwLength;
        }
    }

exit:
    return status;
} /* DoXchgOut */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE2_xchgOut(IKE_context ctx)
{
    MSTATUS status = OK;

#ifdef __DIGICERT_DUMP_IKE_PLAINTEXT__
    ubyte *poMsgPlain = NULL;
    ubyte4 dwMsgPlainLength = 0;
#endif
    struct ikeHdr *pxHdr = (struct ikeHdr *) ctx->pHdrParent;

    IKESA pxSa = ctx->pxSa;
    IKE2XG pxXg = ctx->pxXg;

    MOC_IP_ADDRESS peerAddr=0;
    ubyte2 wPeerPort=0;

#ifdef __IKE_MULTI_HOMING__
    sbyte4 serverInstance=0;
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
    intBoolean bUseNattPort=FALSE;
#endif
    intBoolean bInitiator = FALSE;  /* us */
    intBoolean bResponse = FALSE;   /* outgoing message */

    intBoolean bSK = FALSE;
    ubyte2 wSkHdrLen = 0;
#ifdef __ENABLE_IKE_FRAGMENTATION__
    ubyte4 dwSkBodyLen;
#endif
    ubyte4 dwLength;
    ubyte4 dwBufferSize;
    ubyte *pBuffer = NULL;

    funcPtrIkeCtx pOutFunc = NULL;

    sbyte4 (*funcPtrIkeXchgSend)(MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort,
                                 ubyte *pBuffer, ubyte4 dwBufferSize,
                                 sbyte4 serverInstance,
                                 intBoolean bUseNattPort)
            = m_ikeSettings.funcPtrIkeXchgSend;

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    intBoolean hasHwAccelCookie = FALSE;

    if (!ctx->isHwAccelCookieInit)
    {
        if (OK > (status = IKE_getHwAccelChannel(&ctx->hwAccelCookie)))
            DBG_ABORT

        ctx->isHwAccelCookieInit = hasHwAccelCookie = TRUE;
    }
#endif

    if (!funcPtrIkeXchgSend)
    {
        status = ERR_IKE_CONFIG;
        DBG_EXIT
    }

    if (pxXg)
    {
        if (!IS_VALID_XCHG(pxXg)) goto exit;

        if ((NULL == pxSa) || !IS_VALID(pxSa)) /* jic */
        {
            status = ERR_IKE;
            DBG_EXIT
        }

        if (IS_IKE2_SA_INITED(pxSa) &&
            (IKE_XCHG_INIT != pxXg->oExchange))
        {
            bSK = TRUE;
        }

#ifdef __IKE_MULTI_HOMING__
        serverInstance = pxSa->serverInstance;
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
        bUseNattPort = USE_NATT_PORT(pxSa);
#endif
        bInitiator = IS_INITIATOR(pxSa);
        bResponse = !IS_XCHG_INITIATOR(pxXg);

#ifdef __ENABLE_MOBIKE__
        if (ctx->peerAddr && ctx->wPeerPort &&
            IS_IKE2_SA_AUTHED(pxSa) &&
            (IKE_SA_FLAG_MOBILE & pxSa->flags))
        {
            peerAddr = ctx->peerAddr;
            wPeerPort = ctx->wPeerPort;
        }
        else
#endif
        {
            peerAddr = REF_MOC_IPADDR(pxSa->dwPeerAddr);
            wPeerPort = pxSa->wPeerPort;
        }

#ifdef __ENABLE_IKE_REDIRECT__
        if (REDIRECTED_FROM == ctx->wMsgType)
        {
            sbyte4 i;
            for (i=0; i < pxXg->numMsgs; i++)
            {
                if (pxXg->poMsg[i])
                {
                    FREE(pxXg->poMsg[i]);
                    pxXg->poMsg[i] = NULL;
                }
            }
            pxXg->numMsgs = 0;
        }
#endif
        /* re-transmission */
        if (pxXg->numMsgs)
        {
            sbyte4 i;
            for (i=0; i < pxXg->numMsgs; i++)
            {
                SendMessage(pxXg->poMsg[i], pxXg->dwMsgLen[i],
                            peerAddr, wPeerPort,
                            pxSa, pxXg, bResponse
                            MOC_MTHM_VALUE(serverInstance)
                            MOC_NATT_VALUE(bUseNattPort));
            }
            goto exit;
        }

        /* sanity-check */
        if (bResponse && (IKE_XCHG_FLAG_PENDING & pxXg->x_flags))
        {
            /* pending response */
            DBG_ERRCODE(STATUS_IKE_PENDING)
            goto exit;
        }

        pxHdr = NULL;

#ifdef __ENABLE_IKE_REDIRECT__
        if (REDIRECTED_FROM == ctx->wMsgType)
        {
            if (pxXg && IKE_XCHG_INFO == pxXg->oExchange)
            {
                ctx->wMsgType = 0;
                pOutFunc = IKE2_getStateInfo(IKE_XCHG_INFO, (bResponse ? _R : _I))->outFunc;
            }
            else
            {
                /* Send init again to new gw */
                pOutFunc = IKE2_getStateInfo(IKE_XCHG_INIT, (bResponse ? _R : _I))->outFunc;
            }
        }
        else if (ctx->wMsgType && ctx->wMsgType != REDIRECT)
            pOutFunc = IKE2_getStateInfo(IKE_XCHG_INFO, (bResponse ? _R : _I))->outFunc;
#else
        if (ctx->wMsgType)
            pOutFunc = IKE2_getStateInfo(IKE_XCHG_INFO, (bResponse ? _R : _I))->outFunc;
#endif
        else
            pOutFunc = pxXg->pState->outFunc;
    }

    else if (pxHdr)
    {
        peerAddr = ctx->peerAddr;
        wPeerPort = ctx->wPeerPort;

#ifdef __IKE_MULTI_HOMING__
        serverInstance = ctx->serverInstance;
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
        bUseNattPort = ctx->bUseNattPort;
#endif
        bInitiator = (IKE_FLAG_INITIATOR & pxHdr->oFlags) ? FALSE : TRUE;
        bResponse = (IKE_FLAG_RESPONSE & pxHdr->oFlags) ? FALSE : TRUE;

        pOutFunc = IKE2_getStateInfo(IKE_XCHG_INFO, (bResponse ? _R : _I))->outFunc;
    }

    /* check output function - jic */
    if (!pOutFunc) goto exit;

    /* output buffer */
    dwBufferSize = m_ikeSettings.ikeBufferSize;
#ifdef __ENABLE_IPSEC_NAT_T__
    dwBufferSize += 4;
#endif
    if ((NULL == ctx->pBuffer) || (dwBufferSize > ctx->dwBufferSize))
    {
        /* allocate new buffer */
        if (OK > (status = CRYPTO_ALLOC(ctx->hwAccelCookie, dwBufferSize,
                                        TRUE, (void**) &pBuffer)))
            DBG_EXIT

        ctx->pBuffer = pBuffer;
        ctx->dwBufferSize = dwBufferSize;
    }

    if (pxHdr && !pBuffer)
    {
        ctx->dwBufferSize -= ((ubyte *)pxHdr - ctx->pBuffer);
        ctx->pBuffer = (ubyte *)pxHdr;

        DIGI_MEMSET(ctx->pBuffer + SIZEOF_ISAKMP_HDR, 0x00, ctx->dwBufferSize - SIZEOF_ISAKMP_HDR);
    }
    else
    {
        DIGI_MEMSET(ctx->pBuffer, 0x00, ctx->dwBufferSize);

#ifdef __ENABLE_IPSEC_NAT_T__
        ctx->pBuffer += 4;
        ctx->dwBufferSize -= 4;
#endif
    }

    /* ISAKMP header */
    if (SIZEOF_ISAKMP_HDR > ctx->dwBufferSize)
    {
        status = ERR_IKE_BUFFER_OVERFLOW;
        DBG_EXIT
    }

    if (pxHdr)
    {
        if (pBuffer)
        {
            DIGI_MEMCPY(ctx->pBuffer, (ubyte *)pxHdr, SIZEOF_ISAKMP_HDR);
            pxHdr = (struct ikeHdr *) ctx->pBuffer;
        }

        if (bInitiator) pxHdr->oFlags |= IKE_FLAG_INITIATOR;
        else pxHdr->oFlags &= ~(IKE_FLAG_INITIATOR);

        if (bResponse) pxHdr->oFlags |= IKE_FLAG_RESPONSE;
        else pxHdr->oFlags &= ~(IKE_FLAG_RESPONSE);

        pxHdr->oNextPayload = IKE_NEXT_NONE;
    }
    else
    {
        pxHdr = (struct ikeHdr *) ctx->pBuffer;

        DIGI_MEMCPY(pxHdr->poCky_I, pxSa->poCky_I, IKE_COOKIE_SIZE);
        DIGI_MEMCPY(pxHdr->poCky_R, pxSa->poCky_R, IKE_COOKIE_SIZE);
        pxHdr->oVersion = (2 << 4) | 0; /* 2.0 */

        pxHdr->oExchange = pxXg->oExchange;
        if (bInitiator) pxHdr->oFlags |= IKE_FLAG_INITIATOR;
        if (bResponse) pxHdr->oFlags |= IKE_FLAG_RESPONSE;
        SET_HTONL(pxHdr->dwMsgId, pxXg->dwMsgId);
    }

    /* set up context */
    ctx->pBuffer       += SIZEOF_ISAKMP_HDR;
    ctx->dwBufferSize  -= SIZEOF_ISAKMP_HDR;

    ctx->dwLength       = SIZEOF_ISAKMP_HDR;

    ctx->poNextPayload  = &(pxHdr->oNextPayload);
    ctx->pHdrParent     = pxHdr;

    /* reserve space for Encrypted Payload */
    if (bSK)
    {
        struct ikeGenHdr *pxSkHdr = (struct ikeGenHdr *) ctx->pBuffer;

        wSkHdrLen = (ubyte2)SIZEOF_IKE_GEN_HDR + pxSa->pCipherSuite->wIvLen;
        if (wSkHdrLen > ctx->dwBufferSize)
        {
            status = ERR_IKE_BUFFER_OVERFLOW;
            DBG_EXIT
        }

        pxHdr->oNextPayload = IKE_NEXT_E;
        SET_HTONS(pxSkHdr->wLength, wSkHdrLen); /* temporary; will adjust */

        ctx->poNextPayload  = &(pxSkHdr->oNextPayload);
        ctx->dwLength      += (ubyte4)wSkHdrLen;
        ctx->dwBufferSize  -= (ubyte4)wSkHdrLen;
        ctx->pBuffer       += wSkHdrLen;
    }

    debug_printnl(bResponse ? "  <-- R" : "  I -->");

    /* construct outgoing message */
    if (OK > (status = pOutFunc(ctx)))
    {
        goto exit;
    }
    dwLength = ctx->dwLength;
    SET_HTONL(pxHdr->dwLength, dwLength);

#ifdef __DIGICERT_DUMP_IKE_PLAINTEXT__
    if (bSK &&
        (NULL != (poMsgPlain = (ubyte *) MALLOC(dwLength + 4))))
    {
        dwMsgPlainLength = dwLength;
#ifdef __ENABLE_IPSEC_NAT_T__
        if (bUseNattPort) dwMsgPlainLength += 4;
#endif
        DIGI_MEMCPY(poMsgPlain, ctx->pBuffer - dwMsgPlainLength, dwMsgPlainLength);
    }
#endif

#ifdef __ENABLE_IKE_FRAGMENTATION__
    /* check if fragmentation is needed */
    if (bSK && /*pxXg && pxSa &&*/
        pxSa->maxSkBodyLen[0] &&
        ((ubyte4) pxSa->maxSkBodyLen[0] <
         (dwSkBodyLen = (dwLength - (wSkHdrLen + SIZEOF_ISAKMP_HDR)))))
    {
        ubyte *poSkBodyCopy;

        struct ike2FragHdr *pxSkfHdr = (struct ike2FragHdr *)(pxHdr + 1);
        ubyte2 wSkfHdrLen = (ubyte2)SIZEOF_IKE_FRAG_HDR + pxSa->pCipherSuite->wIvLen;
        ubyte *poSkfBody = (ubyte *)pxSkfHdr + wSkfHdrLen;

        ubyte2 wSkfBodyLen = pxSa->maxSkBodyLen[1]; /* (wSkfBodyLen+1) == wBlockLen !!! */
        sbyte4 i, numSkfs = (sbyte4)(dwSkBodyLen / wSkfBodyLen);
        ubyte2 wLastSkfBodyLen = (ubyte2)(dwSkBodyLen % wSkfBodyLen);
        if (wLastSkfBodyLen) ++numSkfs;
        else wLastSkfBodyLen = wSkfBodyLen;

        if (IKE2_FRAG_MAX < numSkfs)
        {
            status = ERR_IKE_INVALID_PARAM;
            DBG_EXIT
        }

        if (NULL == (poSkBodyCopy = (ubyte *) MALLOC(dwSkBodyLen)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            DBG_EXIT
        }
        DIGI_MEMCPY(poSkBodyCopy, ctx->pBuffer - dwSkBodyLen, dwSkBodyLen);
        dwBufferSize = ctx->dwBufferSize + (ctx->pBuffer - poSkfBody);

        DB_PRINT("%s: SK body length = %d; need fragmentation!\n", __FUNCTION__, dwSkBodyLen);

        pxHdr->oNextPayload = IKE_NEXT_EF;
        SET_HTONS(pxSkfHdr->wTotalFragments, numSkfs);

        pxXg->numMsgs = 0; /* jic */

        for (i=0; i < numSkfs; i++)
        {
            ubyte2 wBodyLen = (((i+1)<numSkfs) ? wSkfBodyLen : wLastSkfBodyLen);

            DIGI_MEMCPY(poSkfBody, poSkBodyCopy + (i * wSkfBodyLen), wBodyLen);
            ctx->pBuffer = poSkfBody + wBodyLen;
            ctx->dwBufferSize = dwBufferSize - wBodyLen;
            ctx->dwLength = dwLength = SIZEOF_ISAKMP_HDR + wSkfHdrLen + wBodyLen;

            SET_HTONL(pxHdr->dwLength, dwLength);

            SET_HTONS(pxSkfHdr->wLength, wSkfHdrLen); /* temporary; will adjust */
            SET_HTONS(pxSkfHdr->wFragNum, i+1);

            if (OK > (status = DoXchgOut(ctx, peerAddr, wPeerPort, TRUE, bResponse,
                                         &pxXg->poMsg[i], &pxXg->dwMsgLen[i]
                                         MOC_MTHM_VALUE(serverInstance)
                                         MOC_NATT_VALUE(bUseNattPort))))
            {
                FREE(poSkBodyCopy);
                goto exit;
            }
            ++pxXg->numMsgs;

            if (!i) /* 1st fragment */
            {
                pxSkfHdr->oNextPayload = 0; /* for remaining fragments */
            }
        } /* for */

        FREE(poSkBodyCopy);
    }
    else
#endif /* __ENABLE_IKE_FRAGMENTATION__ */
    {
        if (OK > (status = DoXchgOut(ctx, peerAddr, wPeerPort, bSK, bResponse,
                                     (pxXg ? &pxXg->poMsg[0] : NULL),
                                     (pxXg ? &pxXg->dwMsgLen[0] : NULL)
                                     MOC_MTHM_VALUE(serverInstance)
                                     MOC_NATT_VALUE(bUseNattPort))))
        {
            goto exit;
        }
        if (pxXg) pxXg->numMsgs = 1;
    }

#ifdef __DIGICERT_DUMP_IKE_PLAINTEXT__
    if (poMsgPlain)
    {
        funcPtrIkeXchgSend(peerAddr, wPeerPort,
                           poMsgPlain, dwMsgPlainLength
                           MOC_MTHM_REQ_VALUE(serverInstance)
                           MOC_NATT_REQ_VALUE(bUseNattPort));
    }
#endif

#ifdef __IKE_UPDATE_TIMER__
    /* set up timer for re-transmission */
    if (pxXg &&
        !bResponse && /* request only */
        (OK > IKE_ADD_TIMER_EVT(1000,
                            ((pxXg - &(pxSa->u.v2.pxXg[_I][0])) / sizeof(*pxXg)),
                            pxSa, RtxTimerEvent, "RTX",
                            pxXg->rtxTimerId, pxXg->rtxTimerHdl)))
    {
        debug_printnl("Failed to schedule timer for retransmission.");
    }
#endif

exit:
#ifdef __DIGICERT_DUMP_IKE_PLAINTEXT__
    if (poMsgPlain) FREE(poMsgPlain);
#endif
    if (pBuffer) CRYPTO_FREE(ctx->hwAccelCookie, TRUE, (void**) &pBuffer);

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    if (hasHwAccelCookie)
    {
        IKE_releaseHwAccelChannel(&ctx->hwAccelCookie);
        ctx->isHwAccelCookieInit = FALSE;
/*      hasHwAccelCookie = FALSE;*/
    }

abort:
#endif
    if (OK > status)
    {
        if (pxSa && IS_VALID(pxSa))
        {
            if (IS_IKE2_SA_AUTHED(pxSa))
            {
                if (pxXg && IS_VALID_XCHG(pxXg))
                    IKE2_delXchg(pxXg, pxSa, status);
            }
            else
            {
                IKE2_delSa(pxSa, FALSE, status);
            }
        }
    }
    return status;
} /* IKE2_xchgOut */


/*------------------------------------------------------------------*/

#ifndef __IKE_TRACK__
#define TRACK_HDR
#define TRACK_PLAINTEXT
#define TRACK_SA
#define TRACK_XG
#define TRACK_OK

#else

#ifndef __IKE_MULTI_THREADED__
#define TK_BUF_SIZE 65535
static ubyte m_tkBuffer[TK_BUF_SIZE];
#else
#define TK_BUF_SIZE 4096
#define m_tkBuffer pxTrack->pBuffer
#endif

typedef struct ike2_track
{
#ifdef __IKE_MULTI_THREADED__
    ubyte *pBuffer;
#endif
    struct ikeHdr *pxHdr;
    struct ikesa *pxSa;
    struct ike2xg *pxXg;

    intBoolean bMsgOK;

    void *userData;

} *IKE2_TRACK;

#define TRACK_HDR \
    if (pxTrack) \
    { \
        DIGI_MEMCPY(m_tkBuffer, pxHdr, (ctx->dwBufferSize < TK_BUF_SIZE) \
                                 ? ctx->dwBufferSize \
                                 : TK_BUF_SIZE); \
        pxTrack->pxHdr = (struct ikeHdr *)m_tkBuffer; \
    }

#define TRACK_PLAINTEXT \
    if (pxTrack && (IKE_XCHG_INIT != pxHdr->oExchange)) \
    { \
        DIGI_MEMCPY(&m_tkBuffer[SIZEOF_ISAKMP_HDR], (ubyte *)pxHdr + SIZEOF_ISAKMP_HDR, \
               dwLength - SIZEOF_ISAKMP_HDR); \
    }

#define TRACK_SA if (pxTrack) pxTrack->pxSa = pxSa;
#define TRACK_XG if (pxTrack) pxTrack->pxXg = pxXg ;
#define TRACK_OK if (pxTrack) pxTrack->bMsgOK = TRUE;


/*------------------------------------------------------------------*/

static MSTATUS
CheckInfoXchg(void *cb, ubyte oType, const ubyte *pPayload, intBoolean *stop)
{
    MSTATUS status = OK;

    IKE2_TRACK pxTrack = (IKE2_TRACK)cb;
    ubyte2 *st = (ubyte2 *) pxTrack->userData;

    struct ike2NotifyHdr *pxNotifyHdr;
    struct ike2DelHdr *pxDelHdr;

    *stop = FALSE;

    switch (oType)
    {
    case IKE_NEXT_N :
        *stop = TRUE;
        pxNotifyHdr = (struct ike2NotifyHdr *)pPayload;
        switch (pxNotifyHdr->oProtoId)
        {
        case 0 :
        case PROTO_ISAKMP :
            *st |= (1 << IKMP_NOTIFY);
            break;
        case PROTO_IPSEC_AH :
        case PROTO_IPSEC_ESP :
            *st |= (1 << PROTOCOL_NOTIFY);
            break;
        default : /* jic */
            *stop = FALSE;
            break;
        }
        break;

    case IKE_NEXT_D :
        *stop = TRUE;
        pxDelHdr = (struct ike2DelHdr *)pPayload;
        switch (pxDelHdr->oProtoId)
        {
        case PROTO_ISAKMP :
            *st |= (1 << IKMP_DELETE);
            break;
        case PROTO_IPSEC_AH :
        case PROTO_IPSEC_ESP :
            *st |= (1 << PROTOCOL_DELETE);
            break;
        default : /* jic */
            *stop = FALSE;
            break;
        }
    default :
        break;
    }

    return status;
} /* CheckInfoXchg */

#endif /* __IKE_TRACK__ */


/*------------------------------------------------------------------*/

#ifdef __IKE_MULTI_THREADED__
static MSTATUS
Check2XchgIn(const IKESA pxSa, void *pData)
{
    MSTATUS status = OK;

    MOC_UNUSED(pData);

    if (IKE_SA_FLAG_DELETED & pxSa->flags)
    {
        status = ERR_IKE_GETSA_FAIL;
        goto exit;
    }

    if (FALSE == RTOS_sameThreadId(pxSa->tid, RTOS_currentThreadId()))
    {
        status = ERR_IKE;//ERR_IKE_BAD_THREAD;
        goto exit; /* abort */
    }

exit:
    return status;
} /* Check2XchgIn */
#endif


/*------------------------------------------------------------------*/

static MSTATUS
IKE2_xchgIn(IKE_context ctx, ikePeerConfig* config
#ifdef __IKE_TRACK__
          , IKE2_TRACK pxTrack
#endif
            )
{
    MSTATUS status = OK;

    MOC_IP_ADDRESS peerAddr = ctx->peerAddr;
    ubyte2 wPeerPort = ctx->wPeerPort;

#ifdef __ENABLE_IPSEC_NAT_T__
    intBoolean bUseNattPort = ctx->bUseNattPort;
#endif
#ifdef __IKE_MULTI_HOMING__
    sbyte4 serverInstance = ctx->serverInstance;
#endif

    struct ikeHdr *pxHdr;

    ubyte oExchange;
    ubyte4 dwMsgId, dwLength;
    intBoolean bInitiator;  /* peer */
    intBoolean bResponse = FALSE;   /* incoming message */

    IKESA pxSa = NULL;
    IKE2XG pxXg = NULL;

    ubyte __crypto__(poHash, MD5_DIGESTSIZE);

#ifdef __ENABLE_IPSEC_NAT_T__
    if (bUseNattPort) /* received at port 4500 */
    {
        struct ikeNatEspMarker *pxEspMkr = (struct ikeNatEspMarker *) ctx->pBuffer;

        /* check unknown ESP spi */
        if (4 > ctx->dwBufferSize)
        {
           status = ERR_IKE_BAD_LEN;
           DBG_EXIT
        }
        if (0 != GET_NTOHL(pxEspMkr->dwSpi))
        {
            /* MAY send N(INVALID_SPI) one-way message;
               see RFC4306 1.5 (p12) & draft-eronen-ipsec-ikev2-clarifications-09.txt 7.7 (p47) */
            status = ERR_IPSEC_DROP_FINDSA_FAIL;
            DBG_EXIT
        }

        /* remove non-ESP marker */
        ctx->pBuffer += 4;
        ctx->dwBufferSize -= 4;
    }
#endif /* __ENABLE_IPSEC_NAT_T__ */

    /* message header */
    if (SIZEOF_ISAKMP_HDR > ctx->dwBufferSize)
    {
        status = ERR_IKE_BAD_LEN;
        DBG_EXIT
    }
    pxHdr = (struct ikeHdr *) ctx->pBuffer;
    TRACK_HDR
    debug_print_ikehdr((ubyte *)pxHdr);

    oExchange = pxHdr->oExchange;
    bResponse = (IKE_FLAG_RESPONSE & pxHdr->oFlags) ? TRUE : FALSE;
    bInitiator = (IKE_FLAG_INITIATOR & pxHdr->oFlags) ? TRUE : FALSE;

    ctx->pBuffer        += SIZEOF_ISAKMP_HDR;
    ctx->dwBufferSize   -= SIZEOF_ISAKMP_HDR;
    ctx->dwLength       = SIZEOF_ISAKMP_HDR;

    ctx->pHdrParent     = (void *)pxHdr;
    ctx->oNextPayload   = pxHdr->oNextPayload;

    if ((IKE_NEXT_E == pxHdr->oNextPayload) &&
        (SIZEOF_IKE_GEN_HDR > ctx->dwBufferSize))
    {
        status = ERR_IKE_BAD_LEN;
        DBG_EXIT
    }

    SET_NTOHL(dwMsgId, pxHdr->dwMsgId);
    SET_NTOHL(dwLength, pxHdr->dwLength);

    /* check message length */
    if (SIZEOF_ISAKMP_HDR > dwLength)
    {
        status = ERR_IKE_BAD_LEN;
        DBG_EXIT
    }
    else
    {
        ubyte4 dwBodyLen = dwLength - SIZEOF_ISAKMP_HDR;
        if (dwBodyLen > ctx->dwBufferSize)
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }
        ctx->dwBufferSize = dwBodyLen;
    }

    /* check version */
    if (2 != (pxHdr->oVersion >> 4)) /* 2.0 */
    {
        /* INVALID_MAJOR_VERSION;*/
        status = ERR_IKE_BAD_VERSION;
        DBG_EXIT
    }

    /* check empty initiator cookie */
    if (IKE_isEmptyCky(pxHdr->poCky_I))
    {
        /* INVALID_IKE_SPI */
        status = ERR_IKE_BAD_COOKIE;
        DBG_EXIT
    }

    /* get IKE_SA */
    if (OK > (status = IKE_getSa(pxHdr->poCky_I, pxHdr->poCky_R,
                                 (1 << (bInitiator ? _R : _I)),
                                 peerAddr, &pxSa, NULL,
#ifdef __IKE_MULTI_THREADED__
                                 Check2XchgIn
#else
                                 NULL
#endif
                                 MOC_MTHM_VALUE(serverInstance))))
    {
        TRACK_SA
        /* existing, but no longer valid */
        DBG_EXIT
    }

    if (NULL == pxSa) /* not found */
    {
        /* 1st IKE_SA_INIT message */
        if ((0 == dwMsgId) &&
            bInitiator && !bResponse &&
            (IKE_XCHG_INIT == oExchange) &&
            IKE_isEmptyCky(pxHdr->poCky_R))
        {
            goto request;
        }

        /* unknown cookies may occur in a response w/ N(INVALID_IKE_SPI) w/o SK{...} */
        /* see RFC4306 2.21 (p36) */
        status = ERR_IKE_BAD_COOKIE; /* FOR NOW */
        DBG_EXIT
    }

    ctx->pxSa = pxSa; /* existing IKE_SA */
    TRACK_SA

    /* check peer IP address */
    if (!SAME_MOC_IPADDR(peerAddr, pxSa->dwPeerAddr))
#ifdef __ENABLE_MOBIKE__
    if (!IS_IKE2_SA_AUTHED(pxSa) || !(IKE_SA_FLAG_MOBILE & pxSa->flags))
#endif
    {
        status = ERR_IKE_BAD_MSG;
        DBG_EXIT
    }

#ifdef __ENABLE_IPSEC_NAT_T__
    /* check host NAT-T port */
    if (!bUseNattPort && USE_NATT_PORT(pxSa)) /* expect port 4500 */
    {
        /* For interop w/ Juniper MAG 2600, which switches to
           port 4500 only after (EAP) authentication is done. */
        if (!IS_IKE2_SA_AUTHED(pxSa) && bResponse)
        {
            wPeerPort = pxSa->wPeerPort; /* do not override port!!! */
        }
        else
        {
            status = ERR_IKE_BAD_PORT;
            DBG_EXIT
        }
    }
    else
#endif

    /* check peer port */
    if (wPeerPort != pxSa->wPeerPort) /* changed */
    {
#ifdef __ENABLE_IPSEC_NAT_T__
#ifdef __ENABLE_MOBIKE__
        if (!IS_IKE2_SA_AUTHED(pxSa) || !(IKE_SA_FLAG_MOBILE & pxSa->flags))
#endif
        if ((IKE_NATT_FLAG_NPORT_USED & pxSa->natt_flags) ||
            (IKE_XCHG_AUTH != oExchange) ||
            !IS_IKE2_SA_INITED(pxSa) ||
            IS_IKE2_SA_AUTHED(pxSa) ||
            bResponse || !bUseNattPort)
#endif
        {
            status = ERR_IKE_BAD_PORT;
            DBG_EXIT
        }
    }

    /* check responder cookie */
    if (IKE_isEmptyCky(pxHdr->poCky_R))
    {
        if (IKE_isEmptyCky(pxSa->poCky_R))
        {
            /* responder cookie  may be 0 in the 2nd IKE_SA_INIT message, e.g.
               N(COOKIE), N(INVALID_KE_PAYLOAD), N(NO_PROPOSAL_CHOSEN), etc.
               see draft-eronen-ipsec-ikev2-clarifications-09.txt 2.1 (p4) */
        }
        else
        {
            /* already received IKE_SA_INIT message */
            if (IKE_XCHG_INIT != oExchange)
            {
                status = ERR_IKE_BAD_COOKIE;
                DBG_EXIT
            }

            if (IS_IKE2_SA_AUTHED(pxSa))
            {
                status = ERR_IKE_BAD_XCHG;
                goto exit;
            }

            if (bInitiator) /* from Initiator */
            {
                /* probably re-trans or re-send (due to INVALID_KE_PAYLOAD)
                   of 1st msg */
            }
            else /* from Responder */
            {
                /* probably re-trans of 2nd msg, e.g. N(COOKIE), etc. */
                status = ERR_IKE_BAD_XCHG;
                goto exit;
            }
        }
    }
    else
    {
        if (IKE_isEmptyCky(pxSa->poCky_R) && !bResponse)
        {
            status = ERR_IKE_BAD_COOKIE;
            DBG_EXIT
        }
    }

    /* get exchange */
    if (OK > (status = IKE2_getXchg(pxSa, dwMsgId, bResponse, &pxXg)))
    {
        goto exit;
    }

    ctx->pxXg = pxXg; /* may be NULL (e.g. new inbound request) */
    TRACK_XG

    if (pxXg && (IKE_XCHG_FLAG_PENDING & pxXg->x_flags))
    {
        /* Pending exchange shouldn't expect any more incoming message.
           This means the exchange has already processed the message received
           last time but is pending (before moving to the next state).
         */
        status = STATUS_IKE_PENDING;
        DBG_EXIT
    }

    /* process SK{...} */
    if (IS_IKE2_SA_INITED(pxSa))
    {
        if (OK > (status = IKE2_checkSK(ctx)))
        {
            goto exit;
        }

        if (ctx->u.v2.poIcv) /* integrity-check passed */
        {
            intBoolean bNotRtx =  (!pxXg ||
#ifdef __ENABLE_IKE_FRAGMENTATION__
                                   !pxXg->numMsgs ||
#endif
                                   bResponse);

            if (IS_IKE2_SA_AUTHED(pxSa))
            {
                if (bNotRtx) /* NOT re-transmission */
                {
                    pxSa->dwTimeStamp = RTOS_deltaMS(&gStartTime, NULL);
                    pxSa->flags &= ~(IKE_SA_FLAG_DPD);
                }

                if (!IS_MATURE(pxSa))
                {
                    pxSa->flags |= IKE_SA_FLAG_MATURE;
                    IKE2_finalizeSa(pxSa, pxSa->dwTimeStamp, NULL);
                }
            }

            /* book-keeping */
            if (bNotRtx)  /* NOT re-transmission */
            {
                pxSa->dwCurBytes += dwLength;
                if (1024 <= pxSa->dwCurBytes)
                {
                    ubyte4 dwNewKBytes = pxSa->dwCurKBytes + (pxSa->dwCurBytes / 1024);
                    pxSa->dwCurBytes = (pxSa->dwCurBytes % 1024);

                    /* jic KBytes wraps back to 0 */
                    if (pxSa->dwExpKBytes && (pxSa->dwCurKBytes > dwNewKBytes))
                    {
                        pxSa->dwCurBytes += (ubyte4)((dwNewKBytes + 1) * 1024);
                        dwNewKBytes = ~((ubyte4)0);
                    }
                    pxSa->dwCurKBytes = dwNewKBytes;
                }
#ifdef __IKE_UPDATE_TIMER__
                KB_REKEY(pxSa) /* auto. rekeying - lifetime kbytes */
#endif
            }
        }
        else /* no Encrypted Payload */
        {
            if (!bResponse && pxXg && (IKE_XCHG_INIT == pxXg->oExchange))
            {
                /* OK - re-transmitted inbound IKE_SA_INIT request */
            }
            else
            {
                status = ERR_IKE_BAD_MSG;
                DBG_EXIT
            }
        }
    }

    if (bResponse) goto response;

request:
#ifdef __ENABLE_DIGICERT_HARNESS__
    if (OK > (status = CRYPTO_ALLOC(ctx->hwAccelCookie, MD5_DIGESTSIZE,
                                    TRUE, (void**) &poHash)))
        DBG_EXIT
#endif

    /* check IKE_SA_INIT message */
    if (!ctx->u.v2.poIcv)
    {
        if (IKE_XCHG_INIT != oExchange)
        {
            status = ERR_IKE_BAD_XCHG;
            DBG_EXIT
        }

        if (!pxXg) /* new inbound request */
        {
            /* check N(COOKIE) */
            if (m_ikeSettings.bNotifyCookie)
            if ((OK > (status = IKE2_checkCookie(ctx))) ||
                (NOTIFY_COOKIE == ctx->wMsgType))
                goto exit;

            /* new IKE_SA */
            if (!pxSa)
            {
                if (NULL == (pxSa = IKE2_newSa(config,
                                               peerAddr, wPeerPort, pxHdr->poCky_I, NULL
                                               MOC_NATT_VALUE(bUseNattPort)
                                               MOC_MTHM_VALUE(serverInstance))))
                {
                    ctx->wMsgType = NO_PROPOSAL_CHOSEN;
                    status = ERR_IKE_NEWSA_FAIL;
                    DBG_EXIT
                }
                ctx->pxSa = pxSa;
                TRACK_SA
            }
        }

        /* hash the message for later use */
        if (OK > (status = MD5_completeDigest(MOC_HASH(ctx->hwAccelCookie)
                                              (ubyte *) ctx->pHdrParent,
                                              dwLength, poHash)))
        {
            DBG_EXIT
        }
    }

    if (pxXg) /* existing inbound request */
    {
        if (!ctx->u.v2.poIcv) /* IKE_SA_INIT message */
        {
            /* check re-transmission */
            sbyte4 compareResult;
            if (OK > (status = DIGI_MEMCMP(poHash, pxXg->poIcv[0],
                                          MD5_DIGESTSIZE, &compareResult)))
            {
                DBG_EXIT
            }
            if (0 != compareResult) /* bad re-transmission */
            {
                status = ERR_IKE_BAD_MSG;
                DBG_EXIT
            }

            if (!pxXg->numMsgs && pxSa->merror) /* jic - see initR_in() */
            {
                /* error occurred last time but no outbound response saved!!! */
                status = pxSa->merror;
                DBG_EXIT
            }
        }
#ifdef __ENABLE_IKE_FRAGMENTATION__
        else if (!pxXg->numMsgs) /* reassembling not finished yet */
        {
            goto process;
        }
#endif
        goto exit; /* re-transmission OK; will re-respond as a result */
    }

    if (!pxSa) /* jic */
    {
        status = ERR_IKE;
        DBG_EXIT
    }

    /* if IKE_SA is being deleted, do not accept any new inbound request */
    if ((IKE_SA_FLAG_DELETING & pxSa->flags)
#ifdef __ENABLE_MOBIKE__
     || (IKE_SA_FLAG_UPDATING & pxSa->flags)
#endif
        )
    {
        status = ERR_IKE_GETSA_FAIL;
        DBG_EXIT
    }
    else
    {
        /* save ICV/hash for re-transmission check */
        ubyte *poIcv = NULL;
        ubyte2 wIcvLen = 0;

#ifdef __ENABLE_IKE_FRAGMENTATION__
        if (!ctx->u.v2.bSKF) /* NOT fragment */
#endif
        {
            if (NULL != ctx->u.v2.poIcv)
            {
                if (NULL != pxSa->pMacSuite)
                {
                    wIcvLen = pxSa->pMacSuite->wIcvLen;
                }
                else if (NULL != pxSa->pCipherSuite->pAeadAlgo)
                {
                    wIcvLen = pxSa->pCipherSuite->pAeadAlgo->tagSize;
                }
                else
                {
                    wIcvLen = MD5_DIGESTSIZE;
                }
            }
            else
            {
                wIcvLen = MD5_DIGESTSIZE;
            }

            if (NULL == (poIcv = (ubyte *) MALLOC(wIcvLen)))
            {
                status = ERR_MEM_ALLOC_FAIL;
                DBG_EXIT
            }
        }

        /* new inbound request */
        if (OK > (status = IKE2_newXchg(pxSa, oExchange, dwMsgId, FALSE/* bResponse*/, &pxXg)))
        {
            if (poIcv) FREE(poIcv);
            goto exit;
        }

#ifdef __ENABLE_IKE_FRAGMENTATION__
        if (poIcv)
#endif
        {
            DIGI_MEMCPY(poIcv, (ctx->u.v2.poIcv ? ctx->u.v2.poIcv : poHash), wIcvLen);
            pxXg->poIcv[0] = poIcv;
            pxXg->numIcvs = 1;
        }
    }

    if (!IS_IKE2_SA_AUTHED(pxSa))
        pxXg->pxSa = pxSa;

    ctx->pxXg = pxXg;
    TRACK_XG

    /* check exchange type */
    if (IS_IKE2_SA_INITED(pxSa))
    {
        switch (oExchange)
        {
        case IKE_XCHG_AUTH :    /* IKE_AUTH */
            if (!IS_IKE2_SA_AUTHED(pxSa))
                break;
        case IKE_XCHG_CHILD :   /* CREATE_CHILD_SA */
        case IKE_XCHG_INFO :    /* INFORMATIONAL */
            if (IS_IKE2_SA_AUTHED(pxSa) &&
                (IKE_XCHG_AUTH != oExchange))
                break;
        case IKE_XCHG_INIT :    /* IKE_SA_INIT */
        default :
            ctx->wMsgType = INVALID_SYNTAX;
            status = ERR_IKE_BAD_XCHG;
            DBG_EXIT
        }
    }

    goto process;

response:
    if (!pxXg) goto exit; /* jic - shouldn't happen */

    /* check exchange type */
    if (oExchange != pxXg->oExchange)
    {
        if (IS_IKE2_SA_INITED(pxSa))
        {
            /* Inbound response has passed integrity-check but its exchange
               type is different from original outbound request. Delete the
               exchange as a result.
             */
            if (IS_IKE2_SA_AUTHED(pxSa))
            {
                IKE2_delXchg(pxXg, pxSa, ERR_IKE_BAD_XCHG);
            }
            else
            {
                IKE2_delSa(pxSa, FALSE, ERR_IKE_BAD_XCHG);
            }
        }
        status = ERR_IKE_BAD_XCHG;
        DBG_EXIT
    }

process:
    if (pxXg) /* jic */
    {
        ubyte4 old_flags = pxSa->flags;
#ifdef __ENABLE_IPSEC_NAT_T__
        ubyte old_natt_flags = pxSa->natt_flags;
        ubyte2 wHostPortOld = pxSa->wHostPort;

        if (bUseNattPort)
        {
            if (!USE_NATT_PORT(pxSa))
            {
                if (m_ikeSettings.funcPtrIkeGetHostPort)
                {
                    if (OK > (status = (MSTATUS)
                              m_ikeSettings.funcPtrIkeGetHostPort(
                                    &pxSa->wHostPort
                                    MOC_NATT_REQ_VALUE(TRUE)
                                    MOC_MTHM_REQ_VALUE(pxSa->serverInstance))))
                    {
                        DBG_EXIT
                    }
                }
                else
                {
                    pxSa->wHostPort = IKE_NAT_UDP_PORT;
                }
                pxSa->natt_flags |= IKE_NATT_FLAG_USE_NPORT;
            }
            pxSa->natt_flags |= IKE_NATT_FLAG_NPORT_USED;
        }

        /* changing port, if necessary */
        if (wPeerPort != pxSa->wPeerPort) /* peer port changed */
#ifdef __ENABLE_MOBIKE__
        if (!IS_IKE2_SA_AUTHED(pxSa) || !(IKE_SA_FLAG_MOBILE & pxSa->flags))
#endif
        {
            /* Note: Only for responder inbound IKE_AUTH */
            ctx->wPeerPort = pxSa->wPeerPort;
            pxSa->wPeerPort = wPeerPort;
        }
#endif

        debug_printnl(bResponse ? "  I <--" : "  --> R");

        /* Incoming message processing may endup overwriting ctx->pBuffer 
         in which case it will be freed after call to inFunc() */
        ctx->pRefragmentationBuffer = NULL;

        /* process incoming message */
        status = pxXg->pState->inFunc(ctx);

        /* If ctx->pBuffer was overwritten, pRefragmentationBuffer holds the start pointer
         Free it */
        if (NULL != ctx->pRefragmentationBuffer)
            FREE(ctx->pRefragmentationBuffer);

        if (OK > status)
        {
            if (STATUS_IKE_PENDING != status)
            {
#ifdef __IKE_MULTI_THREADED__
                if (NULL != (pxSa = ctx->pxSa)) /* jic - IKE_SA was deleted */
#endif
                if (IS_VALID(pxSa) && !IS_IKE2_SA_INITED(pxSa))
                {
                    pxSa->flags = old_flags;
#ifdef __ENABLE_IPSEC_NAT_T__
                    pxSa->natt_flags = old_natt_flags;

                    pxSa->wHostPort = wHostPortOld;
                    if (wPeerPort != ctx->wPeerPort)
                        pxSa->wPeerPort = ctx->wPeerPort;
#endif
                }
                goto exit;
            }
        }

        /* DEBUG: dump message (i.e. pxHdr) here (after decryption) */
        TRACK_PLAINTEXT

        /* Note: The length field in Encrypted payload (SK) header is now
           size of generic header plus IV. See InSk() in "ike2_state.c".
         */
    }

exit:
    if (bResponse || (STATUS_IKE_PENDING == status))
    {
#ifdef __ENABLE_IKE_REDIRECT__
        if (REDIRECTED_FROM != ctx->wMsgType)
#endif
            ctx->wMsgType = 0;
    }
    else if (!ctx->wMsgType)
    {
        if ((OK > status) &&
#ifdef __IKE_MULTI_THREADED__
            pxSa &&
#endif
            pxXg && IS_IKE2_SA_INITED(pxSa) && ctx->u.v2.poIcv)
        {
            ctx->wMsgType = INVALID_SYNTAX;
        }
    }
    _CRYPTO_FREE_(ctx->hwAccelCookie, poHash)
    return status;
} /* IKE2_xchgIn */


/*------------------------------------------------------------------*/

extern sbyte4
IKE2_msgRecv(MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort,
             ubyte *pBuffer, ubyte4 dwBufferSize,
             sbyte4 serverInstance,
             intBoolean bUseNattPort
#ifdef __IKE_TRACK__
           , IKE2_TRACK pxTrack
#endif
             )
{
    MSTATUS status = OK;

    MSTATUS status_in = OK;
    IKESA pxSa = NULL;
    IKE2XG pxXg = NULL;
    intBoolean bResponse = FALSE;

    ikePeerConfig* config;

    struct ike_context ctx = { NULL };

#if 1
#ifndef __IKE_MULTI_HOMING__
    MOC_UNUSED(serverInstance);
#endif
#ifndef __ENABLE_IPSEC_NAT_T__
    MOC_UNUSED(bUseNattPort);
#endif
#else
    /* demux event/message */ /* DEPRECATED 10-29-15 */
    if (sizeof(struct ike_event) == dwBufferSize)
    {
        IKEEVT pxEvt = (IKEEVT)pBuffer;
        ubyte2 type = (IKE_KEY_TYPE_MASK & pxEvt->type);

        if (type && ((ubyte2)IKE_KEY_TYPE_MAX >= type))
        {
            status = (MSTATUS) IKE_evtRecv(pxEvt, serverInstance, bUseNattPort);
            goto nocleanup;
        }
    }
#endif

    /* sanity check */
    TEST_MOC_IPADDR6(peerAddr,
    {
        const ubyte *addr6 = GET_MOC_IPADDR6(peerAddr);
        if (0xFF == addr6[0]) /* multicast */
        {
            status = ERR_IKE;
            DBG_STATUS
            goto nocleanup;
        }
    })
    {
        ubyte4 dwPeerAddr = GET_MOC_IPADDR4(peerAddr);
        if ((0 == dwPeerAddr) || (0 == wPeerPort) || /* jic */
            ((dwPeerAddr & 0xe0000000) == 0xe0000000)) /* multicast/broadcast */
        {
            status = ERR_IKE;
            DBG_STATUS
            goto nocleanup;
        }
    }

#ifdef __ENABLE_IPSEC_NAT_T__
    /* check NAT-Keepalive */
    if (bUseNattPort && (1 == dwBufferSize) && (0xFF == *pBuffer))
        goto nocleanup; /* ignore */
#endif

    IKE_LOCK_R; /* !!! */

    if (NULL == (config = IKE_findPeerConfig(peerAddr, wPeerPort, serverInstance)))
    {
        status = ERR_IKE_NO_PEER_CONFIG;
        DBG_ABORT
    }

    /* message received */
    debug_printnl("");
#ifdef __ENABLE_IPSEC_NAT_T__
    if (bUseNattPort) debug_print("#");
#endif
    debug_print("RECV ");
    debug_uint(dwBufferSize);
    debug_print(" bytes from ");
    debug_print_ip(peerAddr);
    debug_print("[");
    debug_int(wPeerPort);
    debug_print("]");
#ifdef __IKE_MULTI_HOMING__
    debug_print(" at ");
#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
    if (NULL != m_ikeSettings.funcPtrIkeGetHostAddr) /* jic */
    {
        MOC_IP_ADDRESS_S hostAddr;
        if (OK > (m_ikeSettings.funcPtrIkeGetHostAddr(&hostAddr, serverInstance)))
        {
            debug_print("@");
            debug_int(serverInstance);
        }
        else debug_print_ip(REF_MOC_IPADDR(hostAddr));
    }
#endif
#endif
    debug_uptime();
    debug_printnl("");

#ifdef __ENABLE_IPSEC_NAT_T__
    if (bUseNattPort) /* received at 4500 */
    {
        if (IKE_DEFAULT_UDP_PORT == wPeerPort) /* jic */
        {
           status = ERR_IKE_BAD_PORT;
           DBG_ABORT
        }
    }
    else /* received at 500 */
    {
        if (IKE_NAT_UDP_PORT == wPeerPort) /* jic */
        {
           status = ERR_IKE_BAD_PORT;
           DBG_ABORT
        }
    }
#endif /* __ENABLE_IPSEC_NAT_T__ */

    /* set up context */
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    if (OK > (status = IKE_getHwAccelChannel(&ctx.hwAccelCookie)))
        DBG_ABORT

    ctx.isHwAccelCookieInit = TRUE;
#endif
    ctx.pBuffer         = pBuffer;
    ctx.dwBufferSize    = dwBufferSize;

#ifdef __ENABLE_DIGICERT_HARNESS__
    dwBufferSize = m_ikeSettings.ikeBufferSize;
#ifdef __ENABLE_IPSEC_NAT_T__
    dwBufferSize += 4;
#endif
    if (dwBufferSize < ctx.dwBufferSize)
        dwBufferSize = ctx.dwBufferSize;

    pBuffer = NULL;
    if (OK > (status = CRYPTO_ALLOC(ctx.hwAccelCookie, dwBufferSize,
                                    TRUE, (void**) &pBuffer)))
        DBG_EXIT

    DIGI_MEMCPY(pBuffer, ctx.pBuffer, ctx.dwBufferSize);
    ctx.pBuffer         = pBuffer;
/*  ctx.dwBufferSize    = dwBufferSize;*/
#endif /* __ENABLE_DIGICERT_HARNESS__ */

    ctx.peerAddr        = peerAddr;
    ctx.wPeerPort       = wPeerPort;

#ifdef __ENABLE_IPSEC_NAT_T__
    ctx.bUseNattPort    = bUseNattPort;
#endif
#ifdef __IKE_MULTI_HOMING__
    ctx.serverInstance  = serverInstance;
#endif

    /* process message */
    if (OK > (status = IKE2_xchgIn(&ctx, config
#ifdef __IKE_TRACK__
                                 , pxTrack
#endif
                                   )))
    {
        if (!ctx.wMsgType) goto exit;
        status_in = status;
    }
    else if (NULL != (pxXg = ctx.pxXg))
    {
        pxSa = ctx.pxSa;
        bResponse = IS_XCHG_INITIATOR(pxXg);

        if (bResponse)
        {
            switch (pxXg->oExchange)
            {
            case IKE_XCHG_AUTH :    /* IKE_AUTH */
                if (IS_IKE2_SA_AUTHED(pxSa))
                    goto final;
                break;
            case IKE_XCHG_CHILD :   /* CREATE_CHILD_SA */
                if (pxXg->pxSa)
                {
                    if (STATE_MAIN_I == pxXg->pxSa->oState)
                        goto final;
                }
                else if (pxXg->pxIPsecSa)
                {
                    if (STATE_QUICK_I == pxXg->pxIPsecSa->oState)
                        goto final;
                }
                /* re-send, e.g. INVALID_KE_PAYLOAD */
                break;
            case IKE_XCHG_INFO :    /* INFORMATIONAL */
                TRACK_OK
                goto exit;
                /*break;*/
            default :
                break;
            }
        }
        else /* request */
        {
             if (pxXg->numMsgs) /* re-transmission */
             {
                 pxXg = NULL; /* !!! */
                 TRACK_XG /* !!! */
             }
        }

        TRACK_OK
    }
    else
    {
        TRACK_OK
    }

    /* send message */
    ctx.pBuffer         = pBuffer;
    ctx.dwBufferSize    = dwBufferSize;

    if (OK > (status = IKE2_xchgOut(&ctx)))
    {
#ifdef __IKE_KEYADD_DONT_WAIT__
        if (NULL != pxXg)
        {
            IPSECSA pxIPsecSa = pxXg->pxIPsecSa;
            if ((NULL != pxIPsecSa) &&
                (OK <= pxIPsecSa->merror) &&
                (STATE_QUICK_R == pxIPsecSa->oState))
            {
                /* TODO: delete keys */
            }
        }
#endif
        if (OK <= status_in)
        goto exit;
    }

    if (OK > status_in)
    {
        status = status_in;
        goto exit;
    }

    if (!pxXg || bResponse) goto exit;

    switch (pxXg->oExchange)
    {
    case IKE_XCHG_INIT :
        pxSa->oState = STATE_MAIN_R2; /* !!! */
        break;

    case IKE_XCHG_AUTH :
        if (!pxSa->u.v2.dwWndLen[_I]) /* ongoing (e.g. EAP) */
            goto exit;

        pxSa->oState = STATE_MAIN_R;

#ifndef __IKE_KEYADD_DONT_WAIT__
        if (!pxXg->pxIPsecSa->wMsgType)
            pxXg->pxIPsecSa->oState = STATE_QUICK_R;
#endif
        break;

    case IKE_XCHG_CHILD :
        if (pxXg->pxSa)
            pxXg->pxSa->oState = STATE_MAIN_R;
        else
#ifndef __IKE_KEYADD_DONT_WAIT__
            pxXg->pxIPsecSa->oState = STATE_QUICK_R;
#else
        {
            status = pxXg->pxIPsecSa->merror;
            goto exit;
        }
#endif
        break;

    case IKE_XCHG_INFO :
#ifdef __ENABLE_MOBIKE__
        if (IKE_XCHG_FLAG_UPDATE_SA & pxXg->x_flags)
        {
#ifdef IKE_SA_ADDR_HASH_TABLE_SIZE_MASK
            IKE_delSaAddrIndex(pxSa);
#endif
            COPY_MOC_IPADDR(pxSa->dwPeerAddr, peerAddr);
            pxSa->wPeerPort = wPeerPort;

#ifdef IKE_SA_ADDR_HASH_TABLE_SIZE_MASK
            IKE_addSaAddrIndex(pxSa);
#endif
            IKE2_doUpdateSa(&ctx);
        }
        /* fall through */
#endif /* __ENABLE_MOBIKE__ */

#ifdef __ENABLE_IKE_REDIRECT__
        if (IKE_SA_FLAG_REDIRECTED & pxSa->flags)
        {
            IKE2_delSa(pxSa, FALSE, STATUS_IKE_REDIRECTED);
        }
#endif

    default :
        goto exit;
        /*break;*/
    }

final:
    TRACK_OK

    switch (pxXg->oExchange)
    {
    case IKE_XCHG_AUTH :    /* IKE_AUTH */
    {
        IKE2_finalizeSa(pxSa, pxSa->dwTimeCreated, NULL);

#ifdef __ENABLE_IKE_REDIRECT__
        if (bResponse && (IKE_SA_FLAG_REDIRECTED & pxSa->flags))
        {
            IKE2_delSa(pxSa, TRUE, STATUS_IKE_REDIRECTED);
            goto exit; /* !!! */
        }
#endif
#ifdef __IKE_KEYADD_DONT_WAIT__
        if (bResponse)
#endif
        if (IS_P2_FINAL_STATE(pxXg->pxIPsecSa->oState))
            IKE_addIPsecKey(&ctx);

        if (bResponse)
            IKE2_delXchg(pxXg, pxSa, OK);
        break;
    }
    case IKE_XCHG_CHILD :   /* CREATE_CHILD_SA */
    {
        IKESA pxSa1 = pxXg->pxSa;
        if (pxSa1)
            /* Note: will not delete 'pxSa' !!! */
            IKE2_finalizeSa(pxSa1, pxSa1->dwTimeCreated, pxSa);
        else
            IKE_addIPsecKey(&ctx);

        if (bResponse)
            IKE2_delXchg(pxXg, pxSa, OK);

#ifdef __IKE_UPDATE_TIMER__
        if (pxSa1)
        {
            pxSa = pxSa1;
            break;
        }
#endif
    }
    default :
        goto exit; /* !!! */
    }

#ifdef __IKE_UPDATE_TIMER__
    /*                                      */
    /* Set up timers for established IKE_SA */
    /*                                      */
    status = IKE2_setupMatureTimers(pxSa);
#endif

exit:
    _CRYPTO_FREE_(ctx.hwAccelCookie, pBuffer)
    if (ctx.u.v2.poCookie)
        CRYPTO_FREE(ctx.hwAccelCookie, TRUE, (void**) &ctx.u.v2.poCookie);

    /* Free AEAD-allocated ICV buffer (allocated by IKE2_decryptAead) */
    if (ctx.pxSa && ctx.pxSa->pCipherSuite &&
        ctx.pxSa->pCipherSuite->pAeadAlgo && ctx.u.v2.poIcv)
    {
        DIGI_FREE((void **) &(ctx.u.v2.poIcv));
    }

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    if (ctx.isHwAccelCookieInit)
    {
        IKE_releaseHwAccelChannel(&ctx.hwAccelCookie);
/*      ctx.isHwAccelCookieInit = FALSE;*/
    }
#endif

abort:
    IKE_UNLOCK_R;

nocleanup:
    return (sbyte4)status;
} /* IKE2_msgRecv */


/*------------------------------------------------------------------*/

#ifdef __IKE_TRACK__

extern sbyte4
IKE2_msgRecvEx1(MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort,
                ubyte *pBuffer, ubyte4 dwBufferSize,
                sbyte4 serverInstance,
                intBoolean bUseNattPort,
                ubyte2 *ret)
{
    MSTATUS status = OK;

    struct ike2_track track = { NULL };
    struct ikeHdr *pxHdr = NULL;
    struct ikesa  *pxSa = NULL;
    struct ike2xg *pxXg = NULL;
    byteBoolean  bReleaseLock = FALSE;

    ubyte2 st = 0;

#ifdef __IKE_MULTI_THREADED__
    if (NULL == (track.pBuffer = (ubyte *) MALLOC(TK_BUF_SIZE)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
#endif

    status = IKE2_msgRecv(peerAddr, wPeerPort,
                          pBuffer, dwBufferSize,
                          serverInstance,
                          bUseNattPort,
                          &track);
    IKE_LOCK_R;
    bReleaseLock = TRUE;

    pxHdr = track.pxHdr;
    pxSa = track.pxSa;
    pxXg = track.pxXg;
    if (pxSa && !IS_VALID(pxSa))
    {
        if(track.bMsgOK && (OK == status) && (pxSa->flags & IKE_SA_FLAG_DELETED))
        {
            st = IKMP_DELETE;
        }
        else
        {
            status = ERR_IKE_BAD_SA;
        }
        goto exit;
    }

    if (track.bMsgOK)
    {
        if (0 > status)
        {
            // internal error during state-change
            goto exit;
        }

        if (pxXg)
        {
            switch (pxXg->oExchange)
            {
            case IKE_XCHG_INIT:
                st |= (1 << IKMP_CONTINUE);
                break;

            case IKE_XCHG_AUTH:
                if (pxSa && IS_IKE2_SA_AUTHED(pxSa))
                {
                    st |= (1 << ((IKE_SA_FLAG_INIT_C & pxSa->flags)
                                 ? IKMP_SA_NEGOTIATED_NOTIFY
                                 : IKMP_SA_NEGOTIATED));
                    if (pxXg->pxIPsecSa) /* responder only? */
                    {
                        st |= (1 << ((OK <= pxXg->pxIPsecSa->merror)
                                     ? PROTOCOL_SA_NEGOTIATED
                                     : PROTOCOL_ERROR));
                    }
#ifdef __ENABLE_IKE_CP__
                    if (pxXg->poCfgAttrs) /* responder only? */
                    {
                        st |= (1 << CONFIG_MODE_DONE);
                        //st |= (1 << CONFIG_MODE_ERROR);
                    }
#endif
                }
                else /* e.g. initiator (1st AUTH msg) or EAP */
                {
                    st |= (1 << IKMP_CONTINUE) | (1 << PROTOCOL_CONTINUE);
#ifdef __ENABLE_IKE_CP__
                    if (pxXg->poCfgAttrs
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
                     || pxSa->u.v2.poCp
#endif
                        )
                    {
                        st |= (1 << CONFIG_MODE_CONTINUE);
                    }
#endif
                }
                break;

            case IKE_XCHG_CHILD: /* responder only? */
                if (pxXg->pxSa)
                {
                    st |= (1 << IKMP_SA_NEGOTIATED);
                }
                else /* if (pxXg->pxIPsecSa) */
                {
                    st |= (1 << PROTOCOL_SA_NEGOTIATED);
                }
                break;

            case IKE_XCHG_INFO:
                track.userData = (void *) &st;
                IKE_travMsg((ubyte *)pxHdr, TK_BUF_SIZE, (void *)&track,
                            CheckInfoXchg);
                break;

            default: /* should not get here */
                break;
            }

        }
        else if (pxSa) /* e.g. re-transmitted request */
        {
            st |= (1 << RETRANSMIT_IGNORE);
        }
        else /* e.g. COOKIE (responder) */
        {
            st |= (1 << IKMP_CONTINUE);
        }

        goto exit; /* !!! */
    }

    if (pxXg)
    {
        intBoolean bResponse = IS_XCHG_INITIATOR(pxXg);
        if (!bResponse && (STATUS_IKE_PENDING == status))
        {
            st |= (1 << RETRANSMIT_IGNORE);
            goto exit;
        }

        switch (pxXg->oExchange)
        {
        case IKE_XCHG_INIT:
            st |= (1 << IKMP_ERROR);
            break;

        case IKE_XCHG_AUTH:
            st |= (1 << IKMP_ERROR) | (1 << PROTOCOL_ERROR);
            break;

        case IKE_XCHG_CHILD: /* responder only? */
            if (pxXg->pxSa)
            {
                st |= (1 << IKMP_ERROR);
            }
            else if (pxXg->pxIPsecSa)
            {
                st |= (1 << PROTOCOL_ERROR);
            }
            break;

        /*case IKE_XCHG_INFO:
            break;*/
        default:
            break;
        }

        goto exit; /* !!! */
    }

    if (pxSa)
    {
        intBoolean bResponse = (IKE_FLAG_RESPONSE & pxHdr->oFlags) ? TRUE : FALSE;
        if (!bResponse && (ERR_IKE_BAD_MSGID == status) &&
            (GET_NTOHL(pxHdr->dwMsgId) < pxSa->u.v2.dwMsgId[_R]))
        {
            st |= (1 << RETRANSMIT_IGNORE);
            goto exit;
        }
    }

    if (pxHdr)
    {
        switch (pxHdr->oExchange)
        {
        case IKE_XCHG_INIT :
            st |= (1 << IKMP_ERROR);
            break;
        case IKE_XCHG_AUTH:
            st |= (1 << IKMP_ERROR) | (1 << PROTOCOL_ERROR);
            break;
        case IKE_XCHG_CHILD:
            st |= (1 << PROTOCOL_ERROR);
            break;
        case IKE_XCHG_INFO :
            break;
        default :
            break;
        }
    }

exit:
#ifdef __IKE_MULTI_THREADED__
    if (track.pBuffer) FREE(track.pBuffer);
#endif
    if (ret) *ret = st;

    if(bReleaseLock == TRUE)
        IKE_UNLOCK_R;

    return status;
} /* IKE2_msgRecvEx1 */

#endif /* __IKE_TRACK__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_IKE_REDIRECT__

/**
@brief      Redirect the responder VPN gateway.

@details    This function enables a VPNB gateway to redirect a VPN client to
            another gateway. Redirection can happen during SA_INIT and
            IKE_AUTH exchange. For details out the IKE v2 redirect mechanism,
            refer to RFC&nbsp;5685.

@ingroup    ike2_functions

@since 5.4
@version 5.4 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_IKE_REDIRECT__

@inc_file ike.h

@param peerAddr         IP address of the IKE2 initiator.
@param serverInstance   Application-specific identifier.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ike2.c
*/
extern MSTATUS
IKE2_sendRedirect(MOC_IP_ADDRESS peerAddr, sbyte4 serverInstance)
{
    MSTATUS     status = OK;
    struct ike_context ctx = { NULL };
    IKESA pxSa = NULL;
    IKE2XG pxXg = NULL;

    IKE_LOCK_W;

    /* get sa by peer addr  and ensure correct state */
    if ((OK > (status = IKE_getSaByAddr(peerAddr, &pxSa, NULL, NULL
                                        MOC_MTHM_VALUE(serverInstance))))
         || (!IS_IKE2_SA_AUTHED(pxSa)))
    {
        status = ERR_IKE_GETSA_FAIL;
        goto exit;
    }

    if (OK > (status = IKE2_newXchg(pxSa, IKE_XCHG_INFO, 0, TRUE, &pxXg)))
        goto exit;

    ctx.wMsgType = REDIRECT;
    ctx.pxSa = pxSa;
    ctx.pxXg = pxXg;

    status = IKE2_xchgOut(&ctx);

exit:
    IKE_UNLOCK_W;
    return status;
}

MOC_EXTERN void
IKE_redirectTimerExpiry(void *cookie, ubyte *type)
{
    MOC_UNUSED(cookie);
    MOC_UNUSED(type);

    g_ikeRedirectCount = 0;
    return;
}

#endif

#else
static void
dummy(void)
{
    return;
}
#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */

