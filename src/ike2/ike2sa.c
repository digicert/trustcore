/**
 * @file  ike2sa.c
 * @brief IKEv2 IKEv2 Security Association Management
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
#if defined(__IKE_SADB_MALLOC__)
#ifdef __IKE_SADB_MEMPOOL__
#error "Must not define both __IKE_SADB_MALLOC__ and __IKE_SADB_MEMPOOL__!"
#endif
#include "../common/dynarray.h"
#elif defined(__IKE_SADB_MEMPOOL__)
#include "../common/mem_pool.h"
#endif
#include "../crypto/dh.h"
#include "../crypto/crypto.h"
#include "../crypto/ca_mgmt.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#ifdef __ENABLE_DIGICERT_PFKEY__
#include "../pfkey/pfkey.h"
#endif
#if defined(__IKE_UPDATE_TIMER__) || defined(__ENABLE_IKE_REDIRECT__)
#include "../common/timer.h"
#endif

#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsecconf.h"
#include "../ipsec/ipseckey.h"

#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ike_crypto.h"
#include "../ike/ikesa.h"
#include "../ike/ike_event.h"
#include "../ike/ike_state.h"
#include "../ike/ike_utils.h"
#include "../ike/ike_status.h"
#include "../ike/ike_cert.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_dh.h"
#include "../crypto_interface/crypto_interface_ecc.h"
#endif

#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
#include "../eap/eap.h"
#include "../ike2/ike2_eap.h"


/*------------------------------------------------------------------*/

extern ubyte4 g_ikeEapInstId; /* EAP instance */
#endif

MOC_EXTERN_DATA_DECL moctime_t gStartTime;

extern ikeSettings m_ikeSettings;

#ifdef __IKE_UPDATE_TIMER__
extern ubyte *m_ikeTimer;
#endif

extern ubyte4 g_ikeScrtVerID;
extern sbyte  g_ikeSecret[];
extern sbyte4 g_ikeScrtLen;

extern IKE_MUTEX g_ikeMtx;


/*------------------------------------------------------------------*/

extern sbyte4 m_ikeSaNum;

#ifndef __IKE_SADB_MALLOC__
extern struct ikesa m_ikeSa[IKE_SA_MAX];

#define GET_NEXT_ELEMENT(_el, _i) _el = &(m_ikeSa[_i]);

#ifdef __IKE_SADB_MEMPOOL__
extern poolHeaderDescr ikePoolHdrDescr;

#ifdef __IKE_MULTI_THREADED__
extern RTOS_MUTEX m_ikePoolLock;
#define LOCK_POOL(_st)  if (OK <= (_st = RTOS_mutexWait(m_ikePoolLock)))
#define UNLOCK_POOL     RTOS_mutexRelease(m_ikePoolLock);
#else
#define LOCK_POOL(_st)
#define UNLOCK_POOL
#endif

#define PUSH_ELEMENT(_el) \
    { \
        MSTATUS st; \
        LOCK_POOL(st) \
        { \
            if (OK > (st = MEM_POOL_putPoolObject(&ikePoolHdrDescr, (void**)&_el))) \
            { \
                DEBUG_ERROR(DEBUG_IKE_MESSAGES, \
                    (sbyte *)"MEM_POOL_putPoolObject() returns error ", st); \
            } \
            UNLOCK_POOL \
        } \
    }

#else
#define PUSH_ELEMENT(_el) /* nothing to be done.*/
#endif

#else

extern DynArray m_ikeSa;

#define GET_NEXT_ELEMENT(_el, _i) \
    if (OK > DYNARR_Get(&m_ikeSa, _i, &(_el))) break;\
    if (NULL == _el) continue;

#define PUSH_ELEMENT(_el)  /* nothing to be done.*/

#endif /* __IKE_SADB_MALLOC__ */

#ifdef __IKE_MULTI_THREADED__
extern RTOS_RWLOCK m_ikeSaRwLock;
#endif


/*------------------------------------------------------------------*/

#define _I 0
#define _R 1

#define DBG_ERRCODE(_s) debug_print_status((sbyte *)__FILE__, __LINE__, (sbyte4)_s);
#define DBG_STATUS      DBG_ERRCODE(status)
#define DBG_EXIT        { DBG_STATUS goto exit; }


/*------------------------------------------------------------------*/

#ifndef __IKE_UPDATE_TIMER__

extern MSTATUS
IKE2_updateSa(IKESA pxSa)
{
    MSTATUS status = OK;

    ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
    ubyte4 m_timeoutDpd;
#ifndef CUSTOM_IKE_GET_DPD_TIMEOUT
    #define timeoutDpd m_timeoutDpd
#endif
    ubyte4 timewaitRetx = m_ikeSettings.ikeWaitRetransmit;

#ifdef __ENABLE_IPSEC_NAT_T__
    intBoolean bKeepalive;
#endif

    IKE_LOCK_R;

#ifdef __IKE_MULTI_THREADED__
    RTOS_rwLockWaitR(m_ikeSaRwLock);
#endif
    if (!(IS_VALID(pxSa) && IS_IKE2_SA(pxSa)))
    {
#ifdef __IKE_MULTI_THREADED__
        RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
        goto exit;
    }

#ifdef __IKE_MULTI_THREADED__
    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* relay this call to the proper thread */
        if (m_ikeSettings.funcPtrIkeThreadSend)
        {
            ubyte4 size = sizeof(struct dpcStateCB);
            struct dpcStateCB us;
            us.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcUpdateSa;
            us.hdr.dpc_len = (ubyte2)size;
            us.version = 2;
            us.data = pxSa;
            status = (MSTATUS)
            m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid, (ubyte *)&us, size);
        }
        else
        {
            status = ERR_IKE_CONFIG;
        }
        RTOS_rwLockReleaseR(m_ikeSaRwLock);
        goto exit;
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
        {
            ubyte4 j, warning;
            ubyte4 warning_cacPin;
            intBoolean bNoReq = TRUE, bNoResp = TRUE;

            ubyte4 timereq = 0;
            ubyte4 timeidled = timenow - pxSa->dwTimeStamp;
#ifdef CUSTOM_IKE_GET_DPD_TIMEOUT
            ubyte4 timeoutDpd = 0;
#endif
            ubyte4 timeout = 1000 * pxSa->ikePeerConfig->ikeTimeoutNegotiation;

            if (IKE_SA_FLAG_DELETING & pxSa->flags)
                goto retransmit;

            if (IKE_SA_FLAG_REKEYED & pxSa->flags)
                goto retransmit;

            if (IKE_checkExpSa(timenow, pxSa))
            {
                IKE2_delSa(pxSa, TRUE, OK);
                goto exit;
            }

retransmit:
            for (j = pxSa->u.v2.dwWndLen[_I]; 0 != j; j--) /* request(s) */
            {
                IKE2XG pxXg = &(pxSa->u.v2.pxXg[_I][j-1]);
                if (!IS_VALID_XCHG(pxXg))
                {
                    if (IKE_XCHG_FLAG_INUSE & pxXg->x_flags)
                         goto pre_dpd;
                    continue;
                }

                if (timeout < (timenow - pxXg->dwTimeStart)) /* expired */
                {
                    IKE2_delXchg(pxXg, pxSa, ERR_IKE_TIMEOUT); /* delete it */
                    timereq = timenow; /* !!! */
                    goto pre_dpd;
                }

                if (!(IKE_XCHG_FLAG_PENDING & pxXg->x_flags) &&
                    (timewaitRetx < (timenow - pxXg->dwTimeStamp)))
                {
                    struct ike_context ctx = { NULL };
                    ctx.pxSa = pxSa;
                    ctx.pxXg = pxXg;
                    status = IKE2_xchgOut(&ctx);
                }

                bNoReq = FALSE;
                continue;

pre_dpd:
                if (bNoReq &&
                    ((IKE_XCHG_INFO == pxXg->oExchange) ||
                     (IKE_XCHG_CHILD == pxXg->oExchange)))
                {
                    if (!timereq ||
                        (timenow - timereq) > (timenow - pxXg->dwTimeStamp))
                        timereq = pxXg->dwTimeStamp;
                }
            } /* for */

            for (j = pxSa->u.v2.dwWndLen[_R]; 0 != j; j--) /* response(s) */
            {
                IKE2XG pxXg = &(pxSa->u.v2.pxXg[_R][j-1]);
                if (IS_VALID_XCHG(pxXg))
                {
                    if (timeout < (timenow - pxXg->dwTimeStart)) /* expired */
                        IKE2_delXchg(pxXg, pxSa, OK/*!!!*/); /* delete it */
                    else
                        bNoResp = FALSE;
                }
            }

            if (IKE_SA_FLAG_DELETING & pxSa->flags)
            {
                /* permanently delete if no exchanges exist */
                if (bNoReq && bNoResp)
                    IKE2_delSa(pxSa, FALSE, OK);

                goto exit; /* !!! */
            }

            if (IKE_SA_FLAG_REKEYED & pxSa->flags)
            {
                /* delete if no pending requests exist */
                if (bNoReq)
                {
                    if (IS_INITIATOR(pxSa) || /* responder waits a little more */
                        (timeout < (timenow - pxSa->dwTimeStamp)))
                    {
                        IKE2_delSa(pxSa, TRUE, OK);
                    }
                    goto exit;
                }
            }

            if (!IS_IKE2_SA_AUTHED(pxSa)) goto exit;

#ifdef __ENABLE_IPSEC_NAT_T__
            bKeepalive = m_ikeSettings.ikeIntervalKeepalive &&
                         ((timenow - pxSa->dwTimeStampOut) > (ubyte4)
                          (1000 * m_ikeSettings.ikeIntervalKeepalive));

            /* send NAT-T Keepalive's */
            if (bKeepalive && IS_HOST_BEHIND_NAT(pxSa))
            {
                if (m_ikeSettings.funcPtrIkeXchgSend) /* jic */
                {
                    ubyte b = 0xFF;
                    m_ikeSettings.
                        funcPtrIkeXchgSend(REF_MOC_IPADDR(pxSa->dwPeerAddr), pxSa->wPeerPort,
                                           (ubyte *)&b, sizeof(ubyte)
                                           MOC_MTHM_REQ_VALUE(pxSa->serverInstance),
                                           TRUE);
                    pxSa->dwTimeStampOut = timenow;
                }
            }
#endif
            /* Repeated Auth (rfc4478) */
            if (IKE_SA_FLAG_REAUTH & pxSa->flags)
                goto exit; /* !!! */

            if (pxSa->u.v2.dwExpAuthSecs &&
                (IKE_SA_FLAG_ORIG_INITR & pxSa->flags)) /* must be original initiator */
            {
                warning = (ubyte4)(1000 * m_ikeSettings.ikeTimeoutEvent); /* enough time to initiate */

                if (((timenow - pxSa->u.v2.dwTimeAuthed) + warning) >
                    (ubyte4)(pxSa->u.v2.dwExpAuthSecs * 1000))
                {
                    pxSa->flags |= IKE_SA_FLAG_REAUTH;

                    /* should start new IKE_SA_INIT exchange */
                    if (m_ikeSettings.funcPtrIkeStatHdlr)
                    {
                        m_ikeSettings.funcPtrIkeStatHdlr(ISC_SA, IST_REAUTH,
                                                         pxSa->dwId, pxSa, NULL);
                        /* TODO: Trigger rekeying child IPsec SA's */
                    }
                    goto exit; /* !!! */
                }

                /* get the cac pin 1 min before re-authentication */
                warning_cacPin = warning + 60000;

                if ((((timenow - pxSa->u.v2.dwTimeAuthed) + warning_cacPin) >
                     (ubyte4)(pxSa->u.v2.dwExpAuthSecs * 1000)) &&
                    m_ikeSettings.funcPtrIkeStatHdlr)
                {
                    m_ikeSettings.funcPtrIkeStatHdlr(ISC_SA, IST_CACPIN,
                                                     pxSa->dwId, pxSa, NULL);
                }
            }

            /* DPD */
            m_timeoutDpd = 1000 * pxSa->ikePeerConfig->ikeTimeoutDpd;
#ifdef CUSTOM_IKE_GET_DPD_TIMEOUT
            if (OK <= CUSTOM_IKE_GET_DPD_TIMEOUT(&timeoutDpd,
                                REF_MOC_IPADDR(pxSa->dwPeerAddr),
                                0, IS_INITIATOR(pxSa)
                                MOC_MTHM_REQ_VALUE(pxSa->serverInstance)))
                timeoutDpd = 1000 * timeoutDpd;
            else
                timeoutDpd = m_timeoutDpd;
#endif
            if (bNoReq && timeoutDpd && (timeoutDpd < timeidled))
            {
                if (timenow == timereq) /* dead peer detected */
                {
                    if (!(pxSa->flags & IKE_SA_FLAG_DPD)) /* not declared dead yet */
                    {
                        pxSa->flags |= IKE_SA_FLAG_DPD;

                        if (!(pxSa->flags & IKE_SA_FLAG_REKEYED)) /* !!! */
                        {
                            if (m_ikeSettings.funcPtrIkeStatHdlr)
                                m_ikeSettings.funcPtrIkeStatHdlr(ISC_SA, IST_DPD,
                                                        pxSa->dwId, pxSa, NULL);
                        }
                    }
                }
                else /* send (empty) request msg */
                {
                    ubyte4 timewait = timeoutDpd;

                    if (pxSa->flags & IKE_SA_FLAG_DPD) /* already declared dead */
                    {
                        timewait = timeoutDpd + (ubyte4)
                                   ((timeidled - timeoutDpd) / 5);
                        if ((ubyte4)1800000 < timewait)
                            timewait = (ubyte4)1800000; /* max 30 mins */
                    }

                    if (!timereq || ((timenow - timereq) >= timewait))
                    {
                        IKE2XG pxXg;
                        if (OK > (status = IKE2_newXchg(pxSa, IKE_XCHG_INFO, 0, TRUE, &pxXg)))
                        {
                            /* jic - unlikely though */
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
                            status = IKE2_xchgOut(&ctx);
                        }
                    }
                }

                goto exit; /* !!! */
            } /* End of DPD */

            /* auto. rekeying */
            if ((IKE_SA_FLAG_ORIG_INITR & pxSa->flags) && /* !!! */
                !(IKE_SA_FLAG_REKEYED & pxSa->flags))
            {
                ubyte4 dwTimeStartRekey = 0;
                IKESA pxSaRekey = pxSa->pxSaRekey;
                if (pxSaRekey)
                {
#ifdef __IKE_MULTI_THREADED__
                    RTOS_rwLockWaitR(m_ikeSaRwLock);
#endif
                    if ((IKE_SA_FLAG_INUSE & pxSaRekey->flags) &&
                        (pxSaRekey->dwId0 == pxSa->dwId0))
                    {
                        if (!(IKE_SA_FLAG_DELETED & pxSaRekey->flags)) /* being rekeyed */
                        {
#ifdef __IKE_MULTI_THREADED__
                            RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
                            goto exit;
                        }
                        dwTimeStartRekey = pxSaRekey->dwTimeStart;
                    }
                    else pxSaRekey = NULL;
#ifdef __IKE_MULTI_THREADED__
                    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
                }

                if ((timeoutDpd && (timeidled > timeoutDpd)) ||
                    ((pxSa->dwTimeStamp - pxSa->dwTimeStart) < timeout))
                {
                    /* idle or no interesting activity */
                    goto exit;
                }

                if (pxSa->dwExpSecs)
                {
                    ubyte4 timeexp = 1000 * pxSa->dwExpSecs;
                    ubyte4 timedlt = timenow - pxSa->dwTimeCreated;

                    warning = timeout * 3;

                    if ((timedlt > (ubyte4)(timeexp/2)) && /* old enough */
                        (timeexp < (timedlt + warning))) /* expiring soon */
                    {
                        /* wait a litte from last rekey attempt */
                        if (!pxSaRekey ||
                            ((timenow - dwTimeStartRekey) >= timeout))
                        {
                            goto rekey;
                        }
                    }
                }

                if (pxSa->dwExpKBytes)
                {
                    warning = 6; /* 6K - FOR NOW */
                    if ((pxSa->dwCurKBytes > (ubyte4)(pxSa->dwExpKBytes/2)) && /* old enough */
                        ((pxSa->dwExpKBytes < (pxSa->dwCurKBytes + warning)) || /* expiring soon */
                         (pxSa->dwCurKBytes > (pxSa->dwCurKBytes + warning)))) /* jic KBytes wraps back to 0 */
                    {
                        /* wait a litte from last rekey attempt */
                        if (!pxSaRekey ||
                            ((timenow - dwTimeStartRekey) >= 300000)) /* ~5mins */
                        {
                            goto rekey;
                        }
                    }
                }

                goto exit;
rekey:
                /* new IKE_SA */
                if (NULL != (pxSaRekey = IKE2_newSa(pxSa->ikePeerConfig, REF_MOC_IPADDR(pxSa->dwPeerAddr),
                                                    pxSa->wPeerPort, NULL, pxSa
                                                    MOC_NATT_VALUE(USE_NATT_PORT(pxSa))
                                                    MOC_MTHM_VALUE(pxSa->serverInstance))))
                {
                    /* new REKEY_SA exchange */
                    IKE2XG pxXg;
                    if (OK > (status = IKE2_newXchg(pxSa, IKE_XCHG_CHILD, 0, TRUE, &pxXg)))
                    {
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
                        status = IKE2_xchgOut(&ctx);
                    }
                }

            } /* END of auto. rekeying */
        }

exit:
    IKE_UNLOCK_R;
    return status;
} /* IKE2_updateSa */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE2_updateSadb(void)
{
    MSTATUS status = OK;

    sbyte4 i;
    ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
    static ubyte4 timethen0 = 0;

    /* regenerate Notify COOKIE secret */
    if ((timenow - timethen0) > (ubyte4)300000) /* every ~5 minutes - for now */
    {
        timethen0 = timenow;
        RANDOM_numberGenerator(g_pRandomContext, (ubyte *)g_ikeSecret, g_ikeScrtLen);
        g_ikeScrtVerID++;
    }

    for (i=0; i < m_ikeSaNum; i++)
    {
        IKESA pxSa;
        GET_NEXT_ELEMENT(pxSa, i)

        status = IKE2_updateSa(pxSa);
    }

    return status;
} /* IKE2_updateSadb */

#endif /* !__IKE_UPDATE_TIMER__ */


/*------------------------------------------------------------------*/

extern IKESA
IKE2_newSa(ikePeerConfig* config, MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort,
           ubyte *poCky, IKESA pxSa0
           MOC_NATT(bUseNattPort)
           MOC_MTHM(serverInstance))
{
    IKESA pxSa = NULL;

    intBoolean bInitiator = ((NULL == poCky) ? TRUE : FALSE);
    sbyte4 i;

    MSTATUS status;
    if (OK > (status = IKE_allocSa(config, peerAddr, wPeerPort, poCky,
                                   &pxSa, pxSa0, 2
                                   MOC_NATT_VALUE(bUseNattPort)
                                   MOC_MTHM_VALUE(serverInstance))))
    {
        pxSa = NULL; /* jic */
        goto exit;
    }

    /* initialize */
    pxSa->oState = (bInitiator ? STATE_MAIN_I1 : STATE_MAIN_R1);

    if (!pxSa0) /* IKE_SA_INIT */
    {
        pxSa->u.v2.dwWndLen[bInitiator ? _I : _R] = 1;

        if (bInitiator) pxSa->flags |= IKE_SA_FLAG_ORIG_INITR;
        else /* Rep Auth (original responder) */
        {
            ubyte4 dwExpAuthSecs =
            pxSa->u.v2.dwExpAuthSecs = config->ikeReauthSecs;
            if (dwExpAuthSecs)
            {
                if ((ubyte4)300 > dwExpAuthSecs)
                    pxSa->u.v2.dwExpAuthSecs = 300;
                else if ((ubyte4)86400 < dwExpAuthSecs)
                    pxSa->u.v2.dwExpAuthSecs = 86400;
            }
        }
    }
    else /* REKEY_SA */
    {
#if defined(__ENABLE_IKE_CP__)
        intBoolean bInitiator0 = (IS_INITIATOR(pxSa0) ? TRUE : FALSE);
#endif
        /* inherit parent attributes */
#ifdef __ENABLE_IPSEC_NAT_T__
        if (IKE_NATT_FLAG_D & pxSa0->natt_flags)
        {
            pxSa->natt_flags |= IKE_NATT_FLAG_D;
            if (IS_HOST_BEHIND_NAT(pxSa0)) SET_HOST_BEHIND_NAT(pxSa)
            if (IS_PEER_BEHIND_NAT(pxSa0)) SET_PEER_BEHIND_NAT(pxSa)
#ifdef __ENABLE_MOBIKE__
            if (IKE_NATT_FLAG_NOT_ALLOWED & pxSa0->natt_flags)
                pxSa->natt_flags |= IKE_NATT_FLAG_NOT_ALLOWED;
#endif
        }
#endif
        pxSa->u.v2.dwTimeAuthed = pxSa0->u.v2.dwTimeAuthed;
        pxSa->u.v2.dwExpAuthSecs = pxSa0->u.v2.dwExpAuthSecs;

#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
        pxSa->u.v2.eapState.proto = pxSa0->u.v2.eapState.proto;
#endif
#ifdef __ENABLE_MOBIKE__
        if (IKE_SA_FLAG_MOBILE & pxSa0->flags)
            pxSa->flags |= IKE_SA_FLAG_MOBILE;
#endif
        if (IKE_SA_FLAG_ORIG_INITR & pxSa0->flags)
            pxSa->flags |= IKE_SA_FLAG_ORIG_INITR;

#ifdef __ENABLE_IKE_FRAGMENTATION__
        if (IKE_SA_FLAG_FRAGMENTATION & pxSa0->flags)
        {
            pxSa->flags |= IKE_SA_FLAG_FRAGMENTATION;
            pxSa->maxSkBodyLen[0] = pxSa0->maxSkBodyLen[0];
            pxSa->maxSkBodyLen[1] = pxSa0->maxSkBodyLen[1];
        }
#endif
#if defined(__ENABLE_IKE_CP__)
        for (i=0; i <= 1; i++)
        {
            sbyte4 j = (bInitiator == bInitiator0) ? i : !i;
#ifdef __ENABLE_IKE_CP__
            struct ikeIdHdr *pxIdHdr = pxSa0->pxID[i];
            if (pxIdHdr) /* jic */
            {
                ubyte2 wIdLen = GET_NTOHS(pxIdHdr->wLength);
                if (NULL == (pxSa->pxID[j] = (struct ikeIdHdr *) MALLOC(wIdLen)))
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }
                DIGI_MEMCPY(pxSa->pxID[j], pxIdHdr, wIdLen);
            }
#endif
        } /* for */
#endif /* defined(__ENABLE_IKE_CP__) */
    }

    if (bInitiator)
    {
        pxSa->oPpsNo = 2;

        /* set DH group */
        if (!pxSa0) /* IKE_SA_INIT */
        {
#ifdef CUSTOM_IKE_GET_P1_DHGRP
            if (0 < pxSa->numDhGrps)
            {
                pxSa->wDhGrp = pxSa->pwDhGrps[0];
            }
            else
#endif
            if (0 == (pxSa->wDhGrp = config->ikeP1DHgroup))
            {
                /* find default DH group */
                for (i=0; ; i++)
                {
                    IKE_dhGroupInfo *pDhGroup = IKE_getDhGroupEx(config, i);
                    if (!pDhGroup) break;

                    if (!pDhGroup->bDisabled[1][_I] &&
                        (0 != (pxSa->wDhGrp = pDhGroup->wTfmId)))
                        break; /* found */
                }
            }
            else
            {
                pxSa->dhGrpSet = TRUE;
            }
        }
        else /* REKEY_SA */
        {
#ifdef CUSTOM_IKE_GET_P2_PFS
            if (0 < pxSa->numDhGrps)
            {
                pxSa->wDhGrp = pxSa->pwDhGrps[0];
            }
            else
#endif
            if ((OAKLEY_GROUP_DEFAULT == (pxSa->wDhGrp = config->ikeP2PFS)) ||
                (0 == pxSa->wDhGrp)) /* PFS is required [RFC7296][RFC5996] 1.3.2 */
            {
                pxSa->wDhGrp = pxSa0->wDhGrp; /* use old IKE_SA's DH group */
            }
        }

        /* set lifetime */
#ifdef CUSTOM_IKE_GET_P1_LIFESECS
        if (OK > CUSTOM_IKE_GET_P1_LIFESECS(&pxSa->dwExpSecs,
                                peerAddr, _I, TRUE
                                MOC_MTHM_REQ_VALUE(serverInstance)))
#endif
        pxSa->dwExpSecs = config->ikeP1LifeSecs;

#ifdef CUSTOM_IKE_GET_P1_LIFEKBYTES
        if (OK > CUSTOM_IKE_GET_P1_LIFEKBYTES(&pxSa->dwExpKBytes,
                                peerAddr, _I, TRUE
                                MOC_MTHM_REQ_VALUE(serverInstance)))
#endif
        pxSa->dwExpKBytes = config->ikeP1LifeKBytes;
    }
    else /* responder */
    {
#ifdef CUSTOM_IKE_GET_P1_LIFESECS
        CUSTOM_IKE_GET_P1_LIFESECS(&pxSa->dwExpSecs,
                                peerAddr, _R, FALSE
                                MOC_MTHM_REQ_VALUE(serverInstance));
#endif
#ifdef CUSTOM_IKE_GET_P1_LIFEKBYTES
        CUSTOM_IKE_GET_P1_LIFEKBYTES(&pxSa->dwExpKBytes,
                                peerAddr, _R, FALSE
                                MOC_MTHM_REQ_VALUE(serverInstance));
#endif
    }

    /* adjust lifetime */
    if (0 == pxSa->dwExpSecs)
        pxSa->dwExpSecs = config->ikeP1LifeSecsMax;

    if (IKE_LIFE_SECS_MAX < pxSa->dwExpSecs)
        pxSa->dwExpSecs = IKE_LIFE_SECS_MAX;

    if (0 == pxSa->dwExpKBytes)
        pxSa->dwExpKBytes = config->ikeP1LifeKBytesMax;

exit:
    if ((OK > status) && (NULL != pxSa))
    {
        IKE2_delSa(pxSa, FALSE, status);
        pxSa = NULL;
    }
    return pxSa;
} /* IKE2_newSa */


/*------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_SP800_135_ACVP__
extern void
#else
static void
#endif
FreeSa(IKESA pxSa)
{
    sbyte4 i;
    for (i=_I; i <= _R; i++)
    {
        if (pxSa->poMsg[i])
        {
            FREE(pxSa->poMsg[i]);
            pxSa->poMsg[i] = NULL;
        }
        pxSa->dwMsgLen[i] = 0;

        if (pxSa->poNonce[i])
        {
            if (pxSa->poNonce[i] != pxSa->nonce)
                FREE(pxSa->poNonce[i]);
            pxSa->poNonce[i] = NULL;
        }
        pxSa->wNonceLen[i] = 0;

#ifndef __ENABLE_IKE_CP__
        if (pxSa->pxID[i])
        {
            FREE(pxSa->pxID[i]);
            pxSa->pxID[i] = NULL;
        }
#endif
    }

    if (pxSa->p_dhContext)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DH_freeDhContextExt(&(pxSa->p_dhContext), NULL, NULL);
#else
        DH_freeDhContext(&(pxSa->p_dhContext), NULL);
#endif
    }


#ifdef __ENABLE_DIGICERT_ECC__
    if (pxSa->p_eccKey)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_EC_deleteKeyAux(&(pxSa->p_eccKey));
#else
        EC_deleteKey(&(pxSa->p_eccKey));
#endif
    }

    if (pxSa->poEccSharedSecret)
    {
        DIGI_MEMSET(pxSa->poEccSharedSecret, 0x00, pxSa->eccSharedSecretLen);
        FREE(pxSa->poEccSharedSecret);
        pxSa->poEccSharedSecret = NULL;
        pxSa->eccSharedSecretLen = 0;
    }
#endif

#ifdef __ENABLE_DIGICERT_PQC__
    if (NULL != pxSa->pQsCtx)
    {
        CRYPTO_INTERFACE_QS_deleteCtx(&(pxSa->pQsCtx));
    }

    if (NULL != pxSa->pQsCipherText)
    {
        DIGI_MEMSET(pxSa->pQsCipherText, 0x00, pxSa->qsCipherTextLen);
        FREE(pxSa->pQsCipherText);
        pxSa->pQsCipherText = NULL;
        pxSa->qsCipherTextLen = 0;
    }

    if (NULL != pxSa->pQsSharedSecret)
    {
        DIGI_MEMSET(pxSa->pQsSharedSecret, 0x00, pxSa->qsSharedSecretLen);
        FREE(pxSa->pQsSharedSecret);
        pxSa->pQsSharedSecret = NULL;
        pxSa->qsSharedSecretLen = 0;
    }
#endif

    if (NULL != pxSa->pDhPeerPubKey)
    {
        FREE(pxSa->pDhPeerPubKey);
        pxSa->pDhPeerPubKey = NULL;
        pxSa->dhPeerPubKeyLen = 0;
    }

    if (NULL != pxSa->pDhSharedSecret)
    {
        DIGI_MEMSET(pxSa->pDhSharedSecret, 0, pxSa->dhSharedSecretLen);
        FREE(pxSa->pDhSharedSecret);
        pxSa->pDhSharedSecret = NULL;
        pxSa->dhSharedSecretLen = 0;
    }


#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    {
        IKE2EAP pxEap = &pxSa->u.v2.eapState;

        if (pxEap->pEapSuite)
        {
            if (pxEap->pEapSuite->delFunc)
                pxEap->pEapSuite->delFunc(pxEap);
            pxEap->pEapSuite = NULL;
        }
        if (pxEap->pSession)
        {
            EAP_sessionDelete(pxEap->pSession, g_ikeEapInstId);
            pxEap->pSession = NULL;
        }
        if (pxEap->pCbData)
        {
            FREE(pxEap->pCbData);
            pxEap->pCbData = NULL;
        }
        if (pxEap->pxMsg)
        {
            FREE(pxEap->pxMsg);
            pxEap->pxMsg = NULL;
        }
        if (pxEap->poMsk)
        {
            FREE(pxEap->poMsk);
            pxEap->poMsk = NULL;
        }
        pxEap->dwMskLen = 0;

        pxEap->pxSa = NULL;
        pxEap->pxXg = NULL;
    }
#endif

#if defined(__ENABLE_IKE_MULTI_AUTH__) || \
    (defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__))
    if (pxSa->u.v2.pxIPsecSa)
    {
        IKE_delIPsecSa(pxSa->u.v2.pxIPsecSa, pxSa);
        FREE(pxSa->u.v2.pxIPsecSa);
        pxSa->u.v2.pxIPsecSa = NULL;
    }
    if (pxSa->u.v2.poSAi2)
    {
        FREE(pxSa->u.v2.poSAi2);
        pxSa->u.v2.poSAi2 = NULL;
    }
#ifdef __ENABLE_IKE_CP__
    if (pxSa->u.v2.poCp)
    {
        FREE(pxSa->u.v2.poCp);
        pxSa->u.v2.poCp = NULL;
    }
#endif
#endif

#if defined(CUSTOM_IKE_GET_P1_DHGRP) || defined(CUSTOM_IKE_GET_P2_PFS)
    if (pxSa->pwDhGrps)
    {
        FREE(pxSa->pwDhGrps);
        pxSa->pwDhGrps = NULL;
        pxSa->numDhGrps = 0;
    }
#endif

#ifdef CUSTOM_IKE_GET_HASH_ALGO
    if (pxSa->pwHashAlgos)
    {
        FREE(pxSa->pwHashAlgos);
        pxSa->pwHashAlgos = NULL;
        pxSa->numHashAlgos = 0;
    }
#endif

#ifdef CUSTOM_IKE_GET_INTEG_ALGO
    if (pxSa->pwMacAlgos)
    {
        FREE(pxSa->pwMacAlgos);
        pxSa->pwMacAlgos = NULL;
        pxSa->numMacAlgos = 0;
    }
#endif

#ifdef CUSTOM_IKE_GET_ENCR_ALGO
    if (pxSa->pwEncrAlgos)
    {
        FREE(pxSa->pwEncrAlgos);
        pxSa->pwEncrAlgos = NULL;
        FREE(pxSa->pwEncrKeyLens);
        pxSa->pwEncrKeyLens = NULL;
        pxSa->numEncrAlgos = 0;
    }
#endif

    if (pxSa->pCertChain)
    {
        if (pxSa->ikePeerConfig->ikeCertChain != pxSa->pCertChain)
        {
            IKE_certUnsetChain(pxSa->pCertChain, pxSa->certChainLen);
            FREE(pxSa->pCertChain);
        }
        pxSa->pCertChain = NULL;
        pxSa->certChainLen = 0;
    }

    return;
} /* FreeSa */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE2_delSa(IKESA pxSa, intBoolean bInfo, MSTATUS merror)
{
    MSTATUS status = OK;

    ubyte4 i;

#ifndef __IKE_MULTI_THREADED__
    /* Protection against race conditions between IKE threads and timer thread */
    intBoolean bIsMutexLocked;
#endif

#ifndef __IKE_MULTI_THREADED__
    /* Protection against race conditions between IKE threads and timer thread */
    IKE_AUTO_LOCK(bIsMutexLocked);
#endif

    if (!pxSa || !IS_VALID(pxSa)) goto exit; /* jic */

    if (merror && !pxSa->merror)
        pxSa->merror = merror;

    /* first remove all child exchanges initiated by us */
    for (i = pxSa->u.v2.dwWndLen[_I]; i != 0; i--)
    {
        IKE2XG pxXg = &(pxSa->u.v2.pxXg[_I][i-1]);
        if (IS_VALID_XCHG(pxXg))
            /*status = */IKE2_delXchg(pxXg, pxSa, pxSa->merror);
    }

    if (IS_IKE2_SA_AUTHED(pxSa))
    {
        if (IKE_SA_FLAG_DELETING & pxSa->flags)
        {
            pxSa->flags &= ~IKE_SA_FLAG_DELETING;
        }
        else if (bInfo)
        {
            /* send delete payload in an informational exchange message */
            IKE2XG pxXg = NULL;
            IKEINFO_delete pDel = (IKEINFO_delete)
                                    MALLOC(sizeof(struct ike_info_delete));
            if (!pDel)
            {
                status = ERR_MEM_ALLOC_FAIL;
            }
            else if (OK > (status = IKE2_newXchg(pxSa, IKE_XCHG_INFO, 0, TRUE, &pxXg)))
            {
                FREE(pDel);
            }
            else
            {
                struct ike_context ctx = { NULL };

                pDel->oProtoId = PROTO_ISAKMP;
                pDel->dwSpi = 0;
                pDel->pxSa = NULL;
                pDel->next = NULL;

                pxXg->pxInfo->pxDelete = pDel;

                ctx.pxSa = pxSa;
                ctx.pxXg = pxXg;

                status = IKE2_xchgOut(&ctx);
            }

            if (OK <= status)
            {
                pxSa->flags |= IKE_SA_FLAG_DELETING;
                goto exit;
            }
        }
    }

    if (m_ikeSettings.funcPtrIkeStatHdlr)
    {
        m_ikeSettings.funcPtrIkeStatHdlr(ISC_SA,
            (IS_IKE2_SA_AUTHED(pxSa)? IST_DELETED : IST_FAIL),
            pxSa->dwId, pxSa, NULL);
    }

    for (i = pxSa->u.v2.dwWndLen[_R]; i != 0; i--)
    {
        IKE2XG pxXg = &(pxSa->u.v2.pxXg[_R][i-1]);
        if (IS_VALID_XCHG(pxXg))
            status = IKE2_delXchg(pxXg, pxSa, pxSa->merror);
    }

#ifdef __ENABLE_IKE_CP__
    for (i=_I; i <= _R; i++)
    {
        if (pxSa->pxID[i])
        {
            FREE(pxSa->pxID[i]);
            pxSa->pxID[i] = NULL;
        }
    }
#endif
#ifdef __IKE_UPDATE_TIMER__
    for (i=0; i < IKESA_TIMER_MAX; i++)
    {
        IKE_DEL_TIMER_EVT(pxSa->timerIDs[i], pxSa->timerHdls[i])
    }
#endif
#ifdef __ENABLE_IKE_REDIRECT__
    if (NULL != pxSa->redirectTimerId)
    {
        TIMER_destroyTimer(pxSa->redirectTimerId);
        pxSa->redirectTimerId = NULL;
    }
#endif
    FreeSa(pxSa);
    pxSa->flags |= IKE_SA_FLAG_DELETED;

    PUSH_ELEMENT(pxSa)
    /* Note: pxSa is *not* removed from hashtables! */

exit:
#ifndef __IKE_MULTI_THREADED__
    /* Protection against race conditions between IKE threads and timer thread */
    if (FALSE == bIsMutexLocked) 
    {
        IKE_AUTO_UNLOCK;
    }
#endif
    return status;
} /* IKE2_delSa */


/*------------------------------------------------------------------*/

#ifdef __IKE_MULTI_THREADED__
#define DPC2_DELSA(_gl, _sas, _sa, _b, _m) \
if (FALSE == _gl) \
{ \
    if (TRUE == RTOS_sameThreadId((_sa)->tid, RTOS_currentThreadId())) \
    { \
        (_sa)->pNext = _sas; \
        _sas = _sa; \
    } \
    else \
    { \
        /* relay this call to the proper thread */ \
        if (m_ikeSettings.funcPtrIkeThreadSend) \
        { \
            struct dpcDelSa ds; \
            ds.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcDelSa; \
            ds.hdr.dpc_len = (ubyte2)sizeof(ds); \
            ds.pxSa = _sa; \
            ds.dwSaId = (_sa)->dwId; \
            ds.bInfo = _b; \
            ds.merror = _m; \
            m_ikeSettings.funcPtrIkeThreadSend((_sa)->tid, \
                                        (ubyte *)&ds, (ubyte4)sizeof(ds)); \
        } \
    } \
} \
else \

#endif

typedef struct ikesa_fs_test
{
    IKESA pxSa;
#ifdef __IKE_MULTI_THREADED__
    IKESA pxSaDel;
    intBoolean bIsGlobalLocked;
#endif
    ubyte4 timenow;
    ubyte4 timedlt;

} *IKESA_FS_TEST;


static MSTATUS
Match2FinalizeSa(IKESA pxSaTmp, void *pData, intBoolean *pIsMatch)
{
#define pTest ((IKESA_FS_TEST)pData)
    MSTATUS status = OK;

    IKESA pxSa = pTest->pxSa;
    ubyte4 timenow = pTest->timenow;
    ubyte4 timedlt = pTest->timedlt;

    if (IS_IKE2_SA(pxSaTmp) &&
        (pxSa != pxSaTmp) &&
#ifdef __ENABLE_IPSEC_NAT_T__
        /* See RFC 3947 6. p.11 */
        ((pxSa->wPeerPort == pxSaTmp->wPeerPort) ||
         !(IS_PEER_BEHIND_NAT(pxSa) || IS_PEER_BEHIND_NAT(pxSaTmp))) &&
#endif
        (!timedlt || (timedlt < (timenow - pxSaTmp->dwTimeCreated))))
    {
        /* found */
        if (IS_IKE2_SA_AUTHED(pxSaTmp))
        {
            if (!((IKE_SA_FLAG_DELETING | IKE_SA_FLAG_REKEYED) & pxSaTmp->flags))
            {
                intBoolean bMature = IS_MATURE(pxSa);
                intBoolean bMatureTmp = IS_MATURE(pxSaTmp);

                if ((bMature || !bMatureTmp) &&
                    (!bMature || bMatureTmp || /* should avoid race condition btw peers */
                     ((timenow - pxSa->dwTimeStart) < (timenow - pxSaTmp->dwTimeCreated))))
                {
#ifdef __IKE_MULTI_THREADED__
                    DPC2_DELSA(pTest->bIsGlobalLocked, pTest->pxSaDel,
                               pxSaTmp, TRUE, STATUS_IKE_REKEY)
#endif
                    IKE2_delSa(pxSaTmp, TRUE, STATUS_IKE_REKEY); /* delete old IKE_SA */
                }
                else
                {
                    pxSa->flags |= IKE_SA_FLAG_NEW; /* keep old IKE_SA */
                }
            }
        }
        else if (!timedlt)
        {
            /* remove incomplete SA's */
            if (!IS_IKE2_SA_INITED(pxSaTmp) ||
                !IS_INITIATOR(pxSaTmp)
                ) /* FOR NOW */
            {
#ifdef __IKE_MULTI_THREADED__
                DPC2_DELSA(pTest->bIsGlobalLocked, pTest->pxSaDel,
                           pxSaTmp, FALSE, STATUS_IKE_REKEY)
#endif
                IKE2_delSa(pxSaTmp, FALSE, STATUS_IKE_REKEY);
            }
        }
    } /* if */

    *pIsMatch = FALSE; /* find next! */

    return status;
#undef pTest
} /* Match2FinalizeSa */


/*------------------------------------------------------------------*/

extern void
IKE2_finalizeSa(IKESA pxSa, ubyte4 timenow, IKESA pxSa0)
{
    ubyte4 timedlt = timenow - pxSa->dwTimeCreated;
    intBoolean bMature = IS_MATURE(pxSa);

    if (!timedlt)
    {
        pxSa->merror = OK;

        if (m_ikeSettings.funcPtrIkeStatHdlr)
        {
            m_ikeSettings.funcPtrIkeStatHdlr(ISC_SA, IST_SUCCESS,
                                             pxSa->dwId, pxSa, pxSa0);
        }

        FreeSa(pxSa); /* free up temp. storage 032417 */
    }

    /* find older SA's */
    if (!timedlt ||
        (bMature && (IKE_SA_FLAG_NEW & pxSa->flags)))
    {
        struct ikesa_fs_test saTest;
        saTest.pxSa = pxSa;
#ifdef __IKE_MULTI_THREADED__
        saTest.pxSaDel = NULL;
        saTest.bIsGlobalLocked = RTOS_rwLockOwnerW(g_ikeMtx);
#endif
        saTest.timenow = timenow;
        saTest.timedlt = timedlt;

        IKE_getSaByAddr(REF_MOC_IPADDR(pxSa->dwPeerAddr),
                        NULL, &saTest, Match2FinalizeSa
                        MOC_MTHM_VALUE(pxSa->serverInstance));

#ifdef __IKE_MULTI_THREADED__
        for (pxSa = saTest.pxSaDel; NULL != pxSa;)
        {
            IKESA pxSaDel = pxSa;
            pxSa = pxSa->pNext;
            IKE2_delSa(pxSaDel, (IS_IKE2_SA_AUTHED(pxSaDel) ? TRUE : FALSE),
                       STATUS_IKE_REKEY);
        }
#endif
    }

    return;
} /* IKE2_finalizeSa */


/*------------------------------------------------------------------*/

#ifdef CUSTOM_IKE_GET_P2_PFS
extern MSTATUS
IKE_customDhGroups(ubyte2 **ppwGroups, sbyte4 *num, intBoolean bInitiator,
                   IKESA pxSa, IKESA pxSa0);
#endif

extern MSTATUS
IKE2_newIPsecSa(IKESA pxSa, IKE2XG pxXg, IPSECSA *ppxIPsecSa)
{
    MSTATUS status = OK;

    intBoolean bInitiator = IS_XCHG_INITIATOR(pxXg);

    IPSECSA pxIPsecSa = (IPSECSA) MALLOC(sizeof(struct ipsecsa));
    if (!pxIPsecSa)
    {
        status = ERR_MEM_ALLOC_FAIL;
        DBG_EXIT
    }
    DIGI_MEMSET((ubyte *)pxIPsecSa, 0x00, sizeof(struct ipsecsa)); /* clean up */

    /* initialize */
    pxIPsecSa->oState = (ubyte)(bInitiator ? STATE_QUICK_I1 : STATE_QUICK_R1);
    pxIPsecSa->oP2SaNum = 1;

#ifdef CUSTOM_IKE_GET_P2_PFS
    if ((IKE_XCHG_CHILD == pxXg->oExchange) && /* CREATE_CHILD_SA only */
        (OK > (status = IKE_customDhGroups(&pxIPsecSa->pwDhGrps,
                                           &pxIPsecSa->numDhGrps,
                                           bInitiator, NULL, pxSa))))
        goto exit;
#endif

    if (bInitiator)
    {
        pxIPsecSa->c_flags |= IKE_CHILD_FLAG_INITIATOR;

    /* PFS */
        if (IKE_XCHG_CHILD == pxXg->oExchange) /* CREATE_CHILD_SA only */
        {
#ifdef CUSTOM_IKE_GET_P2_PFS
            if (0 < pxIPsecSa->numDhGrps)
            {
                pxIPsecSa->wPFS = pxIPsecSa->pwDhGrps[0];
            }
            else
#endif
            if (OAKLEY_GROUP_DEFAULT == (pxIPsecSa->wPFS =
                                            pxSa->ikePeerConfig->ikeP2PFS))
            {
                pxIPsecSa->wPFS = pxSa->wDhGrp; /* use parent IKE_SA's DH group */
            }
        }
    }

    /* nonce */
    if (bInitiator)
    {
        pxIPsecSa->poNi_b = pxIPsecSa->poNonce;
        pxIPsecSa->wNi_bLen = IKE_NONCE_SIZE;
    }
    else
    {
        pxIPsecSa->poNr_b = pxIPsecSa->poNonce;
        pxIPsecSa->wNr_bLen = IKE_NONCE_SIZE;
    }
    if (OK > (status = RANDOM_numberGenerator(g_pRandomContext, pxIPsecSa->poNonce, IKE_NONCE_SIZE)))
        DBG_EXIT

    if (pxXg->pxIPsecSa) /* jic */
    {
        IKE_delIPsecSa(pxXg->pxIPsecSa, pxSa);
        FREE(pxXg->pxIPsecSa);
        pxXg->pxIPsecSa = NULL;
    }

    /* done */
    pxIPsecSa->dwTimeStart = RTOS_deltaMS(&gStartTime, NULL);
    pxIPsecSa->c_flags |= (IKE_CHILD_FLAG_INUSE | IKE_CHILD_FLAG_V2);

    if (ppxIPsecSa) *ppxIPsecSa = pxIPsecSa;
    pxXg->pxIPsecSa = pxIPsecSa;
    pxIPsecSa = NULL;

exit:
    if (pxIPsecSa)
    {
#ifdef CUSTOM_IKE_GET_P2_PFS
        if (pxIPsecSa->pwDhGrps)
            FREE(pxIPsecSa->pwDhGrps);
#endif
        FREE(pxIPsecSa);
    }
    return status;
} /* IKE2_newIPsecSa */


/*------------------------------------------------------------------*/

#define IKE_SA_GET_XCHG(s, d, i) &((s)->u.v2.pxXg[d][((i)+dwWndIdx)%dwWndLen])

extern MSTATUS
IKE2_getXchg(IKESA pxSa, ubyte4 dwMsgId,
             intBoolean bRequest, /* we initiate the exchange? */
             IKE2XG *ppxXg)
{
    /* NOTE: called by IKE2_xchgIn() only; i.e. inbound exchange message */
    MSTATUS status = ERR_IKE_BAD_MSGID;

    IKE2XG pxXg = NULL;
    sbyte4 dir = (bRequest ? _I : _R);

    ubyte4 dwMsgIdCur = pxSa->u.v2.dwMsgId[dir];
    ubyte4 dwWndLen = pxSa->u.v2.dwWndLen[dir];
    ubyte4 dwWndIdx = pxSa->u.v2.dwWndIdx[dir];
    ubyte4 dwMsgIdNext = dwMsgIdCur + dwWndLen;

    /* check message ID */
    if (0 == dwWndLen)
    {
        /* IKE_SA is not yet authenticated */
        DBG_EXIT
    }

    if (dwMsgId < dwMsgIdCur)
    {
        /* old message ID */
        DBG_EXIT
    }

    if (dwMsgId < dwMsgIdNext)
    {
        /* get exchange */
        pxXg = IKE_SA_GET_XCHG(pxSa, dir, dwMsgId - dwMsgIdCur);
        if (!IS_VALID_XCHG(pxXg))
        {
            if (bRequest)
            {
                /* invalid message ID */
                DBG_EXIT
            }
            else
            {
                pxXg = NULL;
            }
        }
    }
    else
    {
        if (bRequest)
        {
            /* message ID too large in a response */
            DBG_EXIT
        }
#if 1
        else
        {
            ubyte4 off = dwMsgId - dwMsgIdNext + 1;
            if (off > dwWndLen)
            {
                /* message ID too large in a request */
                DBG_EXIT
            }
            else
            {
                ubyte4 i;
                for (i=0; i < off; i++)
                {
                    IKE2XG pxXgTmp = IKE_SA_GET_XCHG(pxSa, _R/*dir*/, i);
                    if (!IS_VALID_XCHG(pxXgTmp))
                    {
                        /* cannot advance response window yet */
                        DBG_EXIT
                    }
                }
                /* will advance response window */
            }
        }
#endif /* 1 */
    }

    if (ppxXg) /* jic */
    {
        *ppxXg = pxXg;
    }
    status = OK;

exit:
    return status;
} /* IKE2_getXchg */


/*------------------------------------------------------------------*/

#ifdef __IKE_UPDATE_TIMER__

#ifdef __IKE_MULTI_THREADED__
static void XchgExpTimerEventI(sbyte4 i, ubyte4 saId, void *sa, ubyte4 timerId);
static void XchgExpTimerEventR(sbyte4 i, ubyte4 saId, void *sa, ubyte4 timerId);

#define EXIT_SA goto exit_sa;
#else
#define EXIT_SA goto exit;
#endif

static void
DoXchgExpTimerEvent(IKESA pxSa, sbyte4 dir, sbyte4 i, ubyte4 saId, ubyte4 timerId)
{
    IKE2XG pxXg;
    ubyte4 timeoutDpd;

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

    pxXg = &(pxSa->u.v2.pxXg[dir][i]);
    if (!IS_VALID_XCHG(pxXg))
    {
        EXIT_SA
    }
    if (timerId != pxXg->expTimerId)
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
            evt.func = ((_I==dir) ? XchgExpTimerEventI : XchgExpTimerEventR);
            evt.cookie = i;
            evt.saId = saId;
            evt.sa = pxSa;
            evt.timerId = timerId;
            m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid,
                                            (ubyte *)&evt, (ubyte4)sizeof(evt));
        }
        EXIT_SA
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif

    pxXg->expTimerId = (IKE_TIMER_EVT_T)0; /* !!! */
    pxXg->expTimerHdl = (IKE_TIMER_HDL_T)NULL; /* !!! */

    IKE2_delXchg(pxXg, pxSa, ((_I==dir) ? ERR_IKE_TIMEOUT : OK)); /* delete it */

    if ((IKE_SA_FLAG_DELETING | IKE_SA_FLAG_REKEYED) & pxSa->flags)
    {
        IKE2XG pxXg1;

        /* check if there are any ongoing requests */
        for (i = pxSa->u.v2.dwWndLen[_I]; 0 != i; i--)
        {
            pxXg1 = &(pxSa->u.v2.pxXg[_I][i]);
            if (IS_VALID_XCHG(pxXg1))
            {
                goto exit; /* found */
            }
        }

        if (IKE_SA_FLAG_DELETING & pxSa->flags)
        {
            /* check if there are any lingering responses */
            for (i = pxSa->u.v2.dwWndLen[_R]; 0 != i; i--)
            {
                pxXg1 = &(pxSa->u.v2.pxXg[_R][i]);
                if (IS_VALID_XCHG(pxXg1))
                {
                    goto exit; /* found */
                }
            }

            /* permanently delete IKE_SA since no exchange exists */
            IKE2_delSa(pxSa, FALSE, OK);
        }
        else/* if (IKE_SA_FLAG_REKEYED & pxSa->flags)*/
        {
            /* delete IKE_SA since no ongoing request exists */
            if (IS_INITIATOR(pxSa))
            {
                IKE2_delSa(pxSa, TRUE, OK);
            }
            else /* responder waits a little more */
            {
                ubyte4 timeout = 1000 * pxSa->ikePeerConfig->ikeTimeoutNegotiation;
                ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
                if (timeout < (timenow - pxSa->dwTimeStamp))
                {
                    IKE2_delSa(pxSa, TRUE, OK);
                }
            }
        }

        goto exit; /* !!! */
    }

    if (_R == dir)
    {
        goto exit;
    }

    /* DPD - request only */
    if (!((IKE_XCHG_INFO == pxXg->oExchange) ||
          (IKE_XCHG_CHILD == pxXg->oExchange)))
    {
        /* authenticated only */
        goto exit;
    }

    if (IKE_SA_FLAG_DPD & pxSa->flags)
    {
        /* already declared dead */
        goto exit;
    }

#ifdef CUSTOM_IKE_GET_DPD_TIMEOUT
    if (OK <= CUSTOM_IKE_GET_DPD_TIMEOUT(&timeoutDpd,
                                         REF_MOC_IPADDR(pxSa->dwPeerAddr),
                                         0, IS_INITIATOR(pxSa)
                                         MOC_MTHM_REQ_VALUE(pxSa->serverInstance)))
    {
        timeoutDpd = 1000 * timeoutDpd;
    }
    else
#endif
    timeoutDpd = 1000 * pxSa->ikePeerConfig->ikeTimeoutDpd;

    if (timeoutDpd)
    {
        ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
        ubyte4 timeidled = timenow - pxSa->dwTimeStamp;

        if (timeidled < timeoutDpd)
        {
            /* not idle long enough */
            goto exit;
        }

        if ((timeidled - timeoutDpd) < (timenow - pxXg->dwTimeStamp))
        {
            /* exchange occurred before DPD was triggered */
            goto exit;
        }

        /* dead peer detected */
        pxSa->flags |= IKE_SA_FLAG_DPD;

        if (m_ikeSettings.funcPtrIkeStatHdlr)
        {
            m_ikeSettings.funcPtrIkeStatHdlr(ISC_SA, IST_DPD,
                                             pxSa->dwId, pxSa, NULL);
        }
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
} /* DoXchgExpTimerEvent */

static void
XchgExpTimerEventI(sbyte4 i, ubyte4 saId, void *sa, ubyte4 timerId)
{
    DoXchgExpTimerEvent((IKESA)sa, _I, i, saId, timerId);
}

static void
XchgExpTimerEventR(sbyte4 i, ubyte4 saId, void *sa, ubyte4 timerId)
{
    DoXchgExpTimerEvent((IKESA)sa, _R, i, saId, timerId);
}

#endif /* __IKE_UPDATE_TIMER__ */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE2_newXchg(IKESA pxSa, ubyte oExchange, ubyte4 dwMsgId, /* 0=request */
             intBoolean bRequest, /* we initiate the exchange? */
             IKE2XG *ppxXg)
{
    MSTATUS status = ERR_IKE_NEWSA_FAIL;

    IKE2XG pxXg = NULL;
    sbyte4 dir = (bRequest ? _I : _R);

    ubyte4 dwMsgIdCur = pxSa->u.v2.dwMsgId[dir];
    ubyte4 dwWndLen = pxSa->u.v2.dwWndLen[dir];
    ubyte4 dwWndIdx = pxSa->u.v2.dwWndIdx[dir];
    ubyte4 dwMsgIdNext = dwMsgIdCur + dwWndLen;

    ubyte4 i;
    struct ike_info *pxInfo = NULL;

    if (0 == dwWndLen) DBG_EXIT /* jic */

    /* pre-allocate INFORMATIONAL exchange */
    if (IKE_XCHG_INFO == oExchange)
    {
        if (NULL == (pxInfo = (struct ike_info *) MALLOC(sizeof(struct ike_info))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            DBG_EXIT
        }
        pxInfo->pxDelete = NULL;
        pxInfo->pxNotify = NULL;
    }

    /* we're initiating an exchange */
    if (bRequest)
    {
        switch (oExchange)
        {
        case IKE_XCHG_INIT :    /* IKE_SA_INIT */
            if (IS_IKE2_SA_INITED(pxSa))
                DBG_EXIT
            break;
        case IKE_XCHG_AUTH :    /* IKE_AUTH */
            if (!IS_IKE2_SA_INITED(pxSa) ||
                IS_IKE2_SA_AUTHED(pxSa))
                DBG_EXIT
            break;
        case IKE_XCHG_CHILD :   /* CREATE_CHILD_SA */
        case IKE_XCHG_INFO :    /* INFORMATIONAL */
            if (!IS_IKE2_SA_AUTHED(pxSa))
                DBG_EXIT
            break;
        default : /* jic */
            DBG_EXIT
        }

        for (i = dwWndLen; i != 0; i--)
        {
            IKE2XG pxXgTmp = IKE_SA_GET_XCHG(pxSa, _I/*dir*/, i-1);
            if (IS_VALID_XCHG(pxXgTmp)) break;
            pxXg = pxXgTmp;
        }
        if (!pxXg)
        {
            /* (request) window full */
            DBG_EXIT
        }

        dwMsgId = dwMsgIdCur + i;
    }

    /* the peer initiated this exchange */
    else
    {
        if (!IS_IKE2_SA_INITED(pxSa))
        {
            switch (oExchange)
            {
            case IKE_XCHG_INIT :    /* IKE_SA_INIT */
            case IKE_XCHG_AUTH :    /* IKE_AUTH */
            case IKE_XCHG_CHILD :   /* CREATE_CHILD_SA */
            case IKE_XCHG_INFO :    /* INFORMATIONAL */
                break;
            default :
                DBG_EXIT
            }
        }

        if (dwMsgId < dwMsgIdCur) DBG_EXIT /* jic */

        if (dwMsgId < dwMsgIdNext)
        {
            pxXg = IKE_SA_GET_XCHG(pxSa, _R/*dir*/, dwMsgId - dwMsgIdCur);
        }
        else
        {
            ubyte4 off = dwMsgId - dwMsgIdNext + 1;
#if 1
            if (off > dwWndLen) DBG_EXIT /* jic */
#endif
            /* advance (response) window */
            for (i=0; i < off; i++)
            {
                pxXg = IKE_SA_GET_XCHG(pxSa, _R/*dir*/, i);
                if (IS_VALID_XCHG(pxXg))
                    IKE2_delXchg(pxXg, pxSa, OK);
                else
                {
                    ++(pxSa->u.v2.dwMsgId[_R]);
                    pxSa->u.v2.dwWndIdx[_R] = (pxSa->u.v2.dwWndIdx[_R] + 1)
                                            % pxSa->u.v2.dwWndLen[_R];
                }
            }
        }
    }

    /* at this point we should have an exchange struct */
    if (!pxXg) /* jic */
    {
        DBG_EXIT
    }

    /* initialize */
    DIGI_MEMSET((ubyte *)pxXg, 0x00, sizeof(struct ike2xg)); /* clean up */

#ifdef __IKE_UPDATE_TIMER__
    if (OK > (status = IKE_ADD_TIMER_EVT(
                            (1000 * pxSa->ikePeerConfig->ikeTimeoutNegotiation),
                            ((pxXg - &(pxSa->u.v2.pxXg[bRequest?_I:_R][0])) / sizeof(*pxXg)),
                            pxSa,
                            (bRequest ? XchgExpTimerEventI : XchgExpTimerEventR),
                            "TO2",
                            pxXg->expTimerId, pxXg->expTimerHdl)))
    {
        goto exit;
    }
#endif

    pxXg->dwMsgId = dwMsgId;
    pxXg->oExchange = oExchange;

    if ((IKE_XCHG_INIT <= oExchange) && (IKE_XCHG_INFO  >= oExchange))
    {
        pxXg->pState = IKE2_getStateInfo(oExchange, dir);
    }

    if (bRequest)
    {
        pxXg->x_flags |= IKE_XCHG_FLAG_INITIATOR;
    }

    pxXg->dwTimeStart = RTOS_deltaMS(&gStartTime, NULL);
    pxXg->x_flags |= IKE_XCHG_FLAG_INUSE;

    if (ppxXg) *ppxXg = pxXg;

    if (IKE_XCHG_INFO == oExchange)
    {
        pxXg->pxInfo = pxInfo;
        pxInfo = NULL;
    }

    /* done */
    status = OK;

exit:
    if (pxInfo) FREE(pxInfo);
    return status;
} /* IKE2_newXchg */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE2_delXchg(IKE2XG pxXg, IKESA pxSa, MSTATUS merror)
{
    MSTATUS status = OK;

    intBoolean bInitiator = IS_XCHG_INITIATOR(pxXg);
    sbyte4 i, dir = (bInitiator ? _I : _R);

    IPSECSA pxIPsecSa = pxXg->pxIPsecSa;
    IKESA pxSa1 = pxXg->pxSa;

    if (!IS_VALID_XCHG(pxXg)) goto exit; /* jic */

    /* free up space */
    for (i=0; i < pxXg->numMsgs; i++)
    {
        if (pxXg->poMsg[i])
        {
            FREE(pxXg->poMsg[i]);
            pxXg->poMsg[i] = NULL;
            pxXg->dwMsgLen[i] = 0;
        }
    }
    pxXg->numMsgs = 0;

    for (i=0; i < pxXg->numIcvs; i++)
    {
        if (pxXg->poIcv[i])
        {
            FREE(pxXg->poIcv[i]);
            pxXg->poIcv[i] = NULL;
        }
#ifdef __ENABLE_IKE_FRAGMENTATION__
        if (pxXg->poEfBody[i])
        {
            FREE(pxXg->poEfBody[i]);
            pxXg->poEfBody[i] = NULL;
            pxXg->wEfBodyLen[i] = 0;
        }
#endif
    }
    pxXg->numIcvs = 0;

    if (pxIPsecSa)
    {
        if (IS_VALID_CHILD(pxIPsecSa))
        {
            if (merror && !pxIPsecSa->merror &&
                !IS_P2_FINAL_STATE(pxIPsecSa->oState))
            {
                pxIPsecSa->merror = merror;

                IKE_delIPsecSa(pxIPsecSa, pxSa);
            }
        }

        /* Free intermediate key exchange resources not cleaned by IKE_delIPsecSa */
        if (NULL != pxIPsecSa->poNi_b)
        {
            if (pxIPsecSa->poNi_b != pxIPsecSa->poNonce)
                FREE(pxIPsecSa->poNi_b);
            pxIPsecSa->poNi_b = NULL;
        }
        if (NULL != pxIPsecSa->poNr_b)
        {
            if (pxIPsecSa->poNr_b != pxIPsecSa->poNonce)
                FREE(pxIPsecSa->poNr_b);
            pxIPsecSa->poNr_b = NULL;
        }
        if (NULL != pxIPsecSa->p_dhContext)
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            CRYPTO_INTERFACE_DH_freeDhContextExt(&(pxIPsecSa->p_dhContext), NULL, NULL);
#else
            DH_freeDhContext(&(pxIPsecSa->p_dhContext), NULL);
#endif
        }
        if (NULL != pxIPsecSa->pDhPeerPubKey)
        {
            FREE(pxIPsecSa->pDhPeerPubKey);
            pxIPsecSa->pDhPeerPubKey = NULL;
        }
        if (NULL != pxIPsecSa->pDhSharedSecret)
        {
            DIGI_MEMSET(pxIPsecSa->pDhSharedSecret, 0, pxIPsecSa->dhSharedSecretLen);
            FREE(pxIPsecSa->pDhSharedSecret);
            pxIPsecSa->pDhSharedSecret = NULL;
        }
#ifdef __ENABLE_DIGICERT_ECC__
        if (NULL != pxIPsecSa->p_eccKey)
        {
            CRYPTO_INTERFACE_EC_deleteKeyAux(&(pxIPsecSa->p_eccKey));
        }
        if (NULL != pxIPsecSa->poEccSharedSecret)
        {
            DIGI_MEMSET(pxIPsecSa->poEccSharedSecret, 0x00, pxIPsecSa->eccSharedSecretLen);
            FREE(pxIPsecSa->poEccSharedSecret);
            pxIPsecSa->poEccSharedSecret = NULL;
        }
#endif
#ifdef __ENABLE_DIGICERT_PQC__
        if (NULL != pxIPsecSa->pQsCtx)
        {
            CRYPTO_INTERFACE_QS_deleteCtx(&(pxIPsecSa->pQsCtx));
        }
        if (NULL != pxIPsecSa->pQsCipherText)
        {
            DIGI_MEMSET(pxIPsecSa->pQsCipherText, 0x00, pxIPsecSa->qsCipherTextLen);
            FREE(pxIPsecSa->pQsCipherText);
            pxIPsecSa->pQsCipherText = NULL;
        }
        if (NULL != pxIPsecSa->pQsSharedSecret)
        {
            DIGI_MEMSET(pxIPsecSa->pQsSharedSecret, 0x00, pxIPsecSa->qsSharedSecretLen);
            FREE(pxIPsecSa->pQsSharedSecret);
            pxIPsecSa->pQsSharedSecret = NULL;
        }
#endif

        FREE(pxIPsecSa);
        pxXg->pxIPsecSa = NULL;
    }

    if (pxSa1)
    {
        if (pxSa1 != pxSa)
        {
#ifdef __IKE_MULTI_THREADED__
            RTOS_rwLockWaitR(m_ikeSaRwLock);
#endif
            if (IS_VALID(pxSa1) &&
                (pxSa1->dwId == pxXg->dwSaId) &&
                !IS_IKE2_SA_AUTHED(pxSa1))
            {
#ifdef __IKE_MULTI_THREADED__
                RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
                IKE2_delSa(pxSa1, FALSE, merror);

                if (pxSa->pxSaRekey == pxSa1)
                    pxSa->pxSaRekey = NULL;
            }
            else
            {
#ifdef __IKE_MULTI_THREADED__
                RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
            }
        }
        pxXg->pxSa = NULL;
        pxXg->dwSaId= 0;
    }

#ifdef __ENABLE_MOBIKE__
    if ((IKE_XCHG_FLAG_UPDATE_SA | IKE_XCHG_FLAG_COOKIE2) & pxXg->x_flags)
    {
        if (bInitiator)
            pxSa->flags &= ~(IKE_SA_FLAG_UPDATING);

        if (merror && !pxXg->merror)
            pxXg->merror = merror;

        if (pxXg->merror && m_ikeSettings.funcPtrIkeStatHdlr)
            m_ikeSettings.funcPtrIkeStatHdlr(ISC_MOB, IST_FAIL,
                                             0, pxXg, pxSa);
    }
#endif

    if (pxXg->pxInfo)
    {
        IKEINFO_notify pxNotify = pxXg->pxInfo->pxNotify;
        IKEINFO_delete pxDelete = pxXg->pxInfo->pxDelete;

        while (pxNotify)
        {
            IKEINFO_notify next = pxNotify->next;
            if (pxNotify->poData)
            {
                FREE(pxNotify->poData);
            }
            FREE(pxNotify);
            pxNotify = next;
        }
        while (pxDelete)
        {
            IKEINFO_delete next = pxDelete->next;
            FREE(pxDelete);
            pxDelete = next;
        }
        FREE(pxXg->pxInfo);
        pxXg->pxInfo = NULL;
    }

#ifdef __ENABLE_IKE_CP__
    if (pxXg->poCfgAttrs)
    {
        FREE(pxXg->poCfgAttrs);
        pxXg->poCfgAttrs = NULL;
    }
    pxXg->wCfgAttrsLen = 0;
#endif

#ifdef __IKE_UPDATE_TIMER__
    IKE_DEL_TIMER_EVT(pxXg->expTimerId, pxXg->expTimerHdl)

    IKE_DEL_TIMER_EVT(pxXg->rtxTimerId, pxXg->rtxTimerHdl)
    pxXg->rtxCount = 0;
#endif

    /* done */
    if (pxXg->dwMsgId == pxSa->u.v2.dwMsgId[dir])
    {
        ++(pxSa->u.v2.dwMsgId[dir]);
        pxSa->u.v2.dwWndIdx[dir] = (pxSa->u.v2.dwWndIdx[dir] + 1)
                                 % pxSa->u.v2.dwWndLen[dir];
    }
    pxXg->x_flags |= IKE_XCHG_FLAG_DELETED;

exit:
    return status;
} /* IKE2_delXchg */


/*------------------------------------------------------------------*/

/* This api is for Digicert Internal Usage. Not to be documented */
extern MSTATUS
IKE2_getSaNum(ubyte4 *pCount)
{
    IKESA pxSa;
    ubyte4 count = 0;
    sbyte4 i;
    MSTATUS status = OK;

    if (!pCount)
    {
        status = ERR_IKE_INVALID_PARAM;
        goto exit;
    }

    for (i=0; i < m_ikeSaNum; i++)
    {
        GET_NEXT_ELEMENT(pxSa, i)

        if (IS_VALID(pxSa) && IS_IKE2_SA(pxSa))
        {
            count++;
        }
    }
    *pCount = count;

exit :
    return status;
}


/*------------------------------------------------------------------*/

/* Initiate IKEv2 MOBIKE exchanges.
This function triggers IKEv2 initiation of MOBIKE exchanges.

\since 5.1
\version 5.1 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_IKE_SERVER__$
- $__ENABLE_MOBIKE__$
- $__IKE_MULTI_HOMING__$

\param serverInstanceOld    Current application-specific identifier.
\param serverInstance       New application-specific identifier.

@inc_file ike.h

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

For an example of how to call this function, see Use Cases and Policies in
Mocana NanoSec Product Guide.

*/
#if defined(__ENABLE_MOBIKE__) && defined(__IKE_MULTI_HOMING__)

#ifdef __IKE_MULTI_THREADED__
typedef struct dpcKeyUpd
{
    struct dpcHdr hdr;
    IKESA pxSa;
    sbyte4 serverInstanceOld;
    sbyte4 serverInstanceNew;
    MOC_IP_ADDRESS_S hostAddrNew;

} *IKE_DPC_KEY_UPD;
#endif

#define IS_OLD_IKE2_SA(_sa) (((_sa)->flags) & (IKE_SA_FLAG_DELETING \
                                             | IKE_SA_FLAG_REKEYED \
                                             | IKE_SA_FLAG_REAUTH \
                                               ))

static MSTATUS
UpdateKey(IKESA pxSa, sbyte4 serverInstanceOld, sbyte4 serverInstance,
          MOC_IP_ADDRESS hostAddrNew)
{
    MSTATUS status = OK;

    sbyte4 j;
    IKE2XG pxXg;

    IKE_LOCK_R; /* !!! */

#ifdef __IKE_MULTI_THREADED__
    RTOS_rwLockWaitR(m_ikeSaRwLock);
#endif
        if (!IS_VALID(pxSa) ||
            !IS_IKE2_SA(pxSa) ||
            IS_OLD_IKE2_SA(pxSa) ||
            (serverInstanceOld != pxSa->serverInstance))
        {
#ifdef __IKE_MULTI_THREADED__
            RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
            goto exit;
        }

        /* sanity-check */
#ifdef __ENABLE_DIGICERT_IPV6__
        if (hostAddrNew->family != pxSa->dwHostAddr.family)
        {
#ifdef __IKE_MULTI_THREADED__
            RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
            status = ERR_IKE; /* for now */
            goto exit;
        }
#endif

#ifdef __IKE_MULTI_THREADED__
    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* relay this call to the proper thread */
        if (m_ikeSettings.funcPtrIkeThreadSend)
        {
            ubyte4 size = sizeof(struct dpcKeyUpd);
            struct dpcKeyUpd ku;
            ku.hdr.dpc_func = (IKE_dpcFunc)IKE2_dpcKeyUpdate;
            ku.hdr.dpc_len = (ubyte2)size;
            ku.pxSa = pxSa;
            ku.serverInstanceOld = serverInstanceOld;
            ku.serverInstanceNew = serverInstance;
            ku.hostAddrNew = DEREF_MOC_IPADDR(hostAddrNew);
            status = (MSTATUS)
            m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid, (ubyte *)&ku, size);
        }
        else
        {
            status = ERR_IKE_CONFIG;
        }
        RTOS_rwLockReleaseR(m_ikeSaRwLock);
        goto exit;
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif

        /* remove incomplete IKE_SA */
        if (!IS_IKE2_SA_AUTHED(pxSa))
        {
            IKE2_delSa(pxSa, FALSE, STATUS_IKE_MOBILE);
            goto exit;
        }

        if (!(IKE_SA_FLAG_MOBILE & pxSa->flags))
        {
            /* peer does not support MOBIKE */
            goto exit;
        }

        /* abort pending request(s) */
        for (j = pxSa->u.v2.dwWndLen[_I] - 1; 0 <= j; j--)
        {
            pxXg = &(pxSa->u.v2.pxXg[_I][j]);
            if (IS_VALID_XCHG(pxXg))
                IKE2_delXchg(pxXg, pxSa, STATUS_IKE_MOBILE);
        }

        if (OK > (/*status = */IKE2_newXchg(pxSa, IKE_XCHG_INFO, 0, TRUE, &pxXg)))
        {
            goto exit; /* jic - unlikely though */
        }
        else
        {
            struct ike_context ctx = { NULL };

#ifdef IKE_SA_CKY_HASH_TABLE_SIZE_MASK
            IKE_delSaCkyIndex(pxSa);
#endif
#ifdef IKE_SA_ADDR_HASH_TABLE_SIZE_MASK
            IKE_delSaAddrIndex(pxSa);
#endif
            pxSa->serverInstance = serverInstance;
            pxSa->dwHostAddr = DEREF_MOC_IPADDR(hostAddrNew);

#ifdef IKE_SA_ADDR_HASH_TABLE_SIZE_MASK
            IKE_addSaAddrIndex(pxSa);
#endif
#ifdef IKE_SA_CKY_HASH_TABLE_SIZE_MASK
            IKE_addSaCkyIndex(pxSa);
#endif
            pxSa->flags |= IKE_SA_FLAG_UPDATING;
            pxXg->x_flags |= IKE_XCHG_FLAG_UPDATE_SA;

            if (m_ikeSettings.funcPtrIkeGetHostPort)
            {
                m_ikeSettings.funcPtrIkeGetHostPort(&pxSa->wHostPort
                                        MOC_NATT_REQ_VALUE(USE_NATT_PORT(pxSa))
                                        MOC_MTHM_REQ_VALUE(serverInstance));
            }
            ctx.pxSa = pxSa;
            ctx.pxXg = pxXg;

#ifdef __ENABLE_IPSEC_NAT_T__
            if ((IKE_NATT_FLAG_D & pxSa->natt_flags) &&
                !(IKE_NATT_FLAG_NOT_ALLOWED & pxSa->natt_flags))
            {
                ctx.flags = (IKE_CNTXT_FALG_NAT_D_SRC | IKE_CNTXT_FALG_NAT_D_DST);
            }
#endif
            ctx.wMsgType = UPDATE_SA_ADDRESSES;
            status = IKE2_xchgOut(&ctx);
        }

exit:
    IKE_UNLOCK_R;
    return status;
} /* UpdateKey */


/*------------------------------------------------------------------*/

#ifdef __IKE_MULTI_THREADED__
extern sbyte4
IKE2_dpcKeyUpdate(IKE_DPC_KEY_UPD ku, ubyte4 kuSize)
{
    MSTATUS status = OK;

    if ((sizeof(struct dpcKeyUpd) <= kuSize) &&
        (sizeof(struct dpcKeyUpd) == ku->hdr.dpc_len) &&
        ((IKE_dpcFunc)IKE2_dpcKeyUpdate == ku->hdr.dpc_func) &&
        ku->pxSa /* jic */)
    {
        status = UpdateKey(ku->pxSa,
                           ku->serverInstanceOld, ku->serverInstanceNew,
                           REF_MOC_IPADDR(ku->hostAddrNew));
    }
    return (sbyte4)status;
} /* IKE2_dpcKeyUpdate */
#endif


/*------------------------------------------------------------------*/

extern sbyte4
IKE2_keyUpdate(sbyte4 serverInstanceOld, sbyte4 serverInstance)
{
    MSTATUS status;

    sbyte4 i;
    MOC_IP_ADDRESS_S hostAddrNew;
    sbyte4 (*hostAddrFunc)(MOC_IP_ADDRESS_S *, sbyte4 s) =
                                            m_ikeSettings.funcPtrIkeGetHostAddr;

    if (serverInstanceOld == serverInstance) /* jic */
    {
        status = ERR_IKE; /* for now */
        goto exit;
    }

    /* get new host IP address */
    if (NULL == hostAddrFunc) /* jic */
    {
        status = ERR_IKE_CONFIG;
        goto exit;
    }
    if (OK > (status = (MSTATUS) hostAddrFunc(&hostAddrNew
                                        MOC_MTHM_REQ_VALUE(serverInstance))))
    {
        goto exit;
    }

    for (i=0; i < m_ikeSaNum; i++)
    {
        IKESA pxSa;
        GET_NEXT_ELEMENT(pxSa, i)

        status = UpdateKey(pxSa, serverInstanceOld, serverInstance,
                           REF_MOC_IPADDR(hostAddrNew));
    }

exit:
    return (sbyte4)status;
} /* IKE2_keyUpdate */

#endif /* defined(__ENABLE_MOBIKE__) && defined(__IKE_MULTI_HOMING__) */


#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */

