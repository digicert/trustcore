/**
 * @file  ike_event.c
 * @brief IKE event handling and pending exchanges.
 *
 * @details    IKE event queue management for pending IPsec SA establishments.
 * @since      1.41
 * @version    6.5.1 and later
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
#include "../common/sizedbuffer.h"
#include "../common/vlong.h"
#include "../crypto/dh.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/crypto.h"
#include "../crypto/hmac.h"
#include "../crypto/ca_mgmt.h"

#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif

#ifdef __ENABLE_DIGICERT_PFKEY__
#include "../pfkey/pfkey.h"
#endif
#ifdef __IKE_UPDATE_TIMER__
#include "../common/timer.h"
#endif

#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsecconf.h"
#include "../ipsec/ipseckey.h"

#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ike_childsa.h"
#include "../ike/ike_crypto.h"
#include "../ike/ikesa.h"
#include "../ike/ikekey.h"
#include "../ike/ike_state.h"
#include "../ike/ike_event.h"
#include "../ike/ike_utils.h"
#include "../ike/ike_status.h"

/* [v2] */
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
/*#include "../eap/eap.h"*/
#include "../eap/eap_proto.h"
#include "../ike2/ike2_eap.h"
#endif


/*------------------------------------------------------------------*/

MOC_EXTERN_DATA_DECL moctime_t gStartTime;

extern ikeSettings m_ikeSettings;
extern IKE_MUTEX g_ikeMtx;

#ifdef __IKE_UPDATE_TIMER__
extern ubyte *m_ikeTimer;
#endif


/*------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_IKE_EVENT_MALLOC__
static struct ike_event_q *m_ikeEvt = NULL;
#else
static struct ike_event_q m_ikeEvt[IKE_EVENT_MAX] = { {0} };
#endif
static sbyte4 m_ikeEvtNum = 0;

static ubyte4 m_ikeEvtId = 0;


/*------------------------------------------------------------------*/

#define _I 0
#define _R 1

#define _IN  1
#define _OUT 2

#define EVT_VERS(_e) ((_e)->dwIkeSaId ? \
                      ((0x80000000 & (_e)->dwIkeSaId) ? 2 : 1) \
                      : 0)

#define EVT_TYPE(_e) (IKE_KEY_TYPE_MASK & (_e)->type)

#ifdef __IKE_UPDATE_TIMER__
#define EVT_DELETE(_e) \
    IKE_DEL_TIMER_EVT((_e)->initTimerId, (_e)->initTimerHdl) \
    IKE_DEL_TIMER_EVT((_e)->expTimerId, (_e)->expTimerHdl) \
    (_e)->flags = 0; \
    (_e)->dwId = 0;

#else
#define EVT_DELETE(_e) \
    (_e)->flags = 0; \
    (_e)->dwId = 0;
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_clearEvents(sbyte4 state)
{
    MSTATUS status = OK;

#ifdef __ENABLE_DIGICERT_IKE_EVENT_MALLOC__
    if(IKED_STATE_INIT == state)
    {
       if (NULL == m_ikeEvt)
       {
               m_ikeEvt = (struct ike_event_q*)MALLOC(IKE_EVENT_MAX * sizeof(struct ike_event_q));
               if(m_ikeEvt)
               {
                   DIGI_MEMSET((ubyte *)m_ikeEvt, 0x00, IKE_EVENT_MAX * sizeof(struct ike_event_q));
               }
               else
               {
                   status = ERR_MEM_ALLOC_FAIL;
                   goto exit;
               }
       }
    }
#endif
    if (m_ikeEvtNum)
    {
#if defined(__IKE_UPDATE_TIMER__) && !defined(__IKE_MULTI_THREADED__)
        sbyte4 i;
        for (i=0; i < m_ikeEvtNum; i++)
        {
            IKEEVT_EX pxEvtEx = &(m_ikeEvt[i]);
            if (pxEvtEx->flags)
            {
                IKE_DEL_TIMER_EVT(pxEvtEx->expTimerId, pxEvtEx->expTimerHdl)
                IKE_DEL_TIMER_EVT(pxEvtEx->initTimerId, pxEvtEx->initTimerHdl)
            }
        }
#endif
        DIGI_MEMSET((ubyte *)m_ikeEvt, 0x00, IKE_EVENT_MAX * sizeof(struct ike_event_q));
    }
    else
    {
        m_ikeEvtNum = IKE_EVENT_MAX;
    }
#ifdef __ENABLE_DIGICERT_IKE_EVENT_MALLOC__
    if(IKED_STATE_SHUTDOWN == state)
    {
        if(m_ikeEvt)
        {
            FREE(m_ikeEvt);
        }
        m_ikeEvt = NULL;
        m_ikeEvtNum = 0;
    }

exit:

#endif

    return status;
} /* IKE_clearEvents */


/*------------------------------------------------------------------*/

static MSTATUS
IKE_evtQueue(IKEEVT_EX *ppxEvtEx, IKEEVT pxEvt
             MOC_MTHM(serverInstance) MOC_NATT(bUseNattPort))
{
    MSTATUS status = OK;

    IKEEVT_EX pxEvtEx = NULL;

    sbyte4 i;
    ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
    ubyte4 timeout = 1000 * m_ikeSettings.ikeTimeoutEvent;

    /* find available slot */
    for (i=0; i < m_ikeEvtNum; i++, pxEvtEx = NULL)
    {
        pxEvtEx = &(m_ikeEvt[i]);

        if (!pxEvtEx->flags) break; /* found */

        if (timeout < (timenow - pxEvtEx->dwTimeQueued))
        {
            /* timed out */
            EVT_DELETE(pxEvtEx)
            break;
        }
    }

    if (NULL == pxEvtEx)
    {
        /* TO DO: find oldest? */

        /*debug_printnl("  Event queue full");*/
        status = ERR_IKE_EVENT_FULL;
        goto exit; /* not found */
    }

#ifdef __IKE_UPDATE_TIMER__
    if (OK > (status = IKE_ADD_TIMER_EVT((1000 * m_ikeSettings.ikeTimeoutEvent),
                                         0, pxEvtEx,
                                         IKE_evtExpTimerEvent, "TOE",
                                         pxEvtEx->expTimerId, pxEvtEx->expTimerHdl)))
    {
        /*debug_printnl("Failed to schedule timer for event timeout.");*/
        goto exit;
    }
#endif

    /* initialize */
    pxEvtEx->evt = *pxEvt;

    if (0 == (pxEvtEx->dwId = ++m_ikeEvtId)) /* jic */
    pxEvtEx->dwId           = ++m_ikeEvtId;
    pxEvtEx->dwTimeQueued   = timenow;

    pxEvtEx->dwOldIkeSaId   = 0;

#ifdef __IKE_MULTI_HOMING__
    pxEvtEx->serverInstance = serverInstance;
#endif
    pxEvtEx->pxIPsecSa      = NULL;

    pxEvtEx->flags          = IKE_EVENT_FLAG_INUSE;
#ifdef __ENABLE_IPSEC_NAT_T__
    if (bUseNattPort)
    pxEvtEx->flags         |= IKE_EVENT_FLAG_NATT;
#endif
    if (NULL != ppxEvtEx)
        *ppxEvtEx = pxEvtEx;

exit:
    return status;
} /* IKE_evtQueue */


/*------------------------------------------------------------------*/

static MSTATUS
IKE_evtInfo(IKESA pxSa, IKEEVT_EX pxEvtEx)
{
    MSTATUS status;

    IKEEVT pxEvt = &(pxEvtEx->evt);
    struct ike_context ctx = { NULL };

    /* send deletion info. */
    if (IS_IKE2_SA(pxSa)) /* [v2] */
    {
        IKE2XG pxXg = NULL;
        IKEINFO_delete pDel;

        /* allocate INFORMATIONAL Delete exchange */
        if (NULL == (pDel = (IKEINFO_delete) MALLOC(sizeof(struct ike_info_delete))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        pDel->oProtoId = (ubyte)((IPPROTO_AH == pxEvt->oProtocol)
                       ? PROTO_IPSEC_AH : PROTO_IPSEC_ESP);
        pDel->dwSpi = pxEvt->dwSpi;
        pDel->pxSa = NULL;
        pDel->next = NULL;

        /* create a new request */
        if (OK > (status = IKE2_newXchg(pxSa, IKE_XCHG_INFO, 0, TRUE, &pxXg)))
        {
            FREE(pDel);
            goto exit;
        }
        pxXg->pxInfo->pxDelete = pDel;

        ctx.pxSa = pxSa;
        ctx.pxXg = pxXg;

        status = IKE2_xchgOut(&ctx);
    }
    else /* [v1] */
    {
        struct ike_info_delete deleteInfo = { 0 };
        struct ike_info info = { NULL };

        deleteInfo.oProtoId = (ubyte)((IPPROTO_AH == pxEvt->oProtocol)
                            ? PROTO_IPSEC_AH : PROTO_IPSEC_ESP);
        deleteInfo.dwSpi = pxEvt->dwSpi;
        info.pxDelete = &deleteInfo;

        ctx.pxInfo = &info;
        ctx.pxSa = pxSa;

        if (OK != (status = IKE_xchgOut(&ctx)))
            goto exit;
    }

    EVT_DELETE(pxEvtEx) /* handled */

exit:
    return status;
} /* IKE_evtInfo */


/*------------------------------------------------------------------*/

static MSTATUS
IKE_evtQuick(IKESA pxSa, IKEEVT_EX pxEvtEx)
{
    MSTATUS status = OK;

    sbyte4 i;
    ubyte2 wMode;
#ifdef __ENABLE_IPSEC_NAT_T__
    intBoolean bUseUdpEnc = FALSE;
    intBoolean bNatt = IS_BEHIND_NAT(pxSa);
#endif
    IKEEVT pxEvt = &(pxEvtEx->evt);
    struct ike_context ctx = { NULL };

    P2XG pxP2Xg = NULL; /* [v1] */
    IKE2XG pxXg = NULL; /* [v2] */
    IPSECSA pxIPsecSa = NULL;

    ubyte4 dwExpSecs, dwExpKBytes;
    ubyte4 ikeP2LifeSecs = pxSa->ikePeerConfig->ikeP2LifeSecs;
    ubyte4 ikeP2LifeKBytes = pxSa->ikePeerConfig->ikeP2LifeKBytes;

    ubyte2 bitStrength = 0;
#ifndef __DISABLE_DIGICERT_CONSTRAINT_CIPHER__
    if (!IS_IKE2_SA(pxSa)) /* [v1] CHILD_SA */
        bitStrength = CHILDSA_cipherEffectiveBitStrength(pxSa->pCipherSuite->wTfmId, pxSa->wEncrKeyLen);
#endif

#ifndef __ENABLE_DIGICERT_PFKEY__
    ubyte4 dwSpi=0;
    sbyte4 iNest;

    /* get SA bundle size */
    if ((0 >= (iNest = pxEvt->oSaLen)) ||
        (IPSEC_NEST_MAX < iNest))
    {
        status = ERR_IKE_EVENT;
        goto exit;
    }
#else
    ubyte4 dwSpi = pxEvt->dwSpi;
    struct ipsecpps *pxExIPsecPps = NULL;
    ubyte oPpsNum = 0;

    /* check # of proposal combinations from PF_KEY */
    if ((0 == pxEvt->oCombLen) ||
        (PFKEY_COMB_MAX < pxEvt->oCombLen))
    {
        status = ERR_IKE_EVENT;
        goto exit;
    }

    if ((1 < pxEvt->oCombLen) &&
        (NULL == (pxExIPsecPps = (struct ipsecpps *)
                    MALLOC(sizeof(struct ipsecpps) * (pxEvt->oCombLen - 1)))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
#endif

    /* new IPSEC SA */
    if (IS_IKE2_SA(pxSa)) /* [v2] CHILD_SA */
    {
        ubyte oExchange = (IS_IKE2_SA_AUTHED(pxSa) ? IKE_XCHG_CHILD : IKE_XCHG_INIT);

        if (OK > (status = IKE2_newXchg(pxSa, oExchange, 0, TRUE, &pxXg)))
            goto exit;

        if (OK > (status = IKE2_newIPsecSa(pxSa, pxXg, &pxIPsecSa)))
            goto exit;

        if (IKE_XCHG_INIT == oExchange)
        {
            pxXg->pxSa = pxSa;

            if (IKE_KEY_TYPE_SAINIT == EVT_TYPE(pxEvt)) /* special case!!! */
                pxIPsecSa->c_flags |= IKE_CHILD_FLAG_CONNECT2;
        }
    }
    else /* [v1] phase 2 quick mode exchange */
    {
        if (OK > (status = IKE_newIPsecSa(pxSa, 0, &pxP2Xg)))
            goto exit;

        pxIPsecSa = P2XG_IPSECSA(pxP2Xg);
    }

    /* convert from IPsec to IKE */
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    if (IKE_SA_FLAG_GDOI & pxSa->flags)
    {
        wMode =
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                (IPSEC_MODE_TUNNEL == pxEvt->oMode) ? ENCAPSULATION_MODE_TUNNEL :
#endif
                ENCAPSULATION_MODE_TRANSPORT;

        pxIPsecSa->dwIP[_I]     = pxEvt->dwSrcIP;
        pxIPsecSa->dwIPEnd[_I]  = pxEvt->dwSrcIPEnd;

        pxIPsecSa->dwIP[_R]     = pxEvt->dwDestIP;
        pxIPsecSa->dwIPEnd[_R]  = pxEvt->dwDestIPEnd;
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
	/* copy the content of the fqdn from event to pxipsecsa which will be used to negotiate data*/
        DIGI_MEMCPY(pxIPsecSa->fqdn, pxEvt->fqdn, MOC_MAX_FQDN_LEN);
#endif
    }
    else
#endif
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    if (IPSEC_MODE_TUNNEL == pxEvt->oMode) /* tunnel mode */
    {
        pxIPsecSa->dwIP[_I]     = pxEvt->dwSrcIP;
        pxIPsecSa->dwIPEnd[_I]  = pxEvt->dwSrcIPEnd;

        pxIPsecSa->dwIP[_R]     = pxEvt->dwDestIP;
        pxIPsecSa->dwIPEnd[_R]  = pxEvt->dwDestIPEnd;

        wMode = ENCAPSULATION_MODE_TUNNEL;
    }
    else
#endif
    {
        /* FOR NOW */
        pxIPsecSa->dwIP[_I] = pxIPsecSa->dwIPEnd[_I] = pxEvt->dwSrcAddr;
        pxIPsecSa->dwIP[_R] = pxIPsecSa->dwIPEnd[_R] = pxEvt->dwDestAddr;

        wMode = ENCAPSULATION_MODE_TRANSPORT;
    }

#ifdef __ENABLE_IPSEC_NAT_T__
    if (pxEvt->wUdpEncPort || bNatt) /* should use UDP-encap. */
    {
        bUseUdpEnc = TRUE;
    }
#endif

    pxIPsecSa->wPort[_I]    = pxEvt->wSrcPort;
    if (0 == (
        pxIPsecSa->wPortEnd[_I] = pxIPsecSa->wPort[_I]
        ))
        pxIPsecSa->wPortEnd[_I] = 0xffff; /* [v2] */

    pxIPsecSa->wPort[_R]    = pxEvt->wDestPort;
    if (0 == (
        pxIPsecSa->wPortEnd[_R] = pxIPsecSa->wPort[_R]
        ))
        pxIPsecSa->wPortEnd[_R] = 0xffff; /* [v2] */

    pxIPsecSa->oUlp         = pxEvt->oUlp;

    /* life time seconds */
    dwExpSecs = pxEvt->dwExpSecs;

    if (0 != ikeP2LifeSecs)
    {
        if ((0 == dwExpSecs) ||
            (ikeP2LifeSecs < dwExpSecs))
            dwExpSecs = ikeP2LifeSecs;
    }
    else
    {
        if (0 == dwExpSecs)
            dwExpSecs = pxSa->ikePeerConfig->ikeP2LifeSecsMax;
    }

    if (IKE_LIFE_SECS_MAX < dwExpSecs)
        dwExpSecs = IKE_LIFE_SECS_MAX;

    /* life time kbytes */
    dwExpKBytes = pxEvt->dwExpKBytes;

    if (0 != ikeP2LifeKBytes)
    {
        if ((0 == dwExpKBytes) ||
            (ikeP2LifeKBytes < dwExpKBytes))
            dwExpKBytes = ikeP2LifeKBytes;
    }
    else
    {
        if (0 == dwExpKBytes)
            dwExpKBytes = pxSa->ikePeerConfig->ikeP2LifeKBytesMax;
    }

    /* [v1] default 8 hours (RFC2407 4.5, p.13) */
    if (!IS_IKE2_SA(pxSa))
    {
        if ((0 == dwExpSecs) && (0 == dwExpKBytes))
            dwExpSecs = (ubyte4)28800;
    }

    /* proposal(s) */
    pxIPsecSa->oP2SaNum     = 1;

#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    pxIPsecSa->axP2Sa[0].ifid = pxEvt->ifid;
#endif
#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
    pxIPsecSa->axP2Sa[0].cookie = pxEvt->cookie;
#endif
    pxIPsecSa->axP2Sa[0].dwSeqNo = pxEvt->dwSeqNo;

#ifndef __ENABLE_DIGICERT_PFKEY__
    pxIPsecSa->axP2Sa[0].oChildSaLen = (ubyte)iNest;

    /* set up proposal(s) */
    for (i=0; i < iNest; i++) /* outer header first */
    {
        IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[0].axChildSa[i].ipsecPps);
#else
    pxIPsecSa->axP2Sa[0].oChildSaLen = 1;

    pxIPsecSa->axP2Sa[0].axChildSa[0].pxIPsecPps = pxExIPsecPps;
    pxExIPsecPps = NULL; /* !!! */

    pxIPsecSa->axP2Sa[0].oReplay = pxEvt->oReplay;

    status = OK;
    /* set up proposal(s) */
    for (i=0; i < pxEvt->oCombLen; i++)
    {
        IPSECPPS pxIPsecPps = oPpsNum
                            ? &(pxIPsecSa->axP2Sa[0].axChildSa[0].pxIPsecPps[oPpsNum-1])
                            : &(pxIPsecSa->axP2Sa[0].axChildSa[0].ipsecPps);
#endif
        struct sainfo *si = &(pxEvt->pxSa[i]);
        ubyte oSecuProto  = si->oSecuProto;
        ubyte oAuthAlgo   = si->oAuthAlgo;
        ubyte oEncrAlgo   = si->oEncrAlgo;
        ubyte oEncrKeyLen = si->oEncrKeyLen;
        ubyte aeadTag     = si->aeadTag;

        CHILDSA_authInfo *pAuthAlgo = (oAuthAlgo ? CHILDSA_findAuthAlgo(0, 0, 0, oAuthAlgo) : NULL);

#ifdef __ENABLE_DIGICERT_PFKEY__
        DIGI_MEMSET((ubyte *)pxIPsecPps, 0x00, sizeof(struct ipsecpps)); /* jic */
#else
        /* get SPI */
        do
        {
            if (OK > (status = RANDOM_numberGenerator(g_pRandomContext, (ubyte *)&dwSpi, sizeof(ubyte4))))
                goto exit;
        } while ((ubyte4)255 >= dwSpi);
#endif
        pxIPsecPps->dwSpi[_I] = dwSpi;

        pxIPsecPps->oPpsNo = 1;

#ifdef __ENABLE_DIGICERT_PFKEY__
        if (IS_IKE2_SA(pxSa)) /* [v2] */
            pxIPsecPps->oPpsNo = (ubyte)(oPpsNum+1);
        else /* [v1] */
            pxIPsecPps->oTfmNo = (ubyte)(oPpsNum+1);
#endif
        pxIPsecPps->wMode = wMode;

#ifdef __ENABLE_IPSEC_NAT_T__
        if (bUseUdpEnc)
            pxIPsecPps->p_flags |= IKE_PROP_FLAG_UDP_ENCP;
#endif
        /* life time */
        pxIPsecPps->dwExpSecs   = dwExpSecs;
        pxIPsecPps->dwExpKBytes = dwExpKBytes;

        /* protocol id */
        pxIPsecPps->oSecuProto  = oSecuProto;
        pxIPsecPps->oProtocol       = PROTO_IPSEC_ESP;

#ifndef __ENABLE_DIGICERT_PFKEY__
        status = ERR_IKE_EVENT; /* !!! */

#define GOTO_NEXT goto exit;  /* abort */
#else
#define GOTO_NEXT continue;   /* skip */
#endif

        /* transform id */
        switch (oSecuProto)
        {
        case IPSEC_PROTO_AH :
            pxIPsecPps->oProtocol   = PROTO_IPSEC_AH;

            if (oAuthAlgo)
            {
                if (NULL == pAuthAlgo) GOTO_NEXT
                pxIPsecPps->oTfmId      = pAuthAlgo->oTfmId;
            }
            else
            {
#ifndef __ENABLE_DIGICERT_PFKEY__
                pxIPsecPps->p_flags |= IKE_PROP_FLAG_TFM_ID; /* oTfmId WILDCARD */
#else
                continue; /* skip */
#endif
            }
            break;

        case IPSEC_PROTO_ESP_NULL :
            pxIPsecPps->oTfmId          = ESP_NULL;
            break;

        case IPSEC_PROTO_ESP :
        case IPSEC_PROTO_ESP_AUTH :

        /* encryption algo. */
            if (oEncrAlgo) /* !!! */
            {
                CHILDSA_encrInfo *pEncrAlgo =
                            CHILDSA_findAeadAlgoWithConstraint(bitStrength, 0, 0, oEncrAlgo, aeadTag,
                                                 oEncrKeyLen, NULL);
                if (NULL == pEncrAlgo) GOTO_NEXT

                pxIPsecPps->oTfmId      =
                pxIPsecPps->oEncrAlgo   = pEncrAlgo->oTfmId;
            }
#ifdef __ENABLE_DIGICERT_PFKEY__
            else continue; /* skip */
#else
            /* wildcard encr algo */
            else if (oEncrKeyLen /* specific key-length */
                  || aeadTag /* check AEAD algo */
                     )
            {
                sbyte4 j;
                for (j=0; ; j++)
                {
                    CHILDSA_encrInfo *pEA = CHILDSA_getEncrAlgo(j);
                    if (NULL == pEA) goto exit; /* no match */
                    if (aeadTag) /* specific AEAD algo tag size */
                    {
                        if (aeadTag != pEA->oTagLen) /* mismatch */
                        {
                            continue;
                        }
                    }

                    if (!oEncrKeyLen) break;

                    if (((ubyte2)oEncrKeyLen >= pEA->wKeyLen) &&
                        ((0 == pEA->wKeyLenEnd) ||
                         ((ubyte2)oEncrKeyLen <= pEA->wKeyLenEnd)))
                        break;
                }
                pxIPsecPps->p_flags |= IKE_PROP_FLAG_TFM_ID;    /* oTfmId WILDCARD */
                pxIPsecPps->p_flags |= IKE_PROP_FLAG_ENCR_ALGO; /* oEncrAlgo WILDCARD */
                pxIPsecPps->aeadTag = aeadTag;
            }
#endif
            /* encr algo key-length */
            if (oEncrKeyLen)
                pxIPsecPps->wEncrKeyLen     = (ubyte2)oEncrKeyLen;
            else
            {
#ifndef __ENABLE_DIGICERT_PFKEY__
                pxIPsecPps->p_flags |= IKE_PROP_FLAG_ENCR_KEYLEN; /* wEncrKeyLen WILDCARD */
#else
                continue; /* skip */
#endif
            }
            break;

        default : /* jic */
            GOTO_NEXT
            /*break;*/
        }

        /* auth. algo. */
        if (IPSEC_PROTO_ESP != oSecuProto)
        {
            if (oAuthAlgo)
            {
                if (NULL == pAuthAlgo) GOTO_NEXT
                pxIPsecPps->wAuthAlgo       = pAuthAlgo->wAuthAlgo;
            }
            else
            {
#ifndef __ENABLE_DIGICERT_PFKEY__
                pxIPsecPps->p_flags |= IKE_PROP_FLAG_AUTH_ALGO; /* wAuthAlgo WILDCARD */
#else
                continue; /* skip */
#endif
            }
        }

#ifdef __ENABLE_DIGICERT_PFKEY__
        oPpsNum++;
#endif
    } /* for ( */

#ifdef __ENABLE_DIGICERT_PFKEY__
    if (0 == oPpsNum)
    {
        status = ERR_IKE_EVENT;
        goto exit;
    }
    pxIPsecSa->axP2Sa[0].axChildSa[0].oIPsecPpsNum = oPpsNum;
#endif

    /* initiate exchange */
    ctx.pxSa = pxSa;

#ifdef __ENABLE_IKE_REDIRECT__
    if (IKE_KEY_MOD_REDIRECTED & pxEvt->type)
    {
        ctx.oldPeerAddr = pxEvt->dwOldPeerIP;
        ctx.wMsgType = REDIRECTED_FROM;
    }
#endif

    if (NULL != pxXg) /* [v2] IKE_SA_INIT or CREATE_CHILD_SA */
    {
        ctx.pxXg = pxXg;
        status = IKE2_xchgOut(&ctx);
    }
    else /* [v1] phase 2 quick mode */
    {
        ctx.pxP2Xg = pxP2Xg;
        status = IKE_xchgOut(&ctx);
    }

    if (OK != status)
    {
        /* already deleted */
        pxP2Xg = NULL;
        pxXg = NULL;
        goto exit;
    }

    pxIPsecSa->axP2Sa[0].dwSpdId = pxEvt->dwSpdId;
    pxIPsecSa->axP2Sa[0].spdIndex = pxEvt->spdIndex;

    if (IKE_KEY_TYPE_ACQUIRE == EVT_TYPE(pxEvt)) /* !!! */
    {
        pxIPsecSa->pxEvt = pxEvtEx;
        pxIPsecSa->dwEvtId = pxEvtEx->dwId;

        pxEvtEx->pxIPsecSa = pxIPsecSa;
        pxEvtEx->flags |= IKE_EVENT_FLAG_INXCHG;
    }

exit:
    if (OK != status)
    {
        if (ERR_IKE_EVENT == status)
        {
            EVT_DELETE(pxEvtEx)
        }

        if (NULL != pxXg)
        {
            pxXg->dwMsgId = ~((ubyte4)0); /* do *NOT* advance message ID! */
            IKE2_delXchg(pxXg, pxSa, status);
        }
        else if (NULL != pxP2Xg)
        {
            IKE_delXchg(pxP2Xg, pxSa, status);
        }
    }

#ifdef __ENABLE_DIGICERT_PFKEY__
    if (NULL != pxExIPsecPps)
        FREE(pxExIPsecPps);
#endif
    return status;
} /* IKE_evtQuick */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_evtXchg(IKESA pxSa)
{
    /* Note: referenced by IKEv1 only */
    MSTATUS status = OK;

    sbyte4 i;
    ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
    ubyte4 timeout = 1000 * m_ikeSettings.ikeTimeoutEvent;

#ifdef __IKE_MULTI_HOMING__
    sbyte4 serverInstance = pxSa->serverInstance;
#endif
    INIT_MOC_IPADDR(peerAddr, pxSa->dwPeerAddr)
#ifdef __ENABLE_IPSEC_NAT_T__
    ubyte2 wPeerPort = pxSa->wPeerPort;
    intBoolean bPeerNat = IS_PEER_BEHIND_NAT(pxSa);
#endif
    sbyte4 version = IS_IKE2_SA(pxSa) ? 2 : 1;

    /* find pending exchange */
    for (i=0; i < m_ikeEvtNum; i++)
    {
        IKEEVT_EX pxEvtEx = &(m_ikeEvt[i]);

        IKEEVT pxEvt;
        sbyte4 version0;

        if (!pxEvtEx->flags ||
#ifdef __IKE_MULTI_HOMING__
            (serverInstance != pxEvtEx->serverInstance) ||
#endif
            (IKE_EVENT_FLAG_INXCHG & pxEvtEx->flags))
            continue;

        if (timeout < (timenow - pxEvtEx->dwTimeQueued))
        {
            /* remove the negotiation status for this index*/
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) && !defined(__ENABLE_DIGICERT_GDOI_SERVER__) && defined(__ENABLE_DIGICERT_MULTICAST_MCP__)
            GDOI_resetNegotiationStatus(&pxEvtEx->evt);
#endif
            /* timed out */
            EVT_DELETE(pxEvtEx)
            continue;
        }

        pxEvt = &(pxEvtEx->evt);
        version0 = EVT_VERS(pxEvt);

        if (!version0 || (version == version0))
#ifdef __ENABLE_IPSEC_NAT_T__
        if (((0 == pxEvt->wUdpEncPort) &&
             (!bPeerNat || (IKE_NAT_UDP_PORT == wPeerPort)))
            ||
            ((wPeerPort == pxEvt->wUdpEncPort)/* && bPeerNat*/))
#endif
        {
            if (IKE_KEY_TYPE_ACQUIRE == EVT_TYPE(pxEvt)) /* quick mode */
            {
                if (SAME_MOC_IPADDR(peerAddr, pxEvt->dwDestAddr))
                    status = IKE_evtQuick(pxSa, pxEvtEx);
            }
            else /* informational */
            {
                if (SAME_MOC_IPADDR(peerAddr, pxEvt->dwSrcAddr))
                    status = IKE_evtInfo(pxSa, pxEvtEx);
            }
        }
    } /* for */

    return status;
} /* IKE_evtXchg */


/*------------------------------------------------------------------*/

#define IS_OLD_IKE_SA(_sa)  (((_sa)->flags) & (IKE_SA_FLAG_REKEYED \
                                             | IKE_SA_FLAG_DPD \
                                               ))
#define IS_OLD_IKE2_SA(_sa) (((_sa)->flags) & (IKE_SA_FLAG_DELETING \
                                             | IKE_SA_FLAG_REKEYED \
                                             | IKE_SA_FLAG_REAUTH \
                                             | IKE_SA_FLAG_DPD \
                                               ))
#define IS_OLD(_sa) (IS_IKE2_SA(_sa) ? IS_OLD_IKE2_SA(_sa) : IS_OLD_IKE_SA(_sa))

#define IS_AUTHED(_sa) (IS_IKE2_SA(_sa) ? IS_IKE2_SA_AUTHED(_sa) : IS_IKE_SA_AUTHED(_sa))


/*------------------------------------------------------------------*/

typedef struct ikesa_ev_test
{
    IKEEVT pxEvt;
    IKESA pxSa;

} *IKESA_EF_TEST;


static MSTATUS
MatchEvtFind(IKESA pxSaTmp, void *pData, intBoolean *pIsMatch)
{
#define pTest ((IKESA_EF_TEST)pData)
    MSTATUS status = OK;

    IKEEVT pxEvt = pTest->pxEvt;
    IKESA pxSa = pTest->pxSa;

#ifdef __ENABLE_IPSEC_NAT_T__
    ubyte2 wUdpEncPort = pxEvt->wUdpEncPort;
#endif

    *pIsMatch = FALSE;

    /* check version */
    switch (EVT_VERS(pxEvt))
    {
    case 1 :
        if (IS_IKE2_SA(pxSaTmp)) goto exit;
        break;
    case 2 :
        if (!IS_IKE2_SA(pxSaTmp)) goto exit;
        break;
    }

#ifdef __ENABLE_IPSEC_NAT_T__
    /* See RFC 3947 6. p.11 */
    if (!(
          ((0 == wUdpEncPort) &&
           (!IS_PEER_BEHIND_NAT(pxSaTmp) ||
            (IKE_NAT_UDP_PORT == pxSaTmp->wPeerPort)))
          ||
          ((wUdpEncPort == pxSaTmp->wPeerPort)/* && IS_PEER_BEHIND_NAT(pxSaTmp)*/)
          ))
    {
        goto exit;
    }
#endif
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    if ((IKE_KEY_MOD_GDOI & pxEvt->type) && !(IKE_SA_FLAG_GDOI & pxSaTmp->flags))
    {
        goto exit;
    }
#endif

    /* completed exchange */
    if (IS_AUTHED(pxSaTmp))
    {
        /* get the most recent */
        if (NULL == pxSa)
        {
            pTest->pxSa = pxSaTmp;
        }
        else
        {
            intBoolean bOld = IS_OLD(pxSa);
            intBoolean bOldTmp = IS_OLD(pxSaTmp);

            if ((bOld && bOldTmp) || (!bOld && !bOldTmp))
            {
                ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);

                if ((timenow - pxSa->dwTimeCreated) >
                    (timenow - pxSaTmp->dwTimeCreated))
                {
                    pTest->pxSa = pxSaTmp;
                }
            }
            else if (bOld)
            {
                pTest->pxSa = pxSaTmp;
            }
        }

        goto exit;
    }

    /* exchange in progress */
    if (IS_INITIATOR(pxSaTmp) /* initiator only - in case of attack */
#ifdef __ENABLE_IKE_XAUTH__
     || IS_P1_FINAL_STATE(pxSaTmp->oState)
#endif
        )
    {
        *pIsMatch = TRUE; /* !!! */
    }

exit:
    return status;
#undef pTest
} /* MatchEvtFind */


/*------------------------------------------------------------------*/

static MSTATUS
IKE_evtFindSa(IKEEVT pxEvt, IKESA *ppxSa MOC_MTHM(serverInstance))
{
    MSTATUS status;

    MOC_IP_ADDRESS peerAddr;

    struct ikesa_ev_test saTest;
    saTest.pxEvt = pxEvt;
    saTest.pxSa = NULL;

    IKE_evtGetAddr(pxEvt, NULL, &peerAddr);

    /* find IKE_SA */
    if (OK > (status = IKE_getSaByAddr(peerAddr, ppxSa,
                                       &saTest, MatchEvtFind
                                       MOC_MTHM_VALUE(serverInstance))))
    {
        /* This should never happen, but we are setting status to OK to
           satisfy the static analyzer */
        status = OK;
        goto exit;
    }
    if (NULL != *ppxSa)
        status = ERR_IKE_GETSA_FAIL; /* should wait */
    else
        *ppxSa = saTest.pxSa;

exit:
    return status;
} /* IKE_evtFindSa */


/*------------------------------------------------------------------*/

static MSTATUS
IKE_evtInit(IKEEVT_EX pxEvtEx, IKESA pxSaOld, IKESA *ppxSaNew)
{
    MSTATUS status = OK;

    IKEEVT pxEvt = &(pxEvtEx->evt);

    MOC_IP_ADDRESS peerAddr;
    ubyte2 wPeerPort;
    ikePeerConfig *config;

#ifdef __ENABLE_IPSEC_NAT_T__
    intBoolean bUseNattPort;
#endif
#ifdef __IKE_MULTI_HOMING__
    sbyte4 serverInstance;
#endif
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
    ubyte oExchange;
#endif
    IKESA pxSa;

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    intBoolean bGdoi = (IKE_KEY_MOD_GDOI & pxEvt->type) ? TRUE : FALSE;
#endif

    IKE_evtGetAddr(pxEvt, NULL, &peerAddr);

    if (NULL != pxSaOld)
    {
        config = pxSaOld->ikePeerConfig;
        wPeerPort = pxSaOld->wPeerPort;
#ifdef __ENABLE_IPSEC_NAT_T__
        bUseNattPort = USE_NATT_PORT(pxSaOld);
#endif
#ifdef __IKE_MULTI_HOMING__
        serverInstance = pxSaOld->serverInstance;
#endif
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
        switch (pxSaOld->oState)
        {
        case STATE_AGGR_I :
        case STATE_AGGR_R :
            oExchange = ISAKMP_XCHG_AGGR;
            break;
        default :
            oExchange = ISAKMP_XCHG_IDPROT;
            break;
        }
#endif
    }
    else
    {
        if (NULL == (config = IKE_findPeerConfigFromEvent(pxEvtEx)))
        {
            status = ERR_IKE_NO_PEER_CONFIG;
            goto exit;
        }

#ifdef __IKE_MULTI_HOMING__
        serverInstance = pxEvtEx->serverInstance;
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
        wPeerPort = pxEvt->wUdpEncPort;
        bUseNattPort = ((wPeerPort && (wPeerPort != IKE_DEFAULT_UDP_PORT))
                     || (IKE_EVENT_FLAG_NATT & pxEvtEx->flags))
                     ? TRUE : FALSE;
        if (bUseNattPort && (IKE_DEFAULT_UDP_PORT == wPeerPort))
            wPeerPort = IKE_NAT_UDP_PORT;
        else if (!wPeerPort)
            wPeerPort = (bUseNattPort ? IKE_NAT_UDP_PORT
                                      : IKE_DEFAULT_UDP_PORT);
#else
        wPeerPort = IKE_DEFAULT_UDP_PORT;
#endif
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
        if (bGdoi && (IKE_DEFAULT_UDP_PORT == wPeerPort))
            wPeerPort = IKE_GDOI_UDP_PORT;
#endif
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
        oExchange = config->ikeP1Mode;
#endif
    }

    /* new IKE SA */
    if (NULL == (pxSa = IKE_newSa(config, peerAddr, wPeerPort, NULL
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
                                , oExchange
#endif
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__)
                                , bGdoi
#elif defined(__ENABLE_DIGICERT_GDOI_SERVER__)
                                , FALSE
#endif
                                  MOC_NATT_VALUE(bUseNattPort)
                                  MOC_MTHM_VALUE(serverInstance))))
    {
        status = ERR_IKE_NEWSA_FAIL;
        goto exit;
    }

    /* initiate phase 1 exchange */
    {
        struct ike_context ctx = { NULL };
        ctx.pxSa = pxSa;

        if (IKE_KEY_MOD_INITC & pxEvt->type)
            pxSa->flags |= IKE_SA_FLAG_TX_INIT_C;

        if (OK <= (status = IKE_xchgOut(&ctx)))
        {
            /* rekeying started */
            if ((NULL != pxSaOld) &&
                !IS_OLD_IKE_SA(pxSaOld) &&
                !(IKE_SA_FLAG_DELETED & pxSaOld->flags))
            {
                pxSaOld->pxSaRekey = pxSa;
                pxSaOld->dwSaRekeyId = pxSa->dwId;
            }

            if (NULL != ppxSaNew) *ppxSaNew = pxSa;
        }
    }

exit:
    return status;
} /* IKE_evtInit */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PFKEY__

typedef struct ike2_event_callback
{
    struct ipsecKey key;

    IKESA pxSa;
    ubyte4 dwSaId;

    struct ike_event_q evt;

} *IKE2EVT_CB;


static sbyte4
IKE2_evtCallback(sbyte4 status, void *cbData)
{
    IKESA pxSa = ((IKE2EVT_CB)cbData)->pxSa;
    IKEEVT_EX pxEvtEx;

    IKE_LOCK_W; /* !!! */

    /* validity check */
    if (!IS_VALID(pxSa) ||
        !IS_IKE2_SA(pxSa) ||
        (((IKE2EVT_CB)cbData)->dwSaId != pxSa->dwId))
    {
        status = ERR_IKE_BAD_SA;
        pxSa = NULL; /* !!! */
        goto exit;
    }

    pxSa->merror = OK; /* !!! */

    if (OK > (MSTATUS)status)
        goto exit;

    pxEvtEx = (IKEEVT_EX) &(((IKE2EVT_CB)cbData)->evt);

    if ((ubyte4)255 >=
        (pxEvtEx->evt.dwSpi = ((IKE2EVT_CB)cbData)->key.dwSpi))
    {
        status = ERR_IKE_BAD_SPI;
        goto exit;
    }

    status = IKE_evtQuick(pxSa, pxEvtEx);

exit:
    if (OK > status)
    {
        if ((NULL != pxSa) && IS_VALID(pxSa))
            IKE2_delSa(pxSa, FALSE, status);
    }

    IKE_UNLOCK_W;

    FREE(cbData);
    return status;
} /* IKE2_evtCallback */

#endif /* __ENABLE_DIGICERT_PFKEY__ */


/*------------------------------------------------------------------*/

static MSTATUS
IKE2_evtInit(IKEEVT_EX pxEvtEx, IKESA pxSaOld, IKESA *ppxSaNew)
{
    MSTATUS status = OK;

    IKEEVT pxEvt = &(pxEvtEx->evt);

    MOC_IP_ADDRESS peerAddr;
    ubyte2 wPeerPort;
    ikePeerConfig *config;

#ifdef __ENABLE_IPSEC_NAT_T__
    intBoolean bUseNattPort;
#endif
#ifdef __IKE_MULTI_HOMING__
    sbyte4 serverInstance;
#endif
    IKESA pxSa = NULL;

#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    sbyte4 eap_proto_t;
    const IKE_eapSuiteInfo *pEapSuite;
#endif

    /* IKE_SA_INIT requires a piggybacked CHILD_SA */
    switch (EVT_TYPE(pxEvt))
    {
    case IKE_KEY_TYPE_ACQUIRE :
    case IKE_KEY_TYPE_SAINIT :
        break;
    default :
        status = ERR_IKE_GETSA_FAIL;
        /* remove event from queue */
        EVT_DELETE(pxEvtEx)
        goto exit;
    }

    peerAddr = REF_MOC_IPADDR(pxEvt->dwDestAddr);
    /*IKE_evtGetAddr(pxEvt, NULL, &peerAddr);*/

    if (NULL != pxSaOld)
    {
        config = pxSaOld->ikePeerConfig;
        wPeerPort = pxSaOld->wPeerPort;
#ifdef __ENABLE_IPSEC_NAT_T__
        bUseNattPort = USE_NATT_PORT(pxSaOld);
#endif
#ifdef __IKE_MULTI_HOMING__
        serverInstance = pxSaOld->serverInstance;
#endif
    }
    else
    {
        if (NULL == (config = IKE_findPeerConfigFromEvent(pxEvtEx)))
        {
            status = ERR_IKE_NO_PEER_CONFIG;
            goto exit;
        }

#ifdef __IKE_MULTI_HOMING__
        serverInstance = pxEvtEx->serverInstance;
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
        wPeerPort = pxEvt->wUdpEncPort;
        bUseNattPort = ((wPeerPort && (wPeerPort != IKE_DEFAULT_UDP_PORT))
                     || (IKE_EVENT_FLAG_NATT & pxEvtEx->flags))
                     ? TRUE : FALSE;
        if (bUseNattPort && (IKE_DEFAULT_UDP_PORT == wPeerPort))
            wPeerPort = IKE_NAT_UDP_PORT;
        else if (!wPeerPort)
            wPeerPort = (bUseNattPort ? IKE_NAT_UDP_PORT
                                      : IKE_DEFAULT_UDP_PORT);
#else
        wPeerPort = IKE_DEFAULT_UDP_PORT;
#endif
    }

    /* use EAP auth? */
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    if ((NULL != pxSaOld) && (IKE_SA_FLAG_ORIG_INITR & pxSaOld->flags))
    {
        eap_proto_t = pxSaOld->u.v2.eapState.proto;
    }
    else
    {
#ifdef CUSTOM_IKE_GET_EAP_PROTO
        const ubyte *poId;
        ubyte2 wIdLen=0;
        sbyte4 id_t=0;
#ifdef CUSTOM_IKE_GET_ID
        if (OK > CUSTOM_IKE_GET_ID(&poId, &wIdLen, &id_t,
                                peerAddr, _IN /* peer */, TRUE /* supplicant */
                                MOC_MTHM_REQ_VALUE(serverInstance)))
#else
        /* IDr unknown yet */
#endif
        poId = NULL;
        status = CUSTOM_IKE_GET_EAP_PROTO(&eap_proto_t,
                                poId, wIdLen, id_t,
                                peerAddr, _IN, TRUE
                                MOC_MTHM_REQ_VALUE(serverInstance));
        if (STATUS_IKE_CUSTOM_CONTINUE != status)
        {
            if (OK > status) eap_proto_t = 0;
        }
        else
#endif /* CUSTOM_IKE_GET_EAP_PROTO */
        {
            eap_proto_t = config->eapProtoPeer;
        }
    }

    if (OK > (status = IKE_eapSuite((IKE_EAP_PROTO_T)eap_proto_t, TRUE,
                                    &pEapSuite)))
    {
        /* DEBUG_EXIT */
        goto exit;
    }
#endif /* defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */

    /* new IKE_SA */
    if (NULL == (pxSa = IKE2_newSa(config, peerAddr, wPeerPort, NULL, NULL
                                   MOC_NATT_VALUE(bUseNattPort)
                                   MOC_MTHM_VALUE(serverInstance))))
    {
        status = ERR_IKE_NEWSA_FAIL;
        goto exit;
    }

    if (IKE_KEY_MOD_INITC & pxEvt->type)
        pxSa->flags |= IKE_SA_FLAG_TX_INIT_C;

#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    if (NULL != pEapSuite)
        pxSa->flags |= IKE_SA_FLAG_EAP; /* use EAP auth. */
#endif

#ifdef __ENABLE_DIGICERT_PFKEY__
    if (IKE_KEY_TYPE_SAINIT == EVT_TYPE(pxEvt))
    {
        /* get SPI */
        IKE2EVT_CB cb;
        IPSECKEY key;

        INIT_MOC_IPADDR(dstAddr, pxEvt->dwSrcAddr)
        INIT_MOC_IPADDR(srcAddr, pxEvt->dwDestAddr)

        if (NULL == (cb = (IKE2EVT_CB) MALLOC(sizeof(struct ike2_event_callback))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        key = &(cb->key);
        DIGI_MEMSET((ubyte *)key, 0x00, sizeof(struct ipsecKey));

        key->oProtocol      = (IPSEC_PROTO_AH == pxEvt->pxSa[0].oSecuProto)
                            ? IPPROTO_AH : IPPROTO_ESP;
/*      key->flags          = IPSEC_SA_FLAG_INITIATOR; */ /* dwSeqNo not set yet!!! */

        TEST_MOC_IPADDR6(dstAddr,
        {
            key->flags     |= IPSEC_SA_FLAG_IP6;
            key->dwDestAddr = (CAST_MOC_IPADDR) GET_MOC_IPADDR6(dstAddr);
            key->dwSrcAddr  = (CAST_MOC_IPADDR) GET_MOC_IPADDR6(srcAddr);
        })
        {
            key->dwDestAddr = GET_MOC_IPADDR4(dstAddr);
            key->dwSrcAddr  = GET_MOC_IPADDR4(srcAddr);
        }
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if (IPSEC_MODE_TUNNEL == pxEvt->oMode)
            key->oMode      = IPSEC_MODE_TUNNEL;
        else
#endif
            key->oMode      = IPSEC_MODE_TRANSPORT;
        key->funcPtrPfkeyCb = IKE2_evtCallback;

        cb->pxSa = pxSa;
        cb->dwSaId = pxSa->dwId;

        cb->evt = *pxEvtEx;

        if (OK > (status = IPSEC_keySpi(key)))
        {
            if (STATUS_IKE_PENDING == status)
            {
                if (NULL != ppxSaNew) *ppxSaNew = pxSa;
                pxSa->merror = STATUS_IKE_PENDING;
                status = OK;
            }
            else FREE(cb);
            goto exit;
        }

        pxEvt->dwSpi = key->dwSpi;
        FREE(cb); /* !!! */
    }
#endif

    /* initiate IKE_SA_INIT exchange */
    if (OK > (status = IKE_evtQuick(pxSa, pxEvtEx)))
        goto exit;

    if (NULL != ppxSaNew) *ppxSaNew = pxSa;

exit:
    if (OK > status)
    {
        if ((NULL != pxSa) && IS_VALID(pxSa))
            IKE2_delSa(pxSa, FALSE, status);
    }
    return status;
} /* IKE2_evtInit */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)

static void
PrintEvent(IKEEVT pxEvt)
{
    ubyte2 type = EVT_TYPE(pxEvt);

    debug_uptime();
    debug_print(" ");

    switch (type)
    {
    case IKE_KEY_TYPE_ACQUIRE :
        debug_print("Acquire");
        break;
    case IKE_KEY_TYPE_SUSPEND :
        debug_print("Suspend");
        break;
    case IKE_KEY_TYPE_DELETED :
        debug_print("Deleted");
        break;
    case IKE_KEY_TYPE_CONNECTED :
        debug_print("Connected");
        break;
    case IKE_KEY_TYPE_ABORTED :
        debug_print("Aborted");
        break;
    case IKE_KEY_TYPE_SAINIT :
        debug_print("SA_INIT");
        break;
    default :
        debug_print("Unknown");
        break;
    }
    debug_print(" ");

    /* new event */
    switch (type)
    {
    case IKE_KEY_TYPE_ACQUIRE :
    case IKE_KEY_TYPE_SUSPEND :
    {
#if !defined(__DISABLE_IPSEC_TUNNEL_MODE__) || defined(__ENABLE_DIGICERT_GDOI_CLIENT__)
        intBoolean bTunOrGdoi = FALSE;
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
        if (IPSEC_MODE_TUNNEL == pxEvt->oMode) bTunOrGdoi = TRUE;
#endif
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
        if (IKE_KEY_MOD_GDOI & pxEvt->type) bTunOrGdoi = TRUE;
#endif
        if (bTunOrGdoi)
        {
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
            if (pxEvt->fqdn[0])
            {
                debug_print(pxEvt->fqdn);
            }
            else
#endif
            {
                INIT_MOC_IPADDR(destIP, pxEvt->dwDestIP)
                    debug_print_ip(destIP);
                if (!SAME_MOC_IPADDR(destIP, pxEvt->dwDestIPEnd))
                {
                    debug_print("~");
                    debug_print_ip(REF_MOC_IPADDR(pxEvt->dwDestIPEnd));
                }
            }
        }
        else
#endif
        debug_print_ip(REF_MOC_IPADDR(pxEvt->dwDestAddr));

        if (0 != pxEvt->wDestPort)
        {
            debug_print("[");
            debug_int(pxEvt->wDestPort);
            debug_print("]");
        }

        debug_print(" < ");

#if !defined(__DISABLE_IPSEC_TUNNEL_MODE__) || defined(__ENABLE_DIGICERT_GDOI_CLIENT__)
        if (bTunOrGdoi)
        {
            INIT_MOC_IPADDR(srcIP, pxEvt->dwSrcIP)
            debug_print_ip(srcIP);
            if (!SAME_MOC_IPADDR(srcIP, pxEvt->dwSrcIPEnd))
            {
                debug_print("~");
                debug_print_ip(REF_MOC_IPADDR(pxEvt->dwSrcIPEnd));
            }
        }
        else
#endif
        debug_print_ip(REF_MOC_IPADDR(pxEvt->dwSrcAddr));

        if (0 != pxEvt->wSrcPort)
        {
            debug_print("[");
            debug_int(pxEvt->wSrcPort);
            debug_print("]");
        }
        if (0 != pxEvt->oUlp)
        {
            debug_print(" ");
            debug_print_ip_proto(pxEvt->oUlp);
        }

#if !defined(__DISABLE_IPSEC_TUNNEL_MODE__) || defined(__ENABLE_DIGICERT_GDOI_CLIENT__)
        if (bTunOrGdoi)
        {
            debug_print(" ");
            debug_print_ip(REF_MOC_IPADDR(pxEvt->dwDestAddr));
            debug_print(" << ");
            debug_print_ip(REF_MOC_IPADDR(pxEvt->dwSrcAddr));
        }
#endif
        break;
    }
    case IKE_KEY_TYPE_DELETED :
    case IKE_KEY_TYPE_CONNECTED :
    case IKE_KEY_TYPE_ABORTED :
        if (pxEvt->dwSpi)
        {
            debug_print(((IPPROTO_AH == pxEvt->oProtocol) ? "AH" : "ESP"));
            debug_print(" spi=");
            debug_hexint(pxEvt->dwSpi);
            debug_print(" ");
        }
        if (!(IKE_KEY_MOD_OUTBOUND & pxEvt->type))
        {
            debug_print("src=");
            debug_print_ip(REF_MOC_IPADDR(pxEvt->dwSrcAddr));
            break;
        }
        /* fall through */
    case IKE_KEY_TYPE_SAINIT :
        debug_print("dest=");
        debug_print_ip(REF_MOC_IPADDR(pxEvt->dwDestAddr));
        break;

    default :
        break;
    } /* switch */
} /* PrintEvent */

#else
#define PrintEvent(_evt)
#endif /* defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__) */


/*------------------------------------------------------------------*/

#ifdef __IKE_UPDATE_TIMER__
#define ResetExpTimerEvent(_e, _t) \
    IKE_DEL_TIMER_EVT((_e)->expTimerId, (_e)->expTimerHdl) \
    if (OK > IKE_ADD_TIMER_EVT(_t, 0, _e, \
                               IKE_evtExpTimerEvent, "TOE", \
                               (_e)->expTimerId, (_e)->expTimerHdl)) \
    { \
        debug_printnl("Failed to schedule timer for event timeout."); \
    }
#endif

static MSTATUS
DoDupEvt(IKEEVT pxEvt, IKEEVT_EX *ppxEvtEx, ubyte4 timenow
         MOC_MTHM(serverInstance) MOC_NATT(bUseNattPort))
{
    MSTATUS status = OK;

    sbyte4 i;
    IKEEVT_EX pxEvtEx = NULL;

    ubyte4 timeout = 1000 * m_ikeSettings.ikeTimeoutEvent;
    ubyte4 timeQueued = timenow - timeout + 10000; /* expire in 10 secs - FOR NOW */

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    intBoolean bGdoi = (IKE_KEY_MOD_GDOI & pxEvt->type) ? TRUE : FALSE;
#endif
    INIT_MOC_IPADDR(destAddr,   pxEvt->dwDestAddr)
    INIT_MOC_IPADDR(srcAddr,    pxEvt->dwSrcAddr)

#if !defined(__DISABLE_IPSEC_TUNNEL_MODE__) || defined(__ENABLE_DIGICERT_GDOI_CLIENT__)
    INIT_MOC_IPADDR(destIP,     pxEvt->dwDestIP)
    INIT_MOC_IPADDR(destIPEnd,  pxEvt->dwDestIPEnd)
    INIT_MOC_IPADDR(srcIP,      pxEvt->dwSrcIP)
    INIT_MOC_IPADDR(srcIPEnd,   pxEvt->dwSrcIPEnd)

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    if (IPSEC_MODE_TUNNEL != pxEvt->oMode)
#endif
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
        if (!bGdoi)
#endif
    {
        destIP = destIPEnd = destAddr;
        srcIP = srcIPEnd = srcAddr;
    }
#endif

    /* find duplicate event */
    for (i=0; i < m_ikeEvtNum; i++, pxEvtEx = NULL)
    {
        IKEEVT pxEvtTmp;

        pxEvtEx = &(m_ikeEvt[i]);
        if (!pxEvtEx->flags) continue;

        if (timeout < (timenow - pxEvtEx->dwTimeQueued))
        {
            /* timed out */
            EVT_DELETE(pxEvtEx)
            continue;
        }

        pxEvtTmp = &(pxEvtEx->evt);

        if ((IKE_KEY_TYPE_ACQUIRE == EVT_TYPE(pxEvtTmp)) &&
#ifndef __ENABLE_DIGICERT_PFKEY__
            (pxEvt->dwSpdId == pxEvtTmp->dwSpdId) &&
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
            ((pxEvt->wUdpEncPort == pxEvtTmp->wUdpEncPort) ||
             (!pxEvt->wUdpEncPort && /* special case */
              (IKE_NAT_UDP_PORT == pxEvtTmp->wUdpEncPort))) &&
#endif
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
            ((IKE_KEY_MOD_GDOI & pxEvt->type) == (IKE_KEY_MOD_GDOI & pxEvtTmp->type)) &&
#endif
            (pxEvt->wDestPort == pxEvtTmp->wDestPort) &&
            (pxEvt->wSrcPort == pxEvtTmp->wSrcPort) &&
            (pxEvt->oUlp == pxEvtTmp->oUlp))
        {
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
            if (bGdoi)
            {
                if (!((SAME_MOC_IPADDR(destIP,   pxEvtTmp->dwDestIP) &&
                      SAME_MOC_IPADDR(destIPEnd,pxEvtTmp->dwDestIPEnd) &&
                      SAME_MOC_IPADDR(srcIP,    pxEvtTmp->dwSrcIP) &&
                      SAME_MOC_IPADDR(srcIPEnd, pxEvtTmp->dwSrcIPEnd))
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
                    && (pxEvt->fqdn[0] &&  pxEvtTmp->fqdn[0] && !DIGI_STRCMP((sbyte *) pxEvt->fqdn, (sbyte *) pxEvtTmp->fqdn))
#endif
                    ))
                    continue;

                if (!(SAME_MOC_IPADDR(destAddr, pxEvtTmp->dwDestAddr) &&
                      SAME_MOC_IPADDR(srcAddr,  pxEvtTmp->dwSrcAddr)))
                    continue;
            }
            else
#endif
            if (IPSEC_MODE_TUNNEL == pxEvtTmp->oMode)
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
            {
                if (!(SAME_MOC_IPADDR(destIP,   pxEvtTmp->dwDestIP) &&
                      SAME_MOC_IPADDR(destIPEnd,pxEvtTmp->dwDestIPEnd) &&
                      SAME_MOC_IPADDR(srcIP,    pxEvtTmp->dwSrcIP) &&
                      SAME_MOC_IPADDR(srcIPEnd, pxEvtTmp->dwSrcIPEnd)))
                    continue;
            }
            else if (IPSEC_MODE_TUNNEL == pxEvt->oMode)
            {
                if (!(SAME_MOC_IPADDR(destIP,   pxEvtTmp->dwDestAddr) &&
                      SAME_MOC_IPADDR(destIPEnd,pxEvtTmp->dwDestAddr) &&
                      SAME_MOC_IPADDR(srcIP,    pxEvtTmp->dwSrcAddr) &&
                      SAME_MOC_IPADDR(srcIPEnd, pxEvtTmp->dwSrcAddr)))
                    continue;
            }
#else
            {
                if (!(SAME_MOC_IPADDR(destAddr, pxEvtTmp->dwDestIP) &&
                      SAME_MOC_IPADDR(destAddr, pxEvtTmp->dwDestIPEnd) &&
                      SAME_MOC_IPADDR(srcAddr,  pxEvtTmp->dwSrcIP) &&
                      SAME_MOC_IPADDR(srcAddr,  pxEvtTmp->dwSrcIPEnd)))
                    continue;
            }
#endif
            else
            {
                if (!(SAME_MOC_IPADDR(destAddr, pxEvtTmp->dwDestAddr) &&
                      SAME_MOC_IPADDR(srcAddr,  pxEvtTmp->dwSrcAddr)))
                    continue;
            }

            /* duplicate found */
            if (IKE_KEY_TYPE_ACQUIRE == EVT_TYPE(pxEvt))
            {
                if (!(IKE_EVENT_FLAG_INXCHG & pxEvtEx->flags))
                {
                    pxEvtEx->dwTimeQueued = timenow;
#ifdef __IKE_UPDATE_TIMER__
                    ResetExpTimerEvent(pxEvtEx, timeout)
#endif
                }
                status = ERR_IKE_EVENT; /* !!! for now */
            }
            else /* IKE_KEY_TYPE_SUSPEND */
            {
                /* stop exchange */
                if (IKE_EVENT_FLAG_INXCHG & pxEvtEx->flags)
                {
                    IPSECSA pxIPsecSa = pxEvtEx->pxIPsecSa;
                    if ((NULL != pxIPsecSa) &&
                        IS_VALID_CHILD(pxIPsecSa) &&
                        (pxEvtEx == pxIPsecSa->pxEvt) &&
                        (pxEvtEx->dwId == pxIPsecSa->dwEvtId))
                    {
                        if (IKE_CHILD_FLAG_V2 & pxIPsecSa->c_flags) /* [v2] */
                        {
                        }
                        else /* [v1] */
                        if (STATE_QUICK_I2c != pxIPsecSa->oState) /* not COMMIT state */
                        {
                            IKE_delIPsecSa(pxIPsecSa, NULL); /* pxSa!!! */

                            if (STATE_QUICK_I != pxIPsecSa->oState)
                            {
                                pxEvtEx->dwTimeQueued = timeQueued;
                                pxEvtEx->flags |= IKE_EVENT_FLAG_INXCHG;
#ifdef __IKE_UPDATE_TIMER__
                                IKE_DEL_TIMER_EVT(pxEvtEx->initTimerId, pxEvtEx->initTimerHdl) /* !!! */
                                ResetExpTimerEvent(pxEvtEx, 10000)
#endif
                            }
                        }
                    }
                    else
                    {
                        if (NULL != pxIPsecSa)
                        {
                            pxEvtEx->pxIPsecSa = NULL;

                            if (IS_VALID_CHILD(pxIPsecSa) &&
                                (pxEvtEx == pxIPsecSa->pxEvt))
                                pxIPsecSa->pxEvt = NULL;
                        }
                        pxEvtEx->dwTimeQueued = timeQueued;
#ifdef __IKE_UPDATE_TIMER__
                        ResetExpTimerEvent(pxEvtEx, 10000)
#endif
                    }
                }
                else
                {
                    pxEvtEx->dwTimeQueued = timeQueued;
                    pxEvtEx->flags |= IKE_EVENT_FLAG_INXCHG;
#ifdef __IKE_UPDATE_TIMER__
                    IKE_DEL_TIMER_EVT(pxEvtEx->initTimerId, pxEvtEx->initTimerHdl)
                    ResetExpTimerEvent(pxEvtEx, 10000)
#endif
                }
            }

            break; /* found */
        }
    } /* for */

    if ((NULL == pxEvtEx) &&
        (IKE_KEY_TYPE_SUSPEND == EVT_TYPE(pxEvt)))
    {
        IKEEVT_EX pxEvtExTmp; /* !!! */

        /* prevent initiating exchanges */
        if (OK <= (status = IKE_evtQueue(&pxEvtExTmp, pxEvt
                                         MOC_MTHM_VALUE(serverInstance)
                                         MOC_NATT_VALUE(bUseNattPort))))
        {
            pxEvtExTmp->dwTimeQueued = timeQueued;
            pxEvtExTmp->flags |= IKE_EVENT_FLAG_INXCHG;
            pxEvtExTmp->evt.type = IKE_KEY_TYPE_ACQUIRE;
#ifdef __IKE_UPDATE_TIMER__
            ResetExpTimerEvent(pxEvtExTmp, 10000)
#endif
        }
    }

    if (NULL != ppxEvtEx)
        *ppxEvtEx = pxEvtEx;

    return status;
} /* DoDupEvt */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_evtAcquire(IKESA pxSa, IPSECSA pxIPsecSa, ubyte2 type,
               ubyte4 dwSpdId, intBoolean bTransport)
{
    sbyte4 _r = IS_CHILD_INITIATOR(pxIPsecSa) ? _R : _I;

    /* prevent initiating exchanges */
    struct ike_event evt = { 0 };

    evt.type            = type;

    evt.dwDestAddr      = pxSa->dwPeerAddr;
    evt.dwSrcAddr       = pxSa->dwHostAddr;

#ifdef __ENABLE_IPSEC_NAT_T__
    evt.wUdpEncPort     = IS_PEER_BEHIND_NAT(pxSa) ? pxSa->wPeerPort : 0;
#endif
    evt.dwIkeSaId       = pxSa->dwId;
    evt.ikeSaLoc        = pxSa->loc;

    evt.wDestPort       = pxIPsecSa->wPort[_r];
    evt.wSrcPort        = pxIPsecSa->wPort[!_r];

    evt.oUlp            = pxIPsecSa->oUlp;

#ifdef __DISABLE_IPSEC_TUNNEL_MODE__
    MOC_UNUSED(bTransport);
#else
    if (!bTransport)
    {
        evt.oMode       = IPSEC_MODE_TUNNEL;

        evt.dwDestIP    = pxIPsecSa->dwIP[_r];
        evt.dwDestIPEnd = pxIPsecSa->dwIPEnd[_r];

        evt.dwSrcIP     = pxIPsecSa->dwIP[!_r];
        evt.dwSrcIPEnd  = pxIPsecSa->dwIPEnd[!_r];
    }
    else
#endif
        evt.oMode       = IPSEC_MODE_TRANSPORT;

#ifdef __ENABLE_IPSEC_INTERFACE_ID__
    evt.ifid            = pxSa->ifid;
#endif
    SET_MOC_COOKIE(evt.cookie, pxSa->cookie)

    evt.dwSpdId         = dwSpdId;

    return DoDupEvt(&evt, NULL,
                    RTOS_deltaMS(&gStartTime, NULL)
                    MOC_MTHM_VALUE(pxSa->serverInstance)
                    MOC_NATT_VALUE(FALSE));
} /* IKE_evtAcquire */


/*------------------------------------------------------------------*/

#ifdef CUSTOM_IKE_GET_VERSION

static MSTATUS
GetVersion_I(ikePeerConfig* config, sbyte4 *version, IKEEVT pxEvt, sbyte4 serverInstance)
{
    MSTATUS status;

    sbyte4 num = 1;
    MOC_IP_ADDRESS peerAddr;

    if (NULL == config)
        return ERR_IKE_NO_PEER_CONFIG;

    if (OK > (status = IKE_evtGetAddr(pxEvt, NULL, &peerAddr)))
        goto exit;

    status = CUSTOM_IKE_GET_VERSION(version, &num, peerAddr,
                                    0, TRUE, /* initiator */
                                    serverInstance);
    if (STATUS_IKE_CUSTOM_CONTINUE != status)
    {
        if (OK > status) goto exit;

        if (1 > num)
        {
            status = STATUS_IKE_CUSTOM_NONE;
            goto exit;
        }
    }
    else
    {
        status = OK;
        *version = config->ikeVersion;
    }

exit:
    return status;
} /* GetVersion_I */

#endif


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PFKEY__

typedef struct ike_event_callback
{
    struct ipsecKey key;
    struct ike_event evt;
    sbyte4 serverInstance;
    intBoolean bUseNattPort;

} *IKEEVT_CB;


static sbyte4
IKE_evtCallback(sbyte4 status, void *cbData)
{
    IKEEVT pxEvt;

    if (OK > (MSTATUS)status)
    {
        status = (sbyte4)OK;
        goto exit;
    }

    pxEvt = (IKEEVT) &(((IKEEVT_CB)cbData)->evt);
    pxEvt->dwSpi = ((IKEEVT_CB)cbData)->key.dwSpi;

    if ((ubyte4)255 >= pxEvt->dwSpi)
    {
        status = ERR_IKE_BAD_SPI;
        goto exit;
    }

    status = IKE_evtRecv(pxEvt,
                         ((IKEEVT_CB)cbData)->serverInstance,
                         ((IKEEVT_CB)cbData)->bUseNattPort);

exit:
    FREE(cbData);
    return status;
} /* IKE_evtCallback */

#endif /* __ENABLE_DIGICERT_PFKEY__ */


/*------------------------------------------------------------------*/

#ifdef __IKE_UPDATE_TIMER__
#define SetInitTimerEvent(_e, _t) \
    if (OK > (status = IKE_ADD_TIMER_EVT(_t, _t, _e, \
                                         IKE_evtInitTimerEvent, "RTE", \
                                         (_e)->initTimerId, (_e)->initTimerHdl))) \
    { \
        debug_printnl("Failed to schedule timer for event initiation."); \
    }
#endif

extern MSTATUS
IKE_evtRecvEx(ikePeerConfig* config,
              IKEEVT pxEvt, sbyte4 serverInstance, intBoolean bUseNattPort)
{
    MSTATUS status = OK;

    sbyte4 saLoc = pxEvt->ikeSaLoc;
    ubyte4 dwSaId = pxEvt->dwIkeSaId;

    ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
    IKESA pxSa = NULL;

    intBoolean bInitIkeSa = FALSE;

    sbyte4 version = EVT_VERS(pxEvt);
    ubyte2 type = EVT_TYPE(pxEvt);

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    intBoolean bGdoi = (IKE_KEY_MOD_GDOI & pxEvt->type) ? TRUE : FALSE;
#endif

    IKEEVT_EX pxEvtEx; /* queued event */

    if (NULL == config)
        return ERR_IKE_NO_PEER_CONFIG;

#ifndef __IKE_MULTI_HOMING__
    MOC_UNUSED(serverInstance);
#endif
#ifndef __ENABLE_IPSEC_NAT_T__
    MOC_UNUSED(bUseNattPort);
#endif

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    if (bGdoi && (IKE_KEY_TYPE_ACQUIRE == type))
    {
        /* set GDOI Key Server as peer (dest) address */
        MOC_IP_ADDRESS_S keyServerAddr = config->keyServerAddr;

        if (NULL != m_ikeSettings.funcPtrIkeGetHostAddr) /* jic */
        {
            m_ikeSettings.funcPtrIkeGetHostAddr(&pxEvt->dwSrcAddr,
                                                serverInstance);
        }
        if (ISZERO_MOC_IPADDR(keyServerAddr)
#ifdef __ENABLE_DIGICERT_IPV6__
         || (keyServerAddr.family != pxEvt->dwSrcAddr.family)
#endif
            )
        {
            debug_printnl("IKE_evtRecvEx: Invalid GDOI server address!");
            status = ERR_IKE_CONFIG;
            goto exit;
        }
        pxEvt->dwDestAddr = keyServerAddr;
    }
#endif

    PrintEvent(pxEvt);

    /* new event */
    switch (type)
    {
    case IKE_KEY_TYPE_ACQUIRE :
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
        if (bGdoi)
        {
            /* GDOI: only 'dest' info is applicable; reverse and set as 'src' */
            MOC_IP_ADDRESS_S tmpAddr;
            ubyte2 tmpPort;

            tmpAddr = pxEvt->dwSrcIP;
            pxEvt->dwSrcIP = pxEvt->dwDestIP;
            pxEvt->dwDestIP = tmpAddr;

            tmpAddr = pxEvt->dwSrcIPEnd;
            pxEvt->dwSrcIPEnd = pxEvt->dwDestIPEnd;
            pxEvt->dwDestIPEnd = tmpAddr;

            tmpPort = pxEvt->wSrcPort;
            pxEvt->wSrcPort = pxEvt->wDestPort;
            pxEvt->wDestPort = tmpPort;

            /* clear SPD reference as GDOI key is added manually; see GDOI_addTek() */
            pxEvt->dwSpdId = 0;
            pxEvt->spdIndex = 0;
        }
#endif
    case IKE_KEY_TYPE_SUSPEND :
    {
        /* check duplicate event */
        status = DoDupEvt(pxEvt, &pxEvtEx, timenow
                          MOC_MTHM_VALUE(serverInstance)
                          MOC_NATT_VALUE(bUseNattPort));

        if ((OK > status) || /* duplicate found */
            (IKE_KEY_TYPE_SUSPEND == type))
        {
#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
            if (NULL != pxEvtEx)
            {
                if (IKE_EVENT_FLAG_INXCHG & pxEvtEx->flags)
                {
                    IPSECSA pxIPsecSa = pxEvtEx->pxIPsecSa;
                    if (NULL != pxIPsecSa)
                    {
                        if (IKE_KEY_TYPE_ACQUIRE == type)
                        {
                            debug_printnl(" CURRENT");
                        }
                        else /* IKE_KEY_TYPE_SUSPEND */
                        {
                            if ((IKE_CHILD_FLAG_V2 & pxIPsecSa->c_flags) || /* for now */
                                (STATE_QUICK_I2c == pxIPsecSa->oState)) /* COMMIT state */
                                debug_printnl(" CURRENT");
                            else
                                debug_printnl(" SUSPENDED");
                        }
                    }
                    else
                    {
                        debug_printnl(" RECENT");
                    }
                }
                else
                {
                    debug_printnl(" PENDING");
                }
            }
            else
            {
                debug_printnl(NULL);
            }
#endif /* defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__) */

            goto exit; /* !!! */
        }

        debug_printnl(NULL);

        /* IKE_KEY_TYPE_ACQUIRE */
#ifdef __ENABLE_DIGICERT_PFKEY__
        if (0 == pxEvt->dwSpi)
        {
            /* get SPI */
            IKEEVT_CB cb;
            IPSECKEY key;

            INIT_MOC_IPADDR(dstAddr, pxEvt->dwSrcAddr)
            INIT_MOC_IPADDR(srcAddr, pxEvt->dwDestAddr)

            if (NULL == (cb = (IKEEVT_CB) MALLOC(sizeof(struct ike_event_callback))))
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }

            key = &(cb->key);
            DIGI_MEMSET((ubyte *)key, 0x00, sizeof(struct ipsecKey));

            key->oProtocol      = (IPSEC_PROTO_AH == pxEvt->pxSa[0].oSecuProto)
                                ? IPPROTO_AH : IPPROTO_ESP;
            key->flags          = IPSEC_SA_FLAG_INITIATOR;

            TEST_MOC_IPADDR6(dstAddr,
            {
                key->flags     |= IPSEC_SA_FLAG_IP6;
                key->dwDestAddr = (CAST_MOC_IPADDR) GET_MOC_IPADDR6(dstAddr);
                key->dwSrcAddr  = (CAST_MOC_IPADDR) GET_MOC_IPADDR6(srcAddr);
            })
            {
                key->dwDestAddr = GET_MOC_IPADDR4(dstAddr);
                key->dwSrcAddr  = GET_MOC_IPADDR4(srcAddr);
            }
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
            if (IPSEC_MODE_TUNNEL == pxEvt->oMode)
                key->oMode      = IPSEC_MODE_TUNNEL;
            else
#endif
                key->oMode      = IPSEC_MODE_TRANSPORT;
            key->cookie         = pxEvt->cookie;
            key->dwSeqNo        = pxEvt->dwSeqNo;

            key->funcPtrPfkeyCb = IKE_evtCallback;

            cb->evt = *pxEvt;
            cb->serverInstance = serverInstance;
            cb->bUseNattPort = bUseNattPort;

            if (OK > (status = IPSEC_keySpi(key)))
            {
                if (STATUS_IKE_PENDING != status)
                    FREE(cb);
                goto exit;
            }

            pxEvt->dwSpi = key->dwSpi;
            FREE(cb); /* !!! */
        }
#endif /* __ENABLE_DIGICERT_PFKEY__ */

        if (dwSaId)
        {
            IKE_getSaById(dwSaId, saLoc, &pxSa);

            if (NULL != pxSa)
            {
                if (!IS_AUTHED(pxSa)) pxSa = NULL; /* jic */
                else
                switch (version) /* double-check IKE_SA version */
                {
                case 1 :
                    if (IS_IKE2_SA(pxSa)) pxSa = NULL;
                    break;
                case 2 :
                    if (!IS_IKE2_SA(pxSa)) pxSa = NULL;
                    break;
                }
            }
        }

        break;
    }

    case IKE_KEY_TYPE_CONNECTED :
    case IKE_KEY_TYPE_ABORTED :
        if (!dwSaId) /* jic */
        {
            debug_printnl(" ERR");
            status = ERR_IKE;
            goto exit;
        }
        /* fall through */
    case IKE_KEY_TYPE_DELETED :
        if ((IKE_KEY_MOD_OUTBOUND | IKE_KEY_MOD_PRIVATE) & pxEvt->type)
        {
            /* DELETED: outbound or no notification necessary */
            debug_printnl(" IGN");
            goto exit;
        }

        if (!dwSaId) /* jic */
        {
            /* will try to find IKE_SA */
            debug_printnl(NULL);
            break;
        }

        /* get IKE_SA */
        status = IKE_getSaById(dwSaId, saLoc, &pxSa);

        if (NULL != pxSa)
        {
            if (!IS_AUTHED(pxSa)) pxSa = NULL; /* jic */
            else
            switch (version) /* double-check IKE_SA version */
            {
            case 1 :
                if (IS_IKE2_SA(pxSa)) pxSa = NULL;
                break;
            case 2 :
                if (!IS_IKE2_SA(pxSa)) pxSa = NULL;
                break;
            }
        }

        if (2 == version) /* [v2] */
        {
            if ((OK > status) || (NULL == pxSa) ||
                ((IKE_SA_FLAG_REKEYED | IKE_SA_FLAG_DELETING) & pxSa->flags))
            {
                /* already deleted */
                if (OK <= status) status = ERR_IKE_GETSA_FAIL;
                debug_printnl(" IGN");
                goto exit;
            }

            if (IKE_KEY_TYPE_CONNECTED == type)
            {
                if (pxEvt->dwSpi)
                {
                    /* TODO: remove responder exchange */
                    debug_printnl(NULL);
                    goto exit;
                }

                /* note: pxSa may be a rekey! */
                if (IS_MATURE(pxSa))
                {
                    pxSa->dwTimeStamp = timenow;
                    pxSa->flags &= ~(IKE_SA_FLAG_DPD);
                }
                else if (saLoc == pxSa->loc)
                {
                    pxSa->flags |= IKE_SA_FLAG_MATURE;
                    IKE2_finalizeSa(pxSa, timenow, NULL);
                }
                debug_printnl(" ACK");
                goto exit;
            }

            if (IS_OLD_IKE2_SA(pxSa))
            {
                status = ERR_IKE_GETSA_FAIL;
                debug_printnl(" IGN");
                goto exit;
            }

            debug_printnl(NULL);
        }
        else /* [v1] */
        {
            if (OK <= status)
            {
                if (NULL == pxSa) status = ERR_IKE_GETSA_FAIL;
                else
                if (pxEvt->dwSpi)
                {
                    /* stop re-transmission of quick mode final message, if applicable */
                    if ((dwSaId == pxSa->dwId) && /* jic - rekey */
                        (IKE_KEY_TYPE_DELETED != type))
                    {
                        ubyte oProtoId = (IPPROTO_AH == pxEvt->oProtocol)
                                       ? PROTO_IPSEC_AH : PROTO_IPSEC_ESP;
                        IPSECSA pxIPsecSa = IKE_findIPsecSa(pxSa, oProtoId, pxEvt->dwSpi);
                        if (pxIPsecSa)
                        {
                            debug_print(" ACK");
                            IKE_delIPsecSa(pxIPsecSa, pxSa);
                        }
                    }
                }
                else/* if (IKE_KEY_TYPE_CONNECTED == type) */
                {
                    debug_print(" ACK");
                    pxSa->dwTimeStamp = timenow;

                    /* reset DPD */
                    pxSa->flags &= ~(IKE_SA_FLAG_DPD);
                    pxSa->u.v1.dwDpdTimeStart = 0;
                }
            }

            debug_printnl(NULL);

            if (IKE_KEY_TYPE_CONNECTED == type)
                goto exit;
        }

        /* TO DO: find duplicates */

        break;

    case IKE_KEY_TYPE_SAINIT :
        debug_printnl(NULL);
        break;

    default : /* jic */
        status = ERR_IKE_EVENT;
        debug_printnl(NULL);
        goto exit;

    } /* switch (type) */

    if ((NULL == pxSa) || IS_OLD(pxSa) ||
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
        (bGdoi && !(IKE_SA_FLAG_GDOI & pxSa->flags)) ||
#endif
        (IKE_SA_FLAG_DELETED & pxSa->flags))
    {
        bInitIkeSa = TRUE;
    }
    else
    {
        IKESA pxSaRekey = pxSa->pxSaRekey;
        if ((NULL != pxSaRekey) && IS_VALID(pxSaRekey) &&
            (pxSaRekey->dwId == (IS_IKE2_SA(pxSa)
                              ? pxSa->dwId : pxSa->dwSaRekeyId)))
        {
            /* rekeying in progress */
            status = IKE_evtQueue(&pxEvtEx, pxEvt
                                  MOC_MTHM_VALUE(serverInstance)
                                  MOC_NATT_VALUE(bUseNattPort));
#ifdef __IKE_UPDATE_TIMER__
            if (OK <= status)
            {
                SetInitTimerEvent(pxEvtEx, 1000)
            }
#endif
            goto exit;
        }
    }

    /* find IKE_SA */
    if (bInitIkeSa)
    {
        IKESA pxSaTmp = NULL;

        if (OK > (status = IKE_evtFindSa(pxEvt, &pxSaTmp
                                         MOC_MTHM_VALUE(serverInstance))))
        {
            /* exchange in progress */
            if (IKE_KEY_TYPE_SAINIT == type)
            {
                /*if (NULL != pxSaTmp)*/
                pxEvt->dwSeqNo = pxSaTmp->dwId; /* !!! */
                status = STATUS_IKE_PENDING;
            }
            else
            {
                status = IKE_evtQueue(&pxEvtEx, pxEvt
                                      MOC_MTHM_VALUE(serverInstance)
                                      MOC_NATT_VALUE(bUseNattPort));
#ifdef __IKE_UPDATE_TIMER__
                if (OK <= status)
                {
                    SetInitTimerEvent(pxEvtEx, 1000)
                }
#endif
            }
            goto exit;
        }

        if (NULL != pxSaTmp)
        {
            pxSa = pxSaTmp;
            version = (IS_IKE2_SA(pxSa) ? 2 : 1);

            if (!IS_OLD(pxSa))
            {
                if (IKE_KEY_TYPE_SAINIT == type)
                {
                    if ((IKE_KEY_MOD_SAINIT | IKE_KEY_MOD_INITC)
                        & pxEvt->type) /* !!! */
                    {
                        /* don't connect if present */
                        pxEvt->dwSeqNo = pxSa->dwId; /* !!! */
                        status = STATUS_IKE_GETSA_SUCCESS;
                        goto exit;
                    }
                }
                else bInitIkeSa = FALSE;
            }
        }
    }

    if (!version)
    {
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
        if (!bGdoi) /* GDOI [v1] only */
#endif
#ifdef CUSTOM_IKE_GET_VERSION
        if (OK > (status = GetVersion_I(config, &version, pxEvt
                                        MOC_MTHM_REQ_VALUE(serverInstance))))
            goto exit;
#else
        version = config->ikeVersion;
#endif
    }

    /* queue the event */
    if (OK > (status = IKE_evtQueue(&pxEvtEx, pxEvt
                                    MOC_MTHM_VALUE(serverInstance)
                                    MOC_NATT_VALUE(bUseNattPort))))
        goto exit;

    /* initiate new IKE_SA exchange */
    if (bInitIkeSa)
    {
        IKESA pxSa1 = NULL;

        if (2 == version) /* [v2] */
            status = IKE2_evtInit(pxEvtEx, pxSa, &pxSa1);
        else
            status = IKE_evtInit(pxEvtEx, pxSa, &pxSa1);

        if (IKE_KEY_TYPE_SAINIT == type)
        {
            /* remove event from queue */
            EVT_DELETE(pxEvtEx)

            if (NULL != pxSa1)
                pxEvt->dwSeqNo = pxSa1->dwId; /* !!! */
        }
    }
    else
    {
        if (IKE_KEY_TYPE_ACQUIRE == type)
            status = IKE_evtQuick(pxSa, pxEvtEx);
        else
            status = IKE_evtInfo(pxSa, pxEvtEx);
    }

#ifdef __IKE_UPDATE_TIMER__
    if (pxEvtEx->flags &&
        !(IKE_EVENT_FLAG_INXCHG & pxEvtEx->flags))
    {
        SetInitTimerEvent(pxEvtEx, 1000)
    }
#endif

exit:
    return status;
} /* IKE_evtRecvEx */


/*------------------------------------------------------------------*/

static MSTATUS
HandleEvent(IKEEVT_EX pxEvtEx)
{
    MSTATUS status = OK;

    /* handle pending p2 exchange */
        ikePeerConfig* config;
        if (NULL == (config = IKE_findPeerConfigFromEvent(pxEvtEx)))
        {
            /* server instance already removed - remove event */
            EVT_DELETE(pxEvtEx)
            goto exit;
        }
        {
            IKEEVT pxEvt = &(pxEvtEx->evt);
            IKESA pxSa = NULL;

            sbyte4 version = EVT_VERS(pxEvt);

            if ((2 == version) && /* [v2] informational (Delete) */
                (IKE_KEY_TYPE_ACQUIRE != EVT_TYPE(pxEvt)))
            {
                status = IKE_getSaById(pxEvt->dwIkeSaId, pxEvt->ikeSaLoc, &pxSa);

                if ((OK > status) || (NULL == pxSa) ||
                    !IS_IKE2_SA(pxSa) || !IS_AUTHED(pxSa) || /* jic */
                    ((IKE_SA_FLAG_REKEYED | IKE_SA_FLAG_DELETING) & pxSa->flags))
                {
                    /* parent IKE_SA already deleted - remove event! */
                    EVT_DELETE(pxEvtEx)
                }
                else
                {
                    status = IKE_evtInfo(pxSa, pxEvtEx);
                }
                goto exit;
            }

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
            if (IKE_KEY_MOD_GDOI & pxEvt->type)
            {
                /* in case GDOI Key Server address is changed */
                MOC_IP_ADDRESS_S keyServerAddr = config->keyServerAddr;
                if (!SAME_MOC_IPADDR(REF_MOC_IPADDR(pxEvt->dwDestAddr), keyServerAddr) &&
#ifdef __ENABLE_DIGICERT_IPV6__
                    (keyServerAddr.family == pxEvt->dwDestAddr.family) &&
#endif
                    !ISZERO_MOC_IPADDR(keyServerAddr))
                {
                    pxEvt->dwDestAddr = keyServerAddr;
                }
            }
#endif
            if (OK > (status = IKE_evtFindSa(pxEvt, &pxSa
                                    MOC_MTHM_VALUE(pxEvtEx->serverInstance))))
            {
                /* [v2] pending REKEY_SA under CREATE_CHILD_SA */
                if (IS_IKE2_SA(pxSa) &&
                    !pxSa->u.v2.dwWndLen[_I] && !pxSa->u.v2.dwWndLen[_R])
                {
                    if (pxEvtEx->dwOldIkeSaId == pxSa->dwId)
                        pxEvtEx->dwOldIkeSaId = 0; /* jic */
                }
                goto exit; /* exchange in progress */
            }

            /* initiate new IKE_SA exchange */
            if ((NULL == pxSa) || IS_OLD(pxSa) ||
                (pxEvtEx->dwOldIkeSaId == pxSa->dwId))
            {
                if (!version)
                {
                    if (NULL == pxSa)
                    {
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
                        if (!(IKE_KEY_MOD_GDOI & pxEvt->type)) /* GDOI [v1] only */
#endif
#ifdef CUSTOM_IKE_GET_VERSION
                        if (OK > (status = GetVersion_I(config, &version, pxEvt
                                MOC_MTHM_REQ_VALUE(pxEvtEx->serverInstance))))
                            goto exit;
#else
                        version = config->ikeVersion;
#endif
                    }
                    else if (IS_IKE2_SA(pxSa)) version = 2;
                }

                if (2 == version) /* [v2] */
                    status = IKE2_evtInit(pxEvtEx, pxSa, NULL);
                else
                    status = IKE_evtInit(pxEvtEx, pxSa, NULL);
            }
            else
            {
                if (IKE_KEY_TYPE_ACQUIRE == EVT_TYPE(pxEvt))
                    status = IKE_evtQuick(pxSa, pxEvtEx);
                else
                    status = IKE_evtInfo(pxSa, pxEvtEx);
            }
        }

exit:
    return status;
} /* HandleEvent */


/*------------------------------------------------------------------*/

#ifndef __IKE_UPDATE_TIMER__

extern MSTATUS
IKE_handleEvents(void)
{
    MSTATUS status = OK;

    sbyte4 i;
    ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
    ubyte4 timeout = 1000 * m_ikeSettings.ikeTimeoutEvent;

    IKE_LOCK_W;

    /* handle pending p2 exchange */
    for (i=0; i < m_ikeEvtNum; i++)
    {
        IKEEVT_EX pxEvtEx = &(m_ikeEvt[i]);

        if (!pxEvtEx->flags) continue;

        if (timeout < (timenow - pxEvtEx->dwTimeQueued))
        {
            /* timed out */
            EVT_DELETE(pxEvtEx)
            continue;
        }

        if (!(IKE_EVENT_FLAG_INXCHG & pxEvtEx->flags))
        {
            status = HandleEvent(pxEvtEx);
        }
    } /* for */

    IKE_UNLOCK_W;
    return status;
} /* IKE_handleEvents */


#else

/*------------------------------------------------------------------*/

extern void
IKE_evtInitTimerEvent(sbyte4 timeout, ubyte4 evtId, void *data, ubyte4 timerId)
{
    IKEEVT_EX pxEvtEx = (IKEEVT_EX)data;

    MSTATUS status;

    IKE_LOCK_W;
    if (!pxEvtEx) goto exit; /* jic */

    if (evtId != pxEvtEx->dwId)
    {
        goto exit; //EXIT_EVT
    }

    if (!pxEvtEx->flags)
    {
        goto exit; //EXIT_EVT
    }

    if (timerId != pxEvtEx->initTimerId)
    {
        goto exit; //EXIT_EVT
    }

    pxEvtEx->initTimerId = (IKE_TIMER_EVT_T)0; /* !!! */
    pxEvtEx->initTimerHdl = (IKE_TIMER_HDL_T)0; /* !!! */

    if (IKE_EVENT_FLAG_INXCHG & pxEvtEx->flags) /* jic */
    {
        goto exit;
    }

    status = HandleEvent(pxEvtEx);

    if (pxEvtEx->flags &&
        !(IKE_EVENT_FLAG_INXCHG & pxEvtEx->flags))
    {
        timeout *= 2;
        SetInitTimerEvent(pxEvtEx, timeout)
    }

exit:
    IKE_UNLOCK_W;
    return;
} /* IKE_evtInitTimerEvent */


/*------------------------------------------------------------------*/

extern void
IKE_evtExpTimerEvent(sbyte4 cookie, ubyte4 evtId, void *data, ubyte4 timerId)
{
    IKEEVT_EX pxEvtEx = (IKEEVT_EX)data;

    IKE_LOCK_W;
    if (!pxEvtEx) goto exit; /* jic */

    MOC_UNUSED(cookie);

    if (evtId != pxEvtEx->dwId)
    {
        goto exit; //EXIT_EVT
    }

    if (!pxEvtEx->flags)
    {
        goto exit; //EXIT_EVT
    }

    if (timerId != pxEvtEx->expTimerId)
    {
        goto exit; //EXIT_EVT
    }

    pxEvtEx->expTimerId = (IKE_TIMER_EVT_T)0; /* !!! */
    pxEvtEx->expTimerHdl = (IKE_TIMER_HDL_T)0; /* !!! */

    /* timed out */
    IKE_DEL_TIMER_EVT(pxEvtEx->initTimerId, pxEvtEx->initTimerHdl)
    pxEvtEx->flags = 0;
    pxEvtEx->dwId = 0;

exit:
    IKE_UNLOCK_W;
    return;
} /* IKE_evtExpTimerEvent */

#endif /* __IKE_UPDATE_TIMER__ */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_evtGetAddr(IKEEVT pxEvt,
               MOC_IP_ADDRESS *pHostAddr, MOC_IP_ADDRESS *pPeerAddr)
{
    MSTATUS status = OK;

    if ((NULL == pxEvt) ||
        ((NULL == pHostAddr) && (NULL == pPeerAddr)))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (EVT_TYPE(pxEvt))
    {
    case IKE_KEY_TYPE_DELETED   :
        if (!(IKE_KEY_MOD_OUTBOUND & pxEvt->type))
        {
            break;
        }
        /* fall through */
    case IKE_KEY_TYPE_ACQUIRE   :
    case IKE_KEY_TYPE_SUSPEND   :
    case IKE_KEY_TYPE_SAINIT    :
        if (pHostAddr)
            *pHostAddr = REF_MOC_IPADDR(pxEvt->dwSrcAddr);
        if (pPeerAddr)
            *pPeerAddr = REF_MOC_IPADDR(pxEvt->dwDestAddr);
        goto exit;
    default :
        break;
    }

    switch (EVT_TYPE(pxEvt))
    {
    case IKE_KEY_TYPE_DELETED   :
    case IKE_KEY_TYPE_CONNECTED :
    case IKE_KEY_TYPE_ABORTED   :
        if (pHostAddr)
            *pHostAddr = REF_MOC_IPADDR(pxEvt->dwDestAddr);
        if (pPeerAddr)
            *pPeerAddr = REF_MOC_IPADDR(pxEvt->dwSrcAddr);
        break;
    default :
        status = ERR_IKE_EVENT;
        break;
    }

exit:
    return status;
} /* IKE_evtGetAddr */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_evtGetPeerAddr(IKEEVT pxEvt,
                   MOC_IP_ADDRESS *pPeerAddr, ubyte2* pwPeerPort)
{
    MSTATUS status = OK;

    if ((NULL == pxEvt) || (NULL == pPeerAddr) || (NULL == pwPeerPort))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (EVT_TYPE(pxEvt))
    {
    case IKE_KEY_TYPE_DELETED   :
        if (!(IKE_KEY_MOD_OUTBOUND & pxEvt->type))
        {
            break;
        }
        /* fall through */
    case IKE_KEY_TYPE_ACQUIRE   :
    case IKE_KEY_TYPE_SUSPEND   :
    case IKE_KEY_TYPE_SAINIT    :
        *pPeerAddr = REF_MOC_IPADDR(pxEvt->dwDestAddr);
        *pwPeerPort = pxEvt->wUdpEncPort;
        goto exit;
    default :
        break;
    }

    switch (EVT_TYPE(pxEvt))
    {
    case IKE_KEY_TYPE_DELETED   :
    case IKE_KEY_TYPE_CONNECTED :
    case IKE_KEY_TYPE_ABORTED   :
        *pPeerAddr = REF_MOC_IPADDR(pxEvt->dwSrcAddr);
        *pwPeerPort = pxEvt->wUdpEncPort;
        break;
    default :
        status = ERR_IKE_EVENT;
        break;
    }

exit:
    return status;
} /* IKE_evtGetPeerAddr */


/*------------------------------------------------------------------*/

extern ikePeerConfig*
IKE_findPeerConfigFromEvent(IKEEVT_EX pxEvtEx)
{
    MOC_IP_ADDRESS peerAddr;
    ubyte2 wPeerPort;

    if (NULL == pxEvtEx)
        return NULL;

    IKE_evtGetPeerAddr(&pxEvtEx->evt, &peerAddr, &wPeerPort);

    return IKE_findPeerConfig(peerAddr, wPeerPort
                              MOC_MTHM_REQ_VALUE(pxEvtEx->serverInstance));
} /* IKE_findPeerConfigFromEvent */


/*------------------------------------------------------------------*/

extern sbyte4
IKE_evtRecv(IKEEVT pxEvt, sbyte4 serverInstance, intBoolean bUseNattPort)
{
    MSTATUS status;

    MOC_IP_ADDRESS peerAddr;
    ubyte2 wPeerPort;
    ikePeerConfig *config;

    IKE_LOCK_W; /* !!! */

    if (OK > (status = IKE_evtGetPeerAddr(pxEvt, &peerAddr, &wPeerPort)))
        goto exit;

    if (NULL == (config = IKE_findPeerConfig(peerAddr, wPeerPort,
                                             serverInstance)))
    {
        status = ERR_IKE_NO_PEER_CONFIG;
        goto exit;
    }

    status = IKE_evtRecvEx(config, pxEvt, serverInstance, bUseNattPort);

exit:
    IKE_UNLOCK_W;
    return (sbyte4)status;
} /* IKE_evtRecv */


#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */

