/**
 * @file  ike_frag.c
 * @brief IKE message fragmentation support.
 *
 * @details    IKEv1 fragmentation for large messages (RFC 3195).
 * @since      5.0
 * @version    6.5.1 and later
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     +   \c \__ENABLE_IKE_FRAGMENTATION__
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

#if defined(__ENABLE_DIGICERT_IKE_SERVER__) && defined(__ENABLE_IKE_FRAGMENTATION__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../crypto/dh.h"
#include "../crypto/rsa.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../crypto/pubcrypto.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/crypto.h"
#include "../harness/harness.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/tree.h"
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"
#include "../common/timer.h"

#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsecconf.h"

#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ikesa.h"
#include "../ike/ike_state.h"
#include "../ike/ike_utils.h"
#include "../ike/ike_frag.h"


/*------------------------------------------------------------------*/

#ifdef __IKE_UPDATE_TIMER__
extern IKE_MUTEX g_ikeMtx;

#ifdef __IKE_MULTI_THREADED__
extern ikeSettings m_ikeSettings;
extern RTOS_RWLOCK m_ikeSaRwLock;
#endif
extern ubyte *m_ikeTimer;
#endif

#define IKE_LAST_FRAGMENT_FLAG    0x01


/*------------------------------------------------------------------*/

#define DBG_STATUS  debug_print_status((sbyte *)__FILE__, __LINE__, (sbyte4)status);
#define DBG_EXIT    { DBG_STATUS goto exit; }

#define CHECK_MALLOC(_t, _p, _s) \
    if (NULL == ((_p) = (_t *) MALLOC(_s))) \
    { \
        status = ERR_MEM_ALLOC_FAIL; \
        DBG_EXIT \
    } \


/*------------------------------------------------------------------*/

#ifdef __IKE_UPDATE_TIMER__

static void
ReassemblyTimerExpiry(sbyte4 cookie, ubyte4 saId, void *data, ubyte4 timerId)
{
    IKESA pxSa = (IKESA)data;

    MOC_UNUSED(cookie);

    IKE_LOCK_R;
    if (!pxSa) goto exit; /* jic */

#ifndef __IKE_MULTI_THREADED__
    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_REASSEMBLY]))
    {
       goto exit;
    }

#else
    RTOS_rwLockWaitR(m_ikeSaRwLock);

    if (!IS_VALID(pxSa) ||
        (saId != pxSa->dwId) ||
        (timerId != pxSa->timerIDs[IKESA_TIMER_REASSEMBLY]))
    {
        goto exit_sa;
    }

    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* relay this call to the proper thread */
        if (m_ikeSettings.funcPtrIkeThreadSend)
        {
            struct dpcTimerEvent evt;
            evt.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcTimerEvent;
            evt.hdr.dpc_len = (ubyte2)sizeof(evt);
            evt.func = ReassemblyTimerExpiry;
            evt.cookie = cookie;
            evt.saId = saId;
            evt.sa = data;
            evt.timerId = timerId;
            m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid,
                                            (ubyte *)&evt, (ubyte4)sizeof(evt));
        }
        goto exit_sa;
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif

    pxSa->timerIDs[IKESA_TIMER_REASSEMBLY] = (IKE_TIMER_EVT_T)0;
    pxSa->timerHdls[IKESA_TIMER_REASSEMBLY] = (IKE_TIMER_HDL_T)NULL;
    IKE_flushFragReassemble(pxSa);

exit:
    IKE_UNLOCK_R;
    return;

#ifdef __IKE_MULTI_THREADED__
exit_sa:
    RTOS_rwLockReleaseR(m_ikeSaRwLock);
    IKE_UNLOCK_R;
    return;
#endif
}

#else

extern void
IKE_fragReassemblyTimerExpiry(void *cookie, ubyte *type)
{
    IKESA     pxSa   = (IKESA)cookie;

    MOC_UNUSED(type);

    if (!pxSa)
    {
        goto exit;
    }

    pxSa->fragReceived = 0;
    IKE_flushFragReassemble(pxSa);

exit:
    return;
}

#endif


/*------------------------------------------------------------------*/

static MSTATUS
ike_fragReassemble(IKE_context ctx, ubyte2 fragId)
{
    ubyte4                   i = 0;
    ubyte4                   fragCount = 1;
    sbyte4                   msgSize = 0;
    ubyte                    lastFragFlag = 0;
    ubyte*                   pBuffer;
    IKE_reassembly_list**    ppHash;
    IKE_reassembly_list*     pNode;
    IKE_reassembly_list*     pTrail;
    IKE_reassembly_list*     pTrav;
    IKESA                    pxSa = NULL;
    MSTATUS                  status = OK;
    ubyte4                   dwLength = 0;

    if (!ctx->pxSa)
    {
        status = ERR_IKE_REASSEMBLY;
        goto exit;
    }

    pxSa = ctx->pxSa;
    pBuffer = NULL;

    while (0 == lastFragFlag)
    {
        i = fragCount % IKE_FRAG_BUCKETS_MAX;
        ppHash = &(pxSa->pFragHash[i]);

        if (NULL == *ppHash)
        {
            status = ERR_IKE_REASSEMBLY;
            goto exit;
        }

        pNode = *ppHash;
        pTrail = NULL;

        for (pTrav = pNode; pTrav; pTrav = pTrav->pNext)
        {
            if (pTrav->fragNum == fragCount && pTrav->fragId == fragId)
            {
                pBuffer = realloc(pBuffer, pTrav->fragSize + msgSize);
                DIGI_MEMCPY(&(pBuffer[msgSize]), pTrav->pBuffer, pTrav->fragSize);
                msgSize += pTrav->fragSize;

                if (pTrav->lastFrag)
                    lastFragFlag = pTrav->lastFrag;

                break;
            }
            pTrail = pTrav;
        } /* for */

        if (NULL == pTrav)
        {
            /* did not find a match */
            status = ERR_IKE_REASSEMBLY;
            goto exit;
        }

        /* Check length header in first fragment */
        if (fragCount == 1)
        {
#ifdef __ENABLE_IPSEC_NAT_T__
            intBoolean bUseNattPort = USE_NATT_PORT(pxSa);
            struct ikeHdr *pxHdr = NULL;
            if (bUseNattPort)
            {
                pxHdr = (struct ikeHdr *) (pTrav->pBuffer + 4);
                dwLength = DIGI_NTOHL((ubyte *)&(pxHdr->dwLength)) + 4;
            }
            else
#endif
            {
                pxHdr = (struct ikeHdr *) (pTrav->pBuffer);
                dwLength = DIGI_NTOHL((ubyte *)&(pxHdr->dwLength)) ;
            }
        }

        if (!pTrail)
        {
            *ppHash = pTrav->pNext;
        }
        else
        {
            pTrail->pNext = pTrav->pNext;
        }

        FREE(pTrav);
        fragCount++;

    } /* while */

    if (dwLength != msgSize)
    {
        status = ERR_IKE_REASSEMBLY;
        goto exit;
    }

    ctx->pBuffer = pBuffer;
    ctx->pRefragmentationBuffer = pBuffer;  /* save the reassembled buffer to free later */
    return OK;

exit:
    FREE(pBuffer);
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
ike_checkFragReassemble(IKE_context ctx, ubyte2 fragId)
{
    ubyte4                   i = 0;
    ubyte4                   fragCount = 1;
    ubyte4                   lastFragFlag = 0;
    IKE_reassembly_list**    ppHash;
    IKE_reassembly_list*     pTrav;
    IKESA                    pxSa;
    MSTATUS                  status = OK;

    if ((!ctx) || (NULL == (pxSa = ctx->pxSa)))
    {
        status = ERR_IKE_REASSEMBLY;
        goto exit;
    }

    while (0 == lastFragFlag)
    {
        /* Find the first fragment */
        i = fragCount % IKE_FRAG_BUCKETS_MAX;
        ppHash = &(pxSa->pFragHash[i]);

        if (NULL == *ppHash)
        {
            status = ERR_IKE_REASSEMBLY_INCOMPLETE;
            goto exit;
        }

        for (pTrav = *ppHash; pTrav; pTrav = pTrav->pNext)
        {
            if (pTrav->fragNum == fragCount && pTrav->fragId == fragId)
            {
                break;
            }
        }

        if (NULL == pTrav)
        {
            /* did not find a match */
            status = ERR_IKE_REASSEMBLY_INCOMPLETE;
            goto exit;
        }

        if (pTrav->lastFrag)
        {
            lastFragFlag = pTrav->lastFrag;
        }
        fragCount++;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_fragCreate(IKESA pxSa, ubyte fragNum, ubyte2 *pFragId,
               struct ikeHdr *pHdr, ubyte *pFragData,
               intBoolean lastFrag, ubyte4 fragSize, ubyte **pPkt)
{
    ubyte*               pBuffer;
    struct ikeHdr*       pxHdr;
    struct ikeFragHdr*   pFragHdr;
    ubyte2               fragDataLen;
    MSTATUS              status = OK;

    if (!pxSa || !pFragId || !pHdr || !pFragData ||
        ((SIZEOF_ISAKMP_HDR + SIZEOF_IKE_FRAG_HDR) >= fragSize))
    {
        status = ERR_IKE_INVALID_PARAM;
        goto exit;
    }

    fragDataLen = (ubyte2)(fragSize - SIZEOF_ISAKMP_HDR - SIZEOF_IKE_FRAG_HDR);

    /* Allocate fragment */
    CHECK_MALLOC(ubyte, pBuffer, fragSize)
    DIGI_MEMSET(pBuffer, 0x00, fragSize);

#ifdef __ENABLE_IPSEC_NAT_T__
    intBoolean bUseNattPort = USE_NATT_PORT(pxSa);
    if (bUseNattPort)
    {
        fragDataLen -= 4;
        DIGI_MEMCPY(pBuffer, ((ubyte *) pHdr - 4), 4);
        pxHdr = (struct ikeHdr *)(pBuffer + 4);
        DIGI_MEMCPY(pxHdr, pHdr, SIZEOF_ISAKMP_HDR);
        SET_HTONL(pxHdr->dwLength, fragSize - 4);
    }
    else
#endif /* __ENABLE_IPSEC_NAT_T__ */
    {
        pxHdr = (struct ikeHdr *)pBuffer;
        DIGI_MEMCPY(pxHdr, pHdr, SIZEOF_ISAKMP_HDR);
        SET_HTONL(pxHdr->dwLength, fragSize);
    }

    pxHdr->oNextPayload = ISAKMP_NEXT_FRAGMENT;

    /* Encryption flag has to be cleared */

    pxHdr->oFlags &= 0xfe;

    pFragHdr = (struct ikeFragHdr *)(pxHdr + 1);

    pFragHdr->oFragNum = fragNum;

    /* Increment the frag id if this is the first fragment */
    if ((1 == fragNum) && (0 == *pFragId)) /* and not re-transmission */
    {
        *pFragId = ++pxSa->fragId;
    }
    SET_HTONS(pFragHdr->wFragId, *pFragId);

    SET_HTONS(pFragHdr->wLength, (fragDataLen + SIZEOF_IKE_FRAG_HDR));

    if (lastFrag)
    {
        pFragHdr->oFlags |= IKE_LAST_FRAGMENT_FLAG;
    }

    DIGI_MEMCPY((ubyte *)(pFragHdr + 1), pFragData, fragDataLen);

   *pPkt = pBuffer;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_flushFragReassemble(IKESA pxSa)
{
    IKE_reassembly_list*     pNode;
    IKE_reassembly_list*     pNext;
    ubyte4                   i;
    MSTATUS                  status = OK;

    if (!pxSa)
    {
        status = ERR_IKE_INVALID_PARAM;
        goto exit;
    }

    for (i = 0; i < IKE_FRAG_BUCKETS_MAX; i++)
    {
        pNode = pxSa->pFragHash[i];

        while (pNode)
        {
            pNext = pNode->pNext;
            FREE(pNode);

            pNode = pNext;
        }  /* while */

        pxSa->pFragHash[i] = NULL;
    }   /* for */

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_fragRecv(IKE_context ctx, ubyte *pIsReassembled)
{
    IKESA                    pxSa;
    struct ikeHdr*           pxHdr = NULL;
    ubyte2                   fragDataLen = 0;
    ubyte4                   idx;
    ubyte2                   wFragId = 0;
    struct ikeFragHdr*       pFragHdr;
    IKE_reassembly_list**    ppHash;
    IKE_reassembly_list*     pNewFrag;
    IKE_reassembly_list*     pNode;
    IKE_reassembly_list*     pTrail = NULL;
    MSTATUS                  status = OK;
    intBoolean bUseNattPort = 0;
    ubyte2 wFragHdrLen      = 0;

    if ((NULL == ctx) || (NULL == ctx->pBuffer) || (NULL == ctx->pxSa) || (!pIsReassembled))
    {
        status = ERR_IKE_FRAG_NULL_POINTER;
        goto exit;
    }

    pxSa = ctx->pxSa;
    if (!(IKE_SA_FLAG_FRAGMENTATION & pxSa->flags))
    {
        status = ERR_IKE_FRAG_NOT_SUPPORTED;
        goto exit;
    }

    bUseNattPort = USE_NATT_PORT(pxSa);
    *pIsReassembled = 0;

    pxHdr = (struct ikeHdr *) ctx->pBuffer;

    /* Copy fragment details into node */
    pFragHdr = (struct ikeFragHdr *)(pxHdr + 1);

    /* Check if this is the first fragment */
#ifdef __IKE_UPDATE_TIMER__
    if ((IKE_TIMER_EVT_T)0 == pxSa->timerIDs[IKESA_TIMER_REASSEMBLY])
    {
        /* Start a reassembly timer of 70 secs */
        if (OK > (status = IKE_ADD_TIMER_EVT(70000, 0, pxSa,
                                             ReassemblyTimerExpiry, "RAS",
                                             pxSa->timerIDs[IKESA_TIMER_REASSEMBLY],
                                             pxSa->timerHdls[IKESA_TIMER_REASSEMBLY])))
        {
            goto exit;
        }

        DIGI_MEMSET((ubyte *)pxSa->pFragHash, 0x00,
                   (IKE_FRAG_BUCKETS_MAX * sizeof(IKE_reassembly_list *)));
    }
#else
    if (0 == pxSa->fragReceived)
    {
        /* Start a reassembly timer of 70 secs */
        if (OK > (status = TIMER_queueTimer((void *)pxSa, pxSa->reassemblyTimerId, 70, 0)))
        {
            goto exit;
        }

        DIGI_MEMSET((ubyte *)pxSa->pFragHash, 0x00,
                   (IKE_FRAG_BUCKETS_MAX * sizeof(IKE_reassembly_list *)));
        pxSa->fragReceived = 1;
    }
#endif

    wFragHdrLen = DIGI_NTOHS((ubyte *)&pFragHdr->wLength);

    if (wFragHdrLen < SIZEOF_IKE_FRAG_HDR)
    {
        status = ERR_IKE_BAD_FRAGMENT;
        goto exit;
    }

    fragDataLen = (ubyte2)(wFragHdrLen - SIZEOF_IKE_FRAG_HDR);

#ifdef __ENABLE_IPSEC_NAT_T__
    if (1 == pFragHdr->oFragNum)
    {
        if (bUseNattPort)
        {
            fragDataLen += 4;
        }
    }
#endif

    CHECK_MALLOC(IKE_reassembly_list, pNewFrag, sizeof(IKE_reassembly_list) + fragDataLen)
    DIGI_MEMSET((ubyte *)pNewFrag, 0x00, (sizeof(IKE_reassembly_list) + fragDataLen));

    wFragId = DIGI_NTOHS((ubyte *)&pFragHdr->wFragId);
    pNewFrag->fragId   = wFragId;
    pNewFrag->fragNum  = pFragHdr->oFragNum;
    pNewFrag->fragSize = fragDataLen;

    if (pFragHdr->oFlags & IKE_LAST_FRAGMENT_FLAG)
        pNewFrag->lastFrag = 1;

    pNewFrag->pBuffer  = (ubyte *)(pNewFrag + 1);

#ifdef __ENABLE_IPSEC_NAT_T__
    if (bUseNattPort && (1 == pFragHdr->oFragNum))
    {
        DIGI_MEMCPY(pNewFrag->pBuffer, ((ubyte *)pxHdr - 4), 4);
        DIGI_MEMCPY(pNewFrag->pBuffer + 4, (pFragHdr + 1), fragDataLen - 4);
    }
    else
#endif
    DIGI_MEMCPY(pNewFrag->pBuffer, (pFragHdr + 1), fragDataLen);

    idx                = pFragHdr->oFragNum % IKE_FRAG_BUCKETS_MAX;
    ppHash             = &(pxSa->pFragHash[idx]);

    if (NULL == *ppHash)
    {
        *ppHash = pNewFrag;
    }
    else
    {
        /* insert into hash bucket */
        for (pNode = *ppHash; pNode; pNode = pNode->pNext)
        {
            /* check for duplicates */
            if ((pNode->fragNum == pNewFrag->fragNum) &&
                (pNode->fragId == pNewFrag->fragId))
            {
                status = STATUS_IKE_PENDING;
                FREE(pNewFrag);
                goto exit;
            }

            pTrail = pNode;
        } /* for */

        pTrail->pNext = pNewFrag;
    }

    if (OK > (status = ike_checkFragReassemble(ctx, wFragId)))
        goto exit;

    if (OK > (status = ike_fragReassemble(ctx, wFragId)))
        goto exit;

    *pIsReassembled = 1;

    /* Reassembly successful, so stop reassembly timer */
#ifdef __IKE_UPDATE_TIMER__
    IKE_DEL_TIMER_EVT(pxSa->timerIDs[IKESA_TIMER_REASSEMBLY], pxSa->timerHdls[IKESA_TIMER_REASSEMBLY])
#else
    TIMER_unTimer((void *)pxSa, pxSa->reassemblyTimerId);
    pxSa->fragReceived = 0;
#endif

exit:
    return status;
} /* IKE_fragRecv */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_fragCheckFragment(ubyte *pBuffer, ubyte *pIsFragment)
{
    struct ikeHdr*       pxHdr;
    struct ikeFragHdr*   pFragHdr;
    ubyte4               dwLength;
    ubyte2               fragLength;
    MSTATUS              status = OK;

    if (!pIsFragment)
    {
        status = ERR_IKE_FRAG_NULL_POINTER;
        goto exit;
    }

    *pIsFragment = 0;

    if (NULL == pBuffer)
    {
        status = ERR_IKE_FRAG_NULL_POINTER;
        goto exit;
    }

    pxHdr = (struct ikeHdr *)(pBuffer);

    dwLength = DIGI_NTOHL((ubyte *)&(pxHdr->dwLength));

    if (ISAKMP_NEXT_FRAGMENT != pxHdr->oNextPayload)
    {
        goto exit;
    }

    /* This msg has the FRAGMENT payload */
    /* Check if any other payloads are present */
    pFragHdr = (struct ikeFragHdr *)(pxHdr + 1);
    if (!pFragHdr)
    {
        status = ERR_IKE_BAD_FRAGMENT;
        goto exit;
    }

    fragLength = DIGI_NTOHS((ubyte *)&(pFragHdr->wLength));

    if (fragLength < SIZEOF_IKE_FRAG_HDR)
    {
        status = ERR_IKE_BAD_FRAGMENT;
        goto exit;
    }

    if (dwLength > (ubyte4)(fragLength + SIZEOF_ISAKMP_HDR))
    {
        status = ERR_IKE_BAD_FRAGMENT;
        goto exit;
    }

    *pIsFragment = 1;

exit:
    return status;
}

#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) && defined(__ENABLE_IKE_FRAGMENTATION__) */
