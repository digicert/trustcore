/**
 * @file  ipsec_frag.c
 * @brief NanoSec IPsec IP datagram fragmentation implementation.
 *
 * @details    This file contains IP fragmentation and reassembly for IPsec.
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_IPSEC_FRAGMENTATION__
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

#ifdef __ENABLE_IPSEC_FRAGMENTATION__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../ipsec/ipsec_utils.h"
#include "../ipsec/ipsec_protos.h"
#include "../ipsec/ipsec_frag.h"


/*------------------------------------------------------------------*/

MOC_EXTERN_DATA_DECL moctime_t gStartTime;


/*------------------------------------------------------------------*/

typedef struct fragment
{
    ubyte* pBuffer;
    ubyte2 wLength;
    ubyte oHdrLen;
    ubyte2 wPayloadLen;
    ubyte2 wOffset;
    intBoolean bMore;

} *FRAGMENT;

typedef struct datagram
{
    intBoolean bInUse;
    ubyte4 dwTimeOut;

    ubyte2 wId;
    ubyte oProtocol;
    ubyte4 dwSrcAddr;
    ubyte4 dwDestAddr;

    struct fragment frag[IPSEC_PACKETS_MAX];
    sbyte4 fragNum;

    ubyte2 wPayloadLen;

} *DATAGRAM;


static struct datagram m_ipsecDgram[IPSEC_DGRAM_MAX];
static sbyte4 m_ipsecDgramNum = IPSEC_DGRAM_MAX;

static RTOS_MUTEX m_mtx = NULL;


/*------------------------------------------------------------------*/

extern sbyte4 IPSEC_fragInit(void)
{
    MSTATUS status = OK;

    DIGI_MEMSET((ubyte *)m_ipsecDgram, 0x00, m_ipsecDgramNum * sizeof(struct datagram));
    status = RTOS_mutexCreate(&m_mtx, IPSEC_REASSEMBLY_MUTEX, 0);

    return (sbyte4)status;
} /* IPSEC_fragInit */


/*------------------------------------------------------------------*/

static void
free_dgram(DATAGRAM dgram)
{
    sbyte4 i;

    for (i=0; i < dgram->fragNum; i++)
    {
        FRAGMENT frag = &(dgram->frag[i]);
        if (NULL != frag->pBuffer)
            FREE(frag->pBuffer);
    }
    DIGI_MEMSET((ubyte *)dgram, 0x00, sizeof(struct datagram));
}


/*------------------------------------------------------------------*/

extern sbyte4 IPSEC_fragFlush(void)
{
    MSTATUS status = OK;

    sbyte4 i;

    if (OK > (status = RTOS_mutexWait(m_mtx)))
        goto exit;

    for (i=0; i < m_ipsecDgramNum; i++)
    {
        DATAGRAM dgram = &(m_ipsecDgram[i]);
        if (dgram->bInUse)
            free_dgram(dgram);
    }

    RTOS_mutexRelease(m_mtx);
    status = RTOS_mutexFree(&m_mtx);

exit:
    return (sbyte4)status;
} /* IPSEC_fragFlush */


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_fragRcv(ubyte **ppBuffer, ubyte2 *pwBufferSize)
{
    MSTATUS status = OK;

    intBoolean bMutexOn = FALSE;

    ubyte *pBuffer = *ppBuffer;
    ubyte2 wBufferSize = *pwBufferSize;

    struct ipHdr *pxHdr;
    ubyte oHdrLen;
    ubyte2 wLength;
    ubyte2 wFragOff;
    ubyte2 wId;
    ubyte oProtocol;
    ubyte4 dwSrcAddr;
    ubyte4 dwDestAddr;

    ubyte2 wPayloadLen;
    ubyte2 wOffset;
    intBoolean bMore;

    ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);

    sbyte4 i;

    DATAGRAM dgram = NULL;
    FRAGMENT frag = NULL;

    /* get ip header */
    if (wBufferSize < sizeof(struct ipHdr))
    {
        status = ERR_IPSEC_BAD_IP;
        goto exit;
    }
    pxHdr = (struct ipHdr *)pBuffer;

    /* check ip version */
    if (0x40 != (pxHdr->ip_vhl & 0xF0))
    {
        status = STATUS_IPSEC_BYPASS;
        goto exit;
    }

    /* check length */
    oHdrLen    = (pxHdr->ip_vhl & 0x0F) << 2;
    SET_NTOHS(wLength, pxHdr->ip_len);

    if (oHdrLen < sizeof(struct ipHdr) ||
        wLength > wBufferSize ||
        oHdrLen > wLength)
    {
        status = ERR_IPSEC_BAD_IP;
        goto exit;
    }

    wPayloadLen = wLength - oHdrLen;

    /* check fragmentation */
    SET_NTOHS(wFragOff, pxHdr->ip_off);
    wOffset = (IP_OFFMASK & wFragOff) * 8;
    bMore = (IP_MF & (~(IP_OFFMASK) & wFragOff));

    if (!wOffset && /* fragment offset == 0 */
        !bMore)     /* and no more fragments */
    {
        status = STATUS_IPSEC_BYPASS;    /* passed on to upper layer */
        goto exit;
    }

    /* get ip packet info */
    SET_NTOHS(wId, pxHdr->ip_id);
    oProtocol  = pxHdr->ip_p;
    SET_NTOHL(dwSrcAddr, pxHdr->ip_src);
    SET_NTOHL(dwDestAddr, pxHdr->ip_dst);

    /* synchronize */
    if (OK > (status = RTOS_mutexWait(m_mtx)))
        goto exit;
    bMutexOn = TRUE;

    /* find datagram */
    for (i=0; i < m_ipsecDgramNum; i++, dgram = NULL)
    {
        intBoolean bFound = FALSE;

        dgram = &(m_ipsecDgram[i]);
        if (!dgram->bInUse) continue;

        if ((wId == dgram->wId) &&
            (oProtocol == dgram->oProtocol) &&
            (dwSrcAddr == dgram->dwSrcAddr) &&
            (dwDestAddr == dgram->dwDestAddr))
        {
            bFound = TRUE;
        }

        /* check timeout */
        if (timenow > dgram->dwTimeOut)
        {
            free_dgram(dgram);

            if (bFound)
            {
                status = ERR_IPSEC_FRAGMENTATION;
                goto exit;
            }
            continue;
        }

        if (bFound) break;
    } /* for */

    /* new datagram */
    if (NULL == dgram)
    {
        for (i=0; i < m_ipsecDgramNum; i++, dgram = NULL)
        {
            dgram = &(m_ipsecDgram[i]);
            if (!dgram->bInUse) break;
        }
        if (NULL == dgram)
        {
            status = ERR_IPSEC_FRAGMENTATION;
            goto exit;
        }
        dgram->bInUse     = TRUE;
        dgram->dwTimeOut  = timenow + TIMEOUT_IPSEC_REASSEMBLY;
        dgram->wId        = wId;
        dgram->oProtocol  = oProtocol;
        dgram->dwSrcAddr  = dwSrcAddr;
        dgram->dwDestAddr = dwDestAddr;
    }

    if ((IPSEC_PACKETS_MAX <= dgram->fragNum) ||
        (IPSEC_DGRAM_SIZE_MAX < (dgram->wPayloadLen + wPayloadLen)))
    {
        status = ERR_IPSEC_FRAGMENTATION;
        goto exit;
    }

    /* find fragment order */
    for (i=0; i < dgram->fragNum; i++)
    {
        frag = &(dgram->frag[i]);

        if (frag->wOffset == wOffset) /* duplicate */
        {
            status = ERR_IPSEC_FRAGMENTATION;
            goto exit;
        }
        if (frag->wOffset > wOffset) /* insert new fragment here */
        {
            if (!bMore)
            {
                status = ERR_IPSEC_FRAGMENTATION;
                goto exit;
            }
            break;
        }
        if (!frag->bMore) /* continue? */
        {
            status = ERR_IPSEC_FRAGMENTATION;
            goto exit;
        }
    }

    /* allocate new fragment */
    if (NULL == (pBuffer = (ubyte *) MALLOC(wLength)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMCPY(pBuffer, (ubyte *)pxHdr, wLength);

    /* insert fragment */
    frag = &(dgram->frag[i]);
    DIGI_MEMMOVE((ubyte *)(frag + 1), (ubyte *)frag,
                sizeof(struct fragment) * (dgram->fragNum - i));
    ++(dgram->fragNum);

    frag->pBuffer     = pBuffer;
    frag->wLength     = wLength;
    frag->oHdrLen     = oHdrLen;
    frag->wPayloadLen = wPayloadLen;
    frag->wOffset     = wOffset;
    frag->bMore       = bMore;

    dgram->wPayloadLen += wPayloadLen;

    /* check completion */
    wPayloadLen = 0;
    for (i=0; i < dgram->fragNum; i++)
    {
        frag = &(dgram->frag[i]);

        if (frag->wOffset == wPayloadLen)
        {
            wPayloadLen += frag->wPayloadLen;
            continue;
        }
        if (frag->wOffset > wPayloadLen) /* more fragments */
            goto exit;

        /* error */
        status = ERR_IPSEC_FRAGMENTATION;
        goto remove;
    }

    if (frag->bMore) /* more fragments */
        goto exit;

    /* return datagram */
    frag = &(dgram->frag[0]);
    wLength = wPayloadLen + frag->oHdrLen;
    if (wBufferSize < wLength) /* buffer too small */
    {
        if (NULL == (pBuffer = (ubyte *) MALLOC(wLength)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto remove;
        }
        *ppBuffer = pBuffer;
    }
    else
    {
        pBuffer = *ppBuffer;
    }

    *pwBufferSize = wLength;

    /* copy 1st fragment */
    DIGI_MEMCPY(pBuffer, frag->pBuffer, frag->wLength);
    pxHdr = (struct ipHdr *)pBuffer;

    SET_NTOHS(wFragOff, pxHdr->ip_off);
    wFragOff &= ~(IP_OFFMASK | IP_MF);
    SET_HTONS(pxHdr->ip_off, wFragOff);
    SET_HTONS(pxHdr->ip_len, wLength);

    /* calculate new ip header checksum */
    SET_HTONS(pxHdr->ip_sum, 0);
    SET_HTONS(pxHdr->ip_sum, Checksum16((ubyte *)pxHdr, frag->oHdrLen));

    /* copy more fragments */
    pBuffer += frag->wLength;
    for (i=1; i < dgram->fragNum; i++)
    {
        frag = &(dgram->frag[i]);
        DIGI_MEMCPY(pBuffer, frag->pBuffer + frag->oHdrLen, frag->wPayloadLen);
        pBuffer += frag->wPayloadLen;
    }

    status = STATUS_IPSEC_BYPASS;

remove:
    free_dgram(dgram);

exit:
    if (bMutexOn)
        RTOS_mutexRelease(m_mtx);

    return (sbyte4)status;
} /* IPSEC_fragRcv */


/*------------------------------------------------------------------*/

extern sbyte4
IPSEC_fragSnd(ubyte *pBuffer, ubyte2 wBufferSize, ubyte2 wMtu,
              funcPtrIPsecFragSend pSndFunc, void *sendCtx)
{
    MSTATUS status = OK;

    struct ipHdr *pxHdr;
    ubyte oHdrLen;
    ubyte2 wLength;

    ubyte *poPayload;
    ubyte2 wPayloadLen;

    ubyte2 wFragOff;
    ubyte2 wOffset;
    intBoolean bMore;

    ubyte2 wNfb;

    /* get ip header */
    if (wBufferSize < sizeof(struct ipHdr))
    {
        status = ERR_IPSEC_BAD_IP;
        goto exit;
    }
    pxHdr = (struct ipHdr *)pBuffer;

    /* check ip version */
    if (0x40 != (pxHdr->ip_vhl & 0xF0))
    {
        status = STATUS_IPSEC_BYPASS;
        goto exit;
    }

    /* check length */
    oHdrLen = (pxHdr->ip_vhl & 0x0F) << 2;
    SET_NTOHS(wLength, pxHdr->ip_len);

    if (oHdrLen < sizeof(struct ipHdr) ||
        wLength > wBufferSize ||
        oHdrLen > wLength)
    {
        status = ERR_IPSEC_BAD_IP;
        goto exit;
    }

    if (oHdrLen >= wMtu)
    {
        status = ERR_IPSEC_FRAGMENTATION;
        goto exit;
    }

    if (wMtu >= wLength) /* no need for fragmentation */
    {
        status = STATUS_IPSEC_BYPASS;
        goto exit;
    }

    /* check fragmentation */
    SET_NTOHS(wFragOff, pxHdr->ip_off);
    bMore = (IP_MF & (~(IP_OFFMASK) & wFragOff));
    wOffset = (IP_OFFMASK & wFragOff);

    /* send fragmented packets */
    wNfb = (wMtu - oHdrLen) / 8;
    wMtu = (wNfb * 8) + oHdrLen;

    poPayload = ((ubyte *)pxHdr) + oHdrLen;
    wPayloadLen = wLength - oHdrLen;

    for (;;)
    {
        wFragOff = wOffset;

        if (wMtu < wLength)
        {
            wOffset += wNfb;
            wPayloadLen = wLength - wMtu;

            wFragOff |= IP_MF;
            wLength = wMtu;
        }
        else
        {
            wPayloadLen = 0;
            if (bMore) wFragOff |= IP_MF;
        }

        SET_HTONS(pxHdr->ip_off, wFragOff);
        SET_HTONS(pxHdr->ip_len, wLength);

        SET_HTONS(pxHdr->ip_sum, 0);
        SET_HTONS(pxHdr->ip_sum, Checksum16((ubyte *)pxHdr, oHdrLen));

        if (OK > (status = pSndFunc(sendCtx, pBuffer, wLength)))
            goto exit;

        if (0 == wPayloadLen) /* done */
            break;

        DIGI_MEMMOVE(poPayload, pBuffer + wLength, wPayloadLen);
        wLength = wPayloadLen + oHdrLen;

    } /* for */

exit:
    return (sbyte4)status;
} /* IPSEC_fragSnd */


#endif /* __ENABLE_IPSEC_FRAGMENTATION__ */

