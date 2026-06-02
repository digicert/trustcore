/**
 * @file  ipsec6.c
 * @brief NanoSec IPsec IPv6 support implementation.
 *
 * @details    This file contains IPv6 support for NanoSec IPsec.
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IPSEC_SERVICE__
 *     +   \c \__ENABLE_DIGICERT_IPV6__
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

#if (defined(__ENABLE_DIGICERT_IPSEC_SERVICE__) && defined(__ENABLE_DIGICERT_IPV6__))

#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#include "../ipsec/ipsec6.h"
#include "../ipsec/ipsec_utils.h"
#include "../ipsec/ipsec_protos.h"


/*------------------------------------------------------------------*/

#ifndef EXIT_IPSEC
#define EXIT_IPSEC  { DB_PRINT("%s (%d): %d\n", __FUNCTION__, __LINE__, (int)status); goto exit; }
#endif


/*------------------------------------------------------------------*/

typedef struct ip6_context
{
    ubyte  *poBuffer;
    ubyte4  dwBufSize;
    ubyte4  dwHdrLen;

    ubyte  *poNextHeader;
    ubyte  *poDestAddr;

    ubyte4  dwLength;
    intBoolean bFragOff, bMoreFrags;

    intBoolean bIn;

} *IP6_context;


/*------------------------------------------------------------------*/

#define ADVANCE(_size) \
    ctx->poBuffer  += (_size);\
    ctx->dwBufSize -= (ubyte4)(_size);\
    ctx->dwHdrLen  += (ubyte4)(_size);\


#define BEGIN_EXT_HDR(_type, _hdr, _size) \
    _type * _hdr;\
    ubyte2 wBodyLen;\
\
    if (ctx->dwBufSize < (ubyte4)(_size))\
    {\
        status = (ctx->bIn ? ERR_IPSEC_BAD_IP6 : ERR_IPSEC_BUFFER_OVERFLOW);\
        EXIT_IPSEC\
    }\
    _hdr = (_type *) ctx->poBuffer;\
    ADVANCE(_size)\
\
    wBodyLen = (((ubyte2) (_hdr)->oHdrExtLen) << 3) + (ubyte2)8 - (ubyte2)(_size);\
    if ((ubyte4)wBodyLen > ctx->dwBufSize)\
    {\
        status = (ctx->bIn ? ERR_IPSEC_BAD_IP6 : ERR_IPSEC_BUFFER_OVERFLOW);\
        EXIT_IPSEC\
    }\
    ctx->poNextHeader = &(_hdr)->oNextHeader;\


#define END_EXT_HDR ADVANCE(wBodyLen)


/*------------------------------------------------------------------*/

static MSTATUS
DoExtHdr(IP6_context ctx)
{
    MSTATUS status = OK;

    BEGIN_EXT_HDR(struct extHdr6, pxExtHdr, SIZEOF_EXT_HDR6)
    END_EXT_HDR

exit:
    return status;
} /* DoExtHdr */


/*------------------------------------------------------------------*/
/*    IPv6 TLV options.*/

#define IPV6_TLV_PAD0        0
#define IPV6_TLV_PADN        1
#define IPV6_TLV_JUMBO        0xC2


/*------------------------------------------------------------------*/

static MSTATUS
DoHopOpts(IP6_context ctx)
{
    MSTATUS status = OK;

    if (0 != ctx->dwLength) /* skip over */
    {
        if (OK > (status = DoExtHdr(ctx)))
            EXIT_IPSEC
    }
    else
    {
        BEGIN_EXT_HDR(struct extHdr6, pxHopOptsHdr, SIZEOF_EXT_HDR6)

        while (wBodyLen)
        {
            ubyte opt_type = ctx->poBuffer[0];
            if (IPV6_TLV_PAD0 == opt_type)
            {
                wBodyLen--;
                ADVANCE(1)
            }
            else if (1 == wBodyLen)
            {
                status = (ctx->bIn ? ERR_IPSEC_BAD_IP6 : ERR_IPSEC_BUFFER_OVERFLOW);
                EXIT_IPSEC
            }
            else
            {
                ubyte opt_datalen = ctx->poBuffer[1];
                if ((opt_datalen + 2) > wBodyLen)
                {
                    status = (ctx->bIn ? ERR_IPSEC_BAD_IP6 : ERR_IPSEC_BUFFER_OVERFLOW);
                    EXIT_IPSEC
                }
                wBodyLen = wBodyLen - (opt_datalen + 2);
                ADVANCE(opt_datalen + 2)

                /* Jumbo payload option */
                if (IPV6_TLV_JUMBO == opt_type)
                {
                    ubyte4 dwLength;
                    if (4 != opt_datalen)
                    {
                        status = ERR_IPSEC_BAD_IP6;
                        EXIT_IPSEC
                    }
                    dwLength = DIGI_NTOHL(ctx->poBuffer - 4);

                    /* check length */
                    if (((ctx->dwHdrLen + ctx->dwBufSize - SIZEOF_IP6_HDR) < dwLength) ||
                        ((ctx->dwHdrLen + wBodyLen - SIZEOF_IP6_HDR) > dwLength))
                    {
                        status = (ctx->bIn ? ERR_IPSEC_BAD_IP6 : ERR_IPSEC_BUFFER_OVERFLOW);
                        EXIT_IPSEC
                    }

                    ctx->dwBufSize = dwLength + SIZEOF_IP6_HDR - ctx->dwHdrLen;
                    ctx->dwLength = dwLength + SIZEOF_IP6_HDR;
                    break;
                }
            }
        }

        END_EXT_HDR
    }

exit:
    return status;
} /* DoHopOpts */


/*------------------------------------------------------------------*/

static MSTATUS
DoRtn(IP6_context ctx)
{
    MSTATUS status = OK;

    if (NULL != ctx->poDestAddr) /* skip over */
    {
        if (OK > (status = DoExtHdr(ctx)))
            EXIT_IPSEC
    }
    else
    {
        BEGIN_EXT_HDR(struct rtnHdr6, pxRtnHdr, SIZEOF_RTN_HDR6)

        /* locate final destination */
        if ((0 == pxRtnHdr->oType) &&
            (0 != pxRtnHdr->oSegmentLeft))
        {
            sbyte4 n = (wBodyLen / 16);
            if (pxRtnHdr->oSegmentLeft <= n)
                ctx->poDestAddr = ctx->poBuffer + ((n - 1) * 16);
        }

        END_EXT_HDR
    }

exit:
    return status;
} /* DoRtn */


/*------------------------------------------------------------------*/

static MSTATUS
DoFrag(IP6_context ctx)
{
    MSTATUS status = OK;

    ubyte2 wFragOff;

    BEGIN_EXT_HDR(struct fragHdr6, pxFragHdr, SIZEOF_FRAG_HDR6)

    wFragOff = GET_NTOHS(pxFragHdr->wOffset);
    ctx->bMoreFrags = (IP6_MF & wFragOff) ? TRUE : FALSE;
    ctx->bFragOff = IP6_OFFMASK(wFragOff) ? TRUE : FALSE;

    END_EXT_HDR

exit:
    return status;
} /* DoFrag */


/*------------------------------------------------------------------*/

extern MSTATUS
GetPktInfo6(struct ip6Hdr *pxHdr6, ubyte2 wBufSize,
            ubyte2 *pwLength, ubyte2 *pwHdrLen,
            ubyte **ppoNextHeader, ubyte **ppoDestAddr,
            intBoolean *pbFragOff, intBoolean *pbMoreFrags,
            intBoolean bIn)
{
    MSTATUS status = OK;

    struct ip6_context ctx = { 0 };
    ubyte2 wLength;
    ubyte  oProtocol;

    if (SIZEOF_IP6_HDR > wBufSize)
    {
        status = (bIn ? ERR_IPSEC_BAD_IP6 : ERR_IPSEC_BUFFER_OVERFLOW);
        EXIT_IPSEC
    }

    if (0 != (wLength = GET_NTOHS(pxHdr6->ip6_payload_len)))
    {
        if (((ubyte4)wLength + SIZEOF_IP6_HDR) > wBufSize)
        {
            status = (bIn ? ERR_IPSEC_BAD_IP6 : ERR_IPSEC_BUFFER_OVERFLOW);
            EXIT_IPSEC
        }
        wBufSize =
        ctx.dwLength = (ubyte4)wLength + SIZEOF_IP6_HDR;
    }
    else /* skip Jumbo payload - FOR NOW */
    {
        status = STATUS_IPSEC_BYPASS;
        EXIT_IPSEC
    }

    ctx.poBuffer = ((ubyte *)pxHdr6) + SIZEOF_IP6_HDR;
    ctx.dwBufSize = wBufSize - SIZEOF_IP6_HDR;
    ctx.dwHdrLen = SIZEOF_IP6_HDR;

    ctx.bIn = bIn;
    ctx.poNextHeader = &pxHdr6->ip6_nexthdr;

    /* traverse extension headers */
    for (;;)
    {
        oProtocol = *(ctx.poNextHeader);

        if (     IPPROTO_HOPOPTS == oProtocol)
        {
            /* get Jumbo payload option */
            if (OK > (status = DoHopOpts(&ctx)))
                goto exit;
        }
        else if (IPPROTO_ROUTING == oProtocol)
        {
            if (OK > (status = DoRtn(&ctx)))
                goto exit;
        }
        else if (IPPROTO_FRAGMENT == oProtocol)
        {
            if (OK > (status = DoFrag(&ctx)))
                goto exit;

            if (ctx.bFragOff || ctx.bMoreFrags)
                break;
        }
        else if (IPPROTO_DSTOPTS == oProtocol)
        {
            if (OK > (status = DoExtHdr(&ctx)))
                EXIT_IPSEC
        }
        else
        {
            break;
        }
    } /* for */

    if (0 == ctx.dwLength)
    {
        status = ERR_IPSEC_BAD_IP6;
        EXIT_IPSEC
    }

    *pwLength       = (ubyte2) ctx.dwLength;
    *pwHdrLen       = (ubyte2) ctx.dwHdrLen;

    *pbFragOff      = ctx.bFragOff;;
    *pbMoreFrags    = ctx.bMoreFrags;

    *ppoNextHeader  = ctx.poNextHeader;
    *ppoDestAddr    = ctx.poDestAddr;

exit:
    return status;
} /* GetPktInfo6 */


#endif /* (defined(__ENABLE_DIGICERT_IPSEC_SERVICE__) && defined(__ENABLE_DIGICERT_IPV6__)) */

