
/**
 * @file  gdoi_client.c
 * @brief GDOI client implementation
 *
 * @details    GDOI group member functionality for receiving group keys
 *
 * @flags      Compilation flags required:
 *     + \c \__ENABLE_DIGICERT_GDOI_CLIENT__
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

#include "../../common/moptions.h"

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"

#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/mrtos.h"
#include "../../common/debug_console.h"

#include "../../crypto/md5.h"
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../crypto/crypto.h"
#include "../../crypto/hmac.h"
#include "../../crypto/ca_mgmt.h"

#include "../../ipsec/ipsec.h"
#include "../../ipsec/ipsec_defs.h"
#include "../../ipsec/ipsec_protos.h"
#include "../../ipsec/ipseckey.h"
#include "../../ike/ike.h"
#include "../../ike/ike_defs.h"
#include "../../ike/ike_childsa.h"
#include "../../ike/ike_crypto.h"
#include "../../ike/ikesa.h"
#include "../../ike/ike_state.h"
#include "../../ike/ike_utils.h"
#include "../../ike/ike_status.h"

#include "../../gdoi/gdoi.h"
#include "../../gdoi/client/gdoi_client.h"
#include "../../ipsec/script.h"

MOC_EXTERN_DATA_DECL moctime_t gStartTime;

#ifdef __ENABLE_DIGICERT_NW_REDUNDANCY__
extern MOC_IP_ADDRESS_S KDCHeartbeatMcastIp;
typedef struct encr_key
{
    ubyte encr_key_len;
    ubyte4 encr_key_validity;
    ubyte encr_key[CHILDSA_ENCRKEY_MAX];
} encr_key_s;
ubyte g_encr_key_index ;
encr_key_s g_encr_key[MOC_MAX_HEARTBEAT_ENCR_KEYS];
ubyte g_encr_key_avlbl = 0;
RTOS_MUTEX       m_NwRedMtx = NULL;
#endif

extern ikeSettings m_ikeSettings;
extern fqdnUnicastGroupConfig m_fqdnGroupList[MAX_UNICAST_GROUP]; /* FQDN unicast group list */

#define ADVANCE(_size) \
    ctx->pBuffer += (_size);\
    ctx->dwBufferSize -= (ubyte4) (_size);\
    ctx->dwLength += (ubyte4) (_size);\

#define _I 0
#define _R 1

static ubyte2 mAttrMode[] =
{
    ENCAPSULATION_MODE_TRANSPORT,
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    ENCAPSULATION_MODE_TUNNEL,
#endif
};

#define NUM_ATTR_MODE (sizeof(mAttrMode) / sizeof(ubyte2))

#define DBG_ERRCODE(_s) debug_print_status((sbyte *)__FILE__, __LINE__, (sbyte4)_s);
#define DBG_STATUS      DBG_ERRCODE(status)
#define DBG_EXIT        { DBG_STATUS goto exit; }
#define DBG_NL_EXIT     { debug_printnl(NULL); DBG_EXIT }

#ifdef __ENABLE_DIGICERT_HARNESS__
#define __crypto__(_d, _s) * _d = NULL
#define __crypto_i__(_d, _i) _d = NULL
#define _CRYPTO_ALLOC_(_d, _s) \
    if (OK > (status = CRYPTO_ALLOC(ctx->hwAccelCookie, _s, TRUE, (void**) &(_d)))) \
        DBG_EXIT
#define _CRYPTO_COPY_(_d, _s, _o) \
    _CRYPTO_ALLOC_(_d, _s) \
    DIGI_MEMCPY(_d, _o, _s);
#define _CRYPTO_FREE_(_d) \
    if (_d) CRYPTO_FREE(ctx->hwAccelCookie, TRUE, (void**) &(_d));
#else
#define __crypto__(_d, _s) _d[_s]
#define __crypto_i__(_d, _i) _d = _i
#define _CRYPTO_ALLOC_(_d, _s)
#define _CRYPTO_COPY_(_d, _s, _o)
#define _CRYPTO_FREE_(_d)
#endif

#ifdef CUSTOM_IKE_CATCH_EXCEPTION
#define CURR_PAYLOAD            ctx->oCurrPayload = ctx->oNextPayload;\
                                ctx->pCurrPayload = ctx->pBuffer;
#define CATCH_PAYLOAD           void *_pCPL = ctx->pCurrPayload;\
                                ubyte _oCPL = ctx->oCurrPayload;\
                                CURR_PAYLOAD
#define FINALLY_PAYLOAD         ctx->oCurrPayload = _oCPL;\
                                ctx->pCurrPayload = _pCPL;
#else
#define CURR_PAYLOAD
#define CATCH_PAYLOAD
#define FINALLY_PAYLOAD
#endif

#define IN_HDR(_type, _hdr, _size) \
    _type * _hdr = NULL;\
\
    if (ctx->dwBufferSize < (ubyte4)(_size))\
    {\
        /*SET_MSGTYPE(UNEQUAL_PAYLOAD_LENGTHS)*/\
        status = ERR_IKE_BAD_LEN;\
        DBG_EXIT\
    }\
    _hdr = (_type *) ctx->pBuffer;\
    ADVANCE(_size)\


#define IN_BEGIN_0(_type, _hdr, _size) \
    ubyte2 wLength, wBodyLen;\
    IN_HDR(_type, _hdr, _size)\
\
    SET_NTOHS(wLength, (_hdr)->wLength);\
    wBodyLen = (ubyte2)(wLength - ((ubyte2)(_size)));\
\
    if (wLength < (ubyte2)(_size))\
    {\
        /*SET_MSGTYPE(PAYLOAD_MALFORMED)*/\
        status = ERR_IKE_BAD_MSG;\
        DBG_EXIT\
    }\
\
    if ((ubyte4)wBodyLen > ctx->dwBufferSize)\
    {\
        /*SET_MSGTYPE(UNEQUAL_PAYLOAD_LENGTHS)*/\
        status = ERR_IKE_BAD_LEN;\
        DBG_EXIT\
    }\


#define IN_BEGIN(_type, _hdr, _size) \
    IN_BEGIN_0(_type, _hdr, _size)\
    ctx->oNextPayload = (_hdr)->oNextPayload;\

#define IN_END ADVANCE(wBodyLen)

#define IN_DOWN(_p, _n) \
    dwBufferSize = ctx->dwBufferSize;\
    dwLength = ctx->dwLength;\
    oNextPayload = ctx->oNextPayload;\
    pHdrParent = ctx->pHdrParent;\
    \
    ctx->dwBufferSize = wBodyLen;\
    ctx->dwLength = 0;\
    ctx->oNextPayload = _n;\
    ctx->pHdrParent = _p;\

#define IN_UP(_p) \
    ctx->pBuffer = ((ubyte *)(_p)) + wLength;\
    ctx->dwBufferSize = dwBufferSize - wBodyLen;\
    ctx->dwLength = dwLength + wBodyLen;\
    ctx->oNextPayload = oNextPayload;\
    ctx->pHdrParent = pHdrParent;\

#define DO_FUNC(_func) \
    if (OK > (status = _func(ctx)))\
        goto exit;\

#ifdef CUSTOM_IKE_CATCH_EXCEPTION
#define IN_FUNC(_inFunc) \
    { CATCH_PAYLOAD \
      DO_FUNC(_inFunc)\
      FINALLY_PAYLOAD }
#else
#define IN_FUNC(_inFunc) DO_FUNC(_inFunc)
#endif

#define IN_PAYLOAD(_nextPl, _inFunc, _st) \
    if (_nextPl != ctx->oNextPayload)\
    {\
        CURR_PAYLOAD \
        /*SET_MSGTYPE(INVALID_PAYLOAD_TYPE)*/\
        status = (_st);\
        DBG_EXIT\
    }\
    IN_FUNC(_inFunc)\

#define IN_OPT_PAYLOAD(_nextPl, _inFunc) \
    if (_nextPl == ctx->oNextPayload)\
    {\
        IN_FUNC(_inFunc)\
    }\

#define IN_LOOP_BEGIN \
    for (;;)\
    {\
        ubyte _oNp = ctx->oNextPayload;\
        CATCH_PAYLOAD \

#define IN_NEXT(_nextPl, _inFunc) \
        if (_oNp == (_nextPl))\
        {\
            DO_FUNC(_inFunc)\
        }\
        else \

#define IN_LOOP_END \
        {\
            FINALLY_PAYLOAD\
            break;\
        }\
        FINALLY_PAYLOAD \
    }\


/*------------------------------------------------------------------*/

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
extern void
PrintIPsecKey(IPSECKEY_EX pxKey, MSTATUS st, ubyte4 dwSpdId);
#else
#define PrintIPsecKey(_key, _st, _spdid)
#endif

extern MSTATUS
OutHashGen(IKE_context ctx);

extern MSTATUS
OutNonce(IKE_context ctx);

extern MSTATUS
OutId2(IKE_context ctx);

extern MSTATUS
InAttrBV(IKE_context ctx, ubyte2 *type, ubyte2 *len, ubyte2 *value, ubyte4 *value1);

extern MSTATUS
InHash12(IKE_context ctx);

extern MSTATUS
InNonce(IKE_context ctx);

extern MSTATUS
InGen(IKE_context ctx, ubyte2 *pwBodyLen);

extern MSTATUS
OutHash12(IKE_context ctx);

extern MSTATUS
InHash34(IKE_context ctx);

extern MSTATUS
OutHash34(IKE_context ctx);


/*------------------------------------------------------------------*/

static MSTATUS
InSak(IKE_context ctx)
{
    MSTATUS status = OK;

    // TBD
    IN_BEGIN(struct ikeGenHdr, pxGenHdr, SIZEOF_IKE_GEN_HDR)
    IN_END

exit:
    return status;
} /* InSak */


/*------------------------------------------------------------------*/

static MSTATUS
InGap(IKE_context ctx)
{
    MSTATUS status = OK;

    // for now
    IN_BEGIN(struct ikeGenHdr, pxGenHdr, SIZEOF_IKE_GEN_HDR)
    IN_END

exit:
    return status;
} /* InGap */


/*------------------------------------------------------------------*/

static MSTATUS
InSatId2(IKE_context ctx)
{
    /* See InId2() */
    MSTATUS status = OK;

    IPSECSA pxIPsecSa = P2XG_IPSECSA(ctx->pxP2Xg);

    /* SRC ID, DST ID */
    sbyte4 i;
    for (i=1; i >= 0; i--)
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        ubyte4 dwIpAddr, dwIpAddrEnd;
#else
        #define ipAddr dwIpAddr
        #define ipAddrEnd dwIpAddrEnd
#endif
        MOC_IP_ADDRESS_S ipAddr = MOC_IPADDR_NONE;
        MOC_IP_ADDRESS_S ipAddrEnd = MOC_IPADDR_NONE;

        ubyte oType;
        ubyte2 wPort;
        ubyte2 wBodyLen;

        if (ctx->dwBufferSize < SIZEOF_GDOI_SAA_ID)
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }

        oType = ctx->pBuffer[0];
        wPort = DIGI_NTOHS(ctx->pBuffer + 1);
        wBodyLen = DIGI_NTOHS(ctx->pBuffer + 3);
        ADVANCE(SIZEOF_GDOI_SAA_ID)

        if (ctx->dwBufferSize < wBodyLen)
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }

        /* identification data */
        switch (oType)
        {
        case ID_IPV4_ADDR :
            if (4 != wBodyLen)
            {
                status = ERR_IKE_BAD_LEN;
                DBG_EXIT
            }

            dwIpAddr = DIGI_NTOHL(ctx->pBuffer);

            if (!i /* !!! */ && !dwIpAddr)
            {
                status = ERR_IKE_BAD_MSG;
                DBG_EXIT
            }

#ifdef __ENABLE_DIGICERT_IPV6__
            SET_MOC_IPADDR4(ipAddr, dwIpAddr);
#endif
            ipAddrEnd = ipAddr;
            break;

        case ID_USER_FQDN:
            pxIPsecSa->wPort[i] = wPort;
            ADVANCE(wBodyLen)
            continue;
        case ID_IPV4_ADDR_RANGE :
        case ID_IPV4_ADDR_SUBNET :
            if (8 != wBodyLen)
            {
                status = ERR_IKE_BAD_LEN;
                DBG_EXIT
            }

            dwIpAddr = DIGI_NTOHL(ctx->pBuffer);
            dwIpAddrEnd = DIGI_NTOHL(ctx->pBuffer + 4);

            if (ID_IPV4_ADDR_RANGE == oType) /* range */
            {
                if (!i /* !!! */ && !dwIpAddrEnd && !dwIpAddr)
                {
                    status = ERR_IKE_BAD_MSG;
                    DBG_EXIT
                }
                if (dwIpAddrEnd < dwIpAddr) /* make sure ip < ip_end */
                {
                    ubyte4 dwTmp = dwIpAddr;
                    dwIpAddr = dwIpAddrEnd;
                    dwIpAddrEnd = dwTmp;
                }
            }
            else /* subnet/mask */
            {
                /* TO DO: valid netmask? */

                /* convert subnet/mask to ip range */
                dwIpAddr &= dwIpAddrEnd;
                dwIpAddrEnd = (dwIpAddr | ~(dwIpAddrEnd));
            }

#ifdef __ENABLE_DIGICERT_IPV6__
            SET_MOC_IPADDR4(ipAddr, dwIpAddr);
            SET_MOC_IPADDR4(ipAddrEnd, dwIpAddrEnd);
#endif
            break;

#ifdef __ENABLE_DIGICERT_IPV6__
        case ID_IPV6_ADDR :
            if (16 != wBodyLen)
            {
                status = ERR_IKE_BAD_LEN;
                DBG_EXIT
            }

            SET_MOC_IPADDR6(ipAddr, ctx->pBuffer);
            ipAddrEnd = ipAddr;
            break;

        case ID_IPV6_ADDR_RANGE :
            if (32 != wBodyLen)
            {
                status = ERR_IKE_BAD_LEN;
                DBG_EXIT
            }

            SET_MOC_IPADDR6(ipAddr, ctx->pBuffer);
            SET_MOC_IPADDR6(ipAddrEnd, ctx->pBuffer + 16);

            if (LT_MOC_IPADDR6(ipAddrEnd, ipAddr)) /* make sure ip < ip_end */
            {
                MOC_IP_ADDRESS_S ipTmp = ipAddr;
                ipAddr = ipAddrEnd;
                ipAddrEnd = ipTmp;
            }
            break;

        case ID_IPV6_ADDR_SUBNET :
        {
            ubyte *m, *s, *e;
            sbyte4 j;

            if (32 != wBodyLen)
            {
                status = ERR_IKE_BAD_LEN;
                DBG_EXIT
            }

            SET_MOC_IPADDR6(ipAddr, ctx->pBuffer);
            ipAddrEnd = ipAddr;

            /* convert subnet/mask to ip range */
            m = ctx->pBuffer + 16;
            s = (ubyte *) ipAddr.uin.addr6;
            e = (ubyte *) ipAddrEnd.uin.addr6;

            for (j=0; j < 16; j++)
            {
                ubyte c = m[j];
                if (0xFF != c)
                {
                    /* TO DO: valid netmask? */
                    s[j] &= c;
                    e[j] |= ~c;
                    j++; /* !!! */
                    break;
                }
            }

            for (; j < 16; j++)
            {
                if (0x00 != m[j]) /* invalid netmask */
                {
                    status = ERR_IKE_BAD_ID2;
                    DBG_EXIT
                }
                s[j] = 0x00;
                e[j] = 0xFF;
            }
            break;
        }
#endif /* __ENABLE_DIGICERT_IPV6__ */

        default :
            ADVANCE(wBodyLen)
            continue;
            //break;
        } /* switch */

        /* process data */
        if (!i)
        {
#ifdef __ENABLE_DIGICERT_IPV6__
            if (!ISZERO_MOC_IPADDR(ipAddr) &&
                (ipAddr.family != pxIPsecSa->dwIP[1].family))
            {
                status = ERR_IKE_BAD_ID2;
                DBG_EXIT
            }
#endif
        }

        pxIPsecSa->wPort[i] = wPort;

        pxIPsecSa->dwIP[i] = ipAddr;
        pxIPsecSa->dwIPEnd[i] = ipAddrEnd;

        ADVANCE(wBodyLen)

#ifndef __ENABLE_DIGICERT_IPV6__
        #undef ipAddr
        #undef ipAddrEnd
#endif
    } /* for */

exit:
    return status;
} /* InSatId2 */


/*------------------------------------------------------------------*/

static MSTATUS
InSat(IKE_context ctx)
{
    MSTATUS status = OK;

    IPSECSA pxIPsecSa = P2XG_IPSECSA(ctx->pxP2Xg);
    sbyte4 i = pxIPsecSa->axP2Sa[0].oChildSaLen;
    IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[0].axChildSa[i].ipsecPps);
    ubyte oTfmId;

    ubyte2 wLifeType = 0, wAuthAlgo = 0, wKeyLen = 0;

    ubyte4 dwBufferSize;
    ubyte4 dwLength;
    ubyte oNextPayload;
    void *pHdrParent;

    /* SAT payload header */
    IN_BEGIN(struct gdoiSaaHdr, pxSatHdr, SIZEOF_GDOI_SAA_HDR)

    if (IPSEC_NEST_MAX <= i) /* too many payloads */
    {
        status = ERR_IKE_MISMATCH;
        DBG_EXIT
    }
/*
    debug_print("    ");
    debug_print_ike_proto(pxSatHdr->oProtoId);
    debug_printnl(NULL);
*/
    /* TODO: check against initiator's (existing) proto/algos */

    switch (pxSatHdr->oProtoId)
    {
    case GDOI_PROTO_IPSEC_ESP :
        pxIPsecPps->oProtocol = PROTO_IPSEC_ESP;
        break;
    case GDOI_PROTO_IPSEC_AH :
        pxIPsecPps->oProtocol = PROTO_IPSEC_AH;
        break;
    default :
        status = ERR_IKE_BAD_PROTOCOL;
        DBG_EXIT
    }

    /* down one level - go to child payloads */
    IN_DOWN(pxSatHdr, 0)

    if (1 > ctx->dwBufferSize)
    {
        status = ERR_IKE_BAD_LEN;
        DBG_EXIT
    }
    pxIPsecSa->oUlp = ctx->pBuffer[0]; /* transport layer protocol */
    ADVANCE(1)

    /* SRC ID, DST ID */
    DO_FUNC(InSatId2)

    /* Transform ID, SPI */
    if (ctx->dwBufferSize < (sizeof(ubyte4) + 1))
    {
        status = ERR_IKE_BAD_LEN;
        DBG_EXIT
    }
    oTfmId = ctx->pBuffer[0];

    debug_print("     ");
    debug_print_ike_tfmid(oTfmId, pxIPsecPps->oProtocol);
    debug_printnl(NULL);

    pxIPsecPps->oEncrAlgo   = 0; /* jic */
    debug_print("      ");

    /* AH */
    if (PROTO_IPSEC_AH == pxIPsecPps->oProtocol)
    {
#ifndef __ENABLE_DIGICERT_PFKEY__
        if (NULL == CHILDSA_findAuthAlgo(0, oTfmId, 0, 0)) /* AH_MD5, AH_SHA, etc. */
#else
        CHILDSA_authInfo *pAuthAlgo = CHILDSA_findAuthAlgo(0, oTfmId, 0, 0);
        if ((NULL == pAuthAlgo) || !pAuthAlgo->bSupported)
#endif
        {
            debug_printnl("AUTH-ALG: unsupported");
            status = ERR_IKE_MISMATCH_AUTH_ALGO;
            goto exit; /* unknown auth algo */
        }
    }

    /* ESP or ESP_AUTH */
    else
#ifndef __ENABLE_DIGICERT_PFKEY__
    if (ESP_NULL != oTfmId)
    {
        if (NULL == CHILDSA_findEncrAlgo(oTfmId, 0, 0, 0, NULL))
        {
            debug_printnl("ENCR-ALG: unsupported");
            status = ERR_IKE_MISMATCH_ENCR_ALGO;
            goto exit; /* unknown encr algo*/
        }
        pxIPsecPps->oEncrAlgo = oTfmId; /* set encr. algo. */
    }
#else
    {
        CHILDSA_encrInfo *pEncrAlgo = CHILDSA_findEncrAlgo(oTfmId, 0, 0,
                                                           0, NULL);
        if ((NULL == pEncrAlgo) || !pEncrAlgo->bSupported)
        {
            debug_printnl("ENCR-ALG: unsupported");
            status = ERR_IKE_MISMATCH_ENCR_ALGO;
            goto exit; /* unknown encr algo*/
        }
        if (ESP_NULL != oTfmId)
        {
            pxIPsecPps->oEncrAlgo = oTfmId; /* set encr. algo. */
        }
    }
#endif

    pxIPsecPps->oTfmId = oTfmId;
    pxIPsecPps->dwSpi[0] = DIGI_NTOHL(ctx->pBuffer + 1);
    ADVANCE(sizeof(ubyte4) + 1)

    /* RFC 2407 SA Attributes */
    pxIPsecPps->wAuthAlgo   = 0;
    pxIPsecPps->wMode       = ENCAPSULATION_MODE_TRANSPORT;
    pxIPsecPps->dwExpKBytes = 0;
    pxIPsecPps->dwExpSecs   = 0;
    pxIPsecPps->wEncrKeyLen = 0;

    for (;;) /* see InAttrs2() */
    {
        ubyte2 wType, wValue, wLength;
        ubyte4 dwValue;

        /* get data attribute */
        if (0 == ctx->dwBufferSize) break;

        if (OK != (status = InAttrBV(ctx, &wType, &wLength, &wValue, &dwValue)))
        {
            goto exit;
        }

        /* check encoding */
        switch (wType)
        {
        case AUTH_ALGORITHM :
        case SA_LIFE_TYPE :
        case ENCAPSULATION_MODE :
        case KEY_LENGTH :
            if (0 != wLength) /* must be TV (B) */
            {
                status = ERR_IKE_BAD_ATTR;
                DBG_NL_EXIT
            }
            break;
        }

        switch (wType)
        {
        case AUTH_ALGORITHM :
            wAuthAlgo = wValue;
            break;
        case KEY_LENGTH :
            debug_int(wValue);
            debug_print("-BITS ");

            if (!wValue || (wValue % 8))
            {
                status = ERR_IKE_MISMATCH_KEYLEN;
                debug_printnl("unsupported");
                goto exit;
            }
            wKeyLen = wValue; /* in bits */
            break;
        case SA_LIFE_TYPE :
            wLifeType = wValue;
            break;
        case SA_LIFE_DURATION :     /* B/V  */
            if (0 != wLength)
            {
                if ((ubyte2)sizeof(ubyte2) != wLength &&
                    (ubyte2)sizeof(ubyte4) != wLength)
                {
                    status = ERR_IKE_BAD_ATTR;
                    DBG_NL_EXIT
                }
            }
            else dwValue = wValue;

            switch (wLifeType)
            {
            case SA_LIFE_TYPE_SECONDS :
                debug_uint(dwValue);
                debug_print("-SECONDS ");
                pxIPsecPps->dwExpSecs = dwValue;
                break;
            case SA_LIFE_TYPE_KBYTES :
                debug_uint(dwValue);
                debug_print("-KILOBYTES ");
                pxIPsecPps->dwExpKBytes = dwValue;
                break;
            default :
                status = ERR_IKE_BAD_ATTR;
                DBG_NL_EXIT
            }
            break;

            case ENCAPSULATION_MODE :
            {
                sbyte4 i;
                for (i = NUM_ATTR_MODE - 1; i >= 0; i--)
                {
                    if (wValue == mAttrMode[i])
                        break;
                }

                if (0 > i) /* unsupported encap. mode */
                {
                    status = ERR_IKE_MISMATCH_ENCAP_MODE;
                    debug_print("ENCAP: ");
                    debug_print_ike_p2_attr_v(wValue, ENCAPSULATION_MODE);
                    debug_printnl(" unsupported");
                    goto exit;

                }
                pxIPsecPps->wMode = wValue;

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
                debug_print_ike_p2_attr_v(wValue, ENCAPSULATION_MODE);
                debug_print(" ");
#endif
                break;
            }

        default : /* unknown attribute */
            debug_print("'");
            debug_int(wType);
            debug_print("'(");
            if (wLength)
            {
                debug_print("[");
                debug_int(wLength);
                debug_print("]");
            }
            else
            {
                debug_int(wValue);
            }
            debug_print(") ");
            break;
        } /* switch */

    } /* for */

    /* check auth. algo. */
    if ((PROTO_IPSEC_AH == pxIPsecPps->oProtocol) ||
        (ESP_NULL == oTfmId)) /* ESP_NULL w/o auth. is not supported! */
    {
        if (!wAuthAlgo) /* auth algo must be specified */
        {
            status = ERR_IKE_MISMATCH_AUTH_ALGO;
            debug_printnl("AUTH-ALG: missing");
            goto exit;
        }
    }

    if (wAuthAlgo)
    {
        CHILDSA_authInfo *pAuthAlgo = CHILDSA_findAuthAlgo(wAuthAlgo, 0, 0, 0);
        if ((NULL == pAuthAlgo) /* unsupported */
#ifdef __ENABLE_DIGICERT_PFKEY__
            || !pAuthAlgo->bSupported
#endif
            )
        {
            status = ERR_IKE_MISMATCH_AUTH_ALGO;
            debug_print("AUTH-ALG: ");
            debug_print_ike_p2_attr_v(wAuthAlgo, AUTH_ALGORITHM);
            debug_printnl(" unsupported");
            goto exit;
        }

        if ((PROTO_IPSEC_AH == pxIPsecPps->oProtocol) &&
            (oTfmId != pAuthAlgo->oTfmId)) /* mismatch */
        {
            status = ERR_IKE_MISMATCH_AUTH_ALGO;
            debug_printnl("AUTH-ALG: attribute mismatch");
            goto exit;
        }
    }

    if (wAuthAlgo)
    {
        pxIPsecPps->wAuthAlgo = wAuthAlgo;
        debug_print_ike_p2_attr_v(wAuthAlgo, AUTH_ALGORITHM);
        debug_print(" ");
    }

    /* check key length */
    if (pxIPsecPps->oEncrAlgo)
    {
        ubyte2 wLen = 0;
        CHILDSA_encrInfo *pEncrAlgo =
                            CHILDSA_findEncrAlgo(pxIPsecPps->oEncrAlgo, 0, 0,
                                                 (ubyte2)(wKeyLen/8),
                                                 (wKeyLen ? NULL : &wLen));
        if (NULL == pEncrAlgo)
        {
            status = ERR_IKE_MISMATCH_ENCR_ALGO;
            debug_printnl("ENCR-ALG: mismatch");
            goto exit;
        }

        if (wKeyLen)
        {
            if (pEncrAlgo->bFixedKeyLen) /* RFC2409 p.36 */
            {
                status = ERR_IKE_MISMATCH_KEYLEN;
                debug_printnl("KEY-LENGTH: unexpected");
                goto exit;
            }
            pxIPsecPps->wEncrKeyLen = (ubyte2)(wKeyLen/8);
        }
        else
        {
            if (!pEncrAlgo->bFixedKeyLen)
            {
                debug_print("DEFAULT: ");
                debug_int(wLen*8);
                debug_print("-BITS ");
            }
        }
    }
    else if (wKeyLen)
    {
        debug_print("KEY-LENGTH: ignored ");
    }

    debug_printnl(NULL);

    /* up one level */
    IN_UP(pxSatHdr)

    /* done */
    pxIPsecSa->axP2Sa[0].oChildSaLen++;

exit:
    return status;
} /* InSat */


/*------------------------------------------------------------------*/

static MSTATUS
InSaG(IKE_context ctx)
{
    MSTATUS status = OK;

    IPSECSA pxIPsecSa = P2XG_IPSECSA(ctx->pxP2Xg);

    ubyte4 dwBufferSize;
    ubyte4 dwLength;
    ubyte oNextPayload;
    void *pHdrParent;

    /* SA payload header */
    IN_BEGIN(struct gdoiSaHdr, pxSaHdr, SIZEOF_GDOI_SA_HDR)

    if (ISAKMP_GDOI != pxSaHdr->oDoi)
    {
        status = ERR_IKE_BAD_MSG;
        DBG_EXIT
    }

    if (0 != pxSaHdr->oSit)
    {
        status = ERR_IKE_BAD_MSG;
        DBG_EXIT
    }

    /* down one level - go to child payloads */
    IN_DOWN(pxSaHdr, pxSaHdr->oNextSaaPayload)

    /* SA Attribute payload(s) */
    IN_OPT_PAYLOAD(ISAKMP_NEXT_SAK, InSak)

    IN_OPT_PAYLOAD(ISAKMP_NEXT_GAP, InGap)

    pxIPsecSa->axP2Sa[0].oChildSaLen = 0; /* jic */

    IN_LOOP_BEGIN
        IN_NEXT(ISAKMP_NEXT_SAT, InSat)
    IN_LOOP_END

    /* up one level */
    IN_UP(pxSaHdr)

exit:
    return status;
} /* InSaG */


/*------------------------------------------------------------------*/

static MSTATUS
InSeq(IKE_context ctx)
{
    MSTATUS status;

    IKESA pxSa = ctx->pxSa;

    ubyte2 wBodyLen;
    ubyte4 dwSeqNo;

    /* generic header */
    if (OK != (status = InGen(ctx, &wBodyLen)))
        goto exit;

    /* KEK sequence number */
    if (sizeof(ubyte4) > wBodyLen)
    {
        status = ERR_IKE_BAD_LEN;
        DBG_EXIT
    }

    dwSeqNo = DIGI_NTOHL(ctx->pBuffer - wBodyLen);

    /* we are GM (client) */
    if (IS_INITIATOR(pxSa)) /* PULL; see gdoiI3_in(() */
    {
        IKESA pxKEK = pxSa->ikePeerConfig->pxKEK;
        if (NULL != pxKEK) /* jic */
        {
            pxKEK->dwSeqNo = dwSeqNo;
        }
    }
    else /* PUSH */
    {

    }

exit:
    return status;
} /* InSeq */


/*------------------------------------------------------------------*/

static MSTATUS
InTekAttrs(IKE_context ctx)
{
    MSTATUS status = OK;

    ubyte4 dwSpi = DIGI_NTOHL(ctx->pBuffer - sizeof(ubyte4));
    IPSECSA pxIPsecSa = P2XG_IPSECSA(ctx->pxP2Xg);
    ubyte2 wEncrKeyLen = 0, wAuthKeyLen = 0;
    ubyte oProtoId = 0;

    /* identify SPI, find key lengths; see DoKe2() */
    sbyte4 i;
    for (i = pxIPsecSa->axP2Sa[0].oChildSaLen - 1; i >= 0; i--)
    {
        IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[0].axChildSa[i].ipsecPps);

        if (dwSpi != pxIPsecPps->dwSpi[0])
        {
            continue;
        }

        oProtoId = pxIPsecPps->oProtocol; /* PROTO_IPSEC_AH or PROTO_IPSEC_ESP */

        if (pxIPsecPps->oEncrAlgo)
        {
            CHILDSA_encrInfo *pEncrAlgo;

            if (0 == (wEncrKeyLen = pxIPsecPps->wEncrKeyLen))
            {
                pEncrAlgo = CHILDSA_findEncrAlgo(pxIPsecPps->oEncrAlgo, 0, 0, 0,
                                                 &wEncrKeyLen);
            }
#if !defined(__DISABLE_AES_CIPHERS__) || defined(__ENABLE_DIGICERT_GCM__) || defined(__ENABLE_DIGICERT_PFKEY__)
            else
            {
                pEncrAlgo = CHILDSA_findEncrAlgo(pxIPsecPps->oEncrAlgo, 0, 0,
                                                 wEncrKeyLen, NULL);
            }
            if (NULL == pEncrAlgo) /* jic */
            {
                status = ERR_NULL_POINTER;
                DBG_EXIT
            }
            wEncrKeyLen = wEncrKeyLen + pEncrAlgo->oNonceLen;
#endif
        }

        if (pxIPsecPps->wAuthAlgo)
        {
            CHILDSA_authInfo *pAuthAlgo =
                        CHILDSA_findAuthAlgo(pxIPsecPps->wAuthAlgo, 0, 0, 0);
            if (NULL == pAuthAlgo) /* jic */
            {
                status = ERR_NULL_POINTER;
                DBG_EXIT
            }
            wAuthKeyLen = pAuthAlgo->wKeyLen;
        }

        break; /* !!! */
    } /* for */

    if (0 > i) /* SPI not found */
    {
        goto exit;
    }

    for (;;)
    {
        ubyte2 wType, wLength, wValue;
        ubyte4 dwValue;

        /* get data attribute */
        if (0 == ctx->dwBufferSize) break;

        if (OK != (status = InAttrBV(ctx, &wType, &wLength, &wValue, &dwValue)))
        {
            goto exit;
        }

        if (0 == wLength) /* must be TLV (V) */
        {
            status = ERR_IKE_BAD_ATTR;
            DBG_EXIT
        }

        switch (wType)
        {
        case TEK_ALGORITHM_KEY :
            if ((PROTO_IPSEC_ESP == oProtoId) &&
                (0 != wEncrKeyLen) && (wEncrKeyLen <= wLength))
            {
                // TODO: check duplicate
                DIGI_MEMCPY(pxIPsecSa->axP2Sa[0].axChildSa[i].poKey[0],
                           ctx->pBuffer - wLength, wEncrKeyLen);
            }
            else
            {
                status = ERR_IKE_BAD_ATTR; // for now
                DBG_EXIT
            }
            break;
        case TEK_INTEGRITY_KEY :
            if ((PROTO_IPSEC_ESP == oProtoId) &&
                (0 != wAuthKeyLen) && (wAuthKeyLen <= wLength))
            {
                // TODO: check duplicate
                DIGI_MEMCPY(&(pxIPsecSa->axP2Sa[0].axChildSa[i].poKey[0][wEncrKeyLen]),
                           ctx->pBuffer - wLength, wAuthKeyLen);
            }
            else
            {
                status = ERR_IKE_BAD_ATTR; // for now
                DBG_EXIT
            }
            break;
        case TEK_SOURCE_AUTH_KEY :
            if ((PROTO_IPSEC_AH == oProtoId) &&
                (0 != wAuthKeyLen) && (wAuthKeyLen <= wLength))
            {
                // TODO: check duplicate
                DIGI_MEMCPY(pxIPsecSa->axP2Sa[0].axChildSa[i].poKey[0],
                           ctx->pBuffer - wLength, wAuthKeyLen);
            }
            else
            {
                status = ERR_IKE_BAD_ATTR; // for now
                DBG_EXIT
            }
            break;
        default :
            DBG_ERRCODE(ERR_IKE_BAD_ATTR)
            break; /* ignore */
        }

    }


    // TODO: need to check if all required keys are sent!

exit:
    return status;
} /* InTekAttrs */


/*------------------------------------------------------------------*/

static MSTATUS
InKekAttrs(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxKEK = ctx->pxSa->ikePeerConfig->pxKEK;
    sbyte4 result = 0;

    if (NULL == pxKEK) /* jic */
    {
        goto exit;
    }

    /* check SPI (i.e. IKE cookie) */
    if (OK > (status = DIGI_MEMCMP(pxKEK->poCky_I, ctx->pBuffer - IKE_P1_SPI_SIZE,
                                  IKE_COOKIE_SIZE, &result)))
    {
        DBG_EXIT
    }
    if (result)
    {
        goto exit;
    }

    if (OK > (status = DIGI_MEMCMP(pxKEK->poCky_R, ctx->pBuffer - IKE_COOKIE_SIZE,
                                  IKE_COOKIE_SIZE, &result)))
    {
        DBG_EXIT
    }
    if (result)
    {
        goto exit;
    }

    for (;;)
    {
        ubyte2 wType, wLength, wValue;
        ubyte4 dwValue;

        /* get data attribute */
        if (0 == ctx->dwBufferSize) break;

        if (OK != (status = InAttrBV(ctx, &wType, &wLength, &wValue, &dwValue)))
        {
            goto exit;
        }

        if (0 == wLength) /* must be TLV (V) */
        {
            status = ERR_IKE_BAD_ATTR;
            DBG_EXIT
        }

        switch (wType)
        {
        case KEK_ALGORITHM_KEY :
        {
            /* See DoKe() */
            ubyte2 wIvLen = pxKEK->pCipherSuite->wIvLen;
            ubyte2 wEncrKeyLen = pxKEK->wEncrKeyLen;

            if (wLength < (wIvLen + wEncrKeyLen))
            {
                status = ERR_IKE_BAD_ATTR; // for now
                DBG_EXIT
            }
            // TODO: check duplicate

            /* encryption iv */
            DIGI_MEMCPY(pxKEK->u.v1.poIv, ctx->pBuffer - wLength, wIvLen);
            DIGI_MEMCPY(pxKEK->u.v1.poIvOld, pxKEK->u.v1.poIv, wIvLen);
            debug_printd((sbyte *)"    Initialization vector:", pxKEK->u.v1.poIv, wIvLen);

            /* encryption key */
            DIGI_MEMCPY(pxKEK->u.v1.poKeyId_e, ctx->pBuffer - (wLength - wIvLen), wEncrKeyLen);
            debug_printk((sbyte *)"    Encryption key", pxKEK->u.v1.poKeyId_e, wEncrKeyLen);

            pxKEK->flags |= IKE_SA_FLAG_KE;
            break;
        }
        case SIG_ALGORITHM_KEY :
            // TBA
            //pxKEK->pKey;
            break;
        default :
            break; /* ignore */
        }

    }

    pxKEK->flags |= IKE_SA_FLAG_MATURE;
    pxKEK->dwTimeCreated = RTOS_deltaMS(&gStartTime, NULL);


exit:
    return status;
} /* InKekAttrs */


/*------------------------------------------------------------------*/

static MSTATUS
InKd(IKE_context ctx)
{
    MSTATUS status = OK;

    ubyte2 wKpNum;

    ubyte4 dwBufferSize;
    ubyte4 dwLength;
    ubyte oNextPayload;
    void *pHdrParent;

    /* KD payload header */
    IN_BEGIN(struct gdoiKdHdr, pxKdHdr, SIZEOF_GDOI_KD_HDR)

    if (0 == pxKdHdr->wNum)
    {
        status = ERR_IKE_BAD_LEN;
        DBG_EXIT
    }
    SET_NTOHS(wKpNum, pxKdHdr->wNum);

    /* go to KP's */
    IN_DOWN(pxKdHdr, 0)

    for (; wKpNum; wKpNum--)
    {
        ubyte oSpiSize;

        IN_BEGIN_0(struct gdoiKP, pxKp, SIZEOF_GDOI_KP)

        oSpiSize = pxKp->oSpiSize;

        if (wBodyLen < oSpiSize)
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }

        /* get SPI size */
        switch (pxKp->oType)
        {
        case KD_TYPE_TEK :
            if (sizeof(ubyte4) != oSpiSize)
            {
                status = ERR_IKE_BAD_SPI;
                DBG_EXIT
            }
            break;
        case KD_TYPE_KEK :
        case KD_TYPE_LKH :
            if (IKE_P1_SPI_SIZE != oSpiSize)
            {
                status = ERR_IKE_BAD_SPI;
                DBG_EXIT
            }
            break;
        case KD_TYPE_SID : /* PULL only */
            if (oSpiSize)
            {
                status = ERR_IKE_BAD_SPI;
                DBG_EXIT
            }
            break;
        default :
            break;
        }

        if (oSpiSize)
        {
            ADVANCE(oSpiSize)
            wBodyLen = (ubyte2)(wBodyLen - oSpiSize);
        }

        switch (pxKp->oType)
        {
        case KD_TYPE_TEK :
            DO_FUNC(InTekAttrs)
            break;
        case KD_TYPE_KEK :
            DO_FUNC(InKekAttrs)
            break;
        case KD_TYPE_LKH : /* must not PUSH to > 1 GM */
            break;
        case KD_TYPE_SID : /* PULL only */
            break;
        default :
            break;
        }

        IN_END
    } /* for */

    IN_UP(pxKdHdr)

exit:
    return status;
} /* InKd */


/*------------------------------------------------------------------*/

extern MSTATUS
gpullI1_out(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  GDOI Initiator 1 -->");

    /* HASH(1) --> */
    DO_FUNC(OutHashGen)

    /* Ni --> */
    DO_FUNC(OutNonce)

    /* ID --> */
    DO_FUNC(OutId2)

    /* HASH(1) data */
    DO_FUNC(OutHash12)

exit:
    return status;
} /* gpullI1_out */


/*------------------------------------------------------------------*/

extern MSTATUS
gpullI2_in(IKE_context ctx)
{
    MSTATUS status = OK;

    debug_printnl("  GDOI Initiator 2 <--");

    /* <-- HASH(2) */
    IN_PAYLOAD(ISAKMP_NEXT_HASH, InHash12, ERR_IKE_BAD_HASH)

    /* <-- Nr */
    IN_PAYLOAD(ISAKMP_NEXT_NONCE, InNonce, ERR_IKE_BAD_NONCE)

    /* <-- SA */
    IN_PAYLOAD(ISAKMP_NEXT_SA, InSaG, ERR_IKE_BAD_SA)

exit:
    return status;
} /* gpullI2_in */


/*------------------------------------------------------------------*/

extern MSTATUS
gpullI2_out(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  GDOI Initiator 2 -->");

    /* HASH(3) -> */
    DO_FUNC(OutHashGen)

    /* [GAP]  -->  */

    /* HASH(3) data --> */
    DO_FUNC(OutHash34)

exit:
    return status;
} /* gpullI2_out */


/*------------------------------------------------------------------*/

extern MSTATUS
gpullI3_in(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  GDOI Initiator 3 <--");

    /* <-- HASH(4) */
    IN_PAYLOAD(ISAKMP_NEXT_HASH, InHash34, ERR_IKE_BAD_HASH)

    /* <-- [SEQ] */
    IN_OPT_PAYLOAD(ISAKMP_NEXT_SEQ, InSeq)

    /* <-- KD */
    IN_PAYLOAD(ISAKMP_NEXT_KD, InKd, ERR_IKE_BAD_KE)

    P2XG_IPSECSA(ctx->pxP2Xg)->c_flags |= IKE_CHILD_FLAG_MATURE;

exit:
    return status;
} /* gpullI3_in */


/*------------------------------------------------------------------*/

extern MSTATUS
gpushR1_in(IKE_context ctx)
{
    MSTATUS status = OK;

    debug_printnl("  --> GDOI PUSH Responder");

    /* TBD */
//exit:
    return status;
} /* gpushR1_in */


/*------------------------------------------------------------------*/
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) && !defined(__ENABLE_DIGICERT_GDOI_SERVER__)
#ifdef __ENABLE_DIGICERT_MULTICAST_MCP__
extern MSTATUS validateSecurityPolicy(struct ipsecKeyEx *keyEx);
#endif
#endif

extern MSTATUS
GDOI_addTek(IKE_context ctx)
{
    MSTATUS status = OK;
    ubyte4 temp_flags = 0;

    IKESA pxSa = ctx->pxSa;
    IPSECSA pxIPsecSa = P2XG_IPSECSA(ctx->pxP2Xg);

    sbyte4 j,i,k;
    MOC_IP_ADDRESS hostaddr;    /* maintain host address from keyex so it can be used to fill src/destination address for fqdn host name*/
    sbyte4 fqdnGroupIndex = 0;
    ubyte hostIpIndex = 0;

    debug_print(" GDOI_addTek(isakmp=");
    debug_hexint(pxSa->dwId);
    debug_printnl(")");

    for (j=0; j < pxIPsecSa->axP2Sa[0].oChildSaLen; j++)
    {
        sbyte4 st;
        struct ipsecKey key = { 0 };
        struct ipsecKeyEx keyEx = { 0 };

        IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[0].axChildSa[j].ipsecPps);

        /* convert from IKE to IPsec */
        IKE_initIPsecKey(&keyEx, pxSa, pxIPsecSa, pxIPsecPps,
                         pxIPsecSa->axP2Sa[0].axChildSa[j].poKey[0],
                         (ubyte)0, j, 0);

        /* keyEx -> key */
        key.oProtocol   = keyEx.oProtocol;
        key.dwSpi       = keyEx.dwSpi ;

        key.oMode       = keyEx.oMode;

        key.wDestPort   = keyEx.wDestPort;
        key.wSrcPort    = keyEx.wSrcPort;
        key.oUlp        = keyEx.oUlp;

        key.oEncrAlgo   = keyEx.oEncrAlgo;
        key.pEncrKey    = (sbyte *) keyEx.poEncrKey;
        key.wEncrKeyLen = keyEx.wEncrKeyLen;
#ifdef __ENABLE_DIGICERT_GCM__
        key.oAeadIcvLen = keyEx.oAeadIcvLen;
#endif
        key.oAuthAlgo   = keyEx.oAuthAlgo;
        key.wAuthKeyLen = keyEx.wAuthKeyLen;
        key.pAuthKey    = (sbyte *) keyEx.poAuthKey;

        key.flags       = IPSEC_SA_FLAG_GDOI | IPSEC_SA_FLAG_ASCIIKEY;
        keyEx.flags     = keyEx.flags | key.flags;
        /* lifetime */
        keyEx.dwExpSecs =
        key.dwExpSecs   = pxIPsecPps->dwExpSecs;
        keyEx.dwExpKBytes =
        key.dwExpKBytes = pxIPsecPps->dwExpKBytes;

        /* set addresses  */
        TEST_MOC_IPADDR6(keyEx.dwDestIP,
        {
            key.flags |= IPSEC_SA_FLAG_IP6;
            key.dwDestAddr = (usize) GET_MOC_IPADDR6(keyEx.dwDestIP);
            key.dwSrcAddr  = (usize) GET_MOC_IPADDR6(keyEx.dwSrcIP);
        })
        {
            key.dwDestAddr = GET_MOC_IPADDR4(keyEx.dwDestIP);
            key.dwSrcAddr  = GET_MOC_IPADDR4(keyEx.dwSrcIP);
        }

#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
        keyEx.dwIkeSaId = pxSa->dwId0;
        keyEx.ikeSaLoc = pxSa->loc;
        ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
        keyEx.dwTimeStart = timenow - pxIPsecSa->dwTimeStart; /* ms ago */

        /* copy converted key ip addresses back to the keyex structure here*/
        hostaddr = keyEx.dwDestAddr;
        keyEx.dwDestAddr = key.dwDestAddr;
        keyEx.dwSrcAddr = key.dwSrcAddr;
        
        
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        DIGI_MEMCPY(keyEx.fqdn, pxIPsecSa->fqdn, MOC_MAX_FQDN_LEN);   /* needed for validate security policy*/

        if(pxIPsecSa->fqdn[0] != '\0')
        {
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) && !defined(__ENABLE_DIGICERT_GDOI_SERVER__)
            status = validateSecurityPolicy(&keyEx);
            if (OK > status) /* error */
            {
                DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"GDOI_addTek() failed due to security policy mismatch, status = ", status);
                pxIPsecSa->merror = status;
                continue;
            }
#endif
            /*DIGI_MEMSET(keyEx.fqdn, 0, MOC_MAX_FQDN_LEN);*/   /* reverse fqdn after validate policy*/
            temp_flags = keyEx.flags;

            for (k = _R; k >= _I; k--)
            {
                keyEx.flags = temp_flags;
                DIGI_MEMSET((ubyte*)&(keyEx.dwDestAddrList[0]), 0, MAX_IP_IN_FQDN * sizeof(MOC_IP_ADDRESS));
                DIGI_MEMSET((ubyte*)&(keyEx.dwSrcAddrList[0]), 0, MAX_IP_IN_FQDN * sizeof(MOC_IP_ADDRESS));
                keyEx.dwDestAddrCount = 0;
                keyEx.dwSrcAddrCount = 0;
                keyEx.inbound = 0;
                if (_I == k)
                {
                    MOC_IP_ADDRESS addrTemp;
                    hostIpIndex = 0;
                    if (IPSEC_SA_FLAG_INBOUND & keyEx.flags)
                        keyEx.flags &= ~(IPSEC_SA_FLAG_INBOUND);
                    else
                        keyEx.flags |= IPSEC_SA_FLAG_INBOUND;
                    /*addrTemp = keyEx.dwDestAddr;
                    keyEx.dwDestIP = keyEx.dwDestAddr = keyEx.dwSrcAddr;
                    keyEx.dwSrcIPEnd = keyEx.dwSrcIP = keyEx.dwSrcAddr = addrTemp;*/
                    if(OK > (status = fqdnGroupIndex = addIpListInGroup(pxIPsecSa->fqdn,  (ubyte4*)keyEx.dwSrcAddrList, &keyEx.dwSrcAddrCount)))
                    {
                        return status;
                    }
                    if(fqdnGroupIndex >= 0)
                    {
                        status = OK;
                        keyEx.dwDestAddrCount = 0;
                        while(hostIpIndex < m_fqdnGroupList[fqdnGroupIndex].hostIPCount)
                        {            
                            keyEx.dwDestAddrList[hostIpIndex] =  m_fqdnGroupList[fqdnGroupIndex].hostIp[hostIpIndex];
                            keyEx.dwDestAddrCount++;                               
                            hostIpIndex++;
                        }
                    }
                    keyEx.inbound = 1;  /* set inboud to true for incoming packet*/
                }
                else
                {
                    hostIpIndex = 0;
                    if(OK > (status = fqdnGroupIndex =  addIpListInGroup(pxIPsecSa->fqdn,  (ubyte4*)keyEx.dwDestAddrList, &keyEx.dwDestAddrCount)))
                    {
                        return status;
                    }
                    
                    if(fqdnGroupIndex >= 0)
                    {
                        status = OK;
                        keyEx.dwSrcAddrCount = 0;
                        while(hostIpIndex < m_fqdnGroupList[fqdnGroupIndex].hostIPCount)
                        {            
                            keyEx.dwSrcAddrList[hostIpIndex] =  m_fqdnGroupList[fqdnGroupIndex].hostIp[hostIpIndex];
                            keyEx.dwSrcAddrCount++;                                
                            hostIpIndex++;
                        }
                    }
                }
                /* add to IPsec SADB */
                st = IPSEC_groupKeyAdd(&keyEx);

#ifdef __ENABLE_DIGICERT_PFKEY__
                if (STATUS_IKE_PENDING == st)
                {
                    st = OK;
                }
#endif

                if (OK > st) /* error */
                {
                    /* error */
                    if (0 > st) status = (MSTATUS)st;
                    else if (0 > (st = key.status)) status = (MSTATUS)st;
                    else status = STATUS_IPSEC_KEYADD_ABORT;

                    pxIPsecSa->merror = status;
                }
             }          
        }
        else
#endif
        {
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) && !defined(__ENABLE_DIGICERT_GDOI_SERVER__)
#ifdef __ENABLE_DIGICERT_MULTICAST_MCP__
            status = validateSecurityPolicy(&keyEx);
            if (OK > status) /* error */
            {
                DEBUG_ERROR(DEBUG_PLATFORM, (sbyte *)"GDOI_addTek() failed due to security policy mismatch, status = ", status);
                pxIPsecSa->merror = status;
                continue;
            }
#endif
#endif
#ifdef __ENABLE_DIGICERT_NW_REDUNDANCY__

            if(keyEx.dwDestAddr == KDCHeartbeatMcastIp)
            {
                RTOS_mutexWait(m_NwRedMtx);
                DIGI_MEMCPY(g_encr_key[g_encr_key_index].encr_key, keyEx.poEncrKey, key.wEncrKeyLen);
                g_encr_key[g_encr_key_index].encr_key_len = key.wEncrKeyLen;
                g_encr_key[g_encr_key_index].encr_key_validity = RTOS_deltaMS(&gStartTime, NULL) + key.dwExpSecs * 1000;
                g_encr_key_index = (g_encr_key_index + 1) % MOC_MAX_HEARTBEAT_ENCR_KEYS;
                g_encr_key_avlbl = 1;
                RTOS_mutexRelease(m_NwRedMtx);
            }
#endif

            /* add to IPsec SADB */
            st = IPSEC_groupKeyAdd(&keyEx);
#ifdef __ENABLE_DIGICERT_PFKEY__
            if (STATUS_IKE_PENDING == st)
            {
                st = OK;
            }
#endif
            if (OK > st) /* error */
            {
                /* error */
                status = (MSTATUS)st;

                pxIPsecSa->merror = status;
            }
        }
#else
        /* add to IPsec SADB */
        if (1 != (st = IPSEC_keyAdd(&key, 1)))
        {
            /* error */
            if (0 > st) status = (MSTATUS)st;
            else if (0 > (st = key.status)) status = (MSTATUS)st;
            else status = STATUS_IPSEC_KEYADD_ABORT;

            pxIPsecSa->merror = status;
        }
#endif
        PrintIPsecKey(&keyEx, status, 0);
    } /* for (j */

    if (m_ikeSettings.funcPtrIkeStatHdlr)
    {
        m_ikeSettings.funcPtrIkeStatHdlr(ISC_CHILDSA,
                                         ((OK > status) ? IST_FAIL : IST_SUCCESS),
                                         pxIPsecSa->axP2Sa[0].dwSeqNo,
                                         pxIPsecSa, pxSa);
    }

    return status;
} /* GDOI_addTek */


#endif /* __ENABLE_DIGICERT_GDOI_CLIENT__ */
