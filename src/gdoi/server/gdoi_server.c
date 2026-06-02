
/**
 * @file  gdoi_server.c
 * @brief GDOI server implementation
 *
 * @details    GDOI key server functionality for distributing group keys
 *
 * @flags      Compilation flags required:
 *     + \c \__ENABLE_DIGICERT_GDOI_SERVER__
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

#ifdef __ENABLE_DIGICERT_GDOI_SERVER__

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
#include "../../gdoi/server/gdoi_server.h"

MOC_EXTERN_DATA_DEF moctime_t gStartTime;

extern ikeSettings m_ikeSettings;

#define AUTH_MTD(_sa) (_sa)->u.v1.pwIsaAttr[OAKLEY_AUTHENTICATION_METHOD]

#define ADVANCE(_size) \
    ctx->pBuffer += (_size);\
    ctx->dwBufferSize -= (ubyte4) (_size);\
    ctx->dwLength += (ubyte4) (_size);\

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

#define OUT_HDR(_type, _hdr, _size) \
    _type * _hdr;\
\
    if (ctx->dwBufferSize < (_size))\
    {\
        status = ERR_IKE_BUFFER_OVERFLOW;\
        DBG_EXIT\
    }\
    _hdr = (_type *) ctx->pBuffer;\
    ADVANCE(_size)\

#define OUT_TOP_0(_type, _hdr, _size) \
    OUT_HDR(_type, _hdr, _size)\
    SET_HTONS((_hdr)->wLength, _size);\


#define OUT_TOP(_type, _hdr, _size, _np) \
    OUT_TOP_0(_type, _hdr, _size) \
\
    if (NULL != ctx->poNextPayload)\
        *(ctx->poNextPayload) = _np;\
    ctx->poNextPayload = &((_hdr)->oNextPayload);\

#define OUT_DOWN(_p) \
    dwLength = ctx->dwLength;\
    poNextPayload = ctx->poNextPayload;\
    pHdrParent = ctx->pHdrParent;\
    \
    ctx->dwLength = 0;\
    ctx->poNextPayload = NULL;\
    ctx->pHdrParent = _p;\

#define OUT_UP(_p) \
    SET_HTONS((_p)->wLength, GET_NTOHS((_p)->wLength) + ctx->dwLength);\
    ctx->dwLength += dwLength;\
    ctx->poNextPayload = poNextPayload;\
    ctx->pHdrParent = pHdrParent;\

#define DO_FUNC(_func) \
    if (OK > (status = _func(ctx)))\
        goto exit;\

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


/*------------------------------------------------------------------*/

extern MSTATUS
OutAttrV(IKE_context ctx, ubyte2 type, ubyte2 len, void *value);

extern void
OutId2Data(IPSECSA pxIPsecSa, sbyte4 i,
           sbyte4 *id_t, ubyte2 *wBodyLen,
           ubyte4 *pdwIpAddr, ubyte4 *pdwIpAddrEnd
#ifdef __ENABLE_DIGICERT_IPV6__
         , const ubyte **ppoIpAddr6, const ubyte **ppoIpAddr6End
         , ubyte4 ipAddr6Mask[4]
#endif
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
         ,ubyte * fqdn
#endif

           );

extern MSTATUS
OutAhEspAttrs(IKE_context ctx, IPSECPPS pxIPsecPps,
              ubyte2 wAuthAlgo, ubyte2 wKeyLen);

extern MSTATUS
OutAttrB(IKE_context ctx, ubyte2 type, ubyte2 value);

extern MSTATUS
InId2(IKE_context ctx);

extern MSTATUS
OutHashGen(IKE_context ctx);

extern MSTATUS
OutNonce(IKE_context ctx);

extern MSTATUS
InHash12(IKE_context ctx);

extern MSTATUS
InNonce(IKE_context ctx);

extern MSTATUS
OutHash12(IKE_context ctx);

extern MSTATUS
InHash34(IKE_context ctx);

extern MSTATUS
OutHash34(IKE_context ctx);


/*------------------------------------------------------------------*/

static MSTATUS
GetKek(IKE_context ctx)
{
    /* get Rekey SA (PUSH) */
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    ikePeerConfig* config = pxSa->ikePeerConfig;

    if (NULL != config->pxKEK)
    {
        if (!IS_VALID(config->pxKEK) ||
            IKE_checkExpSa(RTOS_deltaMS(&gStartTime, NULL), config->pxKEK))
        {
            config->pxKEK = NULL;
        }
    }

    if (NULL == config->pxKEK)
    {
        MOC_IP_ADDRESS_S clientMAddr = config->keyClientMAddr;
        if (ISZERO_MOC_IPADDR(clientMAddr))
        {
            goto exit;
        }

        config->pxKEK = GDOI_newKek(config, REF_MOC_IPADDR(clientMAddr),
                                    IKE_GDOI_UDP_PORT, NULL
                                    MOC_NATT_VALUE(FALSE)
                                    MOC_MTHM_VALUE(pxSa->serverInstance));
    }

exit:
    return status;
} /* GetKek */


/*------------------------------------------------------------------*/

static MSTATUS
OutSAK(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxKEK = ctx->pxSa->ikePeerConfig->pxKEK;
    ubyte2 wKeyAlgo = 0;
    sbyte4 j;

    ubyte4 dwLength;
    ubyte *poNextPayload;
    void *pHdrParent;

    /* SA payload header */
    OUT_TOP(struct ikeGenHdr, pxSakHdr, SIZEOF_IKE_GEN_HDR, ISAKMP_NEXT_SAK)

    /* down one level - go to KEK Protocol-Specific Payload */
    OUT_DOWN(pxSakHdr)

    /* protocol */
    if (ctx->dwBufferSize < 1)
    {
        status = ERR_IKE_BUFFER_OVERFLOW;
        DBG_EXIT
    }
    ctx->pBuffer[0] = IPPROTO_UDP;
    ADVANCE(1)

    /* SRC ID, DST ID */
    for (j=1; j >= 0; j--)
    {
        ubyte2 wDataLen = 0;

        if (ctx->dwBufferSize < SIZEOF_GDOI_SAA_ID)
        {
            status = ERR_IKE_BUFFER_OVERFLOW;
            DBG_EXIT
        }

        IF_MOC_IPADDR6(pxKEK->dwPeerAddr,
        {
            wDataLen = 16;
            ctx->pBuffer[0] = (ubyte)ID_IPV6_ADDR;
        })
        {
            wDataLen = 4;
            ctx->pBuffer[0] = (ubyte)ID_IPV4_ADDR;
        }
        if (!j) /* DST ID only */
        DIGI_HTONS(ctx->pBuffer + 1, pxKEK->wPeerPort);
        DIGI_HTONS(ctx->pBuffer + 3, wDataLen);
        ADVANCE(SIZEOF_GDOI_SAA_ID)

        if (ctx->dwBufferSize < wDataLen)
        {
            status = ERR_IKE_BUFFER_OVERFLOW;
            DBG_EXIT
        }

        /* identification data */
        if (!j) /* DST ID only */
        {
            MOC_IP_ADDRESS peerAddr = REF_MOC_IPADDR(pxKEK->dwPeerAddr);

            TEST_MOC_IPADDR6(peerAddr,
            {
                DIGI_MEMCPY(ctx->pBuffer, GET_MOC_IPADDR6(peerAddr), 16);
            })
            DIGI_HTONL(ctx->pBuffer, GET_MOC_IPADDR4(peerAddr));
        }

        ADVANCE(wDataLen)
    } /* for */

    /* SPI, RESERVED2 */
    if (ctx->dwBufferSize < (IKE_P1_SPI_SIZE + 4))
    {
        status = ERR_IKE_BUFFER_OVERFLOW;
        DBG_EXIT
    }

    DIGI_MEMCPY(ctx->pBuffer, pxKEK->poCky_I, IKE_COOKIE_SIZE);
    DIGI_MEMCPY(ctx->pBuffer + IKE_COOKIE_SIZE, pxKEK->poCky_R, IKE_COOKIE_SIZE);
    ADVANCE(IKE_P1_SPI_SIZE + 4)

    /* KEK Attributes */
    switch (pxKEK->pCipherSuite->wEncrAlgo)
    {
    case OAKLEY_DES_CBC  : wKeyAlgo = KEK_ALG_DES;  break;
    case OAKLEY_3DES_CBC : wKeyAlgo = KEK_ALG_3DES; break;
    case OAKLEY_AES_CBC  : wKeyAlgo = KEK_ALG_AES;  break;
    default :
        status = ERR_IKE_MISMATCH_ENCR_ALGO;
        DBG_EXIT
    }
    if (OK != (status = OutAttrB(ctx, KEK_ALGORITHM, wKeyAlgo)))
    {
        DBG_EXIT
    }

    if (!pxKEK->pCipherSuite->bFixedKeyLen &&
        OK != (status = OutAttrB(ctx, KEK_KEY_LENGTH, pxKEK->wEncrKeyLen * 8)))
    {
        DBG_EXIT
    }

    if (pxKEK->dwExpSecs)
    {
        ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
        ubyte4 dwExpSecs = pxKEK->dwExpSecs -
                           ((timenow - pxKEK->dwTimeCreated) / 1000);

        SET_HTONL_1(dwExpSecs);
        if (OK != (status = OutAttrV(ctx, KEK_KEY_LIFETIME, sizeof(ubyte4), &dwExpSecs)))
        {
            DBG_EXIT
        }
    }

    /* KEK_MANAGEMENT_ALGORITHM */ /* PUSH only */

    switch (AUTH_MTD(pxKEK))
    {
    case OAKLEY_RSA_SIG   : wKeyAlgo = SIG_ALG_RSA;         break;
#ifdef __ENABLE_DIGICERT_ECC__
#if !(defined(__DISABLE_DIGICERT_ECC_P256__) || defined(__DISABLE_DIGICERT_SHA256__))
    case OAKLEY_ECDSA_256 : wKeyAlgo = SIG_ALG_ECDSA_256;   goto done;
#endif
#if !(defined(__DISABLE_DIGICERT_ECC_P384__) || defined(__DISABLE_DIGICERT_SHA384__))
    case OAKLEY_ECDSA_384 : wKeyAlgo = SIG_ALG_ECDSA_384;   goto done;
#endif
#if !(defined(__DISABLE_DIGICERT_ECC_P521__) || defined(__DISABLE_DIGICERT_SHA512__))
    case OAKLEY_ECDSA_521 : wKeyAlgo = SIG_ALG_ECDSA_521;   goto done;
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    case OAKLEY_P256_MLDSA_44: wKeyAlgo = SIG_ALG_P256_MLDSA_44;   goto done;
    case OAKLEY_P256_FNDSA512:  wKeyAlgo = SIG_ALG_P256_FNDSA512;   goto done;
    case OAKLEY_P384_MLDSA_65: wKeyAlgo = SIG_ALG_P384_MLDSA_65;   goto done;
    case OAKLEY_P521_FNDSA1024: wKeyAlgo = SIG_ALG_P521_FNDSA1024;   goto done;
    case OAKLEY_P521_MLDSA_87: wKeyAlgo = SIG_ALG_P521_MLDSA_87;   goto done;
#endif
#endif
    default :
        status = ERR_IKE_MISMATCH_AUTH_METHOD;
        DBG_EXIT
    }
    if (OK != (status = OutAttrB(ctx, SIG_ALGORITHM, wKeyAlgo)))
    {
        DBG_EXIT
    }

    switch (pxKEK->pHashSuite->wHashAlgo) /* optional for ECDSA-256/384/521 */
    {
    case OAKLEY_MD5 :       wKeyAlgo = SIG_HASH_MD5;     break;
    case OAKLEY_SHA :       wKeyAlgo = SIG_HASH_SHA1;    break;
#ifndef __DISABLE_DIGICERT_SHA256__
    case OAKLEY_SHA2_256 :  wKeyAlgo = SIG_HASH_SHA256;  break;
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
    case OAKLEY_SHA2_384 :  wKeyAlgo = SIG_HASH_SHA384;  break;
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
    case OAKLEY_SHA2_512 :  wKeyAlgo = SIG_HASH_SHA512;  break;
#endif
    default :
        status = ERR_IKE_MISMATCH_HASH_ALGO;
        DBG_EXIT
    }
    if (OK != (status = OutAttrB(ctx, SIG_HASH_ALGORITHM, wKeyAlgo)))
    {
        DBG_EXIT
    }

    //SIG_KEY_LENGTH // optional?

    goto done;

done:
    /* up one level */
    OUT_UP(pxSakHdr)

exit:
    return status;
} /* OutSAK */


/*------------------------------------------------------------------*/

static MSTATUS
OutSAT(IKE_context ctx, IPSECSA pxIPsecSa, sbyte4 i)
{
    MSTATUS status = OK;

    IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[0].axChildSa[i].ipsecPps);
    ubyte4 dwSpi = pxIPsecPps->dwSpi[0];
    ubyte2 wAuthAlgo = pxIPsecPps->wAuthAlgo;
    ubyte2 wKeyLen = pxIPsecPps->wEncrKeyLen;
    sbyte4 j;

    ubyte4 dwLength;
    ubyte *poNextPayload;
    void *pHdrParent;
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
     ubyte fqdn[MOC_MAX_FQDN_LEN];
#endif

    /* SA payload header */
    OUT_TOP(struct gdoiSaaHdr, pxSatHdr, SIZEOF_GDOI_SAA_HDR, ISAKMP_NEXT_SAT)

    pxSatHdr->oProtoId = (PROTO_IPSEC_AH == pxIPsecPps->oProtocol)
                       ? GDOI_PROTO_IPSEC_AH : GDOI_PROTO_IPSEC_ESP;

    /* down one level - go to TEK Protocol-Specific Payload */
    OUT_DOWN(pxSatHdr)

    /* protocol */
    if (ctx->dwBufferSize < 1)
    {
        status = ERR_IKE_BUFFER_OVERFLOW;
        DBG_EXIT
    }
    ctx->pBuffer[0] = pxIPsecSa->oUlp;
    ADVANCE(1)

    /* SRC ID, DST ID */
    for (j=1; j >= 0; j--)
    {
        sbyte4 id_t = 0;
        ubyte2 wDataLen = 0;
        ubyte4 dwIpAddr = 0, dwIpAddrEnd = 0;
#ifdef __ENABLE_DIGICERT_IPV6__
        const ubyte *poIpAddr6 = NULL, *poIpAddr6End = NULL;
        ubyte4 ipAddr6Mask[4];
#endif
        if (ctx->dwBufferSize < SIZEOF_GDOI_SAA_ID)
        {
            status = ERR_IKE_BUFFER_OVERFLOW;
            DBG_EXIT
        }
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        DIGI_MEMSET(fqdn, 0, MOC_MAX_FQDN_LEN);
#endif
        
        OutId2Data(pxIPsecSa, j, &id_t, &wDataLen,
                   &dwIpAddr, &dwIpAddrEnd
#ifdef __ENABLE_DIGICERT_IPV6__
                 , &poIpAddr6, &poIpAddr6End, ipAddr6Mask
#endif
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
                 ,fqdn
#endif
                   );

        ctx->pBuffer[0] = (ubyte)id_t;
        DIGI_HTONS(ctx->pBuffer + 1, pxIPsecSa->wPort[j]);
        DIGI_HTONS(ctx->pBuffer + 3, wDataLen);
        ADVANCE(SIZEOF_GDOI_SAA_ID)

        if (ctx->dwBufferSize < wDataLen)
        {
            status = ERR_IKE_BUFFER_OVERFLOW;
            DBG_EXIT
        }

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        if(fqdn[0]!= '\0')    /* if fqdn obtained*/
        {
            DIGI_MEMCPY(ctx->pBuffer, fqdn, DIGI_STRLEN((sbyte *) fqdn));
        }
        else
#endif
        {

        /* identification data */
#ifdef __ENABLE_DIGICERT_IPV6__
            if (poIpAddr6)
            {
                DIGI_MEMCPY(ctx->pBuffer, poIpAddr6, 16);

                if (poIpAddr6End)
                {
                    DIGI_MEMCPY(ctx->pBuffer + 16, poIpAddr6End, 16);
                }
            }
            else
#endif
            {
                DIGI_HTONL(ctx->pBuffer, dwIpAddr);

                if (4 < wDataLen)
                {
                    DIGI_HTONL(ctx->pBuffer + 4, dwIpAddrEnd);
                }
            }
        }
        ADVANCE(wDataLen)
    }

    /* Transform ID, SPI */
    if (ctx->dwBufferSize < (sizeof(dwSpi) + 1))
    {
        status = ERR_IKE_BUFFER_OVERFLOW;
        DBG_EXIT
    }
    ctx->pBuffer[0] = pxIPsecPps->oTfmId;

    SET_HTONL_1(dwSpi);
    DIGI_MEMCPY(ctx->pBuffer + 1, &dwSpi, sizeof(dwSpi));
    ADVANCE(sizeof(dwSpi) + 1)

    /* RFC 2407 SA Attributes */
    if (OK > (status = OutAhEspAttrs(ctx, pxIPsecPps, wAuthAlgo, wKeyLen)))
    {
        goto exit;
    }

    if ((0 != pxIPsecPps->wMode) &&
        (OK != (status = OutAttrB(ctx, ENCAPSULATION_MODE, pxIPsecPps->wMode))))
    {
        goto exit;
    }

    /* up one level */
    OUT_UP(pxSatHdr)
    
exit:
    return status;
} /* OutSAT */


/*------------------------------------------------------------------*/

static MSTATUS
OutSaG(IKE_context ctx)
{
    MSTATUS status = OK;

    IPSECSA pxIPsecSa = P2XG_IPSECSA(ctx->pxP2Xg);
    sbyte4 i;

    ubyte4 dwLength;
    ubyte *poNextPayload;
    void *pHdrParent;

    /* SA payload header */
    OUT_TOP(struct gdoiSaHdr, pxSaHdr, SIZEOF_GDOI_SA_HDR, ISAKMP_NEXT_SA)

    pxSaHdr->oDoi = ISAKMP_GDOI;
    pxSaHdr->oNextSaaPayload = ISAKMP_NEXT_SAT;

    /* down one level - go to child payloads */
    OUT_DOWN(pxSaHdr)

    /* SA attribute payload(s) */
    if (ctx->pxSa->ikePeerConfig->pxKEK)
    {
        pxSaHdr->oNextSaaPayload = ISAKMP_NEXT_SAK;
        DO_FUNC(OutSAK)
    }

    //DO_FUNC(OutGAP) /* ISAKMP_NEXT_GAP */

    for (i = pxIPsecSa->axP2Sa[0].oChildSaLen - 1; i >= 0; i--)
    {
        if (OK > (status = OutSAT(ctx, pxIPsecSa, i)))
        {
            goto exit;
        }
    }

    /* up one level */
    OUT_UP(pxSaHdr)

exit:
    return status;
} /* OutSaG */


/*------------------------------------------------------------------*/

static MSTATUS
OutTekKp(IKE_context ctx, IPSECSA pxIPsecSa, sbyte4 i)
{
    MSTATUS status = OK;

    IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[0].axChildSa[i].ipsecPps);
    ubyte4 dwSpi = pxIPsecPps->dwSpi[0];
    ubyte oProtoId = pxIPsecPps->oProtocol;
    ubyte2 wEncrKeyLen = 0;

    ubyte4 dwLength;
    ubyte *poNextPayload;
    void *pHdrParent;

    /* KP payload header */
    OUT_TOP_0(struct gdoiKP, pxKp, SIZEOF_GDOI_KP)

    pxKp->oType = KD_TYPE_TEK;
    pxKp->oSpiSize = sizeof(dwSpi);

    /* down one level - go to attributes */
    OUT_DOWN(pxKp)

    if (ctx->dwBufferSize < sizeof(dwSpi))
    {
        status = ERR_IKE_BUFFER_OVERFLOW;
        DBG_EXIT
    }

    SET_HTONL_1(dwSpi);
    DIGI_MEMCPY(ctx->pBuffer, &dwSpi, sizeof(dwSpi));
    ADVANCE(sizeof(dwSpi))

    if (pxIPsecPps->oEncrAlgo && (PROTO_IPSEC_ESP == oProtoId))
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
        if (OK != (status = OutAttrV(ctx, TEK_ALGORITHM_KEY, wEncrKeyLen,
                                pxIPsecSa->axP2Sa[0].axChildSa[i].poKey[0])))
        {
            goto exit;
        }
    }

    if (pxIPsecPps->wAuthAlgo)
    {
        ubyte2 wAuthKeyLen;
        CHILDSA_authInfo *pAuthAlgo =
        CHILDSA_findAuthAlgo(pxIPsecPps->wAuthAlgo, 0, 0, 0);
        if (NULL == pAuthAlgo) /* jic */
        {
            status = ERR_NULL_POINTER;
            DBG_EXIT
        }
        wAuthKeyLen = pAuthAlgo->wKeyLen;

        if (PROTO_IPSEC_AH == oProtoId)
        {
            if (OK != (status = OutAttrV(ctx, TEK_SOURCE_AUTH_KEY, wAuthKeyLen,
                                //pxIPsecSa->axP2Sa[0].axChildSa[i].poKey[0])))
                    &(pxIPsecSa->axP2Sa[0].axChildSa[i].poKey[0][CHILDSA_ENCRKEY_MAX]))))
                    /* auth. key does NOT start at [0]! See GDOI_getTek() */
            {
                goto exit;
            }
        }
        else /* PROTO_IPSEC_ESP */
        {
            if (OK != (status = OutAttrV(ctx, TEK_INTEGRITY_KEY, wAuthKeyLen,
                    &(pxIPsecSa->axP2Sa[0].axChildSa[i].poKey[0][CHILDSA_ENCRKEY_MAX]))))
            {
                goto exit;
            }
        }
    }

    /* up one level */
    OUT_UP(pxKp)

exit:
    return status;
} /* OutTekKp */


/*------------------------------------------------------------------*/

static MSTATUS
OutKd(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxKEK = ctx->pxSa->ikePeerConfig->pxKEK;
    IPSECSA pxIPsecSa = P2XG_IPSECSA(ctx->pxP2Xg);
    ubyte2 wKpNum = pxIPsecSa->axP2Sa[0].oChildSaLen;
    sbyte i;

    ubyte4 dwLength;
    ubyte *poNextPayload;
    void *pHdrParent;

    /* KD payload header */
    OUT_TOP(struct gdoiKdHdr, pxKdHdr, SIZEOF_GDOI_KD_HDR, ISAKMP_NEXT_KD)

    if (pxKEK)
    {
        //wKpNum++;
    }
    SET_HTONS(pxKdHdr->wNum, wKpNum);

    /* down one level - go to child payloads */
    OUT_DOWN(pxKdHdr)

    /* See DoKe2() */
    for (i = pxIPsecSa->axP2Sa[0].oChildSaLen - 1; i >= 0; i--)
    {
        if (OK > (status = OutTekKp(ctx, pxIPsecSa, i)))
        {
            goto exit;
        }
    } /* for */

    if (pxKEK)
    {
        // DO_FUNC(OutKekKp)
    }

    /* up one level */
    OUT_UP(pxKdHdr)

exit:
    return status;
} /* OutKd */


/*------------------------------------------------------------------*/

extern MSTATUS
gpullR1_in(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  --> GDOI Responder 1");

    /* HASH(1) --> */
    IN_PAYLOAD(ISAKMP_NEXT_HASH, InHash12, ERR_IKE_BAD_HASH)

    /* Ni --> */
    IN_PAYLOAD(ISAKMP_NEXT_NONCE, InNonce, ERR_IKE_BAD_NONCE)

    /* ID --> */
    IN_PAYLOAD(ISAKMP_NEXT_ID, InId2, ERR_IKE_BAD_ID)

    /* get Group keys */
    DO_FUNC(GDOI_getTek)

    /* get Rekey SA (PUSH) */
    DO_FUNC(GetKek)

exit:
    return status;
} /* gpullR1_in */


/*------------------------------------------------------------------*/

extern MSTATUS
gpullR1_out(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  <-- GDOI Responder 1");

    /* <-- HASH(2) */
    DO_FUNC(OutHashGen)

    /* <-- Nr */
    DO_FUNC(OutNonce)

    /* <-- SA */
    DO_FUNC(OutSaG)

    /* HASH(2) data */
    DO_FUNC(OutHash12)

exit:
    return status;
} /* gpullR1_out */


/*------------------------------------------------------------------*/

extern MSTATUS
gpullR2_in(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  --> GDOI Responder 2");

    /* HASH(3) --> */
    IN_PAYLOAD(ISAKMP_NEXT_HASH, InHash34, ERR_IKE_BAD_HASH)

    /* [GAP] --> */

exit:
    return status;
} /* gpullR2_in */


/*------------------------------------------------------------------*/

extern MSTATUS
gpullR2_out(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  <-- GDOI Responder 2");

    /* <-- HASH(4) */
    DO_FUNC(OutHashGen)

    /* <-- [SEQ] */
    //DO_FUNC(OutSeq)

    /* <-- KD */
    DO_FUNC(OutKd)

    /* HASH(4) data */
    DO_FUNC(OutHash34)

exit:
    return status;
} /* gpullR2_out */


/*------------------------------------------------------------------*/

extern MSTATUS
gpushI1_out(IKE_context ctx)
{
    MSTATUS status = OK;

    debug_printnl("  GDOI PUSH Initiator -->");

    /* TBD */
//exit:
    return status;
} /* gpushI1_out */


/*------------------------------------------------------------------*/

extern MSTATUS
GDOI_getTek(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    IPSECSA pxIPsecSa = P2XG_IPSECSA(ctx->pxP2Xg);
    IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[0].axChildSa[0].ipsecPps);

#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
    struct ipsecKeyEx key = { 0 };
#else
    struct ipsecKey key = { 0 };
#endif
    key.oUlp = pxIPsecSa->oUlp;
    key.wDestPort = pxIPsecSa->wPort[0];
#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
    key.poEncrKey = (ubyte *)&(pxIPsecSa->axP2Sa[0].axChildSa[0].poKey[0][0]);
    key.poAuthKey = (ubyte *)&(pxIPsecSa->axP2Sa[0].axChildSa[0].poKey[0][CHILDSA_ENCRKEY_MAX]);

    /* add the start and end ip addresses*/
    key.dwDestIP = GET_MOC_IPADDR4(REF_MOC_IPADDR(pxIPsecSa->dwIP[0]));
    key.dwDestIPEnd = GET_MOC_IPADDR4(REF_MOC_IPADDR(pxIPsecSa->dwIPEnd[0]));

    key.dwSrcIP = GET_MOC_IPADDR4(REF_MOC_IPADDR(pxIPsecSa->dwIP[1]));
    key.dwSrcIPEnd = GET_MOC_IPADDR4(REF_MOC_IPADDR(pxIPsecSa->dwIPEnd[1]));

    /* add fqdn entries here*/
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    DIGI_MEMCPY(key.fqdn, pxIPsecSa->fqdn, MOC_MAX_FQDN_LEN);
#endif

#else
    key.pEncrKey = (sbyte *)&(pxIPsecSa->axP2Sa[0].axChildSa[0].poKey[0][0]);
    key.pAuthKey = (sbyte *)&(pxIPsecSa->axP2Sa[0].axChildSa[0].poKey[0][CHILDSA_ENCRKEY_MAX]);
#endif
    key.flags = IPSEC_SA_FLAG_GDOI; /* !!! */

    IF_MOC_IPADDR6(pxIPsecSa->dwIP[0],
    {
        key.flags |= IPSEC_SA_FLAG_IP6;
        key.dwDestAddr = (usize) GET_MOC_IPADDR6(REF_MOC_IPADDR(pxIPsecSa->dwIP[0]));
    })
    {
        key.dwDestAddr = GET_MOC_IPADDR4(REF_MOC_IPADDR(pxIPsecSa->dwIP[0]));
    }

    debug_print(" GDOI_getTek(isakmp=");
    debug_hexint(pxSa->dwId);
    debug_print(")");

#ifdef __ENABLE_DIGICERT_MCP_UNICAST_SUPPORT__
    if (OK > (status = IPSEC_keyGetEx(&key)))
#else
    if (OK > (status = IPSEC_keyGet(&key)))
#endif
    {
        pxIPsecSa->merror = status;
        debug_print(" = ");
        debug_int(status);
        debug_printnl(NULL);
        goto exit;
    }

    debug_printnl(NULL);

    /* ipsecKey -> IPSECSA */
    pxIPsecSa->oUlp = key.oUlp;
    pxIPsecSa->wPort[0] = key.wDestPort;

    pxIPsecSa->axP2Sa[0].oChildSaLen = 1; /* for now */

    switch (key.oProtocol)
    {
    case IPPROTO_AH :
        pxIPsecPps->oProtocol = PROTO_IPSEC_AH;
        break;
    case IPPROTO_ESP :
        pxIPsecPps->oProtocol = PROTO_IPSEC_ESP;
        break;
    }

    pxIPsecPps->dwSpi[0] = key.dwSpi;

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    switch (key.oMode)
    {
    case IPSEC_MODE_TRANSPORT :
        pxIPsecPps->wMode = ENCAPSULATION_MODE_TRANSPORT;
        break;
    case IPSEC_MODE_TUNNEL :
        pxIPsecPps->wMode = ENCAPSULATION_MODE_TUNNEL;
        break;
    }
#else
    pxIPsecPps->wMode = ENCAPSULATION_MODE_TRANSPORT;
#endif

    if (key.oEncrAlgo)
    {
        ubyte2 wKeyLen = key.wEncrKeyLen - key.oNonceLen;

        CHILDSA_encrInfo *pEncrAlgo = CHILDSA_findAeadAlgo(0, 0, key.oEncrAlgo,
                                                           key.oAeadIcvLen,
                                                           wKeyLen, &wKeyLen);
        if (NULL == pEncrAlgo)
        {
            status = ERR_IKE_MISMATCH_ENCR_ALGO;
            goto exit;
        }

        pxIPsecPps->oTfmId      =
        pxIPsecPps->oEncrAlgo   = pEncrAlgo->oTfmId;
        if (!pEncrAlgo->bFixedKeyLen) /* !!! */
        pxIPsecPps->wEncrKeyLen = wKeyLen;
    }

    if (key.oAuthAlgo)
    {
        CHILDSA_authInfo *pAuthAlgo = CHILDSA_findAuthAlgo(0, 0, 0, key.oAuthAlgo);
        if (NULL == pAuthAlgo)
        {
            status = ERR_IKE_MISMATCH_AUTH_ALGO;
            goto exit;
        }
        pxIPsecPps->wAuthAlgo = pAuthAlgo->wAuthAlgo;

        if (IPPROTO_AH == key.oProtocol)
        {
            pxIPsecPps->oTfmId = pAuthAlgo->oTfmId;
            pxIPsecPps->oSecuProto = IPSEC_PROTO_AH;
        }
        else if (!key.oEncrAlgo)
        {
            pxIPsecPps->oTfmId = ESP_NULL;
            pxIPsecPps->oSecuProto = IPSEC_PROTO_ESP_NULL;
        }
        else
        {
            pxIPsecPps->oSecuProto = IPSEC_PROTO_ESP_AUTH;
        }
    }
    else if (key.oEncrAlgo)
    {
        pxIPsecPps->oSecuProto = IPSEC_PROTO_ESP;
    }

    pxIPsecPps->dwExpSecs = key.dwExpSecs;
    pxIPsecPps->dwExpKBytes = key.dwExpKBytes;

exit:
    return status;
} /* GDOI_getTek */

#endif /* __ENABLE_DIGICERT_GDOI_SERVER__ */
