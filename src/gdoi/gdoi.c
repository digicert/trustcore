
/**
 * @file  gdoi.c
 * @brief GDOI (Group Domain of Interpretation) protocol implementation
 *
 * @details    Provides group key management for multicast IPSec
 *
 * @flags      Compilation flags required:
 *     To enable this file's functions, at least one of the following flags must be
 *     defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_GDOI_CLIENT__
 *     +   \c \__ENABLE_DIGICERT_GDOI_SERVER__
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

#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../common/random.h"

#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/crypto.h"
#include "../crypto/hmac.h"
#include "../crypto/ca_mgmt.h"

#include "../ipsec/ipsec.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ike_childsa.h"
#include "../ike/ike_crypto.h"
#include "../ike/ikesa.h"
#include "../ike/ike_state.h"
#include "../ike/ike_utils.h"

#include "../gdoi/gdoi.h"

MOC_EXTERN_DATA_DECL moctime_t gStartTime;

extern ikeSettings m_ikeSettings;

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


/*------------------------------------------------------------------*/

extern MSTATUS
InHashGen(IKE_context ctx);


/*------------------------------------------------------------------*/

static MSTATUS
DoHash34(IKE_context ctx, ubyte4 dwLength, ubyte *poBuf, ubyte *poHash)
{
    MSTATUS status;

    IKESA pxSa = ctx->pxSa;
    IPSECSA pxIPsecSa = P2XG_IPSECSA(ctx->pxP2Xg);

    struct ikeHdr *pxHdr = (struct ikeHdr *) ctx->pHdrParent;
    ubyte *poMsgId = (ubyte *) &(pxHdr->dwMsgId);

    const BulkHashAlgo *pBHAlgo = pxSa->pHashSuite->pBHAlgo;
    ubyte2 wDigestLen = (ubyte2) pBHAlgo->digestSize;

    HMAC_CTX *hmacCtxt;

    /* calculate HASH(3) */
    if (OK > (status = HmacCreate(MOC_HASH(ctx->hwAccelCookie) &hmacCtxt, pBHAlgo)) ||
        OK > (status = HmacKey(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->u.v1.poKeyId_a, wDigestLen)) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poMsgId, sizeof(ubyte4))) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxIPsecSa->poNi_b, pxIPsecSa->wNi_bLen)) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxIPsecSa->poNr_b, pxIPsecSa->wNr_bLen)) ||
        (dwLength && /* jic */
         OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poBuf, dwLength))) ||
        OK > (status = HmacFinal(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poHash)))
        DBG_EXIT
/*
    debug_printb("    SKEYID_a", pxSa->u.v1.poKeyId_a, (sbyte4)wDigestLen);
    debug_printb("    M-ID", poMsgId, sizeof(ubyte4));
    debug_printb("    Ni_b", pxIPsecSa->poNi_b, (sbyte4) pxIPsecSa->wNi_bLen);
    debug_printb("    Nr_b", pxIPsecSa->poNr_b, (sbyte4) pxIPsecSa->wNr_bLen);
    debug_printb("    ...", poBuf, (sbyte4)dwLength);*/

exit:
    HmacDelete(MOC_HASH(ctx->hwAccelCookie) &hmacCtxt);
    return status;
} /* DoHash34 */


/*------------------------------------------------------------------*/

extern MSTATUS
OutHash34(IKE_context ctx)
{
    ubyte2 wDigestLen = (ubyte2) ctx->pxSa->pHashSuite->pBHAlgo->digestSize;

    /* get all payloads following HASH(3/4) payload */
    ubyte4 dwLength = ctx->dwLength /* message length */
                    - SIZEOF_ISAKMP_HDR /* ISAKMP header */
                    - (SIZEOF_IKE_GEN_HDR + wDigestLen); /* HASH(3/4) payload */
    ubyte *poBuf = ctx->pBuffer - dwLength;

    return DoHash34(ctx, dwLength, poBuf, poBuf - wDigestLen);
} /* OutHash34 */


/*------------------------------------------------------------------*/

extern MSTATUS
InHash34(IKE_context ctx)
{
    MSTATUS status;

    IKESA pxSa = ctx->pxSa;

    ubyte2 wDigestLen = (ubyte2) pxSa->pHashSuite->pBHAlgo->digestSize;
    ubyte __crypto__(poHash, IKE_HASH_MAX);
    sbyte4 compareResult;

    ubyte *pBuffer;
    ubyte4 dwBufferSize;
    ubyte4 dwLength;
    ubyte oNextPayload;

    /* hash generic header */
    if (OK != (status = InHashGen(ctx)))
        goto exit;

    /* save current context */
    pBuffer = ctx->pBuffer;
    dwBufferSize = ctx->dwBufferSize;
    dwLength = ctx->dwLength;
    oNextPayload = ctx->oNextPayload;

    /* get total length of all payloads following HASH(3/4) payload */
    /* note: total length in ISAKMP header includes padding for encryption! */
    while (ISAKMP_NEXT_NONE != ctx->oNextPayload)
    {
        CATCH_PAYLOAD
        { IN_BEGIN(struct ikeGenHdr, pxGenHdr, SIZEOF_IKE_GEN_HDR)
          IN_END }
        FINALLY_PAYLOAD
    }

    /* calculate hash value */
    _CRYPTO_ALLOC_(poHash, IKE_HASH_MAX)
    if (OK > (status = DoHash34(ctx, ctx->dwLength - dwLength, pBuffer, poHash)))
        goto exit;

    /* verify hash data */
    if ((OK > (status = DIGI_MEMCMP(poHash, pBuffer - wDigestLen, wDigestLen, &compareResult))) ||
        (0 != compareResult))
    {
        if (!(OK > status))
        {
            status = ERR_IKE_BAD_HASH;
        }
        DBG_EXIT
    }

    /* restore context */
    ctx->pBuffer = pBuffer;
    ctx->dwBufferSize = dwBufferSize;
    ctx->dwLength = dwLength;
    ctx->oNextPayload = oNextPayload;

    ctx->flags |= IKE_CNTXT_FLAG_HASHED;

    /* record when phase 2 exchange is successfully authenticated */
    pxSa->dwTimeStamp = RTOS_deltaMS(&gStartTime, NULL);

exit:
    _CRYPTO_FREE_(poHash)
    return status;
} /* InHash34 */


/*------------------------------------------------------------------*/

extern IKESA
GDOI_newKek(ikePeerConfig *config, MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort,
            ubyte *poCky MOC_NATT(bUseNattPort) MOC_MTHM(serverInstance))
{
    IKESA pxSa = NULL;

    MSTATUS status;

#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
    struct IKE_hashSuiteInfo *pHashSuite = NULL;
    struct IKE_cipherSuiteInfo *pCipherSuite = NULL;
    ubyte2 wEncrKeyLen = 0;

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    if (NULL == poCky) /* initiator */
#endif
    {
        if (NULL == (pHashSuite = IKE_hashSuiteEx(config,
                                                  config->ikeHashAlgo, 0)))
        {
            status = ERR_IKE_MISMATCH_HASH_ALGO;
            goto exit;
        }

        if (NULL == (pCipherSuite = IKE_cipherSuiteEx(config,
                                                     config->ikeEncrAlgo, 0,
                                                     config->ikeEncrKeyLen,
                                                     &wEncrKeyLen)))
        {
            status = ERR_IKE_MISMATCH_ENCR_ALGO;
            goto exit;
        }

        if (NULL == IKE_authMtdEx(config, config->ikeSigMtd, 0))
        {
            status = ERR_IKE_MISMATCH_AUTH_METHOD;
            goto exit;
        }
    }
#endif

    if (OK > (status = IKE_allocSa(config, peerAddr, wPeerPort, poCky,
                                   &pxSa, NULL, 1
                                   MOC_NATT_VALUE(bUseNattPort)
                                   MOC_MTHM_VALUE(serverInstance))))
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        DEBUG_ERROR(DEBUG_IKE_MESSAGES, (sbyte *)"IKE_allocSa() returns error ", status);
#endif
        pxSa = NULL; /* jic */
        goto exit;
    }

#ifdef __ENABLE_IPSEC_NAT_T__
    if (!bUseNattPort)
#endif
    if (NULL == m_ikeSettings.funcPtrIkeGetHostPort)
    {
        pxSa->wHostPort = IKE_GDOI_UDP_PORT;
    }

    pxSa->flags |= IKE_SA_FLAG_GDOI_PUSH;

    /* initialize */
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
    if (NULL != poCky) /* responder */
#endif
    {
        DIGI_MEMCPY(pxSa->poCky_R, poCky + IKE_COOKIE_SIZE, IKE_COOKIE_SIZE);
        pxSa->oState = STATE_MAIN_R;

        goto exit; /* will be further initialized in SAK and KD payloads */
    }
#endif

#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
    /* initiator */
    pxSa->pHashSuite = pHashSuite;
    pxSa->pCipherSuite = pCipherSuite;
    pxSa->wEncrKeyLen = wEncrKeyLen;
    pxSa->u.v1.pwIsaAttr[OAKLEY_AUTHENTICATION_METHOD] = config->ikeSigMtd;

    RANDOM_numberGenerator(g_pRandomContext, pxSa->poCky_R, IKE_COOKIE_SIZE);
    pxSa->oState = STATE_MAIN_I;

#ifdef CUSTOM_IKE_GET_P1_LIFESECS
    if (OK > CUSTOM_IKE_GET_P1_LIFESECS(&pxSa->dwExpSecs,
                                        peerAddr, (poCky ? _R : _I), TRUE
                                        MOC_MTHM_REQ_VALUE(serverInstance)))
#endif
    if (0 == (pxSa->dwExpSecs = config->ikeP1LifeSecs))
        pxSa->dwExpSecs = config->ikeP1LifeSecsMax;

    if (IKE_LIFE_SECS_MAX < pxSa->dwExpSecs)
        pxSa->dwExpSecs = IKE_LIFE_SECS_MAX;

#ifdef CUSTOM_IKE_GET_P1_LIFEKBYTES
    if (OK > CUSTOM_IKE_GET_P1_LIFEKBYTES(&pxSa->dwExpKBytes,
                                          peerAddr, _I, TRUE
                                          MOC_MTHM_REQ_VALUE(serverInstance)))
#endif
    if (0 == (pxSa->dwExpKBytes = config->ikeP1LifeKBytes))
        pxSa->dwExpKBytes = config->ikeP1LifeKBytesMax;

    RANDOM_numberGenerator(g_pRandomContext, pxSa->u.v1.poKeyId_e, pxSa->wEncrKeyLen);

    RANDOM_numberGenerator(g_pRandomContext, pxSa->u.v1.poIv, pxSa->pCipherSuite->wIvLen);
    DIGI_MEMCPY(pxSa->u.v1.poIvOld, pxSa->u.v1.poIv, pxSa->pCipherSuite->wIvLen);

    pxSa->dwTimeCreated = RTOS_deltaMS(&gStartTime, NULL);

    pxSa->flags |= (IKE_SA_FLAG_KE | IKE_SA_FLAG_MATURE);
#endif /* __ENABLE_DIGICERT_GDOI_SERVER__ */

exit:
    return pxSa;
} /* GDOI_newKek */

#endif /* defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__) */
