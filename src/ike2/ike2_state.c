/**
 * @file  ike2_state.c
 * @brief IKEv2 IKEv2 State Machine
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
#include "../crypto/secmod.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../crypto/aes.h"
#include "../crypto/dh.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/crypto.h"
#include "../crypto/hmac.h"
#include "../crypto/rsa.h"
#include "../crypto/chacha20.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../crypto/ca_mgmt.h"
#include "../crypto/pubcrypto.h"
#include "../harness/harness.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/tree.h"
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"
#include "../crypto/cert_store.h"
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_dh.h"
#include "../crypto_interface/crypto_interface_md5.h"
#include "../crypto_interface/crypto_interface_sha1.h"
#include "../crypto_interface/crypto_interface_rsa.h"
#endif
#ifdef __ENABLE_DIGICERT_PQC__
#include "../crypto_interface/crypto_interface_qs.h"
#include "../crypto_interface/crypto_interface_qs_sig.h"
#include "../crypto_interface/crypto_interface_qs_kem.h"
#endif
#include "../ipsec/ipsec.h"
#include "../ipsec/ipsec_defs.h"
#include "../ipsec/ipsec_protos.h"
#include "../ipsec/ipseckey.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ike_childsa.h"
#include "../ike/ike_crypto.h"
#include "../ike/ikesa.h"
#include "../ike/ike_state.h"
#include "../ike/ike_cert.h"
#include "../ike/ike_utils.h"
#include "../ike/ike_status.h"
#if defined(__ENABLE_IKE_REDIRECT__) || defined(__IKE_UPDATE_TIMER__)
#include "../common/timer.h"
#endif

#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../ike2/ike2_eap.h"

extern ubyte4 g_ikeEapInstId;
#endif

#ifdef __ENABLE_IKE_OCSP_EXT__
#ifndef __ENABLE_DIGICERT_OCSP_CLIENT__
#error Must define __ENABLE_DIGICERT_OCSP_CLIENT__
#endif
#include "../ocsp/ocsp.h"
#include "../ocsp/ocsp_context.h"
#include "../ike2/ike2_ocsp.h"
#endif

#ifdef __ENABLE_DIGICERT_SP800_135_ACVP__
void FreeSa(IKESA pxSa);
#include "../ike2/nist/ike2_nist_defs.inc"
#endif

/*------------------------------------------------------------------*/

MOC_EXTERN_DATA_DECL moctime_t gStartTime;

extern IKE_MUTEX g_ikeMtx;

extern ikeSettings m_ikeSettings;

extern ubyte4 g_ikeScrtVerID; /* for COOKIE in IKE_SA_INIT exchange */
extern ubyte  g_ikeSecret[];
extern sbyte4 g_ikeScrtLen;

#ifdef __IKE_MULTI_THREADED__
extern RTOS_RWLOCK m_ikeSaRwLock;
#endif


/*------------------------------------------------------------------*/

#ifdef __ENABLE_IKE_REDIRECT__
extern sbyte4 IKE_redirect(IKE_context ctx);
ubyte4 g_ikeRedirectCount = 0;
#endif

/*------------------------------------------------------------------*/

#define _I 0
#define _R 1

#define _IN  1
#define _OUT 2

#define IKE_NONCE_MIN   (16)
#define IKE_NONCE_MAX   (256)

#define IKE_CNTXT_FALG_NAT_D (IKE_CNTXT_FALG_NAT_D_SRC | IKE_CNTXT_FALG_NAT_D_DST)


/*------------------------------------------------------------------*/

#define DBG_ERRCODE(_s) debug_print_status((sbyte *)__FILE__, __LINE__, (sbyte4)(_s));
#define DBG_STATUS      DBG_ERRCODE(status)
#define DBG_EXIT        { DBG_STATUS goto exit; }
#define DBG_NL_EXIT     { debug_printnl(NULL); DBG_EXIT }

#define CHECK_MALLOC_PTR(_t, _p, _s) \
    if (NULL == ((_p) = (_t *) MALLOC(_s))) \
    { \
        status = ERR_MEM_ALLOC_FAIL; \
        DBG_EXIT \
    } \

#define CHECK_MALLOC_TYPE(_t, _p) CHECK_MALLOC_PTR(_t, _p, sizeof(_t))
#define CHECK_MALLOC(p, s) CHECK_MALLOC_PTR(ubyte, p, s)
#define CHECK_FREE(p) if (NULL != (p)) { FREE(p); (p) = NULL; }

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


/*------------------------------------------------------------------*/

#define ADVANCE(_size) \
    ctx->pBuffer += (_size);\
    ctx->dwBufferSize -= (ubyte4) (_size);\
    ctx->dwLength += (ubyte4) (_size);\


/*------------------------------------------------------------------*/

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


#define OUT_TOP(_type, _hdr, _size, _np) \
    OUT_HDR(_type, _hdr, _size)\
    SET_HTONS((_hdr)->wLength, _size);\
    \
    if (NULL != ctx->poNextPayload)\
        *(ctx->poNextPayload) = _np;\
    ctx->poNextPayload = &((_hdr)->oNextPayload);\


#define OUT_BEGIN(_type, _hdr, _size, _np) \
    OUT_TOP(_type, _hdr, _size, _np)\
\
    if (ctx->dwBufferSize < wBodyLen)\
    {\
        status = ERR_IKE_BUFFER_OVERFLOW;\
        DBG_EXIT\
    }\
    SET_HTONS((_hdr)->wLength, GET_NTOHS((_hdr)->wLength) + wBodyLen);\


#define OUT_END ADVANCE(wBodyLen)


#define OUT_DOWN(_p) \
{\
    ubyte4 _dwLength = ctx->dwLength;\
    ubyte *_poNextPayload = ctx->poNextPayload;\
    void *_pHdrParent = ctx->pHdrParent;\
    \
    ctx->dwLength = 0;\
    ctx->poNextPayload = NULL;\
    ctx->pHdrParent = _p;\


#define OUT_UP(_p) \
    SET_HTONS((_p)->wLength, GET_NTOHS((_p)->wLength) + ctx->dwLength);\
    ctx->dwLength += _dwLength;\
    ctx->poNextPayload = _poNextPayload;\
    ctx->pHdrParent = _pHdrParent;\
}\


/*------------------------------------------------------------------*/

#define IN_HDR(_type, _hdr, _size) \
    _type * _hdr = NULL;\
\
    if (ctx->dwBufferSize < (ubyte4)(_size))\
    {\
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
        status = ERR_IKE_BAD_MSG;\
        DBG_EXIT\
    }\
\
    if ((ubyte4)wBodyLen > ctx->dwBufferSize)\
    {\
        status = ERR_IKE_BAD_LEN;\
        DBG_EXIT\
    }\


#define IN_BEGIN(_type, _hdr, _size) \
    IN_BEGIN_0(_type, _hdr, _size)\
    ctx->oNextPayload = (_hdr)->oNextPayload;\


#define IN_END ADVANCE(wBodyLen)


#define IN_DOWN(_p) \
{\
    ubyte4 _dwBufferSize = ctx->dwBufferSize;\
    ubyte4 _dwLength = ctx->dwLength;\
    ubyte _oNextPayload = ctx->oNextPayload;\
    void *_pHdrParent = ctx->pHdrParent;\
    \
    ctx->dwBufferSize = wBodyLen;\
    ctx->dwLength = 0;\
    ctx->oNextPayload = 0;\
    ctx->pHdrParent = _p;\


#define IN_UP(_p) \
    ctx->pBuffer = ((ubyte *)(_p)) + wLength;\
    ctx->dwBufferSize = _dwBufferSize - wBodyLen;\
    ctx->dwLength = _dwLength + wBodyLen;\
    ctx->oNextPayload = _oNextPayload;\
    ctx->pHdrParent = _pHdrParent;\
}\


#define IN_SET \
{\
    ubyte *_buffer = ctx->pBuffer;\
    ubyte4 _bufferSize = ctx->dwBufferSize;\
    ubyte4 _length = ctx->dwLength;\
    ubyte _nextPayload = ctx->oNextPayload;\


#define IN_RESET \
    ctx->pBuffer = _buffer;\
    ctx->dwBufferSize = _bufferSize;\
    ctx->dwLength = _length;\
    ctx->oNextPayload = _nextPayload;\
}\


#define DO_FUNC(_func) { if (OK > (status = _func(ctx))) goto exit; }

#define IN_PAYLOAD(_nextPl, _inFunc) \
    if (_nextPl != ctx->oNextPayload)\
    {\
        status = ERR_IKE_BAD_PAYLOAD;\
        DBG_EXIT\
    }\
    DO_FUNC(_inFunc)\


#define IN_PAYLOAD2(_nextPl1, _nextPl2, _inFunc) \
    if ((_nextPl1 != ctx->oNextPayload) &&\
        (_nextPl2 != ctx->oNextPayload))\
    {\
        status = ERR_IKE_BAD_PAYLOAD;\
        DBG_EXIT\
    }\
    DO_FUNC(_inFunc)\

#ifdef __ENABLE_IKE_FRAGMENTATION__
#define IN_SK   IN_PAYLOAD2(IKE_NEXT_E, IKE_NEXT_EF, InSK)
#else
#define IN_SK   IN_PAYLOAD( IKE_NEXT_E,              InSK)
#endif


#define IN_OPT_PAYLOAD(_nextPl, _inFunc) \
    if (_nextPl == ctx->oNextPayload)\
        DO_FUNC(_inFunc)\


#define IN_LOOP_BEGIN \
    for (;;)\
    {\
        ubyte _oNp = ctx->oNextPayload;\


#define IN_NEXT(_nextPl, _inFunc) \
        if (_oNp == (_nextPl))\
            DO_FUNC(_inFunc)\
        else \


#define IN_LAST(_nextPl, _inFunc) \
        if (_oNp == (_nextPl))\
        {\
            DO_FUNC(_inFunc)\
            break;\
        }\
        else\


#define IN_REJECT(_nextPl) \
        if ((_nextPl) == _oNp)\
        {\
            status = ERR_IKE_BAD_PAYLOAD;\
            DBG_EXIT\
        }\
        else\


#define IN_LOOP_END \
        {\
            break;\
        }\
    }\


#define IN_LOOP_NONE \
        if (IKE_NEXT_NONE == _oNp)\
        {\
            break;\
        }\
        else\
        {\
            IN_BEGIN(struct ikeGenHdr, pxGenHdr, SIZEOF_IKE_GEN_HDR)\
            IN_END\
        }


#define LAST_PAYLOAD(_nextPl, _inFunc) \
    IN_LOOP_BEGIN \
        IN_LAST(_nextPl, _inFunc) \
    IN_LOOP_NONE \
    }

#define GET_PAYLOAD(_nextPl, _inFunc) \
    IN_SET \
        LAST_PAYLOAD(_nextPl, _inFunc) \
    IN_RESET


/*------------------------------------------------------------------*/

#define CERT_STATUS_CHECK(_sa, _c, _st) \
    if (m_ikeSettings.funcPtrCertStatusCheck) \
    { \
        IKE_certStatusCB *cb; \
        CHECK_MALLOC_TYPE(IKE_certStatusCB, cb) \
\
        cb->dwSaId = (_sa)->dwId; \
        cb->saLoc = (_sa)->loc; \
        cb->pxSa = (_sa); \
\
        if (OK > ((_st) = (MSTATUS) m_ikeSettings.funcPtrCertStatusCheck( \
                                            (_c)->certificates, (_c)->certNum,\
                                            IKE2_certStatusCallback, cb, \
                                            (_sa)->serverInstance, _sa))) \
        { \
            if (STATUS_IKE_PENDING == (_st)) (_st) = OK; \
            else \
            { \
                FREE(cb); \
                DBG_EXIT \
            } \
        } \
        else \
        { \
            FREE(cb); \
        } \
    }


/*------------------------------------------------------------------*/

extern sbyte4
IKE2_certStatusCallback(void *data, sbyte4 result)
{
#define cb ((IKE_certStatusCB *)data)
    MSTATUS status;
    IKESA pxSa = NULL;

    IKE_LOCK_R; /* !!! */

    if ((NULL == cb) || (NULL == cb->pxSa))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* get IKE_SA */
    if (OK > (status = IKE_getSaByLoc(cb->saLoc, &pxSa)))
    {
        goto exit;
    }

    if (cb->pxSa != pxSa)
    {
        status = ERR_IKE_GETSA_FAIL;
        goto exit;
    }

#ifdef __IKE_MULTI_THREADED__
    RTOS_rwLockWaitR(m_ikeSaRwLock);
#endif
    if (!IS_VALID(pxSa) || (cb->dwSaId != pxSa->dwId))
    {
#ifdef __IKE_MULTI_THREADED__
        RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
        status = ERR_IKE_GETSA_FAIL;
        goto exit;
    }

    /* sanity-check */
    if (!IS_IKE2_SA(pxSa))
    {
#ifdef __IKE_MULTI_THREADED__
        RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
        status = ERR_IKE_BAD_SA;
        goto exit;
    }

#ifdef __IKE_MULTI_THREADED__
    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* relay this call to the proper thread */
        if (m_ikeSettings.funcPtrIkeThreadSend)
        {
            ubyte4 size = sizeof(struct dpcStateCB);
            struct dpcStateCB cs;
            cs.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcCertStatusCallback;
            cs.hdr.dpc_len = (ubyte2)size;
            cs.version = 2;
            cs.status = result;
            cs.data = data;
            status = (MSTATUS) m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid,
                                                            (ubyte *)&cs, size);
            if (OK <= status) data = NULL; /* !!! */
        }
        else
        {
            status = ERR_IKE_CONFIG;
        }
        RTOS_rwLockReleaseR(m_ikeSaRwLock);
        goto exit;
    }

    RTOS_rwLockWaitR(m_ikeSaRwLock);
#endif

    /* certificate status-check returns error */
    if (OK > (status = (MSTATUS)result))
    {
        /* clear cache */
        struct ike_context ctx = { NULL };
        ctx.pxSa = pxSa;
        IKE_certUnbind(&ctx);

        /* delete IKE_SA */
        pxSa->merror = status; /* jic */
        status = IKE2_delSa(pxSa, TRUE, status);
    }

exit:
    if (data) FREE(data);
    IKE_UNLOCK_R;
    return (sbyte4)status;
#undef cb
} /* IKE2_certStatusCallback */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_IPSEC_NAT_T__) || defined(__ENABLE_MOBIKE__)

static MSTATUS
DoHashNatD(IKE_context ctx, ubyte *poHash, intBoolean bPeer)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    struct ikeHdr *pxHdr = (struct ikeHdr *) ctx->pHdrParent;

    SHA1_CTX *hashCtxt = NULL;

    MOC_IP_ADDRESS ipAddr;
    ubyte2 wPort;

    ubyte4 dwIpAddr;
    const ubyte *poIpAddr;
    sbyte4 lenIpAddr;

    /* get IP address and port */
    if (bPeer)
    {
#ifdef __ENABLE_MOBIKE__
        ipAddr = ctx->peerAddr;
        wPort = ctx->wPeerPort;

        if ((0 == ipAddr) || (0 == wPort)) /* !!! */
#endif
        {
            ipAddr = REF_MOC_IPADDR(pxSa->dwPeerAddr);
            wPort = pxSa->wPeerPort;
        }
    }
    else
    {
        ipAddr = REF_MOC_IPADDR(pxSa->dwHostAddr);
        wPort = pxSa->wHostPort;
        /*wPort = USE_NATT_PORT(pxSa) ? IKE_NAT_UDP_PORT : IKE_DEFAULT_UDP_PORT;*/
    }

    /* calculate NAT_D hash value */
    SET_HTONS_1(wPort);

    TEST_MOC_IPADDR6(ipAddr,
    {
        poIpAddr = GET_MOC_IPADDR6(ipAddr);
        lenIpAddr = 16;
    })
    {
        SET_HTONL(dwIpAddr, GET_MOC_IPADDR4(ipAddr));
        poIpAddr = (const ubyte *) &dwIpAddr;
        lenIpAddr = 4;
    }

    if (OK > (status = IKE_sha1Alloc(MOC_HASH(ctx->hwAccelCookie) (BulkCtx *)&hashCtxt)))
        DBG_EXIT

    status = DIGI_MEMSET((void*)hashCtxt, 0x00, sizeof(SHA1_CTX));
    if (OK != status)
        DBG_EXIT

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if ((OK > (status = CRYPTO_INTERFACE_SHA1_initDigest(MOC_HASH(ctx->hwAccelCookie) hashCtxt))) ||
        (OK > (status = CRYPTO_INTERFACE_SHA1_updateDigest(MOC_HASH(ctx->hwAccelCookie) hashCtxt, pxHdr->poCky_I, IKE_COOKIE_SIZE))) ||
        (OK > (status = CRYPTO_INTERFACE_SHA1_updateDigest(MOC_HASH(ctx->hwAccelCookie) hashCtxt, pxHdr->poCky_R, IKE_COOKIE_SIZE))) ||
        (OK > (status = CRYPTO_INTERFACE_SHA1_updateDigest(MOC_HASH(ctx->hwAccelCookie) hashCtxt, poIpAddr, lenIpAddr))) ||
        (OK > (status = CRYPTO_INTERFACE_SHA1_updateDigest(MOC_HASH(ctx->hwAccelCookie) hashCtxt, (ubyte *)&wPort, sizeof(wPort)))) ||
        (OK > (status = CRYPTO_INTERFACE_SHA1_finalDigest(MOC_HASH(ctx->hwAccelCookie) hashCtxt, poHash))))
#else
    if ((OK > (status = SHA1_initDigestHandShake(MOC_HASH(ctx->hwAccelCookie) hashCtxt))) ||
        (OK > (status = SHA1_updateDigestHandShake(MOC_HASH(ctx->hwAccelCookie) hashCtxt, pxHdr->poCky_I, IKE_COOKIE_SIZE))) ||
        (OK > (status = SHA1_updateDigestHandShake(MOC_HASH(ctx->hwAccelCookie) hashCtxt, pxHdr->poCky_R, IKE_COOKIE_SIZE))) ||
        (OK > (status = SHA1_updateDigestHandShake(MOC_HASH(ctx->hwAccelCookie) hashCtxt, poIpAddr, lenIpAddr))) ||
        (OK > (status = SHA1_updateDigestHandShake(MOC_HASH(ctx->hwAccelCookie) hashCtxt, (ubyte *)&wPort, sizeof(wPort)))) ||
        (OK > (status = SHA1_finalDigestHandShake(MOC_HASH(ctx->hwAccelCookie) hashCtxt, poHash))))
#endif
        DBG_EXIT

exit:
    if (hashCtxt)
    {
        IKE_sha1Free(MOC_HASH(ctx->hwAccelCookie) (BulkCtx *)&hashCtxt);
    }
    return status;
} /* DoHashNatD */

#endif /* defined(__ENABLE_IPSEC_NAT_T__) || defined(__ENABLE_MOBIKE__) */


/*------------------------------------------------------------------*/

static MSTATUS
OutAttrB(IKE_context ctx, ubyte2 type, ubyte2 value)
{
    MSTATUS status = OK;

    struct ikeAttr0 *pxAttr0;

    OUT_HDR(struct ikeAttr, pxAttr, SIZEOF_IKE_ATTR)

    SET_HTONS(pxAttr->wAFtype, type);
    SET_HTONS(pxAttr->wLenVal, value);

    pxAttr0 = (struct ikeAttr0 *) pxAttr;
    pxAttr0->oAF |= 0x80;
/*
    printf("\t\tAttr= %d Val= %d\n", (int)type, (int)value);
*/
exit:
    return status;
} /* OutAttrB */


/*------------------------------------------------------------------*/

static intBoolean isAeadCipher(ubyte2 wTfmId)
{
    switch(wTfmId)
    {
        case ENCR_CHACHA20_POLY1305:
        case ENCR_AES_CCM_16:
        case ENCR_AES_CCM_12:
        case ENCR_AES_CCM_8:
        case ENCR_AES_GCM_16:
        case ENCR_AES_GCM_12:
        case ENCR_AES_GCM_8:
            return TRUE;
        default:
            return FALSE;
    }
}


/*------------------------------------------------------------------*/

static MSTATUS
OutTfm_I(IKE_context ctx)
{
    /* Note: IKE_SA initiator only */
    MSTATUS status = OK;

    IKE2XG pxXg = ctx->pxXg;
    IKESA pxSa = pxXg->pxSa;

    struct ikePpsHdr *pxPpsHdr = (struct ikePpsHdr *) ctx->pHdrParent;

    sbyte4 i, k;

    /* traverse transform's */
    for (i=0; i < NUM_TFM_TYPE; i++)
    {
        ubyte oTfmType = (ubyte)(MIN_TFM_TYPE + i);

        for (k=0; ; k++) /* enumerate */
        {
            ubyte2 wTfmId = 0, wKeyLen = 0;

            if (TFM_ENCR == oTfmType) /* Encryption Algorithm */
            {
                IKE_cipherSuiteInfo *pCipherSuite;
#ifdef CUSTOM_IKE_GET_ENCR_ALGO
                if (0 < pxSa->numEncrAlgos)
                {
                    if (k >= pxSa->numEncrAlgos) break;
                    wTfmId = pxSa->pwEncrAlgos[k];

                    wKeyLen = pxSa->pwEncrKeyLens[k];
                    pCipherSuite = IKE_cipherSuiteEx(pxSa->ikePeerConfig, 0, wTfmId, wKeyLen, NULL);
                    if (!pCipherSuite) continue; /* jic */
                    if ((1 == pxPpsHdr->oNum) && (NULL == pCipherSuite->pAeadAlgo)) continue;
                    if ((2 == pxPpsHdr->oNum) && (NULL != pCipherSuite->pAeadAlgo)) continue;
                    if (pCipherSuite->bFixedKeyLen)
                        wKeyLen = 0; /* !!! */
                }
                else
#endif
                {
                    pCipherSuite = IKE_getCipherSuiteEx(pxSa->ikePeerConfig, k);
                    if (!pCipherSuite) break;
                    if (pCipherSuite->bDisabled[1][_I]) continue;
                    /* First Proposal Payload contains AEAD algorithms.
                     * Second Proposal Payload does not contain AEAD algorithms. */
                    if ((1 == pxPpsHdr->oNum) && (NULL == pCipherSuite->pAeadAlgo)) continue;
                    if ((2 == pxPpsHdr->oNum) && (NULL != pCipherSuite->pAeadAlgo)) continue;
                    wTfmId = pCipherSuite->wTfmId;

                    if (!pCipherSuite->bFixedKeyLen
#ifdef __ENABLE_DIGICERT_IKE_STRONGSWAN_562__
                            || (ENCR_CHACHA20_POLY1305 == wTfmId)
#endif
                            )
                    {
                        if (0 == (wKeyLen = pCipherSuite->wKeyLenEnd))
                            wKeyLen = pCipherSuite->wKeyLen;
                    }
                }
            }

            else if (TFM_PRF == oTfmType) /* PRF */
            {
#ifdef CUSTOM_IKE_GET_HASH_ALGO
                if (0 < pxSa->numHashAlgos)
                {
                    if (k >= pxSa->numHashAlgos) break;
                    wTfmId = pxSa->pwHashAlgos[k];
                }
                else
#endif
                {
                    IKE_hashSuiteInfo *pHashSuite = IKE_getHashSuiteEx(pxSa->ikePeerConfig, k);
                    if (!pHashSuite) break;
                    if (pHashSuite->bDisabled[1][_I]) continue;
                    if ((1 == pxPpsHdr->oNum) && (PRF_AES128_XCBC == pHashSuite->wTfmId)) continue;
                    wTfmId = pHashSuite->wTfmId;
                }
            }

            else if (TFM_INTEG == oTfmType) /* Integrity Algorithm */
            {
                /* First Proposal contains AEAD algorithms.
                 * RFC 5996 Section 3.3:
                 *     Combined-mode ciphers include both integrity and encryption in a
                 *     single encryption algorithm, and MUST either offer no integrity
                 *     algorithm or a single integrity algorithm of "none".
                 *
                 * Skip all TF_INTEG algorithms. */
                if (1 == pxPpsHdr->oNum) break;

#ifdef CUSTOM_IKE_GET_INTEG_ALGO
                if (0 < pxSa->numMacAlgos)
                {
                    if (k >= pxSa->numMacAlgos) break;
                    wTfmId = pxSa->pwMacAlgos[k];
                }
                else
#endif
                {
                    IKE_macSuiteInfo *pMacSuite = IKE_getMacSuiteEx(pxSa->ikePeerConfig, k);
                    if (!pMacSuite) break;
                    if (pMacSuite->bDisabled[_I]) continue;
                    wTfmId = pMacSuite->wTfmId;
                }
            }

            else if (TFM_DH == oTfmType) /* DH Group */
            {
#if defined(CUSTOM_IKE_GET_P1_DHGRP) || defined(CUSTOM_IKE_GET_P2_PFS)
                if (0 < pxSa->numDhGrps)
                {
                    if (k >= pxSa->numDhGrps) break;
                    wTfmId = pxSa->pwDhGrps[k]; /* != 0; see IKE_customDhGroups() */
                }
                else
#endif
                {
                    IKE_dhGroupInfo *pGroup = IKE_getDhGroupEx(pxSa->ikePeerConfig, k);
                    if (!pGroup) break;

                    if (((TRUE == pxSa->dhGrpSet) || (pGroup->bDisabled[1][_I])) &&
                        (pGroup->wTfmId != pxSa->wDhGrp)) /* jic */
                        continue;
                    wTfmId = pGroup->wTfmId; /* may be 0 !!! */
                }
            }

            else
            {
                break;
            }

            if (wTfmId)
            {
                /* transform payload header */
                OUT_TOP(struct ike2TfmHdr, pxTfmHdr, SIZEOF_IKE_TFM_HDR, ISAKMP_NEXT_T)
                SET_HTONS(pxTfmHdr->wTfmId, wTfmId);
                pxTfmHdr->oType = oTfmType;
                ++(pxPpsHdr->oTfmLen);
                if (wKeyLen)
                {
                    /* attribute KEY_LENGTH */
                    OUT_DOWN(pxTfmHdr)
                    if (OK != (status = OutAttrB(ctx, ATTR_KEY_LENGTH, wKeyLen * 8)))
                        goto exit;
                    OUT_UP(pxTfmHdr)
                }
            }
        } /* for (k= */
    } /* for (i= */

exit:
    return status;
} /* OutTfm_I */


/*------------------------------------------------------------------*/

static MSTATUS
OutTfm_R(IKE_context ctx)
{
    /* Note: IKE_SA responder only */
    MSTATUS status = OK;

    IKE2XG pxXg = ctx->pxXg;
    IKESA pxSa = pxXg->pxSa;

    struct ikePpsHdr *pxPpsHdr = (struct ikePpsHdr *) ctx->pHdrParent;

    /* traverse transform's */
    sbyte4 i;
    for (i=0; i < NUM_TFM_TYPE; i++)
    {
        ubyte2 wTfmId = 0, wKeyLen = 0;

        ubyte oTfmType = (ubyte)(MIN_TFM_TYPE + i);
        switch (oTfmType)
        {
        case TFM_ENCR : /* Encryption Algorithm */
            if (pxSa->pCipherSuite) /* jic */
            {
                wTfmId = pxSa->pCipherSuite->wTfmId;
                wKeyLen = pxSa->wEncrKeyLen;
            }
            break;
        case TFM_PRF : /* PRF */
            if (pxSa->pHashSuite) /* jic */
            {
                wTfmId = pxSa->pHashSuite->wTfmId;
            }
            break;
        case TFM_INTEG : /* Integrity Algorithm */
            if (pxSa->pMacSuite) /* jic */
            {
                wTfmId = pxSa->pMacSuite->wTfmId;
                wKeyLen = pxSa->wAuthKeyLen;
            }
            break;
        case TFM_DH : /* DH Group */
            wTfmId = pxSa->wDhGrp;
            break;
        default :
            break;
        }

        if (wTfmId)
        {
            /* transform payload header */
            OUT_TOP(struct ike2TfmHdr, pxTfmHdr, SIZEOF_IKE_TFM_HDR, ISAKMP_NEXT_T)
            SET_HTONS(pxTfmHdr->wTfmId, wTfmId);
            pxTfmHdr->oType = oTfmType;
            ++(pxPpsHdr->oTfmLen);

            if (wKeyLen)
            {
                /* attribute KEY_LENGTH */
                OUT_DOWN(pxTfmHdr)
                if (OK != (status = OutAttrB(ctx, ATTR_KEY_LENGTH, wKeyLen * 8)))
                    goto exit;
                OUT_UP(pxTfmHdr)
            }
        }
    } /* for */

exit:
    return status;
} /* OutTfm_R */


/*------------------------------------------------------------------*/

static MSTATUS
OutTfm2(IKE_context ctx, intBoolean isAead)
{
    /* Note: CHILD_SA (AH & ESP) only */
    MSTATUS status = OK;

    IPSECPPS pxIPsecPps = ctx->pxIPsecPps;

    IKE2XG pxXg = ctx->pxXg;
    IKESA  pxSa = ctx->pxSa;  /* pxXg->pxSa is NULL */
    IPSECSA pxIPsecSa = pxXg->pxIPsecSa;
    intBoolean bInitiator = IS_CHILD_INITIATOR(pxIPsecSa);

    ubyte oTfmId = pxIPsecPps->oTfmId;
    ubyte2 wAuthAlgo = pxIPsecPps->wAuthAlgo;
    ubyte2 wEncrKeyLen = pxIPsecPps->wEncrKeyLen;
    ubyte2 wAuthKeyLen = pxIPsecPps->wAuthKeyLen;
    ubyte2 bitStrength = 0;
#ifndef __DISABLE_DIGICERT_CONSTRAINT_CIPHER__
    bitStrength = CHILDSA_cipherEffectiveBitStrength(pxSa->pCipherSuite->wTfmId, pxSa->wEncrKeyLen);
#endif

#ifndef __ENABLE_DIGICERT_PFKEY__
    intBoolean bNoEnumEncr = (!bInitiator ||
                              (ESP_NULL == oTfmId) ||
                              (oTfmId && wEncrKeyLen) ||
                              (PROTO_IPSEC_AH == pxIPsecPps->oProtocol))
                             ? TRUE : FALSE;

    intBoolean bNoEnumAuth = (!bInitiator ||
                              wAuthAlgo ||
                              (IPSEC_PROTO_ESP == pxIPsecPps->oSecuProto))
                             ? TRUE : FALSE;
#else
    intBoolean bNoEnumEncr = TRUE;
    intBoolean bNoEnumAuth = TRUE;
#endif
    struct ikePpsHdr *pxPpsHdr = (struct ikePpsHdr *) ctx->pHdrParent;

    sbyte4 i, j;

#ifndef __ENABLE_DIGICERT_PFKEY__
    if (bInitiator)
    {
        /* reset wildcards - jic re-transmit */
        ubyte2 flags = pxIPsecPps->p_flags;
        if (IKE_PROP_FLAG_TFM_ID & flags)       pxIPsecPps->oTfmId      = 0;
        if (IKE_PROP_FLAG_AUTH_ALGO & flags)    pxIPsecPps->wAuthAlgo   = 0;
        if (IKE_PROP_FLAG_ENCR_ALGO & flags)    pxIPsecPps->oEncrAlgo   = 0;
        if (IKE_PROP_FLAG_ENCR_KEYLEN & flags)  pxIPsecPps->wEncrKeyLen = 0;
    }
#endif

    /* traverse transform's */
    for (i=0; i < NUM_TFM_TYPE; i++)
    {
        ubyte oTfmType = (ubyte)(MIN_TFM_TYPE + i);
        intBoolean bNoEnum = !bInitiator;

        for (j=0; ; j++) /* enumerate */
        {
            ubyte2 wTfmId = 0, wKeyLen = 0;

            if (TFM_ENCR == oTfmType) /* Encryption Algorithm */
            {
                CHILDSA_encrInfo *pEncrAlgo = NULL;

                bNoEnum = bNoEnumEncr;
                wKeyLen = wEncrKeyLen;

                if (bNoEnum)
                {
                    if (PROTO_IPSEC_AH == pxIPsecPps->oProtocol)
                        break;

                    if (ESP_NULL == oTfmId)
                    {
                        wKeyLen = 0; /* jic */
                        wTfmId = ENCR_NULL;
                    }
                    else
                    {
                        /* both 'oTfmId' and 'wKeyLen' are specified */
                        if (NULL == (pEncrAlgo = CHILDSA_findEncrAlgoWithConstraint(bitStrength, oTfmId, 0, 0, wKeyLen, NULL)))
                            break; /* jic */

                        if (pEncrAlgo->bFixedKeyLen && bInitiator)
                            wKeyLen = 0; /* jic */

                        wTfmId = pEncrAlgo->wTfmId;
                    }
                }
                else /* must be initiator */
                {
                    if (NULL == (pEncrAlgo = CHILDSA_getEncrAlgo(j))) break;

                    if (oTfmId && (oTfmId != pEncrAlgo->oTfmId))
                        continue;

                    /* check encr key-length */
                    if (wKeyLen)
                    {

                        if ((wKeyLen < pEncrAlgo->wKeyLen) ||
                            (pEncrAlgo->wKeyLenEnd && (wKeyLen > pEncrAlgo->wKeyLenEnd)))
                            continue;

#ifndef __DISABLE_DIGICERT_CONSTRAINT_CIPHER__
                        if (CHILDSA_cipherEffectiveBitStrength(pEncrAlgo->oTfmId, wKeyLen) > bitStrength)
                            continue;
#endif

                        if (pEncrAlgo->bFixedKeyLen) wKeyLen = 0;
                    }
                    else
                    {
#ifndef __DISABLE_DIGICERT_CONSTRAINT_CIPHER__
                        ubyte2 wKeyLenEnd = CHILDSA_cipherMaxKeyLengthWithConstraint(pEncrAlgo->oTfmId, 0, 0, wKeyLen, wKeyLen, bitStrength);
                        if (wKeyLenEnd == 0)
                        {
                            continue;
                        }
#else
                        ubyte2 wKeyLenEnd = pEncrAlgo->wKeyLenEnd;
#endif

                        if (!pEncrAlgo->bFixedKeyLen
#ifdef __ENABLE_DIGICERT_IKE_STRONGSWAN_562__
                            || (ESP_CHACHA20_POLY1305 == pEncrAlgo->oTfmId)
#endif
                           )
                        {
                            if (0 == (wKeyLen = wKeyLenEnd))
                                wKeyLen = pEncrAlgo->wKeyLen;
                        }

                    }

                    if ((!isAead) && pEncrAlgo->oTagLen &&  /* AEAD encr algo */
                        !oTfmId && (!bNoEnumAuth || wAuthAlgo))
                    {
                        continue; /* should not use auth algo! */
                    }
                    else if(isAead && (!pEncrAlgo->oTagLen) &&
                            (!oTfmId))
                    {
                        continue;
                    }

                    wTfmId = pEncrAlgo->wTfmId;
                }
            }

            else if (TFM_INTEG == oTfmType) /* Integrity Algorithm */
            {
                CHILDSA_authInfo *pAuthAlgo = NULL;

                bNoEnum = bNoEnumAuth;
                wKeyLen = wAuthKeyLen;
#ifdef __ENABLE_DIGICERT_IPSEC_ENUM_AUTH__
/* send NULL Auth in the proposal. This is fix for some old Cisco ASA, which 
   expects explicit NULL AUTH in the proposal. */
                if (IPSEC_PROTO_ESP == pxIPsecPps->oSecuProto)
                {
                    wTfmId = 0;
                    wKeyLen = 0;
                    bNoEnum = FALSE;
                    if (j > 0)
                        break;
                }
                else
                {
                    if (bNoEnum)
                    {
                        /* 'wAuthAlgo' is specified */
                        if (NULL == (pAuthAlgo = CHILDSA_findAuthAlgo(wAuthAlgo, 0, 0, 0)))
                        {
                            if (j == 0)
                            {
                                wTfmId = 0;
                                wKeyLen = 0;
                                bNoEnum = FALSE;
                            }
                            else
                            {
                                break; /* jic */
                            }
                        }
                        else
                        {
                            wTfmId = pAuthAlgo->wTfmId;
                        }

                        if (bInitiator) wKeyLen = 0; /* jic */
                    }
                    else /* must be initiator */
                    {
                        if (NULL == (pAuthAlgo = CHILDSA_getAuthAlgo(j))) break;
                        wKeyLen = 0; /* jic */
                        wTfmId = pAuthAlgo->wTfmId;
                    }
                }

#else
                if (bNoEnum)
                {
                    if (IPSEC_PROTO_ESP == pxIPsecPps->oSecuProto)
                        break;

                    /* 'wAuthAlgo' is specified */
                    if (NULL == (pAuthAlgo = CHILDSA_findAuthAlgo(wAuthAlgo, 0, 0, 0)))
                        break; /* jic */

                    if (bInitiator) wKeyLen = 0; /* jic */
                }
                else /* must be initiator */
                {
                    if (NULL == (pAuthAlgo = CHILDSA_getAuthAlgo(j))) break;
                    wKeyLen = 0; /* jic */
                }

                wTfmId = pAuthAlgo->wTfmId;

                /* if AEAD algorithms are selected, skip Integrity algorithms */
                if (isAead) continue;
#endif     /* __ENABLE_DIGICERT_IPSEC_ENUM_AUTH__ */           
            }

            else if (TFM_DH == oTfmType) /* DH Group */
            {
                /* no PFS for piggybacked CHILD_SA!!! */
                if (IKE_XCHG_CHILD != pxXg->oExchange) break;

                if (bNoEnum)
                {
                    wTfmId = pxIPsecSa->wPFS;
                }
#ifdef CUSTOM_IKE_GET_P2_PFS
                else if (0 < pxIPsecSa->numDhGrps)
                {
                    if (j >= pxIPsecSa->numDhGrps) break;
                    wTfmId = pxIPsecSa->pwDhGrps[j];
                    if (!wTfmId && (1 == pxIPsecSa->numDhGrps))
                        break; /* No PFS; so no D-H Transform! */
                }
#endif
                else
                {
                    IKE_dhGroupInfo *pGroup = IKE_getDhGroupEx(pxSa->ikePeerConfig, j);
                    if (!pGroup) break;
                    if (pGroup->bDisabled[1][_I] &&
                        (pGroup->wTfmId != pxIPsecSa->wPFS)) /* jic */
                        continue;
                    wTfmId = pGroup->wTfmId;
                }
            }

            else if (TFM_ESN == oTfmType) /* ESN */
            {
#if defined(__ENABLE_DIGICERT_PFKEY__)
                bNoEnum = TRUE;
                if (IKE_PROP_FLAG_ESN & pxIPsecPps->p_flags) wTfmId = 1;
#elif defined(__ENABLE_IPSEC_ESN__)
                if (bNoEnum) /* responder */
                {
                    if (IKE_PROP_FLAG_ESN & pxIPsecPps->p_flags) wTfmId = 1;
                }
                else /* initiator */
                {
                    if (j) bNoEnum = TRUE;
                    else wTfmId = 1;
                }
#else
                bNoEnum = TRUE;
#endif
            }
            else
            {
                break;
            }

            if (wTfmId || !bNoEnum || (TFM_ESN == oTfmType))
            {
                /* transform payload header */
                OUT_TOP(struct ike2TfmHdr, pxTfmHdr, SIZEOF_IKE_TFM_HDR, ISAKMP_NEXT_T)
                SET_HTONS(pxTfmHdr->wTfmId, wTfmId);
                pxTfmHdr->oType = oTfmType;
                ++(pxPpsHdr->oTfmLen);

                if (wKeyLen)
                {
                    /* attribute KEY_LENGTH */
                    OUT_DOWN(pxTfmHdr)
                    if (OK != (status = OutAttrB(ctx, ATTR_KEY_LENGTH, wKeyLen * 8)))
                        goto exit;
                    OUT_UP(pxTfmHdr)
                }
            }

            if (bNoEnum) break;
        } /* for (j= */
    } /* for (i= */

exit:
    return status;
} /* OutTfm2 */


/*------------------------------------------------------------------*/

static MSTATUS
OutSa(IKE_context ctx)
{
    MSTATUS status = OK;

    IKE2XG pxXg = ctx->pxXg;
    IKESA pxSa = pxXg->pxSa;
    IPSECSA pxIPsecSa = pxXg->pxIPsecSa;

    /* the value of the Proposal Num in Proposal substructure */
    ubyte4 ppNum = 1;
    intBoolean isAead = FALSE;

    intBoolean bInitiator = IS_XCHG_INITIATOR(pxXg);
    ubyte oSpiSize = sizeof(ubyte4);

    /* for CHILD_SA */
    ubyte oPpsIndex = 0;

    /* SA payload header */
    OUT_TOP(struct ikeGenHdr, pxSaHdr, SIZEOF_IKE_GEN_HDR, IKE_NEXT_SA)

    /* down one level - go to child payloads */
    OUT_DOWN(pxSaHdr)

    /* proposal payload(s) */
    for (; (NULL != pxSa) || (oPpsIndex < pxIPsecSa->axP2Sa[0].oChildSaLen); )
    {
        IPSECPPS pxIPsecPps = (NULL != pxSa) ? NULL :
                    &(pxIPsecSa->axP2Sa[0].axChildSa[oPpsIndex].ipsecPps);
#ifdef __ENABLE_DIGICERT_PFKEY__
        ubyte oPpsNum = (NULL != pxSa) ? 0 :
                    pxIPsecSa->axP2Sa[0].axChildSa[oPpsIndex].oIPsecPpsNum;
        IPSECPPS pxExIPsecPps = (NULL != pxSa) ? NULL :
                    pxIPsecSa->axP2Sa[0].axChildSa[oPpsIndex].pxIPsecPps;

        sbyte4 n = 0;
#endif
        for (;;)
        {
            /* proposal payload header */
            OUT_TOP(struct ikePpsHdr, pxPpsHdr, SIZEOF_IKE_PPS_HDR, ISAKMP_NEXT_P)

            if (NULL != pxSa) /* IKE_SA */
            {
                if (pxSa != ctx->pxSa) /* rekeying */
                    oSpiSize = IKE_COOKIE_SIZE;
                else
                    oSpiSize = 0;

                if (bInitiator)
                    pxPpsHdr->oNum = ppNum;
                else
                    pxPpsHdr->oNum = pxSa->oPpsNo;

                pxPpsHdr->oProtoId = PROTO_ISAKMP;
            }
            else /* CHILD_SA */
            {
                /* We only have two proposals if protocol selected
                 * is ESP and IPSec rules select any for both
                 * encryption and integrity algorithms.
                 **/
                if (bInitiator &&
                    (PROTO_IPSEC_ESP == pxIPsecPps->oProtocol) &&
                    (pxIPsecPps->oTfmId == 0) &&
                    (pxIPsecPps->wAuthAlgo == 0))
                    pxIPsecPps->oPpsNo = 2;

                if (bInitiator)
                    pxPpsHdr->oNum = ppNum;
                else
                    pxPpsHdr->oNum = pxIPsecPps->oPpsNo;
                pxPpsHdr->oProtoId = pxIPsecPps->oProtocol;

#ifdef __ENABLE_IPSEC_NAT_T__
                if (bInitiator &&
                    (IKE_PROP_FLAG_UDP_ENCP & pxIPsecPps->p_flags))
                {
                    /* AH is incompatible with UDP-encap. */
                    if (PROTO_IPSEC_AH == pxIPsecPps->oProtocol)
                    {
                        status = ERR_IKE_MISMATCH;
                        DBG_EXIT
                    }

                    /* if NAT-T is needed but not supported by the peer */
                    if (!(IKE_NATT_FLAG_D & ctx->pxSa->natt_flags))
                    {
                        status = ERR_IKE_MISMATCH;
                        DBG_EXIT
                    }
                }
#endif /* __ENABLE_IPSEC_NAT_T__ */
            }

            /* SPI */
            if (oSpiSize)
            {
                if (ctx->dwBufferSize < oSpiSize)
                {
                    status = ERR_IKE_BUFFER_OVERFLOW;
                    DBG_EXIT
                }
                pxPpsHdr->oSpiSize = oSpiSize;
                SET_HTONS(pxPpsHdr->wLength,
                          SIZEOF_IKE_PPS_HDR/* GET_NTOHS(pxPpsHdr->wLength) */ + oSpiSize);

                if (NULL != pxSa) /* rekeying IKE_SA */
                {
                    ubyte *poSpi = (bInitiator ? pxSa->poCky_I : pxSa->poCky_R);
                    DIGI_MEMCPY(ctx->pBuffer, poSpi, /*oSpiSize*/IKE_COOKIE_SIZE);
                }
                else /* CHILD_SA */
                {
                    ubyte4 dwSpi = pxIPsecPps->dwSpi[bInitiator ? _I : _R];
                    SET_HTONL(pxPpsHdr->dwSpi, dwSpi);
                }
                ADVANCE(oSpiSize)
            }

            /* down one level - go to child payloads */
            OUT_DOWN(pxPpsHdr)

            /* transform payloads */
            if (NULL != pxSa) /* IKE_SA */
            {
                if (bInitiator)
                    status = OutTfm_I(ctx);
                else
                    status = OutTfm_R(ctx);
            }
            else /* CHILD_SA */
            {
                ctx->pxIPsecPps = pxIPsecPps;

                /* if an AEAD algorithm was selected in IPSec policy file, or
                 * we are generating second Proposal is no algorithm is selected.
                 * Then set isAead to TRUE so we don't add INTEG algorithms to Proposal,
                 * as well as skipping non AEAD algorithms. */
                if (isAeadCipher(pxIPsecPps->oTfmId) ||
                    ((pxIPsecPps->oTfmId == 0) && (pxIPsecPps->wAuthAlgo == 0) &&
                     (2 == ppNum)))
                    isAead = TRUE;

                status = OutTfm2(ctx, isAead);
            }

            if (OK != status) goto exit;

            /* up one level */
            OUT_UP(pxPpsHdr)

            if (NULL != pxSa)
            {
                if(!bInitiator) break;

                if (ppNum >= pxSa->oPpsNo)
                    break;
                ppNum++;
            }
            else
            {
#ifdef __ENABLE_DIGICERT_PFKEY__
                pxIPsecPps = pxExIPsecPps + (n++);
                if (n >= (sbyte4)oPpsNum) break;
#else
                if (ppNum >= pxIPsecPps->oPpsNo) break;
                ppNum++;
#endif
            }
        } /* for (;;) */

        if (NULL != pxIPsecPps) /* CHILD_SA */
        {
            ++oPpsIndex;
            continue; /* there may be more proposal payloads */
        }

        break;
    } /* for (; */

    /* up one level */
    OUT_UP(pxSaHdr)

exit:
    return status;
} /* OutSa */


/*------------------------------------------------------------------*/

static MSTATUS
OutGen(IKE_context ctx, ubyte oNextPayload, ubyte2 wBodyLen, ubyte *poBody)
{
    MSTATUS status = OK;

    /* generic header */
    OUT_BEGIN(struct ikeGenHdr, pxGenHdr, SIZEOF_IKE_GEN_HDR, oNextPayload)

    /* data */
    if (NULL != poBody)
        DIGI_MEMCPY(ctx->pBuffer, poBody, wBodyLen);

    /* done */
    OUT_END

exit:
    return status;
} /* OutGen */


/*------------------------------------------------------------------*/

#ifdef CUSTOM_IKE_GET_VENDOR_ID

static MSTATUS
OutVid(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    intBoolean bInitiator = IS_INITIATOR(pxSa);
    MOC_IP_ADDRESS peerAddr = REF_MOC_IPADDR(pxSa->dwPeerAddr);

    sbyte4 i;
    for (i=0; (SIZEOF_IKE_GEN_HDR < ctx->dwBufferSize); i++)
    {
        ubyte2 vidLen = (ubyte2)(ctx->dwBufferSize - SIZEOF_IKE_GEN_HDR);
        if ((OK > CUSTOM_IKE_GET_VENDOR_ID(
                            ctx->pBuffer + SIZEOF_IKE_GEN_HDR, &vidLen,
                            i, peerAddr, 0, bInitiator
                            MOC_MTHM_REQ_VALUE(pxSa->serverInstance)))
            || (0 == vidLen))
        {
            break;
        }

        if (OK != (status = OutGen(ctx, IKE_NEXT_V, vidLen, NULL)))
            goto exit;
    }

exit:
    return status;
} /* OutVid */

#endif


/*------------------------------------------------------------------*/

#if defined(__ENABLE_IPSEC_NAT_T__) || defined(__ENABLE_MOBIKE__)

static MSTATUS
OutNatD(IKE_context ctx)
{
    MSTATUS status = OK;

    sbyte4 i;
    for (i=0; i < 2; i++) /* SRC, DST */
    {
        ubyte2 wBodyLen = SHA_HASH_RESULT_SIZE;

        /* notify payload header */
        OUT_BEGIN(struct ike2NotifyHdr, pxNotifyHdr, SIZEOF_IKE2_NOTIFY_HDR, IKE_NEXT_N)
        SET_HTONS(pxNotifyHdr->wMsgType,
                  (i ? NAT_DETECTION_DESTINATION_IP : NAT_DETECTION_SOURCE_IP));

        /* NAT_D hash data */
        if (OK > (status = DoHashNatD(ctx, ctx->pBuffer, (i ? TRUE : FALSE))))
            goto exit;

        debug_printd((sbyte *)(i ? "   NAT_D (peer):" : "   NAT_D (us):"),
                     ctx->pBuffer, SHA_HASH_RESULT_SIZE);

        OUT_END
    } /* for */

exit:
    return status;
} /* OutNatD */

#endif /* defined(__ENABLE_IPSEC_NAT_T__) || defined(__ENABLE_MOBIKE__) */


/*------------------------------------------------------------------*/

static MSTATUS
OutKe(IKE_context ctx)
{
    MSTATUS                 status      = OK;

    IKE2XG                  pxXg        = ctx->pxXg;
    IKESA                   pxSa        = pxXg->pxSa;
    IPSECSA                 pxIPsecSa   = pxXg->pxIPsecSa;

    intBoolean              bInitiator  = IS_XCHG_INITIATOR(pxXg);

    diffieHellmanContext*   pDHctx = NULL;
    MDhKeyTemplate          keyTemplate = {0};

#ifdef __ENABLE_DIGICERT_ECC__
    ECCKey*                 pEccKey     = NULL;
    sbyte4                  stringLenF;
    ubyte4                  curveId = 0;
    ubyte*                  pPoint      = NULL;
    ubyte4                  pointLen    = 0;
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    QS_CTX*                 pQsCtx = NULL;
    ubyte4                  qsPubKeyLen;
    ubyte4                  cipherTextLen;
#endif
    ubyte2                  wBodyLen;
    /* get DH group */
    ubyte2 wGroup = (pxSa ? pxSa->wDhGrp : pxIPsecSa->wPFS);
    if (0 == wGroup) /* unspecified */
    {
        /* no PFS */
        if (!pxSa) goto exit; /* CHILD_SA */

        status = bInitiator ? ERR_IKE_MISMATCH_DH_GROUP /* bad configuration */
                            : ERR_IKE_BAD_KE; /* missking KE */
        DBG_EXIT
    }

    /* get DH context */
    if (NULL == (pDHctx = (pxSa ? DIFFIEHELLMAN_CONTEXT(pxSa)
                                : DIFFIEHELLMAN_CONTEXT(pxIPsecSa))))
    {
#ifdef __ENABLE_DIGICERT_ECC__
      if (NULL == (pEccKey = (pxSa ? pxSa->p_eccKey : pxIPsecSa->p_eccKey)))
#endif
      {
        if (bInitiator) /* initiator */
        {
            IKE_dhGroupInfo *pDhGroup;
            if (!wGroup || (NULL == (pDhGroup = IKE_dhGroupEx(
                                            ctx->pxSa->ikePeerConfig, wGroup))))
            {
                status = ERR_IKE_BAD_KE;
                DBG_EXIT
            }

#ifdef __ENABLE_DIGICERT_ECC__
            if (0 < pDhGroup->curveId)
            {
                ECCKey **ppEccKey = (pxSa ? &pxSa->p_eccKey : &pxIPsecSa->p_eccKey);

                curveId = pDhGroup->curveId;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                status = CRYPTO_INTERFACE_EC_generateKeyPairAllocAux (MOC_ECC(ctx->hwAccelCookie)
                    curveId, &pEccKey, RANDOM_rngFun, g_pRandomContext);
                if (OK != status)
                    DBG_EXIT
#else
                status = EC_generateKeyPairAlloc (MOC_ECC(ctx->hwAccelCookie)
                    curveId, &pEccKey, RANDOM_rngFun, g_pRandomContext);
                if (OK != status)
                    DBG_EXIT
#endif
                *ppEccKey = pEccKey;

#ifdef __ENABLE_DIGICERT_PQC__
                if (0 < pDhGroup->qsAlgoId)
                {
                    QS_CTX **ppQsCtx = (pxSa ? &pxSa->pQsCtx : &pxIPsecSa->pQsCtx);

                    status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(ctx->hwAccelCookie) &pQsCtx, pDhGroup->qsAlgoId);
                    if (OK != status)
                        DBG_EXIT

                    status = CRYPTO_INTERFACE_QS_generateKeyPair(MOC_HASH(ctx->hwAccelCookie) pQsCtx, RANDOM_rngFun, g_pRandomContext);
                    if (OK != status)
                        DBG_EXIT

                    *ppQsCtx = pQsCtx;
                }
#endif
            }
            else
#endif
            {
                /* create DH context */
                diffieHellmanContext **ppDHctx = (pxSa ?
                                                &(DIFFIEHELLMAN_CONTEXT(pxSa)) :
                                                &(DIFFIEHELLMAN_CONTEXT(pxIPsecSa)));
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                if (OK > (status = CRYPTO_INTERFACE_DH_allocateServerExt(MOC_DH(ctx->hwAccelCookie)
                                                     g_pRandomContext, ppDHctx,
                                                     pDhGroup->dwGroupNum, NULL)))
                    DBG_EXIT
#else
                if (OK > (status = DH_allocateServer(MOC_DH(ctx->hwAccelCookie)
                                                     g_pRandomContext, ppDHctx,
                                                     pDhGroup->dwGroupNum)))
                    DBG_EXIT
#endif

                pDHctx = *ppDHctx;
            }
        }
        else /* responder */
        {
            status = ERR_IKE_BAD_KE; /* missing KE - for CREATE_CHILD_SA (redundant?) */
            DBG_EXIT
        }
      }
#ifdef __ENABLE_DIGICERT_ECC__
      else
      {
#ifdef __ENABLE_DIGICERT_PQC__
        pQsCtx = (pxSa ? pxSa->pQsCtx : pxIPsecSa->pQsCtx);
#endif
      }
#endif
    }

    /* get DH public value length */
#ifdef __ENABLE_DIGICERT_ECC__
    if (NULL != pEccKey)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(pEccKey, (ubyte4 *)&stringLenF);
        if (OK != status)
            goto exit;
#else
        status = EC_getElementByteStringLen(pEccKey, (ubyte4 *)&stringLenF);
        if (OK != status)
            goto exit;
#endif
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pEccKey, &curveId);
                    if (OK != status)
                        DBG_EXIT
#else
        status = EC_getCurveIdFromKey(pEccKey, &curveId);
                    if (OK != status)
                        DBG_EXIT
#endif

#if defined (__ENABLE_DIGICERT_ECC_EDDH_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDH_448__)
        if((cid_EC_X25519 == curveId) || (cid_EC_X448 == curveId))
        {
            wBodyLen = (ubyte2)(stringLenF);
        }
        else
#endif
        {
            wBodyLen = (ubyte2)(2 * stringLenF);
        }

#ifdef __ENABLE_DIGICERT_PQC__
        if (NULL != pQsCtx)
        {
            /* initiator sends public key, responder sends cipher text encrypted
             * with public key. */
            if (bInitiator)
            {
                status = CRYPTO_INTERFACE_QS_getPublicKeyLen(pQsCtx, &qsPubKeyLen);
                if (OK != status)
                    DBG_EXIT

                wBodyLen += qsPubKeyLen;
            }
            else
            {
                status = CRYPTO_INTERFACE_QS_KEM_getCipherTextLen(pQsCtx, &cipherTextLen);
                if (OK != status)
                    DBG_EXIT

                wBodyLen += cipherTextLen;
            }
        }
#endif
    }
    else
#endif /* __ENABLE_DIGICERT_ECC__ */
    {
        if (NULL == pDHctx) /* jic */
        {
            status = ERR_NULL_POINTER;
            DBG_EXIT
        }
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_DH_getKeyParametersAllocExt(MOC_DH(ctx->hwAccelCookie) &keyTemplate, pDHctx, MOC_GET_PUBLIC_KEY_DATA, NULL);
        if (OK != status)
            goto exit;
#else
        status = DH_getKeyParametersAlloc(MOC_DH(ctx->hwAccelCookie) &keyTemplate, pDHctx, MOC_GET_PUBLIC_KEY_DATA);
        if (OK != status)
            goto exit;
#endif
        wBodyLen = keyTemplate.pLen;
    }

    /* KE payload header */
    { OUT_BEGIN(struct ikeKeHdr, pxKeHdr, SIZEOF_IKE_KE_HDR, IKE_NEXT_KE)

    SET_HTONS(pxKeHdr->wGrpNo, wGroup);

    /* key exchange data */
#ifdef __ENABLE_DIGICERT_ECC__
    if (NULL != pEccKey)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAllocAux(MOC_ECC(ctx->hwAccelCookie) pEccKey, &pPoint, &pointLen);
        if (OK != status)
            goto exit;
#else
        status = EC_writePublicKeyToBufferAlloc(MOC_ECC(ctx->hwAccelCookie) pEccKey, &pPoint, &pointLen);
        if (OK != status)
            goto exit;
#endif
#if defined (__ENABLE_DIGICERT_ECC_EDDH_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDH_448__)
        if((cid_EC_X25519 == curveId) || (cid_EC_X448 == curveId))
        {
            status = DIGI_MEMCPY (
                (void *)ctx->pBuffer, (void *)(pPoint), pointLen);
        }
        else
#endif
        {
            status = DIGI_MEMCPY (
                (void *)ctx->pBuffer, (void *)(pPoint + 1), pointLen - 1);
        }
        if (OK != status)
            goto exit;

#ifdef __ENABLE_DIGICERT_PQC__
        if (NULL != pQsCtx)
        {
            /* initiator sends public key, responder sends cipher text encrypted
             * with public key. */
            if (NULL != pxSa)
            {
                if (bInitiator)
                {
                    ubyte *pPubKey = NULL;
                    ubyte4 pubKeyLen;

                    status = CRYPTO_INTERFACE_QS_getPublicKeyAlloc(pQsCtx, &pPubKey, &pubKeyLen);
                    if (OK != status)
                        DBG_EXIT

                    status = DIGI_MEMCPY ((void *) (ctx->pBuffer + pointLen - 1), pPubKey, pubKeyLen);
                    if (OK != status)
                    {
                        DIGI_FREE((void **) &pPubKey);
                        DBG_EXIT
                    }

                    DIGI_FREE((void **) &pPubKey);
                }
                else
                {
                    status = DIGI_MEMCPY ((void *)(ctx->pBuffer + pointLen - 1), pxSa->pQsCipherText,
                        pxSa->qsCipherTextLen);
                    if (OK != status)
                        DBG_EXIT
                }
            }
            else
            {
                if (bInitiator)
                {
                    ubyte *pPubKey = NULL;
                    ubyte4 pubKeyLen;

                    status = CRYPTO_INTERFACE_QS_getPublicKeyAlloc(pQsCtx, &pPubKey, &pubKeyLen);
                    if (OK != status)
                        DBG_EXIT

                    status = DIGI_MEMCPY ((void *) (ctx->pBuffer + pointLen - 1), pPubKey, pubKeyLen);
                    if (OK != status)
                    {
                        DIGI_FREE((void **) &pPubKey);
                        DBG_EXIT
                    }

                    DIGI_FREE((void **) &pPubKey);
                }
                else
                {
                    status = DIGI_MEMCPY ((void *)(ctx->pBuffer + pointLen - 1), pxIPsecSa->pQsCipherText,
                        pxIPsecSa->qsCipherTextLen);
                    if (OK != status)
                        DBG_EXIT
                }
            }
            /* else if ipsecsa? */
        }
#endif
    }
    else
#endif
    {
        status = DIGI_MEMCPY(ctx->pBuffer, keyTemplate.pF,keyTemplate.fLen);
        if(OK != status)
            DBG_EXIT
    }

    /* done */
    OUT_END }

exit:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DH_freeKeyTemplateExt(pDHctx, &keyTemplate, NULL);
#else
    DH_freeKeyTemplate(pDHctx, &keyTemplate);
#endif
#ifdef __ENABLE_DIGICERT_ECC__
    CHECK_FREE(pPoint);
#endif
    return status;
} /* OutKe */


/*------------------------------------------------------------------*/

static MSTATUS
OutNonce(IKE_context ctx)
{
    MSTATUS status;

    IKE2XG pxXg = ctx->pxXg;
    IKESA pxSa = pxXg->pxSa;
    IPSECSA pxIPsecSa = pxXg->pxIPsecSa;

    /* nonce data */
    ubyte *poNonce = (pxSa ? pxSa->nonce : pxIPsecSa->poNonce);

    /* generic header */
    if (OK != (status = OutGen(ctx, IKE_NEXT_NONCE, IKE_NONCE_SIZE, poNonce)))
        goto exit;

exit:
    return status;
} /* OutNonce */


/*------------------------------------------------------------------*/

static MSTATUS
OutId(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    intBoolean bInitiator = IS_INITIATOR(pxSa);

    ubyte oNp = (bInitiator ? IKE_NEXT_ID_I : IKE_NEXT_ID_R);
    sbyte4 dir = (bInitiator ? _I : _R);
    struct ikeIdHdr *pxID;

    sbyte4 idType = 0;
    ubyte2 wBodyLen = 0;
    const ubyte *poIdData = NULL;

    ubyte4 dwHostAddr = 0;
    IKE_certDescr pxCertDesc = NULL;

#if defined(__ENABLE_IKE_MULTI_AUTH__) || \
    (defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__))
    intBoolean bUseCert = TRUE;

#ifdef __ENABLE_IKE_MULTI_AUTH__
    if (IKE_SA_FLAG_MULTI_AUTH & pxSa->flags)
    {
        if (!pxSa->u.v2.oAuthMtd || (AUTH_MTD_SHARED_KEY == pxSa->u.v2.oAuthMtd))
        {
            /* multi auths - this specific auth does not use certificate */
            bUseCert = FALSE;
        }
    }
    else
#endif
    {
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
        if (bInitiator && (IKE_SA_FLAG_EAP & pxSa->flags))
        {
            /* EAP supplicant - do not use certificate */
            bUseCert = FALSE;
        }
#endif
    }

    if (bUseCert)
#endif
    {
        /* get host certificate, if necessary */
        (void) IKE_useCert(ctx, 0);
        pxCertDesc = pxSa->pCertChain;
    }

    if (NULL != (pxID = pxSa->pxID[dir])) /* responder? */
    {
        idType = pxID->oType;
        poIdData = (ubyte *)pxID + SIZEOF_IKE_ID_HDR;
        wBodyLen = GET_NTOHS(pxID->wLength) - (ubyte2)SIZEOF_IKE_ID_HDR;
        goto output;
    }

#ifdef CUSTOM_IKE_GET_ID
    /* get custom host ID */
    if (OK <= CUSTOM_IKE_GET_ID(&poIdData, &wBodyLen, &idType,
                                REF_MOC_IPADDR(pxSa->dwPeerAddr),
                                _OUT /* local */, bInitiator
                                MOC_MTHM_REQ_VALUE(pxSa->serverInstance)))
    {
        if (wBodyLen && poIdData) /* jic */
        {
            goto output;
        }
        DBG_ERRCODE(ERR_IKE_BAD_ID)
    }
#endif

    /* use certificate Subject as ID, if any */
    if (NULL != pxCertDesc)
    {
        wBodyLen = pxCertDesc->wSubjLen;
        poIdData = pxCertDesc->poSubject;
        idType = ID_DER_ASN1_DN;
    }
    else
    {
        /* DEFAULT: IP address ID type */
        INIT_MOC_IPADDR(hostAddr, pxSa->dwHostAddr)
        TEST_MOC_IPADDR6(hostAddr,
        {
            wBodyLen = 16;
            idType = ID_IPV6_ADDR;
            poIdData = GET_MOC_IPADDR6(hostAddr);
        })
        {
            wBodyLen = 4;
            idType = ID_IPV4_ADDR;
            poIdData = NULL; /* jic */
            dwHostAddr = GET_MOC_IPADDR4(hostAddr);
        }
    }

output:
    /* id payload header */
    { OUT_BEGIN(struct ikeIdHdr, pxIdHdr, SIZEOF_IKE_ID_HDR, oNp)

    pxIdHdr->oType = (ubyte)idType;

    /* identification data */
    if (NULL != poIdData)
        DIGI_MEMCPY(ctx->pBuffer, poIdData, wBodyLen);
    else
        SET_HTONL(pxIdHdr->dwIpAddr, dwHostAddr);

    /* store ID payload, if necessary */
    if (NULL == pxID)
    {
        ubyte2 wIdLen = wBodyLen + (ubyte2)SIZEOF_IKE_ID_HDR;

        CHECK_MALLOC_PTR(struct ikeIdHdr, pxID, wIdLen)
        DIGI_MEMCPY(pxID, pxIdHdr, wIdLen);
        pxSa->pxID[dir] = pxID;
    }

    /* done */
    OUT_END }

exit:
    return status;
} /* OutId */


/*------------------------------------------------------------------*/

#ifdef CUSTOM_IKE_GET_ID

static MSTATUS
OutId_R(IKE_context ctx)
{
    /* Note: called from authI_out() only */
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    struct ikeIdHdr *pxID = pxSa->pxID[_R];

    sbyte4 idType = 0;
    ubyte2 wBodyLen = 0;
    const ubyte *poIdData = NULL;

    if (NULL != pxID) /* jic */
    {
        idType = pxID->oType;
        poIdData = (ubyte *)pxID + SIZEOF_IKE_ID_HDR;
        wBodyLen = GET_NTOHS(pxID->wLength) - (ubyte2)SIZEOF_IKE_ID_HDR;
    }
    else
    /* get custom peer ID */
    if ((OK > CUSTOM_IKE_GET_ID(&poIdData, &wBodyLen, &idType,
                                REF_MOC_IPADDR(pxSa->dwPeerAddr),
                                _IN /* remote */, TRUE
                                MOC_MTHM_REQ_VALUE(pxSa->serverInstance)))
        || !wBodyLen || (NULL == poIdData)) /* jic */
    {
        /* none */
        goto exit;
    }

    /* id payload header */
    { OUT_BEGIN(struct ikeIdHdr, pxIdHdr, SIZEOF_IKE_ID_HDR, IKE_NEXT_ID_R)

    pxIdHdr->oType = (ubyte)idType;

    /* identification data */
    DIGI_MEMCPY(ctx->pBuffer, poIdData, wBodyLen);

    /* store ID payload, if necessary */
    if (NULL == pxID)
    {
        ubyte2 wIdLen = wBodyLen + (ubyte2)SIZEOF_IKE_ID_HDR;

        CHECK_MALLOC_PTR(struct ikeIdHdr, pxID, wIdLen)
        DIGI_MEMCPY(pxID, pxIdHdr, wIdLen);
        pxSa->pxID[_R] = pxID;
    }

    /* done */
    OUT_END }

exit:
    return status;
} /* OutId_R */

#endif


/*------------------------------------------------------------------*/

static MSTATUS
OutTs(IKE_context ctx, sbyte4 i)
{
    MSTATUS status = OK;

    IPSECSA pxIPsecSa = ctx->pxXg->pxIPsecSa;
    intBoolean bInitiator = IS_CHILD_INITIATOR(pxIPsecSa);
    struct ikeTsHdr *pxTsHdr = (struct ikeTsHdr *)ctx->pHdrParent;

    {
        sbyte4 id_t;
        ubyte2 wBodyLen;

#ifdef __ENABLE_DIGICERT_IPV6__
        ubyte4 dwIpAddr = 0, dwIpAddrEnd = 0;
        const ubyte *poIpAddr6 = NULL, *poIpAddr6End = NULL;
#else
        #define ipAddr dwIpAddr
        #define ipAddrEnd dwIpAddrEnd
#endif
        INIT_MOC_IPADDR(ipAddr, pxIPsecSa->dwIP[i])
        INIT_MOC_IPADDR(ipAddrEnd, pxIPsecSa->dwIPEnd[i])

        /* IPv6 address range */
        TEST_MOC_IPADDR6(ipAddr,
        {
            poIpAddr6 = GET_MOC_IPADDR6(ipAddr);
            poIpAddr6End = GET_MOC_IPADDR6(ipAddrEnd);
            id_t = ID_IPV6_ADDR_RANGE;
            wBodyLen = 32;
        })

        /* IPv4 address range */
        {
#ifdef __ENABLE_DIGICERT_IPV6__
            dwIpAddr = GET_MOC_IPADDR4(ipAddr);
            dwIpAddrEnd = GET_MOC_IPADDR4(ipAddrEnd);
#endif
            id_t = TS_IPV4_ADDR_RANGE;
            wBodyLen = 8;
        }

        /* Traffic Selector */
        { OUT_HDR(struct ikeTS, pxTs, SIZEOF_IKE_TS)

        if (ctx->dwBufferSize < wBodyLen)
        {
            status = ERR_IKE_BUFFER_OVERFLOW;
            DBG_EXIT
        }
        SET_HTONS(pxTs->wLength, SIZEOF_IKE_TS + wBodyLen);

        pxTs->oType = (ubyte)id_t;
        pxTs->oProtocol = pxIPsecSa->oUlp;

        SET_HTONS(pxTs->wPort, pxIPsecSa->wPort[i]);
        SET_HTONS(pxTs->wPortEnd, pxIPsecSa->wPortEnd[i]);

        /* IP address range */
#ifdef __ENABLE_DIGICERT_IPV6__
        if (poIpAddr6)
        {
            DIGI_MEMCPY(ctx->pBuffer, poIpAddr6, 16);
            DIGI_MEMCPY(ctx->pBuffer + 16, poIpAddr6End, 16);
        }
        else
#endif
        {
            SET_HTONL(pxTs->dwIpAddr, dwIpAddr);
            SET_HTONL(pxTs->dwIpAddrEnd, dwIpAddrEnd);
        }

        if (bInitiator)
            debug_print_ike2_ts((ubyte *)pxTs, (0==i));

        /* done */
        ADVANCE(wBodyLen) }

#ifndef __ENABLE_DIGICERT_IPV6__
        #undef ipAddr
        #undef ipAddrEnd
#endif
        ++(pxTsHdr->oTsLen);
    }

exit:
    return status;
} /* OutTs */


/*------------------------------------------------------------------*/

static MSTATUS
OutTSir(IKE_context ctx)
{
    MSTATUS status = OK;

    sbyte4 i;

    if (!ctx->pxXg->pxIPsecSa) goto exit;

    for (i=0; i < 2; i++)
    {
        ubyte oNp = (i ? IKE_NEXT_TS_R : IKE_NEXT_TS_I);

        /* TS payload header */
        OUT_TOP(struct ikeTsHdr, pxTsHdr, SIZEOF_IKE_TS_HDR, oNp)

        /* go to Traffic Selctor(s) */
        OUT_DOWN(pxTsHdr)

        if (OK > (status = OutTs(ctx, i)))
            goto exit;

        OUT_UP(pxTsHdr)
    } /* for */

exit:
    return status;
} /* OutTSir */


/*------------------------------------------------------------------*/

static MSTATUS
matchTrustAnchor(MOC_ASYM(hwAccelDescr hwAccelCtx) const void *arg, const ubyte *testCert, ubyte4 testCertLen)
{
    MSTATUS status;
    IKE_context ctx = (IKE_context)arg;

    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pxRoot = NULL, pxSubj, pxPKI;

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    ubyte *poKIHash = NULL;
    #define poKeyInfoHash poKIHash
#else
    ubyte poKeyInfoHash[SHA1_RESULT_SIZE];
#endif
    ubyte4 keyInfoLen;
    ubyte *poKeyInfo;

    /* Certification Authority value is a concatenated list of SHA-1 hashes of
       the public keys of trusted Certification Authorities (CAs).  Each is
       encoded as the SHA-1 hash of the Subject Public Key Info element from
       each Trust Anchor certificate..
     */
    if (ctx->dwBufferSize < SHA1_RESULT_SIZE)
    {
        status = ERR_IKE_BUFFER_OVERFLOW;
        DBG_EXIT
    }

    /* get TA's Subject Public Key Info */
    MF_attach(&mf, testCertLen, (ubyte *)testCert);
    CS_AttachMemFile(&cs, &mf);

    if (OK > (status = X509_parseCertificate(cs, &pxRoot)))
        DBG_EXIT

    if (OK > (status = X509_getCertificateSubject(ASN1_FIRST_CHILD(pxRoot), &pxSubj)))
        DBG_EXIT

    pxPKI = ASN1_NEXT_SIBLING(pxSubj);
    keyInfoLen = pxPKI->length + pxPKI->headerSize;
    poKeyInfo = (ubyte *)testCert + (pxPKI->dataOffset - pxPKI->headerSize);

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    if (OK > (status = CRYPTO_ALLOC(ctx->hwAccelCookie, SHA1_RESULT_SIZE,
                                    TRUE, (void**) &poKIHash)))
        DBG_EXIT
#endif
    if (OK > (status = SHA1_completeDigest(MOC_HASH(ctx->hwAccelCookie)
                                           poKeyInfo, keyInfoLen,
                                           poKeyInfoHash)))
        DBG_EXIT

    /* certificate authority */
    DIGI_MEMCPY(ctx->pBuffer, poKeyInfoHash, SHA1_RESULT_SIZE);
    ADVANCE(SHA1_RESULT_SIZE)

    status = ERR_FALSE; /* go to next TA!!! */

exit:
    if (NULL != pxRoot)
        TREE_DeleteTreeItem((TreeItem *)pxRoot);

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    if (NULL != poKIHash)
        CRYPTO_FREE(ctx->hwAccelCookie, TRUE, (void**) &poKIHash);
#endif
    return status;
} /* matchTrustAnchor */


/*------------------------------------------------------------------*/

static MSTATUS
OutCr(IKE_context ctx)
{
    MSTATUS status = OK;

    certStorePtr pCertStore;
    ubyte2 wBodyLen = 0;

#ifdef __ENABLE_IKE_OCSP_EXT__
    ocspSettings *pOcspSettings;
    OCSP_certInfo *pTrustedResponder;

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    ubyte *poKIHash = NULL;
    //#define poKeyInfoHash poKIHash
#else
    ubyte poKeyInfoHash[SHA1_RESULT_SIZE];
#endif
    ASN1_ITEMPTR pxRoot = NULL;
#endif

    if (OK > IKE_getCertAuth(ctx, 0))
    {
        /* do not accept certificate */
        goto exit;
    }

    if (OK <= IKE_certLookup(ctx, NULL, NULL))
    {
        /* certificate cached */
        goto exit;
    }

    { /* CERTREQ payload w/ hashes of CA KeyInfo */
    OUT_BEGIN(struct ikeCRHdr, pxCRHdr, SIZEOF_IKE_CR_HDR, IKE_NEXT_CERTREQ)
    pxCRHdr->oType = CERT_X509_SIGNATURE;

    if (NULL != (pCertStore = ctx->pxSa->ikePeerConfig->ikeCertStore))
    {
        ubyte4 dwLength = ctx->dwLength;

        if (OK > (status = CERT_STORE_traverseTrustPoints(MOC_ASYM(ctx->hwAccelCookie)
                                                          pCertStore, ctx,
                                                          matchTrustAnchor)))
        {
            DBG_EXIT
        }

        wBodyLen = (ubyte2)(ctx->dwLength - dwLength);
        if (wBodyLen)
        {
            SET_HTONS(pxCRHdr->wLength, SIZEOF_IKE_CR_HDR + wBodyLen);
        }
    }
    }

#ifdef __ENABLE_IKE_OCSP_EXT__
    if (!ctx->pxSa->ikePeerConfig->bNoIkeOcsp)
    {
        sbyte i;
        ubyte *pBuffer;

        if (NULL != (pOcspSettings = ctx->pxSa->ikePeerConfig->pOcspSettings) &&
            NULL != (pTrustedResponder = pOcspSettings->pTrustedResponders))
        {
            wBodyLen = (ubyte2)(SHA1_RESULT_SIZE * pOcspSettings->trustedResponderCount);
        }
        else wBodyLen = 0;

        { /* OCSP request CERTREQ payload */
        OUT_BEGIN(struct ikeCRHdr, pxCRHdr, SIZEOF_IKE_CR_HDR, IKE_NEXT_CERTREQ)
        pxCRHdr->oType = CERT_OCSP_CONTENT;

        /* concatenate hashes of trusted responder certificates' public keys */
        if (wBodyLen)
        for (pBuffer = ctx->pBuffer,
             i = pOcspSettings->trustedResponderCount; i; i--,
             pBuffer += SHA1_RESULT_SIZE, pTrustedResponder++)
        {
            /* get hash of configured trusted responder's public key */
            MemFile mf;
            CStream cs;
            ASN1_ITEMPTR pxSubj, pxPKI;
            ubyte4 keyInfoLen;
            ubyte *poKeyInfo;

            if (NULL == pTrustedResponder->pCertPath)
            {
                status = ERR_OCSP_INIT_FAIL;
                goto exit;
            }

            MF_attach(&mf, pTrustedResponder->certLen, pTrustedResponder->pCertPath);
            CS_AttachMemFile(&cs, &mf);

            if (OK > (status = X509_parseCertificate(cs, &pxRoot)) ||
                OK > (status = X509_getCertificateSubject(ASN1_FIRST_CHILD(pxRoot), &pxSubj)))
                goto exit;

            pxPKI = ASN1_NEXT_SIBLING(pxSubj);
            keyInfoLen = pxPKI->length + pxPKI->headerSize;
            poKeyInfo = pTrustedResponder->pCertPath + (pxPKI->dataOffset - pxPKI->headerSize);

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
            if (OK > (status = CRYPTO_ALLOC(ctx->hwAccelCookie, SHA1_RESULT_SIZE,
                                            TRUE, (void**) &poKIHash)))
                goto exit;
#endif
            if (OK > (status = SHA1_completeDigest(MOC_HASH(ctx->hwAccelCookie)
                                                   poKeyInfo, keyInfoLen,
                                                   poKeyInfoHash)))
                goto exit;

            DIGI_MEMCPY(pBuffer, poKeyInfoHash, SHA1_RESULT_SIZE);
        }

        OUT_END }
    }
#endif /* __ENABLE_IKE_OCSP_EXT__ */

exit:
#ifdef __ENABLE_IKE_OCSP_EXT__
    if (pxRoot)
        TREE_DeleteTreeItem((TreeItem *)pxRoot);

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    if (poKIHash)
        CRYPTO_FREE(ctx->hwAccelCookie, TRUE, (void**) &poKIHash);
#endif
#endif
    return status;
} /* OutCr */


/*------------------------------------------------------------------*/

static MSTATUS
OutCert(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    sbyte4 certNum = pxSa->certChainLen;
    IKE_certDescr pxCertDesc = pxSa->pCertChain;

#ifdef __ENABLE_IKE_OCSP_EXT__
    ubyte *pResponse = NULL;

    if (!(IKE_SA_FLAG_CR_OCSP & pxSa->flags))
#endif
    if (!(IKE_SA_FLAG_CR & pxSa->flags))
        goto exit; /* certificate not requested */

    if (NULL == pxCertDesc) /* no certificate */
        goto exit;

    for (; 0 < certNum; certNum--, pxCertDesc++)
    {
        ubyte *poCertificate = pxCertDesc->poCertificate;
        ubyte2 wBodyLen = pxCertDesc->wCertLen;

        /* certificate payload header */
        OUT_BEGIN(struct ikeCertHdr, pxCertHdr, SIZEOF_IKE_CERT_HDR, IKE_NEXT_CERT)

        pxCertHdr->oEncoding = CERT_X509_SIGNATURE;

        /* certificate data */
        DIGI_MEMCPY(ctx->pBuffer, poCertificate, wBodyLen);

        /* done */
        OUT_END
    }

#ifdef __ENABLE_IKE_OCSP_EXT__
    if (IKE_SA_FLAG_CR_OCSP & pxSa->flags)
    {
        ubyte2 wBodyLen;

        /* Method handling transport over HTTP and providing raw OCSP response */
        if (OK > (status = IKE_ocspGetResponse(ctx)))
        {
            DBG_STATUS
            status = OK; /* !!! */
            goto exit;
        }
        pResponse = ctx->pOcspResp;
        wBodyLen = ctx->ocspRespLen;

        /* TODO: Add code to check status and indicate to the app in case it is not GOOD */

        if (pResponse && wBodyLen)
        {
            OUT_BEGIN(struct ikeCertHdr, pxCertHdr, SIZEOF_IKE_CERT_HDR, IKE_NEXT_CERT)

            pxCertHdr->oEncoding = CERT_OCSP_CONTENT;

            DIGI_MEMCPY(ctx->pBuffer, pResponse, wBodyLen);

            OUT_END
        }
    }
#endif

exit:
#ifdef __ENABLE_IKE_OCSP_EXT__
    if (pResponse) FREE(pResponse);
#endif
    return status;
} /* OutCert */


/*------------------------------------------------------------------*/

static MSTATUS
OutNotifySa2(IKE_context ctx)
{
    MSTATUS status = OK;

    IPSECSA pxIPsecSa = ctx->pxXg->pxIPsecSa;
#ifdef __ENABLE_DIGICERT_IPCOMP__
    intBoolean bInitiator;
#endif
    ubyte oSalen;
    sbyte4 i;

    if (NULL == pxIPsecSa) goto exit;

    oSalen = pxIPsecSa->axP2Sa[0].oChildSaLen;

#ifdef __ENABLE_DIGICERT_IPCOMP__
    bInitiator = IS_CHILD_INITIATOR(pxIPsecSa);

    /* IPCOMP_SUPPORTED */
    if (bInitiator)
    {
        /* get CPI; see RFC3173 3.3. */
        ubyte2 wCpi;
        do
        {
            if (OK > (status = RANDOM_numberGenerator(g_pRandomContext,
                                                      (ubyte *) &wCpi,
                                                      sizeof(ubyte2))))
            {
                DBG_EXIT
            }
        } while (((ubyte2)256 > wCpi) || ((ubyte2)61439 < wCpi));

        for (i=0; ; i++)
        {
            CHILDSA_compInfo *pCompAlgo = CHILDSA_getCompAlgo(i);
            if (NULL != pCompAlgo)
            {
                /* see RFC4306 2.22. & 3.10.1. on page 69 */
                ubyte oTfmId = pCompAlgo->oTfmId;
                ubyte2 wBodyLen = sizeof(ubyte2) + sizeof(ubyte);

                /* notify payload header */
                OUT_BEGIN(struct ike2NotifyHdr, pxNotifyHdr, SIZEOF_IKE2_NOTIFY_HDR, IKE_NEXT_N)
                SET_HTONS(pxNotifyHdr->wMsgType, IPCOMP_SUPPORTED);

                //pxNotifyHdr->oSpiSize = sizeof(ubyte2);
                //pxNotifyHdr->oProtoId = PROTO_IPCOMP;

                DIGI_HTONS(ctx->pBuffer, wCpi);
                ctx->pBuffer[2] = oTfmId;

                debug_print("   Notify: ");
                debug_print_ike2_notify(IPCOMP_SUPPORTED);
                debug_printnl(NULL);

                debug_print("    CPI=");
                debug_int(wCpi);
                debug_print(" ");
                debug_print_ike_tfmid(oTfmId, PROTO_IPCOMP);
                debug_printnl(NULL);

                OUT_END
            }
            else break;
        }

        if (0 < i) /* compression algorithms supported */
        {
            for (i=0; i < oSalen; i++)
            {
                IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[0].axChildSa[i].ipsecPps);
                pxIPsecPps->wCpi[_I] = wCpi;
            }
        }
    }
    else /* responder */
    {
        IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[0].axChildSa[0].ipsecPps);

        if (pxIPsecPps->oCompAlgo) /* compression algo negotiated */
        {
            ubyte2 wCpi = pxIPsecPps->wCpi[_R];
            ubyte oTfmId = pxIPsecPps->oCompAlgo;
            ubyte2 wBodyLen = sizeof(ubyte2) + sizeof(ubyte);

            OUT_BEGIN(struct ike2NotifyHdr, pxNotifyHdr, SIZEOF_IKE2_NOTIFY_HDR, IKE_NEXT_N)
            SET_HTONS(pxNotifyHdr->wMsgType, IPCOMP_SUPPORTED);

            DIGI_HTONS(ctx->pBuffer, wCpi);
            ctx->pBuffer[2] = oTfmId;

            debug_print("   Notify: ");
            debug_print_ike2_notify(IPCOMP_SUPPORTED);
            debug_printnl(NULL);

            debug_print("    CPI=");
            debug_int(wCpi);
            debug_print(" ");
            debug_print_ike_tfmid(oTfmId, PROTO_IPCOMP);
            debug_printnl(NULL);

            OUT_END
        }
    }
#endif /* __ENABLE_DIGICERT_IPCOMP__ */

    /* USE_TRANSPORT_MODE */
    for (i = (sbyte4)oSalen - 1; i >= 0; i--)
    {
        IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[0].axChildSa[i].ipsecPps);

        if (ENCAPSULATION_MODE_TRANSPORT == pxIPsecPps->wMode)
        {
            ubyte2 wBodyLen = 0;
            /* notify payload header */
            OUT_BEGIN(struct ike2NotifyHdr, pxNotifyHdr, SIZEOF_IKE2_NOTIFY_HDR, IKE_NEXT_N)
            SET_HTONS(pxNotifyHdr->wMsgType, USE_TRANSPORT_MODE);

            debug_print("   Notify: ");
            debug_print_ike2_notify(USE_TRANSPORT_MODE);
            debug_printnl(NULL);

            /* done */
            OUT_END
                break;
        }
    }

exit:
    return status;
} /* OutNotifySa2 */


/*------------------------------------------------------------------*/

static MSTATUS
OutInfo(IKE_context ctx)
{
    MSTATUS status = OK;

    ubyte2 wMsgType = ctx->wMsgType;

    IKESA pxSa = ctx->pxSa;
    IKE2XG pxXg = ctx->pxXg;
    IKEINFO pxInfo = (pxXg ? pxXg->pxInfo : NULL);
    IKEINFO_notify pxNotify = (pxInfo ? pxInfo->pxNotify : NULL);
    IKEINFO_delete pxDelete = (pxInfo ? pxInfo->pxDelete : NULL);

    if (wMsgType)
    {
        IPSECSA pxIPsecSa = NULL;

        ubyte4 dwSpi = 0;
        ubyte oSpiSize = 0;
        ubyte oProtoId = 0;
        ubyte2 wBodyLen = 0;

        if (NULL != pxXg)
        {
            if (NULL != pxXg->pxSa)
            {
                oProtoId = PROTO_ISAKMP;
            }
            else if (NULL != (pxIPsecSa = pxXg->pxIPsecSa))
            {
                IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[0].axChildSa[0].ipsecPps);
                if (0 != (oProtoId = pxIPsecPps->oProtocol))
                {
                    if (0 != (dwSpi = pxIPsecPps->dwSpi[_I]))
                    {
                        wBodyLen = oSpiSize = sizeof(ubyte4);
                    }
                }
            }
        }
        else if (NULL != pxSa) /* RFC4306 3.10 */
        {
            oProtoId = PROTO_ISAKMP;
        }

        switch (wMsgType)
        {
        case INITIAL_CONTACT :
#if defined(__ENABLE_IKE_EAP_ONLY__) && defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
        case EAP_ONLY_AUTHENTICATION :
#endif
#ifdef __ENABLE_IKE_FRAGMENTATION__
        case IKEV2_FRAGMENTATION_SUPPORTED :
#endif
#ifdef __ENABLE_IKE_PPK_RFC8784__
        case USE_PPK :
#endif
#ifdef __ENABLE_IKE_MULTI_AUTH__
        case MULTIPLE_AUTH_SUPPORTED :
        case ANOTHER_AUTH_FOLLOWS :
#endif
            dwSpi = wBodyLen = oProtoId = oSpiSize = 0;
            break;
        case NOTIFY_COOKIE :
            wBodyLen = sizeof(ubyte4) + MD5_DIGESTSIZE;
            dwSpi = oSpiSize = 0; /* jic */
            break;
#ifdef __ENABLE_IKE_PPK_RFC8784__
        case PPK_IDENTITY :
            if (NULL == pxSa) /* jic */
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }
            dwSpi = oProtoId = oSpiSize = 0;
            wBodyLen = pxSa->ikePeerConfig->ppkid_len+1;
            break;
#endif
        case INVALID_KE_PAYLOAD :
            wBodyLen = wBodyLen + (ubyte2)sizeof(ubyte2);
            break;
        case AUTH_LIFETIME :
            oProtoId = oSpiSize = 0;
            wBodyLen = (ubyte2)sizeof(ubyte4);
            break;
#ifdef __ENABLE_MOBIKE__
        case UNACCEPTABLE_ADDRESSES :
        case UNEXPECTED_NAT_DETECTED :
        case MOBIKE_SUPPORTED :
        case NO_ADDITIONAL_ADDRESSES :
        case UPDATE_SA_ADDRESSES :
            wBodyLen = oProtoId = oSpiSize = 0;
            break;
        case NO_NATS_ALLOWED :
            if (NULL == pxSa) /* jic */
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }
            IF_MOC_IPADDR6(pxSa->dwHostAddr, {
                wBodyLen = SIZEOF_IKE_NNA6_DATA; /* 36==(16*2 + sizeof(ubyte2)*2) */
            })
                wBodyLen = SIZEOF_IKE_NNA_DATA; /* 12==(sizeof(ubyte4)*2 + sizeof(ubyte2)*2) */
            oProtoId = oSpiSize = 0;
            break;
#endif
#ifdef __ENABLE_IKE_REDIRECT__
        case REDIRECT_SUPPORTED :
            dwSpi = wBodyLen = oSpiSize = oProtoId = 0;
            break;

        case REDIRECT :
            if (NULL == pxSa) /* jic */
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }
            dwSpi = oSpiSize = oProtoId = 0;
            IF_MOC_IPADDR6(m_ikeSettings.redirectGwAddr,
            {
                wBodyLen  = 18;
            })
            {
                wBodyLen  = 6;
            }
            if (IKE_XCHG_INFO != pxXg->oExchange)
            {
                wBodyLen += pxSa->wNonceLen[_I];
            }
            break;

        case REDIRECTED_FROM :
            dwSpi = oSpiSize = oProtoId = 0;
            IF_MOC_IPADDR6(ctx->oldPeerAddr,
            {
                wBodyLen  = 18;
            })
            {
                wBodyLen  = 6;
            }
            break;
#endif
#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
        case SIGNATURE_HASH_ALGORITHMS :
        {
            sbyte4 i;
            if (NULL == pxSa) /* jic */
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

            for (i=0, wBodyLen=0; ; i++)
            {
                IKE_hashSuiteInfo *pHashSuite = IKE_getHashSuiteEx(pxSa->ikePeerConfig, i);
                if (!pHashSuite) break;
                if (pHashSuite->wSigHash) wBodyLen += (ubyte2)sizeof(ubyte2);
            }

            if (!wBodyLen) /* jic */
            {
                pxSa->u.v2.numSahAlgos = 0; /* !!! */
                goto exit;
            }

            oProtoId = oSpiSize = 0;
            break;
        }
#endif
        default :
            break;
        }

        {
        /* notify payload header */
        OUT_BEGIN(struct ike2NotifyHdr, pxNotifyHdr, SIZEOF_IKE2_NOTIFY_HDR, IKE_NEXT_N)

        if (NULL == pxNotifyHdr) /* jic */
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }
        pxNotifyHdr->oProtoId = oProtoId;
        pxNotifyHdr->oSpiSize = oSpiSize;
        SET_HTONS(pxNotifyHdr->wMsgType, wMsgType);

        debug_print("   Notify: ");
        debug_print_ike2_notify(wMsgType);
        if (oProtoId)
        {
            debug_print(" (");
            debug_print_ike_proto(oProtoId);
            if (dwSpi)
            {
                SET_HTONL(pxNotifyHdr->dwValue, dwSpi);
                debug_print(" spi=");
                debug_hexint(dwSpi);
            }
            debug_print(")");
        }
        debug_printnl(NULL);

        /* notify data */
        switch (wMsgType)
        {
        case NOTIFY_COOKIE :
            DIGI_HTONL(ctx->pBuffer, g_ikeScrtVerID);
            if (ctx->u.v2.poCookie) /* jic */
            DIGI_MEMCPY(ctx->pBuffer + sizeof(ubyte4), ctx->u.v2.poCookie, MD5_DIGESTSIZE);
            break;
#ifdef __ENABLE_IKE_PPK_RFC8784__
        case PPK_IDENTITY :
            ctx->pBuffer[0] = 0x02; /* PPK_ID_FIXED */
            DIGI_MEMCPY(&(ctx->pBuffer[1]), pxSa->ikePeerConfig->ppk_id, pxSa->ikePeerConfig->ppkid_len);
            break;
#endif
        case INVALID_KE_PAYLOAD :
            if (pxXg)
            {
                if (pxXg->pxSa)
                {
                    DIGI_HTONS(ctx->pBuffer + oSpiSize, pxXg->pxSa->wDhGrp);
                }
                else if (pxXg->pxIPsecSa)
                {
                    DIGI_HTONS(ctx->pBuffer + oSpiSize, pxXg->pxIPsecSa->wPFS);
                }
                else /* jic */
                {
                    debug_printnl("    OutInfo() Invalid_KE_Payload; pxXg->pxSa and pxXg->pxIPsecSa are NULL");
                    status = ERR_NULL_POINTER;
                    goto exit;
                }
            }
            else
            {
                if (NULL == pxSa) /* jic */
                {
                    debug_printnl("    OutInfo() Invalid_KE_Payload, null pxSa");
                    status = ERR_NULL_POINTER;
                    goto exit;
                }
                DIGI_HTONS(ctx->pBuffer + oSpiSize, pxSa->wDhGrp); /* SA_INIT (responder) */
            }
            break;
        case AUTH_LIFETIME :
            if ((NULL == pxNotifyHdr) || (NULL == pxSa)) /* jic */
            {
                debug_printnl("    OutInfo() AUTH_LIFETIME, null pxNotifyHdr or pxSa");
                status = ERR_NULL_POINTER;
                goto exit;
            }
            SET_HTONL(pxNotifyHdr->dwValue, pxSa->u.v2.dwExpAuthSecs);
            break;
#ifdef __ENABLE_MOBIKE__
        case NO_NATS_ALLOWED :
        {
            if (NULL == pxXg) /* jic */
            {
                debug_printnl("    OutInfo() NO_NATS_ALLOWED, null pxXg");
                status = ERR_NULL_POINTER;
                goto exit;
            }
            MOC_IP_ADDRESS srcAddr = REF_MOC_IPADDR(pxSa->dwHostAddr);
            MOC_IP_ADDRESS dstAddr = REF_MOC_IPADDR(pxSa->dwPeerAddr);

            if (ctx->peerAddr && (IKE_XCHG_FLAG_COOKIE2 & pxXg->x_flags))
                dstAddr = ctx->peerAddr; /* use new peer addr */

            TEST_MOC_IPADDR6(srcAddr,
            {
                struct ikeNoNatsA6 *pxNna6 = (struct ikeNoNatsA6 *) ctx->pBuffer;
                DIGI_MEMCPY(pxNna6->srcAddr, GET_MOC_IPADDR6(srcAddr), 16);
                DIGI_MEMCPY(pxNna6->dstAddr, GET_MOC_IPADDR6(dstAddr), 16);
                SET_HTONS(pxNna6->wSrcPort, pxSa->wHostPort);
                SET_HTONS(pxNna6->wDstPort, pxSa->wPeerPort);
            })
            {
                struct ikeNoNatsA *pxNna = (struct ikeNoNatsA *) ctx->pBuffer;
                SET_HTONL(pxNna->dwSrcAddr, GET_MOC_IPADDR4(srcAddr));
                SET_HTONL(pxNna->dwDstAddr, GET_MOC_IPADDR4(dstAddr));
                SET_HTONS(pxNna->wSrcPort, pxSa->wHostPort);
                SET_HTONS(pxNna->wDstPort, pxSa->wPeerPort);
            }
            break;
        }
        case UPDATE_SA_ADDRESSES :
#ifdef __ENABLE_IPSEC_NAT_T__
            if (NULL == pxSa) /* jic */
            {
                debug_printnl("    OutInfo() UPDATE_SA_ADDRESSES, null pxSa");
                status = ERR_NULL_POINTER;
                goto exit;
            }
            if (!(IKE_NATT_FLAG_D & pxSa->natt_flags) ||
                (IKE_NATT_FLAG_NOT_ALLOWED & pxSa->natt_flags))
#endif
            {
                OUT_END
                ctx->wMsgType = NO_NATS_ALLOWED; /* !!! */
                status = OutInfo(ctx);
                goto exit;
            }
            break;
#endif /* __ENABLE_MOBIKE__ */

#ifdef __ENABLE_IKE_REDIRECT__
        case REDIRECT :
            IF_MOC_IPADDR6(m_ikeSettings.redirectGwAddr,
            {
                *(ctx->pBuffer) = REDIRECT_GW_TYPE_IPV6;
                *(ctx->pBuffer + 1) = 16;
                DIGI_MEMCPY((ctx->pBuffer + 2),
                           GET_MOC_IPADDR6(REF_MOC_IPADDR(m_ikeSettings.redirectGwAddr)),
                           16);
                if (IKE_XCHG_INFO != pxXg->oExchange)
                    DIGI_MEMCPY((ctx->pBuffer + 18), pxSa->poNonce[_I], pxSa->wNonceLen[_I]);
            })
            {
                *(ctx->pBuffer) = REDIRECT_GW_TYPE_IPV4;
                *(ctx->pBuffer + 1) = 4;
                DIGI_HTONL((ctx->pBuffer + 2),
                          GET_MOC_IPADDR4(REF_MOC_IPADDR(m_ikeSettings.redirectGwAddr)));
                if (IKE_XCHG_INFO != pxXg->oExchange)
                    DIGI_MEMCPY((ctx->pBuffer + 6), pxSa->poNonce[_I], pxSa->wNonceLen[_I]);
            }
            break;

        case REDIRECTED_FROM :
            IF_MOC_IPADDR6(ctx->oldPeerAddr,
            {
                *(ctx->pBuffer) = REDIRECT_GW_TYPE_IPV6;
                *(ctx->pBuffer + 1) = 16;
                DIGI_MEMCPY((ctx->pBuffer + 2),
                           GET_MOC_IPADDR6(REF_MOC_IPADDR(ctx->oldPeerAddr)),
                           16);
            })
            {
                *(ctx->pBuffer) = REDIRECT_GW_TYPE_IPV4;
                *(ctx->pBuffer + 1) = 4;
                DIGI_HTONL((ctx->pBuffer + 2),
                          GET_MOC_IPADDR4(REF_MOC_IPADDR(ctx->oldPeerAddr)));
            }
            break;
#endif /* __ENABLE_IKE_REDIRECT__ */

#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
        case SIGNATURE_HASH_ALGORITHMS :
        {
            sbyte4 i, j;
            for (i=0, j=0; ; i++)
            {
                ubyte2 wSigHash;
                IKE_hashSuiteInfo *pHashSuite = IKE_getHashSuiteEx(pxSa->ikePeerConfig, i);
                if (!pHashSuite) break;

                if (0 != (wSigHash = pHashSuite->wSigHash))
                {
                    DIGI_HTONS(ctx->pBuffer + (j * sizeof(ubyte2)), wSigHash);
                    j++;
                }
            }
            break;
        }
#endif
        default :
            break;
        }

        /* done */
        OUT_END
        }
    }

    for (; NULL != pxNotify; pxNotify = pxNotify->next)
    {
        ubyte4 dwSpi = pxNotify->dwSpi;
        ubyte oSpiSize  = (ubyte)(dwSpi ? sizeof(ubyte4) : 0);
        ubyte2 wBodyLen = (ubyte2)oSpiSize + pxNotify->wDataLen;

        /* notify payload header */
        OUT_BEGIN(struct ike2NotifyHdr, pxNotifyHdr, SIZEOF_IKE2_NOTIFY_HDR, IKE_NEXT_N)

        pxNotifyHdr->oProtoId = pxNotify->oProtoId;
        pxNotifyHdr->oSpiSize = oSpiSize;
        SET_HTONS(pxNotifyHdr->wMsgType, pxNotify->wMsgType);

        debug_print("   Notify: ");
        debug_print_ike2_notify(pxNotify->wMsgType);
        debug_print(" (");
        debug_print_ike_proto(pxNotify->oProtoId);

        /* SPI */
        if (dwSpi)
        {
            SET_HTONL(pxNotifyHdr->dwValue, dwSpi);
            debug_print(" spi=");
            debug_hexint(dwSpi);
        }

        debug_printnl(")");

        /* notify data */
        if ((0 != pxNotify->wDataLen) && (NULL != pxNotify->poData))
            DIGI_MEMCPY(ctx->pBuffer + oSpiSize, pxNotify->poData, pxNotify->wDataLen);

        /* done */
        OUT_END
    }

    for (; NULL != pxDelete; pxDelete = pxDelete->next)
    {
        ubyte4 dwSpi = pxDelete->dwSpi;
        ubyte oSpiSize = (ubyte)(dwSpi ? sizeof(ubyte4) : 0);
        ubyte2 wBodyLen = oSpiSize;

        /* delete payload header */
        OUT_BEGIN(struct ike2DelHdr, pxDelHdr, SIZEOF_IKE2_DEL_HDR, IKE_NEXT_D)

        pxDelHdr->oProtoId = pxDelete->oProtoId;
        if (dwSpi)
        {
            pxDelHdr->oSpiSize = oSpiSize;
            SET_HTONS(pxDelHdr->wSpiLen, 1);
        }
        debug_print3(
            "   Deleted: 1 ",
            ((PROTO_ISAKMP == pxDelHdr->oProtoId) ? "IKE_" : "IPsec "),
            "SA");

        /* SPI */
        if (dwSpi)
        {
            SET_HTONL(pxDelHdr->adwSpi[0], dwSpi);

            debug_print("    IPSEC_delSa(");
            debug_print_ike_proto(pxDelHdr->oProtoId);
            debug_print(" spi=");
            debug_hexint(dwSpi);
            debug_print(" src=");
            debug_print_ip(REF_MOC_IPADDR(pxSa->dwPeerAddr));
            debug_printnl(")");
        }
        else
        {
            debug_print("    IKE2_delSa(peer=");
            debug_print_ip(REF_MOC_IPADDR(pxSa->dwPeerAddr));
            debug_print(" cookies={");
            debug_printr(pxSa->poCky_I, IKE_COOKIE_SIZE, FALSE);
            debug_print(" ");
            debug_printr(pxSa->poCky_R, IKE_COOKIE_SIZE, FALSE);
            debug_printnl("})");
        }

        /* done */
        OUT_END
    }

exit:
    return status;
} /* OutInfo */


#ifdef __ENABLE_IKE_CP__

/*------------------------------------------------------------------*/

static MSTATUS
OutCp(IKE_context ctx)
{
    MSTATUS status = OK;

    IKE2XG pxXg = ctx->pxXg;
    ubyte *poCfgAttrs;

    if ((NULL != pxXg) && /* !!! */
        (NULL != (poCfgAttrs = pxXg->poCfgAttrs)))
    {
        ubyte oCfgType = pxXg->oCfgType;
        ubyte2 wBodyLen = pxXg->wCfgAttrsLen;

        /* Configuration Payload header */
        OUT_BEGIN(struct ikeCfgHdr, pxCfgHdr, SIZEOF_IKE_CFG_HDR, IKE_NEXT_CP)

        pxCfgHdr->oType = oCfgType;
        DIGI_MEMCPY(ctx->pBuffer, poCfgAttrs, wBodyLen);

        /* done */
        OUT_END

        debug_print("   ");
        debug_print_ike_cfgtype(oCfgType);
        debug_printnl(NULL);
        debug_print_ike_cfg_attrs(poCfgAttrs, wBodyLen, (sbyte *)"    ", FALSE);
    }

exit:
    return status;
} /* OutCp */


/*------------------------------------------------------------------*/

static MSTATUS
DoInitCfg(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    IKE2XG pxXg = ctx->pxXg;

    ubyte oCfgType = 0;
    ubyte2 wCfgLen = 0;
    ubyte *poCfg = NULL;

    if (!(IKE_CHILD_FLAG_CONNECT2 & pxXg->pxIPsecSa->c_flags))
        goto exit;

    if (NULL == m_ikeSettings.funcPtrIkeInitCfg)
        goto exit;

    if (OK > m_ikeSettings.funcPtrIkeInitCfg(&poCfg, &wCfgLen, &oCfgType, 0,
                                             pxSa->dwId, pxSa))
        goto exit;

    if ((NULL == poCfg) || (0 == wCfgLen)) /* jic */
        goto exit;

    if (CFG_REQUEST != oCfgType) /* !!! */
    {
        status = ERR_IKE_CONFIG;
        DBG_EXIT
    }

    /* save configuration request */
    CHECK_MALLOC(pxXg->poCfgAttrs, wCfgLen)
    DIGI_MEMCPY(pxXg->poCfgAttrs, poCfg, wCfgLen);
    pxXg->wCfgAttrsLen = wCfgLen;
    pxXg->oCfgType = oCfgType;

    status = OutCp(ctx);

exit:
    if (poCfg && m_ikeSettings.funcPtrIkeReleaseCfg)
        m_ikeSettings.funcPtrIkeReleaseCfg(poCfg);

    return status;
} /* DoInitCfg */

#endif /* __ENABLE_IKE_CP__ */


/*------------------------------------------------------------------*/

extern sbyte4
IKE_checkGroup(ubyte2 wGroup, intBoolean bInitiator,
               IKESA pxSa0, IKESA pxSa, IPSECSA pxIPsecSa)
{
    sbyte4 bad = 0;

#if defined(CUSTOM_IKE_GET_P1_DHGRP) || defined(CUSTOM_IKE_GET_P2_PFS)
    sbyte4 i;

    if (NULL != pxSa)
    {
        if (0 < pxSa->numDhGrps)
        {
            for (i = pxSa->numDhGrps - 1; 0 <= i; i--)
                if (wGroup == pxSa->pwDhGrps[i]) break;

            if (0 > i) bad = ((pxSa0 == pxSa) ? 3 : 4);
            goto exit;
        }
    }
#ifdef CUSTOM_IKE_GET_P2_PFS
    else if (NULL != pxIPsecSa) /* jic */
    {
        if (0 < pxIPsecSa->numDhGrps)
        {
            for (i = pxIPsecSa->numDhGrps - 1; 0 <= i; i--)
                if (wGroup == pxIPsecSa->pwDhGrps[i]) break;

            if (0 > i) bad = 4;
            goto exit;
        }
    }
#endif
#endif /* defined(CUSTOM_IKE_GET_P1_DHGRP) || defined(CUSTOM_IKE_GET_P2_PFS) */

#ifndef CUSTOM_IKE_GET_P2_PFS
    MOC_UNUSED(pxIPsecSa);
#endif

    if (!wGroup && (NULL != pxSa))
    {
        /* 0 is invalid if we are negotiating IKE_SA */
        bad = 2;
        goto exit;
    }
    else
    {
        IKE_dhGroupInfo *pGroup = IKE_dhGroupEx(pxSa0->ikePeerConfig, wGroup);
        if ((NULL == pGroup) ||
            pGroup->bDisabled[IS_IKE2_SA(pxSa0) ? 1 : 0]
                             [bInitiator ? _I : _R])
        {
            bad = 1;
            goto exit; /* unsupported DH group */
        }
    }

exit:
    return bad;
} /* IKE_checkGroup */


/*------------------------------------------------------------------*/

static MSTATUS
InAttrBV(IKE_context ctx, ubyte2 *type, ubyte2 *len, ubyte2 *value, ubyte4 *value1)
{
    MSTATUS status = OK;

    struct ikeAttr0 *pxAttr0;

    IN_HDR(struct ikeAttr, pxAttr, SIZEOF_IKE_ATTR)

    pxAttr0 = (struct ikeAttr0 *) pxAttr;
    *len = 0;
    *value = 0;
    if (value1) *value1 = 0;

    if (pxAttr0->oAF & 0x80) /* TV */
    {
/*
        *type = pxAttr->wAFtype;
        *((ubyte *)type) &= 0x7F;
        *type = NTOHS(*type);
        *value = NTOHS(pxAttr->wLenVal);
*/
        SET_NTOHS(*value, pxAttr->wLenVal);
        SET_NTOHS(*type, pxAttr->wAFtype);
        *type &= 0x7FFF;
    }
    else /* TLV */
    {
        ubyte2 wLength;
        SET_NTOHS(wLength, pxAttr->wLenVal);

        if ((ctx->dwBufferSize < (ubyte4)wLength) ||
            (0 == wLength))
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }

        SET_NTOHS(*type, pxAttr->wAFtype);
        *len = wLength;

        if (value1 && (sizeof(ubyte4) == wLength))
            SET_NTOHL(*value1, pxAttr->dwValue);

        ADVANCE(wLength)
    }

exit:
    return status;
} /* InAttrBV */


/*------------------------------------------------------------------*/

static MSTATUS
InAttrKeyLen(IKE_context ctx, ubyte2 *pwKeyLen)
{
    MSTATUS status = OK;

    for (;;)
    {
        ubyte2 wType, wValue, wLen = 0;

        /* get data attribute */
        if (SIZEOF_IKE_ATTR/*0*/ > ctx->dwBufferSize)
            break;

        if (OK > (status = InAttrBV(ctx, &wType, &wLen, &wValue, NULL)))
            goto exit;

        if (ATTR_KEY_LENGTH == wType)
        {
            if (wLen) /* must be TV */
            {
                status = ERR_IKE_BAD_ATTR;
                DBG_NL_EXIT
            }
            debug_print(" ");
            debug_int(wValue);
            debug_print("-BITS");

            if (wValue % 8) /* must be multiple of 8 */
            {
                debug_printnl(" unsupported");
                status = ERR_IKE_MISMATCH;
            }
            else *pwKeyLen = wValue / 8;

            break;
        }

        debug_print(" ATTR-");
        debug_int(wType);
    } /* for */

exit:
    return status;
} /* InAttrKeyLen */


/*------------------------------------------------------------------*/

static MSTATUS
InTfm2_R(IKE_context ctx)
{
    /* Note: CHILD_SA (AH & ESP) responder only */
    MSTATUS status = ERR_IKE_MISMATCH;

    IKESA pxSa = ctx->pxSa;
    IKE2XG pxXg = ctx->pxXg;
    IPSECSA pxIPsecSa = pxXg->pxIPsecSa;

    IPSECPPS pxIPsecPps = ctx->pxIPsecPps;

    struct ikePpsHdr *pxPpsHdr = (struct ikePpsHdr *) ctx->pHdrParent;
    ubyte oProtoId = pxPpsHdr->oProtoId;/*pxIPsecPps->oProtocol*/

    ubyte2 bitStrength = 0;
#ifndef __DISABLE_DIGICERT_CONSTRAINT_CIPHER__
    bitStrength = CHILDSA_cipherEffectiveBitStrength(pxSa->pCipherSuite->wTfmId, pxSa->wEncrKeyLen);
#endif

#define NUM_ENCR_ALGOS 24 /* FOR NOW */
    struct {
/*      ubyte2 wTfmId;*/
        ubyte2 wKeyLen;
        ubyte oTfmId;
    }
    axEncr[NUM_ENCR_ALGOS] = { { 0 } };
    ubyte oEncrCnt = 0;

#define NUM_AUTH_ALGOS 16 /* FOR NOW */
    struct {
/*      ubyte2 wTfmId;*/
        ubyte2 wKeyLen;
        ubyte2 wAuthAlgo;
        ubyte oTfmId;
    }
    axAuth[NUM_AUTH_ALGOS] = { { 0 } };
    ubyte oAuthCnt = 0;

    intBoolean bDhGrp = FALSE;
    ubyte oDhCnt = 0;

    intBoolean bEsn[2];
    ubyte oEsnCnt = 0;

    sbyte4 i, j;

    /* traverse transform payloads */
    for (i = pxPpsHdr->oTfmLen - 1; 0 <= i ; i--)
    {
        ubyte2 wTfmId, wKeyLen = 0;
        ubyte oTfmType;

        /* transform payload header */
        IN_BEGIN(struct ike2TfmHdr, pxTfmHdr, SIZEOF_IKE_TFM_HDR)

        SET_NTOHS(wTfmId, pxTfmHdr->wTfmId);
        oTfmType = pxTfmHdr->oType;

        debug_print("     ");
        debug_print_ike2_tfm(wTfmId, oTfmType);

        /* get KEY_LENGTH attribute, if necessary */
        if (wBodyLen)
        {
            if (((TFM_ENCR == oTfmType) || (TFM_INTEG == oTfmType)) && wTfmId)
            {
                MSTATUS st;
                IN_DOWN(pxTfmHdr)
                if (OK > (st = InAttrKeyLen(ctx, &wKeyLen)))
                {
                    status = st;
                    goto exit;
                }
                IN_UP(pxTfmHdr)
            }
            else
            {
                IN_END
            }
        }

        switch (oTfmType)
        {
        case TFM_ENCR :     /* Encryption Algorithm (ESP) */
            if (PROTO_IPSEC_AH == oProtoId)
            {
                debug_printnl(" unexpected in AH");
                goto exit;
            }

            if (NUM_ENCR_ALGOS <= oEncrCnt)
            {
                debug_print(" skipped"); /* too many */
            }
            else
            {
                ubyte oTfmId;
                CHILDSA_encrInfo *pEncrAlgo = NULL;

#ifndef __ENABLE_DIGICERT_PFKEY__
                if (ENCR_NULL != wTfmId)
#endif
                {
                    if ((NULL == (pEncrAlgo = CHILDSA_findEncrAlgoWithConstraint(bitStrength, 0, wTfmId, 0,
                                                                   wKeyLen, NULL)))
#ifdef __ENABLE_DIGICERT_PFKEY__
                        || !pEncrAlgo->bSupported
#endif
                        )
                    {
                        debug_print(" unsupported");
                        break;
                    }
                }

                if (ENCR_NULL == wTfmId)
                {
                    if (wKeyLen)
                    {
                        debug_print(" invalid KEY_LENGTH");
                        break;
                    }
                    oTfmId = ESP_NULL;
                }
                else
                {
                    if (!wKeyLen)
                    {
                        /* key-length required? */
                        if (!pEncrAlgo->bFixedKeyLen &&
                            (!pEncrAlgo->wKeyLenEnd ||
                             (pEncrAlgo->wKeyLenEnd == pEncrAlgo->wKeyLen)))
                        {
                            debug_print(" missing KEY_LENGTH");
                            break;
                        }
                    }

                    oTfmId = pEncrAlgo->oTfmId;
                }

#ifndef __DISABLE_DIGICERT_CONSTRAINT_CIPHER__
                if (CHILDSA_cipherEffectiveBitStrength(oTfmId, wKeyLen) > bitStrength)
                {
                    debug_print(" unsupported constraint");
                    break;
                }
#endif
/*              axEncr[oEncrCnt].wTfmId = wTfmId;*/
                axEncr[oEncrCnt].wKeyLen = wKeyLen;
                axEncr[oEncrCnt].oTfmId = oTfmId;
                ++oEncrCnt;
            }
            break;

        case TFM_INTEG :    /* Integrity Algorithm (AH, optional in ESP) */
            if (NUM_AUTH_ALGOS <= oAuthCnt)
            {
                debug_print(" skipped"); /* too many */
                break;
            }

            if (!wTfmId)
            {
                if (PROTO_IPSEC_AH == oProtoId) /* AH */
                {
                    debug_print(" ignored");
                    break;
                }
            }
            else
            {
                CHILDSA_authInfo *pAuthAlgo = CHILDSA_findAuthAlgo(0, 0, wTfmId, 0);
                if ((NULL == pAuthAlgo)
#ifdef __ENABLE_DIGICERT_PFKEY__
                    || !pAuthAlgo->bSupported
#endif
                    )
                {
                    debug_print(" unsupported");
                    break;
                }

                if (wKeyLen && (wKeyLen != pAuthAlgo->wKeyLen))
                {
                    debug_print(" invalid KEY_LENGTH");
                    break;
                }

/*              axAuth[oAuthCnt].wTfmId = wTfmId;*/
                axAuth[oAuthCnt].wKeyLen = wKeyLen;
                axAuth[oAuthCnt].wAuthAlgo = pAuthAlgo->wAuthAlgo;
                if (PROTO_IPSEC_AH == oProtoId) /* AH */
                    axAuth[oAuthCnt].oTfmId = pAuthAlgo->oTfmId;
            }
            ++oAuthCnt;
            break;

        case TFM_DH :       /* Diffie-Hellman Group (optional in AH & ESP, not piggybacked) */
            if (IKE_XCHG_CHILD != pxXg->oExchange)
            {
                /* no PFS for piggybacked CHILD_SA!!! */
                debug_print(wTfmId ? " unexpected" : NULL);
                break;
            }

            if (bDhGrp)
            {
                debug_print(" skipped");
                break;
            }

            oDhCnt++;

            if (IKE_checkGroup(wTfmId, FALSE, pxSa, NULL, pxIPsecSa))
            {
#ifdef CUSTOM_IKE_GET_P2_PFS
                debug_print(pxIPsecSa->numDhGrps ? " mismatch" : " unsupported");
#else
                debug_print(" unsupported");
#endif
                break;
            }

            if (IKE_CNTXT_FLAG_PFS & ctx->flags)
            {
                if (wTfmId != pxIPsecSa->wPFS) /* inconsistent */
                {
                    debug_print(" overridden");
                    break;
                }
            }
            else
            {
                ctx->flags |= IKE_CNTXT_FLAG_PFS;
                pxIPsecSa->wPFS = wTfmId;
            }

            debug_print(" (fallback)");
            bDhGrp = TRUE;
            break;

        case TFM_ESN :      /* Extended Sequence Numbers (AH & ESP) */
            if (2 <= oEsnCnt)
            {
                debug_print(" skipped");
                break;
            }
            bEsn[oEsnCnt] = (wTfmId ? TRUE : FALSE);

            if (oEsnCnt && (bEsn[0] == bEsn[oEsnCnt]))
            {
                debug_print(" ignored");
                break;
            }

#if defined(__ENABLE_IPSEC_ESN__) || defined(__ENABLE_DIGICERT_PFKEY__)
            if (ctx->oPpsIndex)
            {
                /* make sure ESN is consistent within nested IPsec SAs */
                IPSECPPS pxIPsecPps0 = &(pxIPsecSa->axP2Sa[0].axChildSa[0].ipsecPps);
                intBoolean bEsn0 = (IKE_PROP_FLAG_ESN & pxIPsecPps0->p_flags)
                                 ? TRUE : FALSE;
                if (bEsn0 != bEsn[oEsnCnt]) /* inconsistent */
                {
                    debug_print(" overridden");
                    break;
                }
            }
#else
            if (0 != wTfmId) /* ESNs */
            {
                debug_print(" unsupported");
                break;
            }
#endif
            oEsnCnt++;
            break;

        default :
            break; /* skip */
        } /* switch */

        debug_printnl(NULL);

        /* check next payload type */
        switch (ctx->oNextPayload)
        {
        case ISAKMP_NEXT_T :
            if (0 < i) continue;
        case 0 :
            if (0 == i) break;
        default :
            status = ERR_IKE_BAD_PAYLOAD;
            DBG_EXIT
        }
    } /* for */

    /* check encr. algo. */
    if (!oEncrCnt &&
        (PROTO_IPSEC_ESP == oProtoId))
    {
        pxIPsecSa->merror = ERR_IKE_MISMATCH_ENCR_ALGO;
        debug_printnl("     ENCR_ALG mismatch");
        goto exit;
    }

    /* check auth. algo. */
    if (!oAuthCnt &&
        (PROTO_IPSEC_AH == oProtoId))
    {
        pxIPsecSa->merror = ERR_IKE_MISMATCH_AUTH_ALGO;
        debug_printnl("     AUTH_ALG mismatch");
        goto exit;
    }

    /* check PFS */
    if ((IKE_XCHG_CHILD == pxXg->oExchange) && /* CREATE_CHILD_SA only */
        !bDhGrp && !(IKE_CNTXT_FLAG_PFS & ctx->flags))
    {
        if (oDhCnt)
        {
            /* DH tfm's exist but none has been chosen */
            pxIPsecSa->merror = ERR_IKE_MISMATCH_DH_GROUP;
            debug_printnl("     DH_GROUP mismatch");
            goto exit;
        }

        if (IKE_checkGroup(0, FALSE, pxSa, NULL, pxIPsecSa))
        {
            pxIPsecSa->merror = ERR_IKE_MISMATCH_DH_GROUP;
            debug_printnl("     DH_GROUP missing");
            goto exit;
        }

        /* pxIPsecSa->wPFS = 0; */
        ctx->flags |= IKE_CNTXT_FLAG_PFS;
    }

    /* check ESN */
    if (!oEsnCnt)
    {
        /* no valid ESN tfm chosen */
        pxIPsecSa->merror = ERR_IKE_MISMATCH_ESN;
        debug_printnl("     ESN mismatch");
        goto exit;
    }

    /* reset */
#ifdef __ENABLE_IPSEC_NAT_T__
/*  pxIPsecPps->p_flags &= ~(IKE_PROP_FLAG_UDP_ENCP);*/
#endif
    if (!pxIPsecPps->wMode)
        pxIPsecPps->wMode = ENCAPSULATION_MODE_TUNNEL;

#if defined(__ENABLE_IPSEC_ESN__) || defined(__ENABLE_DIGICERT_PFKEY__)
set_esn:
    if (bEsn[0]) pxIPsecPps->p_flags |= IKE_PROP_FLAG_ESN;
    else pxIPsecPps->p_flags &= ~(IKE_PROP_FLAG_ESN);
#endif

    /* enumerate ENCR tfm's */
    for (i=0; !oEncrCnt || (oEncrCnt > i); i++)
    {
        if (oEncrCnt)
        {
            pxIPsecPps->oEncrAlgo   =
            pxIPsecPps->oTfmId      = axEncr[i].oTfmId;
            pxIPsecPps->wEncrKeyLen = axEncr[i].wKeyLen;

            if (ESP_NULL == pxIPsecPps->oTfmId)
            {
                pxIPsecPps->oEncrAlgo = 0;
                if (!oAuthCnt) { /* ??? */ }
            }
        }
        else
        {
            pxIPsecPps->oEncrAlgo   = 0;
            pxIPsecPps->wEncrKeyLen = 0;
        }

        /* enumerate AUTH tfm's */
        for (j=0; !oAuthCnt || (oAuthCnt > j); j++)
        {
            if (oAuthCnt)
            {
                pxIPsecPps->wAuthAlgo = axAuth[j].wAuthAlgo;
                pxIPsecPps->wAuthKeyLen = axAuth[j].wKeyLen;

                if  (PROTO_IPSEC_AH == oProtoId)
                    pxIPsecPps->oTfmId = axAuth[j].oTfmId;
            }
            else
            {
                pxIPsecPps->wAuthAlgo   = 0;
                pxIPsecPps->wAuthKeyLen = 0;
            }
            {
                MSTATUS st;

                struct ipsecKeyEx keyEx = { 0 };
                IKE_initIPsecKey(&keyEx, pxSa, pxIPsecSa, pxIPsecPps,
                                 NULL, 0, ctx->oPpsIndex, _R);

                st = IPSEC_keyReady(&keyEx);
                pxIPsecSa->axP2Sa[0].dwSpdId = keyEx.dwSpdId;
                pxIPsecSa->axP2Sa[0].spdIndex = keyEx.spdIndex;

                if ((OK > st) &&
                    (STATUS_SPD_NARROWED != st))
                {
                    /* mismatch */
                    pxIPsecSa->merror = st;

                    if (ERR_SPD_UNACCEPTABLE_TS == st) /* no applicable policy */
                    {
                        ctx->wMsgType = TS_UNACCEPTABLE;
                        status = ERR_SPD_UNACCEPTABLE_TS;
                        DBG_EXIT
                    }
                }
                else
                {
                    ubyte4 ikeP2LifeSecsMax = pxSa->ikePeerConfig->ikeP2LifeSecsMax;
                    ubyte4 ikeP2LifeKBytesMax = pxSa->ikePeerConfig->ikeP2LifeKBytesMax;

                    /* match */
#ifdef __ENABLE_DIGICERT_PFKEY__
                    pxIPsecSa->axP2Sa[0].oReplay = keyEx.sadb_sa_replay;
                    pxIPsecSa->axP2Sa[0].cookie = keyEx.cookie;
#endif
                    if (STATUS_SPD_NARROWED == st)
                    {
                        if (!pxIPsecSa->oUlp) pxIPsecSa->oUlp = keyEx.oUlp;
                        if (pxIPsecSa->oUlp)
                        {
                            if (keyEx.wDestPort)
                            {
                                pxIPsecSa->wPortEnd[_R] =
                                pxIPsecSa->wPort[_R]    = keyEx.wDestPort;
                            }
                            if (keyEx.wSrcPort)
                            {
                                pxIPsecSa->wPortEnd[_I] =
                                pxIPsecSa->wPort[_I]    = keyEx.wSrcPort;
                            }
                        }

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                        if (IPSEC_MODE_TRANSPORT != keyEx.oMode)
                        {
#if 1 /* !defined(__ENABLE_DIGICERT_IPV6__) */
                            COPY_MOC_IPADDR(pxIPsecSa->dwIP[_R],    keyEx.dwDestIP);
                            COPY_MOC_IPADDR(pxIPsecSa->dwIPEnd[_R], keyEx.dwDestIPEnd);
                            COPY_MOC_IPADDR(pxIPsecSa->dwIP[_I],    keyEx.dwSrcIP);
                            COPY_MOC_IPADDR(pxIPsecSa->dwIPEnd[_I], keyEx.dwSrcIPEnd);
#endif
                        }
#endif
                    }

                    /* set lifetime */
                    pxIPsecPps->dwExpSecs = keyEx.dwExpSecs; /* seconds */

                    if ((0 != ikeP2LifeSecsMax) &&
                        ((0 == pxIPsecPps->dwExpSecs) ||
                         (ikeP2LifeSecsMax < pxIPsecPps->dwExpSecs)))
                    {
                        pxIPsecPps->dwExpSecs = ikeP2LifeSecsMax;
                    }

                    if (IKE_LIFE_SECS_MAX < pxIPsecPps->dwExpSecs)
                        pxIPsecPps->dwExpSecs = IKE_LIFE_SECS_MAX;

                    pxIPsecPps->dwExpKBytes = keyEx.dwExpKBytes; /* kbytes */

                    if ((0 != ikeP2LifeKBytesMax) &&
                        ((0 == pxIPsecPps->dwExpKBytes) ||
                         (ikeP2LifeKBytesMax < pxIPsecPps->dwExpKBytes)))
                    {
                        pxIPsecPps->dwExpKBytes = ikeP2LifeKBytesMax;
                    }

                    /* done */
                    status = OK;
                    goto exit;
                }

            } /* for (k= */

            if (!oAuthCnt) break;
        } /* for (j= */

        if (!oEncrCnt) break;
    } /* for (i= */

#if defined(__ENABLE_IPSEC_ESN__) || defined(__ENABLE_DIGICERT_PFKEY__)
    if (--oEsnCnt)
    {
        bEsn[0] = bEsn[1];
        goto set_esn;
    }
#endif

exit:
    return status;
} /* InTfm2_R */


/*------------------------------------------------------------------*/

static MSTATUS
InTfm2_I(IKE_context ctx)
{
    /* Note: CHILD_SA (AH & ESP) initiator only */
    MSTATUS status = ERR_IKE_MISMATCH;

    IKE2XG pxXg = ctx->pxXg;
    IPSECSA pxIPsecSa = pxXg->pxIPsecSa;

    IPSECPPS pxIPsecPps = ctx->pxIPsecPps;

    struct ikePpsHdr *pxPpsHdr = (struct ikePpsHdr *) ctx->pHdrParent;
    ubyte oProtoId = pxPpsHdr->oProtoId;/*pxIPsecPps->oProtocol*/

    intBoolean bEncrAlgo = FALSE;
    intBoolean bAuthAlgo = FALSE;
    intBoolean bDhGrp = FALSE;
    intBoolean bEsn = FALSE;

    ubyte2 wPFS = 0;

    ubyte2 bitStrength = 0;
#ifndef __DISABLE_DIGICERT_CONSTRAINT_CIPHER__
    bitStrength = CHILDSA_cipherEffectiveBitStrength(ctx->pxSa->pCipherSuite->wTfmId, ctx->pxSa->wEncrKeyLen);
#endif

    /* traverse transform payloads */
    sbyte4 i;
    for (i = pxPpsHdr->oTfmLen - 1; 0 <= i ; i--)
    {
        ubyte2 wTfmId, wKeyLen = 0;
        ubyte oTfmType;

        /* transform payload header */
        IN_BEGIN(struct ike2TfmHdr, pxTfmHdr, SIZEOF_IKE_TFM_HDR)

        SET_NTOHS(wTfmId, pxTfmHdr->wTfmId);
        oTfmType = pxTfmHdr->oType;

        debug_print("     ");
        debug_print_ike2_tfm(wTfmId, oTfmType);

        /* get KEY_LENGTH attribute, if necessary */
        if (wBodyLen)
        {
            if (((TFM_ENCR == oTfmType) || (TFM_INTEG == oTfmType)) && wTfmId)
            {
                MSTATUS st;
                IN_DOWN(pxTfmHdr)
                if (OK > (st = InAttrKeyLen(ctx, &wKeyLen)))
                {
                    status = st;
                    goto exit;
                }
                IN_UP(pxTfmHdr)
            }
            else
            {
                IN_END
            }
        }

        switch (oTfmType)
        {
        case TFM_ENCR :     /* Encryption Algorithm (ESP) */
            if (PROTO_IPSEC_AH == oProtoId)
            {
                debug_printnl(" unexpected in AH");
                goto exit;
            }

            if (bEncrAlgo)
            {
                debug_print(" ignored"); /* 1 tfm only */
            }
            else
            {
                ubyte oTfmId;

                if (ENCR_NULL == wTfmId)
                {
                    if (wKeyLen)
                    {
                        status = ERR_IKE_MISMATCH_KEYLEN;
                        debug_printnl(" invalid KEY_LENGTH");
                        goto exit;
                    }
                    oTfmId = ESP_NULL;
                }
                else
                {
                    CHILDSA_encrInfo *pEncrAlgo = CHILDSA_findEncrAlgoWithConstraint(bitStrength, 0, wTfmId, 0,
                                                                       wKeyLen, NULL);
                    if (NULL == pEncrAlgo)
                    {
                        status = ERR_IKE_MISMATCH_ENCR_ALGO;
                        debug_printnl(" unsupported");
                        goto exit;
                    }

                    if (wKeyLen)
                    {
                        if (pxIPsecPps->wEncrKeyLen)
                        {
                            if (wKeyLen != pxIPsecPps->wEncrKeyLen)
                            {
                                status = ERR_IKE_MISMATCH_KEYLEN;
                                debug_printnl(" mismatch KEY_LENGTH");
                                goto exit;
                            }
                        }
                        else
                        {
                            pxIPsecPps->wEncrKeyLen = wKeyLen;
                        }
                    }
                    else
                    {
                        /* key-length reqiured? */
                        if (!pEncrAlgo->bFixedKeyLen &&
                            (!pEncrAlgo->wKeyLenEnd ||
                             (pEncrAlgo->wKeyLenEnd == pEncrAlgo->wKeyLen)))
                        {
                            status = ERR_IKE_MISMATCH_KEYLEN;
                            debug_printnl(" missing KEY_LENGTH");
                            goto exit;
                        }
                    }

                    oTfmId = pEncrAlgo->oTfmId;
                }

                if (pxIPsecPps->oTfmId)
                {
                    if (oTfmId != pxIPsecPps->oTfmId)
                    {
                        status = ERR_IKE_MISMATCH_ENCR_ALGO;
                        debug_printnl(" mismatch");
                        goto exit;
                    }
                }
                else /* ESP or ESP_AUTH */
                {
                    if (ESP_NULL == oTfmId)
                    {
                        status = ERR_IKE_MISMATCH_ENCR_ALGO;
                        debug_printnl(" mismatch ANY");
                        goto exit;
                    }
                    else
                    {
                        pxIPsecPps->oEncrAlgo = oTfmId; /* set encr. algo. */

                        if ((isAeadCipher(pxIPsecPps->oEncrAlgo)) ||
                            (ESP_NULL_AES_GMAC == pxIPsecPps->oEncrAlgo))
                        {
                            pxIPsecPps->oSecuProto = IPSEC_PROTO_ESP;
                        }
                    }
                    pxIPsecPps->oTfmId = oTfmId;
                }

                bEncrAlgo = TRUE;
            }
            break;

        case TFM_INTEG :    /* Integrity Algorithm (AH, optional in ESP) */
            if (bAuthAlgo)
            {
                debug_print(" ignored"); /* 1 tfm only */
            }
            else
            {
                CHILDSA_authInfo *pAuthAlgo = NULL;
                if (wTfmId && (NULL == (pAuthAlgo = CHILDSA_findAuthAlgo(0, 0, wTfmId, 0))))
                {
                    status = ERR_IKE_MISMATCH_AUTH_ALGO;
                    debug_printnl(" unsupported");
                    goto exit;
                }

                if (IPSEC_PROTO_ESP == pxIPsecPps->oSecuProto) /* ESP */
                {
                    if (NULL != pAuthAlgo)
                    {
                        status = ERR_IKE_MISMATCH_AUTH_ALGO;
                        debug_printnl(" unexpected in ESP");
                        goto exit;
                    }
                }
                else
                {
                    if (NULL == pAuthAlgo)
                    {
                        status = ERR_IKE_MISMATCH_AUTH_ALGO;
                        debug_printnl(" missing");
                        goto exit;
                    }

                    if (wKeyLen)
                    {
                        if (wKeyLen != pAuthAlgo->wKeyLen)
                        {
                            status = ERR_IKE_MISMATCH_KEYLEN;
                            debug_printnl(" invalid KEY_LENGTH");
                            goto exit;
                        }
                        pxIPsecPps->wAuthKeyLen = wKeyLen;
                    }

                    if (pxIPsecPps->wAuthAlgo)
                    {
                        if (pAuthAlgo->wAuthAlgo != pxIPsecPps->wAuthAlgo)
                        {
                            status = ERR_IKE_MISMATCH_AUTH_ALGO;
                            debug_printnl(" mismatch");
                            goto exit;
                        }
                    }
                    else
                    {
                        if (PROTO_IPSEC_AH == oProtoId) /* AH */
                            pxIPsecPps->oTfmId = pAuthAlgo->oTfmId;

                        pxIPsecPps->wAuthAlgo = pAuthAlgo->wAuthAlgo;
                    }
                }

                bAuthAlgo = TRUE;
            }
            break;

        case TFM_DH :       /* Diffie-Hellman Group (optional in AH & ESP, not piggybacked) */
            if (bDhGrp)
            {
                debug_print(" ignored"); /* 1 tfm only */
            }
            else
            {
                if (IKE_XCHG_CHILD != pxXg->oExchange)
                {
                    /* no PFS for piggybacked CHILD_SA!!! */
                    debug_print(wTfmId ? " unexpected" : NULL);
                }
                else
                {
                    wPFS = wTfmId;
                }

                bDhGrp = TRUE;
            }
            break;

        case TFM_ESN :      /* Extended Sequence Numbers (AH & ESP) */
            if (bEsn)
            {
                debug_print(" ignored"); /* 1 tfm only */
            }
            else
            {
#if defined(__ENABLE_DIGICERT_PFKEY__)
                if (((0 == wTfmId) &&
                     (IKE_PROP_FLAG_ESN & pxIPsecPps->p_flags)) ||
                    ((0 != wTfmId) &&
                     !(IKE_PROP_FLAG_ESN & pxIPsecPps->p_flags)))
                {
                    status = ERR_IKE_MISMATCH_ESN;
                    debug_printnl(" mismatch");
                    goto exit;
                }
#elif defined(__ENABLE_IPSEC_ESN__)
                if (ctx->oPpsIndex)
                {
                    /* make sure ESN is consistent within nested SAs */
                    IPSECPPS pxIPsecPps0 = &(pxIPsecSa->axP2Sa[0].axChildSa[0].ipsecPps);

                    if (((0 == wTfmId) &&
                         (IKE_PROP_FLAG_ESN & pxIPsecPps0->p_flags)) ||
                        ((0 != wTfmId) &&
                         !(IKE_PROP_FLAG_ESN & pxIPsecPps0->p_flags)))
                    {
                        status = ERR_IKE_MISMATCH_ESN;
                        debug_printnl(" unexpected");
                        goto exit;
                    }
                }

                if (0 != wTfmId)
                    pxIPsecPps->p_flags |= IKE_PROP_FLAG_ESN;
#else
                if (0 != wTfmId)
                {
                    status = ERR_IKE_MISMATCH_ESN;
                    debug_printnl(" unsupported");
                    goto exit;
                }
#endif
                bEsn = TRUE;
            }
            break;

        default :
            break; /* skip */
        } /* switch */

        debug_printnl(NULL);

        /* check next payload type */
        switch (ctx->oNextPayload)
        {
        case ISAKMP_NEXT_T :
            if (0 < i) continue;
        case 0 :
            if (0 == i) break;
        default :
            status = ERR_IKE_BAD_PAYLOAD;
            DBG_EXIT
        }
    } /* for */

    /* check encr. algo. */
    if (!bEncrAlgo &&
        (PROTO_IPSEC_ESP == oProtoId))
    {
        status = ERR_IKE_MISMATCH_ENCR_ALGO;
        debug_printnl("     ENCR_ALG missing");
        goto exit;
    }

    /* check auth. algo. */
    if (!bAuthAlgo &&
        (IPSEC_PROTO_ESP != pxIPsecPps->oSecuProto))
    {
        status = ERR_IKE_MISMATCH_AUTH_ALGO;
        debug_printnl("     AUTH_ALG missing");
        goto exit;
    }

    /* check ESN */
#if defined(__ENABLE_DIGICERT_PFKEY__)
    if (!bEsn && (IKE_PROP_FLAG_ESN & pxIPsecPps->p_flags))
    {
        status = ERR_IKE_MISMATCH_ESN;
        debug_printnl("     ESN missing");
        goto exit;
    }
#elif defined(__ENABLE_IPSEC_ESN__)
    if (!bEsn && ctx->oPpsIndex)
    {
        /* make sure ESN is consistent within nested SAs */
        IPSECPPS pxIPsecPps0 = &(pxIPsecSa->axP2Sa[0].axChildSa[0].ipsecPps);
        if (IKE_PROP_FLAG_ESN & pxIPsecPps0->p_flags)
        {
            status = ERR_IKE_MISMATCH_ESN;
            debug_printnl("     ESN missing");
            goto exit;
        }
    }
#endif

    /* check PFS */
    if ((IKE_XCHG_CHILD == pxXg->oExchange) && /* CREATE_CHILD_SA only */
        (wPFS != pxIPsecSa->wPFS))
    {
        if (pxIPsecSa->wPFS)
        {
            status = ERR_IKE_MISMATCH_DH_GROUP;
            debug_print("     DH_GROUP ");
            debug_printnl(bDhGrp ? "mismatch" : "missing");
            goto exit;
        }
        debug_printnl("     DH_GROUP unexpected");
    }

    /* special case - IKE_KEY_TYPE_SAINIT event!!! */
    else if (IKE_CHILD_FLAG_CONNECT2 & pxIPsecSa->c_flags)
    {
        /* Note: IPsec policy should be set by now (through CP) */
        struct ipsecKeyEx keyEx = { 0 };
        IKE_initIPsecKey(&keyEx, ctx->pxSa, pxIPsecSa, pxIPsecPps,
                         NULL, 0, ctx->oPpsIndex, _I);

        status = IPSEC_keyReady(&keyEx);
        pxIPsecSa->axP2Sa[0].dwSpdId = keyEx.dwSpdId;
        pxIPsecSa->axP2Sa[0].spdIndex = keyEx.spdIndex;

        if ((OK > status) &&
            (STATUS_SPD_NARROWED != status)) /* !!! */
            DBG_EXIT

        /* match */
#ifdef __ENABLE_DIGICERT_PFKEY__
        pxIPsecSa->axP2Sa[0].oReplay = keyEx.sadb_sa_replay;
        pxIPsecSa->axP2Sa[0].cookie = keyEx.cookie;
#endif
        if (STATUS_SPD_NARROWED == status)
        {
            if (!pxIPsecSa->oUlp) pxIPsecSa->oUlp = keyEx.oUlp;
            if (pxIPsecSa->oUlp)
            {
                if (keyEx.wDestPort)
                {
                    pxIPsecSa->wPortEnd[_I] =
                    pxIPsecSa->wPort[_I]    = keyEx.wDestPort;
                }
                if (keyEx.wSrcPort)
                {
                    pxIPsecSa->wPortEnd[_R] =
                    pxIPsecSa->wPort[_R]    = keyEx.wSrcPort;
                }
            }

#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
            if (IPSEC_MODE_TRANSPORT != keyEx.oMode)
            {
#if 1 /* !defined(__ENABLE_DIGICERT_IPV6__) */
                COPY_MOC_IPADDR(pxIPsecSa->dwIP[_I],    keyEx.dwDestIP);
                COPY_MOC_IPADDR(pxIPsecSa->dwIPEnd[_I], keyEx.dwDestIPEnd);
                COPY_MOC_IPADDR(pxIPsecSa->dwIP[_R],    keyEx.dwSrcIP);
                COPY_MOC_IPADDR(pxIPsecSa->dwIPEnd[_R], keyEx.dwSrcIPEnd);
#endif
            }
#endif
        }

        /* adjust lifetime */
        if ((0 != keyEx.dwExpSecs) && /* seconds */
            ((0 == pxIPsecPps->dwExpSecs) ||
             (keyEx.dwExpSecs < pxIPsecPps->dwExpSecs)))
        {
            pxIPsecPps->dwExpSecs = keyEx.dwExpSecs;

            if (IKE_LIFE_SECS_MAX < pxIPsecPps->dwExpSecs)
                pxIPsecPps->dwExpSecs = IKE_LIFE_SECS_MAX;
        }

        if ((0 != keyEx.dwExpKBytes) && /* kbytes */
            ((0 == pxIPsecPps->dwExpKBytes) ||
             (keyEx.dwExpKBytes < pxIPsecPps->dwExpKBytes)))
        {
            pxIPsecPps->dwExpKBytes = keyEx.dwExpKBytes;
        }
    }

    /* done */
    status = OK;

exit:
    return status;
} /* InTfm2_I */

/*------------------------------------------------------------------*/

#define SET_MERROR(_c) if (bInitiator) \
                       {\
                           bAbort = TRUE;\
                           status = (_c);\
                       }\
                       else pxSa->merror = (_c);

static MSTATUS
InTfm(IKE_context ctx)
{
    /* Note: IKE_SA only */
    MSTATUS status = ERR_IKE_MISMATCH;

    IKE2XG pxXg = ctx->pxXg;
    IKESA pxSa = pxXg->pxSa;

    intBoolean bInitiator = IS_INITIATOR(pxSa);
    struct ikePpsHdr *pxPpsHdr = (struct ikePpsHdr *) ctx->pHdrParent;

    intBoolean bDhGrp = FALSE;

    sbyte4 i;

    /* clean up */
    pxSa->pMacSuite = NULL;
    pxSa->pHashSuite = NULL;
    pxSa->pCipherSuite = NULL;
    pxSa->wEncrKeyLen = 0;
    pxSa->wAuthKeyLen = 0;
    if (!bInitiator) pxSa->wDhGrp = 0;

    /* traverse transform payloads */
    for (i = pxPpsHdr->oTfmLen - 1; 0 <= i ; i--)
    {
        ubyte2 wTfmId, wKeyLen = 0;
        ubyte oTfmType;

        intBoolean bAbort = FALSE;

        /* transform payload header */
        IN_BEGIN(struct ike2TfmHdr, pxTfmHdr, SIZEOF_IKE_TFM_HDR)

        SET_NTOHS(wTfmId, pxTfmHdr->wTfmId);
        oTfmType = pxTfmHdr->oType;

        debug_print("     ");
        debug_print_ike2_tfm(wTfmId, oTfmType);

        /* get KEY_LENGTH attribute */
        if (wBodyLen)
        {
            MSTATUS st;
            IN_DOWN(pxTfmHdr)
            if (OK > (st = InAttrKeyLen(ctx, &wKeyLen)))
            {
                status = st;
                goto exit;
            }
            IN_UP(pxTfmHdr)
        }

        switch (oTfmType)
        {
        case TFM_ENCR :     /* Encryption Algorithm (IKE) */
            if (NULL != pxSa->pCipherSuite)
            {
                debug_print(bInitiator ? " ignored" : " skipped"); /* 1 tfm only */
            }
            else
            {
                IKE_cipherSuiteInfo *pCipherSuite = IKE_cipherSuiteEx(pxSa->ikePeerConfig, 0, wTfmId,
                                                                wKeyLen, NULL);
#ifdef CUSTOM_IKE_GET_ENCR_ALGO
                if ((NULL != pCipherSuite) && (0 < pxSa->numEncrAlgos))
                {
                    sbyte4 j;
                    for (j = pxSa->numEncrAlgos - 1; 0 <= j; j--)
                        if (wTfmId == pxSa->pwEncrAlgos[j])
                        {
                            if (wKeyLen)
                            {
                                if (pxSa->pwEncrKeyLens[j] &&
                                    (wKeyLen != pxSa->pwEncrKeyLens[j]))
                                    continue;
                            }
                            else
                            {
                                wKeyLen = pxSa->pwEncrKeyLens[j];
                                if (wKeyLen)
                                {
                                    pCipherSuite = IKE_cipherSuiteEx(pxSa->ikePeerConfig, 0, wTfmId,
                                                                wKeyLen, NULL);
                                    if (NULL == pCipherSuite) /* jic */
                                    {
                                        wKeyLen = 0; /* !!! */
                                        continue;
                                    }
                                }
                            }
                            break;
                        }

                    if ((0 > j) || (NULL == pCipherSuite))
                    {
                        debug_print(" mismatch");
                        SET_MERROR(ERR_IKE_MISMATCH_ENCR_ALGO)
                        break;
                    }
                }
                else
#endif
                if ((NULL == pCipherSuite) ||
                    pCipherSuite->bDisabled[1][bInitiator ? _I : _R])
                {
                    debug_print(" unsupported");
                    SET_MERROR(ERR_IKE_MISMATCH_ENCR_ALGO)
                    break;
                }

                if (wKeyLen)
                {
                    pxSa->wEncrKeyLen = wKeyLen;
                }
                else
                {
                    /* key-length reqiured? */
                    if (!pCipherSuite->bFixedKeyLen &&
                        (!pCipherSuite->wKeyLenEnd ||
                         (pCipherSuite->wKeyLenEnd == pCipherSuite->wKeyLen)))
                    {
                        debug_print(" missing KEY_LENGTH");
                        SET_MERROR(ERR_IKE_MISMATCH_KEYLEN)
                        break;
                    }
                }
                pxSa->pCipherSuite = pCipherSuite;
            }
            break;

        case TFM_PRF :      /* Pseudo-random Function (IKE) */
            if (NULL != pxSa->pHashSuite)
            {
                debug_print(bInitiator ? " ignored" : " skipped"); /* 1 tfm only */
            }
            else
            {
                IKE_hashSuiteInfo *pHashSuite = IKE_hashSuiteEx(pxSa->ikePeerConfig, 0, wTfmId);
#ifdef CUSTOM_IKE_GET_HASH_ALGO
                if ((NULL != pHashSuite) && (0 < pxSa->numHashAlgos))
                {
                    sbyte4 j;
                    for (j = pxSa->numHashAlgos - 1; 0 <= j; j--)
                        if (wTfmId == pxSa->pwHashAlgos[j]) break;

                    if (0 > j)
                    {
                        debug_print(" mismatch");
                        SET_MERROR(ERR_IKE_MISMATCH_PRF)
                        break;
                    }
                }
                else
#endif
                if ((NULL == pHashSuite) ||
                    pHashSuite->bDisabled[1][bInitiator ? _I : _R])
                {
                    debug_print(" unsupported");
                    SET_MERROR(ERR_IKE_MISMATCH_PRF)
                    break;
                }
                pxSa->pHashSuite = pHashSuite;
            }
            break;

        case TFM_INTEG :    /* Integrity Algorithm (IKE) */
            if (NULL != pxSa->pMacSuite)
            {
                debug_print(bInitiator ? " ignored" : " skipped"); /* 1 tfm only */
            }
            else
            {
                IKE_macSuiteInfo *pMacSuite = IKE_macSuiteEx(pxSa->ikePeerConfig, wTfmId);
#ifdef CUSTOM_IKE_GET_INTEG_ALGO
                if ((NULL != pMacSuite) && (0 < pxSa->numMacAlgos))
                {
                    sbyte4 j;
                    for (j = pxSa->numMacAlgos - 1; 0 <= j; j--)
                        if (wTfmId == pxSa->pwMacAlgos[j]) break;

                    if (0 > j)
                    {
                        debug_print(" mismatch");
                        SET_MERROR(ERR_IKE_MISMATCH_AUTH_ALGO)
                        break;
                    }
                }
                else
#endif
                if ((NULL == pMacSuite) ||
                    pMacSuite->bDisabled[bInitiator ? _I : _R])
                {
                    debug_print(" unsupported");
                    SET_MERROR(ERR_IKE_MISMATCH_AUTH_ALGO)
                    break;
                }

                if (wKeyLen)
                {
                    if (wKeyLen != pMacSuite->wKeyLen)
                    {
                        debug_print(" invalid KEY_LENGTH");
                        SET_MERROR(ERR_IKE_MISMATCH_KEYLEN)
                        break;
                    }
                    pxSa->wAuthKeyLen = wKeyLen;
                }
                pxSa->pMacSuite = pMacSuite;
            }
            break;

        case TFM_DH :       /* Diffie-Hellman Group (IKE) */
            if (bDhGrp)
            {
                debug_print(bInitiator ? " ignored" : " skipped"); /* 1 tfm only */
                break;
            }

            if (bInitiator)
            {
                if (wTfmId != pxSa->wDhGrp)
                {
                    status = ERR_IKE_MISMATCH_DH_GROUP;
                    debug_print(" mismatch");
                    bAbort = TRUE;
                    break;
                }
            }
            else
            {
                sbyte4 bad;
                if (0 != (bad = IKE_checkGroup(wTfmId, FALSE, ctx->pxSa, pxSa, NULL)))
                {
#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
                    switch (bad)
                    {
                    case 1 : debug_print(" unsupported"); break;
                    case 2 : debug_print(" unexpected"); break;
                    default : debug_print(" mismatch"); break;
                    }
#endif
                    pxSa->merror = ERR_IKE_MISMATCH_DH_GROUP;
                    break;
                }

                debug_print(" (fallback)");
                pxSa->wDhGrp = wTfmId;
            }
            bDhGrp = TRUE;
            break;

        default :
            break; /* skip */
        } /* switch */

        debug_printnl(NULL);

        if (bAbort) goto exit;

        if ((NULL != pxSa->pCipherSuite) &&
            (NULL != pxSa->pHashSuite) &&
            (NULL != pxSa->pMacSuite) &&
            bDhGrp
#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
            && (0 == i)
#endif
            )
        {
            status = OK; /* match */
            break;
        }
        else if ((NULL != pxSa->pCipherSuite) &&
            (NULL != pxSa->pHashSuite) &&
            (NULL == pxSa->pMacSuite) &&
            bDhGrp
#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
            && (0 == i)
#endif
            )
        {
            /* check to see if using AEAD algorithm */
            if (isAeadCipher(pxSa->pCipherSuite->wTfmId))
            {
                status = OK;
                break;
            }
        }

        /* check next payload type */
        switch (ctx->oNextPayload)
        {
        case ISAKMP_NEXT_T :
            if (0 < i) continue;
        case 0 :
            if (0 == i) break;
        default :
            status = ERR_IKE_BAD_PAYLOAD;
            DBG_EXIT
        }
    } /* for */

exit:
    return status;
} /* InTfm */


/*------------------------------------------------------------------*/

static MSTATUS
InSa0(IKE_context ctx)
{
    /* Note: CREATE_CHILD_SA or IKE_AUTH only */
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    IKE2XG pxXg = ctx->pxXg;

    /* SA payload header */
    IN_BEGIN(struct ikeGenHdr, pxSaHdr, SIZEOF_IKE_GEN_HDR)

    if (IKE_CNTXT_FLAG_SA & ctx->flags) /* already received SA payload */
    {
        status = ERR_IKE_BAD_PAYLOAD;
        DBG_EXIT
    }

#if defined(__ENABLE_IKE_MULTI_AUTH__) || \
    (defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__))
    if (!IS_XCHG_INITIATOR(pxXg) && !IS_IKE2_SA_AUTHED(pxSa))
        ctx->u.v2.poSAi2 = (const ubyte *)pxSaHdr;
#endif

    /* down one level - go to child payloads */
    IN_DOWN(pxSaHdr)

    /* proposal payload(s) */
    {
        /* proposal payload header */
        IN_BEGIN(struct ikePpsHdr, pxPpsHdr, SIZEOF_IKE_PPS_HDR)

        if (!IS_XCHG_INITIATOR(pxXg)) /* responder */
        {
            if (PROTO_ISAKMP == pxPpsHdr->oProtoId) /* rekeying IKE_SA */
            {
                IKESA pxSa1;

                if (!IS_IKE2_SA_AUTHED(pxSa)) /* IKE_AUTH, expecting CHILD_SA's */
                {
                    status = ERR_IKE_BAD_PAYLOAD;
                    DBG_EXIT
                }

                if ((IKE_COOKIE_SIZE != pxPpsHdr->oSpiSize) ||
                    (IKE_COOKIE_SIZE > wBodyLen))
                {
                    status = ERR_IKE_BAD_LEN;
                    DBG_EXIT
                }

                if (IKE_isEmptyCky(ctx->pBuffer))
                {
                    status = ERR_IKE_BAD_COOKIE;
                    DBG_EXIT
                }

                if (NULL == (pxSa1 = IKE2_newSa(pxSa->ikePeerConfig, REF_MOC_IPADDR(pxSa->dwPeerAddr),
                                                pxSa->wPeerPort, ctx->pBuffer, pxSa
                                                MOC_NATT_VALUE(USE_NATT_PORT(pxSa))
                                                MOC_MTHM_VALUE(pxSa->serverInstance))))
                {
                    /* ctx->wMsgType = NO_PROPOSAL_CHOSEN; */
                    status = ERR_IKE_NEWSA_FAIL;
                    DBG_EXIT
                }
                pxXg->pxSa = pxSa1;
                pxXg->dwSaId = pxSa1->dwId;
            }
            else /* CHILD_SA */
            {
                if (OK > (status = IKE2_newIPsecSa(pxSa, pxXg, NULL)))
                {
                    ctx->wMsgType = NO_ADDITIONAL_SAS;
                    goto exit;
                }

#ifdef __ENABLE_IPSEC_NAT_T__
                if (USE_NATT_PORT(pxSa) && IS_BEHIND_NAT(pxSa))
                {
                    sbyte4 i;
                    for (i=0; i < IPSEC_NEST_MAX; i++)
                    {
                        pxXg->pxIPsecSa->axP2Sa[0].axChildSa[i].
                            ipsecPps.p_flags |= IKE_PROP_FLAG_UDP_ENCP;
                    }
                }
#endif
            }
        }

        IN_END
    }

    /* up one level */
    IN_UP(pxSaHdr)

    ctx->flags |= IKE_CNTXT_FLAG_SA;

exit:
    return status;
} /* InSa0 */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PFKEY__

typedef struct IKE2_stateCB
{
    struct ipsecKey key;

    IKESA pxSa;
    ubyte4 dwSaId;

    IKE2XG pxXg;
    ubyte4 dwMsgId;

    IPSECPPS pxPps;

} IKE2_stateCB;

#ifdef __IKE_UPDATE_TIMER__
extern MSTATUS IKE2_setupMatureTimers(IKESA pxSa);
#endif


/*------------------------------------------------------------------*/

extern sbyte4
IKE2_stateCallback(sbyte4 st, void *cbData)
{
    /* Note: responder only */
    MSTATUS status = (MSTATUS)st;

    IKESA pxSa;
    IKE2XG pxXg;
    IPSECPPS pxPps;

    intBoolean bLastPps = TRUE;
    IPSECSA pxIPsecSa;
    sbyte4 i;

    struct ike_context ctx = { NULL };

    IKE_LOCK_R; /* !!! */

    if ((NULL == cbData) ||
        (NULL == (pxSa = ((IKE2_stateCB *)cbData)->pxSa)) ||
        (NULL == (pxXg = ((IKE2_stateCB *)cbData)->pxXg)))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __IKE_MULTI_THREADED__
    RTOS_rwLockWaitR(m_ikeSaRwLock);
#endif
    if (!IS_VALID(pxSa) ||
        (((IKE2_stateCB *)cbData)->dwSaId != pxSa->dwId))
    {
#ifdef __IKE_MULTI_THREADED__
        RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
        status = ERR_IKE_GETSA_FAIL;
        goto exit;
    }

    /* sanity-check */
    if (!IS_IKE2_SA(pxSa) ||
        (IKE_SA_FLAG_DELETING & pxSa->flags))
    {
#ifdef __IKE_MULTI_THREADED__
        RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
        status = ERR_IKE_BAD_SA;
        goto exit;
    }

    if (!IS_VALID_XCHG(pxXg) ||
        (((IKE2_stateCB *)cbData)->dwMsgId != pxXg->dwMsgId))
    {
#ifdef __IKE_MULTI_THREADED__
        RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
        status = ERR_IKE_BAD_XCHG;
        goto exit;
    }

#ifdef __IKE_MULTI_THREADED__
    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* relay this call to the proper thread */
        if (m_ikeSettings.funcPtrIkeThreadSend)
        {
            ubyte4 size = sizeof(struct dpcStateCB);
            struct dpcStateCB cb;
            cb.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcStateCallback;
            cb.hdr.dpc_len = (ubyte2)size;
            cb.version = 2;
            cb.status = st;
            cb.data = cbData;
            status = (MSTATUS) m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid,
                                                            (ubyte *)&cb, size);
            if (OK <= status) cbData = NULL; /* !!! */
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

    pxPps = ((IKE2_stateCB *)cbData)->pxPps;
    pxIPsecSa = pxXg->pxIPsecSa;

    for (i = pxIPsecSa->axP2Sa[0].oChildSaLen - 1; i >= 0; i--)
    {
        IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[0].axChildSa[i].ipsecPps);
        if ((pxIPsecPps != pxPps) &&
            (0 == pxIPsecPps->dwSpi[_R]))
        {
            bLastPps = FALSE;
            break;
        }
    }

    if (bLastPps)
    {
        pxIPsecSa->merror = OK;
        pxXg->x_flags &= ~(IKE_XCHG_FLAG_PENDING);

        if (IKE_XCHG_AUTH == pxXg->oExchange)
            pxSa->merror = OK;
    }

    if (OK <= status)
    {
        if ((ubyte4)255 >= (pxPps->dwSpi[_R]
                         = ((IKE2_stateCB *)cbData)->key.dwSpi))
            status = ERR_IKE_BAD_SPI;

        else if (!bLastPps) goto exit;

        pxIPsecSa->wMsgType = 0; /* !!! */
    }

    if (OK > status)
    {
        if (IKE_XCHG_AUTH == pxXg->oExchange)
            pxSa->merror = OK;
        else
            ctx.wMsgType = NO_ADDITIONAL_SAS;

        pxIPsecSa->merror = status;
    }

    ctx.pxSa = pxSa;
    ctx.pxXg = pxXg;

    if (OK > (status = IKE2_xchgOut(&ctx)))
    {
#ifdef __IKE_KEYADD_DONT_WAIT__
        if ((OK <= pxIPsecSa->merror) &&
            (STATE_QUICK_R == pxIPsecSa->oState))
        {
            /* TODO: delete keys */
        }
#endif
        goto exit;
    }

    switch (pxXg->oExchange)
    {
    case IKE_XCHG_AUTH :
        pxSa->oState = STATE_MAIN_R;
        IKE2_finalizeSa(pxSa, pxSa->dwTimeCreated, NULL);

#ifndef __IKE_KEYADD_DONT_WAIT__
        if (!pxIPsecSa->wMsgType)
        {
            pxIPsecSa->oState = STATE_QUICK_R;
            IKE_addIPsecKey(&ctx);
        }
#endif
#ifdef __IKE_UPDATE_TIMER__
        status = IKE2_setupMatureTimers(pxSa);
#endif
        break;

    case IKE_XCHG_CHILD :
        status = pxIPsecSa->merror;
#ifndef __IKE_KEYADD_DONT_WAIT__
        if (OK <= status)
        {
            pxIPsecSa->oState = STATE_QUICK_R;
            status = IKE_addIPsecKey(&ctx);
        }
#endif
        break;
    }

exit:
    if (cbData) FREE(cbData);
    IKE_UNLOCK_R;
    return (sbyte4)status;
} /* IKE2_stateCallback */

#endif /* __ENABLE_DIGICERT_PFKEY__ */


/*------------------------------------------------------------------*/

static MSTATUS
InSa(IKE_context ctx)
{
    MSTATUS status = OK;

    IKE2XG pxXg = ctx->pxXg;
    IKESA pxSa = pxXg->pxSa;
    IPSECSA pxIPsecSa = pxXg->pxIPsecSa;

    intBoolean bInitiator = IS_XCHG_INITIATOR(pxXg);

    intBoolean bMatch = TRUE; /* responder */
    ubyte oPpsNo = 0;

    /* for CHILD_SA */
    ubyte oPpsIndex = 0;
    IPSECPPS pxIPsecPps = (NULL != pxSa) ? NULL
                        : &(pxIPsecSa->axP2Sa[0].axChildSa[0].ipsecPps);

    /* SA payload header */
    IN_BEGIN(struct ikeGenHdr, pxSaHdr, SIZEOF_IKE_GEN_HDR)

    /* down one level - go to child payloads */
    IN_DOWN(pxSaHdr)

    /* proposal payload(s) */
    for (;;)
    {
        intBoolean bNext = FALSE; /* responder */
        ubyte oSpiSize;

        /* proposal payload header */
        IN_BEGIN(struct ikePpsHdr, pxPpsHdr, SIZEOF_IKE_PPS_HDR)

        oSpiSize = pxPpsHdr->oSpiSize;
        if (wBodyLen < oSpiSize)
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }

        /* check proposal # */
        if (!oPpsIndex) /* 1st payload of current proposal */
        {
            oPpsNo = pxPpsHdr->oNum;
        }
        else if (oPpsNo > pxPpsHdr->oNum) /* invalid proposal # */
        {
            status = ERR_IKE_BAD_PROPOSAL;
            DBG_EXIT
        }
        else if (oPpsNo < pxPpsHdr->oNum) /* next proposal */
        {
            if (bInitiator) /* initiator */
            {
                /* only 1 proposal expected */
                status = ERR_IKE_BAD_PROPOSAL;
                DBG_EXIT
            }

            /* roll back! */
            ctx->oNextPayload = ISAKMP_NEXT_P;
            ctx->pBuffer -= SIZEOF_IKE_PPS_HDR;
            ctx->dwBufferSize += SIZEOF_IKE_PPS_HDR;
            ctx->dwLength -= SIZEOF_IKE_PPS_HDR;
            bNext = TRUE;
            goto next;
        }
        else
        {
            /* too many payloads? */
            if (!bInitiator &&  /* responder */
                ((pxSa && oPpsIndex) ||
                 (!pxSa && (IPSEC_NEST_MAX <= oPpsIndex))))
            {
                bMatch = FALSE;
                IN_END
                goto skip;
            }
        }

        debug_print("    Proposal #");
        debug_int(pxPpsHdr->oNum);
        debug_print(": ");
        debug_print_ike_proto(pxPpsHdr->oProtoId);
        debug_print("[");
        debug_int(pxPpsHdr->oTfmLen);
        debug_print("]");
#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
        if ((sizeof(ubyte4) == oSpiSize) &&
            (PROTO_ISAKMP != pxPpsHdr->oProtoId))
        {
            debug_print(" spi=");
            debug_hexint(GET_NTOHL(pxPpsHdr->dwSpi));
        }
#endif
        debug_printnl(NULL);

        if (pxSa) /* IKE_SA */
        {
            if (PROTO_ISAKMP != pxPpsHdr->oProtoId) /* protocol id mismatch */
            {
                status = ERR_IKE_BAD_PROTOCOL;
                DBG_EXIT
            }

            if (pxSa != ctx->pxSa) /* rekeying */
            {
                /* SPI */
                if (IKE_COOKIE_SIZE != oSpiSize)
                {
                    status = ERR_IKE_BAD_LEN;
                    DBG_EXIT
                }
                if (bInitiator)
                {
                    if (IKE_isEmptyCky(ctx->pBuffer)) /* jic */
                    {
                        status = ERR_IKE_BAD_COOKIE;
                        DBG_EXIT
                    }
                    DIGI_MEMCPY(pxSa->poCky_R, ctx->pBuffer, /*oSpiSize*/IKE_COOKIE_SIZE);
                }
            }

            if (bInitiator)
            {
            }
            else
                pxSa->oPpsNo = oPpsNo;
        }

        else /* CHILD_SA */
        {
            ubyte4 dwSpi;

            if (bInitiator)
            {
                if (pxIPsecPps->oProtocol != pxPpsHdr->oProtoId) /* protocol id mismatch */
                {
                    status = ERR_IKE_BAD_PROTOCOL;
                    DBG_EXIT
                }

#ifdef __ENABLE_DIGICERT_PFKEY__
                if (1/*pxIPsecPps->oPpsNo*/ != oPpsNo)
                {
                    if ((0 == oPpsNo) ||
                        (oPpsNo > pxIPsecSa->axP2Sa[0].axChildSa[oPpsIndex].
                                             oIPsecPpsNum))
                    {
                        /* no matching Proposal No */
                        status = ERR_IKE_BAD_PROPOSAL;
                        DBG_EXIT
                    }
                    else
                    {
                        IPSECPPS pxExIPsecPps =
                            pxIPsecSa->axP2Sa[0].axChildSa[oPpsIndex].
                                       pxIPsecPps + (oPpsNo - 2);

                        *pxIPsecPps = *pxExIPsecPps; /* !!! */
                    }
                }
#endif
            }
            else /* responder */
            {
                pxIPsecPps->oPpsNo = oPpsNo;

                /* skip proposal payload, if necessary */
                if (bMatch)
                {
                    /* check protocol id */
                    switch (pxPpsHdr->oProtoId)
                    {
                    case PROTO_IPSEC_ESP :
                        break;
                    case PROTO_IPSEC_AH :
#ifdef __ENABLE_IPSEC_NAT_T__
                        /* AH is incompatible with UDP-encap. */
                        if (!USE_NATT_PORT(ctx->pxSa) || !IS_BEHIND_NAT(ctx->pxSa))
#endif
                        break;
                    case PROTO_IPCOMP :
                        pxIPsecSa->merror = ERR_IKE_BAD_PROTOCOL;
                        bMatch = FALSE; /* not supported */
                        break;
                    default :
                        status = ERR_IKE_BAD_PROTOCOL;
                        DBG_EXIT
                    }
                    pxIPsecPps->oProtocol = pxPpsHdr->oProtoId;
                }

                if (!bMatch) /* mismatch */
                {
                    IN_END
                    goto skip;
                }
            }

            /* SPI */
            if (sizeof(dwSpi) != oSpiSize)
            {
                status = ERR_IKE_BAD_SPI;
                DBG_EXIT
            }
            SET_NTOHL(dwSpi, pxPpsHdr->dwSpi);

            if (bInitiator)
                pxIPsecPps->dwSpi[_R] = dwSpi;
            else
            {
                pxIPsecPps->dwSpi[_I] = dwSpi;

#ifndef __ENABLE_DIGICERT_PFKEY__
                while ((ubyte4)255 >= pxIPsecPps->dwSpi[_R]) /* jic re-transmit */
                {
                    if (OK > (status = RANDOM_numberGenerator(g_pRandomContext,(ubyte *)&(pxIPsecPps->dwSpi[_R]), sizeof(ubyte4))))
                        DBG_EXIT
                }
#endif
            }
        } /* else CHILD_SA */

        ADVANCE(oSpiSize)
        wBodyLen = (ubyte2)(wBodyLen - oSpiSize);

        /* down one level - go to child payloads */
        IN_DOWN(pxPpsHdr)

        /* transform payloads */
        if (pxSa) /* IKE_SA */
        {
            status = InTfm(ctx);
        }
        else /* CHILD_SA */
        {
            ctx->pxIPsecPps = pxIPsecPps;
            ctx->oPpsIndex = oPpsIndex;
            if (bInitiator)
                status = InTfm2_I(ctx);
            else
                status = InTfm2_R(ctx);
        }

        if (OK != status)
        {
            if (!bInitiator && /* responder */
                (ERR_IKE_MISMATCH == status)) /* mismatch */
            {
                /* skip to next proposal */
                bMatch = FALSE;
                status = OK;
            }
            else goto exit;
        }

        /* up one level */
        IN_UP(pxPpsHdr)

skip:
        ++oPpsIndex;
        if (pxIPsecPps) /* CHILD_SA */
        {
            if (IPSEC_NEST_MAX > oPpsIndex) /* jic */
                pxIPsecPps = &(pxIPsecSa->axP2Sa[0].axChildSa[oPpsIndex].ipsecPps);
        }

next:
        if (bInitiator) /* initiator */
        {
            if (pxSa || /* IKE_SA accepts only 1 proposal payload */
                (oPpsIndex >= pxIPsecSa->axP2Sa[0].oChildSaLen)) /* expect no more payloads */
            {
                if (IKE_NEXT_NONE != ctx->oNextPayload)
                {
                    status = ERR_IKE_BAD_PAYLOAD;
                    DBG_EXIT
                }
                break; /* accept proposal */
            }
            if (IKE_NEXT_NONE == ctx->oNextPayload) /* expect more payloads */
            {
                status = ERR_IKE_MISMATCH;
                DBG_EXIT
            }
            if (ISAKMP_NEXT_P != ctx->oNextPayload)
            {
                status = ERR_IKE_BAD_PROPOSAL;
                DBG_EXIT
            }
        }
        else /* responder */
        {
            if ((IKE_NEXT_NONE == ctx->oNextPayload) || bNext)
            {
#if defined(__DIGICERT_DEPRECATED__)
/* #ifndef __ENABLE_DIGICERT_PFKEY__ */
/* Deprecating this code section as IPSEC_keyReady is already called in InTfm2_R.
 * This code section has an issue . The wMode is zero, causing the IKE_initIPsecKey to 
 * wrongly assign the pointers. This is causing the pxSa->peerAddress to be modified 
 * during NARROWED selectors case.
 */
                /* check IPsec SA bundle size */
                if (bMatch && pxIPsecPps && (IPSEC_NEST_MAX > oPpsIndex))
                {
                    MSTATUS st;
                    struct ipsecKeyEx keyEx = { 0 };

                    pxIPsecPps->oProtocol   = 0;
                    pxIPsecPps->oEncrAlgo   = 0;
                    pxIPsecPps->wAuthAlgo   = 0;
                    pxIPsecPps->wMode       = 0;

                    IKE_initIPsecKey(&keyEx, ctx->pxSa, pxIPsecSa, pxIPsecPps,
                                     NULL, 0, oPpsIndex, _R);

                    st = IPSEC_keyReady(&keyEx);
                    if ((OK > st) &&
                    (STATUS_SPD_NARROWED != st))
                    {
                        /* mismatch - proposed depth too small */
                        pxIPsecSa->merror = st;
                        bMatch = FALSE;
                    }
                }
#endif
                /* accept proposal */
                if (bMatch)
                {
                    ctx->wMsgType = 0;

                    if (pxSa) /* IKE_SA */
                    {
                        pxSa->merror = OK;
                    }
                    else /* CHILD_SA */
                    {
                        pxIPsecSa->merror = OK;
                        pxIPsecSa->axP2Sa[0].oChildSaLen = oPpsIndex;

#ifdef __ENABLE_DIGICERT_PFKEY__
                        { sbyte4 i;
                        for (i=0; i < oPpsIndex; i++)
                        {
                            IPSECPPS pxPps = &(pxIPsecSa->axP2Sa[0].axChildSa[i].ipsecPps);
                            IKESA pxSa0 = ctx->pxSa;

                            /* get SPI */
                            IKE2_stateCB *cb;
                            IPSECKEY key;

                            INIT_MOC_IPADDR(dstAddr, pxSa0->dwHostAddr)
                            INIT_MOC_IPADDR(srcAddr, pxSa0->dwPeerAddr)
#if 1
                            CHECK_MALLOC_TYPE(IKE2_stateCB, cb)
#else
                            if (NULL == (cb = (IKE2_stateCB *) MALLOC(sizeof(struct IKE2_stateCB))))
                            {
                                /*ctx->wMsgType = ?;*/
                                status = ERR_MEM_ALLOC_FAIL;
                                DBG_EXIT
                            }
#endif
                            key = &(cb->key);
                            DIGI_MEMSET((ubyte *)key, 0x00, sizeof(struct ipsecKey));

                            key->oProtocol      = (PROTO_IPSEC_AH == pxPps->oProtocol)
                                                ? IPPROTO_AH : IPPROTO_ESP;

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
                            if (ENCAPSULATION_MODE_TUNNEL == pxPps->wMode)
                                key->oMode      = IPSEC_MODE_TUNNEL;
                            else
#endif
                                key->oMode      = IPSEC_MODE_TRANSPORT;
                            key->cookie         = pxIPsecSa->axP2Sa[0].cookie;
                            if (i)
                            key->dwSeqNo        = pxIPsecSa->axP2Sa[0].dwSeqNo;

                            key->funcPtrPfkeyCb = IKE2_stateCallback;

                            cb->pxSa = pxSa0;
                            cb->dwSaId = pxSa0->dwId;
                            cb->pxXg = pxXg;
                            cb->dwMsgId = pxXg->dwMsgId;
                            cb->pxPps = pxPps;

                            if ((OK > (status = IPSEC_keySpi(key))) &&
                                (STATUS_IKE_PENDING != status))
                            {
                                FREE(cb);
                                ctx->wMsgType = NO_ADDITIONAL_SAS;
                                DBG_EXIT
                            }

                            if (!i)
                            pxIPsecSa->axP2Sa[0].dwSeqNo = key->dwSeqNo;

                            if (STATUS_IKE_PENDING == status)
                            {
                                status = OK;
                                pxXg->x_flags |= IKE_XCHG_FLAG_PENDING;
                            }
                            else
                            {
                                pxPps->dwSpi[_R] = key->dwSpi;
                                FREE(cb);
                            }
                        } /* for */ }
#endif /* __ENABLE_DIGICERT_PFKEY__ */
                    }

                    break;
                } /* if (bMatch) */

                if (!bNext)
                {
                    if (0 == ctx->wMsgType)
                        ctx->wMsgType = NO_PROPOSAL_CHOSEN;

                    status = ERR_IKE_MISMATCH;
                    goto exit;
                }

                /* start next proposal */
                status = OK;
                bMatch = TRUE;

                oPpsIndex = 0;
                if (NULL != pxIPsecPps) /* CHILD_SA */
                {
#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
                    pxIPsecSa->axP2Sa[0].cookie = 0;
#endif
#ifdef __ENABLE_DIGICERT_PFKEY__
                    pxIPsecSa->axP2Sa[0].oReplay = 0;
#endif
                    pxIPsecSa->axP2Sa[0].dwSpdId = 0;
                    pxIPsecSa->axP2Sa[0].spdIndex = 0;
                    pxIPsecPps = &(pxIPsecSa->axP2Sa[0].axChildSa[0].ipsecPps);

                    pxIPsecSa->wPFS = 0;
                    ctx->flags &= ~(IKE_CNTXT_FLAG_PFS);
                }

                continue;
            } /* END if ((IKE_NEXT_NONE == ctx->oNextPayload) || bNext) */

            if (ISAKMP_NEXT_P != ctx->oNextPayload)
            {
                status = ERR_IKE_BAD_PROPOSAL;
                DBG_EXIT
            }
        } /* responder */

    } /* for (;;) */

    /* up one level */
    IN_UP(pxSaHdr)

exit:
    return status;
} /* InSa */


/*------------------------------------------------------------------*/

static MSTATUS
InGen(IKE_context ctx, ubyte2 *pwBodyLen)
{
    MSTATUS status = OK;

    /* generic header */
    IN_BEGIN(struct ikeGenHdr, pxGenHdr, SIZEOF_IKE_GEN_HDR)

    /* payload body */
    *pwBodyLen = wBodyLen;

    /* done */
    IN_END

exit:
    return status;
} /* InGen */


/*------------------------------------------------------------------*/

static MSTATUS
InVid(IKE_context ctx)
{
    MSTATUS status;

    ubyte2 wVidLen;
#if (defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__))
    ubyte *vid;
#endif

    /* generic header */
    if (OK != (status = InGen(ctx, &wVidLen)))
        goto exit;

    /* get VID */
#if (defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__))
    vid = ctx->pBuffer - wVidLen;
    debug_printd((sbyte *)"   VID:", vid, wVidLen);
#endif
exit:
    return status;
} /* InVid */


/*------------------------------------------------------------------*/

static MSTATUS
InKe(IKE_context ctx)
{
    MSTATUS                 status      = OK;

    IKE2XG                  pxXg        = ctx->pxXg;
    IKESA                   pxSa        = pxXg->pxSa;
    IPSECSA                 pxIPsecSa   = pxXg->pxIPsecSa;

    intBoolean              bInitiator  = IS_XCHG_INITIATOR(pxXg);

    diffieHellmanContext*   pDHctx      = NULL;
    vlong*                  pMpintE     = NULL;
    vlong*                  pVlongQueue = NULL;

#ifdef __ENABLE_DIGICERT_ECC__
    ECCKey*                 pEccKey     = NULL;
    ubyte4                  curveId     = 0;
    ubyte*                  pPoint      = NULL;
    ubyte4                  pointLen    = 0;
#endif

#ifdef __ENABLE_DIGICERT_PQC__
    QS_CTX*                 pQsCtx      = NULL;
    ubyte*                  pQsPubKey   = NULL;
    ubyte4                  qsPubKeyLen = 0;
#endif

    ubyte2                  wGroup;

    /* KE payload header */
    IN_BEGIN(struct ikeKeHdr, pxKeHdr, SIZEOF_IKE_ID_HDR)

    if (IKE_CNTXT_FLAG_KE & ctx->flags) /* already received KE payload */
    {
        status = ERR_IKE_BAD_KE;
        DBG_EXIT
    }

    SET_NTOHS(wGroup, pxKeHdr->wGrpNo);

    if (bInitiator)
    {
        /* check DH group */
        ubyte2 wGrpNo = (pxSa ? pxSa->wDhGrp : pxIPsecSa->wPFS);

        if ((0 == wGrpNo) || /* no KE payload is needed */
            (wGroup != wGrpNo)) /* mismatch */
        {
            status = ERR_IKE_BAD_KE;
            DBG_EXIT
        }

        /* get DH context */
        pDHctx = (pxSa ? DIFFIEHELLMAN_CONTEXT(pxSa) : DIFFIEHELLMAN_CONTEXT(pxIPsecSa));
        if (NULL != pDHctx)
        {
            /* jic re-transmit */
            if (NULL != pxSa)
            {
                if (NULL != pxSa->pDhPeerPubKey)
                {
                    DIGI_FREE((void **)&(pxSa->pDhPeerPubKey));
                    pxSa->pDhPeerPubKey = NULL;
                }
                if (NULL != pxSa->pDhSharedSecret)
                {
                    DIGI_MEMSET(pxSa->pDhSharedSecret, 0, pxSa->dhSharedSecretLen);
                    DIGI_FREE((void **)&(pxSa->pDhSharedSecret));
                    pxSa->pDhSharedSecret = NULL;
                    pxSa->dhSharedSecretLen = 0;
                }
            }
            else
            {
                if (NULL != pxIPsecSa->pDhPeerPubKey)
                {
                    DIGI_FREE((void **)&(pxIPsecSa->pDhPeerPubKey));
                    pxIPsecSa->pDhPeerPubKey = NULL;
                }
                if (NULL != pxIPsecSa->pDhSharedSecret)
                {
                    DIGI_MEMSET(pxIPsecSa->pDhSharedSecret, 0, pxIPsecSa->dhSharedSecretLen);
                    DIGI_FREE((void **)&(pxIPsecSa->pDhSharedSecret));
                    pxIPsecSa->pDhSharedSecret = NULL;
                    pxIPsecSa->dhSharedSecretLen = 0;
                }
            }
        }
        else
        {
#ifdef __ENABLE_DIGICERT_ECC__
            pEccKey = (pxSa ? pxSa->p_eccKey : pxIPsecSa->p_eccKey);
            if (NULL == pEccKey)
#endif
            {
                /* jic - redundant? */
                status = ERR_IKE_BAD_KE;
                DBG_EXIT
            }

#ifdef __ENABLE_DIGICERT_PQC__
            pQsCtx = (pxSa ? pxSa->pQsCtx : pxIPsecSa->pQsCtx);
#endif
        }
    }
    else /* responder */
    {
        /* create DH context */
        diffieHellmanContext **ppDHctx = (pxSa ?
                                        &(DIFFIEHELLMAN_CONTEXT(pxSa)) :
                                        &(DIFFIEHELLMAN_CONTEXT(pxIPsecSa)));
#ifdef __ENABLE_DIGICERT_ECC__
        ECCKey **ppEccKey = (pxSa ? &pxSa->p_eccKey : &pxIPsecSa->p_eccKey);
#endif

#ifdef __ENABLE_DIGICERT_PQC__
        QS_CTX **ppQsCtx = (pxSa ? &pxSa->pQsCtx : &pxIPsecSa->pQsCtx);
#endif
        /* set DH group */
        IKE_dhGroupInfo *pGroup = IKE_dhGroupEx(ctx->pxSa->ikePeerConfig, wGroup);

        if (!pGroup || !wGroup ||
            IKE_checkGroup(wGroup, FALSE, ctx->pxSa, pxSa, pxIPsecSa))
        {
            ctx->wMsgType = INVALID_KE_PAYLOAD;
            status = ERR_IKE_BAD_KE;
            DBG_EXIT
        }

        if (pxSa) pxSa->wDhGrp = wGroup;
        else pxIPsecSa->wPFS = wGroup;

        /* clean up and create */
        if (NULL != *ppDHctx)
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            CRYPTO_INTERFACE_DH_freeDhContextExt(ppDHctx, NULL, NULL);
#else
            DH_freeDhContext(ppDHctx, NULL);
#endif
         }


#ifdef __ENABLE_DIGICERT_ECC__
        if (NULL != *ppEccKey)
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            CRYPTO_INTERFACE_EC_deleteKeyAux(ppEccKey);
#else
            EC_deleteKey(ppEccKey);
#endif
        }

#ifdef __ENABLE_DIGICERT_PQC__
        if (NULL != *ppQsCtx)
        {
            CRYPTO_INTERFACE_QS_deleteCtx(ppQsCtx);
        }
#endif

        if (0 < pGroup->curveId)
        {
            curveId = pGroup->curveId;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_EC_generateKeyPairAllocAux(MOC_ECC(ctx->hwAccelCookie) curveId, ppEccKey, RANDOM_rngFun, g_pRandomContext);
            if (OK != status)
                goto exit;
#else
            status = EC_generateKeyPairAlloc(MOC_ECC(ctx->hwAccelCookie) curveId, ppEccKey, RANDOM_rngFun, g_pRandomContext);
            if (OK != status)
                goto exit;
#endif

            pEccKey = *ppEccKey;

#ifdef __ENABLE_DIGICERT_PQC__
            if (0 < pGroup->qsAlgoId)
            {
                status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(ctx->hwAccelCookie) &pQsCtx, pGroup->qsAlgoId);
                if (OK != status)
                    DBG_EXIT

                *ppQsCtx = pQsCtx;
            }
#endif
        }
        else
#endif
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            if (OK > (status = CRYPTO_INTERFACE_DH_allocateServerExt(MOC_DH(ctx->hwAccelCookie)
                                                 g_pRandomContext, ppDHctx,
                                                 pGroup->dwGroupNum, NULL)))
                DBG_EXIT
#else
            if (OK > (status = DH_allocateServer(MOC_DH(ctx->hwAccelCookie)
                                                 g_pRandomContext, ppDHctx,
                                                 pGroup->dwGroupNum)))
                DBG_EXIT
#endif

            pDHctx = *ppDHctx;
        }
    }

    /* key exchange data */
#ifdef __ENABLE_DIGICERT_ECC__
    if (NULL != pEccKey)
    {
        ubyte** ppSharedSecret = (pxSa ? &pxSa->poEccSharedSecret : &pxIPsecSa->poEccSharedSecret);
        sbyte4* pSharedSecretLen = (pxSa ? &pxSa->eccSharedSecretLen : &pxIPsecSa->eccSharedSecretLen);
        ubyte4 eccPubKeyLen = 0;


        if (NULL != *ppSharedSecret) /* jic */
        {
            FREE(*ppSharedSecret);
            *ppSharedSecret = NULL;
            *pSharedSecretLen = 0;
        }
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pEccKey, &curveId);
                    if (OK != status)
                        DBG_EXIT
#else
        status = EC_getCurveIdFromKey(pEccKey, &curveId);
                    if (OK != status)
                        DBG_EXIT
#endif

#if defined (__ENABLE_DIGICERT_ECC_EDDH_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDH_448__)
        if((cid_EC_X25519 == curveId) || (cid_EC_X448 == curveId))
        {
            status = DIGI_MALLOC((void **)&pPoint, (ubyte4)(wBodyLen));
            if (OK != status)
                DBG_EXIT

            pointLen = (ubyte4)(wBodyLen);
            status = DIGI_MEMCPY (
                 pPoint, (void *)ctx->pBuffer, (ubyte4)wBodyLen);
            if (OK != status)
                goto exit;
        }
        else
#endif
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_EC_getPointByteStringLenByCurveId(curveId, &eccPubKeyLen);
#else
            status = EC_getPointByteStringLenByCurveId(curveId, &eccPubKeyLen);
#endif
            if (OK != status)
                DBG_EXIT

            status = DIGI_MALLOC((void **)&pPoint, (ubyte4)(eccPubKeyLen));
            if (OK != status)
                DBG_EXIT

            pPoint[0] = 0x04;
            pointLen = (ubyte4)(eccPubKeyLen);

            status = DIGI_MEMCPY (
                 pPoint + 1, (void *)ctx->pBuffer, (ubyte4)eccPubKeyLen - 1);
            if (OK != status)
                goto exit;
        }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux (MOC_ECC(ctx->hwAccelCookie)
            pEccKey, pPoint, pointLen, ppSharedSecret, (ubyte4 *) pSharedSecretLen,
            (IKE_SETTINGS_FLAG_ECDH_XY & m_ikeSettings.flags) ? 0 : 1, NULL);
        if (OK != status)
            DBG_EXIT
#else
        status = ECDH_generateSharedSecretFromPublicByteString (MOC_ECC(ctx->hwAccelCookie)
            pEccKey, pPoint, pointLen, ppSharedSecret, (ubyte4 *) pSharedSecretLen,
            (IKE_SETTINGS_FLAG_ECDH_XY & m_ikeSettings.flags) ? 0 : 1, NULL);
        if (OK != status)
            DBG_EXIT
#endif

#ifdef __ENABLE_DIGICERT_PQC__
        if (NULL != pQsCtx)
        {
            ubyte** ppQsSharedSecret = (pxSa ? &pxSa->pQsSharedSecret : &pxIPsecSa->pQsSharedSecret);
            ubyte4* pQsSharedSecretLen = (pxSa ? &pxSa->qsSharedSecretLen : &pxIPsecSa->qsSharedSecretLen);

            ubyte** ppQsCipherText = (pxSa ? &pxSa->pQsCipherText : &pxIPsecSa->pQsCipherText);
            ubyte4* pQsCipherTextLen = (pxSa ? &pxSa->qsCipherTextLen : &pxIPsecSa->qsCipherTextLen);

            ubyte* pCombinedSecret = NULL;
            ubyte4 combinedSecretLen = 0;

            /* initiator sends public key, responder sends cipher text encrypted
             * with public key. */
            if (bInitiator)
            {
                *pQsCipherTextLen = wBodyLen - eccPubKeyLen + 1;
                status = DIGI_MALLOC ((void **) ppQsCipherText, *pQsCipherTextLen);
                if (OK != status)
                    DBG_EXIT

                status = DIGI_MEMCPY (*ppQsCipherText, ctx->pBuffer + eccPubKeyLen - 1, *pQsCipherTextLen);
                if (OK != status)
                    DBG_EXIT

                status = CRYPTO_INTERFACE_QS_KEM_decapsulateAlloc (pQsCtx, *ppQsCipherText,
                    *pQsCipherTextLen, ppQsSharedSecret, pQsSharedSecretLen);
                if (OK != status)
                    DBG_EXIT
            }
            else
            {
                qsPubKeyLen = wBodyLen - eccPubKeyLen + 1;
                status = DIGI_MALLOC ((void **) &pQsPubKey, qsPubKeyLen);
                if (OK != status)
                    DBG_EXIT

                status = DIGI_MEMCPY (pQsPubKey, ctx->pBuffer + eccPubKeyLen - 1, qsPubKeyLen);
                if (OK != status)
                {
                    DIGI_FREE((void **) &pQsPubKey);
                    DBG_EXIT
                }

                status = CRYPTO_INTERFACE_QS_setPublicKey(pQsCtx, pQsPubKey, qsPubKeyLen);
                if (OK != status)
                {
                    DIGI_FREE((void **) &pQsPubKey);
                    DBG_EXIT
                }


                status = CRYPTO_INTERFACE_QS_KEM_encapsulateAlloc(pQsCtx, RANDOM_rngFun,
                    g_pRandomContext, ppQsCipherText, pQsCipherTextLen,
                    ppQsSharedSecret, pQsSharedSecretLen);
                if (OK != status)
                {
                    DIGI_FREE((void **) &pQsPubKey);
                    DBG_EXIT
                }

                DIGI_FREE((void **) &pQsPubKey);
            }

            /* add qs secret to the end of ecc buffer */
            combinedSecretLen = *pQsSharedSecretLen + *pSharedSecretLen;
            status = DIGI_MALLOC ((void **) &pCombinedSecret, combinedSecretLen);
            if (OK != status)
                DBG_EXIT

            status = DIGI_MEMCPY (pCombinedSecret, *ppSharedSecret, *pSharedSecretLen);
            if (OK != status)
                DBG_EXIT

            status = DIGI_MEMCPY (pCombinedSecret + *pSharedSecretLen, *ppQsSharedSecret, *pQsSharedSecretLen);
            if (OK != status)
                DBG_EXIT

            DIGI_FREE((void **) ppSharedSecret);
            DIGI_FREE((void **) ppQsSharedSecret);

            *ppSharedSecret = pCombinedSecret;
            *pSharedSecretLen = combinedSecretLen;
        }
#endif
    }
    else
#endif
    {
        if (NULL == pDHctx) /* jic */
        {
            status = ERR_NULL_POINTER;
            DBG_EXIT
        }

        if (NULL != pxSa)
        {
            status = DIGI_MALLOC((void **)(&(pxSa->pDhPeerPubKey)), (ubyte4)wBodyLen);
            if (OK != status)
                goto exit;

            /* Save the client public key */
            status = DIGI_MEMCPY (
                (void *)pxSa->pDhPeerPubKey, (void *)ctx->pBuffer, (ubyte4)wBodyLen);
            if (OK != status)
                goto exit;

            pxSa->dhPeerPubKeyLen = (ubyte4)wBodyLen;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_DH_computeKeyExchangeExExt (MOC_DH(ctx->hwAccelCookie)
                pDHctx, g_pRandomContext, ctx->pBuffer, (ubyte4)wBodyLen,
                &(pxSa->pDhSharedSecret), &(pxSa->dhSharedSecretLen), NULL);
            if (OK != status)
                DBG_EXIT
#else
            status = DH_computeKeyExchangeEx (MOC_DH(ctx->hwAccelCookie)
                pDHctx, g_pRandomContext, ctx->pBuffer, (ubyte4)wBodyLen,
                &(pxSa->pDhSharedSecret), &(pxSa->dhSharedSecretLen));
            if (OK != status)
                DBG_EXIT
#endif
        }
        else
        {
            status = DIGI_MALLOC((void **)(&(pxIPsecSa->pDhPeerPubKey)), (ubyte4)wBodyLen);
            if (OK != status)
                goto exit;

            /* Save the client public key */
            status = DIGI_MEMCPY (
                (void *)pxIPsecSa->pDhPeerPubKey, (void *)ctx->pBuffer, (ubyte4)wBodyLen);
            if (OK != status)
                goto exit;

            pxIPsecSa->dhPeerPubKeyLen = (ubyte4)wBodyLen;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_DH_computeKeyExchangeExExt (MOC_DH(ctx->hwAccelCookie)
                pDHctx, g_pRandomContext, ctx->pBuffer, (ubyte4)wBodyLen,
                &(pxIPsecSa->pDhSharedSecret), &(pxIPsecSa->dhSharedSecretLen), NULL);
            if (OK != status)
                DBG_EXIT
#else
            status = DH_computeKeyExchangeEx (MOC_DH(ctx->hwAccelCookie)
                pDHctx, g_pRandomContext, ctx->pBuffer, (ubyte4)wBodyLen,
                &(pxIPsecSa->pDhSharedSecret), &(pxIPsecSa->dhSharedSecretLen));
            if (OK != status)
                DBG_EXIT
#endif
        }
    }

    ctx->flags |= IKE_CNTXT_FLAG_KE;

    /* done */
    IN_END

exit:
    VLONG_freeVlong(&pMpintE, NULL);
    VLONG_freeVlongQueue(&pVlongQueue);
#ifdef __ENABLE_DIGICERT_ECC__
    if(pPoint)
        DIGI_FREE((void **) &pPoint);
#endif

    return status;
} /* InKe */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SP800_135_ACVP__
extern MSTATUS
#else
static MSTATUS
#endif
DoKe(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA  pxSaO = ctx->pxSa;
    IKE2XG pxXg  = ctx->pxXg;
    IKESA  pxSa  = pxXg->pxSa;
#ifdef __ENABLE_IKE_PPK_RFC8784__
    struct ikePeerConfig *pPeerConfig = pxSa->ikePeerConfig;
#endif
    /* get old IKE_SA's PRF - see RFC4718 5.5 (p26) */
    const BulkHashAlgo *pBHAlgo = pxSaO->pHashSuite->pBHAlgo;
    const BulkPrfAlgo *pBPAlgo = pxSaO->pHashSuite->pBPAlgo;
    ubyte2 wDigestLen = (ubyte2) (pBHAlgo ? pBHAlgo->digestSize : pBPAlgo->digestSize);

    ubyte2 saltLen = 0;

    if (NULL != pxSa->pCipherSuite->pAeadAlgo)
    {
        saltLen = pxSa->pCipherSuite->pAeadAlgo->implicitNonceSize;
    }

    /* when using an AEAD algorithm, we need to get additional bytes
     * for the salt. */
    ubyte2 wEncrKeyLen = pxSa->wEncrKeyLen;
    ubyte2 wAuthKeyLen = pxSa->wAuthKeyLen;

    ubyte2 wSKLen;
    ubyte __crypto__(SK_seed, IKE_HASH_MAX);
    ubyte* __crypto_i__(SK, pxSa->u.v2.SK); /*IKE_HASH_MAX*3 + IKE_AUTHKEY_MAX*2 + IKE_ENCRKEY_MAX*2);*/

    HMAC_CTX *hmacCtxt = NULL;
    BulkCtx prfCtx = NULL;

    /* get DH shared secret byte strings */
    sbyte4 stringLenK = 0;
    ubyte* pStringMpintK = NULL; /* DH shared secret */

    diffieHellmanContext *pDHctx = DIFFIEHELLMAN_CONTEXT(pxSa);
    if (pDHctx)
    {
        pStringMpintK = pxSa->pDhSharedSecret;
        stringLenK = pxSa->dhSharedSecretLen;
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if (pxSa->p_eccKey)
    {
        pStringMpintK = pxSa->poEccSharedSecret;
        stringLenK = pxSa->eccSharedSecretLen;
    }
#endif

    /* get PRF */
    if (pBHAlgo && (OK > (status = HmacCreate(MOC_HASH(ctx->hwAccelCookie) &hmacCtxt, pBHAlgo))))
    {
        DBG_EXIT
    }

    if (pBPAlgo && (OK > (status = pBPAlgo->allocFunc(MOC_HASH(ctx->hwAccelCookie) &prfCtx))))
    {
        DBG_EXIT
    }

    if (!hmacCtxt && !prfCtx) /* jic */
    {
        status = ERR_IKE;
        DBG_EXIT
    }

    /* get SKEYSEED */
    _CRYPTO_ALLOC_(SK_seed, IKE_HASH_MAX)

    if (pxSa == pxSaO)
    {
        /* prf(Ni | Nr, g^ir) */
        ubyte2 wKeyLen = pxSa->wNonceLen[_I] + pxSa->wNonceLen[_R];
        ubyte *poKey;
        CHECK_MALLOC(poKey, wKeyLen)

        if (hmacCtxt)
        {
            DIGI_MEMCPY(poKey, pxSa->poNonce[_I], pxSa->wNonceLen[_I]);
            DIGI_MEMCPY(poKey + pxSa->wNonceLen[_I], pxSa->poNonce[_R], pxSa->wNonceLen[_R]);
            status = HmacKey(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poKey, wKeyLen);
        }
        else
        {
            /* AES-XCBC-PRF takes a fixed-length key here! See RFC4434 and RFC4306 2.14. */
            wKeyLen = (ubyte2) pBPAlgo->digestSize;
            DIGI_MEMCPY(poKey, pxSa->poNonce[_I], wKeyLen/2);
            DIGI_MEMCPY(poKey + (wKeyLen/2), pxSa->poNonce[_R], wKeyLen/2);
            status = pBPAlgo->initFunc(MOC_SYM(ctx->hwAccelCookie) poKey, wKeyLen, prfCtx);
        }

        FREE(poKey);
        if (OK > status) DBG_EXIT

        if (hmacCtxt)
        {
            if ((OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pStringMpintK, stringLenK))) ||
                (OK > (status = HmacFinal(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, SK_seed))))
                DBG_EXIT
        }
        else
        {
            if ((OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) pStringMpintK, stringLenK, prfCtx))) ||
                (OK > (status = pBPAlgo->finalFunc(MOC_SYM(ctx->hwAccelCookie) SK_seed, prfCtx))))
                DBG_EXIT
        }
    }
    else /* Rekeying IKE_SA */
    {
        /* prf(SK_d (old), [g^ir (new)] | Ni | Nr) */
        if (hmacCtxt)
        {
            if ((OK > (status = HmacKey(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSaO->u.v2.SK_d, wDigestLen))) ||
                (pStringMpintK &&
                 (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pStringMpintK, stringLenK)))) ||
                (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->poNonce[_I], pxSa->wNonceLen[_I]))) ||
                (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->poNonce[_R], pxSa->wNonceLen[_R]))) ||
                (OK > (status = HmacFinal(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, SK_seed))))
                DBG_EXIT
        }
        else
        {
            if ((OK > (status = pBPAlgo->initFunc(MOC_SYM(ctx->hwAccelCookie) pxSaO->u.v2.SK_d, wDigestLen, prfCtx))) ||
                (pStringMpintK &&
                 (OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) pStringMpintK, stringLenK, prfCtx)))) ||
                (OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) pxSa->poNonce[_I], pxSa->wNonceLen[_I], prfCtx))) ||
                (OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) pxSa->poNonce[_R], pxSa->wNonceLen[_R], prfCtx))) ||
                (OK > (status = pBPAlgo->finalFunc(MOC_SYM(ctx->hwAccelCookie) SK_seed, prfCtx))))
                DBG_EXIT
        }
    }

    debug_printk((sbyte *)"    SKEYSEED", SK_seed, wDigestLen);

    /* {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr }
        = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr )

       prf+ (K,S) = T1 | T2 | T3 | T4 | ...
       where:
        T1 = prf (K, S | 0x01)
        T2 = prf (K, T1 | S | 0x02)
        T3 = prf (K, T2 | S | 0x03)
        T4 = prf (K, T3 | S | 0x04)
    */
    if ((hmacCtxt &&
         (OK > (status = HmacKey(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, SK_seed, wDigestLen)))) ||
        (prfCtx &&
         (OK > (status = pBPAlgo->initFunc(MOC_SYM(ctx->hwAccelCookie) SK_seed, wDigestLen, prfCtx)))))
    {
        DBG_EXIT
    }

    if (!wEncrKeyLen)
    {
        if (0 == (wEncrKeyLen = pxSa->pCipherSuite->wKeyLenEnd))
            wEncrKeyLen = pxSa->pCipherSuite->wKeyLen;
    }

    /* add salt length after retrieving key length */
    wEncrKeyLen += saltLen;

    if (!wAuthKeyLen && (NULL != pxSa->pMacSuite)) wAuthKeyLen = pxSa->pMacSuite->wKeyLen;

    wSKLen = (2 * (wAuthKeyLen + wEncrKeyLen)) + (3 * wDigestLen);

#ifdef __ENABLE_DIGICERT_SP800_135_ACVP__
    /* Some test vectors may request more than wSKLen bytes */
    if (g_dkmLen > wSKLen)
        wSKLen = g_dkmLen;

    if (NULL != g_pSKeySeed)
    {
        DIGI_FREE((void **)&g_pSKeySeed);
    }

    status = DIGI_MALLOC((void **)&g_pSKeySeed, wDigestLen);
    if (OK != status)
    {
        DBG_EXIT
    }

    status = DIGI_MEMCPY((void *)g_pSKeySeed, SK_seed, wDigestLen);
    if (OK != status)
    {
        DBG_EXIT
    }

    g_sKeySeedLen = wDigestLen;
#endif

    _CRYPTO_ALLOC_(SK, wSKLen + wDigestLen)
    {
        ubyte *poSK = /*pxSa->u.v2.*/SK;
        ubyte2 len = wSKLen;
        ubyte i = 0x01;
        for (;;)
        {
            if (hmacCtxt)
            {
                if ((OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->poNonce[_I], pxSa->wNonceLen[_I]))) ||
                    (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->poNonce[_R], pxSa->wNonceLen[_R]))) ||
                    (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->poCky_I, IKE_COOKIE_SIZE))) ||
                    (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->poCky_R, IKE_COOKIE_SIZE))) ||
                    (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, &i, 1))) ||
                    (OK > (status = HmacFinal(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poSK))))
                    DBG_EXIT
            }
            else
            {
                if ((OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) pxSa->poNonce[_I], pxSa->wNonceLen[_I], prfCtx))) ||
                    (OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) pxSa->poNonce[_R], pxSa->wNonceLen[_R], prfCtx))) ||
                    (OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) pxSa->poCky_I, IKE_COOKIE_SIZE, prfCtx))) ||
                    (OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) pxSa->poCky_R, IKE_COOKIE_SIZE, prfCtx))) ||
                    (OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) &i, 1, prfCtx))) ||
                    (OK > (status = pBPAlgo->finalFunc(MOC_SYM(ctx->hwAccelCookie) poSK, prfCtx))))
                    DBG_EXIT
            }

            if (len <= wDigestLen) break;
            len = len - wDigestLen;

            if (hmacCtxt)
            {
                if (OK > (status = HmacReset(MOC_HASH(ctx->hwAccelCookie) hmacCtxt)) ||
                    OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poSK, wDigestLen)))
                    DBG_EXIT
            }
            else
            {
                if (OK > (status = pBPAlgo->initFunc(MOC_SYM(ctx->hwAccelCookie) SK_seed, wDigestLen, prfCtx)) ||
                    OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) poSK, wDigestLen, prfCtx)))
                    DBG_EXIT
            }

            poSK += wDigestLen;
            i = (ubyte)(i + 1);
        } /* for (;;) */

#ifdef __ENABLE_DIGICERT_HARNESS__
        DIGI_MEMCPY(pxSa->u.v2.SK, SK, wSKLen);
#endif
        poSK = pxSa->u.v2.SK;
#ifdef __ENABLE_IKE_PPK_RFC8784__
        if ((pxSa == pxSaO) && (pxSa->flags & IKE_SA_FLAG_USEPPK) && (pPeerConfig->ppk_id))
        {
            i = 0x01;
            if (hmacCtxt)
            {
                 if((OK > (status = HmacKey(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pPeerConfig->ppk_psk, pPeerConfig->ppk_psk_len))) || 
                    (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poSK, wDigestLen))) ||
                    (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, &i, 1))) ||
                    (OK > (status = HmacFinal(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poSK))))
                        DBG_EXIT
    
            }
            else
            {
                 if((OK > (status = pBPAlgo->initFunc(MOC_SYM(ctx->hwAccelCookie) pPeerConfig->ppk_psk, pPeerConfig->ppk_psk_len, prfCtx))) ||
                    (OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) poSK, wDigestLen, prfCtx))) ||
                    (OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) &i, 1, prfCtx))) ||
                    (OK > (status = pBPAlgo->finalFunc(MOC_SYM(ctx->hwAccelCookie) poSK, prfCtx))))
                        DBG_EXIT
            }
        }
#endif   /*  __ENABLE_IKE_PPK_RFC8784__ */
        pxSa->u.v2.SK_d = poSK;
        debug_printk((sbyte *)"    SK_d", poSK, wDigestLen);

        poSK += wDigestLen;
        pxSa->u.v2.SK_a[_I] = poSK;
        debug_printk((sbyte *)"    SK_ai", poSK, wAuthKeyLen);

        poSK += wAuthKeyLen;
        pxSa->u.v2.SK_a[_R] = poSK;
        debug_printk((sbyte *)"    SK_ar", poSK, wAuthKeyLen);

        poSK += wAuthKeyLen;
        pxSa->u.v2.SK_e[_I] = poSK;
        debug_printk((sbyte *)"    SK_ei", poSK, wEncrKeyLen);

        poSK += wEncrKeyLen;
        pxSa->u.v2.SK_e[_R] = poSK;
        debug_printk((sbyte *)"    SK_er", poSK, wEncrKeyLen);

        poSK += wEncrKeyLen;
#ifdef __ENABLE_IKE_PPK_RFC8784__
        if ((pxSa == pxSaO) && (pxSa->flags & IKE_SA_FLAG_USEPPK) && (pPeerConfig->ppk_id))
        {
            i = 0x01;
            if (hmacCtxt)
            {
                 if((OK > (status = HmacKey(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pPeerConfig->ppk_psk, pPeerConfig->ppk_psk_len))) || 
                    (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poSK, wDigestLen))) ||
                    (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, &i, 1))) ||
                    (OK > (status = HmacFinal(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poSK))))
                        DBG_EXIT
    
            }
            else
            {
                 if((OK > (status = pBPAlgo->initFunc(MOC_SYM(ctx->hwAccelCookie) pPeerConfig->ppk_psk, pPeerConfig->ppk_psk_len, prfCtx))) ||
                    (OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) poSK, wDigestLen, prfCtx))) ||
                    (OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) &i, 1, prfCtx))) ||
                    (OK > (status = pBPAlgo->finalFunc(MOC_SYM(ctx->hwAccelCookie) poSK, prfCtx))))
                        DBG_EXIT
            }
        }
#endif /*  __ENABLE_IKE_PPK_RFC8784__ */
        pxSa->u.v2.SK_p[_I] = poSK;
        debug_printk((sbyte *)"    SK_pi", poSK, wDigestLen);

        poSK += wDigestLen;
#ifdef __ENABLE_IKE_PPK_RFC8784__
        if ((pxSa == pxSaO) && (pxSa->flags & IKE_SA_FLAG_USEPPK) && (pPeerConfig->ppk_id))
        {
            i = 0x01;
            if (hmacCtxt)
            {
                 if((OK > (status = HmacKey(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pPeerConfig->ppk_psk, pPeerConfig->ppk_psk_len))) || 
                    (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poSK, wDigestLen))) ||
                    (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, &i, 1))) ||
                    (OK > (status = HmacFinal(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poSK))))
                        DBG_EXIT
    
            }
            else
            {
                 if((OK > (status = pBPAlgo->initFunc(MOC_SYM(ctx->hwAccelCookie) pPeerConfig->ppk_psk, pPeerConfig->ppk_psk_len, prfCtx))) ||
                    (OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) poSK, wDigestLen, prfCtx))) ||
                    (OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) &i, 1, prfCtx))) ||
                    (OK > (status = pBPAlgo->finalFunc(MOC_SYM(ctx->hwAccelCookie) poSK, prfCtx))))
                        DBG_EXIT
            }
        }
#endif /*  __ENABLE_IKE_PPK_RFC8784__ */
        pxSa->u.v2.SK_p[_R] = poSK;
        debug_printk((sbyte *)"    SK_pr", poSK, wDigestLen);
    }

exit:
    _CRYPTO_FREE_(SK)
    _CRYPTO_FREE_(SK_seed)
    if (prfCtx) pBPAlgo->freeFunc(MOC_HASH(ctx->hwAccelCookie) &prfCtx);
    if (hmacCtxt) HmacDelete(MOC_HASH(ctx->hwAccelCookie) &hmacCtxt);
#ifdef __ENABLE_DIGICERT_ECC__
    if (pStringMpintK == pxSa->poEccSharedSecret)
    {
        /* zeroize immediately; see RFC6380 7. */
        DIGI_MEMSET(pStringMpintK, 0x00, stringLenK);
        pxSa->poEccSharedSecret = NULL;
        pxSa->eccSharedSecretLen = 0;
    }
#endif
    if (pStringMpintK == pxSa->pDhSharedSecret)
    {
        /* zeroize immediately; see RFC6380 7. */
        DIGI_MEMSET(pStringMpintK, 0x00, stringLenK);
        pxSa->pDhSharedSecret = NULL;
        pxSa->dhSharedSecretLen = 0;
    }
     CHECK_FREE(pStringMpintK)

    return status;
} /* DoKe */


/*------------------------------------------------------------------*/

static MSTATUS
GetMacedID(IKE_context ctx, sbyte4 dir, ubyte *poHash, ubyte2 wDigestLen,
           HMAC_CTX *hmacCtxt, BulkCtx prfCtx, const BulkPrfAlgo *pBPAlgo)
{
    MSTATUS status;

    IKESA pxSa = ctx->pxSa;

    if ((hmacCtxt &&
         (OK > (status = HmacKey(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->u.v2.SK_p[dir], wDigestLen)))) ||
        (prfCtx &&
         (OK > (status = pBPAlgo->initFunc(MOC_SYM(ctx->hwAccelCookie) pxSa->u.v2.SK_p[dir], wDigestLen, prfCtx)))))
    {
        DBG_EXIT
    }
    else
    {
        struct ikeIdHdr *pxId = pxSa->pxID[dir];
        ubyte2 wIdLen = GET_NTOHS(pxId->wLength);

        if (hmacCtxt)
        {
            if ((OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt,
                                           (ubyte *)pxId + SIZEOF_IKE_GEN_HDR,
                                           wIdLen - SIZEOF_IKE_GEN_HDR))) ||
                (OK > (status = HmacFinal(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poHash))))
                DBG_EXIT
        }
        else
        {
            if ((OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie)
                                                    (ubyte *)pxId + SIZEOF_IKE_GEN_HDR,
                                                    wIdLen - SIZEOF_IKE_GEN_HDR, prfCtx))) ||
                (OK > (status = pBPAlgo->finalFunc(MOC_SYM(ctx->hwAccelCookie) poHash, prfCtx))))
                DBG_EXIT
        }
    }

    debug_printk((sbyte *)((_I==dir) ? "    prf(SK_pi,IDi')" : "    prf(SK_pr,IDr')"), poHash, wDigestLen);

exit:
    return status;
} /* GetMacedID */


/*------------------------------------------------------------------*/

static MSTATUS
DoAuthSk(IKE_context ctx, ubyte *poHash, ubyte2 wBodyLen,
         ubyte *poSs, ubyte4 dwSsLen, intBoolean bIn)
{
    MSTATUS status;

    IKESA pxSa = ctx->pxSa;
    intBoolean bInitiator = IS_INITIATOR(pxSa);
    sbyte4 dir = ((bIn && !bInitiator) || (!bIn && bInitiator))
                 ? _I : _R;

    ubyte __crypto__(poMacedID, IKE_HASH_MAX);

    const BulkHashAlgo *pBHAlgo = pxSa->pHashSuite->pBHAlgo;
    const BulkPrfAlgo *pBPAlgo = pxSa->pHashSuite->pBPAlgo;

    HMAC_CTX *hmacCtxt = NULL;
    BulkCtx prfCtx = NULL;

    /* auth. data length */
    ubyte2 wDigestLen;
    if (bIn)
    {
        wDigestLen = (ubyte2) (pBHAlgo ? pBHAlgo->digestSize : pBPAlgo->digestSize);
        if (wDigestLen != wBodyLen)
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }
    }
    else
    {
        wDigestLen = wBodyLen;
    }

    /* get PRF */
    if (pBHAlgo && (OK > (status = HmacCreate(MOC_HASH(ctx->hwAccelCookie) &hmacCtxt, pBHAlgo))))
    {
        DBG_EXIT
    }

    if (pBPAlgo && (OK > (status = pBPAlgo->allocFunc(MOC_HASH(ctx->hwAccelCookie) &prfCtx))))
    {
        DBG_EXIT
    }

    if (!hmacCtxt && !prfCtx) /* jic */
    {
        status = ERR_IKE;
        DBG_EXIT
    }

    /* prf(prf(Shared Secret,"Key Pad for IKEv2"), <msg octets>)

       <msg octets> =
        2nd message | Ni | prf(SK_pr,IDr') for responder
        OR
        1st message | Nr | prf(SK_pi,IDi') for initiator
    */

    /* prf(SK_pr,IDr') or  prf(SK_pi,IDi')*/
    _CRYPTO_ALLOC_(poMacedID, IKE_HASH_MAX)
    if (OK > (status = GetMacedID(ctx, dir, poMacedID, wDigestLen, hmacCtxt, prfCtx, pBPAlgo)))
        goto exit;

    /* prf(Shared Secret,"Key Pad for IKEv2") */
    if (hmacCtxt)
    {
        if ((OK > (status = HmacKey(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poSs, dwSsLen))) ||
            (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, (ubyte *)"Key Pad for IKEv2", 17))) ||
            (OK > (status = HmacFinal(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poHash))))
            DBG_EXIT
    }
    else
    {
        if ((OK > (status = pBPAlgo->initFunc(MOC_SYM(ctx->hwAccelCookie) poSs, dwSsLen, prfCtx))) ||
            (OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) (ubyte *)"Key Pad for IKEv2", 17, prfCtx))) ||
            (OK > (status = pBPAlgo->finalFunc(MOC_SYM(ctx->hwAccelCookie) poHash, prfCtx))))
            DBG_EXIT
    }

    debug_printk((sbyte *)"    prf(SS,\"*\")", poHash, wDigestLen);

    /* calculate authentication data */
    if (hmacCtxt)
    {
        if ((OK > (status = HmacKey(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poHash, wDigestLen))) ||
            (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->poMsg[dir], pxSa->dwMsgLen[dir]))) ||
            (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->poNonce[!dir], pxSa->wNonceLen[!dir]))) ||
            (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poMacedID, wDigestLen))) ||
            (OK > (status = HmacFinal(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poHash))))
            DBG_EXIT
    }
    else
    {
        if ((OK > (status = pBPAlgo->initFunc(MOC_SYM(ctx->hwAccelCookie) poHash, wDigestLen, prfCtx))) ||
            (OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) pxSa->poMsg[dir], pxSa->dwMsgLen[dir], prfCtx))) ||
            (OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) pxSa->poNonce[!dir], pxSa->wNonceLen[!dir], prfCtx))) ||
            (OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) poMacedID, wDigestLen, prfCtx))) ||
            (OK > (status = pBPAlgo->finalFunc(MOC_SYM(ctx->hwAccelCookie) poHash, prfCtx))))
            DBG_EXIT
    }

    debug_printd((sbyte *)((_I==dir) ? "   AUTH_i" : "   AUTH_r"), poHash, wDigestLen);

exit:
    if (prfCtx) pBPAlgo->freeFunc(MOC_HASH(ctx->hwAccelCookie) &prfCtx);
    if (hmacCtxt) HmacDelete(MOC_HASH(ctx->hwAccelCookie) &hmacCtxt);
    _CRYPTO_FREE_(poMacedID)
    return status;
} /* DoAuthSk */


/*------------------------------------------------------------------*/

static MSTATUS
DoAuthSig(IKE_context ctx, ubyte *poHash,
          const BulkHashAlgo *pSigBHAlgo,
          intBoolean bIn)
{
    MSTATUS status;

    IKESA pxSa = ctx->pxSa;
    intBoolean bInitiator = IS_INITIATOR(pxSa);
    sbyte4 dir = ((bIn && !bInitiator) || (!bIn && bInitiator))
                 ? _I : _R;

    ubyte __crypto__(poMacedID, IKE_HASH_MAX);

    BulkCtx hashCtx = NULL;

    HMAC_CTX *hmacCtxt = NULL;
    BulkCtx prfCtx = NULL;
    const BulkPrfAlgo *pBPAlgo = pxSa->pHashSuite->pBPAlgo;
    const BulkHashAlgo *pBHAlgo = pxSa->pHashSuite->pBHAlgo;
    ubyte2 wDigestLen = (ubyte2) (pBHAlgo ? pBHAlgo->digestSize : pBPAlgo->digestSize);

    /* get PRF */
    if (pBHAlgo && (OK > (status = HmacCreate(MOC_HASH(ctx->hwAccelCookie) &hmacCtxt, pBHAlgo))))
    {
        DBG_EXIT
    }

    if (pBPAlgo && (OK > (status = pBPAlgo->allocFunc(MOC_HASH(ctx->hwAccelCookie) &prfCtx))))
    {
        DBG_EXIT
    }

    if (!hmacCtxt && !prfCtx) /* jic */
    {
        status = ERR_IKE;
        DBG_EXIT
    }

    /* <msg octets> =
        2nd message | Ni | prf(SK_pr,IDr') for responder
        OR
        1st message | Nr | prf(SK_pi,IDi') for initiator
    */

    /* prf(SK_pr,IDr') or  prf(SK_pi,IDi')*/
    _CRYPTO_ALLOC_(poMacedID, IKE_HASH_MAX)
    if (OK > (status = GetMacedID(ctx, dir, poMacedID, wDigestLen, hmacCtxt, prfCtx, pBPAlgo)))
        goto exit;

    /* calculate hash data */
    if ((OK > (status = pSigBHAlgo->allocFunc(MOC_HASH(ctx->hwAccelCookie) &hashCtx))) ||
        (OK > (status = pSigBHAlgo->initFunc(MOC_HASH(ctx->hwAccelCookie) hashCtx))) ||
        (OK > (status = pSigBHAlgo->updateFunc(MOC_HASH(ctx->hwAccelCookie) hashCtx, pxSa->poMsg[dir], pxSa->dwMsgLen[dir]))) ||
        (OK > (status = pSigBHAlgo->updateFunc(MOC_HASH(ctx->hwAccelCookie) hashCtx, pxSa->poNonce[!dir], pxSa->wNonceLen[!dir]))) ||
        (OK > (status = pSigBHAlgo->updateFunc(MOC_HASH(ctx->hwAccelCookie) hashCtx, poMacedID, wDigestLen))) ||
        (OK > (status = pSigBHAlgo->finalFunc(MOC_HASH(ctx->hwAccelCookie) hashCtx, poHash))))
        DBG_EXIT

    debug_printd((sbyte *)((_I==dir) ? "   HASH_i" : "   HASH_r"), poHash, (ubyte2) pSigBHAlgo->digestSize);

exit:
    if (hashCtx) pSigBHAlgo->freeFunc(MOC_HASH(ctx->hwAccelCookie) &hashCtx);
    if (prfCtx) pBPAlgo->freeFunc(MOC_HASH(ctx->hwAccelCookie) &prfCtx);
    if (hmacCtxt) HmacDelete(MOC_HASH(ctx->hwAccelCookie) &hmacCtxt);
    _CRYPTO_FREE_(poMacedID)
    return status;
} /* DoAuthSig */


static MSTATUS
DoAuthSigPrf(IKE_context ctx, ubyte **poHash, ubyte4 *pHashLen,
          const BulkHashAlgo *pSigBHAlgo,
          intBoolean bIn)
{
    MSTATUS status;

    IKESA pxSa = ctx->pxSa;
    intBoolean bInitiator = IS_INITIATOR(pxSa);
    sbyte4 dir = ((bIn && !bInitiator) || (!bIn && bInitiator))
                 ? _I : _R;

    ubyte __crypto__(poMacedID, IKE_HASH_MAX);

    BulkCtx hashCtx = NULL;

    HMAC_CTX *hmacCtxt = NULL;
    BulkCtx prfCtx = NULL;
    ubyte4 hashLen = 0;
    const BulkPrfAlgo *pBPAlgo = pxSa->pHashSuite->pBPAlgo;
    const BulkHashAlgo *pBHAlgo = pxSa->pHashSuite->pBHAlgo;
    ubyte2 wDigestLen = (ubyte2) (pBHAlgo ? pBHAlgo->digestSize : pBPAlgo->digestSize);

    /* get PRF */
    if (pBHAlgo && (OK > (status = HmacCreate(MOC_HASH(ctx->hwAccelCookie) &hmacCtxt, pBHAlgo))))
    {
        DBG_EXIT
    }

    if (pBPAlgo && (OK > (status = pBPAlgo->allocFunc(MOC_HASH(ctx->hwAccelCookie) &prfCtx))))
    {
        DBG_EXIT
    }

    if (!hmacCtxt && !prfCtx) /* jic */
    {
        status = ERR_IKE;
        DBG_EXIT
    }

    /* <msg octets> =
        2nd message | Ni | prf(SK_pr,IDr') for responder
        OR
        1st message | Nr | prf(SK_pi,IDi') for initiator
    */

    /* prf(SK_pr,IDr') or  prf(SK_pi,IDi')*/
    _CRYPTO_ALLOC_(poMacedID, IKE_HASH_MAX)
    if (OK > (status = GetMacedID(ctx, dir, poMacedID, wDigestLen, hmacCtxt, prfCtx, pBPAlgo)))
        goto exit;

    hashLen = pxSa->dwMsgLen[dir] + pxSa->wNonceLen[!dir] + wDigestLen;
    CHECK_MALLOC((*poHash), hashLen)

    /* calculate hash data */
    if ((OK > (status = pSigBHAlgo->allocFunc(MOC_HASH(ctx->hwAccelCookie) &hashCtx))) ||
        (OK > (status = pSigBHAlgo->initFunc(MOC_HASH(ctx->hwAccelCookie) hashCtx))) ||
        (OK > (status = pSigBHAlgo->updateFunc(MOC_HASH(ctx->hwAccelCookie) hashCtx, pxSa->poMsg[dir], pxSa->dwMsgLen[dir]))) ||
        (OK > (status = pSigBHAlgo->updateFunc(MOC_HASH(ctx->hwAccelCookie) hashCtx, pxSa->poNonce[!dir], pxSa->wNonceLen[!dir]))) ||
        (OK > (status = pSigBHAlgo->updateFunc(MOC_HASH(ctx->hwAccelCookie) hashCtx, poMacedID, wDigestLen))) ||
        (OK > (status = pSigBHAlgo->finalFunc(MOC_HASH(ctx->hwAccelCookie) hashCtx, *poHash))))
        DBG_EXIT

    *pHashLen = hashLen ;
    debug_printd((sbyte *)((_I==dir) ? "   HASH_i" : "   HASH_r"), *poHash, (ubyte2)hashLen);

exit:
    if (hashCtx) pSigBHAlgo->freeFunc(MOC_HASH(ctx->hwAccelCookie) &hashCtx);
    if (prfCtx) pBPAlgo->freeFunc(MOC_HASH(ctx->hwAccelCookie) &prfCtx);
    if (hmacCtxt) HmacDelete(MOC_HASH(ctx->hwAccelCookie) &hmacCtxt);
    _CRYPTO_FREE_(poMacedID)
    return status;
} /* DoAuthSig */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_ECC__
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static MSTATUS
IKE_ecdsaSigToPoint(PrimeFieldPtr pPF,
                    const ubyte *s, sbyte4 len,
                    PFEPtr *ppX, PFEPtr *ppY)
{
    MSTATUS status;

    PFEPtr pX = NULL, pY = NULL;
    sbyte4 elemLen;

    if (OK > (status = PRIMEFIELD_getElementByteStringLen(pPF, &elemLen)) ||
        OK > (status = PRIMEFIELD_newElement(pPF, &pX)) ||
        OK > (status = PRIMEFIELD_newElement(pPF, &pY)))
    {
        DBG_EXIT
    }

    /* ECDSA signature value is specified differently in RFC4754 and RFC3279! */
    if ((2 * elemLen) == len)
    {
        /* RFC4754 7. concatenated r and s
           The bit lengths of r and s are enforced, if necessary, by pre-pending
           the value with zeros.
         */
        if (OK > (status = PRIMEFIELD_setToByteString(pPF, pX, s, elemLen)) ||
            OK > (status = PRIMEFIELD_setToByteString(pPF, pY, s + elemLen, elemLen)))
        {
            DBG_EXIT
        }
    }
    else if (2 <= len)
    {
        /* RFC3279 2.2.3.
           Ecdsa-Sig-Value  ::=  SEQUENCE  {
                r     INTEGER,
                s     INTEGER  }
           e.g.
           30 45
              02 21
                 00 d4 af 20 a9 c3 34 72 2f 33 76 c1 86 71 68 20
                 88 39 23 c7 bf 7c 8e be c9 24 fd d0 ec 18 f3 38
                 17
              02 20
                 66 27 7a 21 b4 a1 52 5f 15 55 65 2b 3e 83 9a a5
                 3e e4 8d d3 e0 99 33 01 e8 cc ba 94 e5 e5 1b 65
         */
        sbyte4 rLen, sLen;
        status = ERR_IKE_BAD_SIG; /* !!! */

        if (0x30 != s[0]) DBG_EXIT      /* SEQUENCE */
        if (len < (2 + s[1])) DBG_EXIT

        len = s[1] - 2;
        if (0 > len) DBG_EXIT

        if (0x02 != s[2]) DBG_EXIT      /* r INTEGER */
        rLen = (sbyte4) s[3];

        len -= rLen + 2;
        if (0 > len) DBG_EXIT

        if (0x02 != s[4+rLen]) DBG_EXIT /* s INTEGER */
        sLen = (sbyte4) s[4+rLen+1];

        if (sLen > len) DBG_EXIT

        if (OK > (status = PRIMEFIELD_setToByteString(pPF, pX, s+4, rLen)) ||
            OK > (status = PRIMEFIELD_setToByteString(pPF, pY, s+(4+rLen+2), sLen)))
        {
            DBG_EXIT
        }
    }
    else
    {
        status = ERR_FF_INVALID_PT_STRING;
        DBG_EXIT
    }

    *ppX = pX;
    pX = NULL;
    *ppY = pY;
    pY = NULL;

exit:
    if (pX) PRIMEFIELD_deleteElement(pPF, &pX);
    if (pY) PRIMEFIELD_deleteElement(pPF, &pY);
    return status;
} /* IKE_ecdsaSigToPoint */
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
#endif /* __ENABLE_DIGICERT_ECC__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC__
static intBoolean isHybridAuthMtd(ubyte4 authMtdId)
{
    switch (authMtdId)
    {
        case AUTH_MTD_P256_MLDSA_44:
        case AUTH_MTD_P256_FNDSA512:
        case AUTH_MTD_P384_MLDSA_65:
        case AUTH_MTD_P521_FNDSA1024:
        case AUTH_MTD_P521_MLDSA_87:
            return TRUE;
    };

    return FALSE;
}
#endif


/*------------------------------------------------------------------*/

extern MSTATUS IKE_getIdHash(IKE_context ctx,
                             struct ikeIdHdr *pxId, ubyte *poIdHash);

static MSTATUS
InAuthSig(IKE_context ctx, ubyte2 wSigLen, ubyte *poHash
#if defined(__ENABLE_DIGICERT_ECC__) || defined(__ENABLE_IKE_SIG_AUTH_RFC7427__)
        , ubyte oAuthMtd
#endif
#if defined(__ENABLE_IKE_SIG_AUTH_RFC7427__) && defined(__ENABLE_DIGICERT_ECC__)
        , ubyte *poAuthMtd
#endif
          )
{
    MSTATUS     status;

    IKESA       pxSa        = ctx->pxSa;
    intBoolean  bInitiator  = IS_INITIATOR(pxSa);
    sbyte4      dir         = (bInitiator ? _R : _I);

    AsymmetricKey *pPeerKey = NULL;

    ubyte *pBuffer = ctx->pBuffer;
    const BulkHashAlgo *pBHAlgo = NULL;

    ubyte*      poSigHash   = NULL;
    vlong*      pVlongQueue = NULL;

    ubyte __crypto__(poIdHash, MD5_DIGESTSIZE);

    /* get peer IDi?_b hash */
    _CRYPTO_ALLOC_(poIdHash, MD5_DIGESTSIZE)
    if (OK > (status = IKE_getIdHash(ctx, pxSa->pxID[dir], poIdHash)))
        DBG_EXIT

    /* get peer certificate's public key */
    if (0 < ctx->certNum)
    {
        if (OK > (status = IKE_certGetKey(ctx, &pPeerKey)))
            DBG_EXIT

#ifdef __ENABLE_IKE_OCSP_EXT__
        if ((IKE_SA_FLAG_CERT_OCSP & pxSa->flags) &&
            (OK > (status = IKE_ocspValidateResponse(ctx))))
            DBG_EXIT
#endif
    }
    else if (OK > (status = IKE_certLookup(ctx, poIdHash, &pPeerKey)))
    {
        DBG_EXIT
    }

#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
    if (AUTH_MTD_SIG == oAuthMtd)
    {
        ubyte sigAlgIdLen;
        ubyte4 akt = 0;

        if (!wSigLen || (wSigLen < (ubyte2)(1 + (sigAlgIdLen = pBuffer[0]))))
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }

        if (OK > (status = IKE_getSigAlgoById(pBuffer + 1, sigAlgIdLen,
                                              &akt, &pBHAlgo)))
            DBG_EXIT

        if ((akt_ecc_ed != pPeerKey->type) && (akt != pPeerKey->type))
        {
            status = ERR_IKE_BAD_SIG;
            DBG_EXIT
        }

        pBuffer += (1 + sigAlgIdLen);
        wSigLen -= (ubyte2)(1 + sigAlgIdLen);
    }
#endif

#ifdef __ENABLE_DIGICERT_ECC__
    if ((akt_ecc == pPeerKey->type) || (akt_ecc_ed == pPeerKey->type)) /* ECDSA */
    {
        ECCKey *pECCKey;
        ubyte4 curveId = 0;
        ubyte4 authCurveId = 0;

        if (AUTH_MTD_RSA_SIG == oAuthMtd)
        {
            status = ERR_IKE_BAD_AUTH;
            DBG_EXIT
        }

        pECCKey = pPeerKey->key.pECC;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pECCKey, &curveId);
        if (OK != status)
            goto exit;
#else
        status = EC_getCurveIdFromKey(pECCKey, &curveId);
        if (OK != status)
            goto exit;
#endif

#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
        if (AUTH_MTD_SIG == oAuthMtd)
        {
            sbyte4 i;
            for (i=0; ; i++)
            {
                IKE_authMtdInfo *pAuthMtd;
                if (NULL == (pAuthMtd = IKE_getAuthMtdEx(pxSa->ikePeerConfig, i)))
                {
                    status = ERR_IKE_BAD_CERT;
                    DBG_EXIT
                }

                authCurveId = pAuthMtd->curveId;
                if (curveId == authCurveId)
                {
                    *poAuthMtd = pAuthMtd->oAuthMtd;
                    break;
                }
            }
        }
        else
#endif
        {
            IKE_authMtdInfo *pAuthMtd = IKE_authMtdEx(pxSa->ikePeerConfig,
                                                      0, oAuthMtd);
            if (NULL == pAuthMtd) /* jic */
            {
                status = ERR_IKE_MISMATCH_AUTH_METHOD;
                DBG_EXIT
            }

            /* check curve */
            authCurveId = pAuthMtd->curveId;

            if (curveId != authCurveId)
            {
                status = ERR_IKE_BAD_CERT;
                DBG_EXIT
            }

            pBHAlgo = pAuthMtd->pBHAlgo;
        }

#if defined (__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)
        if((cid_EC_Ed25519 == curveId) || (cid_EC_Ed448 == curveId))
        {
            ubyte *pMsg = NULL;
            ubyte4 msgLen = 0;
            ubyte4 vfyFail = 0;
            if (OK > (status = DoAuthSigPrf(ctx, &pMsg, &msgLen, pBHAlgo, TRUE)))
                DBG_EXIT

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_ECDSA_verifyMessageExt (MOC_ECC(ctx->hwAccelCookie)
                pECCKey, 0, pMsg, msgLen, pBuffer, wSigLen, &vfyFail, NULL);
#else
            status = ECDSA_verifyMessage (MOC_ECC(ctx->hwAccelCookie)
                pECCKey, 0, pMsg, msgLen, pBuffer, wSigLen, &vfyFail, NULL);
#endif
            CHECK_FREE(pMsg)

            if (OK != status)
                DBG_EXIT

            if (0 != vfyFail)
            {
                status = ERR_IKE_BAD_SIG;
                DBG_EXIT
            }
        }
        else
#endif
        {
            if (OK > (status = DoAuthSig(ctx, poHash, pBHAlgo, TRUE)))
                goto exit;

            ubyte4 elementLen = 0;
            ubyte *pR = NULL;
            ubyte *pS = NULL;
            ubyte4 rLen = 0;
            ubyte4 sLen = 0;
            ubyte4 vfyFail = 0;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(pECCKey, &elementLen);
            if (OK != status)
                goto exit;
#else
            status = EC_getElementByteStringLen(pECCKey, &elementLen);
            if (OK != status)
                goto exit;
#endif

            if ((ubyte4)wSigLen == (elementLen * 2))
            {
                pR = pBuffer;
                pS = pBuffer + elementLen;
                rLen = elementLen;
                sLen = elementLen;
            }
            else
            {
                status = ASN1_parseDsaSignature(pBuffer, (ubyte4)wSigLen, &pR, &rLen, &pS, &sLen);
                if (OK != status)
                    goto exit;
            }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_ECDSA_verifySignatureDigestAux (MOC_ECC(ctx->hwAccelCookie)
                pECCKey, poHash, pBHAlgo->digestSize, pR,
                rLen, pS, sLen, &vfyFail);
#else
            status = ECDSA_verifySignatureDigest (MOC_ECC(ctx->hwAccelCookie)
                pECCKey, poHash, pBHAlgo->digestSize, pR,
                rLen, pS, sLen, &vfyFail);
#endif
            if (OK != status)
                DBG_EXIT

            if (0 != vfyFail)
            {
                status = ERR_IKE_BAD_SIG;
                DBG_EXIT
            }
        }
    }
#ifdef __ENABLE_DIGICERT_PQC__
    else if (akt_hybrid == pPeerKey->type)
    {
        ECCKey *pECCKey;
        QS_CTX *pQsCtx;
        ubyte4 curveId = 0;
        ubyte4 qsAlgoId = 0;
        ubyte4 authCurveId = 0;
        ubyte4 authQsAlgoId = 0;
        ubyte4 elementLen = 0;
        ubyte4 qsSigLen = 0;
        ubyte *pQsSig = NULL;
        ubyte *pR = NULL;
        ubyte *pS = NULL;
        ubyte4 rLen = 0;
        ubyte4 sLen = 0;
        ubyte4 vfyFail = 0;

        if (FALSE == isHybridAuthMtd(oAuthMtd))
        {
            status = ERR_IKE_BAD_AUTH;
            DBG_EXIT
        }

        pECCKey = pPeerKey->key.pECC;
        pQsCtx = pPeerKey->pQsCtx;

        status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pECCKey, &curveId);
        if (OK != status)
            DBG_EXIT

        status = CRYPTO_INTERFACE_QS_getAlg(pQsCtx, &qsAlgoId);
        if (OK != status)
            DBG_EXIT

        IKE_authMtdInfo *pAuthMtd = IKE_authMtdEx(pxSa->ikePeerConfig,
                                                  0, oAuthMtd);
        if (NULL == pAuthMtd) /* jic */
        {
            status = ERR_IKE_MISMATCH_AUTH_METHOD;
            DBG_EXIT
        }

        authCurveId = pAuthMtd->curveId;
        authQsAlgoId = pAuthMtd->qsAlgoId;

        if ((curveId != authCurveId) ||
            (qsAlgoId != authQsAlgoId))
        {
            status = ERR_IKE_BAD_CERT;
            DBG_EXIT
        }

        pBHAlgo = pAuthMtd->pBHAlgo;

        if (OK > (status = DoAuthSig(ctx, poHash, pBHAlgo, TRUE)))
            DBG_EXIT
         
        status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(pECCKey, &elementLen);
        if (OK != status)
            DBG_EXIT

        status = CRYPTO_INTERFACE_QS_SIG_getSignatureLen(pQsCtx, &qsSigLen);
        if (OK != status)
            DBG_EXIT

        /* when using FNDSA algorithm, CRYPTO_INTERFACE_QS_SIG_getSignatureLen returns
         * the largest possible signature. */
        if ((cid_PQC_FNDSA_512 == qsAlgoId) || (cid_PQC_FNDSA_1024 == qsAlgoId))
        {
            if ((ubyte4)wSigLen > (elementLen * 2 + qsSigLen))
            {
                status = ERR_IKE_BAD_SIG;
                DBG_EXIT
            }
        }
        else if ((ubyte4)wSigLen != (elementLen * 2 + qsSigLen))
        {
            status = ERR_IKE_BAD_SIG;
            DBG_EXIT
        }

        pR = pBuffer;
        pS = pBuffer + elementLen;
        rLen = elementLen;
        sLen = elementLen;
        pQsSig = pBuffer + elementLen * 2;
        qsSigLen = wSigLen - 2 * elementLen;

        status = CRYPTO_INTERFACE_ECDSA_verifySignatureDigestAux (MOC_ECC(ctx->hwAccelCookie)
            pECCKey, poHash, pBHAlgo->digestSize, pR, rLen, pS, sLen, &vfyFail);
        if (OK != status)
            DBG_EXIT
        
        if (0 != vfyFail)
        {
            status = ERR_IKE_BAD_SIG;
            DBG_EXIT
        }

        status = CRYPTO_INTERFACE_QS_SIG_verify(MOC_HASH(ctx->hwAccelCookie) pQsCtx, poHash, pBHAlgo->digestSize,
            pQsSig, qsSigLen, &vfyFail);
        if (OK != status)
            DBG_EXIT

        if (0 != vfyFail)
        {
            status = ERR_IKE_BAD_SIG;
            DBG_EXIT
        }
    }
#endif /* __ENABLE_DIGICERT_PQC__ */
    else if ((AUTH_MTD_RSA_SIG != oAuthMtd)
#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
          && (AUTH_MTD_SIG != oAuthMtd)
#endif
             )
    {
        status = ERR_IKE_BAD_AUTH;
        DBG_EXIT
    }
    else /* RSA */
#endif
    {
        RSAKey *pRSAKey = pPeerKey->key.pRSA;
        sbyte4 compareResult;
        ubyte4 dwSigHashLen;
        ubyte2 wHashIdLen;
        ubyte2 wDigestLen;

#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
        const BulkHashAlgo *pBHAlgo1 = NULL;
#endif
        /* signature length */
        sbyte4 sigLen;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if (OK > (status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(MOC_RSA(ctx->hwAccelCookie) pRSAKey, &sigLen)))
            DBG_EXIT
#else
        if (OK > (status = RSA_getCipherTextLength(MOC_RSA(ctx->hwAccelCookie) pRSAKey, &sigLen)))
            DBG_EXIT
#endif

        if (sigLen != (sbyte4)wSigLen)
        {
            status = ERR_IKE_BAD_SIG;
            DBG_EXIT
        }

        /* verify signature data */
        CHECK_MALLOC(poSigHash, wSigLen)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if (OK > (status = CRYPTO_INTERFACE_RSA_verifySignatureAux(MOC_RSA(ctx->hwAccelCookie)
                                               pRSAKey, pBuffer,
                                               poSigHash, &dwSigHashLen, &pVlongQueue)))
            DBG_EXIT
#else
        if (OK > (status = RSA_verifySignature(MOC_RSA(ctx->hwAccelCookie)
                                               pRSAKey, pBuffer,
                                               poSigHash, &dwSigHashLen, &pVlongQueue)))
            DBG_EXIT
#endif

        /* get RSA signature hash algorithm */
#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
        if (AUTH_MTD_SIG == oAuthMtd)
        {
            pBHAlgo1 = pBHAlgo; pBHAlgo = NULL;
        }
#endif
        if (OK > (status = IKE_getHashAlgoByInfo(poSigHash, (ubyte2)dwSigHashLen,
                                                 &wHashIdLen, &pBHAlgo)))
            DBG_EXIT

#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
        if (pBHAlgo1 && (pBHAlgo1 != pBHAlgo))
        {
            status = ERR_IKE_BAD_SIG;
            DBG_EXIT
        }
#ifdef __ENABLE_DIGICERT_ECC__
        *poAuthMtd = AUTH_MTD_RSA_SIG;
#endif
#endif
        wDigestLen = (ubyte2)dwSigHashLen - wHashIdLen;
        if (wDigestLen != pBHAlgo->digestSize)
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }

        /* check hash value */
        if (OK > (status = DoAuthSig(ctx, poHash, pBHAlgo, TRUE)))
            goto exit;

        if (OK > (status = DIGI_MEMCMP(poHash, poSigHash + wHashIdLen, wDigestLen, &compareResult)))
            DBG_EXIT

        if (0 != compareResult)
        {
            debug_printd((sbyte *)"        x", poSigHash + wHashIdLen, wDigestLen);
            status = ERR_IKE_BAD_SIG;
            DBG_EXIT
        }
    }

    /* done */
    if (0 < ctx->certNum)
    {
#ifdef __ENABLE_IKE_OCSP_EXT__
        if (pxSa->ikePeerConfig->bNoIkeOcsp ||
            !(IKE_SA_FLAG_CERT_OCSP & pxSa->flags))
#endif
        CERT_STATUS_CHECK(pxSa, ctx, status)
        IKE_certAssign(ctx, poIdHash, pPeerKey);
    }

exit:
    if (OK > status)
    {
        if (0 < ctx->certNum)
        {
            if (NULL != pPeerKey)
            {
                CRYPTO_uninitAsymmetricKey(pPeerKey, &pVlongQueue);
                FREE(pPeerKey);
            }
        }
        else
        {
            IKE_certUnbind(ctx);
        }
    }

    CHECK_FREE(poSigHash)
    VLONG_freeVlongQueue(&pVlongQueue);

    _CRYPTO_FREE_(poIdHash)
    return status;
} /* InAuthSig */


/*------------------------------------------------------------------*/

static MSTATUS
InAuth0(IKE_context ctx)
{
    MSTATUS status = OK;

    /* AUTH payload header */
    IN_BEGIN(struct ikeAuthHdr, pxAuthHdr, SIZEOF_IKE_AUTH_HDR)
    IN_END

    if (IKE_CNTXT_FLAG_AUTH & ctx->flags) /* already received AUTH payload */
    {
        status = ERR_IKE_BAD_PAYLOAD;
        DBG_EXIT
    }
    ctx->flags |= IKE_CNTXT_FLAG_AUTH;

exit:
    return status;
} /* InAuth0 */


/*------------------------------------------------------------------*/

static MSTATUS
InAuth(IKE_context ctx)
{
    MSTATUS status;

    IKESA pxSa = ctx->pxSa;
    intBoolean bInitiator = IS_INITIATOR(pxSa);

    ubyte __crypto__(poHash, IKE_HASH_MAX);
    ubyte oAuthMtd;

    /* AUTH payload header */
    IN_BEGIN(struct ikeAuthHdr, pxAuthHdr, SIZEOF_IKE_AUTH_HDR)

    _CRYPTO_ALLOC_(poHash, IKE_HASH_MAX)

    /* authentication data */
    switch (oAuthMtd = pxAuthHdr->oMethod)
    {
    case AUTH_MTD_SHARED_KEY :
    {
        ubyte *poSk;
        ubyte4 dwSkLen;
        sbyte4 compareResult;

        /* get shared key */
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
        if (IKE_SA_FLAG_EAP_DONE & pxSa->flags) /* EAP */
        {
            IKE2EAP pxEap = &pxSa->u.v2.eapState;

            /* see RFC4306 2.16 (p32) */
            if ((NULL == (poSk = pxEap->poMsk)) ||
                (0 == (dwSkLen = pxEap->dwMskLen)))
            {
                IKE_hashSuiteInfo *pHashSuite = pxSa->pHashSuite;
                dwSkLen = (pHashSuite->pBHAlgo ? pHashSuite->pBHAlgo->digestSize
                                               : pHashSuite->pBPAlgo->digestSize);
                poSk = pxSa->u.v2.SK_p[bInitiator ? _R : _I];
            }
#ifdef __ENABLE_IKE_MULTI_AUTH__
            /* track applied auth. method (peer) */
            if (!bInitiator || pxEap->poMsk)
            {
                /* for supplicant/initiator, only set this
                   (for authenticator/responder) if MSK is generated !!!
                 */
                pxSa->u.v2.authMtds[bInitiator ? _R : _I] |= (1 << AUTH_MTD_EAP);
            }
#endif
        }
        else
#endif
        {
            IKE_authMtdInfo *pAuthMtd = IKE_authMtdEx(pxSa->ikePeerConfig, 0, AUTH_MTD_SHARED_KEY);
            if (!pAuthMtd || pAuthMtd->bDisabledIn[bInitiator ? _I : _R])
            {
                status = ERR_IKE_MISMATCH_AUTH_METHOD;
                DBG_EXIT
            }

            if (OK > (status = IKE_getPsk(&poSk, &dwSkLen, pxSa, _IN)))
            {
                DBG_EXIT
            }
#ifdef __ENABLE_IKE_MULTI_AUTH__
            /* track applied auth. method (peer) */
            pxSa->u.v2.authMtds[bInitiator ? _R : _I] |= (1 << AUTH_MTD_SHARED_KEY);

#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
            /* if EAP is required, it must be the last method to use (even multiple times) */
            pxSa->u.v2.authMtds[bInitiator ? _R : _I] &= ~(1 << AUTH_MTD_EAP);
#endif
#endif
        }

        /* calculate authentication data */
        status = DoAuthSk(ctx, poHash, wBodyLen, poSk, dwSkLen, TRUE);

#ifdef CUSTOM_IKE_GET_PSK
        if (poSk != pxSa->ikePeerConfig->ikePSKey)
        {
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
            if (!(IKE_SA_FLAG_EAP_DONE & pxSa->flags))
#endif
            DIGI_MEMSET(poSk, 0x00, dwSkLen); /* wipe out PSK from memory */
        }
#endif
        if (OK > status) goto exit;

        /* verify authentication data */
        if (OK > (status = DIGI_MEMCMP(poHash, ctx->pBuffer, wBodyLen, &compareResult)))
            DBG_EXIT

        if (0 != compareResult)
        {
            debug_printd((sbyte *)"        x", ctx->pBuffer, wBodyLen);
            status = ERR_IKE_BAD_HASH;
            DBG_EXIT
        }
        break;
    }

#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
    case AUTH_MTD_SIG :
        if (pxSa->ikePeerConfig->bNoSigAuth)
        {
            status = ERR_IKE_MISMATCH_AUTH_METHOD;
            DBG_EXIT
        }
#ifndef __ENABLE_DIGICERT_ECC__
        oAuthMtd = AUTH_MTD_RSA_SIG;
#endif
#endif
        /* fall through */
#ifdef __ENABLE_DIGICERT_ECC__
    case AUTH_MTD_ECDSA_256 :
    case AUTH_MTD_ECDSA_384 :
    case AUTH_MTD_ECDSA_521 :
        /* fall through */
#endif
    case AUTH_MTD_RSA_SIG :
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
        if (IKE_SA_FLAG_EAP_DONE & pxSa->flags) /* EAP */
        {
            status = ERR_IKE_MISMATCH_AUTH_METHOD;
            DBG_EXIT
        }
#endif

#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
        if (AUTH_MTD_SIG != oAuthMtd)
#endif
        if (OK > (status = IKE_getCertAuth(ctx, oAuthMtd)))
        {
            DBG_EXIT
        }

        if (OK > (status = InAuthSig(ctx, wBodyLen, poHash
#if defined(__ENABLE_DIGICERT_ECC__) || defined(__ENABLE_IKE_SIG_AUTH_RFC7427__)
                                   , pxAuthHdr->oMethod
#endif
#if defined(__ENABLE_IKE_SIG_AUTH_RFC7427__) && defined(__ENABLE_DIGICERT_ECC__)
                                   , &oAuthMtd
#endif
                                     )))
        {
            goto exit;
        }

#if defined(__ENABLE_IKE_SIG_AUTH_RFC7427__) && defined(__ENABLE_DIGICERT_ECC__)
        if (AUTH_MTD_SIG == pxAuthHdr->oMethod)
        {
            if (OK > (status = IKE_getCertAuth(ctx, oAuthMtd)))
            {
                DBG_EXIT
            }
        }
#endif

#ifdef __ENABLE_IKE_MULTI_AUTH__
        /* track applied auth. method (peer) */
        pxSa->u.v2.authMtds[bInitiator ? _R : _I] |= (1 << oAuthMtd);

#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
        /* if EAP is required, it must be the last method to use (even multiple times) */
        pxSa->u.v2.authMtds[bInitiator ? _R : _I] &= ~(1 << AUTH_MTD_EAP);
#endif
#endif
        break;
#ifdef __ENABLE_DIGICERT_PQC__
    case AUTH_MTD_P256_MLDSA_44:
    case AUTH_MTD_P256_FNDSA512:
    case AUTH_MTD_P384_MLDSA_65:
    case AUTH_MTD_P521_FNDSA1024:
    case AUTH_MTD_P521_MLDSA_87:
        {
            if (OK > (status = IKE_getCertAuth(ctx, oAuthMtd)))
            {
                DBG_EXIT
            }

            if (OK > (status = InAuthSig(ctx, wBodyLen, poHash
#if defined(__ENABLE_DIGICERT_ECC__) || defined(__ENABLE_IKE_SIG_AUTH_RFC7427__)
                                       , pxAuthHdr->oMethod
#endif
#if defined(__ENABLE_IKE_SIG_AUTH_RFC7427__) && defined(__ENABLE_DIGICERT_ECC__)
                                       , &oAuthMtd
#endif
                                         )))
            {
                goto exit;
            }
        }
        break;
#endif
    case AUTH_MTD_DSS_SIG :
    default :
        status = ERR_IKE_MISMATCH_AUTH_METHOD;
        DBG_EXIT
        /*break;*/
    }

    /* done */
    IN_END

    ctx->u.v2.oAuthMtd = oAuthMtd; /* responder */

exit:
    if (OK > status)
    {
        if (!bInitiator)
            ctx->wMsgType = AUTHENTICATION_FAILED;
    }
    _CRYPTO_FREE_(poHash)
    return status;
} /* InAuth */


/*------------------------------------------------------------------*/

static MSTATUS
OutAuth(IKE_context ctx)
{
    MSTATUS status = OK;
#ifdef __ENABLE_DIGICERT_CHECK_RSA_BAD_SIGNATURE__
    intBoolean validSig = FALSE;
#endif

    IKESA pxSa = ctx->pxSa;
    intBoolean bInitiator = IS_INITIATOR(pxSa);

    ubyte oAuthMtd = 0;
    IKE_authMtdInfo *pAuthMtd = NULL;

    ubyte2 wBodyLen = 0;
    sbyte4 sigLen = 0;

    IKE_certDescr pxCertDesc = pxSa->pCertChain;
    AsymmetricKey *pxPrivKey = (NULL == pxCertDesc) ? NULL :
                               pxCertDesc->pxPrivKey;

    RSAKey* pRSAKey = NULL;
    const BulkHashAlgo *pBHAlgo = NULL;

#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
    const ubyte *sigAlgId = NULL;
    ubyte sigAlgIdLen = 0;
    sbyte4 i;
#endif
    ubyte* poSigHash = NULL;
    vlong* pVlongQueue = NULL;

    ubyte *pRetSignature = NULL;
    ubyte4 retSignatureLen = 0;

#ifdef __ENABLE_DIGICERT_ECC__
    ECCKey* pECCKey = NULL;
    ubyte __crypto__(poHash, IKE_HASH_MAX);
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    QS_CTX *pQsCtx;
    /* fndsa (falcon) algorithm requires to be calculated
     * to know the length */
    ubyte *pQsSig = NULL;
    ubyte4 qsSigLen;
#endif

    ubyte4 dwSkLen = 0;
    ubyte *poSk = NULL;

    IKE_hashSuiteInfo *pHashSuite = pxSa->pHashSuite;
    ubyte2 wDigestLen = (ubyte2)(pHashSuite->pBHAlgo ? pHashSuite->pBHAlgo->digestSize
                                                     : pHashSuite->pBPAlgo->digestSize);

#ifdef __ENABLE_IKE_MULTI_AUTH__
    if (0 != (oAuthMtd = pxSa->u.v2.oAuthMtd))
    {
        pAuthMtd = IKE_authMtdEx(pxSa->ikePeerConfig, 0, oAuthMtd);
        if (!(pAuthMtd && pAuthMtd->bEnabledOut[bInitiator ? _I : _R])) /* jic */
        {
            status = ERR_IKE_MISMATCH_AUTH_METHOD;
            DBG_EXIT
        }
        if (AUTH_MTD_SHARED_KEY == oAuthMtd)
        {
            if (OK > (status = IKE_getPsk(&poSk, &dwSkLen, pxSa, _OUT)))
            {
                DBG_EXIT
            }
        }
        else if (!(pxCertDesc && (oAuthMtd == pxCertDesc->oAuthMtd)))
        {
            status = ERR_IKE_BAD_CERT;
            DBG_EXIT
        }

        pxSa->u.v2.authMtds[bInitiator ? _I : _R] |= (1 << oAuthMtd);
    }
    else
#endif
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    if (IKE_SA_FLAG_EAP_DONE & pxSa->flags) /* EAP */
    {
        IKE2EAP pxEap = &pxSa->u.v2.eapState;

        /* get shared key; see RFC4306 2.16 (p32) */
        if ((NULL == (poSk = pxEap->poMsk)) ||
            (0 == (dwSkLen = pxEap->dwMskLen)))
        {
            poSk = pxSa->u.v2.SK_p[bInitiator ? _I : _R];
            dwSkLen = wDigestLen;
        }
        oAuthMtd = AUTH_MTD_SHARED_KEY;

#ifdef __ENABLE_IKE_MULTI_AUTH__
        /* track applied auth method (host) */
        if (bInitiator || pxEap->poMsk)
        {
            /* for authenticator/responder, only set this if MSK is generated !!! */
            pxSa->u.v2.authMtds[bInitiator ? _I : _R] |= (1 << AUTH_MTD_EAP);
        }
#endif
    }
    else
#endif
    {
        /* host auth. method */
        if (!bInitiator && /* responder */
            (AUTH_MTD_SHARED_KEY == ctx->u.v2.oAuthMtd))
        {
            if (OK == IKE_getPsk(&poSk, &dwSkLen, pxSa, _OUT))
            {
                oAuthMtd = AUTH_MTD_SHARED_KEY;
                pAuthMtd = IKE_authMtdEx(pxSa->ikePeerConfig, 0, AUTH_MTD_SHARED_KEY);
                if (pAuthMtd && (
#ifdef CUSTOM_IKE_GET_PSK
                                 (poSk != pxSa->ikePeerConfig->ikePSKey) ||
#endif
                                 pAuthMtd->bEnabledOut[_R])) /* if condition true, then bInitiator is always FALSE */
                {
                    goto next;
                }
            }
        }

        if (NULL != pxCertDesc)
        {
            oAuthMtd = pxCertDesc->oAuthMtd;
            pAuthMtd = IKE_authMtdEx(pxSa->ikePeerConfig, 0, oAuthMtd);
            if (pAuthMtd && (
#ifdef CUSTOM_IKE_USE_CERT
                             (pxCertDesc != pxSa->ikePeerConfig->ikeCertChain) ||
#endif
                             pAuthMtd->bEnabledOut[bInitiator ? _I : _R])) /* jic */
            {
                goto next;
            }
        }

        if (OK == IKE_getPsk(&poSk, &dwSkLen, pxSa, _OUT))
        {
            oAuthMtd = AUTH_MTD_SHARED_KEY;
            pAuthMtd = IKE_authMtdEx(pxSa->ikePeerConfig, 0, AUTH_MTD_SHARED_KEY);
            if (pAuthMtd && (
#ifdef CUSTOM_IKE_GET_PSK
                             (poSk != pxSa->ikePeerConfig->ikePSKey) ||
#endif
                             pAuthMtd->bEnabledOut[bInitiator ? _I : _R]))
            {
                goto next;
            }
        }

        /* no applicable auth. method */
        status = ERR_IKE_MISMATCH_AUTH_METHOD;
        DBG_EXIT

#ifdef __ENABLE_IKE_MULTI_AUTH__
next:
        /* track applied auth method (host) */
        pxSa->u.v2.authMtds[bInitiator ? _I : _R] |= (1 << oAuthMtd);
#endif
    }

#ifndef __ENABLE_IKE_MULTI_AUTH__
next:
#endif
    /* auth. data length */
    switch (oAuthMtd)
    {
    case AUTH_MTD_SHARED_KEY :
        wBodyLen = wDigestLen;
        break;

    case AUTH_MTD_RSA_SIG :
    {
        ubyte oSigAlgo;
        ubyte2 wHashIdLen;
        const ubyte *poHashId;

        if (NULL == pxCertDesc) /* jic */
        {
            status = ERR_IKE_NO_CERT;
            DBG_EXIT
        }

#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
        if (pxSa->u.v2.numSahAlgos)
        {
            for (oSigAlgo=0, i = pxSa->u.v2.numSahAlgos - 1; 0 <= i; i--)
            {
                if (OK > (status = IKE_getSigAlgo(akt_rsa, pxSa->u.v2.sahAlgos[i],
                                    &oSigAlgo, &sigAlgId, &sigAlgIdLen, NULL)))
                    DBG_EXIT

                if (oSigAlgo == pxCertDesc->oSigAlgo)
                    break;
            }
            if (sigAlgIdLen)
                wBodyLen = (ubyte2)(1 + sigAlgIdLen);
            else
                oSigAlgo = pxCertDesc->oSigAlgo;
        }
        else
#endif
        {
            /* RFC 5996 Section 3.8:
             * RSA Digital Signature                  1
             *    To promote interoperability, implementations
             *    that support this type SHOULD support signatures that use SHA-1
             *    as the hash function and SHOULD use SHA-1 as the default hash
             *    function when generating signatures.
             */
            oSigAlgo = sha1withRSAEncryption;
        }

        /* get RSA signature hash algorithm & its Digest Info (DER coding) */
        /* See RFC4306 3.8 (p63), RFC4718 3.2 (p10) & RFC3447 9.2 (p42)    */
        if (OK > (status = IKE_getSigHashAlgo(oSigAlgo,
                                              &poHashId, &wHashIdLen, &pBHAlgo)))
            DBG_EXIT

        wDigestLen = wHashIdLen + (ubyte2) pBHAlgo->digestSize;

        if (OK > (status = CRYPTO_ALLOC(ctx->hwAccelCookie, wDigestLen,
                                        TRUE, (void**) &poSigHash)))
            DBG_EXIT

        if (OK > (status = DoAuthSig(ctx, poSigHash + wHashIdLen, pBHAlgo, FALSE)))
            goto exit;

        DIGI_MEMCPY(poSigHash, poHashId, wHashIdLen);

        /* signature length */
        if (NULL == pxPrivKey) /* no private key */
        {
            /* external signing */
            if (NULL == pxSa->ikePeerConfig->funcPtrSignHash)
            {
                status = ERR_IKE_NO_CERT;
                DBG_EXIT
            }

            /* signature data - private key encryption */
            if (OK > (status = (MSTATUS)
                               pxSa->ikePeerConfig->funcPtrSignHash(
                                                poSigHash, (ubyte4)wDigestLen,
                                                &pRetSignature, &retSignatureLen,
                                                pxSa->serverInstance, pxSa)))
                DBG_EXIT

            wBodyLen += (ubyte2)retSignatureLen;
        }
        else
        {
            pRSAKey = pxPrivKey->key.pRSA;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            if (OK > (status = CRYPTO_INTERFACE_getRSACipherTextLength(MOC_RSA(ctx->hwAccelCookie)
                                                            pRSAKey, &sigLen,
                                                            pxPrivKey->type)))
#else
            if (OK > (status = RSA_getCipherTextLength(MOC_RSA(ctx->hwAccelCookie) pRSAKey, &sigLen)))
#endif
                DBG_EXIT

            wBodyLen += (ubyte2)sigLen;
        }
        break;
    }
#ifdef __ENABLE_DIGICERT_ECC__
    case AUTH_MTD_ECDSA_256 :
    case AUTH_MTD_ECDSA_384 :
    case AUTH_MTD_ECDSA_521 :
#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
    case AUTH_MTD_SIG :
#endif
      {
        ubyte curveId = 0;
        if (NULL == pxPrivKey) /* jic */
        {
            status = ERR_IKE_NO_CERT;
            DBG_EXIT
        }
        pECCKey = pxPrivKey->key.pECC;
        if(akt_ecc_ed != (pxPrivKey->type & 0xff))
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(pECCKey, (ubyte4 *)&sigLen);
            if (OK != status)
                goto exit;
#else
            status = EC_getElementByteStringLen(pECCKey, (ubyte4 *)&sigLen);
            if (OK != status)
                goto exit;
#endif

            wBodyLen = (ubyte2)(sigLen * 2);
        }
#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
        if (pxSa->u.v2.numSahAlgos)
        {
            for (i = pxSa->u.v2.numSahAlgos - 1; 0 <= i; i--)
            {
                if (OK > (status = IKE_getSigAlgo(akt_ecc, pxSa->u.v2.sahAlgos[i],
                                        &curveId, &sigAlgId, &sigAlgIdLen, &pBHAlgo)))
                    DBG_EXIT

                if (pBHAlgo == pAuthMtd->pBHAlgo)
                {
                    sigAlgIdLen = 0; /* !!! */
                    break;
                }
                else if((curveId) && (curveId == pAuthMtd->curveId))
                {
                    break;
                }
            }
            if (sigAlgIdLen)
                wBodyLen += (ubyte2)(1 + sigAlgIdLen);
            else
                pBHAlgo = pAuthMtd->pBHAlgo;
        }
        else
#endif
        {
            pBHAlgo = pAuthMtd->pBHAlgo;
        }
        break;
      }
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    case AUTH_MTD_P256_MLDSA_44:
    case AUTH_MTD_P256_FNDSA512:
    case AUTH_MTD_P384_MLDSA_65:
    case AUTH_MTD_P521_FNDSA1024:
    case AUTH_MTD_P521_MLDSA_87:
    {
        ubyte curveId = 0;

        pBHAlgo = pAuthMtd->pBHAlgo;
        _CRYPTO_ALLOC_(poHash, IKE_HASH_MAX)
        if (OK > (status = DoAuthSig(ctx, poHash, pBHAlgo, FALSE)))
            DBG_EXIT

        if (NULL == pxPrivKey) /* jic */
        {
            status = ERR_IKE_NO_CERT;
            DBG_EXIT
        }

        pECCKey = pxPrivKey->key.pECC;
        pQsCtx = pxPrivKey->pQsCtx;

        if(akt_hybrid == (pxPrivKey->type & 0xff))
        {
            status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(pECCKey, (ubyte4 *)&sigLen);
            if (OK != status)
                DBG_EXIT

            wBodyLen = (ubyte2)(sigLen * 2);

            status = CRYPTO_INTERFACE_QS_SIG_getSignatureLen(pQsCtx, &qsSigLen);
            if (OK != status)
                DBG_EXIT

            status = DIGI_MALLOC((void **) &pQsSig, qsSigLen);
            if (OK != status)
                DBG_EXIT

            status = CRYPTO_INTERFACE_QS_SIG_sign (MOC_HASH(ctx->hwAccelCookie) pQsCtx, RANDOM_rngFun,
                g_pRandomContext, poHash, pBHAlgo->digestSize, pQsSig,
                qsSigLen, &qsSigLen);
            if (OK != status)
                DBG_EXIT

            wBodyLen = (wBodyLen + (ubyte2)qsSigLen);
        }
        else
        {
            status = ERR_IKE_BAD_CERT_TYPE;
            DBG_EXIT
        }

        break;
      }
      break;
#endif
/*  case AUTH_MTD_DSS_SIG :*/
    default :
        /* shouldn't get here */
        status = ERR_IKE_MISMATCH_AUTH_METHOD;
        DBG_EXIT
    }

    /* AUTH payload header */
    {
    OUT_BEGIN(struct ikeAuthHdr, pxAuthHdr, SIZEOF_IKE_AUTH_HDR, IKE_NEXT_AUTH)

#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
    if (sigAlgIdLen)
    {
        pxAuthHdr->oMethod = AUTH_MTD_SIG;
        ctx->pBuffer[0] = sigAlgIdLen;
        DIGI_MEMCPY(ctx->pBuffer + 1, sigAlgId, sigAlgIdLen);
        wBodyLen -= (ubyte2)(1 + sigAlgIdLen);
        ADVANCE(1 + sigAlgIdLen)
    }
    else
#endif
    {
        pxAuthHdr->oMethod = oAuthMtd;
    }

    /* calculate authentication data */
    switch (oAuthMtd)
    {
    case AUTH_MTD_SHARED_KEY :
        if (OK > (status = DoAuthSk(ctx, ctx->pBuffer, wBodyLen,
                                    poSk, dwSkLen, FALSE)))
        {
            goto exit;
        }
        break;

    case AUTH_MTD_RSA_SIG :
        if (NULL != pRSAKey)
        {
            /* signature data - private key encryption */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            if (OK > (status = CRYPTO_INTERFACE_RSA_signMessage(
                                                MOC_RSA(ctx->hwAccelCookie)
                                                pRSAKey, poSigHash, wDigestLen,
                                                ctx->pBuffer, &pVlongQueue,
                                                pxPrivKey->type)))
#else
            if (OK > (status = RSA_signMessage(MOC_RSA(ctx->hwAccelCookie)
                                               pRSAKey, poSigHash, wDigestLen,
                                               ctx->pBuffer, &pVlongQueue)))
#endif
                DBG_EXIT

#ifdef __ENABLE_DIGICERT_CHECK_RSA_BAD_SIGNATURE__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_RSA_verifyDigest(MOC_RSA(ctx->hwAccelCookie) pRSAKey,
                                                    poSigHash, wDigestLen, ctx->pBuffer,
                                                    sigLen, &validSig, NULL);
#else
            status = RSA_verifyDigest(MOC_RSA(ctx->hwAccelCookie) pRSAKey,
                                                    poSigHash, wDigestLen, ctx->pBuffer,
                                                    sigLen, &validSig, NULL);
#endif
            if(OK != status)
                goto exit;

            if (validSig == FALSE)
            {
                status = ERR_IKE_BAD_SIG;
                goto exit;
            }
#endif
        }
        else /* externally RSA signed already */
        {
            DIGI_MEMCPY(ctx->pBuffer, pRetSignature, retSignatureLen);
        }
        break;

#ifdef __ENABLE_DIGICERT_ECC__
    case AUTH_MTD_ECDSA_256 :
    case AUTH_MTD_ECDSA_384 :
    case AUTH_MTD_ECDSA_521 :
    {
        _CRYPTO_ALLOC_(poHash, IKE_HASH_MAX)
        if (OK > (status = DoAuthSig(ctx, poHash, pBHAlgo, FALSE)))
            DBG_EXIT

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_ECDSA_signDigestAux (MOC_ECC(ctx->hwAccelCookie)
            pECCKey, RANDOM_rngFun, g_pRandomContext, poHash, pBHAlgo->digestSize,
            ctx->pBuffer, sigLen * 2, (ubyte4 *) &sigLen);
        if (OK != status)
            goto exit;
#else
        status = ECDSA_signDigest (MOC_ECC(ctx->hwAccelCookie)
            pECCKey, RANDOM_rngFun, g_pRandomContext, poHash, pBHAlgo->digestSize,
            ctx->pBuffer, sigLen * 2, (ubyte4 *) &sigLen);
        if (OK != status)
            goto exit;
#endif

        break;
    }
#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
#if defined (__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)
    case AUTH_MTD_SIG:
      {
        ubyte *pMsg = NULL;
        ubyte4 msgLen = 0;
        if (OK > (status = DoAuthSigPrf(ctx, &pMsg, &msgLen, pBHAlgo, FALSE)))
            DBG_EXIT
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_ECDSA_signMessageExt (MOC_ECC(ctx->hwAccelCookie)
            pECCKey, RANDOM_rngFun, g_pRandomContext, 0, pMsg, msgLen,
            ctx->pBuffer, ctx->dwBufferSize, (ubyte4 *) &sigLen, NULL);
        if (OK != status)
            goto exit;
#else
        status = ECDSA_signMessage (MOC_ECC(ctx->hwAccelCookie)
            pECCKey, RANDOM_rngFun, g_pRandomContext, 0, pMsg, msgLen,
            ctx->pBuffer, ctx->dwBufferSize, (ubyte4 *) &sigLen, NULL);
        if (OK != status)
            goto exit;
#endif
        wBodyLen = sigLen;
        SET_HTONS(pxAuthHdr->wLength, GET_NTOHS(pxAuthHdr->wLength) + wBodyLen);\
        CHECK_FREE(pMsg);
        break;
      }
#endif   /* __ENABLE_DIGICERT_ECC_EDDSA_25519__ || __ENABLE_DIGICERT_ECC_EDDSA_448__ */
#endif  /*__ENABLE_IKE_SIG_AUTH_RFC7427__ */
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    case AUTH_MTD_P256_MLDSA_44:
    case AUTH_MTD_P256_FNDSA512:
    case AUTH_MTD_P384_MLDSA_65:
    case AUTH_MTD_P521_FNDSA1024:
    case AUTH_MTD_P521_MLDSA_87:
      {
          ubyte4 curSigLen = sigLen;

        status = CRYPTO_INTERFACE_ECDSA_signDigestAux (MOC_ECC(ctx->hwAccelCookie)
            pECCKey, RANDOM_rngFun, g_pRandomContext, poHash, pBHAlgo->digestSize,
            ctx->pBuffer, sigLen * 2, &sigLen);
        if (OK != status)
            DBG_EXIT

        status = DIGI_MEMCPY(ctx->pBuffer + sigLen, pQsSig, qsSigLen);
        if (OK != status)
            DBG_EXIT

        status = DIGI_FREE((void **) &pQsSig);
        break;
      }
      break;
#endif
    default:
        break;
    }

    /* done */
    OUT_END
    }

exit:
#ifdef CUSTOM_IKE_GET_PSK
    if (poSk &&
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
        !(IKE_SA_FLAG_EAP_DONE & pxSa->flags) &&
#endif
        (poSk != pxSa->ikePeerConfig->ikePSKey))
    {
        DIGI_MEMSET(poSk, 0x00, dwSkLen); /* wipe out PSK from memory */
    }
#endif
    if (pRetSignature && pxSa->ikePeerConfig->funcPtrReleaseSig)
    {
        pxSa->ikePeerConfig->funcPtrReleaseSig(pRetSignature);
    }
    if (poSigHash)
    {
        CRYPTO_FREE(ctx->hwAccelCookie, TRUE, (void**) &poSigHash);
    }
#ifdef __ENABLE_DIGICERT_ECC__
    _CRYPTO_FREE_(poHash)
#endif
    VLONG_freeVlongQueue(&pVlongQueue);
    return status;
} /* OutAuth */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SP800_135_ACVP__
extern MSTATUS
#else
static MSTATUS
#endif
DoKe2(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    IKE2XG pxXg = ctx->pxXg;
    IPSECSA pxIPsecSa = pxXg->pxIPsecSa;

    sbyte4 stringLenK = 0;
    ubyte* pStringMpintK = NULL;
    diffieHellmanContext *pDHctx = DIFFIEHELLMAN_CONTEXT(pxIPsecSa);

    const BulkHashAlgo *pBHAlgo = pxSa->pHashSuite->pBHAlgo;
    const BulkPrfAlgo *pBPAlgo = pxSa->pHashSuite->pBPAlgo;
    ubyte2 wDigestLen = (ubyte2)(pBHAlgo ? pBHAlgo->digestSize : pBPAlgo->digestSize);

    HMAC_CTX *hmacCtxt = NULL;
    BulkCtx prfCtx = NULL;

    ubyte *poKeyBlob = NULL;
    ubyte2 wKeyBlobLen = 0;

    sbyte4 i, j;

    /* get key blob size */
    for (i = pxIPsecSa->axP2Sa[0].oChildSaLen - 1; i >= 0; i--)
    {
        IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[0].axChildSa[i].ipsecPps);
        ubyte2 wKeyLen;

        if (pxIPsecPps->oEncrAlgo)
        {
            CHILDSA_encrInfo *pEncrAlgo;

            if (0 == (wKeyLen = pxIPsecPps->wEncrKeyLen))
                pEncrAlgo = CHILDSA_findEncrAlgo(pxIPsecPps->oEncrAlgo, 0, 0, 0, &wKeyLen);
            else
                pEncrAlgo = CHILDSA_findEncrAlgo(pxIPsecPps->oEncrAlgo, 0, 0, wKeyLen, NULL);

            if (NULL == pEncrAlgo) /* jic */
            {
                status = ERR_NULL_POINTER;
                DBG_EXIT
            }
            wKeyLen = wKeyLen + pEncrAlgo->oNonceLen;
            wKeyBlobLen = wKeyBlobLen + (ubyte2)(wKeyLen * 2);
        }

        if (pxIPsecPps->wAuthAlgo)
        {
            if (0 == (wKeyLen = pxIPsecPps->wAuthKeyLen))
            {
                CHILDSA_authInfo *pAuthAlgo = CHILDSA_findAuthAlgo(pxIPsecPps->wAuthAlgo, 0, 0, 0);
                if (NULL == pAuthAlgo) /* jic */
                {
                    status = ERR_NULL_POINTER;
                    DBG_EXIT
                }
                wKeyLen = pAuthAlgo->wKeyLen;
            }
            wKeyBlobLen = wKeyBlobLen + (ubyte2)(wKeyLen * 2);
        }
    }

#ifdef __ENABLE_DIGICERT_SP800_135_ACVP__
    /* Some test vectors may request more than wKeyBlobLen bytes */
    if (g_childDkmLen > wKeyBlobLen)
        wKeyBlobLen = g_childDkmLen;
#endif

    /* allocate key blob */
    if (OK > (status = CRYPTO_ALLOC(ctx->hwAccelCookie, wKeyBlobLen + wDigestLen,
                                    TRUE, (void**) &poKeyBlob)))
        DBG_EXIT

    /* get DH shared secret string, if any */
    if (pDHctx)
    {
        pStringMpintK = pxIPsecSa->pDhSharedSecret;
        stringLenK = pxIPsecSa->dhSharedSecretLen;
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if (pxIPsecSa->p_eccKey)
    {
        pStringMpintK = pxIPsecSa->poEccSharedSecret;
        stringLenK = pxIPsecSa->eccSharedSecretLen;
    }
#endif

    /* get PRF */
    if (pBHAlgo && (OK > (status = HmacCreate(MOC_HASH(ctx->hwAccelCookie) &hmacCtxt, pBHAlgo))))
    {
        DBG_EXIT
    }

    if (pBPAlgo && (OK > (status = pBPAlgo->allocFunc(MOC_HASH(ctx->hwAccelCookie) &prfCtx))))
    {
        DBG_EXIT
    }

    if (!hmacCtxt && !prfCtx) /* jic */
    {
        status = ERR_IKE;
        DBG_EXIT
    }

    /*
        IKE_AUTH
        = prf+(SK_d, Ni1 | Nr1)

        CREATE_CHILD_SA
        = prf+(SK_d, [g^ir (new)] | Ni | Nr )

        prf+ (K,S) = T1 | T2 | T3 | T4 | ...
       where:
        T1 = prf (K, S | 0x01)
        T2 = prf (K, T1 | S | 0x02)
        T3 = prf (K, T2 | S | 0x03)
        T4 = prf (K, T3 | S | 0x04)
    */

    /* get KEYMAT */
    if ((hmacCtxt &&
         (OK > (status = HmacKey(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->u.v2.SK_d, wDigestLen)))) ||
        (prfCtx &&
         (OK > (status = pBPAlgo->initFunc(MOC_SYM(ctx->hwAccelCookie) pxSa->u.v2.SK_d, wDigestLen, prfCtx)))))
    {
        DBG_EXIT
    }
    else
    {
        ubyte *poKB = poKeyBlob;
        ubyte o = 0x01;

        ubyte *poNonce[2];
        ubyte2 wNonceLen[2];
        for (i = _I; _R >= i; i++)
        {
            if (IKE_XCHG_AUTH == pxXg->oExchange) /* IKE_AUTH */
            {
                poNonce[i] = pxSa->poNonce[i];
                wNonceLen[i] = pxSa->wNonceLen[i];
            }
            else /* CREATE_CHILD_SA */
            {
                poNonce[i] = ((_I==i) ? pxIPsecSa->poNi_b : pxIPsecSa->poNr_b);
                wNonceLen[i] = ((_I==i) ? pxIPsecSa->wNi_bLen : pxIPsecSa->wNr_bLen);
            }
        }

        for (;;)
        {
            if (hmacCtxt)
            {
                if ((pStringMpintK &&
                     (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pStringMpintK, stringLenK)))) ||
                    (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poNonce[_I], wNonceLen[_I]))) ||
                    (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poNonce[_R], wNonceLen[_R]))) ||
                    (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, &o, 1))) ||
                    (OK > (status = HmacFinal(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poKB))))
                    DBG_EXIT
            }
            else
            {
                if ((pStringMpintK &&
                     (OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) pStringMpintK, stringLenK, prfCtx)))) ||
                    (OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) poNonce[_I], wNonceLen[_I], prfCtx))) ||
                    (OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) poNonce[_R], wNonceLen[_R], prfCtx))) ||
                    (OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) &o, 1, prfCtx))) ||
                    (OK > (status = pBPAlgo->finalFunc(MOC_SYM(ctx->hwAccelCookie) poKB, prfCtx))))
                    DBG_EXIT
            }

            if (wKeyBlobLen <= wDigestLen) break;
            wKeyBlobLen = wKeyBlobLen - wDigestLen;

            if (hmacCtxt)
            {
                if (OK > (status = HmacReset(MOC_HASH(ctx->hwAccelCookie) hmacCtxt)) ||
                    OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poKB, wDigestLen)))
                    DBG_EXIT
            }
            else
            {
                if (OK > (status = pBPAlgo->initFunc(MOC_SYM(ctx->hwAccelCookie) pxSa->u.v2.SK_d, wDigestLen, prfCtx)) ||
                    OK > (status = pBPAlgo->updateFunc(MOC_SYM(ctx->hwAccelCookie) poKB, wDigestLen, prfCtx)))
                    DBG_EXIT
            }

            poKB += wDigestLen;
            o = (ubyte)(o + 1);
        }

        poKB = poKeyBlob;

#ifdef __ENABLE_DIGICERT_SP800_135_ACVP__
        if (NULL != g_pChildDkm)
        {
            DIGI_FREE((void **)&g_pChildDkm);
        }

        status = DIGI_MALLOC((void **)&g_pChildDkm, g_childDkmLen);
        if (OK != status)
        {
            DBG_EXIT
        }

        status = DIGI_MEMCPY((void *)g_pChildDkm, poKeyBlob, g_childDkmLen);
        if (OK != status)
        {
            DBG_EXIT
        }
#endif

        /* set IPsec SA keys - see RFC4306, 2.17 (p33) */
        for (i = _R; _I <= i; i--)
        {
            for (j=0; j < pxIPsecSa->axP2Sa[0].oChildSaLen; j++)
            {
                ubyte2 wEncrKeyLen = 0, wAuthKeyLen = 0;
                ubyte *poKey = pxIPsecSa->axP2Sa[0].axChildSa[j].poKey[i];
                IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[0].axChildSa[j].ipsecPps);

                if (pxIPsecPps->oEncrAlgo)
                {
                    CHILDSA_encrInfo *pEncrAlgo;

                    if (0 == (wEncrKeyLen = pxIPsecPps->wEncrKeyLen))
                        pEncrAlgo = CHILDSA_findEncrAlgo(pxIPsecPps->oEncrAlgo, 0, 0, 0, &wEncrKeyLen);
                    else
                        pEncrAlgo = CHILDSA_findEncrAlgo(pxIPsecPps->oEncrAlgo, 0, 0, wEncrKeyLen, NULL);

                    if (NULL == pEncrAlgo) /* jic */
                    {
                        status = ERR_NULL_POINTER;
                        DBG_EXIT
                    }
                    wEncrKeyLen = wEncrKeyLen + pEncrAlgo->oNonceLen;
                }

                if (pxIPsecPps->wAuthAlgo)
                {
                    if (0 == (wAuthKeyLen = pxIPsecPps->wAuthKeyLen))
                    {
                        CHILDSA_authInfo *pAuthAlgo = CHILDSA_findAuthAlgo(pxIPsecPps->wAuthAlgo, 0, 0, 0);
                        if (NULL == pAuthAlgo) /* jic */
                        {
                            status = ERR_NULL_POINTER;
                            DBG_EXIT
                        }
                        wAuthKeyLen = pAuthAlgo->wKeyLen;
                    }
                }

                if (wEncrKeyLen)
                {
                    DIGI_MEMCPY(poKey, poKB, wEncrKeyLen);
                    poKey += wEncrKeyLen;
                    poKB += wEncrKeyLen;
                }

                if (wAuthKeyLen)
                {
                    DIGI_MEMCPY(poKey, poKB, wAuthKeyLen);
                    /*poKey += wAuthKeyLen;*/
                    poKB += wAuthKeyLen;
                }
            } /* for (j=0; */
        } /* for (i */
    }

exit:
#ifdef __ENABLE_DIGICERT_ECC__
    if (pStringMpintK == pxIPsecSa->poEccSharedSecret)
    {
        /* zeroize immediately; see RFC6380 7. */
        DIGI_MEMSET(pStringMpintK, 0x00, stringLenK);
        pxIPsecSa->poEccSharedSecret = NULL;
        pxIPsecSa->eccSharedSecretLen = 0;
    }
#endif
    if (pStringMpintK == pxIPsecSa->pDhSharedSecret)
    {
        /* zeroize immediately; */
        DIGI_MEMSET(pStringMpintK, 0x00, stringLenK);
        pxIPsecSa->pDhSharedSecret = NULL;
        pxIPsecSa->dhSharedSecretLen = 0;
    }
    CHECK_FREE(pStringMpintK)
    if (hmacCtxt) HmacDelete(MOC_HASH(ctx->hwAccelCookie) &hmacCtxt);
    if (prfCtx) pBPAlgo->freeFunc(MOC_HASH(ctx->hwAccelCookie) &prfCtx);
    if (poKeyBlob) CRYPTO_FREE(ctx->hwAccelCookie, TRUE, (void**) &poKeyBlob);

    return status;
} /* DoKe2 */


/*------------------------------------------------------------------*/

static MSTATUS
InNonce(IKE_context ctx)
{
    MSTATUS status;

    IKE2XG pxXg = ctx->pxXg;
    IKESA pxSa = pxXg->pxSa;
    IPSECSA pxIPsecSa = pxXg->pxIPsecSa;

    intBoolean bInitiator = IS_XCHG_INITIATOR(pxXg);

    ubyte2 wBodyLen;
    ubyte *poNonce;

    /* already received Nonce payload? */
    if (IKE_CNTXT_FLAG_NONCE & ctx->flags)
    {
        status = ERR_IKE_BAD_NONCE;
        DBG_EXIT
    }

    /* generic header */
    if (OK != (status = InGen(ctx, &wBodyLen)))
        goto exit;

    /* nonce data */
    if (((ubyte2)IKE_NONCE_MIN > wBodyLen) || ((ubyte2)IKE_NONCE_MAX < wBodyLen))
    {
        status = ERR_IKE_BAD_LEN;
        DBG_EXIT
    }
    CHECK_MALLOC(poNonce, wBodyLen)

    if (bInitiator)
    {
        if (pxSa)
        {
            CHECK_FREE(pxSa->poNonce[_R])
            pxSa->poNonce[_R] = poNonce;
            pxSa->wNonceLen[_R] = wBodyLen;
        }
        else
        {
            CHECK_FREE(pxIPsecSa->poNr_b)
            pxIPsecSa->poNr_b = poNonce;
            pxIPsecSa->wNr_bLen = wBodyLen;
        }
    }
    else
    {
        if (pxSa)
        {
            CHECK_FREE(pxSa->poNonce[_I])
            pxSa->poNonce[_I] = poNonce;
            pxSa->wNonceLen[_I] = wBodyLen;
        }
        else
        {
            CHECK_FREE(pxIPsecSa->poNi_b)
            pxIPsecSa->poNi_b = poNonce;
            pxIPsecSa->wNi_bLen = wBodyLen;
        }
    }

    DIGI_MEMCPY(poNonce, ctx->pBuffer - wBodyLen, wBodyLen);

    ctx->flags |= IKE_CNTXT_FLAG_NONCE;

exit:
    return status;
} /* InNonce */


/*------------------------------------------------------------------*/

static MSTATUS
InId(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;

    ubyte oNp = ctx->oNextPayload;
    sbyte4 dir = (IKE_NEXT_ID_I == oNp) ? _I : _R;
    ubyte2 cntxt_mask = (_I == dir) ? IKE_CNTXT_FLAG_ID_I : IKE_CNTXT_FLAG_ID_R;

#if defined(CUSTOM_IKE_GET_ID) || defined(CUSTOM_IKE_CHECK_ID)
    intBoolean bInitiator = IS_INITIATOR(pxSa);
    sbyte4 _io = (bInitiator || (_I == dir)) ? _IN/*remote*/ : _OUT/*local*/;
#endif
    struct ikeIdHdr *pxID;

    /* id payload header */
    IN_BEGIN(struct ikeIdHdr, pxIdHdr, SIZEOF_IKE_ID_HDR)

    if (cntxt_mask & ctx->flags) /* already received IDi or IDr payload */
    {
        status = ERR_IKE_BAD_ID;
        DBG_EXIT
    }

    /* identification data */
    switch (pxIdHdr->oType)
    {
    case ID_IPV4_ADDR :
        if (wBodyLen != sizeof(ubyte4))
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }
        break;
    case ID_FQDN :
    case ID_RFC822_ADDR :
        break;
    case ID_IPV6_ADDR :
        if (wBodyLen != (4 * sizeof(ubyte4)))
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }
        break;
    case ID_DER_ASN1_DN :
    case ID_DER_ASN1_GN :
        break;
    case ID_KEY_ID :
        break;
    default :
        status = ERR_IKE_BAD_ID;
        DBG_EXIT
        /*break;*/
    }

    /* check custom ID */
#ifdef CUSTOM_IKE_GET_ID
    if ((_IN == _io) && /* remote!!! */
        (NULL != (pxID = pxSa->pxID[dir]))) /* custom ID already set */
    {
        ubyte2 wIdDataLen = GET_NTOHS(pxID->wLength)
                          - (ubyte2)SIZEOF_IKE_ID_HDR;

        if ((wIdDataLen == wBodyLen) && (pxIdHdr->oType == pxID->oType))
        {
            sbyte4 compareResult;
            if (OK > (status = DIGI_MEMCMP(ctx->pBuffer,
                                          (ubyte *)pxID + SIZEOF_IKE_ID_HDR,
                                          wIdDataLen, &compareResult)))
                DBG_EXIT

            if (0 == compareResult) /* match */
                goto done;
        }

        /* mismatch!!! */
        FREE(pxID);
        pxSa->pxID[dir] = NULL;
        DBG_ERRCODE(ERR_IKE_BAD_ID)
    }
#endif

    /* match custom ID */
#ifdef CUSTOM_IKE_CHECK_ID
    if (OK > CUSTOM_IKE_CHECK_ID(ctx->pBuffer, wBodyLen, pxIdHdr->oType,
                            REF_MOC_IPADDR(pxSa->dwPeerAddr),
                            _io, bInitiator
                            MOC_MTHM_REQ_VALUE(pxSa->serverInstance)))
    {
        if (_IN == _io)
        {
            status = ERR_IKE_BAD_ID;
            DBG_EXIT
        }

        DBG_ERRCODE(ERR_IKE_BAD_ID) /* IDr, responder */
        goto done;
    }
#endif

    /* store ID payload */
    CHECK_MALLOC_PTR(struct ikeIdHdr, pxID, wLength)
    DIGI_MEMCPY(pxID, pxIdHdr, wLength);
    CHECK_FREE(pxSa->pxID[dir])
    pxSa->pxID[dir] = pxID;

#if defined(CUSTOM_IKE_GET_ID) || defined(CUSTOM_IKE_CHECK_ID)
done:
#endif
    /* done */
    IN_END

    ctx->flags |= cntxt_mask;

exit:
    return status;
} /* InId */


/*------------------------------------------------------------------*/

static MSTATUS
InTs(IKE_context ctx, sbyte4 i, ubyte oTsLen)
{
    MSTATUS status = OK;

    sbyte4 j;
    ubyte oUlpTSi = 0; /* for Responder TSr */
    IPSECSA pxIPsecSa = ctx->pxXg->pxIPsecSa;
    intBoolean bInitiator = IS_CHILD_INITIATOR(pxIPsecSa);

    if (!oTsLen)
    {
        status = ERR_IKE_BAD_LEN;
        DBG_EXIT
    }
    if (bInitiator)
    oTsLen = 1; /* FOR NOW */

    for (j=0; j < (sbyte4)oTsLen; j++)
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        ubyte4 dwIpAddr, dwIpAddrEnd;
#else
        #define ipAddr dwIpAddr
        #define ipAddrEnd dwIpAddrEnd
#endif
        MOC_IP_ADDRESS_S ipAddr = MOC_IPADDR_NONE;
        MOC_IP_ADDRESS_S ipAddrEnd = MOC_IPADDR_NONE;
        ubyte2 wPort, wPortEnd;
        ubyte oUlp;

        IN_BEGIN_0(struct ikeTS, pxTs, SIZEOF_IKE_TS)

        /* get IP addresses */
        switch (pxTs->oType)
        {
        case TS_IPV4_ADDR_RANGE :
            if (8 > wBodyLen)
            {
                status = ERR_IKE_BAD_LEN;
                DBG_EXIT
            }

            SET_NTOHL(dwIpAddr, pxTs->dwIpAddr);
            SET_NTOHL(dwIpAddrEnd, pxTs->dwIpAddrEnd);

            if (dwIpAddrEnd < dwIpAddr)
            {
                status = ERR_IKE_BAD_ID2;
                DBG_EXIT
            }

#ifdef __ENABLE_DIGICERT_IPV6__
            SET_MOC_IPADDR4(ipAddr, dwIpAddr);
            SET_MOC_IPADDR4(ipAddrEnd, dwIpAddrEnd);
#endif
            break;

#ifdef __ENABLE_DIGICERT_IPV6__
        case TS_IPV6_ADDR_RANGE :
            if (32 > wBodyLen)
            {
                status = ERR_IKE_BAD_LEN;
                DBG_EXIT
            }

            SET_MOC_IPADDR6(ipAddr, ctx->pBuffer);
            SET_MOC_IPADDR6(ipAddrEnd, ctx->pBuffer + 16);

            if (LT_MOC_IPADDR6(ipAddrEnd, ipAddr))
            {
                status = ERR_IKE_BAD_ID2;
                DBG_EXIT
            }
            break;
#endif
        default :
            status = ERR_IKE_BAD_ID2;
            DBG_EXIT
            /*break;*/
        } /* switch */

        IN_END

        /* get port(s) */
        wPort = GET_NTOHS(pxTs->wPort);
        wPortEnd = GET_NTOHS(pxTs->wPortEnd);

        if ((wPortEnd < wPort) &&
            !(!wPortEnd && (0xffff == wPort))) /* not OPAQUE */
        {
            status = ERR_IKE_BAD_ID2;
            DBG_EXIT
        }

        oUlp = pxTs->oProtocol;
        if (!oUlp && /* no ULP specified */
            !(!wPort && (0xffff == wPortEnd))) /* not ANY */
        {
            status = ERR_IKE_BAD_ID2;
            DBG_EXIT
        }

        /* process data */
        if (bInitiator)
        {
            if (pxIPsecSa->oUlp)
            {
                if (oUlp != pxIPsecSa->oUlp)
                {
                    debug_print_ike2_ts((ubyte *)pxTs, (_I==i));
                    status = ERR_IKE_BAD_ID2;
                    DBG_EXIT
                }
            }

            if ((wPort < pxIPsecSa->wPort[i]) ||
                (wPortEnd > pxIPsecSa->wPortEnd[i]))
            {
                debug_print_ike2_ts((ubyte *)pxTs, (_I==i));
                status = ERR_IKE_BAD_ID2;
                DBG_EXIT
            }

            if (LT_MOC_IPADDR(ipAddr, pxIPsecSa->dwIP[i]) ||
                LT_MOC_IPADDR(pxIPsecSa->dwIPEnd[i], ipAddrEnd))
            {
#ifdef __ENABLE_IPSEC_NAT_T__
                /* special case: Transport Mode behind NAT */
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[0].axChildSa[0].ipsecPps);
                if ((ENCAPSULATION_MODE_TRANSPORT != pxIPsecPps->wMode) ||
#else
                if (
#endif
                    !(((_I==i) && IS_HOST_BEHIND_NAT(ctx->pxSa)) ||
                      ((_R==i) && IS_PEER_BEHIND_NAT(ctx->pxSa))))
#endif
                {
                    debug_print_ike2_ts((ubyte *)pxTs, (_I==i));
                    status = ERR_IKE_BAD_ID2;
                    DBG_EXIT
                }
            }

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
            if ((pxIPsecSa->oUlp != oUlp) ||
                (pxIPsecSa->wPort[i] != wPort) ||
                (pxIPsecSa->wPortEnd[i] != wPortEnd) ||
                !SAME_MOC_IPADDR(REF_MOC_IPADDR(pxIPsecSa->dwIP[i]), ipAddr) ||
                !SAME_MOC_IPADDR(REF_MOC_IPADDR(pxIPsecSa->dwIPEnd[i]), ipAddrEnd))
            {
                debug_print_ike2_ts((ubyte *)pxTs, (_I==i));
            }
#endif
            /* FIX: Cisco FlexVPN (2901) IPv6 interop issue
               Change received TSi from ::/128 to ::/0 */
            IF_MOC_IPADDR6(ipAddr,
            {
                if ((_I == i) &&
                    (IKE_CHILD_FLAG_CONNECT2 & pxIPsecSa->c_flags) &&
                    SAME_MOC_IPADDR(REF_MOC_IPADDR(pxIPsecSa->dwIP[i]), ipAddr) &&
                    SAME_MOC_IPADDR(REF_MOC_IPADDR(pxIPsecSa->dwIP[i]), ipAddrEnd))
                {
                    ipAddrEnd = pxIPsecSa->dwIPEnd[i];
                }
            });
        }
        else /* responder */
        {
            debug_print_ike2_ts((ubyte *)pxTs, (_I==i));

            if (j) /* There are multiple Traffic Selectors */
            {
                if (oUlpTSi && !oUlp) oUlp = oUlpTSi; /* jic */

                if ((oUlp && (oUlp != pxIPsecSa->oUlp)) ||
                    (wPort > pxIPsecSa->wPort[i]) ||
                    (wPortEnd < pxIPsecSa->wPortEnd[i]) ||
                    LT_MOC_IPADDR(pxIPsecSa->dwIP[i], ipAddr) ||
                    LT_MOC_IPADDR(ipAddrEnd, pxIPsecSa->dwIPEnd[i]))
                {
                    /* select the most general one (w.r.t. the 1st TS) */
                    continue;
                }
            }

            if (_R==i)
            {
#ifdef __ENABLE_DIGICERT_IPV6__
                if (ipAddr.family != pxIPsecSa->dwIP[_I].family)
                {
                    status = ERR_IKE_BAD_ID2;
                    DBG_EXIT
                }
#endif
                if (!j && pxIPsecSa->oUlp)
                {
                    if (oUlp != pxIPsecSa->oUlp)
                    {
                        status = ERR_IKE_BAD_ID2;
                        DBG_EXIT
                    }
                    oUlpTSi = pxIPsecSa->oUlp;
                }
            }
            else/* if (_I==i)*/
            {
                if (!wPortEnd && (0xffff == wPort)) /* OPAQUE */
                {
                    status = ERR_IKE_BAD_ID2;
                    DBG_EXIT
                }
            }
        }

        pxIPsecSa->oUlp = oUlp;
        pxIPsecSa->wPort[i] = wPort;
        pxIPsecSa->wPortEnd[i] = wPortEnd;

        pxIPsecSa->dwIP[i] = ipAddr;
        pxIPsecSa->dwIPEnd[i] = ipAddrEnd;

#ifndef __ENABLE_DIGICERT_IPV6__
        #undef ipAddr
        #undef ipAddrEnd
#endif
    } /* for */

exit:
    return status;
} /* InTs */


/*------------------------------------------------------------------*/

static MSTATUS
InTSir(IKE_context ctx)
{
    MSTATUS status = OK;

    sbyte4 i;

    if (IKE_CNTXT_FLAG_TS & ctx->flags) /* (TSi,TSr) payloads processed */
    {
        status = ERR_IKE_BAD_ID2;
        DBG_EXIT
    }

    if (!ctx->pxXg->pxIPsecSa)  /* no CHILD_SA */
    {
        status = ERR_IKE_BAD_ID2;
        DBG_EXIT
    }

    for (i = _I; _R >= i; i++)
    {
        /* TS payload header */
        IN_BEGIN(struct ikeTsHdr, pxTsHdr, SIZEOF_IKE_TS_HDR)

        /* make sure there's a following TSr payload */
        if ((_I==i) && (IKE_NEXT_TS_R != ctx->oNextPayload))
        {
            status = ERR_IKE_BAD_PAYLOAD;
            DBG_EXIT
        }

        /* go to TS's */
        IN_DOWN(pxTsHdr)

        if (OK > (status = InTs(ctx, i, pxTsHdr->oTsLen)))
            goto exit;

        IN_UP(pxTsHdr)

    } /* for (i= */

    ctx->flags |= IKE_CNTXT_FLAG_TS;

exit:
    return status;
} /* InTSir */


#ifdef __ENABLE_IKE_CP__

/*------------------------------------------------------------------*/

static MSTATUS
CheckCfgAttr(ubyte2 wType, ubyte2 wLen, ubyte2 flags)
{
    MSTATUS status = OK;

    switch (wType)
    {
    case INTERNAL_IP4_NETMASK :
    case INTERNAL_ADDRESS_EXPIRY :
        if (flags & (1 << wType))
        {
            status = ERR_IKE_BAD_MSG;
            DBG_EXIT
        }
    case INTERNAL_IP4_ADDRESS :
    case INTERNAL_IP4_DNS :
    case INTERNAL_IP4_NBNS :
    case INTERNAL_IP4_DHCP :
        if (wLen && (4 != wLen))
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }
        break;
    case APPLICATION_VERSION :
        if (flags & (1 << wType))
        {
            status = ERR_IKE_BAD_MSG;
            DBG_EXIT
        }
        break;
    case INTERNAL_IP6_ADDRESS :
        if (wLen && (17 != wLen))
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }
        break;
    case INTERNAL_IP6_DNS :
    /*case INTERNAL_IP6_NBNS :*//* removed [RFC5996] */
    case INTERNAL_IP6_DHCP :
        if (wLen && (16 != wLen))
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }
        break;
    case INTERNAL_IP4_SUBNET :
        if (wLen && (8 != wLen))
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }
        break;
    case SUPPORTED_ATTRIBUTES :
        if (0 != (wLen % 2))
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }
        if (flags & (1 << wType))
        {
            status = ERR_IKE_BAD_MSG;
            DBG_EXIT
        }
        break;
    case INTERNAL_IP6_SUBNET :
        if (17 != wLen)
        {
            /* Note: 0 is not allowed! See RFC4306 3.15.1. (p.82) */
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }
        break;
    default :
        /* discard silently */
        break;
    }

exit:
    return status;
} /* CheckCfgAttr */


/*------------------------------------------------------------------*/

static MSTATUS
InCp(IKE_context ctx)
{
    MSTATUS status = OK;
    ubyte2 flags = 0;

    IKESA pxSa = ctx->pxSa;
    IKE2XG pxXg = ctx->pxXg;
    intBoolean bInitiator = IS_XCHG_INITIATOR(pxXg);

    /* Configuration Payload header */
    IN_BEGIN(struct ikeCfgHdr, pxCfgHdr, SIZEOF_IKE_CFG_HDR)

    if (IKE_CNTXT_FLAG_CP & ctx->flags) /* already received Configuration Payload */
    {
        status = ERR_IKE_BAD_CFG;
        DBG_EXIT
    }

    if (bInitiator)
    {
        if ((NULL == pxXg->poCfgAttrs) ||
            (NULL == m_ikeSettings.funcPtrIkeRespCfg))
        {
            DBG_ERRCODE(ERR_IKE_CONFIG)
            IN_END
            goto exit;
        }

        if (CFG_REPLY != pxCfgHdr->oType)
        {
            status = ERR_IKE_BAD_CFG;
            DBG_EXIT
        }
        debug_printnl("   CFG_REPLY");
    }
    else
    {
        if (CFG_REQUEST != pxCfgHdr->oType)
        {
            status = ERR_IKE_BAD_CFG;
            DBG_EXIT
        }
        debug_printnl("   CFG_REQUEST");

        ctx->u.v2.poCp = (const ubyte *)pxCfgHdr;
    }

    /* go to Configration Attributes */
    IN_DOWN(pxCfgHdr)

    /* data attributes */
    while (ctx->dwBufferSize)
    {
        ubyte2 wType, wLen;

        IN_HDR(struct ikeCfgAttrHdr, pxCfgAttr, SIZEOF_IKE_CFG_ATTR_HDR)

        SET_NTOHS(wType, pxCfgAttr->wType);
        wType &= 0x7fff; /* 1st bit is reserved */
        SET_NTOHS(wLen, pxCfgAttr->wLength);

        if (ctx->dwBufferSize < (ubyte4)wLen)
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }

        if (OK > (status = CheckCfgAttr(wType, wLen, flags)))
            goto exit;

        if (16 > wType) /* !!! */
        flags |= (1 << wType);

        debug_print("    ");
        debug_print_ike_cfgattr(wType, wLen, ctx->pBuffer);
        debug_printnl(NULL);

        ADVANCE(wLen)
    } /* while */

    IN_UP(pxCfgHdr)

    ctx->flags |= IKE_CNTXT_FLAG_CP;

    /* process reply */
    if (bInitiator)
    {
        if (OK > (status = m_ikeSettings.funcPtrIkeRespCfg(
                                    (ubyte *)pxCfgHdr + SIZEOF_IKE_CFG_HDR,
                                    wBodyLen, 0, pxSa->dwId, pxSa)))
        {
            DBG_STATUS
            status = OK; /* !!! */
            goto exit;
        }
    }

exit:
    return status;
} /* InCp */


/*------------------------------------------------------------------*/

static MSTATUS
DoCfgReq(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    IKE2XG pxXg = ctx->pxXg;

    const struct ikeCfgHdr *pxCfgHdr = (const struct ikeCfgHdr *) ctx->u.v2.poCp;
    ubyte *poCfgReq = (ubyte *)pxCfgHdr + SIZEOF_IKE_CFG_HDR;
    ubyte2 wCfgReqLen = GET_NTOHS(pxCfgHdr->wLength) - (ubyte2)SIZEOF_IKE_CFG_HDR;

    ubyte *poCfgResp = NULL, *poBuf;
    ubyte2 wCfgRespLen = 0, wBufSz;
    ubyte2 flags = 0;

    struct ikeIdHdr *pxIdHdr = pxSa->pxID[IS_INITIATOR(pxSa) ? _R : _I]; /* peer */
    ubyte2 wIdLen = GET_NTOHS(pxIdHdr->wLength) - SIZEOF_IKE_ID_HDR;
    ubyte *poId = ((ubyte *)pxIdHdr) + SIZEOF_IKE_ID_HDR;
    sbyte4 idType = pxIdHdr->oType;

    ubyte *identity = NULL;
    ubyte4 id_len = 0;

#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    IKE2EAP pxEap = &pxSa->u.v2.eapState;
    if (pxEap->pSession)
        EAP_getIdentity(pxEap->pSession, g_ikeEapInstId, &identity, &id_len);
#endif
    if (OK > (status = m_ikeSettings.funcPtrIkeGetCfg(
                                &poCfgResp, &wCfgRespLen,
                                poCfgReq, wCfgReqLen,
                                poId, wIdLen, idType,
                                identity, id_len, ctx->peerAddr
                                MOC_NATT_REQ_VALUE((IS_PEER_BEHIND_NAT(pxSa)
                                                    ? pxSa->wPeerPort : 0))
                                MOC_MTHM_REQ_VALUE(pxSa->serverInstance),
                                pxSa)))
    {
        if (STATUS_IKE_PENDING == status)
        {
            pxXg->x_flags |= IKE_XCHG_FLAG_PENDING;
            goto exit;
        }
        DBG_EXIT
    }

    if ((NULL == poCfgResp) || (0 == wCfgRespLen))
    {
        pxXg->poCfgAttrs = NULL;
        pxXg->wCfgAttrsLen = 0;
        goto exit;
    }

    /* check custom configuration response */
    for (poBuf = poCfgResp, wBufSz = wCfgRespLen; SIZEOF_IKE_CFG_ATTR_HDR < wBufSz; )
    {
        struct ikeCfgAttrHdr *pxCfgAttr = (struct ikeCfgAttrHdr *)poBuf;
        ubyte2 wType = GET_NTOHS(pxCfgAttr->wType);
        ubyte2 wLen = GET_NTOHS(pxCfgAttr->wLength);

        if ((wLen + SIZEOF_IKE_CFG_ATTR_HDR) > wBufSz)
            break;

        wType &= 0x7fff; /* 1st bit is reserved */
        if (OK > (status = CheckCfgAttr(wType, wLen, flags)))
            goto exit;

        flags |= (1 << wType);

        wBufSz = wBufSz - (ubyte2)(SIZEOF_IKE_CFG_ATTR_HDR + wLen);
        poBuf += SIZEOF_IKE_CFG_ATTR_HDR + wLen;
    } /* for */

    if (0 != wBufSz) /* response too big - trim it */
    {
        DBG_ERRCODE(ERR_IKE_CONFIG)
        if (0 == (wCfgRespLen = (wCfgRespLen - wBufSz)))
            goto exit;
    }

    /* save configuration response */
    CHECK_MALLOC(pxXg->poCfgAttrs, wCfgRespLen)
    DIGI_MEMCPY(pxXg->poCfgAttrs, poCfgResp, wCfgRespLen);
    pxXg->wCfgAttrsLen = wCfgRespLen;
    pxXg->oCfgType = CFG_REPLY;

exit:
    if (poCfgResp && m_ikeSettings.funcPtrIkeReleaseCfg)
        m_ikeSettings.funcPtrIkeReleaseCfg(poCfgResp);

    return status;
} /* DoCfgReq */

#endif /* __ENABLE_IKE_CP__ */


/*------------------------------------------------------------------*/

static MSTATUS
InCr(IKE_context ctx)
{
    MSTATUS status = OK;

    /* certificate request payload header */
    IN_BEGIN(struct ikeCRHdr, pxCRHdr, SIZEOF_IKE_CR_HDR)

    /* certificate data */
    switch (pxCRHdr->oType)
    {
    case CERT_X509_SIGNATURE :
        ctx->pxSa->flags |= IKE_SA_FLAG_CR;
        break;

    case CERT_OCSP_CONTENT :
#ifdef __ENABLE_IKE_OCSP_EXT__
        if (ctx->pxSa->ikePeerConfig->bNoIkeOcsp)
        {
            ctx->pxSa->flags |= IKE_SA_FLAG_CR; /* !!! */
            break;
        }
        ctx->pxSa->flags |= IKE_SA_FLAG_CR_OCSP;

        /* save trusted OCSP responder hashes */
        ctx->pOcspReq = ctx->pBuffer;
        ctx->ocspReqLen = wBodyLen;
#else
        DBG_ERRCODE(ERR_IKE_BAD_CERT_TYPE)
#endif
        break;

/*  case CERT_PKCS7_WRAPPED_X509 :
    case CERT_PGP :
    case CERT_DNS_SIGNED_KEY= :
    case CERT_X509_KEY_EXCHANGE :
    case CERT_KERBEROS_TOKENS :
    case CERT_CRL :
    case CERT_ARL :
    case CERT_SPKI :
    case CERT_X509_ATTRIBUTE :
    case CERT_RAW_RSA :
*/  default :
        if (!IS_INITIATOR(ctx->pxSa))
        ctx->wMsgType = CERT_TYPE_UNSUPPORTED;
        status = ERR_IKE_BAD_CERT_TYPE;
        DBG_EXIT
        /*break;*/
    }

    /* done */
    IN_END

exit:
    return status;
} /* InCr */


/*------------------------------------------------------------------*/

static MSTATUS
InCert(IKE_context ctx)
{
    MSTATUS status = OK;

    /* certificate payload header */
    IN_BEGIN(struct ikeCertHdr, pxCertHdr, SIZEOF_IKE_CERT_HDR)

    /* certificate data */
    switch (pxCertHdr->oEncoding)
    {
    case CERT_X509_SIGNATURE :
        if (IKE_CERT_CHAIN_MAX <= ctx->certNum)
        {
            status = ERR_IKE_BAD_CERT;
            DBG_EXIT
        }
        ctx->certificates[ctx->certNum].pCertificate = ctx->pBuffer;
        ctx->certificates[ctx->certNum].certLength = wBodyLen;
        ++ctx->certNum;
        break;

    case CERT_OCSP_CONTENT :
#ifdef __ENABLE_IKE_OCSP_EXT__
        if (ctx->pxSa->ikePeerConfig->bNoIkeOcsp)
            break;
        ctx->pxSa->flags |= IKE_SA_FLAG_CERT_OCSP;

        /* save DER-encoded OCSPResponse structure as defined in [RFC2560] */
        ctx->pOcspResp = ctx->pBuffer;
        ctx->ocspRespLen = wBodyLen;
#else
        DBG_ERRCODE(ERR_IKE_BAD_CERT_TYPE)
#endif
        break;

/*  case CERT_PKCS7_WRAPPED_X509 :
    case CERT_PGP :
    case CERT_DNS_SIGNED_KEY= :
    case CERT_KERBEROS_TOKENS :
    case CERT_CRL :
    case CERT_ARL :
    case CERT_SPKI :
    case CERT_X509_ATTRIBUTE :
    case CERT_RAW_RSA :
    case CERT_URL_X509 :
    case CERT_URL_X509_BUNDLE :
*/  default :
        if (!IS_INITIATOR(ctx->pxSa))
        ctx->wMsgType = CERT_TYPE_UNSUPPORTED;
        status = ERR_IKE_BAD_CERT_TYPE;
        DBG_EXIT
        /*break;*/
    }

    /* done */
    IN_END

exit:
    return status;
} /* InCert */


#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

/*------------------------------------------------------------------*/

static MSTATUS
InEap(IKE_context ctx)
{
    MSTATUS status;

    IKESA pxSa = ctx->pxSa;
    intBoolean bInitiator = IS_INITIATOR(pxSa);

    IKE2EAP pxEap = &pxSa->u.v2.eapState;

    ubyte2 wEapMsgLen;
    struct eapMsgHdr *pxEapMsg;
    struct eapMsgHdr *pxLastEapMsg = pxEap->pxMsg;

    ctx->flags |= IKE_CNTXT_FLAG_EAP;

    /* generic header */
    if (OK != (status = InGen(ctx, &wEapMsgLen)))
        goto exit;

    /* ESP message */
    pxEapMsg = (struct eapMsgHdr *)(ctx->pBuffer - wEapMsgLen);
    if ((SIZEOF_EAP_MSG_HDR > wEapMsgLen) ||
        (GET_NTOHS(pxEapMsg->wLength) != wEapMsgLen))
    {
        status = ERR_IKE_BAD_LEN;
        goto exit;
    }

    /* check status code */
    if (bInitiator) /* peer/supplicant */
    {
#ifdef __ENABLE_DIGICERT_EAP_PEER__
        switch (pxEapMsg->oCode)
        {
        case EAP_CODE_SUCCESS :
            if (EAP_PROTO_LEAP != pxEap->proto)
                pxSa->flags |= IKE_SA_FLAG_EAP_DONE;
        case EAP_CODE_REQUEST :
            break;
        case EAP_CODE_FAILURE :
            status = ERR_EAP;
            DBG_EXIT
        case EAP_CODE_RESPONSE :
            if ((EAP_PROTO_LEAP == pxEap->proto) && pxLastEapMsg)
            {
                if ((EAP_CODE_REQUEST != pxLastEapMsg->oCode)
/*                  || (pxEapMsg->oIdentifier != pxLastEapMsg->oIdentifier)*/
                    )
                {
                    status = ERR_EAP_INVALID_CODE;
                    goto exit;
                }
                break;
            }
        default :
            status = ERR_EAP_INVALID_CODE;
            DBG_EXIT
        }

        /* process EAP message */
        if (OK > (status = IKE_eapProcess(pxEapMsg, pxSa, ctx->pxXg)))
            goto exit;

        if ((EAP_PROTO_LEAP == pxEap->proto) &&
            (EAP_CODE_RESPONSE == pxEapMsg->oCode))
            pxSa->flags |= IKE_SA_FLAG_EAP_DONE;
#endif /* __ENABLE_DIGICERT_EAP_PEER__ */
    }
    else /* (responder) authenticator */
    {
#ifdef __ENABLE_DIGICERT_EAP_AUTH__
        if (!pxLastEapMsg) /* jic */
        {
            if ((EAP_PROTO_RADIUS == pxEap->proto) ||
                (EAP_PROTO_TTLS == pxEap->proto))
            {
                status = STATUS_IKE_PENDING;
                goto exit;
            }
            status = ERR_IKE_BAD_MSG;
            DBG_EXIT
        }

        /* retransmit? */
        switch (pxLastEapMsg->oCode)
        {
        case EAP_CODE_SUCCESS :
            if (EAP_PROTO_LEAP == pxEap->proto)
                break;
        case EAP_CODE_FAILURE :
            goto exit; /* EAP session already finished */
        default :
            break;
        }

        switch (pxEapMsg->oCode)
        {
        case EAP_CODE_RESPONSE :
            if (pxEapMsg->oIdentifier != pxLastEapMsg->oIdentifier)
            {
                DBG_ERRCODE(ERR_EAP_INSTANCE_ID_NOT_FOUND)
                goto exit;
            }
            break;
        case EAP_CODE_REQUEST :
            if (EAP_PROTO_LEAP == pxEap->proto)
                break;
        default :
            DBG_ERRCODE(ERR_EAP_INVALID_CODE)
            goto exit;
        }

        /* process EAP message */
        if (OK > (status = IKE_eapProcess(pxEapMsg, pxSa, ctx->pxXg)))
            goto exit;

        if (!pxEap->pxMsg) /* jic */
        {
            status = ERR_EAP;
            DBG_EXIT
        }

        switch (pxEap->pxMsg->oCode)
        {
        case EAP_CODE_RESPONSE :
            if (EAP_PROTO_LEAP == pxEap->proto)
                pxSa->flags |= IKE_SA_FLAG_EAP_DONE;
            break;
        case EAP_CODE_SUCCESS :
            if (EAP_PROTO_LEAP != pxEap->proto)
                pxSa->flags |= IKE_SA_FLAG_EAP_DONE;
            break;
        case EAP_CODE_FAILURE :
            DBG_ERRCODE(ERR_EAP)
            break;
        default :
            break;
        }
#endif /* __ENABLE_DIGICERT_EAP_AUTH__*/
    }

exit:
    if (OK > status)
    {
        if (STATUS_IKE_PENDING != status) /* in case of async */
        {
            if (!bInitiator)
                ctx->wMsgType = AUTHENTICATION_FAILED;
        }
    }
#ifdef __ENABLE_IKE_EAP_ONLY__
    else if ((IKE_SA_FLAG_EAP_ONLY & pxSa->flags) &&
             (IKE_SA_FLAG_EAP_DONE & pxSa->flags) &&
#ifdef __ENABLE_IKE_MULTI_AUTH__
             !pxSa->u.v2.authMtds[_R] && /* authenticator never authenticated */
#endif
             ((NULL == pxEap->poMsk) || (0 == pxEap->dwMskLen)))
    {
        /* EAP-only auth must generate a PSK; see RFC5998 3. p.6 */
        status = ERR_IKE_BAD_AUTH;
        DBG_STATUS
    }
#endif
    return status;
} /* InEap */

#endif /* (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_IPSEC_NAT_T__) || defined(__ENABLE_MOBIKE__)

static MSTATUS
InNatD(IKE_context ctx, intBoolean bPeer)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    IKE2XG pxXg = ctx->pxXg;
    ubyte __crypto__(poHash, SHA_HASH_RESULT_SIZE);

    sbyte4 compareResult;

    if ((NULL == pxSa) || (NULL == pxXg))
        goto exit; /* jic */

    /* ignore, if necessary */
#if defined(__ENABLE_MOBIKE__) && defined(__ENABLE_IPSEC_NAT_T__)
    if ((IKE_XCHG_INFO != pxXg->oExchange) ||
        !(IKE_SA_FLAG_MOBILE & pxSa->flags) ||
        !(IKE_NATT_FLAG_D & pxSa->natt_flags) ||
        (IKE_NATT_FLAG_NOT_ALLOWED & pxSa->natt_flags))
#endif
    if ((IKE_XCHG_INIT != pxXg->oExchange)
#ifndef __ENABLE_IPSEC_NAT_T__
     || !IS_INITIATOR(pxSa) /* !!! */
#endif
        )
    {
        goto exit;
    }

    /* compare NAT_D hash */
    _CRYPTO_ALLOC_(poHash, SHA_HASH_RESULT_SIZE)
    if (OK > (status = DoHashNatD(ctx, poHash, bPeer)))
        goto exit;

    if (OK > (status = DIGI_MEMCMP(poHash, ctx->pBuffer, SHA_HASH_RESULT_SIZE, &compareResult)))
        DBG_EXIT

    if (0 == compareResult) /* NOT behind NAT */
    {
        if (bPeer)  /* peer */
        {
            PEER_NOT_BEHIND_NAT(pxSa)
        }
#if defined(__ENABLE_MOBIKE__) && defined(__ENABLE_IPSEC_NAT_T__)
        else if (IKE_XCHG_INFO == pxXg->oExchange)
        {
            HOST_NOT_BEHIND_NAT(pxSa) /* us */
        }
#endif
    }
    else /* o/w behind NAT */
    {
        debug_printd((sbyte *)(bPeer ? "   NAT_D (peer/NAT):" : "   NAT_D (us/NAT):"),
                     ctx->pBuffer, SHA_HASH_RESULT_SIZE);

        if (!bPeer) /* us */
        {
            SET_HOST_BEHIND_NAT(pxSa)
        }
#if defined(__ENABLE_MOBIKE__) && defined(__ENABLE_IPSEC_NAT_T__)
        else if (IKE_XCHG_INFO == pxXg->oExchange)
        {
            SET_PEER_BEHIND_NAT(pxSa) /* peer */
        }
#endif
    }

#if defined(__ENABLE_MOBIKE__) && defined(__ENABLE_IPSEC_NAT_T__)
    if (IKE_XCHG_INIT == pxXg->oExchange)
#endif
        pxSa->natt_flags |= IKE_NATT_FLAG_D;

exit:
    _CRYPTO_FREE_(poHash)
    return status;
} /* InNatD */

#endif /* defined(__ENABLE_IPSEC_NAT_T__) || defined(__ENABLE_MOBIKE__) */


/*------------------------------------------------------------------*/

static MSTATUS
AddNotify(IKE2XG pxXg, IKEINFO_notify *ppxNotify,
          ubyte2 wMsgType, ubyte2 wDataLen, const ubyte *poData)
{
    MSTATUS status = OK;

    IKEINFO pxInfo = pxXg->pxInfo;

    IKEINFO_notify pxNotify;
    if (NULL == (pxNotify = (IKEINFO_notify)
                            MALLOC(sizeof(struct ike_info_notify))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMSET((ubyte *)pxNotify, 0x00, sizeof(struct ike_info_notify));

    if (0 != wDataLen)
    {
        if (NULL == (pxNotify->poData = (ubyte*) MALLOC(wDataLen)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        if (NULL != poData)
            DIGI_MEMCPY(pxNotify->poData, poData, wDataLen);

        pxNotify->wDataLen = wDataLen;
        pxNotify->wMsgType = wMsgType;
    }

    if (NULL == pxInfo)
    {
        if (NULL == (pxInfo = (IKEINFO) MALLOC(sizeof(struct ike_info))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        pxInfo->pxNotify = NULL;
        pxInfo->pxDelete = NULL;
        pxXg->pxInfo = pxInfo;
    }
    pxNotify->next = pxInfo->pxNotify;
    pxInfo->pxNotify = pxNotify;

    if (NULL != ppxNotify) *ppxNotify = pxNotify;
    pxNotify = NULL;

exit:
    if (NULL != pxNotify)
    {
        if (NULL != pxNotify->poData)
            FREE(pxNotify->poData);
        FREE(pxNotify);
    }
    return status;
} /* AddNotify */


/*------------------------------------------------------------------*/

static MSTATUS
InNotify(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    IKE2XG pxXg = ctx->pxXg;

    intBoolean bInitiator = IS_XCHG_INITIATOR(pxXg);

    ubyte oProtoId, oSpiSize;
    ubyte2 wMsgType;
    ubyte4 dwSpi=0;

    sbyte4 i;

    /* notify payload header */
    IN_BEGIN(struct ike2NotifyHdr, pxNotifyHdr, SIZEOF_IKE2_NOTIFY_HDR)

    oSpiSize = pxNotifyHdr->oSpiSize;
    if (wBodyLen < oSpiSize)
    {
        status = ERR_IKE_BAD_LEN;
        DBG_EXIT
    }

    switch (oProtoId = pxNotifyHdr->oProtoId)
    {
    case 0 :
    case PROTO_ISAKMP :
        if (oSpiSize)
        {
            /* see RFC4306 3.10. p.65 */
            DBG_ERRCODE(ERR_IKE_BAD_SPI)
        }
        break;
    case PROTO_IPSEC_AH :
    case PROTO_IPSEC_ESP :
        if (oSpiSize)
        {
            if (sizeof(ubyte4) != oSpiSize)
            {
                status = ERR_IKE_BAD_SPI;
                DBG_EXIT
            }
            SET_NTOHL(dwSpi, pxNotifyHdr->dwValue);
        }
        break;
    default :
        status = ERR_IKE_BAD_PROTOCOL;
        DBG_EXIT
    }

    SET_NTOHS(wMsgType, pxNotifyHdr->wMsgType);

    debug_print("   Notify: ");
    debug_print_ike2_notify(wMsgType);
    if (oProtoId)
    {
        debug_print(" (");
        debug_print_ike_proto(oProtoId);
        if (oSpiSize && dwSpi)
        {
            debug_print(" spi=");
            debug_hexint(dwSpi);
        }
        debug_print(")");
    }

    if (16383 >= wMsgType) /* error type */
    {
        if (bInitiator) /* response */
        {
            ctx->wMsgType = wMsgType; /* transient!!! */
        }
        else /* request */
        {
            if(AUTHENTICATION_FAILED == wMsgType)
            {

                status = ERR_IKE_MISMATCH_AUTH_METHOD;
                IKE2_delSa(pxSa, FALSE, status);
                ctx->wMsgType = 0;
                IN_END
                goto exit;
            }
            debug_printnl(" ignored");
            IN_END
            goto exit;
        }
    }

    debug_printnl(NULL);

    switch (wMsgType)
    {
    case INVALID_KE_PAYLOAD :
        if (bInitiator && /* must be a response */
            ((IKE_XCHG_INIT == pxXg->oExchange) || /* IKE_SA_INIT */
             (IKE_XCHG_CHILD == pxXg->oExchange))) /* CREATE_CHILD_SA */
        {
            ubyte2 wGrpNo;

            IKESA pxSa1 = pxXg->pxSa;
            IPSECSA pxIPsecSa = pxXg->pxIPsecSa;

            if ((ubyte2)(2 + oSpiSize) != wBodyLen)
            {
                status = ERR_IKE_BAD_LEN;
                DBG_EXIT
            }
            wGrpNo = DIGI_NTOHS(ctx->pBuffer + oSpiSize);

            debug_print("    DH_");
            debug_int(wGrpNo);
            debug_printnl(" proposed");

            if (IKE_checkGroup(wGrpNo, TRUE, pxSa, pxSa1, pxIPsecSa))
            {
                status = ERR_IKE_BAD_KE;
                DBG_EXIT
            }

            /* remember DH group given by Responder */
            if (NULL != pxSa1) /* IKE_SA */
            {
                pxSa1->wDhGrp = wGrpNo;

#ifdef __ENABLE_DIGICERT_PQC__
                if (NULL != pxSa1->pQsCtx)
                    CRYPTO_INTERFACE_QS_deleteCtx(&(pxSa1->pQsCtx));
#endif
            }
            else /* CHILD_SA */
            {
                pxIPsecSa->wPFS = wGrpNo;
            }
            /* will re-send; see initI_in() & childI_in() */
        }
        break;

    case NOTIFY_COOKIE :
        if (IKE_XCHG_INIT == pxXg->oExchange)
        {
            ubyte2 wCookieLen = wBodyLen - oSpiSize;
/*          ubyte *poCookie = ctx->pBuffer + oSpiSize;*/

            if (bInitiator)
            {
                struct ikeHdr *pxHdr = (struct ikeHdr *) pxSa->poMsg[_I];
                ubyte4 dwMsgLen = pxSa->dwMsgLen[_I];

                ubyte4 dwPayloadLen;
                ubyte *poPayload;
                ubyte *poMsg;

                if (!wCookieLen || (64 < wCookieLen))
                {
                    status = ERR_IKE_BAD_LEN;
                    DBG_EXIT
                }

                dwPayloadLen = dwMsgLen - SIZEOF_ISAKMP_HDR;
                poPayload = ((ubyte *)pxHdr) + SIZEOF_ISAKMP_HDR;

                /* jic - NOTIFY_COOKIE received before? */
                if (IKE_NEXT_N == pxHdr->oNextPayload)
                {
                    struct ike2NotifyHdr *pxNotifyHdr0 =
                        (struct ike2NotifyHdr *)poPayload;

                    if (NOTIFY_COOKIE == GET_NTOHS(pxNotifyHdr0->wMsgType))
                    {
                        ubyte2 wLength0 = GET_NTOHS(pxNotifyHdr0->wLength);
                        dwMsgLen = dwMsgLen - (ubyte4)wLength0;
                        poPayload = ((ubyte *)pxNotifyHdr0) + wLength0;
                        dwPayloadLen = dwPayloadLen - (ubyte4)wLength0;

                        pxNotifyHdr->oNextPayload = pxNotifyHdr0->oNextPayload;
                    }
                    else
                    {
                        pxNotifyHdr->oNextPayload = IKE_NEXT_N;
                    }
                }
                else
                {
                    pxNotifyHdr->oNextPayload = pxHdr->oNextPayload;
                    pxHdr->oNextPayload = IKE_NEXT_N;
                }
#if 1
                pxNotifyHdr->oProtoId = PROTO_ISAKMP; /* VPNC: question for ipsecme WG */
#endif
                dwMsgLen = dwMsgLen + (ubyte4)wLength;
                SET_HTONL(pxHdr->dwLength, dwMsgLen);

                /* update 1st IKE_SA_INIT message */
                CHECK_MALLOC(poMsg, dwMsgLen)
                DIGI_MEMCPY(poMsg, pxHdr, SIZEOF_ISAKMP_HDR);
                poMsg += SIZEOF_ISAKMP_HDR;
                DIGI_MEMCPY(poMsg, pxNotifyHdr, wLength);
                poMsg += wLength;
                DIGI_MEMCPY(poMsg, poPayload, dwPayloadLen);
                poMsg -= (dwMsgLen - dwPayloadLen);

                CHECK_FREE(pxSa->poMsg[_I]) /* must do this *after* memcpy!!! */
                pxSa->poMsg[_I] = poMsg;
                pxSa->dwMsgLen[_I] = dwMsgLen;

                /* update stored re-transmission */
#ifdef __ENABLE_IPSEC_NAT_T__
                if (USE_NATT_PORT(pxSa))
                {
                    /* include non-ESP marker */
                    dwMsgLen += 4;
                    CHECK_MALLOC(poMsg, dwMsgLen)
                    DIGI_MEMSET(poMsg, 0x00, 4);
                    DIGI_MEMCPY(poMsg+4, pxSa->poMsg[_I], dwMsgLen-4);
                }
                else
#endif
                {
                    CHECK_MALLOC(poMsg, dwMsgLen)
                    DIGI_MEMCPY(poMsg, pxSa->poMsg[_I], dwMsgLen);
                }

                CHECK_FREE(pxXg->poMsg[0])
                pxXg->poMsg[0] = poMsg;
                pxXg->dwMsgLen[0] = dwMsgLen;
                pxXg->numMsgs = 1;

                ctx->wMsgType = wMsgType; /* transient!!! */
            }
            else /* responder */
            {
                /* check cookie */
            }
        }
        break;

    case INITIAL_CONTACT :
        if ((IKE_XCHG_INIT == pxXg->oExchange) ||
            (IKE_XCHG_AUTH == pxXg->oExchange))
        {
            /* also see RFC4718 7.9. */
            pxSa->flags |= IKE_SA_FLAG_INIT_C;
        }
        break;

    case USE_TRANSPORT_MODE :
    {
        IPSECSA pxIPsecSa = pxXg->pxIPsecSa;
        if (NULL != pxIPsecSa)
        {
            for (i=0; IPSEC_NEST_MAX > i; i++)
            {
                IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[0].axChildSa[i].ipsecPps);
                if (bInitiator)
                {
                    if (i >= pxIPsecSa->axP2Sa[0].oChildSaLen)
                        break;

                    if (ENCAPSULATION_MODE_TUNNEL == pxIPsecPps->wMode)
                    {
                        /* ignored - FOR NOW */
                    }
                }
                pxIPsecPps->wMode = ENCAPSULATION_MODE_TRANSPORT;
            }
        }
        break;
    }

    case IPCOMP_SUPPORTED :
    {
        IPSECSA pxIPsecSa = pxXg->pxIPsecSa;
        if (NULL != pxIPsecSa)
        {
#ifdef __ENABLE_DIGICERT_IPCOMP__
            ubyte2 wCpi;
            ubyte oTfmId;

            if (oSpiSize) /* jic */
            {
                ADVANCE(oSpiSize)
                wBodyLen = wBodyLen - oSpiSize;
            }

            if ((sizeof(ubyte2) + sizeof(ubyte)) > wBodyLen)
            {
                status = ERR_IKE_BAD_LEN;
                DBG_EXIT
            }

            wCpi = DIGI_NTOHS(ctx->pBuffer);
            oTfmId = ctx->pBuffer[2];

            debug_print("    CPI=");
            debug_int(wCpi);
            debug_print(" ");
            debug_print_ike_tfmid(oTfmId, PROTO_IPCOMP);

            if (NULL == CHILDSA_findCompAlgo(oTfmId))
            {
                /* ignore for now */
                //if (bInitiator) pxIPsecSa->merror = ERR_IKE_MISMATCH_IPCOMP_ALGO;
                debug_printnl(" unknown");
            }
            else
            {
                ubyte2 wCpiM = 0;

                for (i=0; IPSEC_NEST_MAX > i; i++)
                {
                    IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[0].axChildSa[i].ipsecPps);

                    if (bInitiator)
                    {
                        if (i >= pxIPsecSa->axP2Sa[0].oChildSaLen)
                            break;

                        if (0 == pxIPsecPps->wCpi[_I]) /* no compression */
                        {
                            /* ignore for now */
                            //pxIPsecSa->merror = ERR_IKE_BAD_TRANSFORM;
                            debug_print(" mismatch");
                            break;
                        }
                    }

                    if (pxIPsecPps->oCompAlgo) /* already set */
                    {
                        debug_print(" skipped");
                        break;
                    }

                    if (!bInitiator)
                    {
                        /* get CPI; see RFC3173 3.3. (responder) */
                        if (0 == wCpiM)
                        do
                        {
                            if (OK > (status = RANDOM_numberGenerator(
                                                            g_pRandomContext,
                                                            (ubyte *) &wCpiM,
                                                            sizeof(ubyte2))))
                            {
                                debug_printnl(NULL);
                                DBG_EXIT
                            }
                        } while (((ubyte2)256 > wCpiM) || ((ubyte2)61439 < wCpiM));

                        pxIPsecPps->wCpi[_R] = wCpiM;
                    }

                    pxIPsecPps->wCpi[bInitiator ? _R : _I] = wCpi;
                    pxIPsecPps->oCompAlgo = oTfmId;
                }
                debug_printnl(NULL);
            }
#else
            /* ignore for now */
            //if (bInitiator) pxIPsecSa->merror = ERR_IKE_BAD_TRANSFORM;
            debug_printnl(" unsupported");
#endif
        }
        else
        {
            debug_printnl(" ignored"); /* jic */
        }
        break;
    }

#if defined(__ENABLE_IPSEC_NAT_T__) || defined(__ENABLE_MOBIKE__)
    case NAT_DETECTION_DESTINATION_IP :
        if (IKE_CNTXT_FALG_NAT_D_DST & ctx->flags)
        {
            /* already received NAT_D_DST payload */
            status = ERR_IKE_BAD_NAT_D;
            DBG_EXIT
        }
        ctx->flags |= IKE_CNTXT_FALG_NAT_D_DST;
        /* fall through */
    case NAT_DETECTION_SOURCE_IP :
#ifdef __ENABLE_MOBIKE__
        if ((NAT_DETECTION_SOURCE_IP == wMsgType) &&
            (IKE_XCHG_INFO == pxXg->oExchange))
        {
            if (IKE_CNTXT_FALG_NAT_D_SRC & ctx->flags)
            {
                /* already received NAT_D_SRC payload */
                status = ERR_IKE_BAD_NAT_D;
                DBG_EXIT
            }
            ctx->flags |= IKE_CNTXT_FALG_NAT_D_SRC;
        }
#endif
        if ((oSpiSize + SHA_HASH_RESULT_SIZE) > wBodyLen)
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }
        if (oSpiSize) /* jic */
        {
            ADVANCE(oSpiSize)
            wBodyLen = wBodyLen - oSpiSize;
        }
        status = InNatD(ctx, (NAT_DETECTION_SOURCE_IP == wMsgType)
                              ? TRUE : FALSE);
        break;
#endif /* defined(__ENABLE_IPSEC_NAT_T__) || defined(__ENABLE_MOBIKE__) */

#ifdef __ENABLE_MOBIKE__
    case MOBIKE_SUPPORTED :
        if (IKE_XCHG_AUTH == pxXg->oExchange)
            pxSa->flags |= IKE_SA_FLAG_MOBILE;
        break;

    case ADDITIONAL_IP4_ADDRESS :
    case ADDITIONAL_IP6_ADDRESS :
        if ((IKE_XCHG_AUTH == pxXg->oExchange) ||
            (!bInitiator &&
             (IKE_XCHG_INFO == pxXg->oExchange) &&
             (IKE_SA_FLAG_MOBILE & pxSa->flags)))
        {
            MOC_IP_ADDRESS_S ipAddr = MOC_IPADDR_NONE;

            ADVANCE(oSpiSize)
            wBodyLen = wBodyLen - oSpiSize;

            if (ADDITIONAL_IP6_ADDRESS == wMsgType)
            {
                if (16 > wBodyLen)
                {
                    status = ERR_IKE_BAD_MSG;
                    DBG_EXIT
                }
#ifdef __ENABLE_DIGICERT_IPV6__
                SET_MOC_IPADDR6(ipAddr, ctx->pBuffer);
#else
                break;
#endif
            }
            else
            {
                if (4 > wBodyLen)
                {
                    status = ERR_IKE_BAD_MSG;
                    DBG_EXIT
                }
                SET_MOC_IPADDR4(ipAddr, DIGI_NTOHL(ctx->pBuffer));
            }

            debug_print("    ");
            debug_print_ip(REF_MOC_IPADDR(ipAddr));
            debug_printnl(NULL);

            /* TBD */
        }
        break;

    case NO_ADDITIONAL_ADDRESSES :
    case UPDATE_SA_ADDRESSES :
        if (!bInitiator &&
            (IKE_XCHG_INFO == pxXg->oExchange) &&
            (IKE_SA_FLAG_MOBILE & pxSa->flags))
        {
            /* no data */
            if (NO_ADDITIONAL_ADDRESSES == wMsgType)
            {
                /* TBD */
            }
            else
            {
                pxXg->x_flags |= IKE_XCHG_FLAG_UPDATE_SA;
            }
        }
        break;

    case COOKIE2 :
        if ((IKE_XCHG_INFO == pxXg->oExchange) &&
            (IKE_SA_FLAG_MOBILE & pxSa->flags))
        {
            ADVANCE(oSpiSize)
            wBodyLen = wBodyLen - oSpiSize;

            if (bInitiator)
            {
                if (IKE_XCHG_FLAG_COOKIE2 & pxXg->x_flags)
                {
                    if (NULL != pxXg->pxInfo) /* jic */
                    {
                        IKEINFO_notify pxNotify = pxXg->pxInfo->pxNotify;
                        for (; NULL != pxNotify; pxNotify = pxNotify->next)
                        {
                            if (COOKIE2 == pxNotify->wMsgType)
                            {
                                sbyte4 compareResult = -1;
                                if (wBodyLen == pxNotify->wDataLen)
                                {
                                    if (OK > (status = DIGI_MEMCMP(
                                            pxNotify->poData, ctx->pBuffer,
                                            wBodyLen, &compareResult)))
                                        DBG_EXIT
                                }
                                if (0 != compareResult) /* mismatch */
                                {
                                    status = ERR_IKE_BAD_COOKIE2;
                                    DBG_EXIT
                                }
                                break;
                            }
                        }
                    }
                    ctx->flags |= IKE_CNTXT_FLAG_COOKIE2;
                }
            }
            else
            {
                /* MUST be between 8 and 64 */
                if ((8 > wBodyLen) || (64 < wBodyLen))
                {
                    status = ERR_IKE_BAD_COOKIE2;
                    DBG_EXIT
                }

                if (OK > (status = AddNotify(pxXg, NULL, COOKIE2,
                                             wBodyLen, ctx->pBuffer)))
                    DBG_EXIT

                ctx->flags |= IKE_CNTXT_FLAG_COOKIE2;
           }
        }
        break;

    case NO_NATS_ALLOWED :
        if (!bInitiator &&
            ((IKE_XCHG_AUTH == pxXg->oExchange) ||
             ((IKE_XCHG_INFO == pxXg->oExchange) &&
              (IKE_SA_FLAG_MOBILE & pxSa->flags))))
        {
            MOC_IP_ADDRESS hostAddr = REF_MOC_IPADDR(pxSa->dwHostAddr);

            MOC_IP_ADDRESS_S srcAddr = MOC_IPADDR_NONE;
            MOC_IP_ADDRESS_S dstAddr = MOC_IPADDR_NONE;
            ubyte2 wSrcPort, wDstPort;

#ifdef __ENABLE_IPSEC_NAT_T__
            if (IS_BEHIND_NAT(pxSa))
            {
                ctx->wMsgType = UNEXPECTED_NAT_DETECTED;
                status = ERR_IKE_BAD_NAT_D;
                DBG_EXIT
            }
#endif
            ADVANCE(oSpiSize)
            wBodyLen = wBodyLen - oSpiSize;

            TEST_MOC_IPADDR6(hostAddr,
            {
                struct ikeNoNatsA6 *pxNna6 = (struct ikeNoNatsA6 *) ctx->pBuffer;

                if (SIZEOF_IKE_NNA6_DATA > wBodyLen)
                {
                    status = ERR_IKE_BAD_MSG;
                    DBG_EXIT
                }

                SET_MOC_IPADDR6(srcAddr, pxNna6->srcAddr);
                SET_MOC_IPADDR6(dstAddr, pxNna6->dstAddr);
                SET_NTOHS(wSrcPort, pxNna6->wSrcPort);
                SET_NTOHS(wDstPort, pxNna6->wDstPort);
            })
            {
                struct ikeNoNatsA *pxNna = (struct ikeNoNatsA *) ctx->pBuffer;

                if (SIZEOF_IKE_NNA_DATA > wBodyLen)
                {
                    status = ERR_IKE_BAD_MSG;
                    DBG_EXIT
                }

                SET_MOC_IPADDR4(srcAddr, GET_NTOHL(pxNna->dwSrcAddr));
                SET_MOC_IPADDR4(dstAddr, GET_NTOHL(pxNna->dwDstAddr));
                SET_NTOHS(wSrcPort, pxNna->wSrcPort);
                SET_NTOHS(wDstPort, pxNna->wDstPort);
            }

            if ((wDstPort != pxSa->wHostPort) ||
                !SAME_MOC_IPADDR(hostAddr, dstAddr) ||
                (wSrcPort != ctx->wPeerPort) ||
                !SAME_MOC_IPADDR(ctx->peerAddr, srcAddr))
            {
                ctx->wMsgType = UNEXPECTED_NAT_DETECTED;
                status = ERR_IKE_BAD_NAT_D;
                DBG_EXIT
            }

            pxSa->natt_flags |= IKE_NATT_FLAG_NOT_ALLOWED;
        }
        break;
#endif /* __ENABLE_MOBIKE__ */

    case R_U_THERE : /* DPD (rfc3706); adapted for IKEv2 */
    {
        IKEINFO_notify pNotify = NULL;

        if (oProtoId && (PROTO_ISAKMP != oProtoId)) /* jic */
        {
            status = ERR_IKE_BAD_MSG;
            DBG_EXIT
        }

        /* check sequence number (4 bytes) */
        if (sizeof(ubyte4) > wBodyLen)
        {
            status = ERR_IKE_BAD_MSG;
            DBG_EXIT
        }

        /* must be an encrypted request */
        if (bInitiator || !IS_IKE2_SA_AUTHED(pxSa))
        {/*
            status = ERR_IKE_BAD_MSG;
            DBG_EXIT */
            break; /* ignore it */
        }

        /* set up R-U-THERE-ACK notification */
        if (OK > (status = AddNotify(pxXg, &pNotify, R_U_THERE_ACK,
                                     sizeof(ubyte4), ctx->pBuffer))) /* seq num */
            DBG_EXIT

        pNotify->oProtoId = PROTO_ISAKMP; /* !!! or 0? */
        break;
    }

    case AUTH_LIFETIME : /* Repeated Auth. (rfc4478) */
        if (0 != oProtoId) /* jic */
        {
            status = ERR_IKE_BAD_MSG;
            DBG_EXIT
        }

        if (sizeof(ubyte4) > wBodyLen) /* lifetime (secs) */
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }

        /* must be original initiator */
        if (!(IKE_SA_FLAG_ORIG_INITR & pxSa->flags))
        {/*
            status = ERR_IKE_BAD_MSG;
            DBG_EXIT */
            break; /* ignore it */
        }

        if (!(IKE_SA_FLAG_REAUTH & pxSa->flags))
        {
            /* get lifetime (in secs) *left* before repeating IKE_SA_INIT */
            ubyte4 dwExpAuthSecs;
            SET_NTOHL(dwExpAuthSecs, pxNotifyHdr->dwValue);

            if (0 == dwExpAuthSecs)
            {
                if (IS_IKE2_SA_AUTHED(pxSa))
                {
                    pxSa->flags |= IKE_SA_FLAG_REAUTH;

                    /* Initial exchange should begin immediately */
                    if (m_ikeSettings.funcPtrIkeStatHdlr)
                        m_ikeSettings.funcPtrIkeStatHdlr(ISC_SA, IST_REAUTH,
                                                    pxSa->dwId, pxSa, NULL);
                        /* TODO: Trigger rekeying child IPsec SA's */
                }
            }
            else
            {
                if ((ubyte4)300 > dwExpAuthSecs)
                    dwExpAuthSecs = 300;
                else if ((ubyte4)86400 < dwExpAuthSecs)
                    dwExpAuthSecs = 86400;

                pxSa->u.v2.dwExpAuthSecs = dwExpAuthSecs;
                if (IS_IKE2_SA_AUTHED(pxSa))
                {
                    ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);
                    pxSa->u.v2.dwExpAuthSecs += (ubyte4)
                                ((timenow - pxSa->u.v2.dwTimeAuthed) / 1000);

                    if ((pxSa != pxXg->pxSa) && (NULL != pxXg->pxSa)) /* jic - REKEY_SA */
                        pxXg->pxSa->u.v2.dwExpAuthSecs = pxSa->u.v2.dwExpAuthSecs;
                }
            }
        }
        break;

#ifdef __ENABLE_IKE_REDIRECT__
    case REDIRECT_SUPPORTED :
    case REDIRECTED_FROM :
    {
        ubyte4  count = 0;

        if (OK > (status = IKE2_getSaNum(&count)))
            goto exit;

#if defined(__ENABLE_IKE_REDIRECT_IN_INIT__)
        if ((IKE_XCHG_INIT == pxXg->oExchange) && (count > IKE_REDIRECT_MAX))
        {
            /* we are maxed out, so send REDIRECT */
            ctx->wMsgType = REDIRECT;
        }
#elif defined(__ENABLE_IKE_REDIRECT_IN_AUTH__)
        if ((IKE_XCHG_AUTH == pxXg->oExchange) && (count > IKE_REDIRECT_MAX))
        {
            /* we are maxed out, so send REDIRECT */
            ctx->wMsgType = REDIRECT;
        }
#endif
        break;
    }

    case REDIRECT :
    {
        /* parse */
        sbyte4 compareResult;
        ubyte4 elapsedMs = 0;

        struct ikeRedirect *pRedirect = (struct ikeRedirect *) ctx->pBuffer;

        if (0 == g_ikeRedirectCount)
        {
            /* start redirect loop detection timer */
            if (OK > (status = TIMER_queueTimer((void *)pxSa, pxSa->redirectTimerId, REDIRECT_LOOP_DETECT_PERIOD, 0)))
            {
                goto exit;
            }
        }
        g_ikeRedirectCount++;

        if ( OK > TIMER_getTimerElapsed((void *)pxSa, pxSa->redirectTimerId, &elapsedMs))
        {
            goto exit;
        }

        if ((g_ikeRedirectCount > MAX_REDIRECTS) && (elapsedMs < REDIRECT_LOOP_DETECT_PERIOD * 1000))
        {
            status = ERR_IKE_REDIRECT_LOOP;
            DBG_EXIT
        }

#ifdef __ENABLE_DIGICERT_IPV6__
        if (pRedirect->gwIdType != REDIRECT_GW_TYPE_IPV6 || pRedirect->gwIdLen != 16)
#endif
        if (pRedirect->gwIdType != REDIRECT_GW_TYPE_IPV4 || pRedirect->gwIdLen != 4)
        {
            status = ERR_IKE_BAD_MSG;
            DBG_EXIT
        }

        if (IKE_XCHG_INFO != pxXg->oExchange)
        {
            if (OK > (status = DIGI_MEMCMP(
#ifdef __ENABLE_DIGICERT_IPV6__
                                          (REDIRECT_GW_TYPE_IPV6 == pRedirect->gwIdType)
                                          ? (ctx->pBuffer + 18) :
#endif
                                          (ctx->pBuffer + 6),
                                          pxSa->poNonce[_I], pxSa->wNonceLen[_I],
                                          &compareResult)))
                DBG_EXIT

            if (0 != compareResult) /* mismatch */
            {
                status = ERR_IKE_BAD_NONCE;
                DBG_EXIT
            }
        }

        COPY_MOC_IPADDR(ctx->oldPeerAddr, ctx->peerAddr);
#ifdef __ENABLE_DIGICERT_IPV6__
        if (REDIRECT_GW_TYPE_IPV6 == pRedirect->gwIdType)
        {
            SET_MOC_IPADDR6(pxSa->dwPeerAddr, ctx->pBuffer + 2);
        }
        else
#endif
        {
            SET_MOC_IPADDR4(pxSa->dwPeerAddr, DIGI_NTOHL(ctx->pBuffer + 2));
        }
        ctx->peerAddr = REF_MOC_IPADDR(pxSa->dwPeerAddr);

        ctx->wMsgType = REDIRECTED_FROM;
        break;
    }
#endif /* __ENABLE_IKE_REDIRECT__ */

#if defined(__ENABLE_IKE_EAP_ONLY__) && defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    case EAP_ONLY_AUTHENTICATION :
        ctx->flags |= IKE_CNTXT_FLAG_EAP_ONLY;
        break;
#endif

#ifdef __ENABLE_IKE_FRAGMENTATION__
    case IKEV2_FRAGMENTATION_SUPPORTED :
        if ((IKE_XCHG_INIT == pxXg->oExchange) &&
            (!pxSa->ikePeerConfig->bNoIkeFrag))
        {
            pxSa->flags |= IKE_SA_FLAG_FRAGMENTATION;
        }
        break;
#endif
#ifdef __ENABLE_IKE_PPK_RFC8784__
    case USE_PPK :
        if ((IKE_XCHG_INIT == pxXg->oExchange) &&
            (pxSa->ikePeerConfig->bUsePpk))
        {
            pxSa->flags |= IKE_SA_FLAG_USEPPK;
        }
        break;
    case PPK_IDENTITY :
    {
        sbyte4 compareResult;
        if ((IKE_XCHG_AUTH == pxXg->oExchange) &&
           (pxSa->flags & IKE_SA_FLAG_USEPPK))
        {
            pxSa->flags |= IKE_SA_FLAG_PPK_ID;
            if(!bInitiator)
            {
            if((wBodyLen != pxSa->ikePeerConfig->ppkid_len+1) ||
                (ctx->pBuffer[0] != 0x02))
            {
                status = ERR_IKE_BAD_MSG;
                DBG_EXIT
            }
            if (OK > (status = DIGI_MEMCMP(pxSa->ikePeerConfig->ppk_id, &(ctx->pBuffer[1]),
                                 wBodyLen-1, &compareResult)))
            {                     
                DBG_EXIT
            }
            if (0 != compareResult) /* mismatch */
            {
                status = ERR_IKE_PPK_ID_MISMATCH;
                ctx->wMsgType = AUTHENTICATION_FAILED;
                DBG_EXIT
            }
            }
        }
        else
        {
            status = ERR_IKE_BAD_MSG;
            DBG_EXIT
        }
        break;
    }
#endif

#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
    case SIGNATURE_HASH_ALGORITHMS :
        if (oProtoId || oSpiSize) /* jic */
        {
            status = ERR_IKE_BAD_MSG;
            DBG_EXIT
        }

        if (!pxSa->ikePeerConfig->bNoSigAuth &&
            (IKE_XCHG_INIT == pxXg->oExchange))
        {
            sbyte4 j = wBodyLen / sizeof(ubyte2);
            if (0 >= j) break;

            pxSa->u.v2.numSahAlgos = 0;
            debug_print("   ");

            for (i=0; i < j; i++)
            {
                ubyte2 wSigHash = DIGI_NTOHS(ctx->pBuffer + (i * sizeof(ubyte2)));
                IKE_hashSuiteInfo *pHashSuite = IKE_sigHashSuite(pxSa->ikePeerConfig, wSigHash);
                debug_print(" ");
                if (pHashSuite)
                {
                    debug_print(pHashSuite->name1);
                    if (NUM_SIGAUTH_HASH > pxSa->u.v2.numSahAlgos)
                    {
                        pxSa->u.v2.sahAlgos[pxSa->u.v2.numSahAlgos++] = wSigHash;
                    }
                    else
                    {
                        debug_print(" (skipped)");
                    }
                }
                else
                {
                    debug_int(wSigHash);
                }
            }
            debug_printnl(NULL);
        }
        break;
#endif

#ifdef __ENABLE_IKE_MULTI_AUTH__
    case MULTIPLE_AUTH_SUPPORTED :
        if (pxSa->ikePeerConfig->bDoMultiAuth &&
            ((bInitiator && (IKE_XCHG_INIT == pxXg->oExchange)) ||
             (!bInitiator && (IKE_XCHG_AUTH == pxXg->oExchange))))
        {
            pxSa->flags |= IKE_SA_FLAG_MULTI_AUTH;
        }
        break;
    case ANOTHER_AUTH_FOLLOWS :
        if (IKE_XCHG_AUTH == pxXg->oExchange)
        {
            ctx->flags |= IKE_CNTXT_FLAG_ANOTHER_AUTH;
        }
        break;
#endif

    default :
        /* FOR NOW */
        break;
    }

    /* done */
    IN_END

exit:
#ifdef CUSTOM_IKE_CATCH_EXCEPTION
       if (status < OK)
       {
               MOC_IP_ADDRESS peerAddr = REF_MOC_IPADDR(pxSa->dwPeerAddr);
               CUSTOM_IKE_CATCH_EXCEPTION(ERR_IKE_NOTIFY_PAYLOAD,
                       peerAddr, ctx->pxIkeHdr,
                       IKE_NEXT_N, pxNotifyHdr,
                       pxSa, pxXg, NULL);
       }
#endif
return status;
} /* InNotify */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_IKE_MULTI_AUTH__
static MSTATUS
InNotifyMultiAuth(IKE_context ctx)
{
    /* Called by authR_in() & authI_in() only */
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    ubyte2 wMsgType;

    /* notify payload header */
    IN_BEGIN(struct ike2NotifyHdr, pxNotifyHdr, SIZEOF_IKE2_NOTIFY_HDR)

    SET_NTOHS(wMsgType, pxNotifyHdr->wMsgType);

    switch (wMsgType)
    {
    case MULTIPLE_AUTH_SUPPORTED :
    case ANOTHER_AUTH_FOLLOWS :
    {
        debug_print("   Notify: ");
        debug_print_ike2_notify(wMsgType);
        debug_printnl(NULL);

        if (MULTIPLE_AUTH_SUPPORTED == wMsgType)
        {
            if (!IS_XCHG_INITIATOR(ctx->pxXg) &&
                pxSa->ikePeerConfig->bDoMultiAuth)
            {
                pxSa->flags |= IKE_SA_FLAG_MULTI_AUTH;
            }
        }
        else
        {
            ctx->flags |= IKE_CNTXT_FLAG_ANOTHER_AUTH;
        }
        break;
    }
    default :
        break;
    }

    /* done */
    IN_END

exit:
    return status;
} /* InNotifyMultiAuth */
#endif


/*------------------------------------------------------------------*/

static MSTATUS
InDelete(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;

    ubyte2 wSpiNum, i;

    /* delete payload header */
    IN_BEGIN(struct ike2DelHdr, pxDelHdr, SIZEOF_IKE2_DEL_HDR)
    SET_NTOHS(wSpiNum, pxDelHdr->wSpiLen);

    debug_print("   Delete: ");
    debug_int(wSpiNum);
    debug_print3(" ",
        ((PROTO_ISAKMP == pxDelHdr->oProtoId) ? "IKE_" : "IPsec "),
        ((1==wSpiNum) ? "SA" : "SA's"));

    /* must always be performed under protection */
    if (!IS_IKE2_SA_AUTHED(pxSa))
    {
        DBG_ERRCODE(ERR_IKE_BAD_PAYLOAD)
        goto exit;
    }

    switch (pxDelHdr->oProtoId)
    {
    case PROTO_ISAKMP :
    {
        ubyte4 j;

        if (pxDelHdr->oSpiSize)
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }

        /*IKE2_delSa(pxSa, TRUE, STATUS_IKE_DELETE_PAYLOAD);*/
        pxSa->flags |= IKE_SA_FLAG_DELETING;
        pxSa->merror = STATUS_IKE_DELETE_PAYLOAD;

        /* delete our requests */
        for (j = pxSa->u.v2.dwWndLen[_I]; 0 != j; j--)
        {
            IKE2XG pxXg = &(pxSa->u.v2.pxXg[_I][j-1]);
            if (IS_VALID_XCHG(pxXg) && (pxXg != ctx->pxXg))
               IKE2_delXchg(pxXg, pxSa, STATUS_IKE_DELETE_PAYLOAD);
        }
        break;
    }
    case PROTO_IPSEC_AH :
    case PROTO_IPSEC_ESP :
    {
        INIT_MOC_IPADDR(peerAddr, pxSa->dwPeerAddr)
#ifdef __ENABLE_DIGICERT_PFKEY__
        INIT_MOC_IPADDR(hostAddr, pxSa->dwHostAddr)
#endif
        struct ipsecKey key = { 0 };
#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
        sbyte4 st;
#endif
        if (sizeof(ubyte4) != pxDelHdr->oSpiSize)
        {
            status = ERR_IKE_BAD_MSG;
            DBG_EXIT
        }
        if (wBodyLen < (sizeof(ubyte4) * wSpiNum))
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }

        TEST_MOC_IPADDR6(peerAddr,
        {
            key.flags |= IPSEC_SA_FLAG_IP6;
            key.dwDestAddr = (CAST_MOC_IPADDR) GET_MOC_IPADDR6(peerAddr);
        })
        key.dwDestAddr = GET_MOC_IPADDR4(peerAddr);

#ifdef __ENABLE_DIGICERT_PFKEY__
        TEST_MOC_IPADDR6(hostAddr, {
            key.dwSrcAddr = (CAST_MOC_IPADDR) GET_MOC_IPADDR6(hostAddr);
        })
        key.dwSrcAddr = GET_MOC_IPADDR4(hostAddr);
#endif
        key.oProtocol = (ubyte)((PROTO_IPSEC_AH == pxDelHdr->oProtoId)
                      ? IPPROTO_AH : IPPROTO_ESP);
#ifdef __ENABLE_IPSEC_NAT_T__
        if (IS_PEER_BEHIND_NAT(pxSa))
            key.wUdpEncPort = pxSa->wPeerPort;
#endif
        key.dwIkeSaId = pxSa->dwId0; /* see RFC4306 1.4. 2nd paragraph */

        for (i=0; i < wSpiNum; i++)
        {
            ubyte4 dwSpi = GET_NTOHL(pxDelHdr->adwSpi[i]);
            key.dwSpi = dwSpi;
#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
            st =
#endif
            IPSEC_keyDelete(&key);

            debug_print("    IPSEC_keyDelete(");
            debug_print_ike_proto(pxDelHdr->oProtoId);
            debug_print(" spi=");
            debug_hexint(key.dwSpi);
            debug_print(" dest=");
            debug_print_ip(peerAddr);
            debug_print(")");
            debug_print_st(st);
        }
        break;
    }
    default :
        status = ERR_IKE_BAD_MSG;
        DBG_EXIT
    }

    /* done */
    IN_END

exit:
    return status;
} /* InDelete */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE2_checkCookie(IKE_context ctx)
{
    MSTATUS status = OK;

    MD5_CTX *md5Ctx = NULL;

    /*
       Cookie = <VersionIDofSecret> | Hash(Ni | IPi | SPIi | <secret>)
     */
    ubyte *poCookie = NULL;
    ubyte *poNonce = NULL;
    ubyte2 wNonceLen = 0;

    IN_SET /* save current context */

    if (IKE_NEXT_N == ctx->oNextPayload)
    {
        /* notify payload header */
        IN_BEGIN(struct ike2NotifyHdr, pxNotifyHdr, SIZEOF_IKE2_NOTIFY_HDR)

        if (NOTIFY_COOKIE == GET_NTOHS(pxNotifyHdr->wMsgType))
        {
            if ((sizeof(ubyte4) + MD5_DIGESTSIZE) > wBodyLen)
            {
                status = ERR_IKE_BAD_LEN;
                DBG_EXIT
            }

            if (DIGI_NTOHL(ctx->pBuffer) == g_ikeScrtVerID)
                poCookie = ctx->pBuffer + sizeof(ubyte4);
            else
            {
                /* wrong secret version */
                DBG_ERRCODE(ERR_IKE_BAD_NOTIFY_COOKIE)
            }
        }

        IN_END
    }

    IN_LOOP_BEGIN
        if (IKE_NEXT_NONCE == ctx->oNextPayload) /* Ni */
        {
            /* generic header */
            if (OK != (status = InGen(ctx, &wNonceLen)))
                goto exit;
            poNonce = ctx->pBuffer - wNonceLen;
            break;
        }
        else
        IN_REJECT(IKE_NEXT_E)
#ifdef __ENABLE_IKE_FRAGMENTATION__
        IN_REJECT(IKE_NEXT_EF)
#endif
    IN_LOOP_NONE
    } /* paranthesis started with IN_LOOP_BEGIN */

    IN_RESET /* restore context */

    if (!poNonce) /* missing Ni */
    {
        status = ERR_IKE_BAD_NONCE;
        DBG_EXIT
    }
    else
    {
        /* calculate cookie value - MD5(Ni | IPi | SPIi | <secret>) */
        ubyte *poSPIi = ((struct ikeHdr *) ctx->pHdrParent)->poCky_I;
        MOC_IP_ADDRESS IPi = ctx->peerAddr;

        ubyte4 dwIPi;
        const ubyte *poIPi;
        sbyte4 lenIPi;

        TEST_MOC_IPADDR6(IPi,
        {
            poIPi = GET_MOC_IPADDR6(IPi);
            lenIPi = 16;
        })
        {
            SET_HTONL(dwIPi, GET_MOC_IPADDR4(IPi));
            poIPi = (const ubyte *) &dwIPi;
            lenIPi = 4;
        }

        if ((NULL == ctx->u.v2.poCookie) && /* jic */
            (OK > (status = CRYPTO_ALLOC(ctx->hwAccelCookie, MD5_DIGESTSIZE, TRUE, (void**) &ctx->u.v2.poCookie))))
            DBG_EXIT

        if (OK > (status = IKE_md5Alloc(MOC_HASH(ctx->hwAccelCookie) (BulkCtx *)&md5Ctx)))
            DBG_EXIT

        status = DIGI_MEMSET((void*)md5Ctx, 0x00, sizeof(MD5_CTX));
        if (OK != status)
            DBG_EXIT

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if ((OK > (status = CRYPTO_INTERFACE_MD5Init_m(MOC_HASH(ctx->hwAccelCookie) md5Ctx))) ||
            (OK > (status = CRYPTO_INTERFACE_MD5Update_m(MOC_HASH(ctx->hwAccelCookie) md5Ctx, poNonce, wNonceLen))) ||
            (OK > (status = CRYPTO_INTERFACE_MD5Update_m(MOC_HASH(ctx->hwAccelCookie) md5Ctx, poIPi, lenIPi))) ||
            (OK > (status = CRYPTO_INTERFACE_MD5Update_m(MOC_HASH(ctx->hwAccelCookie) md5Ctx, poSPIi, IKE_COOKIE_SIZE))) ||
            (OK > (status = CRYPTO_INTERFACE_MD5Update_m(MOC_HASH(ctx->hwAccelCookie) md5Ctx, g_ikeSecret, g_ikeScrtLen))) ||
            (OK > (status = CRYPTO_INTERFACE_MD5Final_m(MOC_HASH(ctx->hwAccelCookie) md5Ctx, ctx->u.v2.poCookie))))
#else
        if ((OK > (status = MD5init_HandShake(MOC_HASH(ctx->hwAccelCookie) md5Ctx))) ||
            (OK > (status = MD5update_HandShake(MOC_HASH(ctx->hwAccelCookie) md5Ctx, poNonce, wNonceLen))) ||
            (OK > (status = MD5update_HandShake(MOC_HASH(ctx->hwAccelCookie) md5Ctx, poIPi, lenIPi))) ||
            (OK > (status = MD5update_HandShake(MOC_HASH(ctx->hwAccelCookie) md5Ctx, poSPIi, IKE_COOKIE_SIZE))) ||
            (OK > (status = MD5update_HandShake(MOC_HASH(ctx->hwAccelCookie) md5Ctx, g_ikeSecret, g_ikeScrtLen))) ||
            (OK > (status = MD5final_HandShake(MOC_HASH(ctx->hwAccelCookie) md5Ctx, ctx->u.v2.poCookie))))
#endif
            DBG_EXIT
    }

    /* check cookie value, if any */
    if (NULL != poCookie)
    {
        sbyte4 compareResult;
        if (OK > (status = DIGI_MEMCMP(poCookie, ctx->u.v2.poCookie, MD5_DIGESTSIZE, &compareResult)))
            DBG_EXIT

        if (0 != compareResult) /* mismatch */
        {
            status = ERR_IKE_BAD_NOTIFY_COOKIE;
            DBG_EXIT
        }

        goto exit;
    }

    ctx->wMsgType = NOTIFY_COOKIE;

exit:
    if (md5Ctx)
    {
        IKE_md5Free(MOC_HASH(ctx->hwAccelCookie) (BulkCtx *)&md5Ctx);
    }
    return status;
} /* IKE2_checkCookie */


/*------------------------------------------------------------------*/

static MSTATUS IKE2_decryptAead(const AeadAlgo *pAlg, ubyte *pKey, ubyte4 keyLen,
    ubyte *pSalt, ubyte4 saltLen, ubyte *pIv, ubyte4 ivLen,
    ubyte *pData, ubyte4 dataLen, ubyte *pAdata, ubyte4 aDataLen,
    ubyte **ppIcv, sbyte4 *pCmpResult)
{
    MSTATUS status;
    BulkCtx pCtx = NULL; 
    ubyte *pNonce = NULL;
    ubyte4 nonceLen;
    ubyte4 tagLen = 0;

    if ((NULL == pAlg) || (NULL == pKey) || (NULL == pData) || (NULL == pAdata) ||
        (NULL == pCmpResult) || (NULL == ppIcv))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pCmpResult = 1;

    if ((saltLen != pAlg->implicitNonceSize) || (ivLen != pAlg->explicitNonceSize))
    {
        status = ERR_IKE_BAD_LEN;
        goto exit;
    }

    nonceLen = saltLen + ivLen;
    status = DIGI_MALLOC((void **)&pNonce, nonceLen);
    if (OK != status)
        goto exit;

    /* add salt bytes of nonce */
    status = DIGI_MEMCPY(pNonce, pSalt, saltLen);
    if (OK != status)
        goto exit;

    /* add IV bytes of nonce */
    status = DIGI_MEMCPY(pNonce + saltLen, pIv, ivLen);
    if (OK != status)
        goto exit;

    pCtx = pAlg->createFunc(pKey, keyLen, FALSE);
    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = pAlg->cipherFunc(pCtx, pNonce, nonceLen, pAdata, aDataLen, pData,
        dataLen - pAlg->tagSize, pAlg->tagSize, FALSE);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **)ppIcv, pAlg->tagSize);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(*ppIcv, pData + dataLen - pAlg->tagSize, pAlg->tagSize);
    if (OK != status)
        goto exit;

exit:
    if (NULL != pNonce)
        DIGI_FREE((void **) &pNonce);

    if (NULL != pAlg)
        pAlg->deleteFunc(&pCtx);

    if (OK == status)
        *pCmpResult = 0;
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
IKE2_checkSK(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    IKE2XG pxXg = ctx->pxXg;
    IKE_macSuiteInfo *pMacSuite = pxSa->pMacSuite;
    IKE_cipherSuiteInfo *pCipherSuite = pxSa->pCipherSuite;
    ubyte4 ivLen;
    ubyte4 saltLen;
    ubyte4 tagLen;

    ubyte* __crypto_i__(SK_a, pxSa->u.v2.SK_a[IS_INITIATOR(pxSa) ? _R : _I]);
    /* we need encryption key if we are using an AEAD algorithm, how we extract tag */
    ubyte* __crypto_i__(SK_e, pxSa->u.v2.SK_e[IS_INITIATOR(pxSa) ? _R : _I]);
    ubyte __crypto__(poDigest, IKE_HASH_MAX);

    /* save current context */
    ubyte *pBuffer = ctx->pBuffer;
    ubyte4 dwBufferSize = ctx->dwBufferSize;
    ubyte4 dwLength = ctx->dwLength;
    ubyte oNextPayload = ctx->oNextPayload;

    if ((NULL == pCipherSuite) || ((NULL == pMacSuite) && 
        (NULL == pCipherSuite->pAeadAlgo)))
    {
        goto exit; /* jic */
    }

    /* locate Encrypted Payload */
    while (IKE_NEXT_NONE != ctx->oNextPayload)
    {
        if ((IKE_NEXT_E == ctx->oNextPayload)
#ifdef __ENABLE_IKE_FRAGMENTATION__
         || (IKE_NEXT_EF == ctx->oNextPayload)
#endif
            )
        {
            ubyte2 wLength0, wIcvLen=0;
            sbyte4 compareResult;

#ifdef __ENABLE_IKE_FRAGMENTATION__
            ubyte2 wFragNum=0, wTotalFragments=0;
            intBoolean bSKF = (IKE_NEXT_EF == ctx->oNextPayload);
            if (bSKF)
            {
                /* Note: IN_BEGIN declares 'wLength' and 'wBodyLen' here */
                IN_BEGIN(struct ike2FragHdr, pxSkfHdr, SIZEOF_IKE_FRAG_HDR)
                SET_NTOHS(wFragNum,        pxSkfHdr->wFragNum);
                SET_NTOHS(wTotalFragments, pxSkfHdr->wTotalFragments);

                if (!wFragNum || !wTotalFragments || (1==wTotalFragments) ||
                    (wFragNum > wTotalFragments) ||
                    (IKE2_FRAG_MAX < wTotalFragments))
                {
                    status = ERR_IKE_BAD_FRAGMENT;
                    DBG_EXIT
                }

                wLength0 = wBodyLen;
                IN_END
            }
            else
#endif
            /* generic header */
            if (OK != (status = InGen(ctx, &wLength0)))
                goto exit;

            /* get ICV */
            if (isAeadCipher(pCipherSuite->wTfmId))
            {
                wIcvLen = pCipherSuite->pAeadAlgo->tagSize;
            }
            else if (NULL != pMacSuite)
            {
                wIcvLen = pMacSuite->wIcvLen;
            }

            if (wIcvLen > wLength0)
            {
                status = ERR_IKE_BAD_LEN;
                DBG_EXIT
            }

            ctx->u.v2.poIcv = ctx->pBuffer - wIcvLen;

            /* check existing ICV */
            if (pxXg)
            {
#ifdef __ENABLE_IKE_FRAGMENTATION__
                if (bSKF && (wTotalFragments < pxXg->numIcvs))
                {
                    status = ERR_IKE_BAD_FRAGMENT;
                    DBG_EXIT
                }
#endif
                if (!IS_XCHG_INITIATOR(pxXg)) /* existing inbound request */
                {
                    ubyte *poIcv = NULL;

#ifdef __ENABLE_IKE_FRAGMENTATION__
                    if (bSKF)
                    {
                        if ((wTotalFragments > pxXg->numIcvs) && pxXg->numMsgs)
                        {
                            /* # of fragments is increased but reassembling is
                               already finished */
                            status = ERR_IKE_BAD_FRAGMENT;
                            DBG_EXIT
                        }

                        poIcv = pxXg->poIcv[wFragNum-1];
                        if (poIcv) /* existing fragment */
                        {
                            if (wTotalFragments > pxXg->numIcvs)
                            {
                                /* # of fragments is increased and all received
                                   fragments will be discarded. */
                                poIcv = NULL; /* do not match exisiting ICV */
                            }
                        }
                        else if (pxXg->numMsgs)
                        {
                            /* new fragment but reassembling is already finished */
                            status = ERR_IKE_BAD_FRAGMENT;
                            DBG_EXIT
                        }
                    }
                    else if (1 < pxXg->numIcvs)
                    {
                        /* received non-fragment while already reassembling */
                        status = ERR_IKE_BAD_MSG;
                        DBG_EXIT
                    }
                    else
#endif
                    poIcv = pxXg->poIcv[0];

                    if (poIcv)
                    {
                        if (OK > (status = DIGI_MEMCMP(ctx->u.v2.poIcv, poIcv,
                                                      wIcvLen, &compareResult)))
                        {
                            DBG_EXIT
                        }
                        if (0 != compareResult) /* bad re-transmission */
                        {
                            status = ERR_IKE_BAD_MSG;
                            DBG_EXIT
                        }
                    }
                }
#ifdef __ENABLE_IKE_FRAGMENTATION__
                else /* inbound response */
                {
                    if (bSKF &&
                        pxXg->poIcv[wFragNum-1] &&
                        (wTotalFragments == pxXg->numIcvs))
                    {
                        /* replay */
                        status = ERR_IKE_BAD_FRAGMENT;
                        DBG_EXIT
                    }
                }
#endif
                /* still need to check msg integrity (see below) */
            }
            else /* new inbound request */
            {
            }

            if (NULL != pMacSuite)
            {
                /* calculate ICV */
                if (!pxSa->wAuthKeyLen)
                    pxSa->wAuthKeyLen = pMacSuite->wKeyLen;

                _CRYPTO_COPY_(SK_a, pxSa->wAuthKeyLen, pxSa->u.v2.SK_a[IS_INITIATOR(pxSa) ? _R : _I])
                _CRYPTO_ALLOC_(poDigest, IKE_HASH_MAX)

                if (OK > (status = pMacSuite->hmacFunc(MOC_HASH(ctx->hwAccelCookie)
                                                        /*pxSa->u.v2.*/SK_a/*[IS_INITIATOR(pxSa) ? _R : _I]*/,
                                                        pxSa->wAuthKeyLen,
                                                        (ubyte *) ctx->pHdrParent,
                                                        ctx->dwLength - wIcvLen,
                                                        poDigest)))
                    DBG_EXIT

                /* ICV is not calculated separately for AEAD algorithms */
                /* compare ICVs */
                if (OK > (status = DIGI_MEMCMP(ctx->u.v2.poIcv, poDigest, wIcvLen, &compareResult)))
                    DBG_EXIT
            }
            else if ((NULL != pCipherSuite) && (NULL != pCipherSuite->pAeadAlgo))
            {
                saltLen = pCipherSuite->pAeadAlgo->implicitNonceSize;
                ivLen = pCipherSuite->pAeadAlgo->explicitNonceSize;
                tagLen = pCipherSuite->pAeadAlgo->tagSize;

                status = IKE2_decryptAead(pCipherSuite->pAeadAlgo, SK_e, pCipherSuite->wKeyLen,
                    SK_e + pCipherSuite->wKeyLen, saltLen, ctx->pBuffer - wLength0, ivLen,
                    ctx->pBuffer - wLength0 + ivLen, wLength0 - ivLen,
                    ctx->pHdrParent, ctx->dwLength - wLength0,
                    (ubyte **) &(ctx->u.v2.poIcv), &compareResult);
                if (OK != status)
                    goto exit;
            }

            if (0 != compareResult) /* mismatch */
            {
                status = ERR_IKE_BAD_HASH;
                DBG_EXIT
            }

#ifdef __ENABLE_IKE_FRAGMENTATION__
            ctx->u.v2.bSKF = bSKF;
#endif
            break;
        }
        else
        {
            IN_BEGIN(struct ikeGenHdr, pxGenHdr, SIZEOF_IKE_GEN_HDR)
            IN_END
        }
    }

    /* restore context */
    ctx->pBuffer = pBuffer;
    ctx->dwBufferSize = dwBufferSize;
    ctx->dwLength = dwLength;
    ctx->oNextPayload = oNextPayload;

exit:
    if (OK > status)
    {
        /* integrity-check failed - will not respond!!! */
        if (pCipherSuite && pCipherSuite->pAeadAlgo && ctx->u.v2.poIcv)
        {
            DIGI_FREE((void **) &(ctx->u.v2.poIcv));
        }
        ctx->u.v2.poIcv = NULL;
    }
    _CRYPTO_FREE_(poDigest)
    _CRYPTO_FREE_(SK_a)
    return status;
} /* IKE2_checkSK */

static MSTATUS IKE2_encryptAead(const AeadAlgo *pAlg, ubyte *pKey, ubyte4 keyLen,
    ubyte *pSalt, ubyte4 saltLen, ubyte *pIv, ubyte4 ivLen,
    ubyte *pData, ubyte4 dataLen, ubyte *pAdata, ubyte4 aDataLen)
{
    MSTATUS status;
    ubyte *pNonce = NULL;
    ubyte4 nonceLen;
    BulkCtx pCtx = NULL;

    if ((NULL == pAlg) || (NULL == pKey) || (NULL == pData) || (NULL == pAdata))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((saltLen != pAlg->implicitNonceSize) || (ivLen != pAlg->explicitNonceSize))
    {
        status = ERR_IKE_BAD_LEN;
        goto exit;
    }

    nonceLen = saltLen + ivLen;
    status = DIGI_MALLOC((void **) &pNonce, nonceLen);
    if (OK != status)
        goto exit;

    /* add salt bytes of nonce */
    status = DIGI_MEMCPY(pNonce, pSalt, saltLen);
    if (OK != status)
        goto exit;

    /* add IV bytes of nonce */
    status = DIGI_MEMCPY(pNonce + saltLen, pIv, ivLen);
    if (OK != status)
        goto exit;

    pCtx = pAlg->createFunc(pKey, keyLen, TRUE);
    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = pAlg->cipherFunc(pCtx, pNonce, nonceLen, pAdata, aDataLen, pData,
        dataLen, pAlg->tagSize, TRUE);
    if (OK != status)
        goto exit;

exit:
    if (NULL != pNonce)
        DIGI_FREE((void **) &pNonce);

    if (NULL != pAlg)
        pAlg->deleteFunc(&pCtx);

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
IKE2_outSK(IKE_context ctx)
{
    MSTATUS status;

    IKESA pxSa = ctx->pxSa;
    sbyte4 dir = (IS_INITIATOR(pxSa) ? _I : _R);

    IKE_macSuiteInfo *pMacSuite = pxSa->pMacSuite;
    IKE_cipherSuiteInfo *pCipherSuite = pxSa->pCipherSuite;

    ubyte2 wIcvLen = 0;
    ubyte2 wIvLen = pCipherSuite->wIvLen;
    ubyte2 wBlockLen = 1;  /* to mitigate coverity */

    if (NULL != pCipherSuite->pBEAlgo)
    {
        wBlockLen = (ubyte2) pCipherSuite->pBEAlgo->blockSize;
    }
    else
    {
        if ((isAeadCipher(pCipherSuite->wTfmId)) && (ENCR_CHACHA20_POLY1305 != pCipherSuite->wTfmId))
        {
            wBlockLen = (ubyte2) AES_BLOCK_SIZE;
        }
    }

    ubyte oPadLen = 0;
    ubyte2 wPadLen;
    if (NULL != pMacSuite)
    {
        wIcvLen = pMacSuite->wIcvLen;
    }
    else if (NULL != pCipherSuite->pAeadAlgo)
    {
        wIcvLen = pCipherSuite->pAeadAlgo->tagSize;
    }

    ubyte __crypto__(poIv, IKE_IV_MAX);
    ubyte __crypto__(poDigest, IKE_HASH_MAX);
    ubyte* __crypto_i__(SK_a, pxSa->u.v2.SK_a[dir]);

    struct ikeHdr *pxHdr = (struct ikeHdr *) ctx->pHdrParent;
    struct ikeGenHdr *pxSkHdr = (struct ikeGenHdr *) ((ubyte *)pxHdr + SIZEOF_ISAKMP_HDR);

#ifdef __ENABLE_IKE_FRAGMENTATION__
    ubyte2 wSkHdrLen = ((IKE_NEXT_EF == pxHdr->oNextPayload) ? SIZEOF_IKE_FRAG_HDR : SIZEOF_IKE_GEN_HDR);
#else
    #define wSkHdrLen SIZEOF_IKE_GEN_HDR
#endif
    ubyte2 wHdrLen = wSkHdrLen + wIvLen;
    ubyte2 wBodyLen = (ubyte2)(ctx->dwLength - (wHdrLen + SIZEOF_ISAKMP_HDR));

    /* set encr. key length, if necessary */
    ubyte2 wEncrKeyLen = pxSa->wEncrKeyLen;
    if (!wEncrKeyLen)
    {
        if (0 == (wEncrKeyLen = pCipherSuite->wKeyLenEnd))
            wEncrKeyLen = pCipherSuite->wKeyLen;

        pxSa->wEncrKeyLen = wEncrKeyLen;
    }

    /* When using ChaCha20-Poly1305, we won't add padding.
     *
     * RFC 7634 Section 3:
     *    The sender SHOULD include no padding and set the Pad Length field
     *    to zero.  The receiver MUST accept any length of padding. */
    if ((ENCR_CHACHA20_POLY1305 != pCipherSuite->wTfmId) &&
        (0 != (wPadLen = ((wBodyLen + 1) % wBlockLen))))
    {
        oPadLen = (ubyte)(wBlockLen - wPadLen);
    }
    wPadLen = (ubyte2)(oPadLen + 1);

    if (wPadLen > ctx->dwBufferSize)
    {
        status = ERR_IKE_BUFFER_OVERFLOW;
        DBG_EXIT
    }

    ctx->pBuffer[oPadLen] = oPadLen;
    wBodyLen = wBodyLen + wPadLen;
    ADVANCE(wPadLen)

    /* initialize IV with random data */
    _CRYPTO_ALLOC_(poIv, IKE_IV_MAX)
    if (OK > (status = RANDOM_numberGenerator(g_pRandomContext, poIv, wIvLen)))
        DBG_EXIT

    DIGI_MEMCPY((ubyte *)pxSkHdr + wSkHdrLen, poIv, wIvLen);

    /* encrypt */
    if (NULL == pCipherSuite->pAeadAlgo)
    {
        if (OK != (status = CRYPTO_Process(MOC_SYM(ctx->hwAccelCookie)
                                     pCipherSuite->pBEAlgo,
                                     pxSa->u.v2.SK_e[dir],
                                     wEncrKeyLen,
                                     poIv, /* to be modified */
                                     (ubyte *)pxSkHdr + wHdrLen,
                                     wBodyLen,
                                     TRUE)))
            DBG_EXIT

        SET_HTONS(pxSkHdr->wLength, wHdrLen + wBodyLen + wIcvLen);

        /* calculate ICV */
        if (wIcvLen > ctx->dwBufferSize)
        {
            status = ERR_IKE_BUFFER_OVERFLOW;
            DBG_EXIT
        }
        ADVANCE(wIcvLen)

        SET_HTONL(pxHdr->dwLength, ctx->dwLength);

        if (!pxSa->wAuthKeyLen)
            pxSa->wAuthKeyLen = pMacSuite->wKeyLen;

        _CRYPTO_COPY_(SK_a, pxSa->wAuthKeyLen, pxSa->u.v2.SK_a[dir])
        _CRYPTO_ALLOC_(poDigest, IKE_HASH_MAX)

        if (OK > (status = pMacSuite->hmacFunc(MOC_HASH(ctx->hwAccelCookie)
                                                /*pxSa->u.v2.*/SK_a/*[dir]*/,
                                                pxSa->wAuthKeyLen,
                                                (ubyte *)pxHdr,
                                                ctx->dwLength - wIcvLen,
                                                poDigest)))
            DBG_EXIT

        DIGI_MEMCPY(ctx->pBuffer - wIcvLen, poDigest, wIcvLen);
    }
    else
    {
        SET_HTONS(pxSkHdr->wLength, wHdrLen + wBodyLen + wIcvLen);
        ADVANCE(wIcvLen);
        SET_HTONL(pxHdr->dwLength, ctx->dwLength);

        status = IKE2_encryptAead(pCipherSuite->pAeadAlgo, pxSa->u.v2.SK_e[dir],
            wEncrKeyLen, pxSa->u.v2.SK_e[dir] + wEncrKeyLen,
            pCipherSuite->pAeadAlgo->implicitNonceSize, poIv, pCipherSuite->pAeadAlgo->explicitNonceSize,
            (ubyte *)pxSkHdr + wHdrLen, wBodyLen, (ubyte *) pxHdr, SIZEOF_IKE_GEN_HDR + SIZEOF_ISAKMP_HDR);
        if (OK != status)
            goto exit;
    }

exit:
#ifndef __ENABLE_IKE_FRAGMENTATION__
    #undef wSkHdrLen
#endif
    _CRYPTO_FREE_(poDigest)
    _CRYPTO_FREE_(poIv)
    _CRYPTO_FREE_(SK_a)
    return status;
} /* IKE2_outSK */


/*------------------------------------------------------------------*/

static MSTATUS
InSK(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;

    IKE_macSuiteInfo *pMacSuite = pxSa->pMacSuite;
    IKE_cipherSuiteInfo *pCipherSuite = pxSa->pCipherSuite;

    ubyte2 wEncrKeyLen, wIcvLen, wIvLen, wPadLen;

#ifdef __ENABLE_IKE_FRAGMENTATION__
    intBoolean bSKF = (IKE_NEXT_EF == ctx->oNextPayload);
    ubyte2 wHdrLen = (bSKF ? SIZEOF_IKE_FRAG_HDR : SIZEOF_IKE_GEN_HDR);
#else
    #define wHdrLen SIZEOF_IKE_GEN_HDR
#endif

    /* generic header */
    IN_BEGIN(struct ikeGenHdr, pxSkHdr, wHdrLen)

    if (!IS_IKE2_SA_INITED(pxSa))
    {
        status = ERR_IKE_BAD_PAYLOAD;
        DBG_EXIT
    }

    /* set encr. key length, if necessary */
    if (0 == (wEncrKeyLen = pxSa->wEncrKeyLen))
    {
        if (0 == (wEncrKeyLen = pCipherSuite->wKeyLenEnd))
            wEncrKeyLen = pCipherSuite->wKeyLen;

        pxSa->wEncrKeyLen = wEncrKeyLen;
    }

    /* remove ICV (already checked) */
    if (isAeadCipher(pCipherSuite->wTfmId))
        wIcvLen = pCipherSuite->pAeadAlgo->tagSize;
    else
        wIcvLen = pMacSuite->wIcvLen;

    if (wIcvLen > wBodyLen) /* jic */
    {
        status = ERR_IKE_BAD_LEN;
        DBG_EXIT
    }
    wBodyLen = wBodyLen - wIcvLen;

    /* check IV */
    wIvLen = pCipherSuite->wIvLen;
    if ((wIvLen + 1) > wBodyLen)
    {
        status = ERR_IKE_BAD_LEN;
        DBG_EXIT
    }
    ADVANCE(wIvLen)
    wBodyLen = wBodyLen - wIvLen;

    /* if using AEAD algorithms, we have already decrypted payload */
    if (!isAeadCipher(pCipherSuite->wTfmId))
    {
        /* the length of encrypted data should be multiple of block length */
        if (!wBodyLen || (wBodyLen % pCipherSuite->wIvLen))
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }

        if (OK != (status = CRYPTO_Process(MOC_SYM(ctx->hwAccelCookie)
                                     pCipherSuite->pBEAlgo,
                                     pxSa->u.v2.SK_e[IS_INITIATOR(pxSa) ? _R : _I],
                                     wEncrKeyLen,
                                     ctx->pBuffer - wIvLen, /* IV */
                                     ctx->pBuffer,
                                     wBodyLen,
                                     FALSE)))
        {
            DBG_EXIT
        }
    }

    /* remove padding */
    wPadLen = (ubyte2) ctx->pBuffer[wBodyLen - 1];
    if (++wPadLen > wBodyLen)
    {
        status = ERR_IKE_BAD_LEN;
        DBG_EXIT
    }
    ctx->dwBufferSize = wBodyLen = wBodyLen - wPadLen;

    SET_HTONS(pxSkHdr->wLength, wIvLen + wHdrLen); /* !!! for debugging */

#ifdef __ENABLE_IKE_FRAGMENTATION__
    if (bSKF)
    {
        sbyte4 i;
        ubyte4 dwBufferSize;
        ubyte *poIcv, *poBuf;
        IKE2XG pxXg = ctx->pxXg;
        struct ike2FragHdr *pxSkfHdr = (struct ike2FragHdr *)pxSkHdr;
        ubyte2 wFragNum = GET_NTOHS(pxSkfHdr->wFragNum);
        ubyte2 wTotalFragments = GET_NTOHS(pxSkfHdr->wTotalFragments);

        if (NULL == (poIcv = (ubyte *) MALLOC(wIcvLen)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            DBG_EXIT
        }
        if (NULL == (poBuf = (ubyte *) MALLOC(wBodyLen)))
        {
            FREE(poIcv);
            status = ERR_MEM_ALLOC_FAIL;
            DBG_EXIT
        }

        if (wTotalFragments > pxXg->numIcvs)
        {
            /* discard all received fragments */
            for (i=0; i < pxXg->numIcvs; i++)
            {
                CHECK_FREE(pxXg->poIcv[i])
                CHECK_FREE(pxXg->poEfBody[i])
                pxXg->wEfBodyLen[i] = 0;
            }
            pxXg->numIcvs = wTotalFragments;
        }

        DIGI_MEMCPY(poIcv, ctx->u.v2.poIcv, wIcvLen);
        pxXg->poIcv[wFragNum-1] = poIcv;

        DIGI_MEMCPY(poBuf, ctx->pBuffer, wBodyLen);
        pxXg->poEfBody[wFragNum-1] = poBuf;
        pxXg->wEfBodyLen[wFragNum-1] = wBodyLen;

        if (1==wFragNum)
        {
            pxXg->oEfNextPayload = pxSkfHdr->oNextPayload;
        }

        /* check if reassembly can be finished */
        for (i=0, dwBufferSize=0; i < wTotalFragments; i++)
        {
            if (NULL == pxXg->poEfBody[i])
            {
                status = STATUS_IKE_PENDING;
                goto exit; /* not yet */
            }
            dwBufferSize += (ubyte4) pxXg->wEfBodyLen[i];
        }

        /* reassemble fragments */
        if (NULL == (poBuf = (ubyte *) MALLOC(dwBufferSize)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            DBG_EXIT
        }

        ctx->oNextPayload = pxXg->oEfNextPayload;
        ctx->dwBufferSize = dwBufferSize;

        /* Save the allocated pointer for release later */
        ctx->pRefragmentationBuffer = poBuf;

        ctx->pBuffer = poBuf;

        for (i=0; i < wTotalFragments; i++)
        {
            DIGI_MEMCPY(poBuf, pxXg->poEfBody[i], pxXg->wEfBodyLen[i]);
            poBuf += pxXg->wEfBodyLen[i];
        }
    }
#endif /* __ENABLE_IKE_FRAGMENTATION__ */

exit:
#ifndef __ENABLE_IKE_FRAGMENTATION__
    #undef wHdrLen
#endif
    return status;
} /* InSK */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_IKE_FRAGMENTATION__
static void
SetMaxSK(IKESA pxSa)
{
    ubyte2 wLength, wBlockLen, wBodyLen;
    sbyte4 i;

    if (!pxSa || !(IKE_SA_FLAG_FRAGMENTATION & pxSa->flags))
    {
        goto exit;
    }

    wBlockLen = (ubyte2) pxSa->pCipherSuite->pBEAlgo->blockSize;
    if (!wBlockLen) /* jic */
    {
        goto exit;
    }

    wLength = SIZEOF_ISAKMP_HDR +   /* IKE message header */
    SIZEOF_IKE_GEN_HDR +  /* Encrypted Payload header */
    pxSa->pCipherSuite->wIvLen +
    wBlockLen + /* 1 cipher block, including 1 pad length octet */
    pxSa->pMacSuite->wIcvLen;

#ifdef __ENABLE_IPSEC_NAT_T__
    if (USE_NATT_PORT(pxSa) || IS_BEHIND_NAT(pxSa))
    {
        wLength += 4;
    }
#endif

    for (i=0; i < 2; i++)
    {
        if (i)
        {
            /* Encrypted Fragment Payload header has additional octets */
            wLength += (ubyte2)(SIZEOF_IKE_FRAG_HDR - SIZEOF_IKE_GEN_HDR);
        }

        if (wLength < pxSa->ikePeerConfig->ikeFragSize)
        {
            wBodyLen = (pxSa->ikePeerConfig->ikeFragSize - wLength);
            wBodyLen = ((wBodyLen / wBlockLen) * wBlockLen) + (wBlockLen - 1);
        }
        else
        {
            /* 'ikeFragSize' is too small! TODO: return error? */
            wBodyLen = wBlockLen - 1;
        }

        if (!wBodyLen) wBodyLen = 1; /* jic */

        pxSa->maxSkBodyLen[i] = wBodyLen;

        DB_PRINT("%s: Body length[%d] = %d\n", __FUNCTION__, i, (int)wBodyLen);
    }

exit:
    return;
} /* SetMaxSK */
#endif


/*------------------------------------------------------------------*/
/*
   IKE_SA_INIT Exchange
   request             --> [N(COOKIE),]
                            SAi1, KEi, Ni,
                           [N(IKEV2_FRAGMENTATION_SUPPORTED),]
                           [N(SIGNATURE_HASH_ALGORITHMS),]
                           [N(NAT_DETECTION_SOURCE_IP)+,
                            N(NAT_DETECTION_DESTINATION_IP),]
                           [V+]
*/

/*------------------------------------------------------------------*/

static MSTATUS
initI_out(IKE_context ctx)
{
    MSTATUS status;

    struct ikeHdr *pxHdr = (struct ikeHdr *) ctx->pHdrParent;
    IKESA pxSa = ctx->pxSa;

    ubyte4 dwLength;

    /* I --> */
    DO_FUNC(OutSa)
    DO_FUNC(OutKe)
    DO_FUNC(OutNonce)

#ifdef __ENABLE_IKE_FRAGMENTATION__
    if (!pxSa->ikePeerConfig->bNoIkeFrag)
    {
        ctx->wMsgType = IKEV2_FRAGMENTATION_SUPPORTED; /* temporary */
        DO_FUNC(OutInfo)
    }
#endif
#ifdef __ENABLE_IKE_PPK_RFC8784__
    if (pxSa->ikePeerConfig->bUsePpk)
    {
        ctx->wMsgType = USE_PPK; 
        DO_FUNC(OutInfo)
    }
#endif

#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
    if (!pxSa->ikePeerConfig->bNoSigAuth)
    {
        ctx->wMsgType = SIGNATURE_HASH_ALGORITHMS; /* temporary */
        DO_FUNC(OutInfo)
    }
#endif
#if defined(__ENABLE_IPSEC_NAT_T__) || defined(__ENABLE_MOBIKE__)
    DO_FUNC(OutNatD)
#endif
#ifdef CUSTOM_IKE_GET_VENDOR_ID
    DO_FUNC(OutVid)
#endif

#ifdef __ENABLE_IKE_REDIRECT__
    if (REDIRECTED_FROM != ctx->wMsgType)
    {
        ctx->wMsgType = REDIRECT_SUPPORTED;
    }
    DO_FUNC(OutInfo)
#endif

    /* store 1st message - for IKE_AUTH */
    CHECK_FREE(pxSa->poMsg[_I])
    pxSa->dwMsgLen[_I] = 0;

    dwLength = ctx->dwLength;
    SET_HTONL(pxHdr->dwLength, dwLength);
    CHECK_MALLOC(pxSa->poMsg[_I], dwLength)
    pxSa->dwMsgLen[_I] = dwLength;
    DIGI_MEMCPY(pxSa->poMsg[_I], (ubyte *)pxHdr, dwLength);

exit:
    return status;
} /* initI_out */


/*------------------------------------------------------------------*/

static MSTATUS
initR_in(IKE_context ctx)
{
    MSTATUS status = OK;

    struct ikeHdr *pxHdr = (struct ikeHdr *) ctx->pHdrParent;
    IKESA pxSa = ctx->pxSa;

    ubyte4 dwLength;

    /* --> R */
#ifdef __ENABLE_IPSEC_NAT_T__
    SET_PEER_BEHIND_NAT(pxSa)
#endif
    IN_LOOP_BEGIN
        IN_NEXT(IKE_NEXT_N,     InNotify)   /* COOKIE, etc. */
    IN_LOOP_END

    IN_PAYLOAD(IKE_NEXT_SA,     InSa)
    IN_LOOP_BEGIN
        IN_NEXT(IKE_NEXT_KE,    InKe)
        IN_NEXT(IKE_NEXT_NONCE, InNonce)
    IN_LOOP_END

    if (!(IKE_CNTXT_FLAG_KE & ctx->flags))      /* missing KEi */
    {
        status = ERR_IKE_BAD_KE;
        DBG_EXIT
    }

    if (!(IKE_CNTXT_FLAG_NONCE & ctx->flags))   /* missing Ni */
    {
        status = ERR_IKE_BAD_NONCE;
        DBG_EXIT
    }

#ifdef __ENABLE_IKE_REDIRECT_IN_INIT__
    if (REDIRECT == ctx->wMsgType)
    {
        IKE2_delSa(pxSa, FALSE, STATUS_IKE_REDIRECTED);
        goto exit;
    }
#endif


    IN_LOOP_BEGIN
        IN_NEXT(IKE_NEXT_N,     InNotify)
        IN_NEXT(IKE_NEXT_V,     InVid)
    IN_LOOP_NONE
    } /* paranthesis started with IN_LOOP_BEGIN */

#ifdef __ENABLE_IKE_PPK_RFC8784__
    if( m_ikeSettings.bPpkEnforce && pxSa->ikePeerConfig->bUsePpk && !(pxSa->flags & IKE_SA_FLAG_USEPPK))
    {
        status = ERR_IKE_PPK_MISCONFIG;
        DBG_EXIT
    }
#endif    

#ifdef __ENABLE_IPSEC_NAT_T__
    if (!(IKE_NATT_FLAG_D & pxSa->natt_flags))
        PEER_NOT_BEHIND_NAT(pxSa)
#endif

    /* generate keys */
    DO_FUNC(DoKe)

    /* store 1st message - for IKE_AUTH */
    CHECK_FREE(pxSa->poMsg[_I])
    pxSa->dwMsgLen[_I] = 0;

    SET_NTOHL(dwLength, pxHdr->dwLength);
    CHECK_MALLOC(pxSa->poMsg[_I], dwLength)
    pxSa->dwMsgLen[_I] = dwLength;
    DIGI_MEMCPY(pxSa->poMsg[_I], (ubyte *)pxHdr, dwLength);

#ifdef __ENABLE_IKE_FRAGMENTATION__
    SetMaxSK(pxSa);
#endif

exit:
    if (OK > status)
    {
        if (!pxSa->merror)
            pxSa->merror = status;

        if (!ctx->wMsgType || /* no response but ICV saved! See IKE2_xchgIn() */
            (INVALID_KE_PAYLOAD == ctx->wMsgType))
        {
            /* remove exchange to allow Initiator to re-send w/ same SPI */
            IKE2XG pxXg = ctx->pxXg;
            pxXg->dwMsgId = ~((ubyte4)0); /* DO NOT advance msg ID! */
            IKE2_delXchg(pxXg, pxSa, status);
            ctx->pxXg = NULL;
        }
    }
    else pxSa->merror = OK;
    return status;
} /* initR_in */


/*------------------------------------------------------------------*/
/*
   IKE_SA_INIT Exchange
   normal response     <--  SAr1, KEr, Nr,
   (no cookie)             [N(IKEV2_FRAGMENTATION_SUPPORTED),]
                           [N(NAT_DETECTION_SOURCE_IP),]
                            N(NAT_DETECTION_DESTINATION_IP),]
                          [[N(HTTP_CERT_LOOKUP_SUPPORTED)], CERTREQ+,]
                           [N(SIGNATURE_HASH_ALGORITHMS),]
                           [N(MULTIPLE_AUTH_SUPPORTED),]
                           [V+]
*/

/*------------------------------------------------------------------*/

static MSTATUS
initR_out(IKE_context ctx)
{
    MSTATUS status;

    struct ikeHdr *pxHdr = (struct ikeHdr *) ctx->pHdrParent;
    IKESA pxSa = ctx->pxSa;

    ubyte4 dwLength;

#ifdef __ENABLE_IKE_REDIRECT__
    if (REDIRECT == ctx->wMsgType)
    {
        DO_FUNC(OutInfo)
        goto exit;
    }
#endif

    /* <-- R */
    DO_FUNC(OutSa)
    DO_FUNC(OutKe)
    DO_FUNC(OutNonce)

#ifdef __ENABLE_IKE_FRAGMENTATION__
    if (IKE_SA_FLAG_FRAGMENTATION & pxSa->flags)
    {
        ctx->wMsgType = IKEV2_FRAGMENTATION_SUPPORTED; /* temporary */
        DO_FUNC(OutInfo)
    }
#endif
#ifdef __ENABLE_IKE_PPK_RFC8784__
    if (IKE_SA_FLAG_USEPPK & pxSa->flags)
    {
        ctx->wMsgType = USE_PPK; 
        DO_FUNC(OutInfo)
    }
#endif

#ifdef __ENABLE_IPSEC_NAT_T__
    if (IKE_NATT_FLAG_D & pxSa->natt_flags)
    DO_FUNC(OutNatD)
#endif
    DO_FUNC(OutCr)

#ifdef __ENABLE_IKE_SIG_AUTH_RFC7427__
    if (pxSa->u.v2.numSahAlgos)
    {
        ctx->wMsgType = SIGNATURE_HASH_ALGORITHMS; /* temporary */
        DO_FUNC(OutInfo)
    }
#endif
#ifdef __ENABLE_IKE_MULTI_AUTH__
    if (pxSa->ikePeerConfig->bDoMultiAuth)
    {
        ctx->wMsgType = MULTIPLE_AUTH_SUPPORTED; /* temporary */
        DO_FUNC(OutInfo)
    }
#endif
#ifdef CUSTOM_IKE_GET_VENDOR_ID
    DO_FUNC(OutVid)
#endif

    /* store 2nd message - for IKE_AUTH */
    CHECK_FREE(pxSa->poMsg[_R])
    pxSa->dwMsgLen[_R] = 0;

    dwLength = ctx->dwLength;
    SET_HTONL(pxHdr->dwLength, dwLength);
    CHECK_MALLOC(pxSa->poMsg[_R], dwLength)
    pxSa->dwMsgLen[_R] = dwLength;
    DIGI_MEMCPY(pxSa->poMsg[_R], (ubyte *)pxHdr, dwLength);

exit:
    return status;
} /* initR_out */


/*------------------------------------------------------------------*/

static MSTATUS
initI_in(IKE_context ctx)
{
    MSTATUS status = OK;

    struct ikeHdr *pxHdr = (struct ikeHdr *) ctx->pHdrParent;
    IKESA pxSa = ctx->pxSa;
    IKE2XG pxXg = ctx->pxXg;

    ubyte4 dwLength;
#ifdef __ENABLE_IPSEC_NAT_T__
    intBoolean bNatt = USE_NATT_PORT(pxSa);
#endif

    /* I <-- */
    IN_LOOP_BEGIN
        IN_NEXT(IKE_NEXT_N,         InNotify) /* COOKIE, INVALID_KE_PAYLOAD, etc. */
    IN_LOOP_END

    if (INVALID_KE_PAYLOAD == ctx->wMsgType)
    {
        /* change Initiator cookie to send a new exchange */
        ubyte cookie[IKE_COOKIE_SIZE];
        if (OK > (status = RANDOM_numberGenerator(g_pRandomContext,
                                                  cookie, IKE_COOKIE_SIZE)))
            DBG_EXIT

#ifdef __IKE_MULTI_THREADED__
        if (NULL == m_ikeSettings.funcPtrIkeGetThreadId)
        {
            status = ERR_IKE_CONFIG;
            DBG_EXIT
        }
        if (OK > (status = (MSTATUS)
                           m_ikeSettings.funcPtrIkeGetThreadId(
                                    &pxSa->tid, cookie, 2, TRUE
                                    MOC_MTHM_REQ_VALUE(pxSa->serverInstance))))
        {
            DBG_EXIT
        }
#endif
        /* will re-send */
        FREE(pxSa->poMsg[_I]);
        pxSa->poMsg[_I] = NULL;
        pxSa->dwMsgLen[_I] = 0;
        CHECK_FREE(pxXg->poMsg[0])
        pxXg->dwMsgLen[0] = 0;
        pxXg->numMsgs = 0;

#ifdef __IKE_UPDATE_TIMER__
        IKE_DEL_TIMER_EVT(pxXg->rtxTimerId, pxXg->rtxTimerHdl)
        pxXg->rtxCount = 0;
#endif
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DH_freeDhContextExt(&(pxSa->p_dhContext), NULL, NULL);
#else
        DH_freeDhContext(&(pxSa->p_dhContext), NULL);
#endif

#ifdef __ENABLE_DIGICERT_ECC__

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_EC_deleteKeyAux(&(pxSa->p_eccKey));
#else
        EC_deleteKey(&(pxSa->p_eccKey));
#endif

#ifdef __ENABLE_DIGICERT_PQC__
        if (NULL != pxSa->pQsCtx)
        {
            CRYPTO_INTERFACE_QS_deleteCtx(&(pxSa->pQsCtx));
        }
#endif
#endif
#ifdef IKE_SA_CKY_HASH_TABLE_SIZE_MASK
        IKE_delSaCkyIndex(pxSa);
#endif
        DIGI_MEMCPY(pxSa->poCky_I, cookie, IKE_COOKIE_SIZE);

#ifdef IKE_SA_CKY_HASH_TABLE_SIZE_MASK
        IKE_addSaCkyIndex(pxSa);
#endif
        goto exit;
    }

    if (ctx->wMsgType) /* Notify code received */
        /* msg is not protected; so don't set error status */
        goto exit;

    IN_PAYLOAD(IKE_NEXT_SA,         InSa)
    IN_LOOP_BEGIN
        IN_NEXT(IKE_NEXT_KE,        InKe)
        IN_NEXT(IKE_NEXT_NONCE,     InNonce)
    IN_LOOP_END

    if (!(IKE_CNTXT_FLAG_KE & ctx->flags))      /* missing KEr */
    {
        status = ERR_IKE_BAD_KE;
        DBG_EXIT
    }

    if (!(IKE_CNTXT_FLAG_NONCE & ctx->flags))   /* missing Nr */
    {
        status = ERR_IKE_BAD_NONCE;
        DBG_EXIT
    }

#if defined(__ENABLE_IPSEC_NAT_T__) || defined(__ENABLE_MOBIKE__)
    SET_PEER_BEHIND_NAT(pxSa)
#endif

    IN_LOOP_BEGIN
        IN_NEXT(IKE_NEXT_N,         InNotify)
        IN_NEXT(IKE_NEXT_CERTREQ,   InCr)
        IN_NEXT(IKE_NEXT_V,         InVid)
    IN_LOOP_NONE
    } /* paranthesis started with IN_LOOP_BEGIN */

#if defined(__ENABLE_IPSEC_NAT_T__) || defined(__ENABLE_MOBIKE__)
    if (!(IKE_NATT_FLAG_D & pxSa->natt_flags))
    {
        PEER_NOT_BEHIND_NAT(pxSa)
    }
#ifndef __ENABLE_IPSEC_NAT_T__
    else if (IS_BEHIND_NAT(pxSa))
    {
        status = ERR_IKE_BAD_NAT_D;
        DBG_EXIT
    }
#endif
#endif

#ifdef __ENABLE_IKE_PPK_RFC8784__
    if( m_ikeSettings.bPpkEnforce && pxSa->ikePeerConfig->bUsePpk && !(pxSa->flags & IKE_SA_FLAG_USEPPK))
    {
        status = ERR_IKE_PPK_MISCONFIG;
        DBG_EXIT
    }
#endif    
    /* set responder cookie - must do this *before* DoKe() */
    if (IKE_isEmptyCky(pxHdr->poCky_R)) /* jic */
    {
        status = ERR_IKE_BAD_COOKIE;
        DBG_EXIT
    }
    DIGI_MEMCPY(pxSa->poCky_R, pxHdr->poCky_R, IKE_COOKIE_SIZE);

    /* generate keys */
    DO_FUNC(DoKe)

    /* store 2nd message - for IKE_AUTH */
    CHECK_FREE(pxSa->poMsg[_R])
    pxSa->dwMsgLen[_R] = 0;

    SET_NTOHL(dwLength, pxHdr->dwLength);
    CHECK_MALLOC(pxSa->poMsg[_R], dwLength)
    pxSa->dwMsgLen[_R] = dwLength;
    DIGI_MEMCPY(pxSa->poMsg[_R], (ubyte *)pxHdr, dwLength);

    pxSa->oState = STATE_MAIN_I2; /* !!! */

    /* prepare for IKE_AUTH exchange */
    CHECK_FREE(pxXg->poMsg[0])
    pxXg->dwMsgLen[0] = 0;
    pxXg->numMsgs = 0;
    pxXg->dwMsgId = ++(pxSa->u.v2.dwMsgId[_I]);
    pxXg->oExchange = IKE_XCHG_AUTH;
    pxXg->pState = IKE2_getStateInfo(IKE_XCHG_AUTH, _I);

#ifdef __IKE_UPDATE_TIMER__
    IKE_DEL_TIMER_EVT(pxXg->rtxTimerId, pxXg->rtxTimerHdl)
    pxXg->rtxCount = 0;
#endif

    /* prepare for piggybacked CHILD_SA */
    pxXg->pxSa = NULL;

#ifdef __ENABLE_IKE_FRAGMENTATION__
    SetMaxSK(pxSa);
#endif

#ifdef __ENABLE_IPSEC_NAT_T__
    if (IS_BEHIND_NAT(pxSa))
    {
        /* use udp-encap, if not already */
        sbyte4 i;
        IPSECSA pxIPsecSa = pxXg->pxIPsecSa;
        for (i = pxIPsecSa->axP2Sa[0].oChildSaLen - 1; i >= 0; i--)
        {
            pxIPsecSa->axP2Sa[0].axChildSa[i].
                ipsecPps.p_flags |= IKE_PROP_FLAG_UDP_ENCP;
        }
    }

    /* changing to new ports, if necessary */
    if (bNatt || !IS_BEHIND_NAT(pxSa))
    {
#ifdef __ENABLE_MOBIKE__
        /* MOBIKE: change the port numbers from 500 to 4500 immediately
           upon detecting that the other end supports NAT-T
           See RFC 4621 5.2.3, p.14
         */
        if (bNatt || !(IKE_NATT_FLAG_D & pxSa->natt_flags))
#endif
        goto exit;
    }

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
    pxSa->wPeerPort = IKE_NAT_UDP_PORT; /* FOR NOW */
    pxSa->natt_flags |= IKE_NATT_FLAG_USE_NPORT;
#endif

exit:
    pxSa->merror = status;
    return status;
} /* initI_in */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_IKE_MULTI_AUTH__

static ubyte
GetMultiAuthMtd(IKESA pxSa, intBoolean *pbAnother)
{
    ubyte oAuthMtd = 0;
    intBoolean bAnotherAuth = FALSE;

    intBoolean bInitiator = IS_INITIATOR(pxSa);
    struct ikePeerConfig *config = pxSa->ikePeerConfig;
    sbyte4 authMtdBits = pxSa->u.v2.authMtds[bInitiator ? _I : _R];

    /* traverse all supported auth methods to find applicable auth method */
    sbyte4 i;
    for (i=0; ; i++)
    {
        ubyte oAuthMtdTemp;

        IKE_authMtdInfo *pAuthMtd = IKE_getAuthMtdEx(config, i);
        if (NULL == pAuthMtd)
        {
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
            if (bInitiator &&
                (IKE_SA_FLAG_EAP & pxSa->flags) && /* with EAP */
                !(IKE_SA_FLAG_EAP_DONE & pxSa->flags))
            {
                /* If EAP is already used, either IKE_SA_FLAG_EAP_DONE is
                   set or IKE_SA_FLAG_EAP ia cleared
                 */
                if (oAuthMtd) bAnotherAuth = TRUE;
            }
#endif
            break; /* no more auth methods */
        }

        if ((0xff == (oAuthMtdTemp = pAuthMtd->oAuthMtd)) || /* !!! */
            !pAuthMtd->bEnabledOut[bInitiator ? _I : _R])
        {
            continue;
        }

        if ((1 << oAuthMtdTemp) & authMtdBits)
        {
            continue; /* this auth method has already been used */
        }

        if (oAuthMtd) /* already found */
        {
            bAnotherAuth = TRUE;
            break;
        }

        oAuthMtd = oAuthMtdTemp; /* found */
        if (!pbAnother) break;
    } /* for */

    if (pbAnother) *pbAnother = bAnotherAuth;

    return oAuthMtd;
} /* GetMultiAuthMtd */


/*------------------------------------------------------------------*/
/*
   IKE_AUTH Multiple Auth. Exchange

   (without EAP)
   request             --> IDi, [CERT+,] AUTH,
                           [N(ANOTHER_AUTH_FOLLOWS)]

   (with EAP)
   request             --> IDi
                     / --> EAP
   repeat 1..N times |
                     \ <-- EAP
   last request        --> AUTH,
                           [N(ANOTHER_AUTH_FOLLOWS)]

   (Responder only)
   request             -->

*/

/*------------------------------------------------------------------*/

static MSTATUS
authI_outMulti(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    intBoolean bAnotherAuth = FALSE;
#ifdef __ENABLE_IKE_PPK_RFC8784__
    intBoolean bSendPpkId = FALSE;
#endif
    ubyte oAuthMtd = pxSa->u.v2.oAuthMtd
                   = GetMultiAuthMtd(pxSa, &bAnotherAuth);

    if (!oAuthMtd)
    {
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
        if (IKE_SA_FLAG_EAP & pxSa->flags) /* with EAP */
        {
            DO_FUNC(OutId)

#ifdef __ENABLE_IKE_EAP_ONLY__
            if (pxSa->ikePeerConfig->bDoEapOnly)
            {
                pxSa->flags |= IKE_SA_FLAG_EAP_ONLY;
                ctx->wMsgType = EAP_ONLY_AUTHENTICATION; /* temporary */
                DO_FUNC(OutInfo)
            }
#endif
            goto exit; /* !!! */
        }
#endif
        DBG_ERRCODE(ERR_IKE_MISMATCH_AUTH_METHOD)
        goto exit; /* no applicable auth method */
    }

#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    /* force EAP to be the last auth method (may be used multiple times) */
    if (pxSa->u.v2.eapState.proto)
    {
        pxSa->flags |= IKE_SA_FLAG_EAP;
        bAnotherAuth = TRUE;
    }
#endif

    DO_FUNC(OutId)

    if (AUTH_MTD_SHARED_KEY != oAuthMtd)
    {
        DO_FUNC(OutCert)
    }

#ifdef __ENABLE_IKE_PPK_RFC8784__
    bSendPpkId = (!(pxSa->u.v2.authMtds[_I]) && !(pxSa->flags & IKE_SA_FLAG_EAP_DONE));
#endif
    DO_FUNC(OutAuth)
#ifdef __ENABLE_IKE_PPK_RFC8784__
    if((pxSa->flags & IKE_SA_FLAG_USEPPK) && (pxSa->ikePeerConfig) && (pxSa->ikePeerConfig->ppk_id))
    {
        ctx->wMsgType = PPK_IDENTITY; 
        DO_FUNC(OutInfo)
    }
#endif    

    if (bAnotherAuth)
    {
        ctx->wMsgType = ANOTHER_AUTH_FOLLOWS; /* temporary */
        DO_FUNC(OutInfo)
    }

exit:
    return status;
} /* authI_outMulti */

#endif /* __ENABLE_IKE_MULTI_AUTH__ */


/*------------------------------------------------------------------*/
/*
   IKE_AUTH Exchange without EAP
   request             --> IDi, [CERT+,]
                           [N(INITIAL_CONTACT),]
                           [[N(HTTP_CERT_LOOKUP_SUPPORTED),] CERTREQ+,]
                           [IDr,]
                           AUTH,

                           [CP(CFG_REQUEST),]
                           [N(IPCOMP_SUPPORTED)+,]
                           [N(USE_TRANSPORT_MODE),]
                           [N(ESP_TFC_PADDING_NOT_SUPPORTED),]
                           [N(NON_FIRST_FRAGMENTS_ALSO),]
                           SAi2, TSi, TSr,

                           [N(MOBIKE_SUPPORTED),
                            [N(ADDITIONAL_*_ADDRESS)+,]
                            [N(NO_NATS_ALLOWED),]]
                           [N(MULTIPLE_AUTH_SUPPORTED),
                            [N(ANOTHER_AUTH_FOLLOWS),]]
                           [V+]


   IKE_AUTH Exchange with EAP
   request             --> IDi,
                           [N(INITIAL_CONTACT),]
                           [[N(HTTP_CERT_LOOKUP_SUPPORTED),] CERTREQ+,]
                           [IDr,]
                           [N(EAP_ONLY_AUTHENTICATION),]

                           [CP(CFG_REQUEST),]
                           [N(IPCOMP_SUPPORTED)+,]
                           [N(USE_TRANSPORT_MODE),]
                           [N(ESP_TFC_PADDING_NOT_SUPPORTED),]
                           [N(NON_FIRST_FRAGMENTS_ALSO),]
                           SAi2, TSi, TSr,

                           [N(MOBIKE_SUPPORTED),
                            [N(ADDITIONAL_*_ADDRESS)+,]
                            [N(NO_NATS_ALLOWED),]]
                           [N(MULTIPLE_AUTH_SUPPORTED),]
                           [V+]

                     / --> EAP
   repeat 1..N times |
                     \ <-- EAP

   last request        --> AUTH,
                           [N(ANOTHER_AUTH_FOLLOWS)]

*/

/*------------------------------------------------------------------*/

static MSTATUS
authI_out(IKE_context ctx)
{
    MSTATUS status;

    IKESA pxSa = ctx->pxSa;
#ifdef __ENABLE_IKE_MULTI_AUTH__
    ubyte oAuthMtd = 0;
    intBoolean bAnotherAuth = FALSE;
#endif

    /* I --> */

#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    intBoolean bDoEap = FALSE;
    IKE2EAP pxEap = &pxSa->u.v2.eapState;

    if (IKE_SA_FLAG_EAP_DONE & pxSa->flags) /* AUTH (with EAP) */
    {
        status = OutAuth(ctx);
#ifdef __ENABLE_IKE_PPK_RFC8784__
        if((pxSa->flags & IKE_SA_FLAG_USEPPK) && (pxSa->ikePeerConfig) && (pxSa->ikePeerConfig->ppk_id))
        {
            ctx->wMsgType = PPK_IDENTITY; 
            DO_FUNC(OutInfo)
        }
#endif    

#ifdef __ENABLE_IKE_MULTI_AUTH__
        if ((OK <= status) &&
            (IKE_SA_FLAG_MULTI_AUTH & pxSa->flags) &&
            (0 != GetMultiAuthMtd(pxSa, NULL)))
        {
            ctx->wMsgType = ANOTHER_AUTH_FOLLOWS; /* temporary */
            status = OutInfo(ctx);
        }
#endif
        goto exit;
    }

    if (pxEap->pxMsg) /* EAP */
    {
        status = OutGen(ctx, IKE_NEXT_EAP,
                        GET_NTOHS(pxEap->pxMsg->wLength),
                        (ubyte *) pxEap->pxMsg);
        goto exit;
    }
#endif

#ifdef __ENABLE_IKE_MULTI_AUTH__
    if (IKE_SA_FLAG_MULTI_AUTH & pxSa->flags)
    {
        if (pxSa->u.v2.authMtds[_I]) /* multiple auth !!! */
        {
            status = authI_outMulti(ctx);
            goto exit;
        }

        oAuthMtd = pxSa->u.v2.oAuthMtd
                 = GetMultiAuthMtd(pxSa, &bAnotherAuth);
    }
#endif

    DO_FUNC(OutId)

    if (!(IKE_SA_FLAG_INIT_C & pxSa->flags) &&
        (IKE_SA_FLAG_TX_INIT_C & pxSa->flags))
    {
        ctx->wMsgType = INITIAL_CONTACT; /* temporary !!! */
        DO_FUNC(OutInfo)
    }

#ifdef __ENABLE_IKE_MULTI_AUTH__
    if (IKE_SA_FLAG_MULTI_AUTH & pxSa->flags)
    {
        if (oAuthMtd)
        {
            if (AUTH_MTD_SHARED_KEY != oAuthMtd)
                DO_FUNC(OutCert)
        }
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
        else if (IKE_SA_FLAG_EAP & pxSa->flags) /* with EAP */
        {
            bDoEap = TRUE;
        }
#endif
        else
        {
            status = ERR_IKE_MISMATCH_AUTH_METHOD;
            DBG_EXIT
        }
    }
    else
#endif
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    if (IKE_SA_FLAG_EAP & pxSa->flags) /* with EAP */
    {
        bDoEap = TRUE;
    }
    else
#endif
    DO_FUNC(OutCert)

    DO_FUNC(OutCr)

#ifdef CUSTOM_IKE_GET_ID
    DO_FUNC(OutId_R)    /* [IDr] */
#endif

#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    if (bDoEap) /* with EAP */
    {
#ifdef __ENABLE_IKE_EAP_ONLY__
        if (pxSa->ikePeerConfig->bDoEapOnly)
        {
            pxSa->flags |= IKE_SA_FLAG_EAP_ONLY;
            ctx->wMsgType = EAP_ONLY_AUTHENTICATION; /* temporary */
            DO_FUNC(OutInfo)
        }
#endif
    }
    else
#endif
    {
        DO_FUNC(OutAuth)
#ifdef __ENABLE_IKE_PPK_RFC8784__
        if((pxSa->flags & IKE_SA_FLAG_USEPPK) && (pxSa->ikePeerConfig) && (pxSa->ikePeerConfig->ppk_id))
        {
            ctx->wMsgType = PPK_IDENTITY; 
            DO_FUNC(OutInfo)
        }
#endif    
    }

#ifdef __ENABLE_IKE_CP__
    DO_FUNC(DoInitCfg)
#endif
    DO_FUNC(OutNotifySa2)
    DO_FUNC(OutSa)
    DO_FUNC(OutTSir)

#ifdef __ENABLE_MOBIKE__
    ctx->wMsgType = MOBIKE_SUPPORTED; /* temporary !!! */
    DO_FUNC(OutInfo)

#ifdef __ENABLE_IPSEC_NAT_T__
    if (!(IKE_NATT_FLAG_D & pxSa->natt_flags))
#endif
    {
        ctx->wMsgType = NO_NATS_ALLOWED; /* temporary !!! */
        DO_FUNC(OutInfo)
    }
#endif /* __ENABLE_MOBIKE__ */

#ifdef __ENABLE_IKE_MULTI_AUTH__
    if (IKE_SA_FLAG_MULTI_AUTH & pxSa->flags)
    {
        ctx->wMsgType = MULTIPLE_AUTH_SUPPORTED; /* temporary */
        DO_FUNC(OutInfo)
    }
    if (bAnotherAuth)
    {
        ctx->wMsgType = ANOTHER_AUTH_FOLLOWS; /* temporary */
        DO_FUNC(OutInfo)
    }
#endif

exit:
    return status;
} /* authI_out */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_IKE_MULTI_AUTH__) || \
    (defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__))

static MSTATUS
DoSa2Late_R(IKE_context ctx)
{
    /* Called by authR_in() only */
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    IKE2XG pxXg = ctx->pxXg;
    IPSECSA pxIPsecSa = pxXg->pxIPsecSa;

    if (pxIPsecSa->wMsgType) /* error already detected */
    {
        status = ERR_IKE_BAD_SA; /* temporary; pxIPsecSa->merror already set */
        goto exit;
    }

    /* process (saved) configuration request */
#ifdef __ENABLE_IKE_CP__
    if (pxSa->u.v2.poCp && m_ikeSettings.funcPtrIkeGetCfg)
    {
        ctx->wMsgType = INTERNAL_ADDRESS_FAILURE;
        ctx->u.v2.poCp = pxSa->u.v2.poCp;
        ctx->u.v2.poSAi2 = pxSa->u.v2.poSAi2; /* for async CP */
            DO_FUNC(DoCfgReq)
        ctx->u.v2.poSAi2 = NULL;
        ctx->u.v2.poCp = NULL;
        ctx->wMsgType = 0;
    }
#endif /* __ENABLE_IKE_CP__ */

    /* process (saved) SAi2 */
    if (pxSa->u.v2.poSAi2)
    {
        struct ikeGenHdr *pxSaHdr = (struct ikeGenHdr *) pxSa->u.v2.poSAi2;
        ubyte2 wSAi2Len = GET_NTOHS(pxSaHdr->wLength);

        struct ike_context ctx1 = *ctx;
        ctx1.dwBufferSize = wSAi2Len;
        ctx1.dwLength = 0;
        ctx1.oNextPayload = IKE_NEXT_SA;
        ctx1.pBuffer = pxSa->u.v2.poSAi2;

        if (OK > (status = InSa(&ctx1)))
        {
            ctx->wMsgType = ctx1.wMsgType;
            goto exit;
        }

        ctx->wMsgType = 0;
        pxIPsecSa->merror = OK;

        /* generate keys */
        pxIPsecSa->wPFS = 0; /* jic - must be no PFS */
        DO_FUNC(DoKe2)

#ifdef __ENABLE_DIGICERT_PFKEY__
        /* async SADB_GETSPI msg */
       if (IKE_XCHG_FLAG_PENDING & pxXg->x_flags)
           status = STATUS_IKE_PENDING;
#endif
    }

exit:
#ifdef __ENABLE_IKE_CP__
    if (pxSa->u.v2.poCp)
    {
        ctx->u.v2.poCp = NULL;
        FREE(pxSa->u.v2.poCp);
        pxSa->u.v2.poCp = NULL;
    }
#endif
    if (pxSa->u.v2.poSAi2)
    {
        FREE(pxSa->u.v2.poSAi2);
        pxSa->u.v2.poSAi2 = NULL;
    }

    if (OK > status)
    {
        /* Always return OK, except for STATUS_IKE_PENDING */
        /* Save status in pxIPsecSa->merror & pxIPsecSa->wMsgType */
        if (!pxIPsecSa->merror)
            pxIPsecSa->merror = status;

        if (!pxIPsecSa->wMsgType)
        {
            pxIPsecSa->wMsgType = ctx->wMsgType;
            if (!pxIPsecSa->wMsgType)
                pxIPsecSa->wMsgType = NO_ADDITIONAL_SAS;
        }

#if defined(__ENABLE_DIGICERT_PFKEY__) || defined(__ENABLE_IKE_CP__)
        if (STATUS_IKE_PENDING != status)
#endif
        {
            status = OK; /* !!! */
        }
    }
    else pxIPsecSa->merror = OK;
    ctx->wMsgType = 0; /* !!! */
    return status;
} /* DoSa2Late_R */

#endif /* defined(__ENABLE_IKE_MULTI_AUTH__) || (defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)) */


/*------------------------------------------------------------------*/

static MSTATUS
DoSa2_R(IKE_context ctx
#if defined(__ENABLE_IKE_MULTI_AUTH__) || \
    (defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__))
      , intBoolean bLater
#endif
        )
{
    /* Called by authR_in() only */
    MSTATUS status = OK;

#if defined(__ENABLE_IKE_MULTI_AUTH__) || \
    (defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__))
    IKESA pxSa = ctx->pxSa;
#endif
    IKE2XG pxXg = ctx->pxXg;
    IPSECSA pxIPsecSa = pxXg->pxIPsecSa;

    /* Sanity checks on payloads related to SAi2 */

    if (!(IKE_CNTXT_FLAG_TS & ctx->flags)) /* missing TSi, TSr */
    {
        ctx->wMsgType = TS_UNACCEPTABLE;
        status = ERR_IKE_BAD_ID2;
        DBG_EXIT
    }

    IN_SET
    IN_LOOP_BEGIN
        IN_REJECT(  IKE_NEXT_KE)
        IN_REJECT(  IKE_NEXT_NONCE)
    IN_LOOP_NONE
    } /* paranthesis started with IN_LOOP_BEGIN */
    IN_RESET

    /* check configuration request */
#ifdef __ENABLE_IKE_CP__
    if (ctx->u.v2.poCp)
    {
        if (NULL == m_ikeSettings.funcPtrIkeGetCfg)
        {
            /*DBG_ERRCODE(ERR_IKE_CONFIG)*/
        }
        else
        {
            const struct ikeCfgHdr *pxCfgHdr =
                                    (const struct ikeCfgHdr *) ctx->u.v2.poCp;
            ubyte2 wCpLen = GET_NTOHS(pxCfgHdr->wLength);
            if (0 != (wCpLen - SIZEOF_IKE_CFG_HDR))
            {
                 ctx->wMsgType = INTERNAL_ADDRESS_FAILURE;
#if defined(__ENABLE_IKE_MULTI_AUTH__) || \
    (defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__))
                if (bLater) /* save for later (EAP or multi-auth) */
                {
                    CHECK_MALLOC(pxSa->u.v2.poCp, wCpLen)
                    DIGI_MEMCPY(pxSa->u.v2.poCp, ctx->u.v2.poCp, wCpLen);
                }
                else
#endif
                {
                    DO_FUNC(DoCfgReq) /* process it */
                }
                ctx->wMsgType = 0;
            }
        }
    }
#endif /* __ENABLE_IKE_CP__ */

#if defined(__ENABLE_IKE_MULTI_AUTH__) || \
    (defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__))
    if (bLater)
    {
        const struct ikeGenHdr *pxSaHdr =
                                (const struct ikeGenHdr *) ctx->u.v2.poSAi2;
        ubyte2 wSAi2Len = GET_NTOHS(pxSaHdr->wLength);
        CHECK_MALLOC(pxSa->u.v2.poSAi2, wSAi2Len)
        DIGI_MEMCPY(pxSa->u.v2.poSAi2, ctx->u.v2.poSAi2, wSAi2Len);
    }
    else
#endif
    {
        LAST_PAYLOAD(IKE_NEXT_SA, InSa)

        ctx->wMsgType = 0;
        pxIPsecSa->merror = OK;

        /* generate keys */
        pxIPsecSa->wPFS = 0; /* jic - must be no PFS */
        DO_FUNC(DoKe2)

#ifdef __ENABLE_DIGICERT_PFKEY__
        /* async SADB_GETSPI msg */
       if (IKE_XCHG_FLAG_PENDING & pxXg->x_flags)
           status = STATUS_IKE_PENDING;
#endif
    }

exit:
    if (OK > status)
    {
        /* Always return OK, except for STATUS_IKE_PENDING */
        /* Save status in pxIPsecSa->merror & pxIPsecSa->wMsgType */
        if (!pxIPsecSa->merror)
            pxIPsecSa->merror = status;

        pxIPsecSa->wMsgType = ctx->wMsgType;
        if (0 == pxIPsecSa->wMsgType)
            pxIPsecSa->wMsgType = NO_ADDITIONAL_SAS;

#if defined(__ENABLE_DIGICERT_PFKEY__) || defined(__ENABLE_IKE_CP__)
        if (STATUS_IKE_PENDING != status)
#endif
        {
            status = OK; /* !!! */
        }
    }
    else pxIPsecSa->merror = OK;
    ctx->wMsgType = 0; /* !!! */
    return status;
} /* DoSa2_R */


/*------------------------------------------------------------------*/

static MSTATUS
authR_in(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    IKE2XG pxXg = ctx->pxXg;

#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    IKE2EAP pxEap = &pxSa->u.v2.eapState;
#endif
    IPSECSA pxIPsecSa = NULL;

#if defined(__ENABLE_IKE_MULTI_AUTH__) || \
    (defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__))
    intBoolean bAnotherAuth = FALSE;
#endif

    /* --> R */
    IN_SK   /* SK {...} */

#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    if (IKE_SA_FLAG_EAP_DONE & pxSa->flags) /* AUTH (with EAP) */
    {
        CHECK_FREE(pxEap->pxMsg)
        IN_PAYLOAD(IKE_NEXT_AUTH, InAuth)

#ifdef __ENABLE_IKE_MULTI_AUTH__
        IN_OPT_PAYLOAD(IKE_NEXT_N, InNotifyMultiAuth)

        /* check if we should continue with another auth */
        if (IKE_SA_FLAG_MULTI_AUTH & pxSa->flags)
        {
            if ((IKE_CNTXT_FLAG_ANOTHER_AUTH & ctx->flags) || /* peer */
                (0 != GetMultiAuthMtd(pxSa, NULL))) /* host */
            {
                bAnotherAuth = TRUE; /* yes, multi auth!!! */
            }
        }
        else if (IKE_CNTXT_FLAG_ANOTHER_AUTH & ctx->flags) /* another peer auth */
        {
            /* multi-auth not supported */
            status = ERR_IKE_BAD_AUTH;
            DBG_EXIT
        }

        if (!(IKE_CNTXT_FLAG_ANOTHER_AUTH & ctx->flags)) /* no more peer auth */
#endif
        if (IKE_SA_FLAG_INIT_C & pxSa->flags) /* initial contact */
        {
            IKE_initContSa(pxSa);
            pxSa->flags &= ~(IKE_SA_FLAG_INIT_C); /* jic */
        }

        goto do_sa2; /* !!! */
    }

    if (pxEap->pxMsg) /* EAP */
    {
        pxSa->flags &= ~(IKE_SA_FLAG_EAP); /* clear after 1st inbound EAP */
        IN_PAYLOAD(IKE_NEXT_EAP, InEap)
        goto exit;
    }
#endif /* defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */

#ifdef __ENABLE_IPSEC_NAT_T__
    if (IS_BEHIND_NAT(pxSa) && !USE_NATT_PORT(pxSa))
    {
        status = ERR_IKE_BAD_PORT; /* should use port 4500 */
        DBG_EXIT
    }
#endif

#ifdef __ENABLE_IKE_MULTI_AUTH__
    IN_SET
    IN_LOOP_BEGIN
        IN_NEXT(    IKE_NEXT_AUTH,  InAuth0)
        IN_NEXT(    IKE_NEXT_N,     InNotifyMultiAuth)
    IN_LOOP_NONE
    } /* paranthesis started with IN_LOOP_BEGIN */
    IN_RESET

    if (IKE_CNTXT_FLAG_AUTH & ctx->flags) /* use AUTH */
    {
        if ((IKE_CNTXT_FLAG_ANOTHER_AUTH & ctx->flags) && /* another peer auth */
            !(IKE_SA_FLAG_MULTI_AUTH & pxSa->flags)) /* multi-auth not supported */
        {
            status = ERR_IKE_BAD_AUTH;
            DBG_EXIT
        }
    }
    else
    {
        ctx->flags &= ~(IKE_CNTXT_FLAG_ANOTHER_AUTH); /* jic */
    }

    GET_PAYLOAD(    IKE_NEXT_ID_I,  InId)
#else
    IN_SET
    IN_LOOP_BEGIN
        IN_NEXT(    IKE_NEXT_ID_I,  InId)
        IN_NEXT(    IKE_NEXT_SA,    InSa0)
    IN_LOOP_NONE
    } /* paranthesis started with IN_LOOP_BEGIN */
    IN_RESET
#endif

    if (!(IKE_CNTXT_FLAG_ID_I & ctx->flags)) /* missing IDi */
    {
#ifdef __ENABLE_IKE_MULTI_AUTH__
        if (!(IKE_CNTXT_FLAG_AUTH & ctx->flags) && /* no AUTH (and no EAP) */
            pxSa->u.v2.authMtds[_I] && /* peer auth already done (at least once) */
            (0 != GetMultiAuthMtd(pxSa, &bAnotherAuth))) /* more host auth */
        {
            /* OK. The initiator (peer) sent an empty IKE_AUTH message. */
            /* Note: pxSa->u.v2.pxIPsecSa must be non-NULL !!! */
            goto do_sa2;
        }
#endif
        status = ERR_IKE_BAD_ID;
        DBG_EXIT
    }

#ifdef __ENABLE_IKE_MULTI_AUTH__
    if (pxSa->u.v2.pxIPsecSa) /* SAi2 saved from 1st (inbound) IKE_AUTH msg */
    {
        /* more peer auth */
        IN_SET
        IN_LOOP_BEGIN
            IN_NEXT(IKE_NEXT_CERT,  InCert)
            IN_NEXT(IKE_NEXT_N,     InNotify)
            IN_NEXT(IKE_NEXT_CERTREQ, InCr)
            IN_NEXT(IKE_NEXT_ID_R,  InId)
        IN_LOOP_NONE
        } /* paranthesis started with IN_LOOP_BEGIN */
        IN_RESET

        goto do_auth;
    }

    GET_PAYLOAD(    IKE_NEXT_SA,    InSa0)
#endif
    pxIPsecSa = pxXg->pxIPsecSa;

    if (NULL == pxIPsecSa) /* missing SAi2 */
    {
        status = ERR_IKE_BAD_SA;
        DBG_EXIT
    }

    IN_SET
    IN_LOOP_BEGIN
        IN_NEXT(    IKE_NEXT_CERT,  InCert)
        IN_NEXT(    IKE_NEXT_N,     InNotify)
        IN_NEXT(  IKE_NEXT_CERTREQ, InCr)
        IN_NEXT(    IKE_NEXT_ID_R,  InId)
#ifndef __ENABLE_IKE_MULTI_AUTH__
        IN_NEXT(    IKE_NEXT_AUTH,  InAuth0)
#endif
#ifdef __ENABLE_IKE_CP__
        IN_NEXT(    IKE_NEXT_CP,    InCp)
#endif
        IN_NEXT(    IKE_NEXT_TS_I,  InTSir)
        IN_REJECT(  IKE_NEXT_TS_R)
        IN_NEXT(    IKE_NEXT_V,     InVid)
    IN_LOOP_NONE
    } /* paranthesis started with IN_LOOP_BEGIN */
    IN_RESET

#ifdef __ENABLE_IKE_MULTI_AUTH__
do_auth:
#endif
    if (IKE_CNTXT_FLAG_AUTH & ctx->flags) /* use AUTH, w/o EAP */
    {
        LAST_PAYLOAD(IKE_NEXT_AUTH, InAuth)

#ifdef __ENABLE_IKE_MULTI_AUTH__
        if (!(IKE_CNTXT_FLAG_ANOTHER_AUTH & ctx->flags)) /* no more peer auth */
#endif
        if (IKE_SA_FLAG_INIT_C & pxSa->flags) /* initial contact */
        {
            IKE_initContSa(pxSa);
            pxSa->flags &= ~(IKE_SA_FLAG_INIT_C); /* jic */
        }

#ifdef __ENABLE_IKE_MULTI_AUTH__
        /* check if we should continue with another auth */
        if (IKE_CNTXT_FLAG_ANOTHER_AUTH & ctx->flags) /* peer */
        {
            bAnotherAuth = TRUE;
        }
        else if (IKE_SA_FLAG_MULTI_AUTH & pxSa->flags)
        {
            GetMultiAuthMtd(pxSa, &bAnotherAuth); /* host */
        }

        if (pxSa->u.v2.authMtds[_R]) /* host auth already done (at least once) */
        {
            goto do_sa2;
        }
#endif
        /* check if host PSK auth is configured */
        if (OK == IKE_getPsk(NULL, NULL, pxSa, _OUT))
        {
            IKE_authMtdInfo *pAuthMtd = IKE_authMtdEx(pxSa->ikePeerConfig, 0, AUTH_MTD_SHARED_KEY);
            if (pAuthMtd && pAuthMtd->bEnabledOut[_R]) /* yes */
            {
                goto do_sa2;
            }
        }
    }
    else /* with EAP */
    {
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
#ifdef __ENABLE_IKE_EAP_ONLY__
        if ((IKE_CNTXT_FLAG_EAP_ONLY & ctx->flags) &&
            /* received EAP_ONLY_AUTHENTICATION notification */
            pxSa->ikePeerConfig->bDoEapOnly)
        {
            pxSa->flags |= IKE_SA_FLAG_EAP_ONLY;
        }
#endif
        /* initiate EAP session */
        if (OK > (status = IKE_eapProcess(NULL, pxSa, pxXg)))
        {
            ctx->wMsgType = AUTHENTICATION_FAILED;
            goto exit;
        }
        pxSa->flags |= IKE_SA_FLAG_EAP;
        bAnotherAuth = TRUE;

#ifdef __ENABLE_IKE_EAP_ONLY__
        if (IKE_SA_FLAG_EAP_ONLY & pxSa->flags)
            goto do_sa2; /* only send AUTH after EAP is done */
#endif
#ifdef __ENABLE_IKE_MULTI_AUTH__
        if (~((1 << AUTH_MTD_SHARED_KEY) | (1 << AUTH_MTD_EAP)) & pxSa->u.v2.authMtds[_R])
        {
            /* host 'cert-based' auth already done */
            goto do_sa2;
        }
#endif
#else
        /* missing AUTH */
        ctx->wMsgType = AUTHENTICATION_FAILED;
        status = ERR_IKE_BAD_AUTH;
        DBG_EXIT
#endif
    }

    /* make sure host 'cert-based' auth is configured */
    if (OK > (status = IKE_useCert(ctx, 0)))
    {
        ctx->wMsgType = AUTHENTICATION_FAILED;
        DBG_EXIT
    }

do_sa2:

#ifdef __ENABLE_IKE_PPK_RFC8784__
    if((pxSa->flags & IKE_SA_FLAG_USEPPK) && !(pxSa->flags & IKE_SA_FLAG_PPK_ID))
    {
        ctx->wMsgType = AUTHENTICATION_FAILED;
        status = ERR_IKE_MISMATCH_AUTH_METHOD;
        DBG_EXIT
    }
#endif
#if defined(__ENABLE_IKE_MULTI_AUTH__) || \
    (defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__))

#ifdef __ENABLE_IKE_MULTI_AUTH__
    if (!bAnotherAuth)
    {
        /* check if peer has used all required auth methods */
        sbyte4 reqInAuthMtds = pxSa->ikePeerConfig->reqInAuthMtds[_R];
        if ((reqInAuthMtds & pxSa->u.v2.authMtds[_I]) != reqInAuthMtds)
        {
            ctx->wMsgType = AUTHENTICATION_FAILED;
            status = ERR_IKE_MISMATCH_AUTH_METHOD;
            DBG_EXIT
        }
    }
#endif

    if (!pxIPsecSa) /* EAP success or already in multi-auth */
    {
#ifdef __ENABLE_IKE_MULTI_AUTH__
        if (bAnotherAuth) goto exit; /* !!! */
#endif
        /* retrieve piggybacked CHILD_SA (SAi2) */
        pxXg->pxIPsecSa = pxSa->u.v2.pxIPsecSa;
        pxSa->u.v2.pxIPsecSa = NULL;
        pxXg->pxSa = NULL;
        status = DoSa2Late_R(ctx);
    }
    else
    {
        /* piggybacked CHILD_SA (SAi2) */
        pxXg->pxSa = NULL;
        if (OK > (status = DoSa2_R(ctx, bAnotherAuth)))
        {
            goto exit;
        }

        if (bAnotherAuth)
        {
            /* store piggybacked CHILD_SA
               (new exchanges will be needed for upcoming EAP or multi auth)
             */
            pxSa->u.v2.pxIPsecSa = pxIPsecSa;
            pxXg->pxIPsecSa = NULL;
        }
    }
#else
    /* piggybacked CHILD_SA (SAi2) */
    pxXg->pxSa = NULL;
    status = DoSa2_R(ctx);
#endif

exit:
    pxSa->merror = status;
    return status;
} /* authR_in */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_IKE_MULTI_AUTH__) && \
    (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

static void
ResetEap(IKESA pxSa, IKE2EAP pxEap)
{
    /* clean up EAP data, if any */
    pxSa->flags &= ~(IKE_SA_FLAG_EAP_DONE);
#ifdef __ENABLE_IKE_EAP_ONLY__
    pxSa->flags &= ~(IKE_SA_FLAG_EAP_ONLY);
#endif
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

    return;
}

#endif


/*------------------------------------------------------------------*/
/*
   IKE_AUTH Exchange without EAP
   response            <-- IDr, [CERT+,] AUTH,
                           [CP(CFG_REPLY),]
                           [N(IPCOMP_SUPPORTED),]
                           [N(USE_TRANSPORT_MODE),]
                           [N(ESP_TFC_PADDING_NOT_SUPPORTED),]
                           [N(NON_FIRST_FRAGMENTS_ALSO),]
                           SAr2, TSi, TSr,
                           [N(ADDITIONAL_TS_POSSIBLE),]
                           [N(AUTH_LIFETIME),]
                           [N(MOBIKE_SUPPORTED),
                            [N(ADDITIONAL_*_ADDRESS)+,]]
                           [V+]


   IKE_AUTH Exchange with EAP
   1st response        <-- IDr,
                          [CERT+,] (w/o EAP_ONLY_AUTHENTICATION)
                           AUTH,   (w/o EAP_ONLY_AUTHENTICATION)
                           EAP,
                           [V+]

                     / --> EAP
   repeat 1..N times |
                     \ <-- EAP

   last request        --> AUTH

   last response       <-- AUTH,
                           [CP(CFG_REPLY),]
                           [N(IPCOMP_SUPPORTED),]
                           [N(USE_TRANSPORT_MODE),]
                           [N(ESP_TFC_PADDING_NOT_SUPPORTED),]
                           [N(NON_FIRST_FRAGMENTS_ALSO),]
                           SAr2, TSi, TSr,
                           [N(ADDITIONAL_TS_POSSIBLE),]
                           [N(AUTH_LIFETIME),]
                           [N(MOBIKE_SUPPORTED),
                            [N(ADDITIONAL_*_ADDRESS)+,]]
                           [V+]
*/

/*------------------------------------------------------------------*/

static MSTATUS
authR_out(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    IPSECSA pxIPsecSa = ctx->pxXg->pxIPsecSa;
#ifdef __ENABLE_IKE_MULTI_AUTH__
    ubyte oAuthMtd = 0;
    intBoolean bAnotherAuth = FALSE;
#endif
#ifdef __ENABLE_IKE_REDIRECT_IN_AUTH__
    ubyte4  count = 0;
#endif

    /* <-- R */

#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    IKE2EAP pxEap = &pxSa->u.v2.eapState;

    if (pxEap->pxMsg) /* EAP auth w/ EAP payload */
    {
        if (IKE_SA_FLAG_EAP & pxSa->flags) /* 1st EAP payload */
        {
#ifdef __ENABLE_IKE_MULTI_AUTH__
            if ((IKE_SA_FLAG_MULTI_AUTH & pxSa->flags) &&
                (0 == (oAuthMtd = pxSa->u.v2.oAuthMtd
                                = GetMultiAuthMtd(pxSa, NULL))))
            {
                /* no more host auth */
            }
            else
#endif
            {
            DO_FUNC(OutId)                  /* IDr */

#if defined(__ENABLE_IKE_EAP_ONLY__)
            if (!(IKE_SA_FLAG_EAP_ONLY & pxSa->flags))
#endif
            {
#ifdef __ENABLE_IKE_MULTI_AUTH__
            if (AUTH_MTD_SHARED_KEY != oAuthMtd)
#endif
            DO_FUNC(OutCert)                /* [CERT+] */

            DO_FUNC(OutAuth)                /* AUTH */

#ifdef __ENABLE_IKE_MULTI_AUTH__
            pxSa->u.v2.oAuthMtd = 0; /* !!! */
#endif
            }}
        }

        status = OutGen(ctx, IKE_NEXT_EAP,  /* EAP */
                        GET_NTOHS(pxEap->pxMsg->wLength),
                        (ubyte *) pxEap->pxMsg);
        goto exit; /* !!! */
    }

    if (IKE_SA_FLAG_EAP_DONE & pxSa->flags) /* EAP auth's final msg */
    {
        DO_FUNC(OutAuth)                    /* AUTH (with EAP) */

#ifdef __ENABLE_IKE_MULTI_AUTH__
        if ((IKE_SA_FLAG_MULTI_AUTH & pxSa->flags) &&
            (0 != GetMultiAuthMtd(pxSa, NULL)))
        {
            bAnotherAuth = TRUE; /* another host auth */
        }
#endif
    }
    else
#endif /* defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */

#ifdef __ENABLE_IKE_MULTI_AUTH__
    if ((IKE_SA_FLAG_MULTI_AUTH & pxSa->flags) &&
        (0 == (oAuthMtd = GetMultiAuthMtd(pxSa, &bAnotherAuth))))
    {
        /* no more host auth */
    }
    else
#endif
    {
#ifdef __ENABLE_IKE_MULTI_AUTH__
        if (oAuthMtd &&
            (AUTH_MTD_SHARED_KEY != oAuthMtd) &&
            (AUTH_MTD_SHARED_KEY == ctx->u.v2.oAuthMtd))
        {
            /* if PSK is used by peer auth, use PSK for host auth if possible */
            IKE_authMtdInfo *pAuthMtd = IKE_authMtdEx(pxSa->ikePeerConfig, 0,
                                                      AUTH_MTD_SHARED_KEY);
            if (pAuthMtd && pAuthMtd->bEnabledOut[_R] &&
                !((1 << AUTH_MTD_SHARED_KEY) & pxSa->u.v2.authMtds[_R]))
            {
                oAuthMtd = AUTH_MTD_SHARED_KEY;
            }
        }
        pxSa->u.v2.oAuthMtd = oAuthMtd;
#endif
        DO_FUNC(OutId)      /* IDr */

#ifdef __ENABLE_IKE_MULTI_AUTH__
        if (AUTH_MTD_SHARED_KEY != oAuthMtd)
#endif
        DO_FUNC(OutCert)    /* [CERT+] */

        DO_FUNC(OutAuth)    /* AUTH */

#ifdef __ENABLE_IKE_MULTI_AUTH__
        pxSa->u.v2.oAuthMtd = 0; /* !!! */
#endif
    }

#ifdef __ENABLE_IKE_MULTI_AUTH__
    if (bAnotherAuth || /* another host auth */
        (IKE_CNTXT_FLAG_ANOTHER_AUTH & ctx->flags)) /* another peer auth */
    {
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
        ResetEap(pxSa, pxEap);
#endif
        if (bAnotherAuth)
        {
            ctx->wMsgType = ANOTHER_AUTH_FOLLOWS; /* temporary !!! */
            DO_FUNC(OutInfo)
        }
        goto exit;
    }
#endif /* __ENABLE_IKE_MULTI_AUTH__ */

    if (NULL == pxIPsecSa)
    {
        status = ERR_NULL_POINTER;
        DBG_EXIT
    }

#ifdef __ENABLE_IKE_CP__
        DO_FUNC(OutCp)
#endif

#ifdef __IKE_KEYADD_DONT_WAIT__
    if (!pxIPsecSa->wMsgType)
    {
        pxIPsecSa->oState = STATE_QUICK_R;
        if (OK > IKE_addIPsecKey(ctx))
            pxIPsecSa->wMsgType = NO_ADDITIONAL_SAS;
    }
#endif

#ifdef __ENABLE_IKE_REDIRECT_IN_AUTH__
    if (OK > (status = IKE2_getSaNum(&count)))
        goto exit;

    if (count >= IKE_REDIRECT_MAX)
        pxIPsecSa->wMsgType = REDIRECT;
#endif

    if (pxIPsecSa->wMsgType)
    {
        ctx->wMsgType = pxIPsecSa->wMsgType; /* temporary !!! */
        DO_FUNC(OutInfo)
    }
    else
    {
        DO_FUNC(OutNotifySa2)
        DO_FUNC(OutSa)
        DO_FUNC(OutTSir)
    }

    if (pxSa->u.v2.dwExpAuthSecs)
    {
        ctx->wMsgType = AUTH_LIFETIME; /* temporary !!! */
        DO_FUNC(OutInfo)
    }

#ifdef __ENABLE_MOBIKE__
    if (IKE_SA_FLAG_MOBILE & pxSa->flags)
    {
        ctx->wMsgType = MOBIKE_SUPPORTED; /* temporary !!! */
        DO_FUNC(OutInfo)
    }
#endif
#ifdef __ENABLE_IKE_PPK_RFC8784__
    if (IKE_SA_FLAG_USEPPK & pxSa->flags)
    {
        ctx->wMsgType = PPK_IDENTITY; /* temporary !!! */
        DO_FUNC(OutInfo)
    }
#endif
    pxSa->u.v2.dwWndLen[_I] = 1; /* or from window size notify */
/*  pxSa->u.v2.dwWndLen[_R] = IKE_WINDOW_SIZE;*/

    pxSa->u.v2.dwTimeAuthed =
    pxSa->dwTimeCreated =
    pxSa->dwTimeStamp = RTOS_deltaMS(&gStartTime, NULL);

exit:
    return status;
} /* authR_out */


/*------------------------------------------------------------------*/

static MSTATUS
DoSa2_I(IKE_context ctx)
{
    /* Called by authI_in() only */
    MSTATUS status = OK;
    IPSECSA pxIPsecSa = ctx->pxXg->pxIPsecSa;

    if (!(IKE_CNTXT_FLAG_TS & ctx->flags)) /* missing TSi, TSr */
    {
        status = ERR_IKE_BAD_ID2;
        DBG_EXIT
    }

    IN_LOOP_BEGIN
        IN_LAST(    IKE_NEXT_SA, InSa)
        IN_REJECT(  IKE_NEXT_KE)
        IN_REJECT(  IKE_NEXT_NONCE)
    IN_LOOP_NONE
    } /* paranthesis started with IN_LOOP_BEGIN */

    pxIPsecSa->wPFS = 0; /* jic - no PFS */

    /* generate keys */
    DO_FUNC(DoKe2)

    pxIPsecSa->c_flags |= IKE_CHILD_FLAG_MATURE;
    pxIPsecSa->oState = STATE_QUICK_I;

exit:
    if (OK > status)
    {
        pxIPsecSa->merror = status;
    }
    return status;
} /* DoSa2_I */


/*------------------------------------------------------------------*/

static MSTATUS
authI_in(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    IKE2XG pxXg = ctx->pxXg;
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    IKE2EAP pxEap = &pxSa->u.v2.eapState;
#endif
#ifdef __ENABLE_IKE_MULTI_AUTH__
    intBoolean bAnotherAuth = FALSE;
    sbyte4 reqInAuthMtds;
#endif

    /* I <-- */
    IN_SK   /* SK {...} */

    IN_LOOP_BEGIN
        IN_NEXT(    IKE_NEXT_N,     InNotify)
    IN_LOOP_END

#ifdef __ENABLE_IKE_REDIRECT__
    if (ctx->wMsgType && ctx->wMsgType != REDIRECT) /* Notify error received */
#else
    if (ctx->wMsgType) /* Notify error received */
#endif
    {
        pxSa->wMsgType = ctx->wMsgType;
        status = ERR_IKE_NOTIFY_PAYLOAD;
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    if (pxEap->pxMsg) /* EAP */
    {
        IN_PAYLOAD(IKE_NEXT_EAP, InEap)
        goto exit;
    }
#endif

    IN_SET
    IN_LOOP_BEGIN
        IN_NEXT(    IKE_NEXT_AUTH,  InAuth0)
#ifdef __ENABLE_IKE_MULTI_AUTH__
        IN_NEXT(    IKE_NEXT_N,     InNotifyMultiAuth)
#endif
        IN_NEXT(    IKE_NEXT_V,     InVid)
    IN_LOOP_NONE
    } /* paranthesis started with IN_LOOP_BEGIN */
    IN_RESET

#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
    if (IKE_SA_FLAG_EAP_DONE & pxSa->flags)
    {
        goto do_auth;
    }
#endif

    IN_SET
    IN_LOOP_BEGIN
        IN_NEXT(    IKE_NEXT_ID_R,  InId)
        IN_NEXT(    IKE_NEXT_CERT,  InCert)
/*      IN_REJECT(  IKE_NEXT_ID_I)*/
    IN_LOOP_NONE
    } /* paranthesis started with IN_LOOP_BEGIN */
    IN_RESET

    if (!(IKE_CNTXT_FLAG_ID_R & ctx->flags)) /* missing IDr */
    {
#ifdef __ENABLE_IKE_MULTI_AUTH__
        if (IKE_CNTXT_FLAG_AUTH & ctx->flags) /* use AUTH  */
#endif
        {
            status = ERR_IKE_BAD_ID;
            DBG_EXIT
        }
    }

#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
do_auth:
#endif
    if (!(IKE_CNTXT_FLAG_AUTH & ctx->flags)) /* missing AUTH */
    {
#ifdef __ENABLE_IKE_MULTI_AUTH__
        if (pxSa->u.v2.oAuthMtd) /* non-EAP multi-auth */
        {
            if (pxSa->u.v2.authMtds[_R]) /* peer already authenticated */
            {
                goto do_multi_auth;
            }
        }
        else
#endif
        {
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__) && \
    (defined(__ENABLE_IKE_MULTI_AUTH__) || defined(__ENABLE_IKE_EAP_ONLY__))
             /* '1st inbound EAP' may skip AUTH in some cases */
            if ((IKE_SA_FLAG_EAP & pxSa->flags) &&
                !(IKE_SA_FLAG_EAP_DONE & pxSa->flags))
            {
#ifdef __ENABLE_IKE_MULTI_AUTH__
                if (pxSa->u.v2.authMtds[_R]) /* peer already authenticated */
                {
                    goto do_eap;
                }
#endif
#ifdef __ENABLE_IKE_EAP_ONLY__
                if (IKE_SA_FLAG_EAP_ONLY & pxSa->flags) /* EAP-only */
                {
                    goto do_eap_only;
                }
#endif
            }
#endif
        }
        status = ERR_IKE_BAD_AUTH;
        DBG_EXIT
    }

    GET_PAYLOAD(IKE_NEXT_AUTH, InAuth)

#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
#ifdef __ENABLE_IKE_MULTI_AUTH__
    if (0 == pxSa->u.v2.oAuthMtd)
#endif
    if (IKE_SA_FLAG_EAP & pxSa->flags)
    {
        if (!(IKE_SA_FLAG_EAP_DONE & pxSa->flags)) /* 1st inbound EAP */
        {
#ifdef __ENABLE_IKE_MULTI_AUTH__
do_eap:
#endif
#ifdef __ENABLE_IKE_EAP_ONLY__
            pxSa->flags &= ~(IKE_SA_FLAG_EAP_ONLY); /* w/o EAP-only */
do_eap_only:
#endif
            LAST_PAYLOAD(IKE_NEXT_EAP, InEap)

            if (!(IKE_CNTXT_FLAG_EAP & ctx->flags)) /* missing EAP */
            {
                status = ERR_IKE_BAD_PAYLOAD;
                DBG_EXIT
            }
            goto exit;
        }

        /* final (inboubd) msg of this IKE_AUTH exchange */
        pxSa->flags &= ~(IKE_SA_FLAG_EAP); /* no more EAP */
    }
#endif

#ifdef __ENABLE_IKE_MULTI_AUTH__
    /* Check if we should continue with another auth. */
    if (IKE_SA_FLAG_MULTI_AUTH & pxSa->flags)
    {
do_multi_auth:
        if ((IKE_CNTXT_FLAG_ANOTHER_AUTH & ctx->flags) || /* notified by peer */
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
            (IKE_SA_FLAG_EAP & pxSa->flags) ||  /* EAP */
#endif
            (0 != GetMultiAuthMtd(pxSa, NULL))) /* cert or PSK */
        {
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
            ResetEap(pxSa, pxEap);
#endif
            bAnotherAuth = TRUE;
            goto exit; /* yes */
        }
    }

    /* check if peer has used all required auth methods */
    reqInAuthMtds = pxSa->ikePeerConfig->reqInAuthMtds[_I];
    if ((reqInAuthMtds & pxSa->u.v2.authMtds[_R]) != reqInAuthMtds)
    {
        status = ERR_IKE_MISMATCH_AUTH_METHOD;
        DBG_EXIT
    }
#endif /* __ENABLE_IKE_MULTI_AUTH__ */

    if (IKE_SA_FLAG_INIT_C & pxSa->flags) /* initial contact */
    {
        IKE_initContSa(pxSa);
    }

#ifdef __ENABLE_IKE_CP__
    GET_PAYLOAD(    IKE_NEXT_CP,    InCp)
#endif

    IN_SET
    IN_LOOP_BEGIN
        IN_NEXT(    IKE_NEXT_N,     InNotify)
        IN_NEXT(    IKE_NEXT_SA,    InSa0)
        IN_NEXT(    IKE_NEXT_TS_I,  InTSir)
        IN_REJECT(  IKE_NEXT_TS_R)
    IN_LOOP_NONE
    } /* paranthesis started with IN_LOOP_BEGIN */
    IN_RESET

#ifdef __ENABLE_IKE_PPK_RFC8784__
    if((pxSa->flags & IKE_SA_FLAG_USEPPK) && !(pxSa->flags & IKE_SA_FLAG_PPK_ID))
    {
        ctx->wMsgType = AUTHENTICATION_FAILED;
        status = ERR_IKE_MISMATCH_AUTH_METHOD;
        DBG_EXIT
    }
#endif

#ifdef __ENABLE_IKE_REDIRECT__
    if (REDIRECTED_FROM == ctx->wMsgType)
    {
        if (OK > IKE_redirect(ctx))
        {
            DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: IKE_redirect failed.");
        }
        else
        {
            pxSa->flags |= IKE_SA_FLAG_REDIRECTED;
            pxSa->dwPeerAddr = ctx->oldPeerAddr;
            ctx->peerAddr = REF_MOC_IPADDR(pxSa->dwPeerAddr);
        }
    }
#endif

    /* IKE_SA established */
/*  pxSa->u.v2.dwWndLen[_I] = <from window size notify>; */
    pxSa->u.v2.dwWndLen[_R] = 1/*IKE_WINDOW_SIZE*/;

    pxSa->u.v2.dwTimeAuthed =
    pxSa->dwTimeCreated =
    pxSa->dwTimeStamp = RTOS_deltaMS(&gStartTime, NULL);

    pxSa->flags |= IKE_SA_FLAG_MATURE;
    pxSa->oState = STATE_MAIN_I;

    /* piggybacked CHILD_SA */
    if (IKE_CNTXT_FLAG_SA & ctx->flags) /* jic - missing SAr2 */
    {
        DoSa2_I(ctx);
    }
    else if (ctx->wMsgType)
    {
        IPSECSA pxIPsecSa = pxXg->pxIPsecSa;
        pxIPsecSa->wMsgType = ctx->wMsgType;
        pxIPsecSa->merror = ERR_IKE_NOTIFY_PAYLOAD;
    }

exit:
    if (OK > status)
    {
        pxSa->merror = status;

        if (STATUS_IKE_PENDING != status)
        {
            IKE2_delSa(pxSa, FALSE, status);
#ifdef __IKE_MULTI_THREADED__
            ctx->pxSa = NULL; /* !!! for IKE2_xchgIn() */
#endif
        }
#ifdef __IKE_UPDATE_TIMER__
        else if (IKE_XCHG_FLAG_PENDING & pxXg->x_flags)
        {
            /* Incoming message has been processed but the exchange is
               pending (before moving to the next state). We need to cancel re-
               transmission timer here !!!
             */
            IKE_DEL_TIMER_EVT(pxXg->rtxTimerId, pxXg->rtxTimerHdl)
            pxXg->rtxCount = 0;
        }
#endif
    }
    else
    {
        /* prepare for next IKE_AUTH exchange */
#if defined(__ENABLE_IKE_MULTI_AUTH__) || \
    (defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__))
        if (
#ifdef __ENABLE_IKE_MULTI_AUTH__
            bAnotherAuth || /* multiple auth. */
#endif
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)
            (IKE_SA_FLAG_EAP & pxSa->flags) || /* more EAP */
#endif
            FALSE)
        {
            sbyte4 i;
            for (i=0; i < pxXg->numMsgs; i++)
            {
                CHECK_FREE(pxXg->poMsg[i])
                pxXg->dwMsgLen[i] = 0;
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

#ifdef __IKE_UPDATE_TIMER__
            IKE_DEL_TIMER_EVT(pxXg->rtxTimerId, pxXg->rtxTimerHdl)
            pxXg->rtxCount = 0;
#endif
            /* advance msg ID !!! */
            pxXg->dwMsgId = ++(pxSa->u.v2.dwMsgId[_I]);
        }
#endif
        pxSa->merror = OK;
    }
    return status;
} /* authI_in */


/*------------------------------------------------------------------*/
/*
   CREATE_CHILD_SA Exchange

   for Creating/Rekeying CHILD_SAs
   request             --> [N(REKEY_SA)],
                           [N(IPCOMP_SUPPORTED)+],
                           [N(USE_TRANSPORT_MODE)],
                           [N(ESP_TFC_PADDING_NOT_SUPPORTED)],
                           [N(NON_FIRST_FRAGMENTS_ALSO)],
                           SAi, Ni, [KEi], TSi, TSr

   for Rekeying the IKE_SA
   request             --> SAi, Ni, [KEi]
*/

/*------------------------------------------------------------------*/

static MSTATUS
childI_out(IKE_context ctx)
{
    MSTATUS status;

    IPSECSA pxIPsecSa = ctx->pxXg->pxIPsecSa;

    /* I --> */
    if (pxIPsecSa)
        DO_FUNC(OutNotifySa2)

    DO_FUNC(OutSa)
    DO_FUNC(OutNonce)
    DO_FUNC(OutKe)

    if (pxIPsecSa)
    {
        DO_FUNC(OutTSir)

        if (STATE_QUICK_I2c != pxIPsecSa->oState) /* jic re-send, e.g. INVALID_KE_PAYLOAD  */
        pxIPsecSa->oState = STATE_QUICK_I2;
    }

exit:
    return status;
} /* childI_out */


/*------------------------------------------------------------------*/

static MSTATUS
childR_in(IKE_context ctx)
{
    MSTATUS status = OK;

    IKE2XG pxXg = ctx->pxXg;

    IKESA pxSa = NULL;
    IPSECSA pxIPsecSa = NULL;

    /* --> R */
    IN_SK   /* SK {...} */

    /* IKE_SA or CHILD_SA? */
    IN_SET
    IN_LOOP_BEGIN
        IN_NEXT(    IKE_NEXT_SA,    InSa0)
    IN_LOOP_NONE
    } /* paranthesis started with IN_LOOP_BEGIN */
    IN_RESET

    pxSa = pxXg->pxSa;
    pxIPsecSa = pxXg->pxIPsecSa;

    if (!pxSa && !pxIPsecSa)                    /* missing SAi */
    {
        status = ERR_IKE_BAD_SA;
        DBG_EXIT
    }

    IN_SET
    IN_LOOP_BEGIN
        IN_NEXT(    IKE_NEXT_N,     InNotify)
        IN_NEXT(    IKE_NEXT_NONCE, InNonce)
        IN_NEXT(    IKE_NEXT_TS_I,  InTSir)
        IN_REJECT(  IKE_NEXT_TS_R)
    IN_LOOP_NONE
    } /* paranthesis started with IN_LOOP_BEGIN */
    IN_RESET

    if (!(IKE_CNTXT_FLAG_NONCE & ctx->flags))   /* missing Ni */
    {
        status = ERR_IKE_BAD_NONCE;
        DBG_EXIT
    }

    if (!(IKE_CNTXT_FLAG_TS & ctx->flags) &&    /* missing TSi, TSr */
        !pxSa) /* CHILD_SA */
    {
        ctx->wMsgType = TS_UNACCEPTABLE;
        status = ERR_IKE_BAD_ID2;
        DBG_EXIT
    }

    LAST_PAYLOAD(    IKE_NEXT_SA,   InSa)

    /* process KEi *after* SAi */
    LAST_PAYLOAD(    IKE_NEXT_KE,   InKe)

    if (!(IKE_CNTXT_FLAG_KE & ctx->flags))      /* no KEi (i.e. PFS) */
    {
        if (pxSa || /* rekeying IKE_SA; PFS is required [RFC7296][RFC5996] 1.3.2 */
            IKE_checkGroup(0, FALSE, ctx->pxSa, NULL, pxIPsecSa)) /* CHILD_SA */
        {
            ctx->wMsgType = INVALID_KE_PAYLOAD;
            status = ERR_IKE_BAD_KE;
            DBG_EXIT
        }

        if (pxIPsecSa) /* CHILD_SA */
            pxIPsecSa->wPFS = 0;
    }

    /* generate keys */
    if (pxSa) /* rekeying IKE_SA */
    {
        status = DoKe(ctx);
    }
    else /* CHILD_SA */
    {
        if (OK > (status = DoKe2(ctx)))
            ctx->wMsgType = NO_ADDITIONAL_SAS;

#ifdef __ENABLE_DIGICERT_PFKEY__
        /* async SADB_GETSPI msg */
        else if (IKE_XCHG_FLAG_PENDING & pxXg->x_flags)
            status = STATUS_IKE_PENDING;
#endif
    }

exit:
    if (OK > status)
    {
        if (pxSa)
        {
            if (!pxSa->merror)
                pxSa->merror = status;
        }
        else if (pxIPsecSa) /* must check!!! */
        {
            if (!pxIPsecSa->merror)
                pxIPsecSa->merror = status;
        }
    }
    else
    {
        if (pxSa) pxSa->merror = OK;
        else pxIPsecSa->merror = OK;
    }
    return status;
} /* childR_in */


/*------------------------------------------------------------------*/
/*
   CREATE_CHILD_SA Exchange

   for Creating/Rekeying CHILD_SAs
   response            <-- [N(IPCOMP_SUPPORTED)],
                           [N(USE_TRANSPORT_MODE)],
                           [N(ESP_TFC_PADDING_NOT_SUPPORTED)],
                           [N(NON_FIRST_FRAGMENTS_ALSO)],
                           SAr, Nr, [KEr], TSi, TSr,
                           [N(ADDITIONAL_TS_POSSIBLE)]

   for Rekeying the IKE_SA
   response            <-- SA, Nr, [KEr]
*/

/*------------------------------------------------------------------*/

static MSTATUS
childR_out(IKE_context ctx)
{
    MSTATUS status;

    IKE2XG pxXg = ctx->pxXg;
    IKESA pxSa = pxXg->pxSa;

    /* <-- R */
#ifdef __IKE_KEYADD_DONT_WAIT__
    IPSECSA pxIPsecSa = pxXg->pxIPsecSa;
    if (pxIPsecSa)
    {
        pxIPsecSa->oState = STATE_QUICK_R;
        if (OK > IKE_addIPsecKey(ctx))
        {
            ctx->wMsgType = NO_ADDITIONAL_SAS;
            DO_FUNC(OutInfo)
            goto exit;
        }
    }
#endif
    DO_FUNC(OutSa)
    DO_FUNC(OutNonce)
    DO_FUNC(OutKe)

    if (pxSa) /* rekeying IKE_SA */
    {
        IKESA pxSa0 = ctx->pxSa;
        pxSa0->flags |= IKE_SA_FLAG_REKEYED;
        pxSa0->merror = STATUS_IKE_REKEY;

        pxSa0->pxSaRekey = pxSa; /* !!! */

        pxSa->u.v2.dwWndLen[_I] = 1; /* or from window size notify */
        pxSa->u.v2.dwWndLen[_R] = 1/*IKE_WINDOW_SIZE*/;

        pxSa->dwTimeStamp = /* for DPD */
        pxSa->dwTimeCreated = RTOS_deltaMS(&gStartTime, NULL);
    }
    else /* CHILD_SA */
    {
        DO_FUNC(OutTSir)
        DO_FUNC(OutNotifySa2)
    }

exit:
    return status;
} /* childR_out */


/*------------------------------------------------------------------*/

static MSTATUS
childI_in(IKE_context ctx)
{
    MSTATUS status = OK;

    IKE2XG pxXg = ctx->pxXg;
    IKESA pxSa = pxXg->pxSa;
    IPSECSA pxIPsecSa = pxXg->pxIPsecSa;
    /* Note: either 'pxSa' or 'pxIPsecSa' is non-NULL but not both */

    /* I <-- */
    IN_SK   /* SK {...} */

    if (pxIPsecSa)
    {
        /* response is received; so IKE_SA is not dead */
        /* advance the state - IKE_SA won't be rekeyed; see IKE_delIPsecSa() */
        pxIPsecSa->oState = STATE_QUICK_I2c;
    }

    IN_LOOP_BEGIN
        IN_NEXT(    IKE_NEXT_N,     InNotify)
    IN_LOOP_END

    if ((INVALID_KE_PAYLOAD == ctx->wMsgType) &&
        (1 == ctx->pxSa->u.v2.dwWndLen[_I])) /* for now */
    {
        /* will re-send a new exchange */
        sbyte4 i;
        for (i = pxXg->numMsgs - 1; i >= 0; i--)
        {
            CHECK_FREE(pxXg->poMsg[i])
            pxXg->dwMsgLen[i] = 0;
        }
        pxXg->numMsgs = 0;

        if (pxSa) /* rekeying IKE_SA */
        {
            /* change Initiator cookie - jic Responder keeps old state */
            ubyte cookie[IKE_COOKIE_SIZE];
            if (OK > (status = RANDOM_numberGenerator(g_pRandomContext,
                                                      cookie, IKE_COOKIE_SIZE)))
                DBG_EXIT

#ifdef __IKE_MULTI_THREADED__
            if (NULL == m_ikeSettings.funcPtrIkeGetThreadId)
            {
                status = ERR_IKE_CONFIG;
                DBG_EXIT
            }
            if (OK > (status = (MSTATUS)
                               m_ikeSettings.funcPtrIkeGetThreadId(
                                    &pxSa->tid, cookie, 2, TRUE
                                    MOC_MTHM_REQ_VALUE(pxSa->serverInstance))))
            {
                DBG_EXIT
            }
#endif
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            CRYPTO_INTERFACE_DH_freeDhContextExt(&(pxSa->p_dhContext), NULL, NULL);
#else
            DH_freeDhContext(&(pxSa->p_dhContext), NULL);
#endif

#ifdef __ENABLE_DIGICERT_ECC__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            CRYPTO_INTERFACE_EC_deleteKeyAux(&(pxSa->p_eccKey));
#else
            EC_deleteKey(&(pxSa->p_eccKey));
#endif

#ifdef __ENABLE_DIGICERT_PQC__
            if (NULL != pxSa->pQsCtx)
            {
                CRYPTO_INTERFACE_QS_deleteCtx(&(pxSa->pQsCtx));
            }
#endif
#endif
#ifdef IKE_SA_CKY_HASH_TABLE_SIZE_MASK
            IKE_delSaCkyIndex(pxSa);
#endif
            DIGI_MEMCPY(pxSa->poCky_I, cookie, IKE_COOKIE_SIZE);

#ifdef IKE_SA_CKY_HASH_TABLE_SIZE_MASK
            IKE_addSaCkyIndex(pxSa);
#endif
        }
        else if (pxIPsecSa) /* CHILD_SA */
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            CRYPTO_INTERFACE_DH_freeDhContextExt(&(pxIPsecSa->p_dhContext), NULL, NULL);
#else
            DH_freeDhContext(&(pxIPsecSa->p_dhContext), NULL);
#endif

#ifdef __ENABLE_DIGICERT_ECC__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            CRYPTO_INTERFACE_EC_deleteKeyAux(&(pxIPsecSa->p_eccKey));
#else
            EC_deleteKey(&(pxIPsecSa->p_eccKey));
#endif

#ifdef __ENABLE_DIGICERT_PQC__
            if (NULL != pxIPsecSa->pQsCtx)
            {
                CRYPTO_INTERFACE_QS_deleteCtx(&(pxIPsecSa->pQsCtx));
            }
#endif
#endif
        }

        pxXg->dwMsgId = ++(ctx->pxSa->u.v2.dwMsgId[_I]); /* !!! */

#ifdef __IKE_UPDATE_TIMER__
        IKE_DEL_TIMER_EVT(pxXg->rtxTimerId, pxXg->rtxTimerHdl)
        pxXg->rtxCount = 0;
#endif
        goto exit;
    }

    if (ctx->wMsgType) /* Notify error received */
    {
        if (pxSa) /* rekeying IKE_SA */
            pxSa->wMsgType = ctx->wMsgType;
        else if (pxIPsecSa) /* CHILD_SA */
            pxIPsecSa->wMsgType = ctx->wMsgType;

        status = ERR_IKE_NOTIFY_PAYLOAD;
        goto exit;
    }

    IN_SET
    IN_LOOP_BEGIN
        IN_NEXT(    IKE_NEXT_SA,    InSa0)
        IN_NEXT(    IKE_NEXT_NONCE, InNonce)
        IN_NEXT(    IKE_NEXT_KE,    InKe)
        IN_NEXT(    IKE_NEXT_TS_I,  InTSir)
        IN_REJECT(  IKE_NEXT_TS_R)
        IN_NEXT(    IKE_NEXT_N,     InNotify)
    IN_LOOP_NONE
    } /* paranthesis started with IN_LOOP_BEGIN */
    IN_RESET

    if (!(IKE_CNTXT_FLAG_SA & ctx->flags)) /* missing SAr */
    {
        status = ERR_IKE_BAD_SA;
        DBG_EXIT
    }

    if (!(IKE_CNTXT_FLAG_NONCE & ctx->flags)) /* missing Nr */
    {
        status = ERR_IKE_BAD_NONCE;
        DBG_EXIT
    }

    if (!(IKE_CNTXT_FLAG_KE & ctx->flags)) /* no KEr (i.e. PFS) */
    {
        if (pxSa) /* rekeying IKE_SA */
        {
            /* PFS is required [RFC7296][RFC5996] 1.3.2 */
            status = ERR_IKE_BAD_KE;
            DBG_EXIT
        }

        if (pxIPsecSa && /* CHILD_SA - jic */
            pxIPsecSa->wPFS)
        {
            if (IKE_checkGroup(0, TRUE, ctx->pxSa, NULL, pxIPsecSa))
            {
                status = ERR_IKE_BAD_KE;
                DBG_EXIT
            }

            pxIPsecSa->wPFS = 0;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            CRYPTO_INTERFACE_DH_freeDhContextExt(&(pxIPsecSa->p_dhContext), NULL, NULL);
#else
            DH_freeDhContext(&(pxIPsecSa->p_dhContext), NULL);
#endif
#ifdef __ENABLE_DIGICERT_ECC__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            CRYPTO_INTERFACE_EC_deleteKeyAux(&(pxIPsecSa->p_eccKey));
#else
            EC_deleteKey(&(pxIPsecSa->p_eccKey));
#endif
#endif
        }
    }

    if (!pxSa && !(IKE_CNTXT_FLAG_TS & ctx->flags)) /* missing TSi, TSr */
    {
        status = ERR_IKE_BAD_ID2;
        DBG_EXIT
    }

    LAST_PAYLOAD(   IKE_NEXT_SA,    InSa)

    /* generate keys */
    if (pxSa) /* rekeying IKE_SA */
    {
        IKESA pxSa0 = ctx->pxSa;
        IKESA pxSaRekey = pxSa0->pxSaRekey;

        DO_FUNC(DoKe)

        pxSa0->flags |= IKE_SA_FLAG_REKEYED;
        pxSa0->merror = STATUS_IKE_REKEY;

        /* check conflicting rekeying */
        if (pxSaRekey != pxSa)
        {
            pxSa0->pxSaRekey = pxSa; /* !!! */
        }

        pxSa->flags |= IKE_SA_FLAG_MATURE;
        pxSa->oState = STATE_MAIN_I;

        pxSa->u.v2.dwWndLen[_I] = 1; /* or from window size notify */
        pxSa->u.v2.dwWndLen[_R] = 1/*IKE_WINDOW_SIZE*/;

        pxSa->dwTimeStamp = /* for DPD */
        pxSa->dwTimeCreated = RTOS_deltaMS(&gStartTime, NULL);
    }
    else /* CHILD_SA */
    {
        if (NULL == pxIPsecSa) /* jic */
        {
            status = ERR_NULL_POINTER;
            DBG_EXIT
        }

        DO_FUNC(DoKe2)

        pxIPsecSa->c_flags |= IKE_CHILD_FLAG_MATURE;
        pxIPsecSa->oState = STATE_QUICK_I;
    }

exit:
    if (pxSa) pxSa->merror = status;
    else if (pxIPsecSa) pxIPsecSa->merror = status;

    if ((OK > status) && (STATUS_IKE_PENDING != status))
    {
        IKE2_delXchg(pxXg, ctx->pxSa, status);
    }
    return status;
} /* childI_in */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOBIKE__

extern MSTATUS
IKE2_doUpdateSa(IKE_context ctx)
{
    MSTATUS status = OK;

    IKE2XG pxXg = ctx->pxXg;
    IKESA pxSa = ctx->pxSa;

    intBoolean bInitiator = IS_XCHG_INITIATOR(pxXg);

    struct ipsecKey key = { 0 };
    key.dwIkeSaId = pxSa->dwId0;

    if ((IKE_XCHG_FLAG_COOKIE2 & pxXg->x_flags) || /* initiator only */
        (!bInitiator && (IKE_XCHG_FLAG_UPDATE_SA & pxXg->x_flags)))
    {
        MOC_IP_ADDRESS peerAddr = REF_MOC_IPADDR(pxSa->dwPeerAddr);
        TEST_MOC_IPADDR6(peerAddr,
        {
            key.flags |= IPSEC_SA_FLAG_IP6;
            key.dwDestAddr = (CAST_MOC_IPADDR) GET_MOC_IPADDR6(peerAddr);
        })
        key.dwDestAddr = GET_MOC_IPADDR4(peerAddr);
    }
    else if (IKE_XCHG_FLAG_UPDATE_SA & pxXg->x_flags) /* must be initiator */
    {
        MOC_IP_ADDRESS hostAddr = REF_MOC_IPADDR(pxSa->dwHostAddr);
        TEST_MOC_IPADDR6(hostAddr,
        {
            key.flags |= IPSEC_SA_FLAG_IP6;
            key.dwSrcAddr = (CAST_MOC_IPADDR) GET_MOC_IPADDR6(hostAddr);
        })
        key.dwSrcAddr = GET_MOC_IPADDR4(hostAddr);
    }

#ifdef __ENABLE_IPSEC_NAT_T__
    if (IS_BEHIND_NAT(pxSa))
    {
        key.wUdpEncPort = pxSa->wPeerPort;
        if (IS_PEER_BEHIND_NAT(pxSa))
            key.flags |= IPSEC_SA_FLAG_NAT_PEER;
    }
#endif
    status = IPSEC_keyUpdate(&key);

    if (m_ikeSettings.funcPtrIkeStatHdlr)
        m_ikeSettings.funcPtrIkeStatHdlr(ISC_MOB, IST_SUCCESS,
                                         0, pxXg, pxSa);

    return status;
} /* IKE2_doUpdateSa */

#endif /* __ENABLE_MOBIKE__ */


/*------------------------------------------------------------------*/
/*
   INFORMATIONAL Exchange
   request             --> [N+],
                           [D+],
                           [CP(CFG_REQUEST)]
*/

/*------------------------------------------------------------------*/

static MSTATUS
infoI_out(IKE_context ctx)
{
    MSTATUS status;

    /* I --> */
    DO_FUNC(OutInfo)

#if defined(__ENABLE_MOBIKE__) && defined(__ENABLE_IPSEC_NAT_T__)
    if (IKE_CNTXT_FALG_NAT_D & ctx->flags)
    DO_FUNC(OutNatD)
#endif

#ifdef __ENABLE_IKE_CP__
/*  DO_FUNC(OutCp)*/
#endif

exit:
    return status;
} /* infoI_out */


/*------------------------------------------------------------------*/

static MSTATUS
infoR_in(IKE_context ctx)
{
    MSTATUS status = OK;

#ifdef __ENABLE_MOBIKE__
    IKE2XG pxXg = ctx->pxXg;
#endif
#if (defined(__ENABLE_MOBIKE__) && defined(__ENABLE_IPSEC_NAT_T__)) || \
    defined(__ENABLE_IKE_REDIRECT__)
    IKESA pxSa = ctx->pxSa;
#endif

    /* --> R */
    IN_SK   /* SK {...} */

    IN_LOOP_BEGIN
        IN_NEXT(    IKE_NEXT_N,     InNotify)
        IN_NEXT(    IKE_NEXT_D,     InDelete)
#ifdef __ENABLE_IKE_CP__
        IN_NEXT(    IKE_NEXT_CP,    InCp)
#endif
    IN_LOOP_NONE
    } /* paranthesis started with IN_LOOP_BEGIN */

#ifdef __ENABLE_IKE_CP__
    if (ctx->u.v2.poCp &&
        (IKE_CNTXT_FLAG_CP & ctx->flags) && /* jic */
        (NULL != m_ikeSettings.funcPtrIkeGetCfg))
    {
        DO_FUNC(DoCfgReq)
    }
#endif

#if defined(__ENABLE_MOBIKE__) && defined(__ENABLE_IPSEC_NAT_T__)
    if (IKE_XCHG_FLAG_UPDATE_SA & pxXg->x_flags)
    {
        if ((IKE_NATT_FLAG_D & pxSa->natt_flags) &&
            !(IKE_NATT_FLAG_NOT_ALLOWED & pxSa->natt_flags))
        {
            if (!(IKE_CNTXT_FALG_NAT_D_SRC & ctx->flags) ||
                !(IKE_CNTXT_FALG_NAT_D_DST & ctx->flags))
            {
                /* missing NAT_D Notify */
                status = ERR_IKE_BAD_NAT_D;
                DBG_EXIT
            }
        }
    }
#endif

#ifdef __ENABLE_IKE_REDIRECT__
    if (REDIRECTED_FROM == ctx->wMsgType)
    {
        if (OK > IKE_redirect(ctx))
        {
            DEBUG_PRINTNL(DEBUG_COMMON, (sbyte *)"ERROR: IKE_redirect failed.");
        }
        else
        {
            pxSa->flags |= IKE_SA_FLAG_REDIRECTED;
            pxSa->dwPeerAddr = ctx->oldPeerAddr;
            ctx->peerAddr = REF_MOC_IPADDR(pxSa->dwPeerAddr);
        }
    }
#endif

exit:
#ifdef __ENABLE_MOBIKE__
    pxXg->merror = status;
#endif
    return status;
} /* infoR_in */


/*------------------------------------------------------------------*/
/*
   INFORMATIONAL Exchange
   response            <-- [N+],
                           [D+],
                           [CP(CFG_REPLY)]
*/

/*------------------------------------------------------------------*/

static MSTATUS
infoR_out(IKE_context ctx)
{
    MSTATUS status;

    /* <-- R */
    DO_FUNC(OutInfo)

#if defined(__ENABLE_MOBIKE__) && defined(__ENABLE_IPSEC_NAT_T__)
    if (ctx->pxSa && /* !!! */
        (IKE_CNTXT_FALG_NAT_D & ctx->flags) &&
        ((16383 < ctx->wMsgType) || !ctx->wMsgType)) /* jic - error */
    DO_FUNC(OutNatD)
#endif

#ifdef __ENABLE_IKE_CP__
    DO_FUNC(OutCp)
#endif

exit:
    return status;
} /* infoR_out */


/*------------------------------------------------------------------*/

static MSTATUS
infoI_in(IKE_context ctx)
{
    MSTATUS status = OK;

    IKE2XG pxXg = ctx->pxXg;
    IKESA pxSa = ctx->pxSa;

#if defined(__ENABLE_MOBIKE__) && defined(__ENABLE_IPSEC_NAT_T__)
    ubyte old_natt_flags = pxSa->natt_flags;
#endif

    /* I <-- */
    IN_SK   /* SK {...} */

    IN_LOOP_BEGIN
        IN_NEXT(    IKE_NEXT_N,     InNotify)
        IN_NEXT(    IKE_NEXT_D,     InDelete)
/*      IN_NEXT(    IKE_NEXT_CP,    InCp)*/
    IN_LOOP_NONE
    } /* paranthesis started with IN_LOOP_BEGIN */

#ifdef __ENABLE_MOBIKE__
    if (IKE_XCHG_FLAG_UPDATE_SA & pxXg->x_flags)
    {
        if (ctx->wMsgType) /* Notify error received */
        {
            pxXg->wMsgType = ctx->wMsgType;
            status = ERR_IKE_NOTIFY_PAYLOAD;
            goto exit;
        }

#ifdef __ENABLE_IPSEC_NAT_T__
        if ((IKE_NATT_FLAG_D & pxSa->natt_flags) &&
            !(IKE_NATT_FLAG_NOT_ALLOWED & pxSa->natt_flags))
        {
            if (!(IKE_CNTXT_FALG_NAT_D_SRC & ctx->flags) ||
                !(IKE_CNTXT_FALG_NAT_D_DST & ctx->flags))
            {
                /* missing NAT_D Notify */
                status = ERR_IKE_BAD_NAT_D;
                DBG_EXIT
            }
        }
#endif
    }

    if (IKE_XCHG_FLAG_COOKIE2 & pxXg->x_flags)
    {
        if (!(IKE_CNTXT_FLAG_COOKIE2 & ctx->flags))
        {
            /* missing COOKIE2 Notify */
            status = ERR_IKE_BAD_COOKIE2;
            DBG_EXIT
        }

#ifdef IKE_SA_ADDR_HASH_TABLE_SIZE_MASK
        IKE_delSaAddrIndex(pxSa);
#endif
        COPY_MOC_IPADDR(pxSa->dwPeerAddr, ctx->peerAddr);
        pxSa->wPeerPort = ctx->wPeerPort;

#ifdef IKE_SA_ADDR_HASH_TABLE_SIZE_MASK
        IKE_addSaAddrIndex(pxSa);
#endif
    }

    if (((IKE_XCHG_FLAG_UPDATE_SA | IKE_XCHG_FLAG_COOKIE2) & pxXg->x_flags)
#ifdef __ENABLE_IPSEC_NAT_T__
     || ((old_natt_flags != pxSa->natt_flags) && !IS_HOST_BEHIND_NAT(pxSa))
#endif
        )
    {
        IKE2_doUpdateSa(ctx);
    }
#endif /* __ENABLE_MOBIKE__ */

exit:
#ifdef __ENABLE_MOBIKE__
    pxXg->merror = status;
#endif
    if (STATUS_IKE_PENDING != status)
    {
        IKE2_delXchg(pxXg, pxSa, status);
    }
    return status;
} /* infoI_in */


/*------------------------------------------------------------------*/

static IKE_stateInfo initI      = { initI_in,   initI_out };
static IKE_stateInfo authI      = { authI_in,   authI_out };
static IKE_stateInfo childI     = { childI_in,  childI_out };
static IKE_stateInfo infoI      = { infoI_in,   infoI_out };

static IKE_stateInfo initR      = { initR_in,   initR_out };
static IKE_stateInfo authR      = { authR_in,   authR_out };
static IKE_stateInfo childR     = { childR_in,  childR_out };
static IKE_stateInfo infoR      = { infoR_in,   infoR_out };

static IKE_stateInfo* mStates[4][2] =
{
    {&initI,    &initR},    /* IKE_SA_INIT */
    {&authI,    &authR},    /* IKE_AUTH */
    {&childI,   &childR},   /* CREATE_CHILD_SA */
    {&infoI,    &infoR},    /* INFORMATIONAL */
};


/*------------------------------------------------------------------*/

extern IKE_stateInfo*
IKE2_getStateInfo(ubyte oExchange, sbyte4 dir)
{
    if ((IKE_XCHG_INIT > oExchange) || (IKE_XCHG_INFO  < oExchange))
        return NULL;

    return mStates[oExchange - IKE_XCHG_INIT][dir];
} /* IKE2_getStateInfo */

#ifdef __ENABLE_DIGICERT_SP800_135_ACVP__
#include "../ike2/nist/ike2_nist.inc"
#endif

#else
static void
dummy(void)
{
    return;
}

#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */
