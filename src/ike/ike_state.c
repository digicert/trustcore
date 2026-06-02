/**
 * @file  ike_state.c
 * @brief IKE Developer API - Exchange State Machine
 *
 * @details    IKEv1 state machine implementation for exchange processing
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

#include "../crypto/mocasymkeys/mocsw/commonrsa.h"
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
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../asn1/ASN1TreeWalker.h"
#include "../asn1/derencoder.h"
#include "../crypto/dh.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/crypto.h"
#include "../crypto/hmac.h"
#include "../crypto/rsa.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../crypto/ca_mgmt.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/pkcs_common.h"
#include "../crypto/pkcs7.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
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
#include "../ipsec/script.h"
#ifdef __ENABLE_IKE_XAUTH__
#include "../ike/ike_xauth.h"
#endif


/*------------------------------------------------------------------*/
extern ubyte4 m_groupListCount;
extern sbyte m_configured_fqdnList[MAX_UNICAST_GROUP][MOC_MAX_FQDN_LEN];
#ifdef __ENABLE_IPSEC_MARGIN_LIFETIME__
extern ubyte4 g_IkeP2MarginLifeSecs;
#endif

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
extern fqdnUnicastGroupConfig m_fqdnGroupList[MAX_UNICAST_GROUP]; /* FQDN unicast group list */
#endif

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__

extern MSTATUS
gpullI1_out(IKE_context ctx);

extern MSTATUS
gpullI2_in(IKE_context ctx);

extern MSTATUS
gpullI2_out(IKE_context ctx);

extern MSTATUS
gpullI3_in(IKE_context ctx);

extern MSTATUS
gpushR1_in(IKE_context ctx);

#endif

#ifdef __ENABLE_DIGICERT_GDOI_SERVER__

extern MSTATUS
gpullR1_in(IKE_context ctx);

extern MSTATUS
gpullR1_out(IKE_context ctx);

extern MSTATUS
gpullR2_in(IKE_context ctx);

extern MSTATUS
gpullR2_out(IKE_context ctx);

extern MSTATUS
gpushI1_out(IKE_context ctx);

#endif

#ifdef __ENABLE_DIGICERT_PQC__
extern intBoolean isHybridAuthMtd(ubyte4 authMtdId);
#endif

/*------------------------------------------------------------------*/

MOC_EXTERN_DATA_DECL moctime_t gStartTime;

extern IKE_MUTEX g_ikeMtx;

extern ikeSettings m_ikeSettings;


/*------------------------------------------------------------------*/

#define _I 0
#define _R 1

#define _IN  1
#define _OUT 2

#define IKE_NONCE_MIN   (8)
#define IKE_NONCE_MAX   (256)


/*------------------------------------------------------------------*/

static ubyte vidDpd[] = /* see RFC3706 */
{
    0xAF, 0xCA, 0xD7, 0x13, 0x68, 0xA1, 0xF1, 0xC9,
    0x6B, 0x86, 0x96, 0xFC, 0x77, 0x57, 0x01, 0x00
};
#define vidDpdLen 16

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
static sbyte vidDpdDesc[] = "Dead Peer Detection 1.0";
#endif

#if defined(__ENABLE_DIGICERT_XAUTH_PERP__)
static ubyte vidPerp[] =
{
    0xB1, 0xAC, 0x79, 0x66, 0xB8, 0xFD, 0x69, 0xDE
};
#define vidPerpLen 8

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
static sbyte vidPerpDesc[] = "Mocana PERP 1.0";
#endif
#endif

#ifdef __ENABLE_IKE_XAUTH__
static ubyte vidXauth[] = /* draft-ietf-ipsec-isakmp-xauth-06.txt */
{
    0x09, 0x00, 0x26, 0x89, 0xDF, 0xD6, 0xB7, 0x12
};
#define vidXauthLen 8

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
static sbyte vidXauthDesc[] = "XAUTH";
#endif
#endif

#ifdef __ENABLE_IPSEC_NAT_T__

static ubyte vidNatT[] = /* RFC 3947 */
{
    0x4a, 0x13, 0x1c, 0x81, 0x07, 0x03, 0x58, 0x45,
    0x5c, 0x57, 0x28, 0xf2, 0x0e, 0x95, 0x45, 0x2f
};

static ubyte vidNatT48[] = /* Testing NAT-T RFC */
{
    0xc4, 0x0f, 0xee, 0x00, 0xd5, 0xd3, 0x9d, 0xdb,
    0x1f, 0xc7, 0x62, 0xe0, 0x9b, 0x7c, 0xfe, 0xa7
};

static ubyte vidNatT3[] = /* draft-ietf-ipsec-nat-t-ike-03 */
{
    0x7d, 0x94, 0x19, 0xa6, 0x53, 0x10, 0xca, 0x6f,
    0x2c, 0x17, 0x9d, 0x92, 0x15, 0x52, 0x9d, 0x56
};

static ubyte vidNatT2[] = /* draft-ietf-ipsec-nat-t-ike-02 */
{
    0xcd, 0x60, 0x46, 0x43, 0x35, 0xdf, 0x21, 0xf8,
    0x7c, 0xfd, 0xb2, 0xfc, 0x68, 0xb6, 0xa4, 0x48
};

static ubyte vidNatT2n[] = /* draft-ietf-ipsec-nat-t-ike-02\n */
{
    0x90, 0xcb, 0x80, 0x91, 0x3e, 0xbb, 0x69, 0x6e,
    0x08, 0x63, 0x81, 0xb5, 0xec, 0x42, 0x7b, 0x1f
};

static ubyte vidNatT0[] = /* draft-ietf-ipsec-nat-t-ike-00 */
{
    0x44, 0x85, 0x15, 0x2d, 0x18, 0xb6, 0xbb, 0xcd,
    0x0b, 0xe8, 0xa8, 0x46, 0x95, 0x79, 0xdd, 0xcc
};

typedef struct
{
#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
    sbyte  *pDesc;
#endif
    ubyte  *poVid;
    ubyte2  wVidLen;
    ubyte   oNatD;
    ubyte   oNatOa;
    ubyte2  wUdpTunnel;
    ubyte2  wUdpTransport;
} IKE_natTinfo;

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
#define VID_DESC(_d) (sbyte *)_d ,
#else
#define VID_DESC(_d)
#endif

static IKE_natTinfo mNatTinfo[] =
{
    {VID_DESC("RFC 3947")
        vidNatT,    16,
        ISAKMP_NEXT_NAT_D,                  ISAKMP_NEXT_NAT_OA,
        ENCAPSULATION_MODE_UDP_TUNNEL,      ENCAPSULATION_MODE_UDP_TRANSPORT},
    {VID_DESC("Testing NAT-T RFC")
        vidNatT48,  16,
        ISAKMP_NEXT_NAT_D_DRAFTS_48,        ISAKMP_NEXT_NAT_OA_DRAFTS_48,
        ENCAPSULATION_MODE_UDP_TUNNEL,      ENCAPSULATION_MODE_UDP_TRANSPORT},
    {VID_DESC("draft-ietf-ipsec-nat-t-ike-03")
        vidNatT3,   16,
        ISAKMP_NEXT_NAT_D_DRAFTS,           ISAKMP_NEXT_NAT_OA_DRAFTS,
        ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS,ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS},
    {VID_DESC("draft-ietf-ipsec-nat-t-ike-02")
        vidNatT2,   16,
        ISAKMP_NEXT_NAT_D_DRAFTS,           ISAKMP_NEXT_NAT_OA_DRAFTS,
        ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS,ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS},
    {VID_DESC("draft-ietf-ipsec-nat-t-ike-02\\n")
        vidNatT2n,  16,
        ISAKMP_NEXT_NAT_D_DRAFTS,           ISAKMP_NEXT_NAT_OA_DRAFTS,
        ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS,ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS},
    {VID_DESC("draft-ietf-ipsec-nat-t-ike-00")
        vidNatT0,   16,
        ISAKMP_NEXT_NAT_D_DRAFTS,           ISAKMP_NEXT_NAT_OA_DRAFTS,
        ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS,ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS}
};

#define NUM_VID_NAT_T (sizeof(mNatTinfo) / sizeof(IKE_natTinfo))

#endif /* __ENABLE_IPSEC_NAT_T__ */

#ifdef __ENABLE_IKE_FRAGMENTATION__

#define vidFragLen       20

static ubyte vidFrag[] =
{
    0x40, 0x48, 0xb7, 0xd5, 0x6e, 0xbc, 0xe8, 0x85,
    0x25, 0xe7, 0xde, 0x7f, 0x00, 0xd6, 0xc2, 0xd3,
    0x80, 0x00, 0x00, 0x00
};

static sbyte vidFragDesc[] = "IKE Fragmentation Support";

#endif /*__ENABLE_IKE_FRAGMENTATION__ */


/*------------------------------------------------------------------*/
/* phase 1 attributes */

typedef struct
{
    ubyte2  wType;
    MSTATUS merror;
} IKE_tfmAttrInfo;

static IKE_tfmAttrInfo mTfmAttr[] =
{
    {OAKLEY_AUTHENTICATION_METHOD,  ERR_IKE_MISMATCH_AUTH_METHOD    },

    {OAKLEY_GROUP_DESCRIPTION,      ERR_IKE_MISMATCH_DH_GROUP       },

    {OAKLEY_HASH_ALGORITHM,         ERR_IKE_MISMATCH_HASH_ALGO      },

    {OAKLEY_ENCRYPTION_ALGORITHM,   ERR_IKE_MISMATCH_ENCR_ALGO      },

    {OAKLEY_KEY_LENGTH,             ERR_IKE_MISMATCH_KEYLEN         }
};

#define NUM_TFM_ATTR ((sizeof(mTfmAttr) / sizeof(IKE_tfmAttrInfo)) - 1)


/*------------------------------------------------------------------*/
/* phase 2 attributes */

static ubyte2 mAttrMode[] =
{
    ENCAPSULATION_MODE_TRANSPORT,
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
    ENCAPSULATION_MODE_TUNNEL,
#endif
};

#define NUM_ATTR_MODE (sizeof(mAttrMode) / sizeof(ubyte2))


/*------------------------------------------------------------------*/

#define DBG_ERRCODE(_s) debug_print_status((sbyte *)__FILE__, __LINE__, (sbyte4)_s);
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

#define AUTH_MTD(_sa) (_sa)->u.v1.pwIsaAttr[OAKLEY_AUTHENTICATION_METHOD]

#ifdef __ENABLE_IKE_XAUTH__

static ubyte2 m_wAuthMtd;

#ifdef __ENABLE_IKE_HYBRID_RSA__

#define BASE_AUTH_MTD(_sa) \
    ((65000 < (m_wAuthMtd = AUTH_MTD(_sa))) \
     ? (ubyte2)((m_wAuthMtd - 64999) / 2) \
     : (((HYBRID_INIT_RSA == m_wAuthMtd) || (HYBRID_RESP_RSA == m_wAuthMtd)) \
        ? (ubyte2)OAKLEY_RSA_SIG : m_wAuthMtd))

#define PROP_HYBRID_AUTH(_sa) \
    ((_sa)->ikePeerConfig->bDoHybrid && (_sa)->ikePeerConfig->xauthType)

#define PROP_HYBRID_CLIENT(_sa) \
    ((_sa)->ikePeerConfig->bDoHybrid && (1 == (_sa)->ikePeerConfig->xauthType))

#define PROP_HYBRID_SERVER(_sa) \
    ((_sa)->ikePeerConfig->bDoHybrid && (2 == (_sa)->ikePeerConfig->xauthType))

#define IS_HYBRID_CLIENT(_sa) \
    (((HYBRID_INIT_RSA == AUTH_MTD(_sa)) && IS_INITIATOR(_sa)) || \
     ((HYBRID_RESP_RSA == AUTH_MTD(_sa)) && !IS_INITIATOR(_sa)))

#define IS_HYBRID_SERVER(_sa) \
    (((HYBRID_INIT_RSA == AUTH_MTD(_sa)) && !IS_INITIATOR(_sa)) || \
     ((HYBRID_RESP_RSA == AUTH_MTD(_sa)) && IS_INITIATOR(_sa)))

#else

#define BASE_AUTH_MTD(_sa) \
    ((65000 < (m_wAuthMtd = AUTH_MTD(_sa))) \
     ? (ubyte2)((m_wAuthMtd - 64999) / 2) : m_wAuthMtd)

#endif

#else

#define BASE_AUTH_MTD(_sa) AUTH_MTD(_sa)

#endif


/*------------------------------------------------------------------*/

#ifdef __ENABLE_IPSEC_NAT_T__
#define CSC_CB_NATT(_cb, _ctx) \
    (_cb)->wPeerPort = (_ctx)->wPeerPort;
#else
#define CSC_CB_NATT(_cb, _ctx)
#endif

#define CERT_STATUS_CHECK(_b, _sa, _c, _st) \
    if ((_b) && m_ikeSettings.funcPtrCertStatusCheck) \
    { \
        IKE_certStatusCB *cb; \
        CHECK_MALLOC_TYPE(IKE_certStatusCB, cb) \
\
        cb->dwSaId = (_sa)->dwId; \
        cb->saLoc = (_sa)->loc; \
        cb->pxSa = (_sa); \
        CSC_CB_NATT(cb, _c) \
\
        if (OK > ((_st) = (MSTATUS) m_ikeSettings.funcPtrCertStatusCheck( \
                                            (_c)->certificates, (_c)->certNum,\
                                            IKE_certStatusCallback, cb, \
                                            (_sa)->serverInstance, _sa))) \
        { \
            if (STATUS_IKE_PENDING == (_st)) goto exit; \
            IKE_certUnbind(_c); \
            FREE(cb); \
            DBG_EXIT \
        } \
        FREE(cb); \
    }


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC__
static intBoolean isHybridOakleyMtd(ubyte4 authMtdId)
{
    switch (authMtdId)
    {
        case OAKLEY_P256_MLDSA_44:
        case OAKLEY_P256_FNDSA512:
        case OAKLEY_P384_MLDSA_65:
        case OAKLEY_P521_FNDSA1024:
        case OAKLEY_P521_MLDSA_87:
            return TRUE;
    }

    return FALSE;
}
#endif

#ifdef __ENABLE_IPSEC_NAT_T__

static intBoolean
NeedNatOa(IKESA pxSa, IPSECSA pxIPsecSa, intBoolean bPeer)
{
    intBoolean bNatOaNeeded = FALSE;
    MOC_UNUSED(bPeer);
    if (IS_BEHIND_NAT(pxSa))
    {
        /* check proposals */
        sbyte4 i, j;
        for (i = pxIPsecSa->oP2SaNum - 1; i >= 0; i--)
        {
            for (j = pxIPsecSa->axP2Sa[i].oChildSaLen - 1; j >= 0; j--)
            {
                IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[i].axChildSa[j].ipsecPps);

                /* UDP-encap. transport mode */
                if (IKE_PROP_FLAG_UDP_ENCP & pxIPsecPps->p_flags)
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                if (ENCAPSULATION_MODE_TRANSPORT == pxIPsecPps->wMode)
#endif
                {
                    bNatOaNeeded = TRUE; /* NAT-OA's are needed */
                    goto exit;
                }
            }
        }
    }

exit:
    return bNatOaNeeded;
} /* NeedNatOa */


/*------------------------------------------------------------------*/

static MSTATUS
DoHashNatD(IKE_context ctx, ubyte *poHash, intBoolean bPeer)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    BulkHashAlgo *pBHAlgo = pxSa->pHashSuite->pBHAlgo;
    BulkCtx hashCtxt = NULL;

    MOC_IP_ADDRESS ipAddr;
    ubyte2 wPort;

    ubyte4 dwIpAddr;
    const ubyte *poIpAddr;
    sbyte4 lenIpAddr;

    /* get IP address and port */
    if (bPeer)
    {
        ipAddr = REF_MOC_IPADDR(pxSa->dwPeerAddr);
        wPort = pxSa->wPeerPort;
    }
    else
    {
        ipAddr = REF_MOC_IPADDR(pxSa->dwHostAddr);
        wPort = pxSa->wHostPort;
        /*wPort = USE_NATT_PORT(pxSa) ? IKE_NAT_UDP_PORT : IKE_DEFAULT_UDP_PORT;*/
    }

    /* calculate NAT-D hash value */
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

    if ((OK > (status = pBHAlgo->allocFunc(MOC_HASH(ctx->hwAccelCookie) &hashCtxt))) ||
        (OK > (status = pBHAlgo->initFunc(MOC_HASH(ctx->hwAccelCookie) hashCtxt))) ||
        (OK > (status = pBHAlgo->updateFunc(MOC_HASH(ctx->hwAccelCookie) hashCtxt, pxSa->poCky_I, IKE_COOKIE_SIZE))) ||
        (OK > (status = pBHAlgo->updateFunc(MOC_HASH(ctx->hwAccelCookie) hashCtxt, pxSa->poCky_R, IKE_COOKIE_SIZE))) ||
        (OK > (status = pBHAlgo->updateFunc(MOC_HASH(ctx->hwAccelCookie) hashCtxt, poIpAddr, lenIpAddr))) ||
        (OK > (status = pBHAlgo->updateFunc(MOC_HASH(ctx->hwAccelCookie) hashCtxt, (ubyte *)&wPort, sizeof(wPort)))) ||
        (OK > (status = pBHAlgo->finalFunc(MOC_HASH(ctx->hwAccelCookie) hashCtxt, poHash))))
        DBG_EXIT

exit:
    if (hashCtxt) pBHAlgo->freeFunc(MOC_HASH(ctx->hwAccelCookie) &hashCtxt);
    return status;
} /* DoHashNatD */

#endif /* __ENABLE_IPSEC_NAT_T__ */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)

static MSTATUS
DoHashPsk(IKE_context ctx, ubyte *poHash, const BulkHashAlgo *pBHAlgo)
{
    MSTATUS status;

    ubyte2 wDigestLen = (ubyte2) pBHAlgo->digestSize;
    HMAC_CTX *hmacCtxt = NULL;
    IKESA pxSa = ctx->pxSa;

    /* get PSK */
    ubyte4 dwKeyLen = 0;
    ubyte *poKey = NULL;
    if (OK > (status = IKE_getPsk(&poKey, &dwKeyLen, pxSa, 0)))
        DBG_EXIT

    /* calculate hash */
    if (OK > (status = HmacCreate(MOC_HASH(ctx->hwAccelCookie) &hmacCtxt, pBHAlgo)) ||
        OK > (status = HmacKey(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->u.v1.poKeyId, wDigestLen)) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poKey, (ubyte2)dwKeyLen)) ||
        OK > (status = HmacFinal(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poHash)))
        DBG_EXIT

exit:
#ifdef CUSTOM_IKE_GET_PSK
    if ((NULL != poKey) && (poKey != pxSa->ikePeerConfig->ikePSKey))
    {
        DIGI_MEMSET(poKey, 0x00, dwKeyLen); /* wipe out PSK from memory */
    }
#endif
    HmacDelete(MOC_HASH(ctx->hwAccelCookie) &hmacCtxt);
    return status;
} /* DoHashPsk */

#endif /* defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__) */


/*------------------------------------------------------------------*/

static MSTATUS
DoHash(IKE_context ctx, ubyte *poHash, intBoolean bIn, const BulkHashAlgo *pBHAlgo)
{
    MSTATUS status;

    IKESA pxSa = ctx->pxSa;
    intBoolean bInitiator = IS_INITIATOR(pxSa);
    intBoolean bHashI = ((bIn && !bInitiator) || (!bIn && bInitiator));

    struct ikeIdHdr *pxId = (bHashI ? pxSa->pxID[_I] : pxSa->pxID[_R]);
    ubyte *poIDi_b = (ubyte*)pxId + SIZEOF_IKE_GEN_HDR;
    ubyte2 wIDi_bLen = (pxId ? (GET_NTOHS(pxId->wLength) - SIZEOF_IKE_GEN_HDR) : 0);

    diffieHellmanContext *pDHctx = DIFFIEHELLMAN_CONTEXT(pxSa);

#ifdef __ENABLE_DIGICERT_ECC__
    sbyte4 stringLenF;
    ubyte* pStringMpintF = NULL;/* DH server public value */
#endif

    sbyte4 stringLenFToUse;
    ubyte* pStringMpintFToUse = NULL;/* DH server public value */

#ifdef __ENABLE_DIGICERT_ECC__
    sbyte4 stringLenE;
    ubyte* pStringMpintE = NULL;/* DH client public value */
#endif

    sbyte4 stringLenEToUse;
    ubyte* pStringMpintEToUse = NULL;/* DH client public value */

    ubyte2 wDigestLen = (ubyte2) pBHAlgo->digestSize;
    HMAC_CTX *hmacCtxt = NULL;

    MDhKeyTemplate keyTemplate = {0};
    ubyte *pBuffer = NULL;

    /* get DH value byte strings */
#ifdef __ENABLE_DIGICERT_ECC__
    ECCKey *pEccKey = pxSa->p_eccKey;
    if (NULL != pEccKey)
    {
        ECCKey *pEccKeyPeer = pxSa->p_eccKeyPeer;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAllocAux(MOC_ECC(ctx->hwAccelCookie) pEccKey, &pStringMpintF, (ubyte4 *)&stringLenF);
        if (OK != status)
            goto exit;
#else
        status = EC_writePublicKeyToBufferAlloc(MOC_ECC(ctx->hwAccelCookie) pEccKey, &pStringMpintF, (ubyte4 *)&stringLenF);
        if (OK != status)
            goto exit;
#endif

        /* Trim the leading 0x04 byte (which indicates compression status) */
        pStringMpintFToUse = pStringMpintF + 1;
        stringLenFToUse = stringLenF - 1;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAllocAux(MOC_ECC(ctx->hwAccelCookie) pEccKeyPeer, &pStringMpintE, (ubyte4 *)&stringLenE);
        if (OK != status)
            goto exit;
#else
        status = EC_writePublicKeyToBufferAlloc(MOC_ECC(ctx->hwAccelCookie) pEccKeyPeer, &pStringMpintE, (ubyte4 *)&stringLenE);
        if (OK != status)
            goto exit;
#endif

        /* Trim the leading 0x04 byte (which indicates compression status) */
        pStringMpintEToUse = pStringMpintE + 1;
        stringLenEToUse = stringLenE - 1;
    }
    else
#endif /* __ENABLE_DIGICERT_ECC__ */
    {
        pStringMpintEToUse = pxSa->pDhPeerPubKey;
        stringLenEToUse = pxSa->dhPeerPubKeyLen;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_DH_getKeyParametersAllocExt(MOC_DH(ctx->hwAccelCookie) &keyTemplate, pDHctx, MOC_GET_PRIVATE_KEY_DATA, NULL);
        if (OK != status)
            goto exit;
#else
        status = DH_getKeyParametersAlloc(MOC_DH(ctx->hwAccelCookie) &keyTemplate, pDHctx, MOC_GET_PRIVATE_KEY_DATA);
        if (OK != status)
            goto exit;
#endif

        /* RFC 2409, section 5:
         * The Diffie-Hellman public value passed in a KE payload, in either a
         * phase 1 or phase 2 exchange, MUST be the length of the negotiated
         * Diffie-Hellman group enforced, if necessary, by pre-pending the value
         * with zeros.
         */
        if (keyTemplate.fLen < keyTemplate.pLen)
        {
            status = DIGI_MALLOC((void **)&pBuffer, keyTemplate.pLen);
            if (OK != status)
            {
                goto exit;
            }

            DIGI_MEMSET(pBuffer, 0, keyTemplate.pLen - keyTemplate.fLen);
            DIGI_MEMCPY(pBuffer + keyTemplate.pLen - keyTemplate.fLen,
                    keyTemplate.pF, keyTemplate.fLen);

            pStringMpintFToUse = pBuffer;
            stringLenFToUse = keyTemplate.pLen;
        }
        else
        {
            pStringMpintFToUse = keyTemplate.pF;
            stringLenFToUse = keyTemplate.fLen;
        }
    }

    /* calculate HASH_I/R */
    if (OK > (status = HmacCreate(MOC_HASH(ctx->hwAccelCookie) &hmacCtxt, pBHAlgo)) ||
        OK > (status = HmacKey(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->u.v1.poKeyId, wDigestLen)) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie)
                                  hmacCtxt, (bIn ? pStringMpintEToUse : pStringMpintFToUse),
                                            (bIn ? stringLenEToUse : stringLenFToUse))) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie)
                                  hmacCtxt, (bIn ? pStringMpintFToUse: pStringMpintEToUse),
                                            (bIn ? stringLenFToUse: stringLenEToUse))) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie)
                                  hmacCtxt, (bHashI ? pxSa->poCky_I : pxSa->poCky_R), IKE_COOKIE_SIZE)) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie)
                                  hmacCtxt, (bHashI ? pxSa->poCky_R : pxSa->poCky_I), IKE_COOKIE_SIZE)) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie)
                                  hmacCtxt, pxSa->poMsg[_I], pxSa->dwMsgLen[_I])) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poIDi_b, wIDi_bLen)) ||
        OK > (status = HmacFinal(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poHash)))
        DBG_EXIT

exit:

#ifdef __ENABLE_DIGICERT_ECC__
    CHECK_FREE(pStringMpintF)
    CHECK_FREE(pStringMpintE)
#endif

    HmacDelete(MOC_HASH(ctx->hwAccelCookie) &hmacCtxt);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DH_freeKeyTemplateExt(pDHctx, &keyTemplate, NULL);
#else
    DH_freeKeyTemplate(pDHctx, &keyTemplate);
#endif

    DIGI_FREE((void **)&pBuffer);
    return status;
} /* DoHash */


/*------------------------------------------------------------------*/

static MSTATUS
DoHash12(IKE_context ctx, ubyte4 dwLength, ubyte *poBuf, ubyte *poHash)
{
    MSTATUS status;

    IKESA pxSa = ctx->pxSa;
    P2XG pxXg = ctx->pxP2Xg;
    IPSECSA pxIPsecSa = ((NULL != pxXg) && IS_QUICK_MODE_STATE(pxXg->oState))
                      ? P2XG_IPSECSA(pxXg) : NULL;

    struct ikeHdr *pxHdr = (struct ikeHdr *) ctx->pHdrParent;
    ubyte *poMsgId = (ubyte *) &(pxHdr->dwMsgId);

    intBoolean bHash2 = ((ISAKMP_XCHG_QUICK == pxHdr->oExchange) &&
                       /* ISAKMP_XCHG_GPULL has the same value! */
                         pxIPsecSa && pxIPsecSa->wNi_bLen &&
                         ((STATE_QUICK_R1 == pxIPsecSa->oState) ||
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
                          (STATE_GPULL_R1 == pxIPsecSa->oState) ||
#endif
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
                          (STATE_GPULL_I2 == pxIPsecSa->oState) ||
#endif
                          (STATE_QUICK_I2 == pxIPsecSa->oState)));

    const BulkHashAlgo *pBHAlgo = pxSa->pHashSuite->pBHAlgo;
    ubyte2 wDigestLen = (ubyte2) pBHAlgo->digestSize;
    HMAC_CTX *hmacCtxt;

    /* calculate HASH(1/2) */
    if ((OK > (status = HmacCreate(MOC_HASH(ctx->hwAccelCookie) &hmacCtxt, pBHAlgo))) ||
        (OK > (status = HmacKey(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->u.v1.poKeyId_a, wDigestLen))) ||
        (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poMsgId, sizeof(ubyte4)))))
        DBG_EXIT

    if (bHash2 && /* HASH(2) only */
        (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxIPsecSa->poNi_b, pxIPsecSa->wNi_bLen))))
        DBG_EXIT

    if ((OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poBuf, dwLength))) ||
        (OK > (status = HmacFinal(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poHash)))) /* HASH(1/2) data */
        DBG_EXIT

exit:
    HmacDelete(MOC_HASH(ctx->hwAccelCookie) &hmacCtxt);
    return status;
} /* DoHash12 */


/*------------------------------------------------------------------*/

static MSTATUS
DoHash3(IKE_context ctx, ubyte* poHash)
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
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, (ubyte *) "\0", 1)) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poMsgId, sizeof(ubyte4))) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxIPsecSa->poNi_b, pxIPsecSa->wNi_bLen)) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxIPsecSa->poNr_b, pxIPsecSa->wNr_bLen)) ||
        OK > (status = HmacFinal(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poHash)))
        DBG_EXIT

exit:
    HmacDelete(MOC_HASH(ctx->hwAccelCookie) &hmacCtxt);
    return status;
} /* DoHash3 */


/*------------------------------------------------------------------*/

#define SET_MSGTYPE(_m) if (!bInitiator) ctx->wMsgType = (_m);
#define SET_MERROR(_e)  if (bInitiator) status = (_e); else pxSa->merror = (_e);
#define SET_MERROR2(_e) if (bInitiator) status = (_e); else pxIPsecSa->merror = (_e);


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


#define OUT_TOP_0(_type, _hdr, _size) \
    OUT_HDR(_type, _hdr, _size)\
    SET_HTONS((_hdr)->wLength, _size);\


#define OUT_TOP(_type, _hdr, _size, _np) \
    OUT_TOP_0(_type, _hdr, _size) \
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


/*------------------------------------------------------------------*/

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


#define IN_SKIP(_nextPl) \
        if (_oNp == (_nextPl))\
        {\
            IN_BEGIN(struct ikeGenHdr, pxGenHdr, SIZEOF_IKE_GEN_HDR) \
            IN_END \
        }\
        else \


#define IN_LAST(_nextPl, _inFunc) \
        if (_oNp == (_nextPl))\
        {\
            DO_FUNC(_inFunc)\
            FINALLY_PAYLOAD \
            break;\
        }\
        else\


#define IN_LOOP_END \
        {\
            FINALLY_PAYLOAD\
            break;\
        }\
        FINALLY_PAYLOAD \
    }\


#define IN_LOOP_NONE \
        if (ISAKMP_NEXT_NONE == _oNp)\
        {\
            FINALLY_PAYLOAD \
            break;\
        }\
        else\
        {\
            IN_BEGIN(struct ikeGenHdr, pxGenHdr, SIZEOF_IKE_GEN_HDR) \
            IN_END \
        }

#define IN_LOOP_NONE_END \
        FINALLY_PAYLOAD \
    }

/*------------------------------------------------------------------*/

extern MSTATUS
OutAttrB(IKE_context ctx, ubyte2 type, ubyte2 value)
{
    MSTATUS status = OK;

    struct ikeAttr0 *pxAttr0;

    OUT_HDR(struct ikeAttr, pxAttr, SIZEOF_IKE_ATTR)

    SET_HTONS(pxAttr->wAFtype, type);
    SET_HTONS(pxAttr->wLenVal, value);

    pxAttr0 = (struct ikeAttr0 *) pxAttr;
    pxAttr0->oAF |= 0x80;

exit:
    return status;
} /* OutAttrB */


/*------------------------------------------------------------------*/

extern MSTATUS
OutAttrV(IKE_context ctx, ubyte2 type, ubyte2 len, void *value)
{
    MSTATUS status = OK;

    OUT_HDR(struct ikeAttr, pxAttr, SIZEOF_IKE_ATTR)

    SET_HTONS(pxAttr->wAFtype, type);
    SET_HTONS(pxAttr->wLenVal, len);

    if (ctx->dwBufferSize < len)
    {
        status = ERR_IKE_BUFFER_OVERFLOW;
        DBG_EXIT
    }

    DIGI_MEMCPY(ctx->pBuffer, value, len);

    ADVANCE(len)

exit:
    return status;
} /* OutAttrV */


/*------------------------------------------------------------------*/

static MSTATUS
OutAttrLife(IKE_context ctx, ubyte2 wLife, ubyte2 wType, ubyte2 wDuration, ubyte4 dwValue)
{
    MSTATUS status;

    if (OK != (status = OutAttrB(ctx, wLife, wType)))
        goto exit;

    if (dwValue <= (ubyte4)0xffff)
    {
        if (OK != (status = OutAttrB(ctx, wDuration, (ubyte2)dwValue)))
            goto exit;
    }
    else
    {
        SET_HTONL_1(dwValue);
        if (OK != (status = OutAttrV(ctx, wDuration, sizeof(ubyte4), &dwValue)))
            goto exit;
    }

exit:
    return status;
} /* OutAttrLife */


/*------------------------------------------------------------------*/

static MSTATUS
OutTfm(IKE_context ctx, sbyte4 index, ubyte2 pwAttrVal[], ubyte4 proposalNum)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    sbyte4 i;

    if ((sbyte4) NUM_TFM_ATTR > index)
    {
        /* we must be initiator!!! */
        ubyte2 wType = mTfmAttr[index].wType;
        ubyte4 authMethod = 0;

        pwAttrVal[index] = 0;

        for (i=0; ; i++)
        {
            ubyte2 wValue;

            /* traverse all supported attr. values */
            switch (wType)
            {
            case OAKLEY_AUTHENTICATION_METHOD :
            {
                if (1 == authMethod)
                    goto done;

                /* check valid authentication method */
                IKE_authMtdInfo *pAuthMtd = IKE_getAuthMtdEx(pxSa->ikePeerConfig, i);
                if (NULL == pAuthMtd) goto done;

                wValue = pAuthMtd->wAuthMtd;

#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)
                if (PROP_HYBRID_AUTH(pxSa))
                {
                    if (OAKLEY_RSA_SIG != wValue)
                        continue; /* rsa-sig only, if hybrid auth is proposed */
                }
#endif
#ifdef __ENABLE_DIGICERT_PQC__
                if(TRUE == isHybridOakleyMtd(wValue))
                {
                    if (!pAuthMtd->bEnabled[_I])
                        continue;
                    if (OK > IKE_useCert(ctx, wValue))
                        continue; /* no valid host certificate */
                }
                else
#endif
                {
                switch (wValue)
                {
                case OAKLEY_RSA_SIG :
#ifdef __ENABLE_DIGICERT_ECC__
                case OAKLEY_ECDSA_SIG :
                case OAKLEY_ECDSA_256 :
                case OAKLEY_ECDSA_384 :
                case OAKLEY_ECDSA_521 :
#endif
#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)
                    /* hybrid client doesn't need host certificate */
                    if (!PROP_HYBRID_CLIENT(pxSa))
#endif
                    if (OK > IKE_useCert(ctx, wValue))
                        continue; /* no valid host certificate */
                    break;

#ifdef CUSTOM_IKE_GET_PSK
                case OAKLEY_PRESHARED_KEY :
                    if (OK > IKE_getPsk(NULL, NULL, pxSa, 0))
                        continue; /* no pre-shared key found */
                    break;
#endif
                default :
                    if (!pAuthMtd->bEnabled[_I]) continue;
                    break;
                }
                }
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
                if (STATE_AGGR_I1 == pxSa->oState)
                {
                    if((sizeof(ubyte2)*2 - 2) >= wValue)
                    {
                        /* remember proposed auth mothods briefly */
                        AUTH_MTD(pxSa) |= (ubyte2)(1 << wValue); /* for OutCR_aggrI1 & OutId */
                    }
                    else
                    {
                        AUTH_MTD(pxSa) = wValue;
                    }
                }
#endif
#ifdef __ENABLE_IKE_XAUTH__
                /* XAUTHInit means:
                   Whoever initiates IKE_SA needs to be authenticated via XAUTH
                   (whose exchange will be initiated by the IKE_SA responder).
                   XAUTHResp is the opposite.
                 */
                /* Note: we are the IKE_SA initiator here!!! */
#ifdef __ENABLE_IKE_HYBRID_RSA__
                if (PROP_HYBRID_CLIENT(pxSa))
                    wValue = HYBRID_INIT_RSA; /* hybrid rsa XAUTHInit */
                else if (PROP_HYBRID_SERVER(pxSa))
                    wValue = HYBRID_RESP_RSA; /* hybrid rsa XAUTHResp */
                else
#endif
                if (4 <= pxSa->ikePeerConfig->xauthDraft) /* !!! */
                switch (pxSa->ikePeerConfig->xauthType)
                {
                case 1 : /* client (to be authenticated) */
                    wValue = (ubyte2)((2 * wValue) + 64999); /* XAUTHInit */
                    break;
                case 2 : /* server (to initiate authentication) */
                    wValue = (ubyte2)((2 * wValue) + 65000); /* XAUTHResp */
                    break;
                default :
                    break;
                }
#endif
                authMethod++;
                break;
            }

            case OAKLEY_GROUP_DESCRIPTION :
                wValue = pxSa->u.v1.pwIsaAttr[OAKLEY_GROUP_DESCRIPTION];
                if ((0 != wValue) /* already set */
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
                    /* DH group is not negotiable for aggresive mode */
                 || (STATE_AGGR_I1 == pxSa->oState)
#endif
                    )
                {
                    if (i) goto done; /* only propose 1 DH group */
                    break;
                }
#ifdef CUSTOM_IKE_GET_P1_DHGRP
                if (0 < pxSa->numDhGrps)
                {
                    if (i >= pxSa->numDhGrps) goto done;
                    wValue = pxSa->pwDhGrps[i];
                }
                else
#endif
                {
                    IKE_dhGroupInfo *pGroup = IKE_getKeyExchangeGroup(pxSa->ikePeerConfig, i, proposalNum);
                    if (NULL == pGroup) goto done;

                    if (pGroup->bDisabled[0][_I] ||
                        (0 == (wValue = pGroup->wTfmId)))
                        continue;
                }
                break;

            case OAKLEY_HASH_ALGORITHM :
#ifdef CUSTOM_IKE_GET_HASH_ALGO
                if (0 < pxSa->numHashAlgos)
                {
                    if (i >= pxSa->numHashAlgos) goto done;
                    wValue = pxSa->pwHashAlgos[i];
                }
                else
#endif
                {
                    IKE_hashSuiteInfo *pHashSuite = IKE_getHashSuiteEx(pxSa->ikePeerConfig, i);
                    if (NULL == pHashSuite) goto done;

                    if (pHashSuite->bDisabled[0][_I] ||
                        (NULL == pHashSuite->pBHAlgo)) /* !!! jic PRF_AES128_XCBC */
                        continue;

                    wValue = pHashSuite->wHashAlgo;
                }
                break;

            case OAKLEY_ENCRYPTION_ALGORITHM :
            {
                IKE_cipherSuiteInfo *pCipherSuite;
                ubyte2 wKeyLen;

#ifdef CUSTOM_IKE_GET_ENCR_ALGO
                if (0 < pxSa->numEncrAlgos)
                {
                    if (i >= pxSa->numEncrAlgos) goto done;

                    wValue = pxSa->pwEncrAlgos[i];
                    wKeyLen = pxSa->pwEncrKeyLens[i];
                    pCipherSuite = IKE_cipherSuiteEx(pxSa->ikePeerConfig, wValue, 0, wKeyLen, NULL);
                }
                else
#endif
                {
                    pCipherSuite = IKE_getCipherSuiteEx(pxSa->ikePeerConfig, i);
                    if (NULL == pCipherSuite) goto done;

                    if (pCipherSuite->bDisabled[0][_I]) continue;

                    wKeyLen = pCipherSuite->wKeyLenEnd;
                    wValue = pCipherSuite->wEncrAlgo;
                }

                if (pCipherSuite->bFixedKeyLen)
                    pwAttrVal[NUM_TFM_ATTR] = 0; /* !!! */
                else
                    pwAttrVal[NUM_TFM_ATTR] = (ubyte2)(wKeyLen * 8);
                break;
            }
            default : /* should not get here */
                goto done;
                /*break;*/
            }

            /* make recursive call */
            pwAttrVal[index] = wValue;
            if (OK != (status = OutTfm(ctx, index+1, pwAttrVal, proposalNum)))
                goto exit;

        } /* for */

done:
        if (0 == pwAttrVal[index]) /* if no attr. value is selected */
        {
            status = mTfmAttr[index].merror;
            DBG_EXIT
        }
    }
    else
    {
        intBoolean bInitiator = IS_INITIATOR(pxSa);
        struct ikePpsHdr *pxPpsHdr = (struct ikePpsHdr *) ctx->pHdrParent;

        ubyte4 dwLength;
        ubyte *poNextPayload;
        void *pHdrParent;

        ubyte4 dwValue;
        ubyte2 wKeyLen;

        /* transform payload header */
        OUT_TOP(struct ikeTfmHdr, pxTfmHdr, SIZEOF_IKE_TFM_HDR, ISAKMP_NEXT_T)

        ++(pxPpsHdr->oTfmLen);
        pxTfmHdr->oNum = (ubyte)(bInitiator ? pxPpsHdr->oTfmLen : pxSa->oTfmNo);
        pxTfmHdr->oAttrId = KEY_IKE;

        /* sa attributes */
        OUT_DOWN(pxTfmHdr)

        for (i=0; i < (sbyte4) NUM_TFM_ATTR; i++)
        {
            if (OK != (status = OutAttrB(ctx, mTfmAttr[i].wType, pwAttrVal[i])))
                goto exit;
        }

        /* ISAKMP SA life type/duration - secs */
        if ((0 != (dwValue = pxSa->dwExpSecs)) &&
            (OK != (status = OutAttrLife(ctx, OAKLEY_LIFE_TYPE, OAKLEY_LIFE_SECONDS, OAKLEY_LIFE_DURATION, dwValue))))
            goto exit;

        /* ISAKMP SA life type/duration - kbytes */
        if ((0 != (dwValue = pxSa->dwExpKBytes)) &&
            (OK != (status = OutAttrLife(ctx, OAKLEY_LIFE_TYPE, OAKLEY_LIFE_KILOBYTES, OAKLEY_LIFE_DURATION, dwValue))))
            goto exit;

        /* KEY_LENGTH */
        wKeyLen = pwAttrVal[NUM_TFM_ATTR];
        if (wKeyLen &&
            (OK != (status = OutAttrB(ctx, OAKLEY_KEY_LENGTH, wKeyLen))))
            goto exit;

#ifdef CUSTOM_IKE_GET_TFM_ATTRS
        if (bInitiator)
        {
            ubyte2 wAttrsExLen = (ubyte2) ctx->dwBufferSize;
            if (OK > (status = CUSTOM_IKE_GET_TFM_ATTRS(
                            ctx->pBuffer, &wAttrsExLen,
                            ctx->pBuffer - ctx->dwLength,
                            (ubyte2) ctx->dwLength,
                            PROTO_ISAKMP, KEY_IKE,
                            REF_MOC_IPADDR(pxSa->dwPeerAddr),
                            0, TRUE
                            MOC_MTHM_REQ_VALUE(pxSa->serverInstance))))
            {
                if (STATUS_IKE_CUSTOM_CONTINUE != status)
                    DBG_EXIT
                status = OK;
            }
            else if (0 != wAttrsExLen)
            {
                if (wAttrsExLen > ctx->dwBufferSize)
                {
                    status = ERR_IKE_BUFFER_OVERFLOW;
                    DBG_EXIT
                }
                ADVANCE(wAttrsExLen)
            }
        }
#endif

        /* done */
        OUT_UP(pxTfmHdr)
    }

exit:
    return status;
} /* OutTfm */


/*------------------------------------------------------------------*/

extern MSTATUS
OutAhEspAttrs(IKE_context ctx, IPSECPPS pxIPsecPps,
              ubyte2 wAuthAlgo, ubyte2 wKeyLen)
{
    MSTATUS status = OK;

    ubyte4 dwValue;

    /* authentication */
    if (wAuthAlgo &&
        (OK != (status = OutAttrB(ctx, AUTH_ALGORITHM, wAuthAlgo))))
    {
        goto exit;
    }

    /* encr. key length */
    if (wKeyLen &&
        (OK != (status = OutAttrB(ctx, KEY_LENGTH, (ubyte2)(8 * wKeyLen)))))
    {
        goto exit;
    }

    /* IPsec SA life type/duration - secs */
    if ((0 != (dwValue = pxIPsecPps->dwExpSecs)) &&
        (OK != (status = OutAttrLife(ctx, SA_LIFE_TYPE, SA_LIFE_TYPE_SECONDS,
                                     SA_LIFE_DURATION, dwValue))))
    {
        goto exit;
    }

    /* IPsec SA life type/duration - kbytes */
    if ((0 != (dwValue = pxIPsecPps->dwExpKBytes)) &&
        (OK != (status = OutAttrLife(ctx, SA_LIFE_TYPE, SA_LIFE_TYPE_KBYTES,
                                     SA_LIFE_DURATION, dwValue))))
    {
        goto exit;
    }

exit:
    return status;
} /* OutAhEspAttrs */


/*------------------------------------------------------------------*/

static MSTATUS
OutTfmAhEsp(IKE_context ctx, ubyte oTfmId, ubyte2 wAuthAlgo, ubyte2 wKeyLen
#if defined(__ENABLE_IPSEC_ESN__) || defined(__ENABLE_DIGICERT_PFKEY__)
          , intBoolean bEsn
#endif
            )
{
    MSTATUS status = OK;

    struct ikePpsHdr *pxPpsHdr = (struct ikePpsHdr *) ctx->pHdrParent;
    IPSECSA pxIPsecSa = P2XG_IPSECSA(ctx->pxP2Xg);
    IPSECPPS pxIPsecPps = ctx->pxIPsecPps;

#if !defined(__ENABLE_DIGICERT_PFKEY__) || defined(CUSTOM_IKE_GET_TFM_ATTRS)
    intBoolean bInitiator = IS_CHILD_INITIATOR(pxIPsecSa);
#endif
    ubyte4 dwLength;
    ubyte *poNextPayload;
    void *pHdrParent;

    /* transform payload header */
    OUT_TOP(struct ikeTfmHdr, pxTfmHdr, SIZEOF_IKE_TFM_HDR, ISAKMP_NEXT_T)

    ++(pxPpsHdr->oTfmLen);

#ifndef __ENABLE_DIGICERT_PFKEY__
    if (bInitiator)
        pxTfmHdr->oNum = pxPpsHdr->oTfmLen;
    else
#endif
        pxTfmHdr->oNum = pxIPsecPps->oTfmNo;

    pxTfmHdr->oAttrId = oTfmId;

    /* data attributes */
    OUT_DOWN(pxTfmHdr)

    if (OK > (status = OutAhEspAttrs(ctx, pxIPsecPps, wAuthAlgo, wKeyLen)))
    {
        goto exit;
    }

    /* PFS */
    if (pxIPsecSa->wPFS &&
        (OK != (status = OutAttrB(ctx, GROUP_DESCRIPTION, pxIPsecSa->wPFS))))
    {
        goto exit;
    }

    /* mode */
    if (pxIPsecPps->wMode)
    {
        ubyte2 wMode = pxIPsecPps->wMode;

#ifdef __ENABLE_IPSEC_NAT_T__
        /* get UDP-encap. mode attribute value */
        if (IKE_PROP_FLAG_UDP_ENCP & pxIPsecPps->p_flags)
        {
            /* Note: 'index out of range' already checked in either InAttrs2() or OutPps() */
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
            if ((ubyte2)ENCAPSULATION_MODE_TUNNEL == wMode)
                wMode = mNatTinfo[ctx->pxSa->u.v1.iNatT - 1].wUdpTunnel;
            else
#endif
                wMode = mNatTinfo[ctx->pxSa->u.v1.iNatT - 1].wUdpTransport;
        }
#endif
        if (OK != (status = OutAttrB(ctx, ENCAPSULATION_MODE, wMode)))
            goto exit;
    }

#if defined(__ENABLE_IPSEC_ESN__) || defined(__ENABLE_DIGICERT_PFKEY__)
    if (bEsn && (OK != (status = OutAttrB(ctx, EXT_SEQ_NO, 1))))
    {
        goto exit;
    }
#endif

#ifdef USE_MOC_COOKIE
    /* cookie */
    {
        ubyte4 cookie = pxIPsecSa->axP2Sa[ctx->oP2SaIndex].cookie;
        if (cookie &&
            (!bInitiator || (cookie != ctx->pxSa->cookie)))
        {
            if (cookie <= (ubyte4)0xffff)
            {
                if (OK != (status = OutAttrB(ctx, IPSEC_COOKIE_TYPE, (ubyte2)cookie)))
                    goto exit;
            }
            else
            {
                SET_HTONL_1(cookie);
                if (OK != (status = OutAttrV(ctx, IPSEC_COOKIE_TYPE, sizeof(cookie), &cookie)))
                    goto exit;
            }
        }
    }
#endif

#ifdef CUSTOM_IKE_GET_TFM_ATTRS
    if (bInitiator)
    {
        ubyte2 wAttrsExLen = (ubyte2) ctx->dwBufferSize;
        if (OK > (status = CUSTOM_IKE_GET_TFM_ATTRS(
                        ctx->pBuffer, &wAttrsExLen,
                        ctx->pBuffer - ctx->dwLength,
                        (ubyte2) ctx->dwLength,
                        pxIPsecPps->oProtocol, oTfmId,
                        REF_MOC_IPADDR(ctx->pxSa->dwPeerAddr),
                        0, TRUE
                        MOC_MTHM_REQ_VALUE(ctx->pxSa->serverInstance))))
        {
            if (STATUS_IKE_CUSTOM_CONTINUE != status)
                DBG_EXIT
            status = OK;
        }
        else if (0 != wAttrsExLen)
        {
            if (wAttrsExLen > ctx->dwBufferSize)
            {
                status = ERR_IKE_BUFFER_OVERFLOW;
                DBG_EXIT
            }
            ADVANCE(wAttrsExLen)
        }
    }
#endif

    /* done */
    OUT_UP(pxTfmHdr)

exit:
    return status;
} /* OutTfmAhEsp */


/*------------------------------------------------------------------*/

static MSTATUS
OutTfm2(IKE_context ctx)
{
    MSTATUS status = OK;

    IPSECPPS pxIPsecPps = ctx->pxIPsecPps;
    IPSECSA pxIPsecSa = P2XG_IPSECSA(ctx->pxP2Xg);
    intBoolean bInitiator = IS_CHILD_INITIATOR(pxIPsecSa);

    ubyte oTfmId = pxIPsecPps->oTfmId;
    ubyte2 wAuthAlgo = pxIPsecPps->wAuthAlgo;
    ubyte2 wKeyLen = pxIPsecPps->wEncrKeyLen;
    ubyte2 bitStrength = 0;
#ifndef __DISABLE_DIGICERT_CONSTRAINT_CIPHER__
    bitStrength = CHILDSA_cipherEffectiveBitStrength(ctx->pxSa->pCipherSuite->wTfmId, ctx->pxSa->wEncrKeyLen);
#endif

    if (!bInitiator) /* responder */
    {
        if (OK != (status = OutTfmAhEsp(ctx, oTfmId, wAuthAlgo, wKeyLen
#if defined(__ENABLE_IPSEC_ESN__) || defined(__ENABLE_DIGICERT_PFKEY__)
                                      , (IKE_PROP_FLAG_ESN & pxIPsecPps->p_flags)
#endif
                                        )))
            goto exit;
    }
    else /* initiator */
#ifdef __ENABLE_DIGICERT_PFKEY__
    {
        ubyte oSaIndex = ctx->oP2SaIndex;
        ubyte oPpsIndex = ctx->oPpsIndex;

        ubyte oTfmNum = pxIPsecSa->axP2Sa[oSaIndex].axChildSa[oPpsIndex].oIPsecPpsNum;
        IPSECPPS pxExIPsecPps = pxIPsecSa->axP2Sa[oSaIndex].axChildSa[oPpsIndex].pxIPsecPps;

        sbyte4 n = 0;
        for (;;)
        {
            if ((PROTO_IPSEC_ESP == pxIPsecPps->oProtocol) &&
                (ESP_NULL != oTfmId))
            {
                CHILDSA_encrInfo *pEncrAlgo = CHILDSA_findEncrAlgoWithConstraint(bitStrength, oTfmId, 0, 0, wKeyLen, NULL);
                if (NULL == pEncrAlgo) /* jic */
                    goto next;

                if (pEncrAlgo->bFixedKeyLen) wKeyLen = 0;
            }

            if (OK != (status = OutTfmAhEsp(ctx, oTfmId, wAuthAlgo, wKeyLen,
                                    (IKE_PROP_FLAG_ESN & pxIPsecPps->p_flags))))
                goto exit;
next:
            if (NULL == pxExIPsecPps) break; /* jic */

            pxIPsecPps = pxExIPsecPps + (n++);
            if (n >= (sbyte4)oTfmNum) break;

            oTfmId = pxIPsecPps->oTfmId;
            wAuthAlgo = pxIPsecPps->wAuthAlgo;
            wKeyLen = pxIPsecPps->wEncrKeyLen;

            ctx->pxIPsecPps = pxIPsecPps;
        }
    }
#else
    {
        sbyte4 i, j;
        intBoolean bEnumEncr = ((oTfmId && wKeyLen) || (ESP_NULL == oTfmId) ||
                                (PROTO_IPSEC_AH == pxIPsecPps->oProtocol))
                             ? FALSE : TRUE;
        intBoolean bEnumAuth = (wAuthAlgo || (IPSEC_PROTO_ESP == pxIPsecPps->oSecuProto))
                             ? FALSE : TRUE;
        for (i=0; ; i++)
        {
            ubyte oTfmId0 = oTfmId;
            ubyte2 wKeyLen1 = wKeyLen;

            if (bEnumEncr)
            {
                CHILDSA_encrInfo *pEncrAlgo = CHILDSA_getEncrAlgo(i);
                if (NULL == pEncrAlgo)
                    break;

                if (oTfmId)
                {
                    if (oTfmId != pEncrAlgo->oTfmId)
                        continue;
                }
                else oTfmId0 = pEncrAlgo->oTfmId;

                /* check encr key-length */
                if (wKeyLen)
                {
                    if ((wKeyLen < pEncrAlgo->wKeyLen) ||
                        (pEncrAlgo->wKeyLenEnd && (wKeyLen > pEncrAlgo->wKeyLenEnd)))
                        continue;

                    if (pEncrAlgo->bFixedKeyLen) wKeyLen1 = 0;
                }
                else
                {
                    if (!pEncrAlgo->bFixedKeyLen)
                    {
                        if (0 == (wKeyLen1 = pEncrAlgo->wKeyLenEnd))
                            wKeyLen1 = pEncrAlgo->wKeyLen;
                    }
                }
                if (pEncrAlgo->oTagLen &&  /* AEAD encr algo */
                    !oTfmId && (bEnumAuth || wAuthAlgo))
                {
                    continue; /* should not use auth algo! */
                }

#ifndef __DISABLE_DIGICERT_CONSTRAINT_CIPHER__
                if (oTfmId0)
                {
                    if (CHILDSA_cipherEffectiveBitStrength(oTfmId0, wKeyLen1) > bitStrength)
                    {
                        continue;
                    }
                }
#endif
            }
            else if ((PROTO_IPSEC_AH != pxIPsecPps->oProtocol) &&
                     (ESP_NULL != oTfmId))
            {
                CHILDSA_encrInfo *pEncrAlgo = CHILDSA_findEncrAlgoWithConstraint(bitStrength, oTfmId, 0, 0, wKeyLen, NULL);
                if (NULL == pEncrAlgo) break; /* jic */

                if (pEncrAlgo->bFixedKeyLen)
                    wKeyLen1 = 0;
            }

            for (j=0; ; j++)
            {
                ubyte oTfmId1 = oTfmId0;
                ubyte2 wAuthAlgo1 = wAuthAlgo;

                if (bEnumAuth)
                {
                    CHILDSA_authInfo *pAuthAlgo = CHILDSA_getAuthAlgo(j);
                    if (NULL == pAuthAlgo)
                        break;

                    wAuthAlgo1 = pAuthAlgo->wAuthAlgo;
                    if (!oTfmId0) oTfmId1 = pAuthAlgo->oTfmId;
                }

                if (OK != (status = OutTfmAhEsp(ctx, oTfmId1, wAuthAlgo1, wKeyLen1
#ifdef __ENABLE_IPSEC_ESN__
                                              , TRUE
#endif
                                                )))
                    goto exit;

                if (!bEnumAuth) break;
            }

            if (!bEnumEncr) break;
        }
    }
#endif

exit:
    return status;
} /* OutTfm2 */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_IPCOMP__

static MSTATUS
OutTfmComp(IKE_context ctx, ubyte oTfmId)
{
    MSTATUS status = OK;

    struct ikePpsHdr *pxPpsHdr = (struct ikePpsHdr *) ctx->pHdrParent;
    IPSECSA pxIPsecSa = P2XG_IPSECSA(ctx->pxP2Xg);
    IPSECPPS pxIPsecPps = ctx->pxIPsecPps;

    intBoolean bInitiator = IS_CHILD_INITIATOR(pxIPsecSa);
    ubyte4 dwValue;

    ubyte4 dwLength;
    ubyte *poNextPayload;
    void *pHdrParent;

    /* transform payload header */
    OUT_TOP(struct ikeTfmHdr, pxTfmHdr, SIZEOF_IKE_TFM_HDR, ISAKMP_NEXT_T)

    ++(pxPpsHdr->oTfmLen);

    if (bInitiator)
        pxTfmHdr->oNum = pxPpsHdr->oTfmLen;
    else
        pxTfmHdr->oNum = pxIPsecPps->oCompTfmNo;

    pxTfmHdr->oAttrId = oTfmId;

    /* data attributes; see RFC3173 4.1. */
    OUT_DOWN(pxTfmHdr)

    /* IPsec SA life type/duration - secs */
    if ((0 != (dwValue = pxIPsecPps->dwExpSecs)) &&
        (OK != (status = OutAttrLife(ctx, SA_LIFE_TYPE, SA_LIFE_TYPE_SECONDS, SA_LIFE_DURATION, dwValue))))
        goto exit;

    /* IPsec SA life type/duration - kbytes */
    if ((0 != (dwValue = pxIPsecPps->dwExpKBytes)) &&
        (OK != (status = OutAttrLife(ctx, SA_LIFE_TYPE, SA_LIFE_TYPE_KBYTES, SA_LIFE_DURATION, dwValue))))
        goto exit;

    /* mode */
    if (pxIPsecPps->wMode)
    {
        ubyte2 wMode = pxIPsecPps->wMode;

#ifdef __ENABLE_IPSEC_NAT_T__
        /* get UDP-encap. mode attribute value */
        if (IKE_PROP_FLAG_UDP_ENCP & pxIPsecPps->p_flags)
        {
            /* Note: 'index out of range' already checked in either InAttrs2() or OutPps() */
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
            if ((ubyte2)ENCAPSULATION_MODE_TUNNEL == wMode)
                wMode = mNatTinfo[ctx->pxSa->u.v1.iNatT - 1].wUdpTunnel;
            else
#endif
                wMode = mNatTinfo[ctx->pxSa->u.v1.iNatT - 1].wUdpTransport;
        }
#endif
        if (OK != (status = OutAttrB(ctx, ENCAPSULATION_MODE, wMode)))
            goto exit;
    }

    /* done */
    OUT_UP(pxTfmHdr)

exit:
    return status;
} /* OutTfmComp */


/*------------------------------------------------------------------*/

static MSTATUS
OutComp(IKE_context ctx)
{
    MSTATUS status = OK;

    ubyte oTfmId = ctx->pxIPsecPps->oCompAlgo;

    if (oTfmId)
    {
        if (OK != (status = OutTfmComp(ctx, oTfmId)))
            goto exit;
    }
    else /* initiator */
    {
        sbyte4 i;
        for (i=0; ; i++)
        {
            CHILDSA_compInfo *pCompAlgo = CHILDSA_getCompAlgo(i);
            if (NULL == pCompAlgo)
                break;

            oTfmId = pCompAlgo->oTfmId;

            if (OK != (status = OutTfmComp(ctx, oTfmId)))
                goto exit;
        }
    }

exit:
    return status;
} /* OutComp */

#endif /* __ENABLE_DIGICERT_IPCOMP__ */

extern ubyte4 getKeyExchangeCount();

/*------------------------------------------------------------------*/

static MSTATUS
OutPps(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    IPSECSA pxIPsecSa = (ctx->pxP2Xg ? P2XG_IPSECSA(ctx->pxP2Xg) : NULL);
    intBoolean bInitiator = (pxIPsecSa ? IS_CHILD_INITIATOR(pxIPsecSa) : IS_INITIATOR(pxSa));

    ubyte4 dwLength;
    ubyte *poNextPayload;
    void *pHdrParent;

    /* for phase 2 */
    ubyte oSaIndex = ctx->oP2SaIndex;
    ubyte oPpsIndex = 0;
    IPSECPPS pxIPsecPps = (NULL == pxIPsecSa) ? NULL
                        : &(pxIPsecSa->axP2Sa[oSaIndex].axChildSa[0].ipsecPps);
#ifdef __ENABLE_DIGICERT_IPCOMP__
    intBoolean bOutComp = FALSE;
#endif
    ubyte4 psHello = 0;
    ubyte4 proposalCount = 0;

    /* proposal payload(s) */
    for (;;)
    {
        /* proposal payload header */
        OUT_TOP(struct ikePpsHdr, pxPpsHdr, SIZEOF_IKE_PPS_HDR, ISAKMP_NEXT_P)

        pxPpsHdr->oNum = proposalCount + 1;
        pxPpsHdr->oProtoId = PROTO_ISAKMP;

        /* phase 2 */
        if (NULL != pxIPsecSa)
        {
            ubyte4 dwSpi;

            if (!bInitiator)
            {
                pxPpsHdr->oNum = pxIPsecPps->oPpsNo;
                dwSpi = pxIPsecPps->dwSpi[_R];
            }
            else
            {
#ifdef __ENABLE_DIGICERT_IPCOMP__
                if (ctx->bNoComp) pxPpsHdr->oNum = 2;
#endif
                dwSpi = pxIPsecPps->dwSpi[_I];

#ifdef __ENABLE_IPSEC_NAT_T__
                if (IKE_PROP_FLAG_UDP_ENCP & pxIPsecPps->p_flags)
                {
                    /* AH is incompatible with UDP-encap. */
                    if (PROTO_IPSEC_AH == pxIPsecPps->oProtocol)
                    {
                        status = ERR_IKE_MISMATCH;
                        DBG_EXIT
                    }

                    /* if NAT-T is needed but not supported by the peer */
                    if (0 >= pxSa->u.v1.iNatT)
                    {
                        status = ERR_IKE_MISMATCH_ENCAP_MODE;
                        DBG_EXIT
                    }
                }
#endif
            }

#ifdef __ENABLE_DIGICERT_IPCOMP__
            if (bOutComp)
            {
                /* get CPI; see RFC3173 3.3. */
                ubyte2 wCpi = pxIPsecPps->wCpi[bInitiator ? _I : _R];
                if (bInitiator &&
                    (0 == wCpi)) /* jic re-transmission */
                {
                    do
                    {
                        if (OK > (status = RANDOM_numberGenerator(
                                                            g_pRandomContext,
                                                            (ubyte *) &wCpi,
                                                            sizeof(ubyte2))))
                        {
                            DBG_EXIT
                        }
                    } while (((ubyte2)256 > wCpi) || ((ubyte2)61439 < wCpi));

                    pxIPsecPps->wCpi[_I] = wCpi;
                }

                if (ctx->dwBufferSize < sizeof(ubyte2))
                {
                    status = ERR_IKE_BUFFER_OVERFLOW;
                    DBG_EXIT
                }

                pxPpsHdr->oProtoId = PROTO_IPCOMP;
                SET_HTONS(pxPpsHdr->wLength, GET_NTOHS(pxPpsHdr->wLength) + sizeof(ubyte2));
                pxPpsHdr->oSpiSize = sizeof(ubyte2);

                DIGI_HTONS((ubyte *) &pxPpsHdr->dwSpi, wCpi);
                ADVANCE(sizeof(ubyte2))
            }
            else
#endif
            {
            pxPpsHdr->oProtoId = pxIPsecPps->oProtocol;

            /* SPI */
            if (ctx->dwBufferSize < sizeof(ubyte4))
            {
                status = ERR_IKE_BUFFER_OVERFLOW;
                DBG_EXIT
            }

            SET_HTONS(pxPpsHdr->wLength, GET_NTOHS(pxPpsHdr->wLength) + sizeof(ubyte4));
            pxPpsHdr->oSpiSize = sizeof(ubyte4);

            SET_HTONL(pxPpsHdr->dwSpi, dwSpi);
            ADVANCE(sizeof(ubyte4))
            }
        } /* if (NULL != pxIPsecSa) */

        /* down one level - go to child payloads */
        OUT_DOWN(pxPpsHdr)

        /* transform payloads */
        if (NULL == pxIPsecSa) /* phase 1 */
        {
            ubyte2 attrVal[NUM_TFM_ATTR + 1] = { 0 };
            if (!bInitiator)
            {
                sbyte4 i;
                for (i = NUM_TFM_ATTR; i >= 0; i--)
                    attrVal[i] = pxSa->u.v1.pwIsaAttr[mTfmAttr[i].wType];
            }

            if (OK != (status = OutTfm(ctx, (bInitiator ? 0 : NUM_TFM_ATTR), attrVal, proposalCount)))
                goto exit;
        }
#ifdef __ENABLE_DIGICERT_IPCOMP__
        else if (bOutComp)
        {
            ctx->pxIPsecPps = pxIPsecPps; /* jic */
            if (OK != (status = OutComp(ctx)))
                goto exit;

            if (bInitiator)
            {
                debug_print("    Proposal #");
                debug_int(pxPpsHdr->oNum);
                debug_print(": ");
                debug_print_ike_proto(pxPpsHdr->oProtoId);
                debug_print("[");
                debug_int(pxPpsHdr->oTfmLen);
                debug_print("]");
                debug_print(" cpi=");
                debug_int(DIGI_NTOHS((ubyte *) &pxPpsHdr->dwSpi));
                debug_printnl(NULL);
            }
        }
#endif
        else /* phase 2 */
        {
            if (bInitiator)
#ifndef __ENABLE_DIGICERT_PFKEY__
            {
                /* reset wildcards - jic re-transmit */
                ubyte2 flags = pxIPsecPps->p_flags;
                if (IKE_PROP_FLAG_TFM_ID & flags)       pxIPsecPps->oTfmId      = 0;
                if (IKE_PROP_FLAG_AUTH_ALGO & flags)    pxIPsecPps->wAuthAlgo   = 0;
                if (IKE_PROP_FLAG_ENCR_ALGO & flags)    pxIPsecPps->oEncrAlgo   = 0;
                if (IKE_PROP_FLAG_ENCR_KEYLEN & flags)  pxIPsecPps->wEncrKeyLen = 0;
            }
#else
            ctx->oPpsIndex = oPpsIndex;
#endif
            ctx->pxIPsecPps = pxIPsecPps;
            if (OK != (status = OutTfm2(ctx)))
                goto exit;

            if (bInitiator)
            {
                debug_print("    Proposal #");
                debug_int(pxPpsHdr->oNum);
                debug_print(": ");
                debug_print_ike_proto(pxPpsHdr->oProtoId);
                debug_print("[");
                debug_int(pxPpsHdr->oTfmLen);
                debug_print("]");
                debug_print(" spi=");
                debug_hexint(GET_NTOHL(pxPpsHdr->dwSpi));
                debug_printnl(NULL);
            }
        }

        /* up one level */
        OUT_UP(pxPpsHdr)

        /* phase 1 */
        if (NULL == pxIPsecSa)
        {
            if (bInitiator)
            {
                /* separate Key Exchange algorithms into multiple proposals */
                if (getKeyExchangeCount() == (proposalCount + 1))
                    break;
            }
            else
            {
                /* responder must reply with 1 proposal only */
                break;
            }
            proposalCount++;
            continue;
        }

        /* phase 2 */
        if (++oPpsIndex >= pxIPsecSa->axP2Sa[oSaIndex].oChildSaLen)
        {
#ifdef __ENABLE_DIGICERT_IPCOMP__
            if (!bOutComp)
            {
                if ((bInitiator && !ctx->bNoComp) ||
                    (!bInitiator && pxIPsecPps->oCompAlgo))
                {
                    if (bInitiator && (NULL == CHILDSA_getCompAlgo(0)))
                    {
                        /* jic - no compression algorithms */
                        ctx->bNoComp = TRUE;
                        break;
                    }

                    bOutComp = TRUE;
                    continue;
                }
            }
#endif
            break; /* no more proposal payloads */
        }

        pxIPsecPps = &(pxIPsecSa->axP2Sa[oSaIndex].axChildSa[oPpsIndex].ipsecPps);

    } /* for (;;) */

exit:
    return status;
} /* OutPps */


/*------------------------------------------------------------------*/

static MSTATUS
OutSa(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    IPSECSA pxIPsecSa = (ctx->pxP2Xg ? P2XG_IPSECSA(ctx->pxP2Xg) : NULL);
    intBoolean bInitiator = (pxIPsecSa ? IS_CHILD_INITIATOR(pxIPsecSa) : IS_INITIATOR(pxSa));

    ubyte4 dwLength;
    ubyte *poNextPayload;
    void *pHdrParent;

    ubyte oSaIndex = 0; /* for phase 2 */

    for (;;)
    {
        /* phase 1, initiator, re-transmit */
        if (!pxIPsecSa && bInitiator && pxSa->poMsg[_I])
        {
            ubyte2 wBodyLen = (ubyte2)(pxSa->dwMsgLen[_I] - (SIZEOF_IKE_SA_HDR - SIZEOF_IKE_GEN_HDR));
            OUT_BEGIN(struct ikeSaHdr, pxSaHdr, SIZEOF_IKE_SA_HDR, ISAKMP_NEXT_SA)
            DIGI_MEMCPY((ubyte *)pxSaHdr + SIZEOF_IKE_GEN_HDR, pxSa->poMsg[_I] , pxSa->dwMsgLen[_I]);
            OUT_END
            break;
        }
        else
        {

        /* SA payload header */
        OUT_TOP(struct ikeSaHdr, pxSaHdr, SIZEOF_IKE_SA_HDR, ISAKMP_NEXT_SA)

        pxSaHdr->oDoi = ISAKMP_DOI_IPSEC;
        pxSaHdr->oSit = SIT_IDENTITY_ONLY;

        ctx->oP2SaIndex = oSaIndex; /* for phase 2 */

        /* down one level - go to child payloads */
        OUT_DOWN(pxSaHdr)

        /* proposal payload(s) */
        if (OK != (status = OutPps(ctx)))
            goto exit;

#ifdef __ENABLE_DIGICERT_IPCOMP__
        if (pxIPsecSa && bInitiator && /* phase 2, initiator */
            !ctx->bNoComp) /* jic */
        {
            /* alternative proposal offering no Compression */
            ctx->bNoComp = TRUE;
            if (OK != (status = OutPps(ctx)))
                goto exit;
        }
#endif

        /* up one level */
        OUT_UP(pxSaHdr)

        /* phase 1 */
        if (NULL == pxIPsecSa)
        {
            /* store initiator SA payload body (no generic header) for HASH */
            if (bInitiator) /* initiator */
            {
                ubyte2 wSAi_bLen = GET_NTOHS(pxSaHdr->wLength) - (ubyte2)SIZEOF_IKE_GEN_HDR;
                pxSa->dwMsgLen[_I] = wSAi_bLen;
                /*CHECK_FREE(pxSa->poMsg[_I])*/
                CHECK_MALLOC(pxSa->poMsg[_I], wSAi_bLen)
                DIGI_MEMCPY(pxSa->poMsg[_I], (ubyte *)pxSaHdr + SIZEOF_IKE_GEN_HDR, wSAi_bLen);
            }
            break; /* only one SA payload */
        }

        /* phase 2 */
        if (++oSaIndex >= pxIPsecSa->oP2SaNum) /* no more SA payloads */
            break;

        }
    } /* for (;;) */

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

static MSTATUS
OutVid(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
#if defined(__ENABLE_IPSEC_NAT_T__) || defined(CUSTOM_IKE_GET_VENDOR_ID) || defined (__ENABLE_IKE_XAUTH__)
    intBoolean bInitiator = IS_INITIATOR(pxSa);
#endif

#if defined(__ENABLE_IPSEC_NAT_T__) || defined(CUSTOM_IKE_GET_VENDOR_ID)
    sbyte4 i;
#endif

#ifdef __ENABLE_IPSEC_NAT_T__
    if (bInitiator)
    {
        for (i=0; i < (sbyte4) NUM_VID_NAT_T; i++)
        {
            if (OK != (status = OutGen(ctx, ISAKMP_NEXT_VID,
                                       mNatTinfo[i].wVidLen, mNatTinfo[i].poVid)))
                goto exit;
        }

    }
    else if (0 <= (i = pxSa->u.v1.iNatT - 1))
    {
        if (OK != (status = OutGen(ctx, ISAKMP_NEXT_VID,
                                   mNatTinfo[i].wVidLen, mNatTinfo[i].poVid)))
            goto exit;
    }
#endif /* __ENABLE_IPSEC_NAT_T__ */

    if (OK != (status = OutGen(ctx, ISAKMP_NEXT_VID, vidDpdLen, vidDpd)))
        goto exit;

#ifdef __ENABLE_IKE_XAUTH__
    if ((bInitiator &&
         pxSa->ikePeerConfig->xauthType &&
         (6 <= pxSa->ikePeerConfig->xauthDraft)) /* !!! */
        || (IKE_SA_FLAG_XAUTH & pxSa->flags))
    {
        if (OK != (status = OutGen(ctx, ISAKMP_NEXT_VID, vidXauthLen, vidXauth)))
            goto exit;
    }
#endif

#ifdef __ENABLE_IKE_FRAGMENTATION__
    if (!pxSa->ikePeerConfig->bNoIkeFrag)
    {
      if (OK != (status = OutGen(ctx, ISAKMP_NEXT_VID, vidFragLen, vidFrag)))
         goto exit;
    }
#endif

#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
    if (OK != (status = OutGen(ctx, ISAKMP_NEXT_VID, vidPerpLen, vidPerp)))
        goto exit;
#endif

#ifdef CUSTOM_IKE_GET_VENDOR_ID
    for (i=0; (SIZEOF_IKE_GEN_HDR < ctx->dwBufferSize); i++)
    {
        ubyte2 wVidLen = (ubyte2)(ctx->dwBufferSize - SIZEOF_IKE_GEN_HDR);
        if ((OK > CUSTOM_IKE_GET_VENDOR_ID(
                            ctx->pBuffer + SIZEOF_IKE_GEN_HDR, &wVidLen,
                            i, REF_MOC_IPADDR(pxSa->dwPeerAddr),
                            0, bInitiator
                            MOC_MTHM_REQ_VALUE(pxSa->serverInstance)))
            || (0 == wVidLen))
        {
            break;
        }

        if (OK != (status = OutGen(ctx, ISAKMP_NEXT_VID, wVidLen, NULL)))
            goto exit;
    }
#endif

exit:
    return status;
} /* OutVid */


#ifdef __ENABLE_IPSEC_NAT_T__

/*------------------------------------------------------------------*/

static MSTATUS
OutNatD(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;

    ubyte2 wDigestLen;
    ubyte  oNextNatD;
    sbyte4 i;

    if (0 >= pxSa->u.v1.iNatT)
        goto exit;

    wDigestLen = (ubyte2) pxSa->pHashSuite->pBHAlgo->digestSize;
    oNextNatD = mNatTinfo[pxSa->u.v1.iNatT - 1].oNatD;

    for (i=0; i < 2; i++)
    {
        /* generic header */
        if (OK != (status = OutGen(ctx, oNextNatD, wDigestLen, NULL)))
            goto exit;

        /* NAT-D hash data */
        if (OK > (status = DoHashNatD(ctx, ctx->pBuffer - wDigestLen,
                                      (i ? FALSE : TRUE))))
            goto exit;

        debug_printd((sbyte *)(i ? "   NAT-D (us):" : "   NAT-D (peer):"),
                     ctx->pBuffer - wDigestLen, wDigestLen);
    } /* for */

exit:
    return status;
} /* OutNatD */


/*------------------------------------------------------------------*/

static MSTATUS
OutNatOa(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    IPSECSA pxIPsecSa = P2XG_IPSECSA(ctx->pxP2Xg);
    intBoolean bInitiator = IS_CHILD_INITIATOR(pxIPsecSa);

    sbyte4 i;
    ubyte oNextNatOa;

    /* no NAT-OA payloads? */
    if ((0 >= pxSa->u.v1.iNatT) || !NeedNatOa(pxSa, pxIPsecSa, FALSE))
        goto exit;

    oNextNatOa = mNatTinfo[pxSa->u.v1.iNatT - 1].oNatOa;

    for (i=0; i < 2; i++)
    {
        ubyte2 wBodyLen;
        sbyte4 idType;

        const ubyte *poIpAddr = NULL;
        ubyte4 dwIpAddr = 0;

        MOC_IP_ADDRESS ipAddr;
        if ((i && !bInitiator) || (!i && bInitiator))
            ipAddr = REF_MOC_IPADDR(pxSa->dwHostAddr);
        else
            ipAddr = REF_MOC_IPADDR(pxSa->dwPeerAddr);

        TEST_MOC_IPADDR6(ipAddr,
        {
            wBodyLen = 16;
            idType = ID_IPV6_ADDR;
            poIpAddr = GET_MOC_IPADDR6(ipAddr);
        })
        {
            wBodyLen = 4;
            idType = ID_IPV4_ADDR;
            dwIpAddr = GET_MOC_IPADDR4(ipAddr);
        }

        /* NAT-OA payload */
        { OUT_BEGIN(struct ikeNatOaHdr, pxNatOaHdr, SIZEOF_IKE_NATOA_HDR, oNextNatOa)

        pxNatOaHdr->oIdType = (ubyte)idType;

        if (poIpAddr)
            DIGI_MEMCPY(ctx->pBuffer, poIpAddr, 16);
        else
            SET_HTONL(pxNatOaHdr->dwIpAddr, dwIpAddr);

        /* done */
        OUT_END }
    } /* for */

exit:
    return status;
} /* OutNatOa */

#endif /* __ENABLE_IPSEC_NAT_T__ */


/*------------------------------------------------------------------*/

static MSTATUS
OutKe(IKE_context ctx)
{
    MSTATUS                 status      = OK;

    IKESA                   pxSa        = ctx->pxSa;
    IPSECSA                 pxIPsecSa   = (ctx->pxP2Xg ? P2XG_IPSECSA(ctx->pxP2Xg) : NULL);
    intBoolean              bInitiator  = (pxIPsecSa ? (IS_CHILD_INITIATOR(pxIPsecSa)) : (IS_INITIATOR(pxSa)));
    diffieHellmanContext*   pDHctx = NULL;
    MDhKeyTemplate keyTemplate = {0};

#ifdef __ENABLE_DIGICERT_ECC__
    sbyte4                  stringLenF;
    ECCKey*                 pEccKey     = NULL;
    ubyte4                  curveId;
    ubyte4                  pointLen;
    ubyte                  *pPoint = NULL;
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    QS_CTX*                 pQsCtx = NULL;
    ubyte4                  qsPubKeyLen = 0;
    ubyte4                  cipherTextLen = 0;
#endif

    sbyte4 stringLenFToUse;
    ubyte* pStringMpintFToUse = NULL;/* DH server public value */
    ubyte *pBuffer = NULL;

    /* phase 2 - no PFS? */
    if ((NULL != pxIPsecSa) && (0 == pxIPsecSa->wPFS))
        goto exit;

    /* get DH context */
    if (NULL == (pDHctx = (pxIPsecSa ? DIFFIEHELLMAN_CONTEXT(pxIPsecSa) : DIFFIEHELLMAN_CONTEXT(pxSa))))
    {
#ifdef __ENABLE_DIGICERT_ECC__
      if (NULL == (pEccKey = (pxIPsecSa ? pxIPsecSa->p_eccKey : pxSa->p_eccKey)))
#endif
      {
        if (bInitiator) /* initiator */
        {
            /* get DH group number */
            ubyte2 wGroup;
            IKE_dhGroupInfo *pDhGroup;

            if (NULL != pxIPsecSa) /* phase 2 */
                wGroup = pxIPsecSa->wPFS;
            else /* phase 1 */
                wGroup = pxSa->u.v1.pwIsaAttr[OAKLEY_GROUP_DESCRIPTION];

            if (!wGroup || (NULL == (pDhGroup = IKE_dhGroupEx(pxSa->ikePeerConfig, wGroup))))
            {
                status = ERR_IKE_BAD_KE;
                DBG_EXIT
            }

#ifdef __ENABLE_DIGICERT_ECC__
            if (0 < (curveId = pDhGroup->curveId))
            {
                ECCKey **ppEccKey = (pxIPsecSa ? &pxIPsecSa->p_eccKey : &pxSa->p_eccKey);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                status = CRYPTO_INTERFACE_EC_generateKeyPairAllocAux (MOC_ECC(ctx->hwAccelCookie)
                    curveId, &pEccKey, RANDOM_rngFun, (void *)g_pRandomContext);
                if (OK != status)
                    goto exit;
#else
                status = EC_generateKeyPairAlloc (MOC_ECC(ctx->hwAccelCookie)
                    curveId, &pEccKey, RANDOM_rngFun, (void *)g_pRandomContext);
                if (OK != status)
                    goto exit;
#endif
                *ppEccKey = pEccKey;

#ifdef __ENABLE_DIGICERT_PQC__
                if (0 < pDhGroup->qsAlgoId)
                {
                    QS_CTX **ppQsCtx = (pxIPsecSa ? &pxIPsecSa->pQsCtx : &pxSa->pQsCtx);

                    status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(ctx->hwAccelCookie) &pQsCtx, pDhGroup->qsAlgoId);
                    if (OK != status)
                        DBG_EXIT

                    status = CRYPTO_INTERFACE_QS_generateKeyPair(MOC_HASH(ctx->hwAccelCookie) pQsCtx, RANDOM_rngFun, g_pRandomContext);
                    if (OK != status)
                        DBG_EXIT

                    *ppQsCtx = pQsCtx;
                }
#endif /* __ENABLE_DIGICERT_PQC__ */
            }
            else
#endif /* __ENABLE_DIGICERT_ECC__ */
            {
                /* create DH context */
                diffieHellmanContext **ppDHctx = (pxIPsecSa ?
                                                &(DIFFIEHELLMAN_CONTEXT(pxIPsecSa)) :
                                                &(DIFFIEHELLMAN_CONTEXT(pxSa)));
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
            status = ERR_IKE_BAD_KE; /* missing KE - for quick mode responder (redundant?) */
            DBG_EXIT
        }
      }
#ifdef __ENABLE_DIGICERT_ECC__
      else
      {
#ifdef __ENABLE_DIGICERT_PQC__
        pQsCtx = (pxIPsecSa ? pxIPsecSa->pQsCtx : pxSa->pQsCtx);
#endif
      }
#endif
    }

#ifdef __ENABLE_DIGICERT_ECC__
    if (NULL != pEccKey)
    {
        ubyte4 totalLength = 0;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(pEccKey, (ubyte4 *)&stringLenF);
        if (OK != status)
            goto exit;
#else
        status = EC_getElementByteStringLen(pEccKey, (ubyte4 *)&stringLenF);
        if (OK != status)
            goto exit;
#endif

        totalLength =  2 * stringLenF;

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

                totalLength += qsPubKeyLen;
            }
            else
            {
                status = CRYPTO_INTERFACE_QS_KEM_getCipherTextLen(pQsCtx, &cipherTextLen);
                if (OK != status)
                    DBG_EXIT

                totalLength += cipherTextLen;
            }
        }
#endif /* __ENABLE_DIGICERT_PQC__ */

        status = OutGen(ctx, ISAKMP_NEXT_KE, (ubyte2)(totalLength), NULL);
        if (OK != status)
            goto exit;

        ubyte *s = ctx->pBuffer - stringLenF;

#ifdef __ENABLE_DIGICERT_PQC__
        if (NULL != pQsCtx)
        {
            if (bInitiator)
            {
                s -= qsPubKeyLen;
            }
            else
            {
                s -= cipherTextLen;
            }
        }
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAllocAux(MOC_ECC(ctx->hwAccelCookie) pEccKey, &pPoint, &pointLen);
#else
        status = EC_writePublicKeyToBufferAlloc(MOC_ECC(ctx->hwAccelCookie) pEccKey, &pPoint, &pointLen);
#endif
        if (OK != status)
            DBG_EXIT

        status = DIGI_MEMCPY (
            (void *)(s- stringLenF), (void *)(pPoint + 1), pointLen - 1);
        if (OK != status)
            DBG_EXIT

#ifdef __ENABLE_DIGICERT_PQC__
        if (NULL != pQsCtx)
        {
            s += stringLenF;
            if (bInitiator)
            {
                status = CRYPTO_INTERFACE_QS_getPublicKey(pQsCtx, s, qsPubKeyLen);
            }
            else
            {
                ubyte *pQsCipherText = (pxIPsecSa ? pxIPsecSa->pQsCipherText : pxSa->pQsCipherText);
                ubyte4 cipherTextLen = (pxIPsecSa ? pxIPsecSa->qsCipherTextLen : pxSa->qsCipherTextLen);

                status = DIGI_MEMCPY(s, pQsCipherText, cipherTextLen);
            }
            if (OK != status)
                DBG_EXIT
        }
#endif
    }
    else
#endif /* __ENABLE_DIGICERT_ECC__ */
    {
        /* get DH public value string */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_DH_getKeyParametersAllocExt(MOC_DH(ctx->hwAccelCookie) &keyTemplate,
                                                              pDHctx,
                                                              MOC_GET_PRIVATE_KEY_DATA,
                                                              NULL);
        if (OK != status)
            goto exit;
#else
        status = DH_getKeyParametersAlloc(MOC_DH(ctx->hwAccelCookie) &keyTemplate, pDHctx, MOC_GET_PRIVATE_KEY_DATA);
        if (OK != status)
            goto exit;
#endif

        /* RFC 2409, section 5:
         * The Diffie-Hellman public value passed in a KE payload, in either a
         * phase 1 or phase 2 exchange, MUST be the length of the negotiated
         * Diffie-Hellman group enforced, if necessary, by pre-pending the value
         * with zeros.
         */
        if (keyTemplate.fLen < keyTemplate.pLen)
        {
            status = DIGI_MALLOC((void **)&pBuffer, keyTemplate.pLen);
            if (OK != status)
            {
                goto exit;
            }

            DIGI_MEMSET(pBuffer, 0, keyTemplate.pLen - keyTemplate.fLen);
            DIGI_MEMCPY(pBuffer + keyTemplate.pLen - keyTemplate.fLen,
                    keyTemplate.pF, keyTemplate.fLen);

            pStringMpintFToUse = pBuffer;
            stringLenFToUse = keyTemplate.pLen;
        }
        else
        {
            pStringMpintFToUse = keyTemplate.pF;
            stringLenFToUse = keyTemplate.fLen;
        }

        status = OutGen(ctx, ISAKMP_NEXT_KE, (ubyte2)(stringLenFToUse), NULL);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY (
            (void *)(ctx->pBuffer - stringLenFToUse), (void *)pStringMpintFToUse, stringLenFToUse);
        if (OK != status)
            goto exit;
    }

exit:
#ifdef __ENABLE_DIGICERT_ECC__
    CHECK_FREE(pPoint);
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DH_freeKeyTemplateExt(pDHctx, &keyTemplate, NULL);
#else
    DH_freeKeyTemplate(pDHctx, &keyTemplate);
#endif

    DIGI_FREE((void **) &pBuffer);
    return status;
} /* OutKe */


/*------------------------------------------------------------------*/

extern MSTATUS
OutNonce(IKE_context ctx)
{
    MSTATUS status;

    IKESA pxSa = ctx->pxSa;
    IPSECSA pxIPsecSa = (ctx->pxP2Xg ? P2XG_IPSECSA(ctx->pxP2Xg) : NULL);

    /* nonce data */
    ubyte *poNonce = (pxIPsecSa ? pxIPsecSa->poNonce : pxSa->nonce);

    /* generic header */
    if (OK != (status = OutGen(ctx, ISAKMP_NEXT_NONCE, IKE_NONCE_SIZE, poNonce)))
        goto exit;

exit:
    return status;
} /* OutNonce */


/*------------------------------------------------------------------*/

static intBoolean
UseCert(IKESA pxSa)
{
    intBoolean ret = FALSE;

#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
    if (STATE_AGGR_I1 == pxSa->oState) /* special case */
    {
#ifdef __ENABLE_DIGICERT_PQC__
        if(TRUE == isHybridOakleyMtd(AUTH_MTD(pxSa)))
        {
            return TRUE;
        }
#endif
        if (AUTH_MTD(pxSa) & (ubyte2)
                        ((1 << OAKLEY_RSA_SIG)
#ifdef __ENABLE_DIGICERT_ECC__
                       | (1 << OAKLEY_ECDSA_SIG)
                       | (1 << OAKLEY_ECDSA_256)
                       | (1 << OAKLEY_ECDSA_384)
                       | (1 << OAKLEY_ECDSA_521)
#endif
                         ))
        {
            ret = TRUE;
        }
    }
    else
#endif
    {
#ifdef __ENABLE_DIGICERT_PQC__
        if(TRUE == isHybridOakleyMtd(BASE_AUTH_MTD(pxSa)))
        {
            return TRUE;
        }
#endif
        switch (BASE_AUTH_MTD(pxSa))
        {
        case OAKLEY_RSA_SIG :
#ifdef __ENABLE_DIGICERT_ECC__
        case OAKLEY_ECDSA_SIG :
        case OAKLEY_ECDSA_256 :
        case OAKLEY_ECDSA_384 :
        case OAKLEY_ECDSA_521 :
#endif
            ret = TRUE;
            break;
        default:
            break;
        }
    }

    return ret;
} /* UseCert */


/*------------------------------------------------------------------*/

static MSTATUS
OutId(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    intBoolean bInitiator = IS_INITIATOR(pxSa);

    sbyte4 dir = (bInitiator ? _I : _R);
    struct ikeIdHdr *pxID = pxSa->pxID[dir];

    sbyte4 idType = 0;
    ubyte2 wBodyLen = 0;
    const ubyte *poIdData = NULL;

    ubyte4 dwHostAddr = 0;

    if (NULL != pxID) /* re-transmit? */
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

#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)
    if (IS_HYBRID_CLIENT(pxSa) || PROP_HYBRID_CLIENT(pxSa) /* jic */)
    {
        /* hybrid client sends empty ID payload */
        poIdData = (const ubyte *)"";
        goto output;
    }
#endif

    /* use certificate Subject as ID, if applicable */
    if ((NULL != pxSa->pCertChain) && UseCert(pxSa))
    {
        IKE_certDescr pxCertDesc = pxSa->pCertChain;

        /* sanity-check !!! */
        if ((pxSa->ikePeerConfig->ikeCertChain == pxCertDesc) &&
            (0 >= (pxSa->certChainLen = pxSa->ikePeerConfig->ikeCertChainLen)))
        {
            /* no more certificate */
            pxSa->pCertChain = NULL;
            status = ERR_IKE_NO_CERT;
            DBG_EXIT
        }

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
    { OUT_BEGIN(struct ikeIdHdr, pxIdHdr, SIZEOF_IKE_ID_HDR, ISAKMP_NEXT_ID)

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

extern void
OutId2Data(IPSECSA pxIPsecSa, sbyte4 i,
           sbyte4 *id_t, ubyte2 *wBodyLen,
           ubyte4 *pdwIpAddr, ubyte4 *pdwIpAddrEnd
#ifdef __ENABLE_DIGICERT_IPV6__
         , const ubyte **ppoIpAddr6, const ubyte **ppoIpAddr6End
         , ubyte4 ipAddr6Mask[4]
#endif
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        ,ubyte *fqdn
#endif
           )
{
    intBoolean bInitiator = IS_CHILD_INITIATOR(pxIPsecSa);

#ifdef __ENABLE_DIGICERT_IPV6__
    ubyte4 dwIpAddr = 0, dwIpAddrEnd = 0;
    const ubyte *poIpAddr6 = NULL, *poIpAddr6End = NULL;
#else
    #define ipAddr dwIpAddr
    #define ipAddrEnd dwIpAddrEnd
#endif
    INIT_MOC_IPADDR(ipAddr, pxIPsecSa->dwIP[i])
    INIT_MOC_IPADDR(ipAddrEnd, pxIPsecSa->dwIPEnd[i])

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    /* add support for fqdn here*/
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
        if((ID_USER_FQDN == pxIPsecSa->IDc_t[i]) && 0 != pxIPsecSa->fqdn[0])
        {
            *id_t = ID_USER_FQDN;
            DIGI_MEMCPY(fqdn, pxIPsecSa->fqdn, DIGI_STRLEN((sbyte *) pxIPsecSa->fqdn));
            *wBodyLen = DIGI_STRLEN((sbyte *) fqdn);
            return;
        }
#endif
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
        if (pxIPsecSa->fqdn[0] != 0)
        {
            *id_t = ID_USER_FQDN;
            DIGI_MEMCPY(fqdn, pxIPsecSa->fqdn, DIGI_STRLEN((sbyte *) pxIPsecSa->fqdn));
            *wBodyLen = DIGI_STRLEN((sbyte *) fqdn);
            return;
        }
#endif
#endif
    /* IPv6 address */
    TEST_MOC_IPADDR6(ipAddr,
    {
        poIpAddr6 = GET_MOC_IPADDR6(ipAddr);

        if ((bInitiator || (ID_IPV6_ADDR == pxIPsecSa->IDc_t[i])) &&
            SAME_MOC_IPADDR(ipAddr, pxIPsecSa->dwIPEnd[i]))
        {
            *id_t = ID_IPV6_ADDR;
            *wBodyLen = 16;
        }
        else
        {
            poIpAddr6End = GET_MOC_IPADDR6(ipAddrEnd);
            *id_t = ID_IPV6_ADDR_RANGE;
            *wBodyLen = 32;

            /* convert ip range to subnet/mask, if applicable */
            if (!bInitiator && (ID_IPV6_ADDR_RANGE == pxIPsecSa->IDc_t[i]))
            {
                /* if IDci/cr is a range and we're the responder, don't convert */
            }
            else
            {
                sbyte4 j;
                for (j=0; j < 4; j++)
                {
                    dwIpAddr = GET_NTOHL(ipAddr->uin.addr6[j]);
                    dwIpAddrEnd = GET_NTOHL(ipAddrEnd->uin.addr6[j]);

                    if (dwIpAddrEnd == dwIpAddr)
                    {
                        ipAddr6Mask[j] = (ubyte4)(-1);
                        *id_t = ID_IPV6_ADDR_SUBNET;
                    }
                    else
                    {
                        ubyte4 dwMask = ~(dwIpAddrEnd ^ dwIpAddr);

                        sbyte4 k;
                        for (k = (sizeof(ubyte4) * 8) - 1; k >= 0; k--)
                        {
                            if (0 == (dwMask & (((ubyte4)1) << k)))
                                break;
                        }

                        if ((0 == (dwMask << ((sizeof(ubyte4) * 8) - k - 1))) && /* valid netmask? */
                            (dwIpAddr == (dwIpAddr & dwMask)) &&
                            (dwIpAddrEnd == (dwIpAddr | ~(dwMask))))
                        {
                            SET_HTONL(ipAddr6Mask[j], dwMask);
                            *id_t = ID_IPV6_ADDR_SUBNET;
                            j++; /* !!! */
                        }
                        else
                        {
                            *id_t = ID_IPV6_ADDR_RANGE;
                        }
                        break; /* !!! */
                    }
                }

                if (ID_IPV6_ADDR_SUBNET == *id_t)
                {
                    for (; j < 4; j++)
                    {
                        if ((0 == ipAddr->uin.addr6[j]) &&
                            ((ubyte4)(-1) == ipAddrEnd->uin.addr6[j]))
                            ipAddr6Mask[j] = 0;
                        else break;
                    }

                    if (4 > j) *id_t = ID_IPV6_ADDR_RANGE;
                    else poIpAddr6End = (const ubyte *)ipAddr6Mask;
                }
            }
        }

        *ppoIpAddr6 = poIpAddr6;
        *ppoIpAddr6End = poIpAddr6End;
    })

    /* IPv4 address */
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        dwIpAddr = GET_MOC_IPADDR4(ipAddr);
        dwIpAddrEnd = GET_MOC_IPADDR4(ipAddrEnd);
#endif
        if ((dwIpAddrEnd == dwIpAddr) &&
            (bInitiator || (ID_IPV4_ADDR == pxIPsecSa->IDc_t[i])))
        {
            *id_t = ID_IPV4_ADDR;
            *wBodyLen = 4;
        }
        else
        {
            *id_t = ID_IPV4_ADDR_RANGE;
            *wBodyLen = 8;

            /* convert ip range to subnet/mask, if applicable */
            if (!bInitiator && (ID_IPV4_ADDR_RANGE == pxIPsecSa->IDc_t[i]))
            {
                /* if IDci/cr is a range and we're the responder, don't convert */
            }
            else if (dwIpAddrEnd == dwIpAddr)
            {
                dwIpAddrEnd = (ubyte4)(-1);
                *id_t = ID_IPV4_ADDR_SUBNET;
            }
            else
            {
                ubyte4 dwMask = ~(dwIpAddrEnd ^ dwIpAddr);

                sbyte4 j;
                for (j = (sizeof(ubyte4) * 8) - 1; j >= 0; j--)
                {
                    if (0 == (dwMask & (((ubyte4)1) << j)))
                        break;
                }

                /* if j less than 0, dwMask is shifted 32 bits or more,
                 * which has undefined behavior. */
                if (0 > j)
                    j = 0;

                if ((0 == (dwMask << ((sizeof(ubyte4) * 8) - j - 1))) && /* valid netmask? */
                    (dwIpAddr == (dwIpAddr & dwMask)) &&
                    (dwIpAddrEnd == (dwIpAddr | ~(dwMask))))
                {
                    dwIpAddrEnd = dwMask;
                    *id_t = ID_IPV4_ADDR_SUBNET;
                }
            }
        }

        *pdwIpAddr = dwIpAddr;
        *pdwIpAddrEnd = dwIpAddrEnd;
    }

#ifndef __ENABLE_DIGICERT_IPV6__
    #undef ipAddr
    #undef ipAddrEnd
#endif

    return;
} /* OutId2Data */


/*------------------------------------------------------------------*/

extern MSTATUS
OutId2(IKE_context ctx)
{
    MSTATUS status = OK;

    IPSECSA pxIPsecSa = P2XG_IPSECSA(ctx->pxP2Xg);
    intBoolean bInitiator = IS_CHILD_INITIATOR(pxIPsecSa);

    sbyte4 i;

    /* client identifiers specified? */
    if (!bInitiator && /* responder */
        !(IKE_CHILD_FLAG_ID2 & pxIPsecSa->c_flags))
    {
        goto exit;
    }

    for (i=0; i < 2; i++)
    {
        sbyte4 id_t = 0;
        ubyte2 wBodyLen = 0;

        ubyte4 dwIpAddr = 0, dwIpAddrEnd = 0;
#ifdef __ENABLE_DIGICERT_IPV6__
        const ubyte *poIpAddr6 = NULL, *poIpAddr6End = NULL;
        ubyte4 ipAddr6Mask[4];
#endif
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        ubyte fqdn[MOC_MAX_FQDN_LEN];
        DIGI_MEMSET(fqdn, 0, MOC_MAX_FQDN_LEN);
#endif

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
        if (i && IS_GPULL_STATE(pxIPsecSa->oState))
        {
            /* only 1 ID payload */
            break;
        }
#endif
        OutId2Data(pxIPsecSa, i, &id_t, &wBodyLen,
                   &dwIpAddr, &dwIpAddrEnd
#ifdef __ENABLE_DIGICERT_IPV6__
                 , &poIpAddr6, &poIpAddr6End, ipAddr6Mask
#endif
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
                 , fqdn
#endif
                   );

        /* id payload header */
        { OUT_BEGIN(struct ikeIdHdr, pxIdHdr, SIZEOF_IKE_ID_HDR, ISAKMP_NEXT_ID)

        pxIdHdr->oType = (ubyte)id_t;
        pxIdHdr->oProtocol = pxIPsecSa->oUlp;
        SET_HTONS(pxIdHdr->wPort, pxIPsecSa->wPort[i]);

#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        if(DIGI_STRLEN((sbyte *) fqdn))    /* if fqdn obtained*/
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
            SET_HTONL(pxIdHdr->dwIpAddr, dwIpAddr);

            if (4 < wBodyLen)
            {
                SET_HTONL(pxIdHdr->dwIpAddrEnd, dwIpAddrEnd);
            }
        }
        }

        if (bInitiator)
            debug_print_ike_id2((ubyte *)pxIdHdr, (0==i));

        /* done */
        OUT_END }
    } /* for (i */

exit:
    return status;
} /* OutId2 */


/*------------------------------------------------------------------*/

static MSTATUS
matchTrustAnchor(MOC_ASYM(hwAccelDescr hwAccelCtx) const void *arg, const ubyte *testCert, ubyte4 testCertLen)
{
    MSTATUS status;
    IKE_context ctx = (IKE_context)arg;

    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pxRoot = NULL, pxSubj;

    ubyte2 wBodyLen;

    /* get TA's subject DN */
    MF_attach(&mf, testCertLen, (ubyte *)testCert);
    CS_AttachMemFile(&cs, &mf);

    if (OK > (status = X509_parseCertificate(cs, &pxRoot)))
        DBG_EXIT

    if (OK > (status = X509_getCertificateSubject(ASN1_FIRST_CHILD(pxRoot), &pxSubj)))
        DBG_EXIT

    wBodyLen = (ubyte2)(pxSubj->length + pxSubj->headerSize);
    if (0 != wBodyLen)
    {
        ubyte *poCertAuthDN = (ubyte *)testCert + (pxSubj->dataOffset - pxSubj->headerSize);

        /* certificate request payload header */
        OUT_BEGIN(struct ikeCRHdr, pxCRHdr, SIZEOF_IKE_CR_HDR, ISAKMP_NEXT_CR)

        pxCRHdr->oType = CERT_X509_SIGNATURE;

        /* certificate authority */
        DIGI_MEMCPY(ctx->pBuffer, poCertAuthDN, wBodyLen);

        /* done */
        OUT_END
    }

    status = ERR_FALSE; /* go to next TA!!! */

exit:
    if (NULL != pxRoot)
        TREE_DeleteTreeItem((TreeItem *)pxRoot);

    return status;
} /* matchTrustAnchor */


/*------------------------------------------------------------------*/

static MSTATUS
DoCR(IKE_context ctx
#ifdef __ENABLE_DIGICERT_ECC__
   , AsymmetricKey *pPeerKey, ubyte2 awAuthMtd[], sbyte4 num
#endif
     )
{
    MSTATUS status = OK;
    certStorePtr pCertStore;

#ifdef __ENABLE_DIGICERT_ECC__
    ubyte4 peerCurveId = 0;
    ubyte4 curveId = 0;

    if (pPeerKey)
    {
        sbyte4 i;
        for (i=0; i < num; i++)
        {
            ubyte2 wAuthMtd = awAuthMtd[i];

            if (OAKLEY_RSA_SIG == wAuthMtd)
            {
                if (akt_rsa == pPeerKey->type)
                    goto exit;
            }
            else if (akt_ecc == pPeerKey->type)
            {
                IKE_authMtdInfo *pAuthMtd =
                                IKE_authMtdEx(ctx->pxSa->ikePeerConfig,
                                              wAuthMtd, 0);

                /* To be consistent with the requirements of using the crypto interface,
                 * we cannot expect the curve inside the key to be available or valid.
                 * Instead we convert the pCurve in the pAuthMtd to a curveId and
                 * ensure it matches the one corresponding to our key */
                if (NULL == pAuthMtd) /* jic */
                {
                    status = ERR_NULL_POINTER;
                    goto exit;
                }
                curveId = pAuthMtd->curveId;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pPeerKey->key.pECC, &peerCurveId);
                if (OK != status)
                    goto exit;
#else
                status = EC_getCurveIdFromKey(pPeerKey->key.pECC, &peerCurveId);
                if (OK != status)
                    goto exit;
#endif

                if (curveId != peerCurveId)
                {
                    status = ERR_IKE_MISMATCH_AUTH_METHOD;
                    goto exit;
                }
            }
        }
    }
#endif

    if (NULL != (pCertStore = ctx->pxSa->ikePeerConfig->ikeCertStore))
    {
        ubyte4 dwLength = ctx->dwLength;

        if (OK > (status = CERT_STORE_traverseTrustPoints(MOC_ASYM(ctx->hwAccelCookie)
                                                          pCertStore, ctx,
                                                          matchTrustAnchor)))
            DBG_EXIT

        if (dwLength != ctx->dwLength) /* TA('s) found */
            goto exit;
    }
    {
        /* CR payload w/ empty CA DN */
        ubyte2 wBodyLen = 0;
        OUT_BEGIN(struct ikeCRHdr, pxCRHdr, SIZEOF_IKE_CR_HDR, ISAKMP_NEXT_CR)
        pxCRHdr->oType = CERT_X509_SIGNATURE;
        OUT_END
    }

exit:
    return status;
} /* DoCR */


/*------------------------------------------------------------------*/

static MSTATUS
OutCR(IKE_context ctx)
{
    MSTATUS status = OK;

#ifdef __ENABLE_DIGICERT_ECC__
    ubyte2 wAuthMtd = BASE_AUTH_MTD(ctx->pxSa);

    AsymmetricKey *pPeerKey = NULL;
    IKE_certLookup(ctx, NULL, &pPeerKey);

    status = DoCR(ctx, pPeerKey, &wAuthMtd, 1);

#else
    if (OK <= IKE_certLookup(ctx, NULL, NULL))
        goto exit;

    status = DoCR(ctx);

exit:
#endif
    return status;
} /* OutCR */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_getIdHash(IKE_context ctx, struct ikeIdHdr *pxId, ubyte *poIdHash)
{
    MSTATUS status;

    ubyte2 wIdLen = GET_NTOHS(pxId->wLength) - SIZEOF_IKE_GEN_HDR;
    ubyte* __crypto_i__(poId, (ubyte*)pxId + SIZEOF_IKE_GEN_HDR);

    _CRYPTO_COPY_(poId, wIdLen, (ubyte*)pxId + SIZEOF_IKE_GEN_HDR)

    if (OK > (status = MD5_completeDigest(MOC_HASH(ctx->hwAccelCookie)
                                          poId, wIdLen, poIdHash)))
        goto exit;

#if !(defined(__ENABLE_DIGICERT_HARNESS__) || \
      defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || \
      defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))
    MOC_UNUSED(ctx);
#endif

exit:
    _CRYPTO_FREE_(poId)
    return status;
} /* IKE_getIdHash */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__

static MSTATUS
OutCR_aggrR1(IKE_context ctx)
{
    /* responder, aggr mode */
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    ubyte __crypto__(poIdHash, MD5_DIGESTSIZE);

#ifdef __ENABLE_DIGICERT_ECC__
    AsymmetricKey *pPeerKey = NULL;
    ubyte2 wAuthMtd = 0;
#endif

    /* get IDii_b hash (already known, sent in 1st message) */
    _CRYPTO_ALLOC_(poIdHash, MD5_DIGESTSIZE)
    if (OK > (status = IKE_getIdHash(ctx, pxSa->pxID[_I], poIdHash)))
        DBG_EXIT

#ifndef __ENABLE_DIGICERT_ECC__
    if (OK <= IKE_certLookup(ctx, poIdHash, NULL))
        goto exit;
#else
    if (OK <= IKE_certLookup(ctx, poIdHash, &pPeerKey))
        wAuthMtd = BASE_AUTH_MTD(pxSa);
#endif

    status = DoCR(ctx
#ifdef __ENABLE_DIGICERT_ECC__
                , pPeerKey, &wAuthMtd, 1
#endif
                  );

exit:
    _CRYPTO_FREE_(poIdHash)
    return status;
} /* OutCR_aggrR1 */


/*------------------------------------------------------------------*/

static MSTATUS
OutCR_aggrI1(IKE_context ctx)
{
    /* initiator, aggr mode */
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;

#ifdef __ENABLE_DIGICERT_ECC__
    AsymmetricKey *pPeerKey = NULL;
    sbyte4 numSigMtds = 0;
    ubyte2 awSigMtd[5];
#endif

#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)
    if (PROP_HYBRID_SERVER(pxSa))
        goto exit; /* hybrid server does not send CR payload */
#endif

    if (!UseCert(pxSa)) goto exit;

#ifndef __ENABLE_DIGICERT_ECC__
    if (OK <= IKE_certLookup(ctx, NULL, NULL))
        goto exit;

    status = DoCR(ctx);
#else
    if (OK <= IKE_certLookup(ctx, NULL, &pPeerKey))
    {
        ubyte2 wAuthMtds = AUTH_MTD(pxSa);

#ifdef __ENABLE_DIGICERT_PQC__
        if(TRUE == isHybridOakleyMtd(wAuthMtds))
        {
            awSigMtd[numSigMtds++] = wAuthMtds;
        }
        else
#endif
        {
        if ((ubyte2)(1 << OAKLEY_RSA_SIG) & wAuthMtds)
            awSigMtd[numSigMtds++] = OAKLEY_RSA_SIG;

        if ((ubyte2)(1 << OAKLEY_ECDSA_SIG) & wAuthMtds)
            awSigMtd[numSigMtds++] = OAKLEY_ECDSA_SIG;

        if ((ubyte2)(1 << OAKLEY_ECDSA_256) & wAuthMtds)
            awSigMtd[numSigMtds++] = OAKLEY_ECDSA_256;

        if ((ubyte2)(1 << OAKLEY_ECDSA_384) & wAuthMtds)
            awSigMtd[numSigMtds++] = OAKLEY_ECDSA_384;

        if ((ubyte2)(1 << OAKLEY_ECDSA_521) & wAuthMtds)
            awSigMtd[numSigMtds++] = OAKLEY_ECDSA_521;
        }
    }

    status = DoCR(ctx, pPeerKey, awSigMtd, numSigMtds);
#endif

exit:
    return status;
} /* OutCR_aggrI1 */

#endif /* __ENABLE_IKE_AGGRESSIVE_MODE__ */


/*------------------------------------------------------------------*/

static MSTATUS
OutCert(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    sbyte4 certNum = pxSa->certChainLen;
    IKE_certDescr pxCertDesc = pxSa->pCertChain;

    /* sanity-check !!! */
    if (pxSa->ikePeerConfig->ikeCertChain == pxCertDesc)
    {
        certNum = pxSa->certChainLen = pxSa->ikePeerConfig->ikeCertChainLen;
        if (0 >= certNum)
        {
            /* no more certificate */
            pxSa->pCertChain = NULL;
#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)
            if (!IS_HYBRID_CLIENT(pxSa))
#endif
            {
                status = ERR_IKE_NO_CERT;
                DBG_EXIT
            }
        }
    }

    if (!(IKE_SA_FLAG_CR & pxSa->flags))
        goto exit; /* certificate not requested */

#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)
    if (IS_HYBRID_CLIENT(pxSa))
    {
        /* hybrid client sends empty CERT payload */
        ubyte2 wBodyLen = 0;
        OUT_BEGIN(struct ikeCertHdr, pxCertHdr, SIZEOF_IKE_CERT_HDR, ISAKMP_NEXT_CERT)
        pxCertHdr->oEncoding = CERT_X509_SIGNATURE;
        OUT_END
    }
    else
#endif

    for (; 0 < certNum; certNum--, pxCertDesc++)
    {
        ubyte *poCertificate = pxCertDesc->poCertificate;
        ubyte2 wBodyLen = pxCertDesc->wCertLen;

        /* certificate payload header */
        OUT_BEGIN(struct ikeCertHdr, pxCertHdr, SIZEOF_IKE_CERT_HDR, ISAKMP_NEXT_CERT)

        pxCertHdr->oEncoding = CERT_X509_SIGNATURE;

        /* certificate data */
        DIGI_MEMCPY(ctx->pBuffer, poCertificate, wBodyLen);

        /* done */
        OUT_END
    }

exit:
    return status;
} /* OutCert */


/*------------------------------------------------------------------*/

static MSTATUS
OutSig(IKE_context ctx)
{
    MSTATUS status = OK;
#ifdef __ENABLE_DIGICERT_CHECK_RSA_BAD_SIGNATURE__
    intBoolean validSig = FALSE;
    ubyte *pOutBuffer = NULL;
#endif

    IKESA pxSa = ctx->pxSa;

    IKE_certDescr pxCertDesc = pxSa->pCertChain;
    AsymmetricKey *pxPrivKey = (NULL == pxCertDesc) ? NULL :
                               pxCertDesc->pxPrivKey;


    /* This is only used when crypto interface is enabled */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    ubyte *pTmpSig = NULL;
    ubyte *pTmpHash = NULL;
    ubyte4 tmpHashLen = 0;
#endif

    ubyte4 sigLen;
    ubyte2 wSigLen;
    vlong *pVlongQueue = NULL;

    ubyte *pRetSignature = NULL;
    ubyte4 retSignatureLen = 0;
#ifdef __ENABLE_DIGICERT_PQC__
    QS_CTX *pQsCtx;
    ubyte4 qsSigLen;
#endif

    ubyte __crypto__(poHash, IKE_HASH_MAX);
    const BulkHashAlgo *pBHAlgo;
    IKE_authMtdInfo * pAuthMtdInfo;

#ifdef __ENABLE_DIGICERT_ECC__
    ubyte *poEcdsaSig = NULL;
    ubyte4 elementLen = 0;

    if (NULL != pxSa->poEcdsaSig) /* in case of re-transmission */
    {
        status = OutGen(ctx, ISAKMP_NEXT_SIG,
                        pxSa->wEcdsaSigLen, pxSa->poEcdsaSig);
        goto exit;
    }

    /* ECDSA-specific SIG Hash Algo */
    pAuthMtdInfo = IKE_authMtdEx(pxSa->ikePeerConfig, BASE_AUTH_MTD(pxSa), 0);
    if(NULL == pAuthMtdInfo)
    {
        DB_PRINT("Auth method match failure for wauth=%d oauth=%d", BASE_AUTH_MTD(pxSa), 0);
        status = ERR_IKE_MISMATCH_AUTH_METHOD;
        goto exit;
    }

    pBHAlgo = pAuthMtdInfo->pBHAlgo;
    if (NULL == pBHAlgo)
#endif
    pBHAlgo = pxSa->pHashSuite->pBHAlgo;

    /* calculate HASH_I/R */
    _CRYPTO_ALLOC_(poHash, IKE_HASH_MAX)
    if (OK > (status = DoHash(ctx, poHash, FALSE, pBHAlgo)))
        goto exit;

    if (NULL == pxPrivKey) /* no private key */
    {
        /* external signing */
        if (NULL != pxSa->ikePeerConfig->funcPtrSignHash)
        {
            /* signature data - private key encryption */
            if (OK > (status = (MSTATUS)
                               pxSa->ikePeerConfig->funcPtrSignHash(
                                            poHash, pBHAlgo->digestSize,
                                            &pRetSignature, &retSignatureLen,
                                            pxSa->serverInstance, pxSa)))
                DBG_EXIT

            /* signature length */
            wSigLen = (ubyte2)retSignatureLen;

            /* generic header */
            if (OK != (status = OutGen(ctx, ISAKMP_NEXT_SIG, wSigLen, NULL)))
                goto exit;

            DIGI_MEMCPY(ctx->pBuffer - wSigLen, pRetSignature, retSignatureLen);
        }
        else
        {
            status = ERR_IKE_NO_CERT;
            DBG_EXIT
        }
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if (akt_ecc == pxPrivKey->type
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
          || akt_tap_ecc == pxPrivKey->type
#endif
             ) /* ECDSA */
    {
        ECCKey *pECCKey = pxPrivKey->key.pECC;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(pECCKey, &elementLen);
        if (OK != status)
            goto exit;
#else
        status = EC_getElementByteStringLen(pECCKey, &elementLen);
        if (OK != status)
            goto exit;
#endif

        wSigLen = (ubyte2)(elementLen * 2);
        CHECK_MALLOC(poEcdsaSig, wSigLen)

        status = OutGen(ctx, ISAKMP_NEXT_SIG, wSigLen, NULL);
        if (OK != status)
            goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_ECDSA_signDigestAux (MOC_ECC(ctx->hwAccelCookie)
            pECCKey, RANDOM_rngFun, g_pRandomContext, poHash, pBHAlgo->digestSize,
            poEcdsaSig, elementLen * 2, &sigLen);
        if (OK != status)
            goto exit;
#else
        status = ECDSA_signDigest (MOC_ECC(ctx->hwAccelCookie)
            pECCKey, RANDOM_rngFun, g_pRandomContext, poHash, pBHAlgo->digestSize,
            poEcdsaSig, elementLen * 2, &sigLen);
        if (OK != status)
            goto exit;
#endif
        pxSa->wEcdsaSigLen = wSigLen;
        pxSa->poEcdsaSig = poEcdsaSig;

        status = DIGI_MEMCPY (
            (void *)(ctx->pBuffer - sigLen), (void *)poEcdsaSig, sigLen);
        poEcdsaSig = NULL;
        if (OK != status)
            goto exit;
    }
#endif /* __ENABLE_DIGICERT_ECC__ */
#if defined(__ENABLE_DIGICERT_PQC__) && defined(__ENABLE_DIGICERT_ECC__)
    else if (akt_hybrid == (pxPrivKey->type & 0xff))
    {
        ECCKey *pECCKey = pxPrivKey->key.pECC;
        pQsCtx = pxPrivKey->pQsCtx;
        status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(pECCKey, (ubyte4 *)&sigLen);
        if (OK != status)
            goto exit;

        wSigLen = (ubyte2)(sigLen * 2);

        status = CRYPTO_INTERFACE_QS_SIG_getSignatureLen(pQsCtx, &qsSigLen);
        if (OK != status)
            goto exit;

        wSigLen = (wSigLen + (ubyte2)qsSigLen);
        CHECK_MALLOC(poEcdsaSig, wSigLen)


        status = CRYPTO_INTERFACE_ECDSA_signDigestAux(MOC_ECC(ctx->hwAccelCookie)
            pECCKey, RANDOM_rngFun, g_pRandomContext, poHash, pBHAlgo->digestSize,
            poEcdsaSig, sigLen * 2, &sigLen);
        if (OK != status)
            goto exit;
        status = CRYPTO_INTERFACE_QS_SIG_sign(MOC_HASH(ctx->hwAccelCookie) pQsCtx, RANDOM_rngFun,
            g_pRandomContext, poHash, pBHAlgo->digestSize, poEcdsaSig + sigLen,
            qsSigLen, &qsSigLen);
        if (OK != status)
            goto exit;

        wSigLen = (sigLen + (ubyte2)qsSigLen);

        pxSa->wEcdsaSigLen = wSigLen;
        pxSa->poEcdsaSig = poEcdsaSig;

        status = OutGen(ctx, ISAKMP_NEXT_SIG, wSigLen, NULL);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY (
            (void *)(ctx->pBuffer - wSigLen), (void *)poEcdsaSig, wSigLen);
        poEcdsaSig = NULL;
        if (OK != status)
            goto exit;

    }
#endif
    else if (akt_rsa == pxPrivKey->type
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
          || akt_tap_rsa == pxPrivKey->type
#endif
             ) /* RSA */
    {
        RSAKey *pRSAKey = pxPrivKey->key.pRSA;

        /* signature length */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if (OK > (status = CRYPTO_INTERFACE_getRSACipherTextLength( MOC_RSA(ctx->hwAccelCookie)
                                                            pRSAKey, (sbyte4 *) &sigLen,
                                                            pxPrivKey->type)))
#else
        if (OK > (status = RSA_getCipherTextLength(MOC_RSA(ctx->hwAccelCookie) pRSAKey, (sbyte4 *)&sigLen)))
#endif
            DBG_EXIT

        wSigLen = (ubyte2)sigLen;

        /* generic header */
        if (OK != (status = OutGen(ctx, ISAKMP_NEXT_SIG, wSigLen, NULL)))
            goto exit;

        /* signature data - private key encryption */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        /*  RFC 2409:
         *      RSA signatures MUST be encoded as a private key encryption in
         *      PKCS #1 format and not as a signature in PKCS #1 format.
         *
         *  CRYPTO_INTERFACE_TAP_RSA_signDigestInfo, which is called by
         *  CRYPTO_INTERFACE_RSA_signMessageAux when provided a TAP key,
         *  expects a DigestInfo buffer as specified by RFC 3447, Section 9.2.
         *
         *  Therefore, it is necessary to do the PKCS #1 encoding separately
         *  without the OID, then apply private key over the buffer.
         **/
        if (akt_tap_rsa == pxPrivKey->type)
        {
            tmpHashLen = wSigLen;
            status = DIGI_MALLOC((void**)&pTmpHash, tmpHashLen);
            if (OK != status)
                DBG_EXIT

            status = RsaPadPkcs15(poHash, pBHAlgo->digestSize, MOC_ASYM_KEY_FUNCTION_SIGN, RANDOM_rngFun, g_pRandomContext,
                pTmpHash, tmpHashLen);
            if (OK != status)
                DBG_EXIT

            if (OK > (status = CRYPTO_INTERFACE_RSA_applyPrivateKeyAux(MOC_RSA(ctx->hwAccelCookie)
                                               pRSAKey,RANDOM_rngFun, g_pRandomContext, pTmpHash, tmpHashLen,
                                               &pTmpSig, &pVlongQueue)))
                DBG_EXIT

            status = DIGI_MEMCPY(ctx->pBuffer - wSigLen, pTmpSig, wSigLen);
            if (OK != status)
                goto exit;

#ifdef __ENABLE_DIGICERT_CHECK_RSA_BAD_SIGNATURE__
            status = CRYPTO_INTERFACE_RSA_applyPublicKeyAux(MOC_RSA(ctx->hwAccelCookie) pRSAKey, pTmpSig, wSigLen,
                                                    &pOutBuffer, &pVlongQueue);
            if(OK != status)
                goto exit;

            validSig = TRUE;
            for(int i = 0; i < wSigLen; i++)
            {
                if (pOutBuffer[i] != pTmpHash[i])
                {
                    validSig = FALSE;
                    break;
                }
            }
            DIGI_FREE((void **) &pOutBuffer);

            if (validSig == FALSE)
            {
                status = ERR_IKE_BAD_SIG;
                goto exit;
            }
#endif
        }
        else
        {
            if (OK > (status = CRYPTO_INTERFACE_RSA_signMessageAux(MOC_RSA(ctx->hwAccelCookie)
                                               pRSAKey, poHash, pBHAlgo->digestSize,
                                               ctx->pBuffer - wSigLen, &pVlongQueue)))
                DBG_EXIT

#ifdef __ENABLE_DIGICERT_CHECK_RSA_BAD_SIGNATURE__
            status = CRYPTO_INTERFACE_RSA_verifyDigest(MOC_RSA(ctx->hwAccelCookie) pRSAKey, poHash, pBHAlgo->digestSize,
                                                    ctx->pBuffer - wSigLen, wSigLen, &validSig, NULL);
            if(OK != status)
                goto exit;

            if (validSig == FALSE)
            {
                status = ERR_IKE_BAD_SIG;
                goto exit;
            }
#endif
        }
#else
        if (OK > (status = RSA_signMessage(MOC_RSA(ctx->hwAccelCookie)
                                           pRSAKey, poHash, pBHAlgo->digestSize,
                                           ctx->pBuffer - wSigLen, &pVlongQueue)))
            DBG_EXIT

#ifdef __ENABLE_DIGICERT_CHECK_RSA_BAD_SIGNATURE__
        status = RSA_verifyDigest(MOC_RSA(ctx->hwAccelCookie) pRSAKey, poHash, pBHAlgo->digestSize,
                                                ctx->pBuffer - wSigLen, wSigLen, &validSig, NULL);
        if(OK != status)
            goto exit;

        if (validSig == FALSE)
        {
            status = ERR_IKE_BAD_SIG;
            goto exit;
        }
#endif
#endif
    }
    else /* jic - invalid host certificate */
    {
        status = ERR_IKE_NO_CERT;
        DBG_EXIT
    }

exit:
    if (pRetSignature && pxSa->ikePeerConfig->funcPtrReleaseSig)
    {
        pxSa->ikePeerConfig->funcPtrReleaseSig(pRetSignature);
    }
#ifdef __ENABLE_DIGICERT_ECC__
    CHECK_FREE(poEcdsaSig)
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (NULL != pTmpHash)
    {
        DIGI_FREE((void**)&pTmpHash);
    }

    if (NULL != pTmpSig)
    {
        DIGI_FREE((void**)&pTmpSig);
    }
#endif

    VLONG_freeVlongQueue(&pVlongQueue);
    _CRYPTO_FREE_(poHash)
    return status;
} /* OutSig */


/*------------------------------------------------------------------*/

static MSTATUS
OutHash(IKE_context ctx)
{
    MSTATUS status;

    const BulkHashAlgo *pBHAlgo = ctx->pxSa->pHashSuite->pBHAlgo;
    ubyte2 wDigestLen = (ubyte2) pBHAlgo->digestSize;

    /* generic header */
    if (OK != (status = OutGen(ctx, ISAKMP_NEXT_HASH, wDigestLen, NULL)))
        goto exit;

    /* hash data */
    if (OK > (status = DoHash(ctx, ctx->pBuffer - wDigestLen, FALSE, pBHAlgo)))
        goto exit;

exit:
    return status;
} /* OutHash */


/*------------------------------------------------------------------*/

extern MSTATUS
OutHashGen(IKE_context ctx)
{
    return OutGen(ctx, ISAKMP_NEXT_HASH,
                  (ubyte2) ctx->pxSa->pHashSuite->pBHAlgo->digestSize,
                  NULL);
} /* OutHashGen */


/*------------------------------------------------------------------*/

extern MSTATUS
OutHash12(IKE_context ctx)
{
    ubyte2 wDigestLen = (ubyte2) ctx->pxSa->pHashSuite->pBHAlgo->digestSize;

    /* get all payloads following HASH(1/2) payload */
    ubyte4 dwLength = ctx->dwLength /* message length */
                    - SIZEOF_ISAKMP_HDR /* ISAKMP header */
                    - (SIZEOF_IKE_GEN_HDR + wDigestLen); /* HASH(1/2) payload */
    ubyte *poBuf = ctx->pBuffer - dwLength;

    return DoHash12(ctx, dwLength, poBuf, poBuf - wDigestLen);
} /* OutHash12 */


/*------------------------------------------------------------------*/

static MSTATUS
OutHash3(IKE_context ctx)
{
    MSTATUS status;

    ubyte2 wDigestLen = (ubyte2) ctx->pxSa->pHashSuite->pBHAlgo->digestSize;

    /* generic header */
    if (OK != (status = OutGen(ctx, ISAKMP_NEXT_HASH, wDigestLen, NULL)))
        goto exit;

    /* hash data */
    if (OK > (status = DoHash3(ctx, ctx->pBuffer - wDigestLen)))
        goto exit;

exit:
    return status;
} /* OutHash3 */


/*------------------------------------------------------------------*/

static MSTATUS
OutInfoRespLife(IKE_context ctx)
{
    MSTATUS status = OK;

    /* Note: called from quickR1_out() only */
    IPSECSA pxIPsecSa = P2XG_IPSECSA(ctx->pxP2Xg);
    IKESA pxSa = ctx->pxSa;
    sbyte4 i, j;

    ubyte4 ikeP2LifeSecsMax = pxSa->ikePeerConfig->ikeP2LifeSecsMax;
    ubyte4 ikeP2LifeKBytesMax = pxSa->ikePeerConfig->ikeP2LifeKBytesMax;

    /* RESPONDER-LIFETIME */
    for (i = pxIPsecSa->oP2SaNum - 1; i >= 0; i--)
    {
        for (j = pxIPsecSa->axP2Sa[i].oChildSaLen - 1; j >= 0; j--)
        {
            IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[i].axChildSa[j].ipsecPps);

            ubyte4 dwExpSecs = pxIPsecPps->dwAdjSecs;
            ubyte4 dwExpKBytes = pxIPsecPps->dwAdjKBytes;

            /* adjust lifetime */
            if (!(IKE_CHILD_FLAG_LIFETIME & pxIPsecSa->c_flags)) /* jic re-transmission */
            {
                /* This fixes the issue where quick mode RESPONDER-LIFETIME notification is not
                   accepted by MS Windows 10. We add a margin lifetime to the already configured
                   IPsec SA lifetime if the initiator's proposed lifetime is > responder's configured
                   lifetime. How much this margin lifetime should be is at the user's discretion.
                */
#ifdef __ENABLE_IPSEC_MARGIN_LIFETIME__
                if (0 != g_IkeP2MarginLifeSecs)
                {
#else
                if (0 != IPSEC_SA_MARGIN_LIFETIME)
                {
                    ubyte4 g_IkeP2MarginLifeSecs = IPSEC_SA_MARGIN_LIFETIME;
#endif
                    if (dwExpSecs > ikeP2LifeSecsMax)
                    {
                        pxSa->ikePeerConfig->ikeP2LifeSecsMax += g_IkeP2MarginLifeSecs;
                        ikeP2LifeSecsMax = pxSa->ikePeerConfig->ikeP2LifeSecsMax;
                        debug_print("INFO: Initiator proposed higher lifetime, adjusting responder's lifetime to ");
                        debug_uint(ikeP2LifeSecsMax);
                        debug_printnl(" seconds");
                    }
                }

                /* seconds */
                if ((0 != ikeP2LifeSecsMax) &&
                    ((0 == dwExpSecs) || (ikeP2LifeSecsMax < dwExpSecs)))
                {
                    dwExpSecs = ikeP2LifeSecsMax;
                }

                if (0 != dwExpSecs)
                {
                    if (IKE_LIFE_SECS_MAX < dwExpSecs)
                        dwExpSecs = IKE_LIFE_SECS_MAX;

                    if (0 != pxIPsecPps->dwExpSecs) /* proposed by peer */
                    {
                        if (dwExpSecs >= pxIPsecPps->dwExpSecs)
                            dwExpSecs = 0; /* no adjustment */
                    }
                    else if (0 == pxIPsecPps->dwExpKBytes) /* unspecified (peer) */
                    {
                        /* assuming 8 hours (RFC2407 4.5, p.13) */
                        if (28800 <= dwExpSecs)
                            dwExpSecs = 0; /* no adjustment */
                    }
                }
                else /* unspecified */
                {
                    if (IKE_LIFE_SECS_MAX < pxIPsecPps->dwExpSecs)
                        dwExpSecs = IKE_LIFE_SECS_MAX;
                }

                pxIPsecPps->dwAdjSecs = dwExpSecs;

                /* kbytes */
                if ((0 != ikeP2LifeKBytesMax) &&
                    ((0 == dwExpKBytes) || (ikeP2LifeKBytesMax < dwExpKBytes)))
                {
                    dwExpKBytes = ikeP2LifeKBytesMax;
                }

                if ((0 != dwExpKBytes) &&
                    (0 != pxIPsecPps->dwExpKBytes) &&  /* proposed by peer */
                    (dwExpKBytes >= pxIPsecPps->dwExpKBytes))
                {
                    dwExpKBytes = 0; /* no adjustment */
                }

                pxIPsecPps->dwAdjKBytes = dwExpKBytes;
            }

            if (dwExpSecs || dwExpKBytes)
            {
                ubyte4 dwLength;
                ubyte *poNextPayload;
                void *pHdrParent;

                ubyte4 dwSpi = pxIPsecPps->dwSpi[_R];

                /* notification payload header */
                OUT_TOP(struct ikeNotifyHdr, pxNotifyHdr, SIZEOF_IKE_NOTIFY_HDR, ISAKMP_NEXT_N)

                pxNotifyHdr->oDoi = ISAKMP_DOI_IPSEC;
                pxNotifyHdr->oProtoId = pxIPsecPps->oProtocol;
                pxNotifyHdr->oSpiSize = sizeof(dwSpi);
                SET_HTONS(pxNotifyHdr->wMsgType, IPSEC_RESPONDER_LIFETIME);

                OUT_DOWN(pxNotifyHdr)

                debug_print("   Notify: ");
                debug_print_ike_notify(IPSEC_RESPONDER_LIFETIME);
                debug_print(" (");
                debug_print_ike_proto(pxIPsecPps->oProtocol);
                debug_print(" spi=");
                debug_hexint(dwSpi);
                debug_print(") ");
                if (dwExpSecs)
                {
                    debug_uint(dwExpSecs);
                    debug_print("-SECONDS ");
                }
                if (dwExpKBytes)
                {
                    debug_uint(dwExpKBytes);
                    debug_print("-KILOBYTES ");
                }
                debug_printnl(NULL);

                /* SPI */
                if (ctx->dwBufferSize < sizeof(dwSpi))
                {
                    status = ERR_IKE_BUFFER_OVERFLOW;
                    DBG_EXIT
                }

                SET_HTONL(pxNotifyHdr->dwSpi, dwSpi);
                ADVANCE(sizeof(dwSpi))

                /* sa attributes */
                if (dwExpSecs && /* IPsec SA life type/duration - secs */
                    (OK != (status = OutAttrLife(ctx, SA_LIFE_TYPE, SA_LIFE_TYPE_SECONDS, SA_LIFE_DURATION,
                                                 dwExpSecs))))
                    goto exit;

                if (dwExpKBytes && /* IPsec SA life type/duration - kbytes */
                    (OK != (status = OutAttrLife(ctx, SA_LIFE_TYPE, SA_LIFE_TYPE_KBYTES, SA_LIFE_DURATION,
                                                 dwExpKBytes))))
                    goto exit;

                /* done */
                OUT_UP(pxNotifyHdr)

            } /* if (dwExpSecs || dwExpKBytes) */

        } /* for (j= */
    } /* for (i= */

    pxIPsecSa->c_flags |= IKE_CHILD_FLAG_LIFETIME; /* jic re-transmission */

exit:
    return status;
} /* OutInfoRespLife */


/*------------------------------------------------------------------*/

static void
DoRespLife1(IKESA pxSa)
{
    /* adjust phase 1 lifetime - responder only */
    ubyte4 ikeP1LifeKBytesMax, ikeP1LifeSecsMax;

#ifdef CUSTOM_IKE_GET_P1_LIFEKBYTES
    ikeP1LifeKBytesMax = pxSa->dwExpKBytes;
    if (OK > CUSTOM_IKE_GET_P1_LIFEKBYTES(&ikeP1LifeKBytesMax,
                        REF_MOC_IPADDR(pxSa->dwPeerAddr),
                        _IN, FALSE
                        MOC_MTHM_REQ_VALUE(pxSa->serverInstance)))
#endif
        ikeP1LifeKBytesMax = pxSa->ikePeerConfig->ikeP1LifeKBytesMax;

#ifdef CUSTOM_IKE_GET_P1_LIFESECS
    ikeP1LifeSecsMax = pxSa->dwExpSecs;
    if (OK > CUSTOM_IKE_GET_P1_LIFESECS(&ikeP1LifeSecsMax,
                        REF_MOC_IPADDR(pxSa->dwPeerAddr),
                        _IN, FALSE
                        MOC_MTHM_REQ_VALUE(pxSa->serverInstance)))
#endif
        ikeP1LifeSecsMax = pxSa->ikePeerConfig->ikeP1LifeSecsMax;

    if (IKE_LIFE_SECS_MAX < ikeP1LifeSecsMax)
        ikeP1LifeSecsMax = IKE_LIFE_SECS_MAX;

    if ((0 != ikeP1LifeSecsMax) && /* seconds */
        ((0 == pxSa->dwExpSecs) ||
         (pxSa->dwExpSecs > ikeP1LifeSecsMax)))
    {
        pxSa->dwExpSecs = ikeP1LifeSecsMax;
        pxSa->flags |= IKE_SA_FLAG_LIFETIME_SECS;
    }

    if ((0 != ikeP1LifeKBytesMax) && /* kbytes */
        ((0 == pxSa->dwExpKBytes) ||
         (pxSa->dwExpKBytes > ikeP1LifeKBytesMax)))
    {
        pxSa->dwExpKBytes = ikeP1LifeKBytesMax;
        pxSa->flags |= IKE_SA_FLAG_LIFETIME_KBYTES;
    }

    return;
} /* DoRespLife1 */


/*------------------------------------------------------------------*/

static MSTATUS
OutInfoRespLife1(IKE_context ctx)
{
    MSTATUS status = OK;

    /* Note: called from mainR3_out() only */
    IKESA pxSa = ctx->pxSa;
    if (!(IKE_SA_FLAG_LIFETIME & pxSa->flags)) /* in case of re-transmission */
    {
        DoRespLife1(pxSa);
        pxSa->flags |= IKE_SA_FLAG_LIFETIME;
    }

    /* RESPONDER-LIFETIME */
    if ((IKE_SA_FLAG_LIFETIME_SECS | IKE_SA_FLAG_LIFETIME_KBYTES) & pxSa->flags)
    {
        ubyte4 dwExpSecs = (IKE_SA_FLAG_LIFETIME_SECS & pxSa->flags)
                         ? pxSa->dwExpSecs : 0;
        ubyte4 dwExpKBytes = (IKE_SA_FLAG_LIFETIME_KBYTES & pxSa->flags)
                           ? pxSa->dwExpKBytes : 0;

        ubyte4 dwLength;
        ubyte *poNextPayload;
        void *pHdrParent;

        /* notification payload header */
        OUT_TOP(struct ikeNotifyHdr, pxNotifyHdr, SIZEOF_IKE_NOTIFY_HDR, ISAKMP_NEXT_N)

        pxNotifyHdr->oDoi = ISAKMP_DOI_IPSEC;
        pxNotifyHdr->oProtoId = PROTO_ISAKMP;
        SET_HTONS(pxNotifyHdr->wMsgType, IPSEC_RESPONDER_LIFETIME);

        OUT_DOWN(pxNotifyHdr)

        debug_print("   Notify: ");
        debug_print_ike_notify(IPSEC_RESPONDER_LIFETIME);
        debug_print(" ");
        if (dwExpSecs)
        {
            debug_uint(dwExpSecs);
            debug_print("-SECONDS ");
        }
        if (dwExpKBytes)
        {
            debug_uint(dwExpKBytes);
            debug_print("-KILOBYTES ");
        }
        debug_printnl(NULL);

        /* sa attributes */
        if (dwExpSecs && /* ISAKMP SA life type/duration - secs */
            (OK != (status = OutAttrLife(ctx, OAKLEY_LIFE_TYPE, OAKLEY_LIFE_SECONDS, OAKLEY_LIFE_DURATION,
                                         dwExpSecs))))
            goto exit;

        if (dwExpKBytes && /* ISAKMP SA life type/duration - kbytes */
            (OK != (status = OutAttrLife(ctx, OAKLEY_LIFE_TYPE, OAKLEY_LIFE_KILOBYTES, OAKLEY_LIFE_DURATION,
                                         dwExpKBytes))))
            goto exit;

        /* done */
        OUT_UP(pxNotifyHdr)

    } /* if (dwExpSecs || dwExpKBytes) */

exit:
    return status;
} /* OutInfoRespLife1 */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)

static MSTATUS
OutNotifyHashPsk(IKE_context ctx)
{
    MSTATUS status;

    /* called by Hybrid-RSA client only */
    IKESA pxSa = ctx->pxSa;

    if (OK > (status = IKE_getPsk(NULL, NULL, pxSa, 0)))
    {
        if (ERR_IKE_NULL_PSK == status) /* no PSK */
        {
            status = OK; /* skip it */
            goto exit;
        }
        DBG_EXIT
    }
    else
    {
        /* PRESHARED_KEY_HASH */
        const BulkHashAlgo *pBHAlgo = pxSa->pHashSuite->pBHAlgo;
        ubyte2 wDigestLen = (ubyte2) pBHAlgo->digestSize;

        ubyte2 wBodyLen = (ubyte2)IKE_P1_SPI_SIZE + wDigestLen;

        /* notification payload header */
        OUT_BEGIN(struct ikeNotifyHdr, pxNotifyHdr, SIZEOF_IKE_NOTIFY_HDR, ISAKMP_NEXT_N)

        if (OK > (status = DoHashPsk(ctx, ctx->pBuffer + IKE_P1_SPI_SIZE, pBHAlgo)))
        {
            goto exit;
        }

        pxNotifyHdr->oDoi = ISAKMP_DOI_IPSEC;
        pxNotifyHdr->oProtoId = PROTO_ISAKMP;
        pxNotifyHdr->oSpiSize = IKE_P1_SPI_SIZE;
        SET_HTONS(pxNotifyHdr->wMsgType, PRESHARED_KEY_HASH);

        DIGI_MEMCPY(ctx->pBuffer, pxSa->poCky_I, IKE_COOKIE_SIZE);
        DIGI_MEMCPY(ctx->pBuffer + IKE_COOKIE_SIZE, pxSa->poCky_R, IKE_COOKIE_SIZE);

        debug_print("   Notify: ");
        debug_print_ike_notify(PRESHARED_KEY_HASH);
        debug_print(" (");
        debug_print_ike_proto(PROTO_ISAKMP);
        debug_print(" spi=");
        debug_printr(ctx->pBuffer, IKE_P1_SPI_SIZE, FALSE);
        debug_printnl(")");

        /* done */
        OUT_END
    }

exit:
    return status;
} /* OutNotifyHashPsk */

#endif /* defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__) */


/*------------------------------------------------------------------*/

static MSTATUS
DoOutNotify(IKE_context ctx, ubyte2 wMsgType)
{
    MSTATUS status = OK;

    /* notification payload header */
    OUT_TOP(struct ikeNotifyHdr, pxNotifyHdr, SIZEOF_IKE_NOTIFY_HDR, ISAKMP_NEXT_N)

    pxNotifyHdr->oDoi = ISAKMP_DOI_IPSEC;
    pxNotifyHdr->oProtoId = PROTO_ISAKMP;
    SET_HTONS(pxNotifyHdr->wMsgType, wMsgType);

    debug_print("   Notify: ");
    debug_print_ike_notify(wMsgType);
    debug_print(" (");
    debug_print_ike_proto(PROTO_ISAKMP);
    debug_printnl(")");

exit:
    return status;
} /* DoOutNotify */


/*------------------------------------------------------------------*/

static MSTATUS
OutInfo(IKE_context ctx)
{
    MSTATUS status = OK;

    IKEINFO pxInfo = ctx->pxInfo;
    IKEINFO_notify pxNotify = pxInfo->pxNotify;
    IKEINFO_delete pxDelete = pxInfo->pxDelete;

    IKESA pxSa;

    if (NULL != pxNotify)
    {
        ubyte4 dwSpi = pxNotify->dwSpi;
        ubyte oSpiSize = (ubyte)(dwSpi ? sizeof(ubyte4) :
                                 ((IKE_P1_SPI_SIZE <= pxNotify->oSpiSize)
                                  ? IKE_P1_SPI_SIZE : pxNotify->oSpiSize));
        ubyte2 wBodyLen = (ubyte2)oSpiSize + pxNotify->wDataLen;

        /* notification payload header */
        OUT_BEGIN(struct ikeNotifyHdr, pxNotifyHdr, SIZEOF_IKE_NOTIFY_HDR, ISAKMP_NEXT_N)

        pxNotifyHdr->oDoi = ISAKMP_DOI_IPSEC;
        pxNotifyHdr->oProtoId = pxNotify->oProtoId;
        pxNotifyHdr->oSpiSize = oSpiSize;
        SET_HTONS(pxNotifyHdr->wMsgType, pxNotify->wMsgType);

        debug_print("   Notify: ");
        debug_print_ike_notify(pxNotify->wMsgType);
        debug_print(" (");
        debug_print_ike_proto(pxNotify->oProtoId);

        /* SPI */
        if (dwSpi)
        {
            SET_HTONL(pxNotifyHdr->dwSpi, dwSpi);

            debug_print(" spi=");
            debug_hexint(dwSpi);
        }
        else if (oSpiSize)
        {
            if (NULL == (pxSa = ctx->pxSa))
            {
                status = ERR_IKE; /* jic */
                DBG_EXIT
            }

            DIGI_MEMCPY(ctx->pBuffer, pxSa->poCky_I,
                ((IKE_COOKIE_SIZE > oSpiSize) ? oSpiSize : IKE_COOKIE_SIZE));

            if (IKE_COOKIE_SIZE < oSpiSize)
                DIGI_MEMCPY(ctx->pBuffer + IKE_COOKIE_SIZE,
                           pxSa->poCky_R, (oSpiSize - IKE_COOKIE_SIZE));

            debug_print(" spi=");
            debug_printr(ctx->pBuffer, (sbyte4)oSpiSize, FALSE);
        }
        debug_printnl(")");

        /* notification data */
        if ((NULL != pxNotify->poData) && pxNotify->wDataLen)
            DIGI_MEMCPY(ctx->pBuffer + oSpiSize, pxNotify->poData, pxNotify->wDataLen);

        /* done */
        OUT_END
    }

    if (NULL != pxDelete)
    {
        ubyte4 dwSpi = pxDelete->dwSpi;
        ubyte oSpiSize = (ubyte)(dwSpi ? sizeof(ubyte4) : IKE_P1_SPI_SIZE);
        ubyte2 wBodyLen = oSpiSize;

        /* delete payload header */
        OUT_BEGIN(struct ikeDelHdr, pxDelHdr, SIZEOF_IKE_DEL_HDR, ISAKMP_NEXT_D)

        pxDelHdr->oDoi = ISAKMP_DOI_IPSEC;
        pxDelHdr->oProtoId = pxDelete->oProtoId;
        pxDelHdr->oSpiSize = oSpiSize;
        SET_HTONS(pxDelHdr->wSpiNum, 1);

        debug_print3(
            "   Deleted: 1 ",
            ((PROTO_ISAKMP == pxDelHdr->oProtoId) ? "ISAKMP" : "IPsec"),
            " SA");

        /* SPI */
        if (dwSpi)
        {
            SET_HTONL(pxDelHdr->adwSpi[0], dwSpi);

            debug_print("    IPSEC_delSa(");
            debug_print_ike_proto(pxDelHdr->oProtoId);
            debug_print(" spi=");
            debug_hexint(dwSpi);
            debug_print(" src=");
            debug_print_ip(REF_MOC_IPADDR(ctx->pxSa->dwPeerAddr));
            debug_printnl(")");
        }
        else
        {
            if (NULL == (pxSa = pxDelete->pxSa))
            {
                status = ERR_IKE; /* jic */
                DBG_EXIT
            }
            DIGI_MEMCPY(ctx->pBuffer, pxSa->poCky_I, IKE_COOKIE_SIZE);
            DIGI_MEMCPY(ctx->pBuffer + IKE_COOKIE_SIZE, pxSa->poCky_R, IKE_COOKIE_SIZE);

            debug_print("    IKE_delSa(peer=");
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


/*------------------------------------------------------------------*/

extern MSTATUS
InAttrBV(IKE_context ctx, ubyte2 *type, ubyte2 *len, ubyte2 *value, ubyte4 *value1)
{
    MSTATUS status = OK;

    struct ikeAttr0 *pxAttr0;

    IN_HDR(struct ikeAttr, pxAttr, SIZEOF_IKE_ATTR)

    pxAttr0 = (struct ikeAttr0 *) pxAttr;
    *len = 0;
    *value = 0;
    *value1 = 0;

    if (pxAttr0->oAF & 0x80) /* TV (B) */
    {
        SET_NTOHS(*value, pxAttr->wLenVal);
        SET_NTOHS(*type, pxAttr->wAFtype);
        *type &= 0x7FFF;
    }
    else /* TLV (V) */
    {
        ubyte2 wLength;
        SET_NTOHS(wLength, pxAttr->wLenVal);

        if (ctx->dwBufferSize < (ubyte4)wLength)
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }

        if (0 == wLength)
        {
            status = ERR_IKE_BAD_ATTR;
            DBG_EXIT
        }

        SET_NTOHS(*type, pxAttr->wAFtype);
        *len = wLength;

        if (sizeof(ubyte4) == wLength)
        {
            SET_NTOHL(*value1, pxAttr->dwValue);
        }
        else if (sizeof(ubyte2) == wLength)
        {
            *value = DIGI_NTOHS(ctx->pBuffer);
            *value1 = (ubyte4) *value;
        }

        ADVANCE(wLength)
    }

exit:
    return status;
} /* InAttrBV */


/*------------------------------------------------------------------*/

#ifdef CUSTOM_IKE_GET_ENCR_ALGO

static intBoolean
SetEncrAlgo(ubyte2 wEncrAlgo, ubyte2 wKeyLen, IKESA pxSa)
{
    /* Note: 'wEncrAlgo' is valid */
    intBoolean bFail = FALSE;

    ikePeerConfig *config = pxSa->ikePeerConfig;
    IKE_cipherSuiteInfo *pCipherSuite = NULL;
    sbyte4 i;

    if (wKeyLen) /* verify given key length */
    {
        if (NULL == (pCipherSuite = IKE_cipherSuiteEx(config, wEncrAlgo, 0,
                                                      wKeyLen, NULL)))
        {
            bFail = TRUE; /* !!! */
            goto exit;
        }
    }

    for (i = pxSa->numEncrAlgos - 1; 0 <= i; i--)
    {
        if (wEncrAlgo == pxSa->pwEncrAlgos[i])
        {
            if (wKeyLen)
            {
                if (pxSa->pwEncrKeyLens[i] &&
                    (wKeyLen != pxSa->pwEncrKeyLens[i]))
                    continue;
            }
            else
            {
                wKeyLen = pxSa->pwEncrKeyLens[i];
                if (wKeyLen)
                    pCipherSuite = IKE_cipherSuiteEx(config, wEncrAlgo, 0,
                                                     wKeyLen, NULL);
                else
                    /* use default key length */
                    /* Warning: unpredictable behavior for variable-keylength algo! */
                    pCipherSuite = IKE_cipherSuiteEx(config, wEncrAlgo, 0,
                                                     0, &wKeyLen);

                if (NULL == pCipherSuite) /* jic */
                {
                    wKeyLen = 0; /* !!! */
                    continue;
                }
            }

            pxSa->pCipherSuite = pCipherSuite;
            pxSa->wEncrKeyLen = wKeyLen;
            goto exit; /* OK */
        }
    }

    bFail = TRUE; /* !!! */

exit:
    return bFail;
} /* SetEncrAlgo */

#endif


/*------------------------------------------------------------------*/

extern sbyte4 IKE_checkGroup(ubyte2 wGroup, intBoolean bInitiator,
                             IKESA pxSa0, IKESA pxSa, IPSECSA pxIPsecSa);

static MSTATUS
InAttrs(IKE_context ctx)
{
    MSTATUS status = ERR_IKE_MISMATCH;

    IKESA pxSa = ctx->pxSa;
    intBoolean bInitiator = IS_INITIATOR(pxSa);

    ubyte2 wType, wValue, wLength;
    ubyte2 wKeyLen = 0;
    ubyte4 dwValue;
    ubyte4 i;

    IKE_authMtdInfo *pAuthMtd = NULL;
    intBoolean bAuthMtdEnabled;

    ubyte2 wDhGrp = 0;
    if (bInitiator)
        wDhGrp = pxSa->u.v1.pwIsaAttr[OAKLEY_GROUP_DESCRIPTION];

    /* clean up */
    pxSa->pHashSuite = NULL;
    pxSa->pCipherSuite = NULL;
    pxSa->wEncrKeyLen = 0;

    DIGI_MEMSET((ubyte *) &(pxSa->u.v1.pwIsaAttr[0]), 0x00, sizeof(ubyte2) * NUM_OAKLEY_ATTRIBUTE_TYPE);

    if (!bInitiator)
    {
        pxSa->dwExpSecs = 0;
        pxSa->dwExpKBytes = 0;
    }

    debug_print("      ");

    /* SA attributes */
    for (;;)
    {
        MSTATUS st;

        /* get data attribute */
        if (0 == ctx->dwBufferSize) break;

        if (OK != (st = InAttrBV(ctx, &wType, &wLength, &wValue, &dwValue)))
        {
            if (!bInitiator)
            {
                if (ERR_IKE_BAD_LEN == st)
                    ctx->wMsgType = UNEQUAL_PAYLOAD_LENGTHS;
                else
                    ctx->wMsgType = PAYLOAD_MALFORMED;
            }
            status = st;
            goto exit;
        }

        /* required attribute */
        for (i=0; i < NUM_TFM_ATTR; i++)
        {
            /* match attr. type */
            if (wType != mTfmAttr[i].wType) continue;

            if (0 != wLength) /* must be TV (B) */
            {
                SET_MSGTYPE(PAYLOAD_MALFORMED)
                status = mTfmAttr[i].merror;
                DBG_NL_EXIT
            }

            /* attr. value supported? */
            switch (wType)
            {
            case OAKLEY_AUTHENTICATION_METHOD :
            {
#ifdef __ENABLE_IKE_XAUTH__
                sbyte4 xauthType = 0; /* 1 (client) or (2) server */
                ubyte2 wAuthMtd = wValue;
#ifdef __ENABLE_IKE_HYBRID_RSA__
                if (PROP_HYBRID_AUTH(pxSa))
                {
                    if (wValue % 2) /* HYBRID_INIT */
                        xauthType = (bInitiator ? 1 : 2);
                    else /* HYBRID_RESP */
                        xauthType = (bInitiator ? 2 : 1);

                    if (xauthType != pxSa->ikePeerConfig->xauthType)
                        goto no_match;

                    if ((HYBRID_INIT_RSA == wValue) || (HYBRID_RESP_RSA == wValue))
                        wAuthMtd = OAKLEY_RSA_SIG; /* rsa-sig only */
                    else
                        goto no_match;
                }
                else
#endif
                if (65000 < wValue)
                {
                    if (wValue % 2) /* XAUTHInit */
                        xauthType = (bInitiator ? 1 : 2);
                    else /* XAUTHResp */
                        xauthType = (bInitiator ? 2 : 1);

                    if (xauthType != pxSa->ikePeerConfig->xauthType)
                        goto no_match;

                    wAuthMtd = (ubyte2)((wValue - 64999) / 2);
                }
                else if (pxSa->ikePeerConfig->xauthType)
                {
                    if (4 <= pxSa->ikePeerConfig->xauthDraft)
                        goto no_match;
                }

                pAuthMtd = IKE_authMtdEx(pxSa->ikePeerConfig, wAuthMtd, 0);
#else
                pAuthMtd = IKE_authMtdEx(pxSa->ikePeerConfig, wValue, 0);
#endif
                if (NULL == pAuthMtd)
                    goto no_match;
                break;
            }
            case OAKLEY_HASH_ALGORITHM :
#ifdef CUSTOM_IKE_GET_HASH_ALGO
                if (0 < pxSa->numHashAlgos)
                {
                    sbyte4 j;
                    for (j = pxSa->numHashAlgos - 1; 0 <= j; j--)
                        if (wValue == pxSa->pwHashAlgos[j]) break;

                    if (0 > j) goto no_match;
                }
                else
#endif
                {
                    IKE_hashSuiteInfo *pHashSuite = IKE_hashSuiteEx(pxSa->ikePeerConfig, wValue, 0);
                    if ((NULL == pHashSuite) ||
                        pHashSuite->bDisabled[0][bInitiator ? _I : _R])
                        goto no_match;
                }
                break;

            case OAKLEY_ENCRYPTION_ALGORITHM :
#ifdef CUSTOM_IKE_GET_ENCR_ALGO
                if (0 < pxSa->numEncrAlgos)
                {
                    sbyte4 j;
                    for (j = pxSa->numEncrAlgos - 1; 0 <= j; j--)
                        if (wValue == pxSa->pwEncrAlgos[j]) break;

                    if (0 > j) goto no_match;
                }
                else
#endif
                if (NULL == IKE_cipherSuiteEx(pxSa->ikePeerConfig, wValue, 0, 0, NULL))
                    goto no_match;
                break;

            case OAKLEY_GROUP_DESCRIPTION :
                if (bInitiator && wDhGrp)
                {
                    if (wValue != wDhGrp) goto no_match;
                }
                else if (IKE_checkGroup(wValue, bInitiator, pxSa, pxSa, NULL))
                    goto no_match;
                break;

            default : /* should not get here */
                goto no_match; /* jic */
            }

            pxSa->u.v1.pwIsaAttr[wType] = wValue; /* set it */
            debug_print_ike_p1_attr_v(wValue, wType);
            debug_print(" ");
            break;

no_match:
            debug_print_ike_p1_attr_t(wType);
            debug_print(": ");
            debug_print_ike_p1_attr_v(wValue, wType);
            debug_printnl(bInitiator ? " mismatch" : " unsupported");

            SET_MERROR(mTfmAttr[i].merror)
            goto exit;

        } /* for (i=0; i < NUM_TFM_ATTR; i++) */

        /* optional attribute */
        switch (wType)
        {
        case OAKLEY_LIFE_TYPE :
            pxSa->u.v1.pwIsaAttr[OAKLEY_LIFE_TYPE] = wValue;
            break;
        case OAKLEY_LIFE_DURATION :     /* B/V */
            if (0 != wLength)
            {
                if ((ubyte2)sizeof(ubyte2) != wLength &&
                    (ubyte2)sizeof(ubyte4) != wLength)
                {
                    SET_MSGTYPE(PAYLOAD_MALFORMED)
                    status = ERR_IKE_BAD_ATTR;
                    DBG_NL_EXIT
                }
            }
            else dwValue = wValue;

            switch (pxSa->u.v1.pwIsaAttr[OAKLEY_LIFE_TYPE])
            {
            case OAKLEY_LIFE_SECONDS :
                debug_uint(dwValue);
                debug_print("-SECONDS ");

                if (bInitiator)
                {
                    if (dwValue != pxSa->dwExpSecs)
                    {
                        status = STATUS_IKE_LIFETIME_SECONDS;
                        debug_printnl("mismatch");
                        goto exit;
                    }
                }
                else
                {
                    if (dwValue && pxSa->ikePeerConfig->ikeP1LifeSecsMin &&
                        (dwValue < pxSa->ikePeerConfig->ikeP1LifeSecsMin))
                    {
                        debug_printnl("too short");
                        goto exit;
                    }
                    pxSa->dwExpSecs = dwValue;
                }
                break;
            case OAKLEY_LIFE_KILOBYTES :
                debug_uint(dwValue);
                debug_print("-KILOBYTES ");

                if (bInitiator)
                {
                    if (dwValue != pxSa->dwExpKBytes)
                    {
                        status = STATUS_IKE_LIFETIME_KBYTES;
                        debug_printnl("mismatch");
                        goto exit;
                    }
                }
                else
                {
                    pxSa->dwExpKBytes = dwValue;
                }
                break;
            default :
                status = ERR_IKE_BAD_ATTR;
                DBG_NL_EXIT
            }
            break;
        case OAKLEY_KEY_LENGTH :
            if (0 != wLength) /* must be TV (B) */
            {
                SET_MSGTYPE(PAYLOAD_MALFORMED)
                status = ERR_IKE_MISMATCH_KEYLEN;
                DBG_NL_EXIT
            }

            debug_int(wValue);
            debug_print("-BITS ");

            if (!wValue || (wValue % 8))
            {
                SET_MERROR(ERR_IKE_MISMATCH_KEYLEN)
                debug_printnl("unsupported");
                goto exit;
            }
            pxSa->u.v1.pwIsaAttr[OAKLEY_KEY_LENGTH] = wValue; /* in bits */
            wKeyLen = (ubyte2)(wValue/8);
            break;

        default : /* unknown attribute */
#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
            for (i=0; i < NUM_TFM_ATTR; i++)
                if (wType == mTfmAttr[i].wType) break;

            if (i >= NUM_TFM_ATTR)
            {
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
            }
#endif
            break;
        } /* switch */

    } /* for (;;) */

    /* check required attributes */
    for (i=0; i < NUM_TFM_ATTR; i++)
    {
        if (0 == pxSa->u.v1.pwIsaAttr[mTfmAttr[i].wType]) /* not set */
        {
            SET_MERROR(mTfmAttr[i].merror)
            debug_print_ike_p1_attr_t(mTfmAttr[i].wType);
            debug_printnl(": missing");
            goto exit;
        }
    }

    if (NULL == pAuthMtd) /* jic */
    {
        SET_MERROR(ERR_IKE_MISMATCH_AUTH_METHOD)
        debug_printnl("AUTH: mismatch");
        goto exit;
    }

    /* check authentication method */
    switch (pAuthMtd->wAuthMtd)
    {
    case OAKLEY_RSA_SIG :
#ifdef __ENABLE_DIGICERT_ECC__
    case OAKLEY_ECDSA_SIG :
    case OAKLEY_ECDSA_256 :
    case OAKLEY_ECDSA_384 :
    case OAKLEY_ECDSA_521 :
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    case OAKLEY_P256_MLDSA_44:
    case OAKLEY_P256_FNDSA512:
    case OAKLEY_P384_MLDSA_65:
    case OAKLEY_P521_FNDSA1024:
#endif
        if (
#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)
            /* hybrid client doesn't need host certificate */
            !IS_HYBRID_CLIENT(pxSa) &&
#endif
            (OK > IKE_useCert(ctx, pAuthMtd->wAuthMtd)))
            bAuthMtdEnabled = FALSE; /* no valid host certificate */
        else bAuthMtdEnabled = TRUE;
        break;

#ifdef CUSTOM_IKE_GET_PSK
    case OAKLEY_PRESHARED_KEY :
        if (OK > IKE_getPsk(NULL, NULL, pxSa, 0))
            bAuthMtdEnabled = FALSE; /* no pre-shared key found */
        else bAuthMtdEnabled = TRUE;
        break;
#endif
    default :
        bAuthMtdEnabled = pAuthMtd->bEnabled[bInitiator ? _I : _R];
        break;
    }

    if (!bAuthMtdEnabled)
    {
        SET_MERROR(ERR_IKE_MISMATCH_AUTH_METHOD)
        debug_printnl("AUTH: mismatch");
        goto exit;
    }

    /* set hash algo. */
    if (NULL == (pxSa->pHashSuite = IKE_hashSuiteEx(pxSa->ikePeerConfig, pxSa->u.v1.pwIsaAttr[OAKLEY_HASH_ALGORITHM],
                                                  0)))
    {
        SET_MERROR(ERR_IKE_MISMATCH_HASH_ALGO)
        debug_printnl("HASH: mismatch");
        goto exit;
    }

    /* set encr. algo. */
#ifdef CUSTOM_IKE_GET_ENCR_ALGO
    if (0 < pxSa->numEncrAlgos)
    {
        if (SetEncrAlgo(pxSa->u.v1.pwIsaAttr[OAKLEY_ENCRYPTION_ALGORITHM],
                        wKeyLen, pxSa))
        {
            SET_MERROR(ERR_IKE_MISMATCH_KEYLEN)
            debug_printnl("KEY-LENGTH: mismatch");
            goto exit;
        }
    }
    else
#endif
    {
        pxSa->pCipherSuite = IKE_cipherSuiteEx(pxSa->ikePeerConfig, pxSa->u.v1.pwIsaAttr[OAKLEY_ENCRYPTION_ALGORITHM], 0,
                                    wKeyLen,
                                    (wKeyLen ? NULL : &(pxSa->wEncrKeyLen)));
        if (NULL == pxSa->pCipherSuite)
        {
            SET_MERROR(ERR_IKE_MISMATCH_KEYLEN)
            debug_printnl("KEY-LENGTH: mismatch");
            goto exit;
        }

        if (pxSa->pCipherSuite->bDisabled[0][bInitiator ? _I : _R])
        {
            SET_MERROR(ERR_IKE_MISMATCH_ENCR_ALGO)
            debug_printnl("ENCR: mismatch");
            goto exit;
        }

        if (wKeyLen) pxSa->wEncrKeyLen = wKeyLen;
    }

    /* check key length */
    if (wKeyLen)
    {
        if (pxSa->pCipherSuite->bFixedKeyLen) /* RFC2409 p.36 */
        {
            SET_MERROR(ERR_IKE_MISMATCH_KEYLEN)
            debug_printnl("KEY-LENGTH: mismatch");
            goto exit;
        }
    }
    else
    {
        if (!pxSa->pCipherSuite->bFixedKeyLen)
        {
            debug_printnl("DEFAULT: ");
            debug_int(pxSa->wEncrKeyLen * 8);
            debug_print("-BITS ");
        }
    }

    debug_printnl(NULL);

    /* done */
    status = OK;

exit:
    if (OK > status)
    {
        /* reset */
        if (bInitiator)
            pxSa->u.v1.pwIsaAttr[OAKLEY_GROUP_DESCRIPTION] = wDhGrp;
    }
    return status;
} /* InAttrs */


/*------------------------------------------------------------------*/

static MSTATUS
InAttrs2(IKE_context ctx)
{
    MSTATUS status = ERR_IKE_MISMATCH;

    IKESA pxSa = ctx->pxSa;
    IPSECSA pxIPsecSa = P2XG_IPSECSA(ctx->pxP2Xg);
    IPSECPPS pxIPsecPps = ctx->pxIPsecPps;
    intBoolean bInitiator = IS_CHILD_INITIATOR(pxIPsecSa);

    struct ikeTfmHdr *pxTfmHdr = (struct ikeTfmHdr *) ctx->pHdrParent;
    ubyte oTfmId = pxTfmHdr->oAttrId;

    ubyte2 wType, wValue, wLength;
    ubyte2 wLifeType = 0, wAuthAlgo = 0, wPFS = 0, wKeyLen = 0;
    ubyte4 dwValue;

    sbyte4 i;

#ifdef __ENABLE_DIGICERT_PFKEY__
    intBoolean bEsn = FALSE; /* initiator only */
#endif
#ifdef CUSTOM_IKE_CATCH_EXCEPTION
    ubyte2 wUnkAttr = 0;
#endif
    ubyte2 bitStrength = 0;
#ifndef __DISABLE_DIGICERT_CONSTRAINT_CIPHER__
    bitStrength = CHILDSA_cipherEffectiveBitStrength(pxSa->pCipherSuite->wTfmId, pxSa->wEncrKeyLen);
#endif

    /* clean up */
    if (bInitiator)
    {
#ifndef __ENABLE_DIGICERT_PFKEY__
        /* reset wildcards */
        ubyte2 flags = pxIPsecPps->p_flags;
        if (IKE_PROP_FLAG_TFM_ID & flags)       pxIPsecPps->oTfmId      = 0;
        if (IKE_PROP_FLAG_AUTH_ALGO & flags)    pxIPsecPps->wAuthAlgo   = 0;
        if (IKE_PROP_FLAG_ENCR_ALGO & flags)    pxIPsecPps->oEncrAlgo   = 0;
        if (IKE_PROP_FLAG_ENCR_KEYLEN & flags)  pxIPsecPps->wEncrKeyLen = 0;
#endif
    }
    else /* responder */
    {
        pxIPsecPps->p_flags     = 0;

/*      pxIPsecPps->oTfmId      = 0;*/
        pxIPsecPps->oEncrAlgo   = 0;
/*      pxIPsecPps->wAuthAlgo   = 0;*/
        pxIPsecPps->wMode       = 0;

        pxIPsecPps->dwExpKBytes = 0;
        pxIPsecPps->dwExpSecs   = 0;

        pxIPsecPps->wEncrKeyLen = 0;
    }

    debug_print("      ");

    /* check transform id */
    if (bInitiator && pxIPsecPps->oTfmId) /* initiator, algo. specified */
    {
        if (oTfmId != pxIPsecPps->oTfmId)
        {
            status = ERR_IKE_BAD_TRANSFORM;
            debug_printnl("ALG: mismatch");
            goto exit;
        }
    }
    else
    {
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
                SET_MSGTYPE(INVALID_TRANSFORM_ID)
                SET_MERROR2(ERR_IKE_MISMATCH_AUTH_ALGO)
                debug_printnl("AUTH-ALG: unsupported");
                goto exit; /* unknown auth algo */
            }
        }

        /* ESP or ESP_AUTH */
        else
#ifndef __ENABLE_DIGICERT_PFKEY__
        if (ESP_NULL != oTfmId)
        {
            if (NULL == CHILDSA_findEncrAlgoWithConstraint(bitStrength, oTfmId, 0, 0, 0, NULL))
#else
        {
            CHILDSA_encrInfo *pEncrAlgo = CHILDSA_findEncrAlgoWithConstraint(bitStrength, oTfmId, 0, 0,
                                                               0, NULL);
            if ((NULL == pEncrAlgo) || !pEncrAlgo->bSupported)
#endif
            {
                SET_MSGTYPE(INVALID_TRANSFORM_ID)
                SET_MERROR2(ERR_IKE_MISMATCH_ENCR_ALGO)
                debug_printnl("ENCR-ALG: unsupported");
                goto exit; /* unknown encr algo*/
            }
#ifdef __ENABLE_DIGICERT_PFKEY__
            if (ESP_NULL != oTfmId)
#endif
            pxIPsecPps->oEncrAlgo = oTfmId; /* set encr. algo. */
        }

        pxIPsecPps->oTfmId = oTfmId;
    }

    /* IPSEC SA attributes */
    for (;;)
    {
        MSTATUS st;

        /* get data attribute */
        if (0 == ctx->dwBufferSize) break;

        if (OK != (st = InAttrBV(ctx, &wType, &wLength, &wValue, &dwValue)))
        {
            if (!bInitiator)
            {
                if (ERR_IKE_BAD_LEN == st)
                    ctx->wMsgType = UNEQUAL_PAYLOAD_LENGTHS;
                else
                    ctx->wMsgType = PAYLOAD_MALFORMED;
            }
            status = st;
            goto exit;
        }

        /* check encoding */
        switch (wType)
        {
        case AUTH_ALGORITHM :
        case SA_LIFE_TYPE :
        case ENCAPSULATION_MODE :
        case GROUP_DESCRIPTION :
        case KEY_LENGTH :
        case EXT_SEQ_NO :
            if (0 != wLength) /* must be TV (B) */
            {
                SET_MSGTYPE(PAYLOAD_MALFORMED)
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
        case SA_LIFE_TYPE :
            wLifeType = wValue;
            break;

        case SA_LIFE_DURATION :     /* B/V  */
            if (0 != wLength)
            {
                if ((ubyte2)sizeof(ubyte2) != wLength &&
                    (ubyte2)sizeof(ubyte4) != wLength)
                {
                    SET_MSGTYPE(PAYLOAD_MALFORMED)
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

                if (bInitiator)
                {
                    if (dwValue != pxIPsecPps->dwExpSecs)
                    {
                        status = STATUS_IKE_LIFETIME_SECONDS;
                        debug_printnl("mismatch");
                        goto exit;
                    }
                }
                else
                {
                    if (dwValue && pxSa->ikePeerConfig->ikeP2LifeSecsMin &&
                        (dwValue < pxSa->ikePeerConfig->ikeP2LifeSecsMin))
                    {
                        debug_printnl("too short");
                        goto exit;
                    }
                    pxIPsecPps->dwExpSecs = dwValue;
                }
                break;
            case SA_LIFE_TYPE_KBYTES :
                debug_uint(dwValue);
                debug_print("-KILOBYTES ");

                if (bInitiator)
                {
                    if (dwValue != pxIPsecPps->dwExpKBytes)
                    {
                        status = STATUS_IKE_LIFETIME_KBYTES;
                        debug_printnl("mismatch");
                        goto exit;
                    }
                }
                else
                {
                    pxIPsecPps->dwExpKBytes = dwValue;
                }
                break;
            default :
                status = ERR_IKE_BAD_ATTR;
                DBG_NL_EXIT
            }
            break;

        case ENCAPSULATION_MODE :
        {
#ifdef __ENABLE_IPSEC_NAT_T__
            ubyte2 udpEncpFlag = 0;
#endif
            for (i = NUM_ATTR_MODE - 1; i >= 0; i--)
            {
                if (wValue == mAttrMode[i])
                    break;
            }

            while (0 > i) /* no normal encap. mode */
            {
#ifdef __ENABLE_IPSEC_NAT_T__
                /* UDP-encap. mode? */
                if (0 <= (i = pxSa->u.v1.iNatT - 1))
                {
                    udpEncpFlag = IKE_PROP_FLAG_UDP_ENCP; /* yes */
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                    if (wValue == mNatTinfo[i].wUdpTunnel)
                    {
                        wValue = ENCAPSULATION_MODE_TUNNEL;
                        break;
                    }
#endif
                    if (wValue == mNatTinfo[i].wUdpTransport)
                    {
                        wValue = ENCAPSULATION_MODE_TRANSPORT;
                        break;
                    }

                    /* Some gateway (e.g. Cisco) may send UDP-ENCAP mode from
                       a differnt NAT-T draft version as agreed in Phase 1.
                     */
                    if (!bInitiator) /* OK only when we are responder */
                    {
                        debug_print("?");
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                        if ((wValue == ENCAPSULATION_MODE_UDP_TUNNEL) ||
                            (wValue == ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS))
                        {
                            if (wValue == ENCAPSULATION_MODE_UDP_TUNNEL)
                                pxSa->u.v1.iNatT = 1;
                            else
                                pxSa->u.v1.iNatT = 3;
                            wValue = ENCAPSULATION_MODE_TUNNEL;
                            break;
                        }
#endif
                        if ((wValue == ENCAPSULATION_MODE_UDP_TRANSPORT) ||
                            (wValue == ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS))
                        {
                            if (wValue == ENCAPSULATION_MODE_UDP_TRANSPORT)
                                pxSa->u.v1.iNatT = 1;
                            else
                                pxSa->u.v1.iNatT = 3;
                            wValue = ENCAPSULATION_MODE_TRANSPORT;
                            break;
                        }
                    }
                }
#endif /* __ENABLE_IPSEC_NAT_T__ */

                /* unsupported mode */
                SET_MERROR2(ERR_IKE_MISMATCH_ENCAP_MODE)
                debug_print("ENCAP: ");
                debug_print_ike_p2_attr_v(wValue, ENCAPSULATION_MODE);
                debug_printnl(" unsupported");
                goto exit;
            }

            if (bInitiator)
            {
                if (wValue != pxIPsecPps->wMode)
                {
                    status = ERR_IKE_MISMATCH_ENCAP_MODE;
                    debug_print("ENCAP: ");
                    debug_print_ike_p2_attr_v(wValue, ENCAPSULATION_MODE);
                    debug_printnl(" mismatch");
                    goto exit;
                }
#ifdef __ENABLE_IPSEC_NAT_T__
                if (udpEncpFlag != (IKE_PROP_FLAG_UDP_ENCP & pxIPsecPps->p_flags))
                {
                    status = ERR_IKE_MISMATCH_ENCAP_MODE;
                    debug_printnl("UDP-ENCAP: mismatch");
                    goto exit;
                }
#endif
            }
            else /* responder */
            {
#ifdef __ENABLE_IPSEC_NAT_T__
                if (udpEncpFlag) /* UDP-encap. mode */
                {
                    /* AH is incompatible with UDP-encap. */
                    if (PROTO_IPSEC_AH == pxIPsecPps->oProtocol)
                    {
                        pxIPsecSa->merror = ERR_IKE_MISMATCH_ENCAP_MODE;
                        debug_printnl("UDP-ENCAP: incompatible");
                        goto exit;
                    }

                    if (!USE_NATT_PORT(pxSa)) /* port 4500 should be used */
                    {
                        pxIPsecSa->merror = ERR_IKE_MISMATCH_ENCAP_MODE;
                        debug_printnl("UDP-ENCAP: mismatch");
                        goto exit;
                    }

                    pxIPsecPps->p_flags |= IKE_PROP_FLAG_UDP_ENCP;
                }
                else /* normal encap. mode */
                {
                    if (IS_BEHIND_NAT(pxSa)) /* should use UDP-encap. */
                    {
                        pxIPsecSa->merror = ERR_IKE_MISMATCH_ENCAP_MODE;
                        debug_printnl("UDP-ENCAP: missing");
                        goto exit;
                    }
                }
#endif
                pxIPsecPps->wMode = wValue;
            }

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
#ifdef __ENABLE_IPSEC_NAT_T__
            if (udpEncpFlag)
            {
                if (!IS_BEHIND_NAT(pxSa)) /* UDP-encap. unnecessary */
                {
                    debug_print("UDP-ENCAP: unnecessary ");
                }
                else
                {
                    debug_print("UDP-");
                }
            }
#endif
            debug_print_ike_p2_attr_v(wValue, ENCAPSULATION_MODE);
            debug_print(" ");
#endif
            break;
        }
        case GROUP_DESCRIPTION :
            if (wPFS && (wValue != wPFS) && wValue)
            {
                /* only 1 allowed */
                SET_MERROR2(ERR_IKE_MISMATCH_DH_GROUP)
                debug_print("GROUP: ");
                debug_print_ike_p1_attr_v(wValue, OAKLEY_GROUP_DESCRIPTION);
                debug_printnl(" unexpected");
                goto exit;
            }
            debug_print_ike_p1_attr_v(wValue, OAKLEY_GROUP_DESCRIPTION);
            debug_print(" ");
            wPFS = wValue;
            break;

        case KEY_LENGTH :
            debug_int(wValue);
            debug_print("-BITS ");

            if (!wValue || (wValue % 8))
            {
                SET_MERROR2(ERR_IKE_MISMATCH_KEYLEN)
                debug_printnl("unsupported");
                goto exit;
            }
            wKeyLen = wValue; /* in bits */
            break;

        case EXT_SEQ_NO :
#if defined(__ENABLE_IPSEC_ESN__) || defined(__ENABLE_DIGICERT_PFKEY__)
            if (1 == wValue)
            {
                debug_print("ESN ");
#ifdef __ENABLE_DIGICERT_PFKEY__
                if (bInitiator && !(IKE_PROP_FLAG_ESN & pxIPsecPps->p_flags))
                {
                    SET_MERROR2(ERR_IKE_MISMATCH_ESN)
                    debug_printnl("mismatch");
                    goto exit;
                }
                bEsn = TRUE; /* for initiator */
#endif
                pxIPsecPps->p_flags |= IKE_PROP_FLAG_ESN;
            }
            else
#endif
            {
                SET_MERROR2(ERR_IKE_MISMATCH_ESN)
                debug_print("ESN: ");
                debug_int(wValue);
                debug_printnl(" unsupported");
                goto exit;
            }
            break;

#ifdef USE_MOC_COOKIE
        case IPSEC_COOKIE_TYPE :
            if (0 != wLength)
            {
                if ((ubyte2)sizeof(ubyte4) != wLength)
                {
                    SET_MSGTYPE(PAYLOAD_MALFORMED)
                    status = ERR_IKE_BAD_ATTR;
                    DBG_NL_EXIT
                }
            }
            else dwValue = wValue;

            debug_print("COOKIE: ");
            debug_uint(dwValue);
            debug_print(" ");

            if (!bInitiator && (0 == ctx->oPpsIndex))
            {
                pxIPsecSa->axP2Sa[ctx->oP2SaIndex].cookie = dwValue;
            }
            else if (dwValue != pxIPsecSa->axP2Sa[ctx->oP2SaIndex].cookie)
            {
                debug_printnl((bInitiator ? "mismatch" : "inconsistent"));
                goto exit;
            }
            break;
#endif

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

#ifdef CUSTOM_IKE_CATCH_EXCEPTION
            if (wType) wUnkAttr = wType;
#endif
            break;
        } /* switch */

    } /* for (;;) */

    /* check auth. algo. */
    if (bInitiator &&
        (pxIPsecPps->wAuthAlgo ||
         (IPSEC_PROTO_ESP == pxIPsecPps->oSecuProto)))
    {
        if (wAuthAlgo != pxIPsecPps->wAuthAlgo)
        {
            status = ERR_IKE_MISMATCH_AUTH_ALGO;
            debug_print("AUTH-ALG:");
            if (wAuthAlgo)
            {
                debug_print(" ");
                debug_print_ike_p2_attr_v(wAuthAlgo, AUTH_ALGORITHM);
            }
            debug_printnl(" mismatch");
            goto exit;
        }
    }
    else
    {
        if ((PROTO_IPSEC_AH == pxIPsecPps->oProtocol)
            || (ESP_NULL == oTfmId)) /* ESP_NULL w/o auth. is not supported! */
        {
            if (!wAuthAlgo) /* auth algo must be specified */
            {
                SET_MERROR2(ERR_IKE_MISMATCH_AUTH_ALGO)
                debug_printnl("AUTH-ALG: missing");
                goto exit;
            }
        }

        if (wAuthAlgo)
        {
            /* check auth algo */
            CHILDSA_authInfo *pAuthAlgo = CHILDSA_findAuthAlgo(wAuthAlgo, 0, 0, 0);
            if ((NULL == pAuthAlgo) /* unsupported */
#ifdef __ENABLE_DIGICERT_PFKEY__
                || !pAuthAlgo->bSupported
#endif
                )
            {
                SET_MERROR2(ERR_IKE_MISMATCH_AUTH_ALGO)
                debug_print("AUTH-ALG: ");
                debug_print_ike_p2_attr_v(wAuthAlgo, AUTH_ALGORITHM);
                debug_printnl(" unsupported");
                goto exit;
            }

            if ((PROTO_IPSEC_AH == pxIPsecPps->oProtocol) &&
                (oTfmId != pAuthAlgo->oTfmId)) /* mismatch */
            {
                SET_MSGTYPE(INVALID_TRANSFORM_ID)
                SET_MERROR2(ERR_IKE_MISMATCH_AUTH_ALGO)
                debug_printnl("AUTH-ALG: attribute mismatch");
                goto exit;
            }
        }

        pxIPsecPps->wAuthAlgo = wAuthAlgo;
    }

    if (pxIPsecPps->wAuthAlgo)
    {
        debug_print_ike_p2_attr_v(pxIPsecPps->wAuthAlgo, AUTH_ALGORITHM);
        debug_print(" ");
    }

    /* check key length */
    if (pxIPsecPps->oEncrAlgo)
    {
        CHILDSA_encrInfo *pEncrAlgo =
                CHILDSA_findEncrAlgoWithConstraint(bitStrength, pxIPsecPps->oEncrAlgo, 0, 0,
                                                    (ubyte2)(wKeyLen/8),
                                                    (wKeyLen ? NULL : &wValue));
        if (NULL == pEncrAlgo)
        {
            SET_MERROR2(ERR_IKE_MISMATCH_ENCR_ALGO)
            debug_printnl("ENCR-ALG: mismatch");
            goto exit;
        }

        if (wKeyLen)
        {
            if (pEncrAlgo->bFixedKeyLen) /* RFC2409 p.36 */
            {
                SET_MERROR2(ERR_IKE_MISMATCH_KEYLEN)
                debug_printnl("KEY-LENGTH: unexpected");
                goto exit;
            }

            if (bInitiator && pxIPsecPps->wEncrKeyLen) /* initiator, key len. specified */
            {
                if (wKeyLen != (ubyte2)(8 * pxIPsecPps->wEncrKeyLen))
                {
                    status = ERR_IKE_MISMATCH_KEYLEN;
                    debug_printnl("KEY-LENGTH: mismatch");
                    goto exit;
                }
            }
            else pxIPsecPps->wEncrKeyLen = (ubyte2)(wKeyLen/8);
        }
        else
        {
            if (bInitiator)
            {
                if (pxIPsecPps->wEncrKeyLen)
                {
                    if (wValue != pxIPsecPps->wEncrKeyLen)
                    {
                        status = ERR_IKE_MISMATCH_KEYLEN;
                        debug_printnl("KEY-LENGTH: mismatch");
                        goto exit;
                    }
                }
            }

            if (!pEncrAlgo->bFixedKeyLen)
            {
                debug_print("DEFAULT: ");
                debug_int(wValue*8);
                debug_print("-BITS ");
            }
        }
    }
    else
    {
        if (wKeyLen)
            debug_print("KEY-LENGTH: ignored ");
    }

    /* check PFS consistency (see RFC2409 pp.17-18) */
    if (bInitiator)
    {
        /* inconsistent - only OK if no KE payload is exchanged */
        if (wPFS != pxIPsecSa->wPFS)
        {
            if (pxIPsecSa->wPFS)
            {
                debug_printnl(wPFS ? "GROUP: mismatch" : "GROUP: missing");
                status = ERR_IKE_MISMATCH_DH_GROUP;
                goto exit;
            }
            debug_print("GROUP: inconsistent");
        }
    }
    else /* responder */
    {
        if (IKE_checkGroup(wPFS, FALSE, pxSa, NULL, pxIPsecSa))
        {
            debug_print("GROUP: ");
#ifdef CUSTOM_IKE_GET_P2_PFS
            debug_printnl(wPFS ? (pxIPsecSa->numDhGrps ? "mismatch" : "unsupported") : "missing");
#else
            debug_printnl(wPFS ? "unsupported" : "missing");
#endif
            pxIPsecSa->merror = ERR_IKE_MISMATCH_DH_GROUP;
            goto exit;
        }

        if (IKE_CNTXT_FLAG_PFS & ctx->flags)
        {
            /* inconsistent, but OK if no KE payload is sent by peer */
            if (wPFS != pxIPsecSa->wPFS)
            {
                debug_print("GROUP: inconsistent");

                if (wPFS && pxIPsecSa->wPFS)
                {
                    pxIPsecSa->merror = ERR_IKE_MISMATCH_DH_GROUP;
                    debug_printnl(NULL);
                    goto exit;
                }

                pxIPsecSa->wPFS = 0;
            }
        }
        else
        {
            pxIPsecSa->wPFS = wPFS;
            ctx->flags |= IKE_CNTXT_FLAG_PFS;
        }
    }

    /* check ESN */
#if defined(__ENABLE_IPSEC_ESN__) || defined(__ENABLE_DIGICERT_PFKEY__)
#ifdef __ENABLE_DIGICERT_PFKEY__
    if (bInitiator && !bEsn && (IKE_PROP_FLAG_ESN & pxIPsecPps->p_flags))
    {
        debug_printnl("ESN: mismatch");
        status = ERR_IKE_MISMATCH_ESN;
        goto exit;
    }
#endif
    if (ctx->oPpsIndex)
    {
        /* make sure ESN is consistent within nested IPsec SAs */
        IPSECPPS pxIPsecPps0 = &(pxIPsecSa->axP2Sa[ctx->oP2SaIndex].axChildSa[0].ipsecPps);
        if ((IKE_PROP_FLAG_ESN & pxIPsecPps->p_flags) !=
            (IKE_PROP_FLAG_ESN & pxIPsecPps0->p_flags)) /* inconsistent */
        {
            if (bInitiator)
            {
#ifndef __ENABLE_DIGICERT_PFKEY__
                debug_printnl("ESN: mismatch");
                status = ERR_IKE_MISMATCH_ESN;
                goto exit;
#endif
            }
            else
            {
                pxIPsecSa->merror = ERR_IKE_MISMATCH_ESN;
                debug_printnl("ESN: inconsistent");
                goto exit;
            }
        }
    }
#endif

    debug_printnl(NULL);

    /* match proposal against SPD */
    if (!bInitiator) /* responder only */
    {
        MSTATUS st;
        ubyte oSaIndex = ctx->oP2SaIndex;

        struct ipsecKeyEx keyEx = { 0 };
        IKE_initIPsecKey(&keyEx, pxSa, pxIPsecSa, pxIPsecPps,
                         NULL, oSaIndex, ctx->oPpsIndex, _R);

        if ((0 == pxIPsecPps->dwExpSecs) && (0 == pxIPsecPps->dwExpKBytes))
            keyEx.dwExpSecs = 28800; /* 8 hours (RFC2407 4.5, p.13) */
        else
        keyEx.dwExpSecs = pxIPsecPps->dwExpSecs;
        keyEx.dwExpKBytes = pxIPsecPps->dwExpKBytes;

        st = IPSEC_keyReady(&keyEx);
        pxIPsecSa->axP2Sa[oSaIndex].dwSpdId = keyEx.dwSpdId;
        pxIPsecSa->axP2Sa[oSaIndex].spdIndex = keyEx.spdIndex;

        if (OK > st)
        {
            /* mismatch */
            pxIPsecSa->merror = st;

            if (ERR_SPD_UNACCEPTABLE_TS == st) /* no applicable policy */
            {
                ctx->wMsgType = INVALID_ID_INFORMATION;
                status = ERR_SPD_UNACCEPTABLE_TS;
                DBG_STATUS
            }
            goto exit;
        }

        pxIPsecPps->dwAdjSecs   = keyEx.dwExpSecs;
        pxIPsecPps->dwAdjKBytes = keyEx.dwExpKBytes;

#ifdef __ENABLE_DIGICERT_PFKEY__
        pxIPsecSa->axP2Sa[oSaIndex].oReplay = keyEx.sadb_sa_replay;
        pxIPsecSa->axP2Sa[oSaIndex].cookie = keyEx.cookie;
#endif
    }

    /* done */
    status = OK;

#ifdef CUSTOM_IKE_CATCH_EXCEPTION
    if (wUnkAttr)
    {
        MOC_IP_ADDRESS peerAddr = REF_MOC_IPADDR(pxSa->dwPeerAddr);
        struct ikeHdr *pxIkeHdr = (struct ikeHdr *) ctx->pxIkeHdr;
        P2XG pxXg = ctx->pxP2Xg;

        CUSTOM_IKE_CATCH_EXCEPTION(ERR_IKE_UNKNOWN_ATTR,
            peerAddr, pxIkeHdr, ISAKMP_NEXT_T, pxTfmHdr,
            pxSa, pxXg, pxIPsecSa);
    }
#endif

exit:
    return status;
} /* InAttrs2 */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_IPCOMP__

static MSTATUS
InAttrsComp(IKE_context ctx)
{
    MSTATUS status = ERR_IKE_MISMATCH;

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
#ifdef __ENABLE_IPSEC_NAT_T__
    IKESA pxSa = ctx->pxSa;
#endif
#endif
    IPSECSA pxIPsecSa = P2XG_IPSECSA(ctx->pxP2Xg);
    IPSECPPS pxIPsecPps = ctx->pxIPsecPps;
    intBoolean bInitiator = IS_CHILD_INITIATOR(pxIPsecSa);

    struct ikeTfmHdr *pxTfmHdr = (struct ikeTfmHdr *) ctx->pHdrParent;
    ubyte oTfmId = pxTfmHdr->oAttrId;

    ubyte2 wType, wValue, wLength;
    ubyte2 wLifeType = 0;
    ubyte4 dwValue;

    debug_print("       ");

    /* check transform id */
    if (bInitiator && (0 == pxIPsecPps->wCpi[_I]))
    {
        /* initiator, no compression */
        status = ERR_IKE_BAD_TRANSFORM;
        debug_printnl("ALG: mismatch");
        goto exit;
    }

    if (NULL == CHILDSA_findCompAlgo(oTfmId)) /* IPCOMP_DEFLATE, IPCOMP_LZS, etc. */
    {
        SET_MSGTYPE(INVALID_TRANSFORM_ID)
        SET_MERROR2(ERR_IKE_MISMATCH_IPCOMP_ALGO)
        debug_printnl("IPCOMP-ALG: unsupported");
        goto exit; /* unknown comp algo */
    }

    pxIPsecPps->oCompAlgo = oTfmId;

    /* IPCOMP attributes - parsing only */
    for (;;)
    {
        MSTATUS st;

        /* get data attribute */
        if (0 == ctx->dwBufferSize) break;

        if (OK != (st = InAttrBV(ctx, &wType, &wLength, &wValue, &dwValue)))
        {
            if (!bInitiator)
            {
                if (ERR_IKE_BAD_LEN == st)
                    ctx->wMsgType = UNEQUAL_PAYLOAD_LENGTHS;
                else
                    ctx->wMsgType = PAYLOAD_MALFORMED;
            }
            status = st;
            goto exit;
        }

        /* check encoding */
        switch (wType)
        {
        case SA_LIFE_TYPE :
        case ENCAPSULATION_MODE :
            if (0 != wLength) /* must be TV (B) */
            {
                SET_MSGTYPE(PAYLOAD_MALFORMED)
                status = ERR_IKE_BAD_ATTR;
                DBG_NL_EXIT
            }
            break;
        }

        switch (wType)
        {
        case SA_LIFE_TYPE :
            wLifeType = wValue;
            break;

        case SA_LIFE_DURATION :     /* B/V  */
            if (0 != wLength)
            {
                if ((ubyte2)sizeof(ubyte2) != wLength &&
                    (ubyte2)sizeof(ubyte4) != wLength)
                {
                    SET_MSGTYPE(PAYLOAD_MALFORMED)
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
                break;
            case SA_LIFE_TYPE_KBYTES :
                debug_uint(dwValue);
                debug_print("-KILOBYTES ");
                break;
            default :
                status = ERR_IKE_BAD_ATTR;
                DBG_NL_EXIT
            }
            break;

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)

        case ENCAPSULATION_MODE :
        {
#ifdef __ENABLE_IPSEC_NAT_T__
            ubyte2 udpEncpFlag = 0;
#endif
            sbyte4 i;
            for (i = NUM_ATTR_MODE - 1; i >= 0; i--)
            {
                if (wValue == mAttrMode[i])
                    break;
            }

            if (0 > i) /* no normal encap. mode */
            {
#ifdef __ENABLE_IPSEC_NAT_T__
                /* UDP-encap. mode? */
                if (0 <= (i = pxSa->u.v1.iNatT - 1))
                {
                    udpEncpFlag = IKE_PROP_FLAG_UDP_ENCP; /* yes */
                }
#ifndef __DISABLE_IPSEC_TUNNEL_MODE__
                if ((0 <= i) && (wValue == mNatTinfo[i].wUdpTunnel))
                {
                    wValue = ENCAPSULATION_MODE_TUNNEL;
                }
                else
#endif
                if ((0 <= i) && (wValue == mNatTinfo[i].wUdpTransport))
                {
                    wValue = ENCAPSULATION_MODE_TRANSPORT;
                }
                else
#endif /* __ENABLE_IPSEC_NAT_T__ */
                {
                    /* unsupported mode */
                    debug_print("ENCAP: ");
                    debug_print_ike_p2_attr_v(wValue, ENCAPSULATION_MODE);
                    debug_print(" unsupported ");
                    break;
                }
            }

            if (bInitiator)
            {
                if (wValue != pxIPsecPps->wMode)
                {
                    debug_print("ENCAP: ");
                    debug_print_ike_p2_attr_v(wValue, ENCAPSULATION_MODE);
                    debug_print(" mismatch ");
                    break;
                }
#ifdef __ENABLE_IPSEC_NAT_T__
                if (udpEncpFlag != (IKE_PROP_FLAG_UDP_ENCP & pxIPsecPps->p_flags))
                {
                    debug_print("UDP-ENCAP: mismatch ");
                    break;
                }
#endif
            }
            else /* responder */
            {
#ifdef __ENABLE_IPSEC_NAT_T__
                if (udpEncpFlag) /* UDP-encap. mode */
                {
                    /* AH is incompatible with UDP-encap. */
                    if (PROTO_IPSEC_AH == pxIPsecPps->oProtocol)
                    {
                        debug_print("UDP-ENCAP: incompatible ");
                        break;
                    }

                    if (!USE_NATT_PORT(pxSa)) /* port 4500 should be used */
                    {
                        debug_print("UDP-ENCAP: mismatch ");
                        break;
                    }
                }
                else /* normal encap. mode */
                {
                    if (IS_BEHIND_NAT(pxSa)) /* should use UDP-encap. */
                    {
                        debug_print("UDP-ENCAP: missing ");
                        break;
                    }
                }
#endif
            }

#ifdef __ENABLE_IPSEC_NAT_T__
            if (udpEncpFlag)
            {
                if (!IS_BEHIND_NAT(pxSa)) /* UDP-encap. unnecessary */
                {
                    debug_print("UDP-ENCAP: unnecessary ");
                }
                else
                {
                    debug_print("UDP-");
                }
            }
#endif
            debug_print_ike_p2_attr_v(wValue, ENCAPSULATION_MODE);
            debug_print(" ");
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

#endif /* defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__) */

        } /* switch */

    } /* for (;;) */

    debug_printnl(NULL);

    /* done */
    status = OK;

exit:
    return status;
} /* InAttrsComp */


/*------------------------------------------------------------------*/

static MSTATUS
InTfmsComp(IKE_context ctx)
{
    MSTATUS status = ERR_IKE_MISMATCH;
    IPSECPPS pxIPsecPps = ctx->pxIPsecPps;
    struct ikePpsHdr *pxPpsHdr = (struct ikePpsHdr *) ctx->pHdrParent;

    ubyte4 dwBufferSize;
    ubyte4 dwLength;
    ubyte oNextPayload;
    void *pHdrParent;

    /* loop through transform payloads */
    sbyte4 i;
    for (i=0; i < pxPpsHdr->oTfmLen; i++)
    {
        if ((0 < i) && (ISAKMP_NEXT_T != ctx->oNextPayload))
        {
            status = ERR_IKE_BAD_TRANSFORM;
            DBG_EXIT
        }
        else
        {
            /* transform payload header */
            IN_BEGIN(struct ikeTfmHdr, pxTfmHdr, SIZEOF_IKE_TFM_HDR)

            debug_print("      Transform #");
            debug_int(pxTfmHdr->oNum);
            debug_print(": ");
            debug_print_ike_tfmid(pxTfmHdr->oAttrId, pxPpsHdr->oProtoId);
            debug_printnl(NULL);

            /* down one level - go to data attributes */
            IN_DOWN(pxTfmHdr, 0)

            pxIPsecPps->oCompTfmNo = pxTfmHdr->oNum;
            status = InAttrsComp(ctx);

            /* up one level */
            IN_UP(pxTfmHdr)

            if (OK > status)
            {
                if (ERR_IKE_MISMATCH != status)
                    goto exit;
            }

            if (OK == status) /* match */
            {
                break;
            }
        }
    } /* for */

exit:
    return status;
} /* InTfmsComp */


/*------------------------------------------------------------------*/

static MSTATUS
InPpComp(IKE_context ctx)
{
    /* special handling for PROTO_IPCOMP Proposal Payload */
    MSTATUS status = OK;

    P2XG pxXg = ctx->pxP2Xg;
    IPSECPPS pxIPsecPps = ctx->pxIPsecPps;

    IPSECSA pxIPsecSa = P2XG_IPSECSA(pxXg);
    intBoolean bInitiator = IS_CHILD_INITIATOR(pxIPsecSa);

    ubyte4 dwBufferSize;
    ubyte4 dwLength;
    ubyte oNextPayload;
    void *pHdrParent;

    ubyte2 wCpi = 0;
    ubyte oSpiSize;

    /* proposal payload header */
    IN_BEGIN(struct ikePpsHdr, pxPpsHdr, SIZEOF_IKE_PPS_HDR)

    if ((PROTO_IPCOMP != pxPpsHdr->oProtoId) ||
        (pxPpsHdr->oNum != pxIPsecPps->oPpsNo))
    {
        IN_END
        goto done;
    }

    /* check spi size */
    oSpiSize = pxPpsHdr->oSpiSize;
    if (wBodyLen < oSpiSize)
    {
        SET_MSGTYPE(UNEQUAL_PAYLOAD_LENGTHS)
        status = ERR_IKE_BAD_LEN;
        DBG_EXIT
    }

    /* initiator accepts one transform per proposal payload */
    if (bInitiator && (1 != pxPpsHdr->oTfmLen))
    {
        status = ERR_IKE_BAD_TRANSFORM;
        DBG_EXIT
    }

    debug_print("     Proposal #");
    debug_int(pxPpsHdr->oNum);
    debug_print(": ");
    debug_print_ike_proto(PROTO_IPCOMP);
    debug_print("[");
    debug_int(pxPpsHdr->oTfmLen);
    debug_print("] cpi=");
    if (sizeof(ubyte2) == oSpiSize)
    {
        wCpi = DIGI_NTOHS((ubyte *) &pxPpsHdr->dwSpi);
        debug_int(wCpi);
    }
    else if (sizeof(ubyte4) == oSpiSize)
    {
        wCpi = (ubyte2)(GET_NTOHL(pxPpsHdr->dwSpi) & 0xffff);
        debug_int(wCpi);
    }
    debug_printnl(NULL);

    /* CPI; see RFC3173 4.1. */
    if ((sizeof(ubyte2) != oSpiSize) && (sizeof(ubyte4) != oSpiSize))
    {
        SET_MSGTYPE(INVALID_SPI)
        status = ERR_IKE_BAD_SPI;
        DBG_EXIT
    }

    if (bInitiator)
    {
        if (0 == pxIPsecPps->wCpi[_I]) /* no compression */
        {
            status = ERR_IKE_BAD_PROTOCOL;
            DBG_EXIT
        }

        pxIPsecPps->wCpi[_R] = wCpi;
    }
    else
    {
        pxIPsecPps->wCpi[_I] = wCpi;

        /* get CPI; see RFC3173 3.3. */
        if (0 == pxIPsecPps->wCpi[_R]) /* jic */
        {
            do
            {
                if (OK > (status = RANDOM_numberGenerator(g_pRandomContext,
                                                          (ubyte *) &wCpi,
                                                          sizeof(ubyte2))))
                {
                    DBG_EXIT
                }
            } while (((ubyte2)256 > wCpi) || ((ubyte2)61439 < wCpi));

            pxIPsecPps->wCpi[_R] = wCpi;
        }
    }

    ADVANCE(oSpiSize)
    wBodyLen = (ubyte2)(wBodyLen - oSpiSize);

    /* down one level - go to child Transform Payloads */
    IN_DOWN(pxPpsHdr, ISAKMP_NEXT_T)

    status = InTfmsComp(ctx);

    /* up one level */
    IN_UP(pxPpsHdr)

    if (OK != status)
    {
        if (!bInitiator) /* responder */
        {
            if (ERR_IKE_MISMATCH == status) /* mismatch */
            {
                /* will skip to next proposal */
            }
            else
            {
                if (0 == ctx->wMsgType)
                    ctx->wMsgType = BAD_PROPOSAL_SYNTAX;
                goto exit;
            }
        }
        else goto exit;
    }

done:
    /* rollback input buffer */
    ctx->oNextPayload = ISAKMP_NEXT_P; /* !!! */
    //ADVANCE(-wLength)
    ctx->pBuffer = (ubyte *)pxPpsHdr; //-= wLength;
    ctx->dwBufferSize += (ubyte4)wLength;
    ctx->dwLength -= (ubyte4)wLength;

exit:
    return status;
} /* InPpComp */

#endif /* __ENABLE_DIGICERT_IPCOMP__ */


/*------------------------------------------------------------------*/

static MSTATUS
InTfm(IKE_context ctx)
{
    MSTATUS status = ERR_IKE_MISMATCH;

    IKESA pxSa = ctx->pxSa;
    IPSECSA pxIPsecSa = (ctx->pxP2Xg ? P2XG_IPSECSA(ctx->pxP2Xg) : NULL);
    intBoolean bInitiator = (pxIPsecSa ? IS_CHILD_INITIATOR(pxIPsecSa) : IS_INITIATOR(pxSa));

    IPSECPPS pxIPsecPps = ctx->pxIPsecPps;
    struct ikePpsHdr *pxPpsHdr = (struct ikePpsHdr *) ctx->pHdrParent;

    ubyte4 dwBufferSize;
    ubyte4 dwLength;
    ubyte oNextPayload;
    void *pHdrParent;

    /* loop through transform payloads */
    sbyte4 i;
    for (i=0; i < pxPpsHdr->oTfmLen; i++)
    {
#ifdef __ENABLE_DIGICERT_PFKEY__
        IPSECPPS pxExIPsecPps = NULL;
#endif
        if ((0 < i) && (ISAKMP_NEXT_T != ctx->oNextPayload))
        {
            status = ERR_IKE_BAD_TRANSFORM;
            DBG_EXIT
        }

        {

        /* transform payload header */
        IN_BEGIN(struct ikeTfmHdr, pxTfmHdr, SIZEOF_IKE_TFM_HDR)

        debug_print("     Transform #");
        debug_int(pxTfmHdr->oNum);
        debug_print(": ");
        debug_print_ike_tfmid(pxTfmHdr->oAttrId, pxPpsHdr->oProtoId);
        debug_printnl(NULL);

        /* down one level - go to data attributes */
        IN_DOWN(pxTfmHdr, 0)

        if (NULL == pxIPsecSa) /* phase 1 */
        {
            if (KEY_IKE != pxTfmHdr->oAttrId)
            {
                SET_MSGTYPE(INVALID_TRANSFORM_ID)
                status = ERR_IKE_BAD_TRANSFORM;
                DBG_EXIT
            }
            pxSa->oTfmNo = pxTfmHdr->oNum;
            status = InAttrs(ctx);
        }
        else  /* phase 2 */
        {
#ifdef __ENABLE_DIGICERT_PFKEY__
            if (bInitiator && (pxIPsecPps->oTfmNo != pxTfmHdr->oNum))
            {
                if (!pxTfmHdr->oNum) /* jic */
                {
                    status = ERR_IKE_BAD_TRANSFORM;
                    goto exit;
                }
                else
                {
                    sbyte4 j;
                    ubyte oSaIndex = ctx->oP2SaIndex;
                    ubyte oPpsIndex = ctx->oPpsIndex;

                    pxExIPsecPps = pxIPsecSa->axP2Sa[oSaIndex].axChildSa[oPpsIndex].
                                   pxIPsecPps;

                    for (j = (sbyte4)
                             pxIPsecSa->axP2Sa[oSaIndex].axChildSa[oPpsIndex].
                                        oIPsecPpsNum - 2;
                         j >= 0; j--)
                    {
                        if (pxTfmHdr->oNum == pxExIPsecPps[j].oTfmNo)
                            break;
                    }
                    if (0 > j) /* no matching transform ID */
                    {
                        status = ERR_IKE_BAD_TRANSFORM;
                        goto exit;
                    }

                    pxExIPsecPps = pxExIPsecPps + j;
                    pxExIPsecPps->dwSpi[_R] = pxIPsecPps->dwSpi[_R]; /* !!! */
                    ctx->pxIPsecPps = pxExIPsecPps;
                }
            }
            else
#endif
            pxIPsecPps->oTfmNo = pxTfmHdr->oNum;
            status = InAttrs2(ctx);
        }

        /* up one level */
        IN_UP(pxTfmHdr)

        if (OK > status)
        {
            if (ERR_IKE_MISMATCH != status)
                goto exit;
        }

        if (OK == status) /* match */
        {
#ifdef __ENABLE_DIGICERT_PFKEY__
            if (NULL != pxExIPsecPps) /* must be phase 2, initiator */
            {
                /* swap */
                struct ipsecpps ipsecPps = *pxIPsecPps;
                *pxIPsecPps = *pxExIPsecPps;
                *pxExIPsecPps = ipsecPps;
            }
#endif
            break;
        }

        } /* IN_BEGIN */

        CURR_PAYLOAD /* !!! */
    } /* for */

exit:
    return status;
} /* InTfm */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PFKEY__

static MSTATUS DoKe2(IKE_context ctx);

typedef struct IKE_stateCB
{
    struct ipsecKey key;

    IKESA pxSa;
    ubyte4 dwSaId;

    P2XG pxXg;
    ubyte4 dwMsgId;

    IPSECPPS pxPps;

} IKE_stateCB;


/*------------------------------------------------------------------*/

#ifdef __IKE_MULTI_THREADED__

extern RTOS_RWLOCK m_ikeSaRwLock;

extern sbyte4
IKE_dpcStateCallback(IKE_DPC_STATE_CB cb, ubyte4 cbSize)
{
    sbyte4 status = 0;

    if ((sizeof(struct dpcStateCB) <= cbSize) &&
        (sizeof(struct dpcStateCB) == cb->hdr.dpc_len) &&
        ((IKE_dpcFunc)IKE_dpcStateCallback == cb->hdr.dpc_func))
    {
        if (1 == cb->version)
            status = IKE_stateCallback(cb->status, cb->data);
        else if (2 == cb->version)
            status = IKE2_stateCallback(cb->status, cb->data);
    }
    return status;
} /* IKE_dpcStateCallback */

#endif /* __IKE_MULTI_THREADED__ */


/*------------------------------------------------------------------*/

extern sbyte4
IKE_stateCallback(sbyte4 st, void *cbData)
{
    /* Note: responder only */
    MSTATUS status = (MSTATUS)st;

    IKESA pxSa;
    P2XG pxXg;
    IPSECPPS pxPps;

    intBoolean bLastPps = TRUE;
    IPSECSA pxIPsecSa;
    sbyte4 i, j;

    IKE_LOCK_R; /* !!! */

    if ((NULL == cbData) ||
        (NULL == (pxSa = ((IKE_stateCB *)cbData)->pxSa)) ||
        (NULL == (pxXg = ((IKE_stateCB *)cbData)->pxXg)))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __IKE_MULTI_THREADED__
    RTOS_rwLockWaitR(m_ikeSaRwLock);
#endif
    if (!IS_VALID(pxSa) ||
        (((IKE_stateCB *)cbData)->dwSaId != pxSa->dwId))
    {
#ifdef __IKE_MULTI_THREADED__
        RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
        status = ERR_IKE_GETSA_FAIL;
        pxSa = NULL;
        goto exit;
    }

    /* sanity-check */
    if (IS_IKE2_SA(pxSa))
    {
#ifdef __IKE_MULTI_THREADED__
        RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
        status = ERR_IKE_BAD_SA;
        pxSa = NULL;
        goto exit;
    }

    if (!IS_VALID_XCHG(pxXg) ||
        (((IKE_stateCB *)cbData)->dwMsgId != pxXg->dwMsgId))
    {
#ifdef __IKE_MULTI_THREADED__
        RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
        status = ERR_IKE_BAD_XCHG;
        pxXg = NULL;
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
            cb.version = 1;
            cb.status = st;
            cb.data = cbData;
            status = (MSTATUS) m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid,
                                                            (ubyte *)&cb, size);
            if (OK > status) pxSa = NULL;
            else cbData = NULL; /* !!! */
        }
        else
        {
            status = ERR_IKE_CONFIG;
            pxSa = NULL;
        }
        RTOS_rwLockReleaseR(m_ikeSaRwLock);
        goto exit;
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif

    pxPps = ((IKE_stateCB *)cbData)->pxPps;
    pxIPsecSa = P2XG_IPSECSA(pxXg);

    for (i = pxIPsecSa->oP2SaNum - 1; bLastPps && (i >= 0); i--)
    {
        for (j = pxIPsecSa->axP2Sa[i].oChildSaLen - 1; j >= 0; j--)
        {
            IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[i].axChildSa[j].ipsecPps);
            if ((pxIPsecPps != pxPps) &&
                (0 == pxIPsecPps->dwSpi[_R]))
            {
                bLastPps = FALSE;
                break;
            }
        }
    }

    if (bLastPps)
    {
        pxIPsecSa->merror = OK;
        pxXg->x_flags &= ~(IKE_XCHG_FLAG_PENDING);
    }

    if (OK > status) goto exit;

    if ((ubyte4)255 >= (pxPps->dwSpi[_R]
                     = ((IKE_stateCB *)cbData)->key.dwSpi))
    {
        status = ERR_IKE_BAD_SPI;
        goto exit;
    }

    if (bLastPps)
    {
        struct ike_context ctx = { NULL };

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
        if (OK > (status = IKE_getHwAccelChannel(&ctx.hwAccelCookie)))
            goto exit;

        ctx.isHwAccelCookieInit = TRUE;
#endif
        ctx.pxSa = pxSa;
        ctx.pxP2Xg = pxXg;

        if (OK <= (status = DoKe2(&ctx)))
        {
            if (OK > (status = IKE_xchgOut(&ctx)))
                pxXg = NULL;
        }
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
        IKE_releaseHwAccelChannel(&ctx.hwAccelCookie);
#endif
    }

exit:
    if ((OK > status) && pxSa && pxXg)
        IKE_delXchg(pxXg, pxSa, status);

    if (cbData) FREE(cbData);
    IKE_UNLOCK_R;
    return (sbyte4)status;
} /* IKE_stateCallback */

#endif /* __ENABLE_DIGICERT_PFKEY__ */


/*------------------------------------------------------------------*/

static MSTATUS
InPps(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    P2XG pxXg = ctx->pxP2Xg;
    IPSECSA pxIPsecSa = (pxXg ? P2XG_IPSECSA(pxXg) : NULL);
    intBoolean bInitiator = (pxIPsecSa ? IS_CHILD_INITIATOR(pxIPsecSa) : IS_INITIATOR(pxSa));

    ubyte4 dwBufferSize;
    ubyte4 dwLength;
    ubyte oNextPayload;
    void *pHdrParent;

    /* for phase 2 */
    ubyte oSaIndex = ctx->oP2SaIndex;
    intBoolean bMatch = TRUE; /* responder */
    ubyte oPpsIndex = 0;
    IPSECPPS pxIPsecPps = (NULL == pxIPsecSa) ? NULL
                        : &(pxIPsecSa->axP2Sa[oSaIndex].axChildSa[0].ipsecPps);
    ubyte oPpsNo = 0;
    intBoolean foundMatch = FALSE;

    for (;;)
    {
        intBoolean bNext = FALSE; /* for phase 2 responder */
        ubyte oSpiSize;

        /* proposal payload header */
        IN_BEGIN(struct ikePpsHdr, pxPpsHdr, SIZEOF_IKE_PPS_HDR)

        /* phase 2 - check proposal payload number */
        if (NULL != pxIPsecSa)
        {
            if (0 == oPpsIndex)
            {
                /* first payload of current proposal */
                oPpsNo = pxPpsHdr->oNum;
            }
            else if (oPpsNo != pxPpsHdr->oNum)
            {
                if (bInitiator) /* initiator */
                {
                    /* only one proposal expected */
                    status = ERR_IKE_BAD_PROPOSAL;
                    DBG_EXIT
                }

                /* this payload belongs to the next proposal - roll back! */
                ctx->oNextPayload = ISAKMP_NEXT_P;
                ctx->pBuffer -= SIZEOF_IKE_PPS_HDR;
                ctx->dwBufferSize += SIZEOF_IKE_PPS_HDR;
                ctx->dwLength -= SIZEOF_IKE_PPS_HDR;
                bNext = TRUE;
                goto next;
            }
            else
            {
                /* too many payloads - responder */
                if (!bInitiator && (IPSEC_NEST_MAX <= oPpsIndex))
                {
                    bMatch = FALSE;
                    IN_END
                    goto next;
                }
            }
            pxIPsecPps->oPpsNo = oPpsNo;
        }

        /* check spi size */
        oSpiSize = pxPpsHdr->oSpiSize;
        if (wBodyLen < oSpiSize)
        {
            SET_MSGTYPE(UNEQUAL_PAYLOAD_LENGTHS)
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }

        /* initiator accepts one transform per proposal payload */
        if (bInitiator && (1 != pxPpsHdr->oTfmLen))
        {
            status = ERR_IKE_BAD_TRANSFORM;
            DBG_EXIT
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

        /* phase 1 */
        if (NULL == pxIPsecSa)
        {
            if (PROTO_ISAKMP != pxPpsHdr->oProtoId) /* protocol id mismatch */
            {
                SET_MSGTYPE(INVALID_PROTOCOL_ID)
                status = ERR_IKE_BAD_PROTOCOL;
                DBG_EXIT
            }
        }
        else /* phase 2 */
        {
            ubyte4 dwSpi;

            if (bInitiator)
            {
                if (pxIPsecPps->oProtocol != pxPpsHdr->oProtoId) /* protocol id mismatch */
                {
                    status = ERR_IKE_BAD_PROTOCOL;
                    DBG_EXIT
                }
            }
            else /* responder */
            {
                /* skip proposal payload, if necessary */
                if (bMatch)
                {
                    /* check protocol id */
                    switch (pxIPsecPps->oProtocol = pxPpsHdr->oProtoId)
                    {
                    case PROTO_IPSEC_AH :
                    case PROTO_IPSEC_ESP :
                        break;
                    case PROTO_IPCOMP :
                        ctx->wMsgType = INVALID_PROTOCOL_ID;
                        pxIPsecSa->merror = ERR_IKE_BAD_PROTOCOL;
                        bMatch = FALSE; /* not supported */
                        break;
                    default :
                        ctx->wMsgType = INVALID_PROTOCOL_ID;
                        status = ERR_IKE_BAD_PROTOCOL;
                        DBG_EXIT
                    }
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
                SET_MSGTYPE(INVALID_SPI)
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

            ctx->pxIPsecPps = pxIPsecPps;
            ctx->oPpsIndex = oPpsIndex;

#ifdef __ENABLE_DIGICERT_IPCOMP__
            pxIPsecPps->oCompAlgo = 0; /* reset - jic */

            /* If the next payload is a PROTO_IPCOMP Proposal Payload,
               go ahead matching its child Transform Payload(s) first.
             */
            if (ISAKMP_NEXT_P == ctx->oNextPayload)
            {
                IN_END /* skip to next payload */

                if (OK != (status = InPpComp(ctx)))
                {
                    if (!bInitiator) /* responder */
                    {
                        if (ERR_IKE_MISMATCH == status) /* mismatch */
                        {
                            /* skip to next proposal */
                            bMatch = FALSE;
                            status = OK;
                            goto skip;
                        }
                    }
                    goto exit;
                }

                /* rollback to current payload */
                //ADVANCE(-wBodyLen)
                ctx->pBuffer -= wBodyLen;
                ctx->dwBufferSize += (ubyte4)wBodyLen;
                ctx->dwLength -= (ubyte4)wBodyLen;
            }
#endif
        } /* END of phase 2 */

        ADVANCE(oSpiSize)
        wBodyLen = (ubyte2)(wBodyLen - oSpiSize);

        /* down one level - go to child payloads */
        IN_DOWN(pxPpsHdr, ISAKMP_NEXT_T)

        /* transform payloads */
        {
            CATCH_PAYLOAD

            if (OK != (status = InTfm(ctx)))
            {
                if (!bInitiator) /* responder */
                {
                    if (ERR_IKE_MISMATCH == status) /* mismatch */
                    {
                        if (NULL != pxIPsecSa) /* phase 2 - skip to next proposal */
                        {
                            bMatch = FALSE;
                            status = OK;
                        }
                        else
                        {
                            if (ISAKMP_NEXT_P != pxPpsHdr->oNextPayload)
                            {
                                if (0 == ctx->wMsgType)
                                    ctx->wMsgType = NO_PROPOSAL_CHOSEN;
                                break;
                            }
                        }
                    }
                    else
                    {
                        if (0 == ctx->wMsgType)
                            ctx->wMsgType = BAD_PROPOSAL_SYNTAX;
                        goto exit;
                    }
                }
                else goto exit;
            }
            else
            {
                foundMatch = TRUE;
            }

            FINALLY_PAYLOAD
        }

        /* up one level */
        IN_UP(pxPpsHdr)

        /* phase 1 */
        if (NULL == pxIPsecSa)
        {
#ifdef __ENABLE_IKE_XAUTH__
            if ((65000 < AUTH_MTD(pxSa)) ||
#ifdef __ENABLE_IKE_HYBRID_RSA__
                (64220 < AUTH_MTD(pxSa)) ||
#endif
                (pxSa->ikePeerConfig->xauthType &&
                 (4 > pxSa->ikePeerConfig->xauthDraft)))
            {
                pxSa->flags |= IKE_SA_FLAG_XAUTH;
            }
#endif
            if (bInitiator)
            {
                if (ISAKMP_NEXT_NONE == pxPpsHdr->oNextPayload)
                    break;
            }
            else
            {
                /* if we are responder, and we found a tranform to use, we are done */
                if ((ISAKMP_NEXT_NONE == pxPpsHdr->oNextPayload) || (TRUE == foundMatch))
                    break;
            }
        }
        else
        {
            /* phase 2 */
#ifdef __ENABLE_DIGICERT_IPCOMP__
            if (pxIPsecPps->oCompAlgo) /* compression algo matched */
            {
                /* skip next payload (already processed) */
                struct ikePpsHdr *pxCompPpsHdr = (struct ikePpsHdr *) ctx->pBuffer;
                ubyte2 wCompPpsLen = GET_NTOHS(pxCompPpsHdr->wLength);
                ctx->oNextPayload = pxCompPpsHdr->oNextPayload;
                ADVANCE(wCompPpsLen)
            }
#endif
    skip:
            pxIPsecPps = &(pxIPsecSa->axP2Sa[oSaIndex].axChildSa[++oPpsIndex].ipsecPps);

    next:
            CURR_PAYLOAD /* !!! */

            if (bInitiator) /* initiator */
            {
                if (oPpsIndex >= pxIPsecSa->axP2Sa[oSaIndex].oChildSaLen)
                {
                    /* expect no more payloads */
                    if (ISAKMP_NEXT_NONE != ctx->oNextPayload)
                    {
                        status = ERR_IKE_MISMATCH;
                        DBG_EXIT
                    }
                    break; /* accept proposal */
                }
                if (ISAKMP_NEXT_NONE == ctx->oNextPayload) /* expect more payloads */
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
                if ((ISAKMP_NEXT_NONE == ctx->oNextPayload) || bNext)
                {
#ifndef __ENABLE_DIGICERT_PFKEY__
                    /* check IPsec SA bundle size */
                    if (bMatch && (IPSEC_NEST_MAX > oPpsIndex))
                    {
                        MSTATUS st;
                        struct ipsecKeyEx keyEx = { 0 };

                        pxIPsecPps->oProtocol   = 0;
                        pxIPsecPps->oEncrAlgo   = 0;
                        pxIPsecPps->wAuthAlgo   = 0;
                        pxIPsecPps->wMode       = 0;

                        IKE_initIPsecKey(&keyEx, pxSa, pxIPsecSa, pxIPsecPps,
                                         NULL, oSaIndex, oPpsIndex, _R);

                        if (OK > (st = IPSEC_keyReady(&keyEx)))
                        {
                            /* mismatch - proposed depth too small */
                            ctx->wMsgType = NO_PROPOSAL_CHOSEN;
                            pxIPsecSa->merror = st;
                            bMatch = FALSE;
                        }
                    }
#endif
                    /* accept proposal */
                    if (bMatch)
                    {
                        ctx->wMsgType = 0;
                        pxIPsecSa->merror = OK;
                        pxIPsecSa->axP2Sa[oSaIndex].oChildSaLen = oPpsIndex;

#ifdef __ENABLE_DIGICERT_PFKEY__
                        { sbyte4 i;
                        for (i=0; i < oPpsIndex; i++)
                        {
                            IPSECPPS pxPps = &(pxIPsecSa->axP2Sa[oSaIndex].axChildSa[i].ipsecPps);

                            /* get SPI */
                            IKE_stateCB *cb;
                            IPSECKEY key;

                            INIT_MOC_IPADDR(dstAddr, pxSa->dwHostAddr)
                            INIT_MOC_IPADDR(srcAddr, pxSa->dwPeerAddr)

                            CHECK_MALLOC_TYPE(IKE_stateCB, cb)

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
                            key->cookie         = pxIPsecSa->axP2Sa[oSaIndex].cookie;
                            if (i)
                            key->dwSeqNo        = pxIPsecSa->axP2Sa[oSaIndex].dwSeqNo;

                            key->funcPtrPfkeyCb = IKE_stateCallback;

                            cb->pxSa = pxSa;
                            cb->dwSaId = pxSa->dwId;
                            cb->pxXg = pxXg;
                            cb->dwMsgId = pxXg->dwMsgId;
                            cb->pxPps = pxPps;

                            if ((OK > (status = IPSEC_keySpi(key))) &&
                                (STATUS_IKE_PENDING != status))
                            {
                                FREE(cb);
                                /*ctx->wMsgType = ?;*/
                                DBG_EXIT
                            }

                            if (!i)
                            pxIPsecSa->axP2Sa[oSaIndex].dwSeqNo = key->dwSeqNo;

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
#if defined(__ENABLE_IPSEC_COOKIE__) || defined(__ENABLE_DIGICERT_PFKEY__)
                    pxIPsecSa->axP2Sa[oSaIndex].cookie = 0;
#endif
#ifdef __ENABLE_DIGICERT_PFKEY__
                    pxIPsecSa->axP2Sa[oSaIndex].oReplay = 0;
#endif
                    pxIPsecSa->axP2Sa[oSaIndex].dwSpdId = 0;
                    pxIPsecSa->axP2Sa[oSaIndex].spdIndex = 0;
                    pxIPsecPps = &(pxIPsecSa->axP2Sa[oSaIndex].axChildSa[0].ipsecPps);

                    if (0 == oSaIndex)
                    {
                        pxIPsecSa->wPFS = 0;
                        ctx->flags &= ~(IKE_CNTXT_FLAG_PFS);
                    }

                    continue;
                } /* END if ((ISAKMP_NEXT_NONE == ctx->oNextPayload) || bNext) */

                if (ISAKMP_NEXT_P != ctx->oNextPayload)
                {
                    ctx->wMsgType = BAD_PROPOSAL_SYNTAX;
                    status = ERR_IKE_BAD_PROPOSAL;
                    DBG_EXIT
                }
            } /* responder */
        }

    } /* for (;;) */

exit:
    return status;
} /* InPps */


/*------------------------------------------------------------------*/

static MSTATUS
InSa(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    IPSECSA pxIPsecSa = (ctx->pxP2Xg ? P2XG_IPSECSA(ctx->pxP2Xg) : NULL);
    intBoolean bInitiator = (pxIPsecSa ? IS_CHILD_INITIATOR(pxIPsecSa) : IS_INITIATOR(pxSa));

    ubyte4 dwBufferSize;
    ubyte4 dwLength;
    ubyte oNextPayload;
    void *pHdrParent;

    ubyte oSaIndex = 0; /* for phase 2 */

    for (;;)
    {
        /* SA payload header */
        IN_BEGIN(struct ikeSaHdr, pxSaHdr, SIZEOF_IKE_SA_HDR)

        if (ISAKMP_DOI_IPSEC != pxSaHdr->oDoi)
        {
            SET_MSGTYPE(DOI_NOT_SUPPORTED)
            status = ERR_IKE_BAD_MSG;
            DBG_EXIT
        }

        if (SIT_IDENTITY_ONLY != pxSaHdr->oSit)
        {
            SET_MSGTYPE(SITUATION_NOT_SUPPORTED)
            status = ERR_IKE_BAD_MSG;
            DBG_EXIT
        }

        if (NULL == pxIPsecSa) /* phase 1 */
        {
            /* store initiator SA payload body (no generic header) for HASH */
            if (!bInitiator) /* responder */
            {
                ubyte2 wSAi_bLen = wLength - (ubyte2)SIZEOF_IKE_GEN_HDR;
                pxSa->dwMsgLen[_I] = wSAi_bLen;
                CHECK_FREE(pxSa->poMsg[_I])
                CHECK_MALLOC(pxSa->poMsg[_I], wSAi_bLen)
                DIGI_MEMCPY(pxSa->poMsg[_I], (ubyte *)pxSaHdr + SIZEOF_IKE_GEN_HDR, wSAi_bLen);
            }
        }
        else /* phase 2 */
        {
            if (!bInitiator) /* responder */
                pxIPsecSa->oP2SaNum = oSaIndex + 1;

            ctx->oP2SaIndex = oSaIndex;
        }

        /* down one level - go to child payloads */
        IN_DOWN(pxSaHdr, ISAKMP_NEXT_P)

        /* proposal payload(s) */
        IN_FUNC(InPps)

        /* up one level */
        IN_UP(pxSaHdr)

        /* phase 1 */
        if (NULL == pxIPsecSa)
            break; /* only one SA payload */

        /* phase 2 */
        ++oSaIndex;

        CURR_PAYLOAD /* !!! */

        if (bInitiator) /* initiator */
        {
            if (oSaIndex >= pxIPsecSa->oP2SaNum) /* enough SA payloads */
                break;

            if (ISAKMP_NEXT_SA != ctx->oNextPayload) /* expect more */
            {
                status = ERR_IKE_BAD_SA;
                DBG_EXIT
                /* or accept fewer than we requested? */
            }
        }
        else /* responder */
        {
            if (ISAKMP_NEXT_SA != ctx->oNextPayload) /* no more SA payloads */
                break;

            if (IKE_P2_SA_MAX <= oSaIndex) /* too many SA payloads for us to handle */
            {
                status = ERR_IKE_BAD_PAYLOAD;
                DBG_EXIT
                /* or just skip it? */
            }
        }
    } /* for (;;) */

exit:
    return status;
} /* InSa */


/*------------------------------------------------------------------*/

extern MSTATUS
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

    IKESA pxSa = ctx->pxSa;

    ubyte2 wVidLen;
    ubyte *vid;
    sbyte4 compareResult;

#ifdef __ENABLE_IPSEC_NAT_T__
    sbyte4 i;
#endif

    /* generic header */
    if (OK != (status = InGen(ctx, &wVidLen)))
        goto exit;

    /* get VID */
    vid = ctx->pBuffer - wVidLen;

    /* NAT-T */
#ifdef __ENABLE_IPSEC_NAT_T__
    for (i=0; i < (sbyte4) NUM_VID_NAT_T; i++)
    {
        if (mNatTinfo[i].wVidLen == wVidLen)
        {
            if (OK > (status = DIGI_MEMCMP(vid, mNatTinfo[i].poVid, wVidLen, &compareResult)))
                DBG_EXIT

            if (0 == compareResult)
            {
                debug_print3("   VID: ", mNatTinfo[i].pDesc, NULL);

                /* only applicable in 1st round of msgs */
                switch (pxSa->oState)
                {
                case STATE_MAIN_I2 :
                case STATE_MAIN_R1 :
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
                case STATE_AGGR_I2 :
                case STATE_AGGR_R1 :
#endif
                    if ((0 >= pxSa->u.v1.iNatT) || (i < pxSa->u.v1.iNatT))
                        pxSa->u.v1.iNatT = i+1;
                    break;
                }
                goto exit;
            }
        }
    }
#endif /* __ENABLE_IPSEC_NAT_T__ */

    /* DPD */
    if ((ubyte2)vidDpdLen == wVidLen)
    {
        if (OK > (status = DIGI_MEMCMP(vid, vidDpd, wVidLen, &compareResult)))
            DBG_EXIT

        if (0 == compareResult)
        {
            debug_print3("   VID: ", vidDpdDesc, NULL);

            if (!pxSa->u.v1.dwDpdSeqNo)
            {
                ubyte4 dwDpdSeqNo;
                if (OK > (status = RANDOM_numberGenerator(g_pRandomContext,
                                                          (ubyte *) &dwDpdSeqNo,
                                                          sizeof(ubyte4))))
                    DBG_EXIT

                if (dwDpdSeqNo)
                {
                    pxSa->u.v1.dwDpdSeqNo = dwDpdSeqNo
                                      & 0x7fffffff; /* RFC3706 6.2. */
                }
            }
            goto exit;
        }
    }

#ifdef __ENABLE_IKE_XAUTH__
    if ((ubyte2)vidXauthLen == wVidLen)
    {
        if (OK > (status = DIGI_MEMCMP(vid, vidXauth, wVidLen, &compareResult)))
            DBG_EXIT

        if (0 == compareResult)
        {
            debug_print3("   VID: ", vidXauthDesc, NULL);
            goto exit;
        }
    }
#endif

#ifdef __ENABLE_IKE_FRAGMENTATION__
    if (!pxSa->ikePeerConfig->bNoIkeFrag)
    {
        if (16 <= wVidLen) /*((ubyte2)vidFragLen == wVidLen)*/
        {
            /* compare the first 16 bytes only */
            if (OK > (status = DIGI_MEMCMP(vid, vidFrag, 16, &compareResult)))
            {
                DBG_EXIT
            }

            /* check for Main mode fragmentation support */
            if ((0 == compareResult) &&
                ((16 == wVidLen) || ((vid[16] & 0x80) != 0)))
            {
                debug_print3("   VID: ", vidFragDesc, NULL);
                pxSa->flags |= IKE_SA_FLAG_FRAGMENTATION;
                goto exit;
            }
        }
    }
#endif

#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
    if ((ubyte2)vidPerpLen == wVidLen)
    {
        if (OK > (status = DIGI_MEMCMP(vid, vidPerp, wVidLen, &compareResult)))
        {
            DBG_EXIT
        }

        if (0 == compareResult)
        {
            debug_print3("   VID: ", vidPerpDesc, NULL);
            goto exit;
        }
    }
#endif

    debug_printd((sbyte *)"   VID:", vid, wVidLen);

#ifdef CUSTOM_IKE_CATCH_EXCEPTION
    {
        MOC_IP_ADDRESS peerAddr = REF_MOC_IPADDR(pxSa->dwPeerAddr);
        struct ikeHdr *pxIkeHdr = (struct ikeHdr *) ctx->pHdrParent;
        void *pVid = ctx->pCurrPayload;
        P2XG pxXg = ctx->pxP2Xg;
        IPSECSA pxIPsecSa = ((NULL != pxXg) && IS_QUICK_MODE_STATE(pxXg->oState))
                          ? P2XG_IPSECSA(pxXg) : NULL;

        CUSTOM_IKE_CATCH_EXCEPTION(ERR_IKE_UNKNOWN_VID,
            peerAddr, pxIkeHdr,
            ISAKMP_NEXT_VID, pVid,
            pxSa, pxXg, pxIPsecSa);
    }
#endif

exit:
    return status;
} /* InVid */


/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_ECC__

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static MSTATUS
IKEEC_setPointFromByteString(PEllipticCurvePtr pEC,
                             const ubyte* s, sbyte4 len,
                             PFEPtr pX, PFEPtr pY)
{
    MSTATUS         status;

    PrimeFieldPtr   pPF;
    sbyte4          elemLen;

    pPF = EC_getUnderlyingField(pEC);

    if (OK > (status = PRIMEFIELD_getElementByteStringLen(pPF, &elemLen)))
        goto exit;

    if ((2 * elemLen) != len)
    {
        status = ERR_FF_INVALID_PT_STRING;
        goto exit;
    }

    if (OK > (status = PRIMEFIELD_setToByteString(pPF, pX, s, elemLen)))
        goto exit;

    if (OK > (status = PRIMEFIELD_setToByteString(pPF, pY, s + elemLen, elemLen)))
        goto exit;

exit:
    return status;
} /* IKEEC_setPointFromByteString */
#endif


/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__

extern MSTATUS
IKEEC_byteStringToPoint(PEllipticCurvePtr pEC,
                        const ubyte* s, sbyte4 len,
                        PFEPtr* ppX, PFEPtr* ppY)
{
    MSTATUS         status;

    PrimeFieldPtr   pPF = NULL;

    PFEPtr          pNewX = NULL;
    PFEPtr          pNewY = NULL;

    if (!pEC || !s || !ppX || !ppY)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    pPF = EC_getUnderlyingField(pEC);

    if (OK > (status = PRIMEFIELD_newElement(pPF, &pNewX)))
        goto exit;

    if (OK > (status = PRIMEFIELD_newElement(pPF, &pNewY)))
        goto exit;

    if (OK > (status = IKEEC_setPointFromByteString(pEC, s, len, pNewX, pNewY)))
        goto exit;

    *ppX = pNewX;
    pNewX = 0;
    *ppY = pNewY;
    pNewY = 0;

exit:
    if (pPF)
    {
        PRIMEFIELD_deleteElement(pPF, &pNewX);
        PRIMEFIELD_deleteElement(pPF, &pNewY);
    }
    return status;
} /* IKEEC_byteStringToPoint */
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

#endif /* __ENABLE_DIGICERT_ECC__ */


/*------------------------------------------------------------------*/

static MSTATUS
InKe(IKE_context ctx)
{
    MSTATUS                 status      = OK;

    IKESA                   pxSa        = ctx->pxSa;
    IPSECSA                 pxIPsecSa   = (ctx->pxP2Xg ? P2XG_IPSECSA(ctx->pxP2Xg) : NULL);
    intBoolean              bInitiator  = (pxIPsecSa ? IS_CHILD_INITIATOR(pxIPsecSa) : IS_INITIATOR(pxSa));

    ubyte2                  wLength;

    diffieHellmanContext*   pDHctx      = NULL;
    vlong*                  pMpintE     = NULL;
    vlong*                  pVlongQueue = NULL;

#ifdef __ENABLE_DIGICERT_ECC__
    ECCKey*                 pEccKey     = NULL;
    ubyte4                  curveId = 0;
    ubyte*                  pPubPoint = NULL;
#endif

#ifdef __ENABLE_DIGICERT_PQC__
    QS_CTX*                 pQsCtx      = NULL;
    ubyte*                  pQsPubKey   = NULL;
    ubyte4                  qsPubKeyLen = 0;
#endif

    /* phase 2 - check PFS */
    if (NULL != pxIPsecSa)
    {
        if (0 == pxIPsecSa->wPFS)
        {
            status = ERR_IKE_BAD_KE; /* no KE payload is needed */
            DBG_EXIT
        }
    }

    /* already received KE payload? */
    if (IKE_CNTXT_FLAG_KE & ctx->flags)
    {
        status = ERR_IKE_BAD_KE;
        DBG_EXIT
    }

    /* create DH context, if necessary */
    if (!bInitiator) /* responder */
    {
        ubyte2 wGroup = 0;
        IKE_dhGroupInfo *pDhGroup;

        diffieHellmanContext **ppDHctx = (pxIPsecSa ?
                                        &(DIFFIEHELLMAN_CONTEXT(pxIPsecSa)) :
                                        &(DIFFIEHELLMAN_CONTEXT(pxSa)));
#ifdef __ENABLE_DIGICERT_ECC__
        ECCKey **ppEccKey = (pxIPsecSa ? &pxIPsecSa->p_eccKey : &pxSa->p_eccKey);
#endif

#ifdef __ENABLE_DIGICERT_PQC__
        QS_CTX **ppQsCtx = (pxIPsecSa ? &pxIPsecSa->pQsCtx : &pxSa->pQsCtx);
#endif

        /* get DH group number */
        if (NULL != pxIPsecSa) /* phase 2 */
            wGroup = pxIPsecSa->wPFS;
        else if (NULL != pxSa) /* phase 1 */
            wGroup = pxSa->u.v1.pwIsaAttr[OAKLEY_GROUP_DESCRIPTION];

        if (!wGroup || (NULL == (pDhGroup = IKE_dhGroupEx(pxSa->ikePeerConfig, wGroup))))
        {
            status = ERR_IKE_BAD_KE;
            DBG_EXIT
        }

        /* clean up and create */
        if (NULL != *ppDHctx)
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            CRYPTO_INTERFACE_DH_freeDhContextExt(ppDHctx, &pVlongQueue, NULL);
#else
            DH_freeDhContext(ppDHctx, &pVlongQueue);
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

            if (NULL == pxIPsecSa) /* IKE_SA */
            {
                if (NULL != pxSa->p_eccKeyPeer)
                {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                    CRYPTO_INTERFACE_EC_deleteKeyAux(&pxSa->p_eccKeyPeer);
#else
                    EC_deleteKey(&pxSa->p_eccKeyPeer);
#endif
                }
            }
        }

#ifdef __ENABLE_DIGICERT_PQC__
        if (NULL != *ppQsCtx)
        {
            CRYPTO_INTERFACE_QS_deleteCtx(ppQsCtx);
        }
#endif

        if (0 != (curveId = pDhGroup->curveId))
        {
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
            if (0 < pDhGroup->qsAlgoId)
            {
                status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(ctx->hwAccelCookie) &pQsCtx, pDhGroup->qsAlgoId);
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
    else /* initiator */
    {
        /* get DH context */
        pDHctx = (pxIPsecSa ? DIFFIEHELLMAN_CONTEXT(pxIPsecSa) : DIFFIEHELLMAN_CONTEXT(pxSa));
        if (NULL != pDHctx)
        {
            /* jic re-transmit */
            if (NULL != pxIPsecSa)
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
            else
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
        }
        else
        {
#ifdef __ENABLE_DIGICERT_ECC__
            pEccKey = (pxIPsecSa ? pxIPsecSa->p_eccKey : pxSa->p_eccKey);
            if (NULL != pEccKey)
            {
                /* jic re-transmit */
                if (NULL == pxIPsecSa) /* IKE_SA */
                {
                    if (NULL != pxSa->p_eccKeyPeer)
                    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                        CRYPTO_INTERFACE_EC_deleteKeyAux(&pxSa->p_eccKeyPeer);
#else
                        EC_deleteKey(&pxSa->p_eccKeyPeer);
#endif
                    }
                }

#ifdef __ENABLE_DIGICERT_PQC__
                pQsCtx = (pxIPsecSa ? pxIPsecSa->pQsCtx : pxSa->pQsCtx);
#endif
            }
            else
#endif
            {
                /* jic - redundant? */
                status = ERR_IKE_BAD_KE;
                DBG_EXIT
            }
        }
    }

    /* generic header */
    if (OK != (status = InGen(ctx, &wLength)))
        DBG_EXIT

    /* key exchange data */
#ifdef __ENABLE_DIGICERT_ECC__
    if (NULL != pEccKey)
    {
        ubyte** ppSharedSecret = (pxIPsecSa ? &pxIPsecSa->poEccSharedSecret : &pxSa->poEccSharedSecret);
        sbyte4* pSharedSecretLen = (pxIPsecSa ? &pxIPsecSa->eccSharedSecretLen : &pxSa->eccSharedSecretLen);
        ubyte4 eccPubKeyLen = 0;

        if (NULL != *ppSharedSecret) /* jic */
        {
            FREE(*ppSharedSecret);
            *ppSharedSecret = NULL;
            *pSharedSecretLen = 0;
        }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pEccKey, &curveId);
#else
        status = EC_getCurveIdFromKey(pEccKey, &curveId);
#endif
        if (OK != status)
            DBG_EXIT

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_EC_getPointByteStringLenByCurveId(curveId, &eccPubKeyLen);
#else
        status = EC_getPointByteStringLenByCurveId(curveId, &eccPubKeyLen);
#endif
        if (OK != status)
            DBG_EXIT

        /* Allocate a new buffer for the public point, the EC and ECDH functions expect the
         * public key in this format */
        status = DIGI_MALLOC((void **)&pPubPoint, (ubyte4)(eccPubKeyLen));
        if (OK != status)
            goto exit;

        /* Set the byte for compression status */
        pPubPoint[0] = 0x04;

        /* Copy the concatenation of X and Y from ctx->pBuffer to form (0x04 || X || Y) */
        status = DIGI_MEMCPY (
            (void *)(pPubPoint + 1), (void *)(ctx->pBuffer - wLength), (ubyte4)(eccPubKeyLen - 1));
        if (OK != status)
            goto exit;

        if (NULL != pxIPsecSa) /* CHILD_SA */
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux (MOC_ECC(ctx->hwAccelCookie)
                pEccKey, pPubPoint, (ubyte4)(eccPubKeyLen), ppSharedSecret, (ubyte4 *)pSharedSecretLen,
                (IKE_SETTINGS_FLAG_ECDH_XY & m_ikeSettings.flags) ? 0 : 1, NULL);
#else
            status = ECDH_generateSharedSecretFromPublicByteString (MOC_ECC(ctx->hwAccelCookie)
                pEccKey, pPubPoint, (ubyte4)(eccPubKeyLen), ppSharedSecret, (ubyte4 *)pSharedSecretLen,
                (IKE_SETTINGS_FLAG_ECDH_XY & m_ikeSettings.flags) ? 0 : 1, NULL);
#endif
            if (OK != status)
                DBG_EXIT

#ifdef __ENABLE_DIGICERT_PQC__
            if (NULL != pQsCtx)
            {
                ubyte** ppQsSharedSecret = &pxIPsecSa->pQsSharedSecret;
                ubyte4* pQsSharedSecretLen = &pxIPsecSa->qsSharedSecretLen;

                ubyte** ppQsCipherText = &pxIPsecSa->pQsCipherText;
                ubyte4* pQsCipherTextLen = &pxIPsecSa->qsCipherTextLen;

                ubyte* pCombinedSecret = NULL;
                ubyte4 combinedSecretLen = 0;

                if (bInitiator)
                {
                    *pQsCipherTextLen = wLength - eccPubKeyLen + 1;
                    status = DIGI_MALLOC ((void **) ppQsCipherText, *pQsCipherTextLen);
                    if (OK != status)
                        DBG_EXIT

                    status = DIGI_MEMCPY (*ppQsCipherText, ctx->pBuffer - *pQsCipherTextLen, *pQsCipherTextLen);
                    if (OK != status)
                        DBG_EXIT

                    status = CRYPTO_INTERFACE_QS_KEM_decapsulateAlloc (pQsCtx, *ppQsCipherText,
                        *pQsCipherTextLen, ppQsSharedSecret, pQsSharedSecretLen);
                    if (OK != status)
                        DBG_EXIT
                }
                else
                {
                    qsPubKeyLen = wLength - eccPubKeyLen + 1;
                    status = DIGI_MALLOC ((void **) &pQsPubKey, qsPubKeyLen);
                    if (OK != status)
                        DBG_EXIT

                    status = DIGI_MEMCPY (pQsPubKey, ctx->pBuffer - qsPubKeyLen, qsPubKeyLen);
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
        else /* IKE_SA */
        {
            ECCKey *pEccKeyPeer;

            /* TODO: can this code be removed? */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pEccKey, &curveId);
#else
            status = EC_getCurveIdFromKey(pEccKey, &curveId);
#endif
            if (OK != status)
                DBG_EXIT

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_EC_newPublicKeyFromByteStringAux (MOC_ECC(ctx->hwAccelCookie)
                curveId, &pEccKeyPeer, pPubPoint, (ubyte4)(eccPubKeyLen));
#else
            status = EC_newPublicKeyFromByteString (MOC_ECC(ctx->hwAccelCookie)
                curveId, &pEccKeyPeer, pPubPoint, (ubyte4)(eccPubKeyLen));
#endif
            if (OK != status)
                DBG_EXIT

            pxSa->p_eccKeyPeer = pEccKeyPeer;
            /* TODO: is this value set in above API making
             * this redundant? */
            pEccKeyPeer->privateKey = FALSE;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromKeysAux (MOC_ECC(ctx->hwAccelCookie)
                pEccKey, pEccKeyPeer, ppSharedSecret, (ubyte4 *)pSharedSecretLen,
                (IKE_SETTINGS_FLAG_ECDH_XY & m_ikeSettings.flags) ? 0 : 1, NULL);
#else
            status = ECDH_generateSharedSecretFromKeys (MOC_ECC(ctx->hwAccelCookie)
                pEccKey, pEccKeyPeer, ppSharedSecret, (ubyte4 *)pSharedSecretLen,
                (IKE_SETTINGS_FLAG_ECDH_XY & m_ikeSettings.flags) ? 0 : 1, NULL);
#endif
            if (OK != status)
                DBG_EXIT

#ifdef __ENABLE_DIGICERT_PQC__
        if (NULL != pQsCtx)
        {
            ubyte** ppQsSharedSecret = (pxIPsecSa ? &pxIPsecSa->pQsSharedSecret : &pxSa->pQsSharedSecret);
            ubyte4* pQsSharedSecretLen = (pxIPsecSa ? &pxIPsecSa->qsSharedSecretLen : &pxSa->qsSharedSecretLen);

            ubyte** ppQsCipherText = (pxIPsecSa ? &pxIPsecSa->pQsCipherText : &pxSa->pQsCipherText);
            ubyte4* pQsCipherTextLen = (pxIPsecSa ? &pxIPsecSa->qsCipherTextLen : &pxSa->qsCipherTextLen);

            ubyte* pCombinedSecret = NULL;
            ubyte4 combinedSecretLen = 0;

            /* initiator sends public key, responder sends cipher text encrypted
             * with public key. */
            if (bInitiator)
            {
                *pQsCipherTextLen = wLength - eccPubKeyLen + 1;
                status = DIGI_MALLOC ((void **) ppQsCipherText, *pQsCipherTextLen);
                if (OK != status)
                    DBG_EXIT

                status = DIGI_MEMCPY (*ppQsCipherText, ctx->pBuffer - *pQsCipherTextLen, *pQsCipherTextLen);
                if (OK != status)
                    DBG_EXIT

                status = CRYPTO_INTERFACE_QS_KEM_decapsulateAlloc (pQsCtx, *ppQsCipherText,
                    *pQsCipherTextLen, ppQsSharedSecret, pQsSharedSecretLen);
                if (OK != status)
                    DBG_EXIT
            }
            else
            {
                qsPubKeyLen = wLength - eccPubKeyLen + 1;
                status = DIGI_MALLOC ((void **) &pQsPubKey, qsPubKeyLen);
                if (OK != status)
                    DBG_EXIT

                status = DIGI_MEMCPY (pQsPubKey, ctx->pBuffer - qsPubKeyLen, qsPubKeyLen);
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
    }
    else
#endif
    {
        if (NULL == pDHctx) /* jic */
        {
            status = ERR_NULL_POINTER;
            DBG_EXIT
        }

        if (NULL != pxIPsecSa)
        {
            status = DIGI_MALLOC((void **)(&(pxIPsecSa->pDhPeerPubKey)), (ubyte4)wLength);
            if (OK != status)
                goto exit;

            /* Save the client public key */
            status = DIGI_MEMCPY (
                (void *)pxIPsecSa->pDhPeerPubKey, (void *)(ctx->pBuffer - wLength), (ubyte4)wLength);
            if (OK != status)
                goto exit;
            pxIPsecSa->dhPeerPubKeyLen = (ubyte4)wLength;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_DH_computeKeyExchangeExExt (MOC_DH(ctx->hwAccelCookie)
                pDHctx, g_pRandomContext, ctx->pBuffer - wLength, (ubyte4)wLength,
                &(pxIPsecSa->pDhSharedSecret), &(pxIPsecSa->dhSharedSecretLen), NULL);
            if (OK != status)
                goto exit;
#else
            status = DH_computeKeyExchangeEx (MOC_DH(ctx->hwAccelCookie)
                pDHctx, g_pRandomContext, ctx->pBuffer - wLength, (ubyte4)wLength,
                &(pxIPsecSa->pDhSharedSecret), &(pxIPsecSa->dhSharedSecretLen));
            if (OK != status)
                goto exit;
#endif
        }
        else
        {
            status = DIGI_MALLOC((void **)(&(pxSa->pDhPeerPubKey)), (ubyte4)wLength);
            if (OK != status)
                goto exit;

            /* Save the client public key */
            status = DIGI_MEMCPY (
                (void *)pxSa->pDhPeerPubKey, (void *)(ctx->pBuffer - wLength), (ubyte4)wLength);
            if (OK != status)
                goto exit;

            pxSa->dhPeerPubKeyLen = (ubyte4)wLength;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_DH_computeKeyExchangeExExt (MOC_DH(ctx->hwAccelCookie)
                pDHctx, g_pRandomContext, ctx->pBuffer - wLength, (ubyte4)wLength,
                &(pxSa->pDhSharedSecret), &(pxSa->dhSharedSecretLen), NULL);
            if (OK != status)
                goto exit;
#else
            status = DH_computeKeyExchangeEx (MOC_DH(ctx->hwAccelCookie)
                pDHctx, g_pRandomContext, ctx->pBuffer - wLength, (ubyte4)wLength,
                &(pxSa->pDhSharedSecret), &(pxSa->dhSharedSecretLen));
            if (OK != status)
                goto exit;
#endif
        }
    }

    ctx->flags |= IKE_CNTXT_FLAG_KE;

exit:
    VLONG_freeVlong(&pMpintE, NULL);
    VLONG_freeVlongQueue(&pVlongQueue);
#ifdef __ENABLE_DIGICERT_ECC__
    if(pPubPoint)
        DIGI_FREE((void **) &pPubPoint);
#endif
    return status;
} /* InKe */


/*------------------------------------------------------------------*/

static MSTATUS
DoKe(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    intBoolean bInitiator = IS_INITIATOR(pxSa);

    diffieHellmanContext *pDHctx = DIFFIEHELLMAN_CONTEXT(pxSa);

    sbyte4 stringLenK;
    ubyte* pStringMpintK = NULL;/* DH shared secret */

#ifdef __ENABLE_DIGICERT_ECC__
    sbyte4 stringLenE;
    ubyte* pStringMpintE = NULL;/* DH client public value */
#endif

    sbyte4 stringLenEToUse;
    ubyte* pStringMpintEToUse = NULL;/* DH client public value */

#ifdef __ENABLE_DIGICERT_ECC__
    sbyte4 stringLenF;
    ubyte* pStringMpintF = NULL;/* DH server public value */
#endif

    sbyte4 stringLenFToUse;
    ubyte* pStringMpintFToUse = NULL;/* DH server public value */

    sbyte4 stringLen_I, stringLen_R;
    ubyte *pStringMpint_I, *pStringMpint_R;

    ubyte2 wEncrKeyLen = pxSa->wEncrKeyLen;
    const BulkHashAlgo *pBHAlgo = pxSa->pHashSuite->pBHAlgo;
    ubyte2 wDigestLen = (ubyte2) pBHAlgo->digestSize;

    HMAC_CTX *hmacCtxt = NULL;
    BulkCtx hashCtxt = NULL;

    ubyte __crypto__(poKeyId, IKE_ENCRKEY_MAX);
    ubyte __crypto__(poIv, IKE_IV_MAX);

    MDhKeyTemplate keyTemplate = {0};
    ubyte *pBuffer = NULL;

    /* get DH value byte strings */
#ifdef __ENABLE_DIGICERT_ECC__
    ECCKey *pEccKey = pxSa->p_eccKey;
    if (NULL != pEccKey)
    {
        ECCKey *pEccKeyPeer = pxSa->p_eccKeyPeer;
        pStringMpintK = pxSa->poEccSharedSecret;
        stringLenK = pxSa->eccSharedSecretLen;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAllocAux (MOC_ECC(ctx->hwAccelCookie)
            pEccKeyPeer, &pStringMpintE, (ubyte4 *)&stringLenE);
        if (OK != status)
            goto exit;
#else
        status = EC_writePublicKeyToBufferAlloc (MOC_ECC(ctx->hwAccelCookie)
            pEccKeyPeer, &pStringMpintE, (ubyte4 *)&stringLenE);
        if (OK != status)
            goto exit;
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAllocAux (MOC_ECC(ctx->hwAccelCookie)
            pEccKey, &pStringMpintF, (ubyte4 *)&stringLenF);
        if (OK != status)
            goto exit;
#else
        status = EC_writePublicKeyToBufferAlloc (MOC_ECC(ctx->hwAccelCookie)
            pEccKey, &pStringMpintF, (ubyte4 *)&stringLenF);
        if (OK != status)
            goto exit;
#endif

        pStringMpintEToUse = pStringMpintE + 1;
        stringLenEToUse = stringLenE - 1;

        pStringMpintFToUse = pStringMpintF + 1;
        stringLenFToUse = stringLenF - 1;
    }
    else
#endif /* __ENABLE_DIGICERT_ECC__ */
    {
        pStringMpintK = pxSa->pDhSharedSecret;
        stringLenK = pxSa->dhSharedSecretLen;
        pStringMpintEToUse = pxSa->pDhPeerPubKey;
        stringLenEToUse = pxSa->dhPeerPubKeyLen;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_DH_getKeyParametersAlloc(MOC_DH(ctx->hwAccelCookie) &keyTemplate, pDHctx, MOC_GET_PRIVATE_KEY_DATA);
        if (OK != status)
            goto exit;
#else
        status = DH_getKeyParametersAlloc(MOC_DH(ctx->hwAccelCookie) &keyTemplate, pDHctx, MOC_GET_PRIVATE_KEY_DATA);
        if (OK != status)
            goto exit;
#endif

        /* RFC 2409, section 5:
         * The Diffie-Hellman public value passed in a KE payload, in either a
         * phase 1 or phase 2 exchange, MUST be the length of the negotiated
         * Diffie-Hellman group enforced, if necessary, by pre-pending the value
         * with zeros.
         */
        if (keyTemplate.fLen < keyTemplate.pLen)
        {
            status = DIGI_MALLOC((void **)&pBuffer, keyTemplate.pLen);
            if (OK != status)
            {
                goto exit;
            }

            DIGI_MEMSET(pBuffer, 0, keyTemplate.pLen - keyTemplate.fLen);
            DIGI_MEMCPY(pBuffer + keyTemplate.pLen - keyTemplate.fLen,
                    keyTemplate.pF, keyTemplate.fLen);

            pStringMpintFToUse = pBuffer;
            stringLenFToUse = keyTemplate.pLen;
        }
        else
        {
            pStringMpintFToUse = keyTemplate.pF;
            stringLenFToUse = keyTemplate.fLen;
        }
    }

    /* get PRF */
    if (OK > (status = HmacCreate(MOC_HASH(ctx->hwAccelCookie) &hmacCtxt, pBHAlgo)))
        DBG_EXIT

    if (OK > (status = pBHAlgo->allocFunc(MOC_HASH(ctx->hwAccelCookie) &hashCtxt)))
        DBG_EXIT

    /* generate SKEYID */
    _CRYPTO_ALLOC_(poKeyId, IKE_ENCRKEY_MAX) /* !!! */

    switch (BASE_AUTH_MTD(pxSa))
    {
    case OAKLEY_PRESHARED_KEY :
    {
        /* get PSK */
        ubyte4 dwKeyLen = 0;
        ubyte *poKey = NULL;
        if (OK > (status = IKE_getPsk(&poKey, &dwKeyLen, pxSa, 0)))
            DBG_EXIT

        status = HmacKey(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poKey, dwKeyLen);

#ifdef CUSTOM_IKE_GET_PSK
        if (poKey != pxSa->ikePeerConfig->ikePSKey)
            DIGI_MEMSET(poKey, 0x00, dwKeyLen); /* wipe out PSK from memory */
#endif
        if ((OK > status) ||
            (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->poNonce[_I], pxSa->wNonceLen[_I]))) ||
            (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->poNonce[_R], pxSa->wNonceLen[_R]))) ||
            (OK > (status = HmacFinal(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, /*pxSa->*/poKeyId))))
            DBG_EXIT

        break;
    }
    case OAKLEY_RSA_SIG :
#ifdef __ENABLE_DIGICERT_ECC__
    case OAKLEY_ECDSA_SIG :
    case OAKLEY_ECDSA_256 :
    case OAKLEY_ECDSA_384 :
    case OAKLEY_ECDSA_521 :
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    case OAKLEY_P256_MLDSA_44:
    case OAKLEY_P256_FNDSA512:
    case OAKLEY_P384_MLDSA_65:
    case OAKLEY_P521_FNDSA1024:
#endif
    {
        ubyte2 wKeyLen = pxSa->wNonceLen[_I] + pxSa->wNonceLen[_R];
        ubyte *poKey;

        if (sizeof(hmacCtxt->key) < wKeyLen)
        {
            status = ERR_BAD_LENGTH;
            DBG_EXIT
        }

        CHECK_MALLOC(poKey, wKeyLen)

        DIGI_MEMCPY(poKey, pxSa->poNonce[_I], pxSa->wNonceLen[_I]);
        DIGI_MEMCPY(poKey + pxSa->wNonceLen[_I], pxSa->poNonce[_R], pxSa->wNonceLen[_R]);

        status = HmacKey(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poKey, wKeyLen);
        FREE(poKey);

        if ((OK > status) ||
            (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pStringMpintK, stringLenK))) ||
            (OK > (status = HmacFinal(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, /*pxSa->*/poKeyId))))
            DBG_EXIT

        break;
    }
    default :
        status = ERR_IKE; /* should not get here */
        DBG_EXIT
    } /* switch */

    DIGI_MEMCPY(pxSa->u.v1.poKeyId, poKeyId, wDigestLen);
    debug_printk((sbyte *)"    SKEYID", poKeyId, wDigestLen);

    /* generate SKEYID_D */
    if (OK > (status = HmacKey(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->u.v1.poKeyId, wDigestLen)) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pStringMpintK, stringLenK)) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->poCky_I, IKE_COOKIE_SIZE)) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->poCky_R, IKE_COOKIE_SIZE)) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, (ubyte *) "\0", 1)) ||
        OK > (status = HmacFinal(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, /*pxSa->u.v1.*/poKeyId/*_d*/)))
        DBG_EXIT

    DIGI_MEMCPY(pxSa->u.v1.poKeyId_d, poKeyId, wDigestLen);
    debug_printk((sbyte *)"    SKEYID_d", poKeyId, wDigestLen);

    /* generate SKEYID_A */
    if (OK > (status = HmacReset(MOC_HASH(ctx->hwAccelCookie) hmacCtxt)) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->u.v1.poKeyId_d, wDigestLen)) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pStringMpintK, stringLenK)) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->poCky_I, IKE_COOKIE_SIZE)) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->poCky_R, IKE_COOKIE_SIZE)) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, (ubyte *) "\1", 1)) ||
        OK > (status = HmacFinal(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, /*pxSa->u.v1.*/poKeyId/*_a*/)))
        DBG_EXIT

    DIGI_MEMCPY(pxSa->u.v1.poKeyId_a, poKeyId, wDigestLen);
    debug_printk((sbyte *)"    SKEYID_a", poKeyId, wDigestLen);

    /* generate SKEYID_E */
    if (OK > (status = HmacReset(MOC_HASH(ctx->hwAccelCookie) hmacCtxt)) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->u.v1.poKeyId_a, wDigestLen)) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pStringMpintK, stringLenK)) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->poCky_I, IKE_COOKIE_SIZE)) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->poCky_R, IKE_COOKIE_SIZE)) ||
        OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, (ubyte *) "\2", 1)) ||
        OK > (status = HmacFinal(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, /*pxSa->u.v1.*/poKeyId/*_e*/)))
        DBG_EXIT

    DIGI_MEMCPY(pxSa->u.v1.poKeyId_e, poKeyId, wDigestLen);
    debug_printk((sbyte *)"    SKEYID_e", poKeyId, wDigestLen);

    /* if SKEYID_E is too small to be the encryption key, expand it */
    if (wEncrKeyLen > wDigestLen)
    {
        sbyte4 i, count = (wEncrKeyLen / wDigestLen) + ((wEncrKeyLen % wDigestLen) ? 1 : 0);
        ubyte *poKey;

        if (OK > (status = HmacKey(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, /*pxSa->u.v1.*/poKeyId/*_e*/, wDigestLen)) ||
            OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, (ubyte *) "\0", 1)))
            DBG_EXIT

        for (poKey = /*pxSa->u.v1.*/poKeyId/*_e*/, i=1; ; i++, poKey += wDigestLen)
        {
            if (OK > (status = HmacFinal(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poKey)))
                DBG_EXIT

            if (i >= count) break;

            if (OK > (status = HmacReset(MOC_HASH(ctx->hwAccelCookie) hmacCtxt)) ||
                OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, poKey, wDigestLen)))
                DBG_EXIT
        }

        DIGI_MEMCPY(pxSa->u.v1.poKeyId_e, poKeyId, wEncrKeyLen);
    }
    debug_printk((sbyte *)"    Encryption key", poKeyId, wEncrKeyLen);

    /* encryption iv */
    if (bInitiator)
    {
        pStringMpint_I = pStringMpintFToUse;
        pStringMpint_R = pStringMpintEToUse;
        stringLen_I = stringLenFToUse;
        stringLen_R = stringLenEToUse;
    }
    else
    {
        pStringMpint_I = pStringMpintEToUse;
        pStringMpint_R = pStringMpintFToUse;
        stringLen_I = stringLenEToUse;
        stringLen_R = stringLenFToUse;
    }

    _CRYPTO_ALLOC_(poIv, IKE_IV_MAX)

    if (OK > (status = pBHAlgo->initFunc(MOC_HASH(ctx->hwAccelCookie) hashCtxt)) ||
        OK > (status = pBHAlgo->updateFunc(MOC_HASH(ctx->hwAccelCookie) hashCtxt, pStringMpint_I, stringLen_I)) ||
        OK > (status = pBHAlgo->updateFunc(MOC_HASH(ctx->hwAccelCookie) hashCtxt, pStringMpint_R, stringLen_R)) ||
        OK > (status = pBHAlgo->finalFunc(MOC_HASH(ctx->hwAccelCookie) hashCtxt, /*pxSa->u.v1.*/poIv)))
        DBG_EXIT

    DIGI_MEMCPY(pxSa->u.v1.poIv, poIv, IKE_IV_MAX);
    DIGI_MEMCPY(pxSa->u.v1.poIvOld, poIv, pxSa->pCipherSuite->wIvLen);

#ifndef __ENABLE_KEYVPN_LOG_SUPPRESSION__
    debug_printd((sbyte *)"    Initialization vector:", /*pxSa->u.v1.*/poIv, pxSa->pCipherSuite->wIvLen);
#endif

    /* done */
    pxSa->flags |= IKE_SA_FLAG_KE;

exit:
    _CRYPTO_FREE_(poIv)
    _CRYPTO_FREE_(poKeyId)
    if (hashCtxt) pBHAlgo->freeFunc(MOC_HASH(ctx->hwAccelCookie) &hashCtxt);
    if (hmacCtxt) HmacDelete(MOC_HASH(ctx->hwAccelCookie) &hmacCtxt);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DH_freeKeyTemplateExt(pDHctx, &keyTemplate, NULL);
#else
    DH_freeKeyTemplate(pDHctx, &keyTemplate);
#endif

    if (pStringMpintK != pxSa->pDhSharedSecret)
    {
#ifdef __ENABLE_DIGICERT_ECC__
        if (pStringMpintK != pxSa->poEccSharedSecret)
        {
            CHECK_FREE(pStringMpintK)
        }
#else
        pStringMpintK = NULL;
#endif
    }

#ifdef __ENABLE_DIGICERT_ECC__
    CHECK_FREE(pStringMpintE)
    CHECK_FREE(pStringMpintF)
#endif

    DIGI_FREE((void **)&pBuffer);
    return status;
} /* DoKe */


/*------------------------------------------------------------------*/

static MSTATUS
DoKe2(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    IPSECSA pxIPsecSa = P2XG_IPSECSA(ctx->pxP2Xg);

    diffieHellmanContext *pDHctx = DIFFIEHELLMAN_CONTEXT(pxIPsecSa);

    sbyte4 stringLenK = 0;
    ubyte* pStringMpintK = NULL;/* DH shared secret */

    const BulkHashAlgo *pBHAlgo = pxSa->pHashSuite->pBHAlgo;
    ubyte2 wDigestLen = (ubyte2) pBHAlgo->digestSize;
    HMAC_CTX *hmacCtxt = NULL;

    ubyte2 bitStrength = 0;
#ifndef __DISABLE_DIGICERT_CONSTRAINT_CIPHER__
    bitStrength = CHILDSA_cipherEffectiveBitStrength(pxSa->pCipherSuite->wTfmId, pxSa->wEncrKeyLen);
#endif

    ubyte __crypto__(poKey, CHILDSA_ENCRKEY_MAX + CHILDSA_AUTHKEY_MAX);

    sbyte4 i, j;

    /* get DH shared secret string, if any */
    if (NULL != pDHctx)
    {
        pStringMpintK = pxIPsecSa->pDhSharedSecret;
        stringLenK = pxIPsecSa->dhSharedSecretLen;
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if (NULL != pxIPsecSa->p_eccKey)
    {
        pStringMpintK = pxIPsecSa->poEccSharedSecret;
        stringLenK = pxIPsecSa->eccSharedSecretLen;
    }
#endif

    /* get PRF */
    if (OK > (status = HmacCreate(MOC_HASH(ctx->hwAccelCookie) &hmacCtxt, pBHAlgo)))
        DBG_EXIT

    if (OK > (status = HmacKey(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxSa->u.v1.poKeyId_d, wDigestLen)))
        DBG_EXIT

    _CRYPTO_ALLOC_(poKey, CHILDSA_ENCRKEY_MAX + CHILDSA_AUTHKEY_MAX)

    /* traverse all SA's */
    for (i = pxIPsecSa->oP2SaNum - 1; i >= 0; i--)
    {
        for (j = pxIPsecSa->axP2Sa[i].oChildSaLen - 1; j >= 0; j--)
        {
            /* generate phase 2 keying material */
            IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[i].axChildSa[j].ipsecPps);

            ubyte  oProtoId = pxIPsecPps->oProtocol;
            ubyte2 wKeyLen = 0;
            ubyte2 wCount;
            ubyte4 dwSpi;

            if (pxIPsecPps->oEncrAlgo)
            {
                CHILDSA_encrInfo *pEncrAlgo;

                if (0 == (wKeyLen = pxIPsecPps->wEncrKeyLen))
                    pEncrAlgo = CHILDSA_findEncrAlgoWithConstraint(bitStrength, pxIPsecPps->oEncrAlgo, 0, 0, 0, &wKeyLen);

                else
                    pEncrAlgo = CHILDSA_findEncrAlgoWithConstraint(bitStrength, pxIPsecPps->oEncrAlgo, 0, 0, wKeyLen, NULL);

                if (NULL == pEncrAlgo) /* jic */
                {
                    status = ERR_NULL_POINTER;
                    DBG_EXIT
                }
                wKeyLen = wKeyLen + pEncrAlgo->oNonceLen;
            }

            if (pxIPsecPps->wAuthAlgo)
            {
                CHILDSA_authInfo *pAuthAlgo = CHILDSA_findAuthAlgo(pxIPsecPps->wAuthAlgo, 0, 0, 0);
                if (NULL == pAuthAlgo) /* jic */
                {
                    status = ERR_NULL_POINTER;
                    DBG_EXIT
                }
                wKeyLen = wKeyLen + pAuthAlgo->wKeyLen;
            }

            /* initiator */
            SET_HTONL(dwSpi, pxIPsecPps->dwSpi[_I]);
            for (wCount=0; wCount < wKeyLen; wCount = (ubyte2)(wCount + wDigestLen))
            {
                if ((OK > (status = HmacReset(MOC_HASH(ctx->hwAccelCookie) hmacCtxt))) ||
                    ((0 != wCount) &&
                     (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, &(/*pxIPsecPps->*/poKey/*[_I]*/[wCount-wDigestLen]), wDigestLen)))) ||
                    ((NULL != pStringMpintK) &&
                     (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pStringMpintK, stringLenK)))) ||
                    (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, &oProtoId, 1/*sizeof(ubyte)*/))) ||
                    (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, (ubyte *) &dwSpi, sizeof(ubyte4)))) ||
                    (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxIPsecSa->poNi_b, pxIPsecSa->wNi_bLen))) ||
                    (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxIPsecSa->poNr_b, pxIPsecSa->wNr_bLen))) ||
                    (OK > (status = HmacFinal(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, &(/*pxIPsecPps->*/poKey/*[_I]*/[wCount])))))
                    DBG_EXIT
            }
            DIGI_MEMCPY(pxIPsecSa->axP2Sa[i].axChildSa[j].poKey[_I],
                       poKey, wKeyLen);

            /* responder */
            SET_HTONL(dwSpi, pxIPsecPps->dwSpi[_R]);
            for (wCount=0; wCount < wKeyLen; wCount = (ubyte2)(wCount + wDigestLen))
            {
                if ((OK > (status = HmacReset(MOC_HASH(ctx->hwAccelCookie) hmacCtxt))) ||
                    ((0 != wCount) &&
                     (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, &(/*pxIPsecPps->*/poKey/*[_R]*/[wCount-wDigestLen]), wDigestLen)))) ||
                    ((NULL != pStringMpintK) &&
                     (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pStringMpintK, stringLenK)))) ||
                    (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, &oProtoId, 1/*sizeof(ubyte)*/))) ||
                    (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, (ubyte *) &dwSpi, sizeof(ubyte4)))) ||
                    (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxIPsecSa->poNi_b, pxIPsecSa->wNi_bLen))) ||
                    (OK > (status = HmacUpdate(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, pxIPsecSa->poNr_b, pxIPsecSa->wNr_bLen))) ||
                    (OK > (status = HmacFinal(MOC_HASH(ctx->hwAccelCookie) hmacCtxt, &(/*pxIPsecPps->*/poKey/*[_R]*/[wCount])))))
                    DBG_EXIT
            }
            DIGI_MEMCPY(pxIPsecSa->axP2Sa[i].axChildSa[j].poKey[_R],
                       poKey, wKeyLen);

        } /* for (j=0; */
    } /* for (i=0; */

exit:
#ifdef __ENABLE_DIGICERT_ECC__
    if (pStringMpintK != pxIPsecSa->poEccSharedSecret)
#endif
    pStringMpintK = NULL;
    HmacDelete(MOC_HASH(ctx->hwAccelCookie) &hmacCtxt);
    _CRYPTO_FREE_(poKey)
    return status;
} /* DoKe2 */


/*------------------------------------------------------------------*/

extern MSTATUS
InNonce(IKE_context ctx)
{
    MSTATUS status;

    IKESA pxSa = ctx->pxSa;
    IPSECSA pxIPsecSa = (ctx->pxP2Xg ? P2XG_IPSECSA(ctx->pxP2Xg) : NULL);
    intBoolean bInitiator = (pxIPsecSa ? IS_CHILD_INITIATOR(pxIPsecSa) : IS_INITIATOR(pxSa));

    ubyte2 wLength;
    ubyte *poNonce;

    /* already received Nonce payload? */
    if (IKE_CNTXT_FLAG_NONCE & ctx->flags)
    {
        status = ERR_IKE_BAD_NONCE;
        DBG_EXIT
    }

    /* generic header */
    if (OK != (status = InGen(ctx, &wLength)))
        goto exit;

    /* nonce data */
    if (((ubyte2)IKE_NONCE_MIN > wLength) || ((ubyte2)IKE_NONCE_MAX < wLength))
    {
        status = ERR_IKE_BAD_LEN;
        DBG_EXIT
    }
    CHECK_MALLOC(poNonce, wLength)

    if (bInitiator)
    {
        if (NULL != pxIPsecSa)
        {
            CHECK_FREE(pxIPsecSa->poNr_b)
            pxIPsecSa->poNr_b = poNonce;
            pxIPsecSa->wNr_bLen = wLength;
        }
        else
        {
            CHECK_FREE(pxSa->poNonce[_R])
            pxSa->poNonce[_R] = poNonce;
            pxSa->wNonceLen[_R] = wLength;
        }
    }
    else
    {
        if (NULL != pxIPsecSa)
        {
            CHECK_FREE(pxIPsecSa->poNi_b)
            pxIPsecSa->poNi_b = poNonce;
            pxIPsecSa->wNi_bLen = wLength;
        }
        else
        {
            CHECK_FREE(pxSa->poNonce[_I])
            pxSa->poNonce[_I] = poNonce;
            pxSa->wNonceLen[_I] = wLength;
        }
    }

    DIGI_MEMCPY(poNonce, ctx->pBuffer - wLength, wLength);

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
    intBoolean bInitiator = IS_INITIATOR(pxSa);

    ubyte2 wPort;
    ubyte *poID;

    /* id payload header */
    IN_BEGIN(struct ikeIdHdr, pxIdHdr, SIZEOF_IKE_ID_HDR)

    /* RFC2407 4.6.2 p19 & RFC2408 3.8 p32 */
    if (((0 != pxIdHdr->oProtocol) &&
         (IPPROTO_UDP != pxIdHdr->oProtocol)) ||
        ((0 != (wPort = GET_NTOHS(pxIdHdr->wPort))) &&
         (IKE_DEFAULT_UDP_PORT != wPort)))
    {
        status = ERR_IKE_BAD_ID;
        DBG_EXIT
    }

    /* already received ID payload? */
    if (IKE_CNTXT_FLAG_ID & ctx->flags)
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
    case ID_USER_FQDN :
        break;
    case ID_IPV4_ADDR_SUBNET :
    case ID_IPV4_ADDR_RANGE :
        if (wBodyLen != (2 * sizeof(ubyte4)))
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }
        break;
    case ID_IPV6_ADDR :
        if (wBodyLen != (4 * sizeof(ubyte4)))
        {
            status = ERR_IKE_BAD_LEN;
            DBG_EXIT
        }
        break;
    case ID_IPV6_ADDR_SUBNET :
    case ID_IPV6_ADDR_RANGE :
        if (wBodyLen != (2 * (4 * sizeof(ubyte4))))
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
#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)
    case 0 :
        if (IS_HYBRID_SERVER(pxSa) || PROP_HYBRID_SERVER(pxSa) /* jic */)
        {
            break; /* hybrid server OK */
        }
#endif
    default :
        status = ERR_IKE_BAD_MSG;
        DBG_EXIT
    }

    /* match custom peer ID payload */
#ifdef CUSTOM_IKE_CHECK_ID
    if (OK > CUSTOM_IKE_CHECK_ID(ctx->pBuffer, wBodyLen, pxIdHdr->oType,
                            REF_MOC_IPADDR(pxSa->dwPeerAddr),
                            _IN /* remote */, bInitiator
                            MOC_MTHM_REQ_VALUE(pxSa->serverInstance)))
    {
        status = ERR_IKE_BAD_ID;
        DBG_EXIT
    }
#endif

    /* store ID payload */
    CHECK_MALLOC(poID, wLength)
    DIGI_MEMCPY(poID, pxIdHdr, wLength);
    CHECK_FREE(pxSa->pxID[bInitiator ? _R : _I])
    pxSa->pxID[bInitiator ? _R : _I] = (struct ikeIdHdr *)poID;

    /* done */
    IN_END

    ctx->flags |= IKE_CNTXT_FLAG_ID;

exit:
    return status;
} /* InId */


/*------------------------------------------------------------------*/

extern MSTATUS
InId2(IKE_context ctx)
{
    MSTATUS status = OK;

    IPSECSA pxIPsecSa = P2XG_IPSECSA(ctx->pxP2Xg);
    intBoolean bInitiator = IS_CHILD_INITIATOR(pxIPsecSa);

    sbyte4 i;
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
    intBoolean is_ip_found = FALSE;
#endif

    if (IKE_CHILD_FLAG_ID2 & pxIPsecSa->c_flags) /* IDci/IDcr payloads processed */
    {
        if (bInitiator)
        {
            status = ERR_IKE_BAD_ID2;
            DBG_EXIT
        }
        else
        {
            IN_BEGIN(struct ikeIdHdr, pxIdHdr, SIZEOF_IKE_ID_HDR)
            IN_END
            goto exit;
        }
    }

    for (i=0; i < 2; i++)
    {
#ifdef __ENABLE_DIGICERT_IPV6__
        ubyte4 dwIpAddr, dwIpAddrEnd;
#else
        #define ipAddr dwIpAddr
        #define ipAddrEnd dwIpAddrEnd
#endif
        MOC_IP_ADDRESS_S ipAddr = MOC_IPADDR_NONE;
        MOC_IP_ADDRESS_S ipAddrEnd = MOC_IPADDR_NONE;

#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
        if (i && IS_GPULL_STATE(pxIPsecSa->oState))
        {
            /* only 1 ID payload */
            break;
        }
#endif
        /* id payload header */
        { IN_BEGIN(struct ikeIdHdr, pxIdHdr, SIZEOF_IKE_ID_HDR)

#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
        if (!IS_GPULL_STATE(pxIPsecSa->oState))
#endif
        /* make sure there's 2nd id payload */
        if ((0==i) && (ISAKMP_NEXT_ID != ctx->oNextPayload))
        {
            IN_END
            CURR_PAYLOAD

            status = ERR_IKE_BAD_ID;
            DBG_EXIT
        }

        /* identification data */
        switch (pxIdHdr->oType)
        {
        case ID_IPV4_ADDR :
            if (4 != wBodyLen)
            {
                status = ERR_IKE_BAD_LEN;
                DBG_EXIT
            }

            SET_NTOHL(dwIpAddr, pxIdHdr->dwIpAddr);

            if (!dwIpAddr)
            {
                status = ERR_IKE_BAD_MSG;
                DBG_EXIT
            }

#ifdef __ENABLE_DIGICERT_IPV6__
            SET_MOC_IPADDR4(ipAddr, dwIpAddr);
#endif
            ipAddrEnd = ipAddr;
            break;
#ifdef __ENABLE_DIGICERT_MCP_FQDN_SUPPORT__
        case ID_USER_FQDN:
            is_ip_found = FALSE;
            DIGI_MEMSET((ubyte *) pxIPsecSa->fqdn, 0 , MOC_MAX_FQDN_LEN);
            DIGI_MEMCPY(pxIPsecSa->fqdn, ctx->pBuffer, GET_NTOHS(pxIdHdr->wLength) - (ubyte2)SIZEOF_IKE_ID_HDR);
            /* check if the peer ip adddress is part of this fqdn adddress or not*/
            MOC_IS_IP_PART_OF_GROUP(ctx->pxSa->dwPeerAddr, pxIPsecSa->fqdn, is_ip_found);
            if(FALSE == is_ip_found)
            {
                DB_PRINT("MCP: group address: %s, not configured for peer adddress:%x\n",
                    pxIPsecSa->fqdn, ctx->pxSa->dwPeerAddr);
                status = ERR_IKE_BAD_ID;
                DBG_EXIT
            }

            break;
#endif
        case ID_IPV4_ADDR_RANGE :
        case ID_IPV4_ADDR_SUBNET :
            if (8 != wBodyLen)
            {
                status = ERR_IKE_BAD_LEN;
                DBG_EXIT
            }

            SET_NTOHL(dwIpAddr, pxIdHdr->dwIpAddr);
            SET_NTOHL(dwIpAddrEnd, pxIdHdr->dwIpAddrEnd);

            if (ID_IPV4_ADDR_RANGE == pxIdHdr->oType) /* range */
            {
                if (!dwIpAddrEnd && !dwIpAddr)
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
            break;
        } /* switch */

        /* process data */
        if (bInitiator)
        {
            if ((GET_NTOHS(pxIdHdr->wPort) != pxIPsecSa->wPort[i]) ||
                (pxIdHdr->oProtocol != pxIPsecSa->oUlp))
            {
                status = ERR_IKE_BAD_ID2;
                DBG_EXIT
            }
#ifdef __ENABLE_ALL_DEBUGGING__
            if (!SAME_MOC_IPADDR(REF_MOC_IPADDR(ipAddr), pxIPsecSa->dwIP[i]) ||
                !SAME_MOC_IPADDR(REF_MOC_IPADDR(ipAddrEnd), pxIPsecSa->dwIPEnd[i]))
            {
                debug_print_ike_id2((ubyte *)pxIdHdr, (0==i));
            }
#endif
        }
        else /* responder */
        {
            debug_print_ike_id2((ubyte *)pxIdHdr, (0==i));

            if (i)
            {
#ifdef __ENABLE_DIGICERT_IPV6__
                if (!ISZERO_MOC_IPADDR(ipAddr) &&
                    (ipAddr.family != pxIPsecSa->dwIP[0].family))
                {
                    status = ERR_IKE_BAD_ID2;
                    DBG_EXIT
                }
#endif
                if (pxIPsecSa->oUlp != pxIdHdr->oProtocol)
                {
                    status = ERR_IKE_BAD_ID2;
                    DBG_EXIT
                }
            }
            else pxIPsecSa->oUlp = pxIdHdr->oProtocol;

            SET_NTOHS(pxIPsecSa->wPort[i], pxIdHdr->wPort);
            pxIPsecSa->IDc_t[i] = (IKE_ID_T) pxIdHdr->oType;

            pxIPsecSa->dwIP[i] = ipAddr;
            pxIPsecSa->dwIPEnd[i] = ipAddrEnd;
        }

        /* done */
        IN_END }
        CURR_PAYLOAD /* !!! */

#ifndef __ENABLE_DIGICERT_IPV6__
        #undef ipAddr
        #undef ipAddrEnd
#endif
    } /* for (i */

    pxIPsecSa->c_flags |= IKE_CHILD_FLAG_ID2;

exit:
    return status;
} /* InId2 */


/*------------------------------------------------------------------*/

static MSTATUS
DoId2(IKE_context ctx)
{
    MSTATUS status = OK;

    sbyte4 i;

    /* Note: called from quickR1_in() only */
    IPSECSA pxIPsecSa = P2XG_IPSECSA(ctx->pxP2Xg);

    /* save current context */
    IN_SET

    /* locate IDci, IDcr payloads */
    while (ISAKMP_NEXT_NONE != ctx->oNextPayload)
    {
        CATCH_PAYLOAD

        if (ISAKMP_NEXT_ID == ctx->oNextPayload)
        {
            if (IKE_CHILD_FLAG_ID2 & pxIPsecSa->c_flags) /* IDci/IDcr payloads processed */
            {
                status = ERR_IKE_BAD_ID2;
                DBG_EXIT
            }
            DO_FUNC(InId2)
        }
        else
        {
            IN_BEGIN(struct ikeGenHdr, pxGenHdr, SIZEOF_IKE_GEN_HDR)
            IN_END
        }

        FINALLY_PAYLOAD
    }

    /* restore context */
    IN_RESET

    /* initialize IP identification, if necessary */
    for (i=0; i < 2; i++)
    {
        if (ISZERO_MOC_IPADDR(pxIPsecSa->dwIP[i]) &&
            ISZERO_MOC_IPADDR(pxIPsecSa->dwIPEnd[i]))
        {
            pxIPsecSa->dwIP[i] =
            pxIPsecSa->dwIPEnd[i] = (i ? ctx->pxSa->dwHostAddr
                                       : ctx->pxSa->dwPeerAddr);
        }
    } /* for */

exit:
    return status;
} /* DoId2 */


/*------------------------------------------------------------------*/

static MSTATUS
InCR(IKE_context ctx)
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

        default :
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
} /* InCR */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_IKE_PKCS7_SUPPORT__

static MSTATUS
ExtractPKCS7Cert(IKE_context ctx)
{
    MSTATUS status = OK;
    MemFile ikeFile;
    CStream ikeStream;
    const ubyte* pCertBuf = NULL;
    ASN1_ITEMPTR pPkcsRoot = NULL;
    ASN1_ITEMPTR pCert = NULL;
    ASN1_ITEMPTR pTemp = NULL;
    ubyte2 numCerts = 0;
    ubyte2 tempCtr = 0;

    if (OK > (status = MF_attach(&ikeFile, ctx->dwBufferSize, ctx->pBuffer)))
    {
        /* figure out the right error code here */
        goto exit;
    }

    CS_AttachMemFile(&ikeStream, &ikeFile);

    if (OK > (status = ASN1_Parse(ikeStream, &pPkcsRoot)))
        goto exit;

    if (OK > (status = PKCS7_GetCertificates(pPkcsRoot, ikeStream,
                                             &pCert)))
        goto exit;

    /* we receive the certificate chain in reverse order, so flip it around */

    pTemp = pCert;
    while (pTemp)
    {
        numCerts++;
        pTemp = ASN1_NEXT_SIBLING(pTemp);
    }

    if (IKE_CERT_CHAIN_MAX < (ctx->certNum + numCerts))
    {
        status = ERR_IKE_BAD_CERT;
        goto exit;
    }
    else
        tempCtr = numCerts;

    while (pCert && tempCtr)
    {
        tempCtr--;
        pCertBuf = CS_memaccess(ikeStream,
                                pCert->dataOffset - pCert->headerSize,
                                pCert->length + pCert->headerSize);
        ctx->certificates[ctx->certNum + tempCtr].pCertificate = (ubyte *)pCertBuf;
        ctx->certificates[ctx->certNum + tempCtr].certLength = pCert->length + pCert->headerSize;
        CS_stopaccess(ikeStream, pCertBuf);
        pCert = ASN1_NEXT_SIBLING(pCert);
    }
    ctx->certNum += numCerts;

exit:
    if (pPkcsRoot)
        TREE_DeleteTreeItem((TreeItem *)pPkcsRoot);

    return status;
} /* ExtractPKCS7Cert */

#endif /* __ENABLE_DIGICERT_IKE_PKCS7_SUPPORT__ */


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
    case CERT_PKCS7_WRAPPED_X509 :
#ifdef __ENABLE_DIGICERT_IKE_PKCS7_SUPPORT__
        if (OK > (status = ExtractPKCS7Cert(ctx)))
        {
            debug_print("Failed to extract PKCS wrapped cert\n, status =%d");
            DBG_EXIT
        }
#else
        debug_print("PKCS7 wrapped certificate not enabled\n");
        status = ERR_IKE_BAD_CERT_TYPE;
#endif
        break;
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

    default :
        status = ERR_IKE_BAD_CERT_TYPE;
        DBG_EXIT
    }

    /* done */
    IN_END

exit:
    return status;
} /* InCert */


/*------------------------------------------------------------------*/

static MSTATUS
InSig(IKE_context ctx)
{
    MSTATUS     status;

    ubyte2      wSigLen;

    IKESA       pxSa        = ctx->pxSa;
    intBoolean  bInitiator  = IS_INITIATOR(pxSa);
    sbyte4      dir         = (bInitiator ? _R : _I);

    const BulkHashAlgo *pBHAlgo = pxSa->pHashSuite->pBHAlgo;

    AsymmetricKey *pPeerKey = NULL;

    ubyte*      poSigHash   = NULL;
    vlong*      pVlongQueue = NULL;

#ifdef __ENABLE_DIGICERT_ECC__
    ubyte2      wAuthMtd;
#endif

    ubyte __crypto__(poIdHash, MD5_DIGESTSIZE);
    ubyte __crypto__(poHash, IKE_HASH_MAX);

    /* generic header */
    if (OK != (status = InGen(ctx, &wSigLen)))
        goto exit;

    /* get peer IDi?_b hash */
    _CRYPTO_ALLOC_(poIdHash, MD5_DIGESTSIZE)
    if (OK > (status = IKE_getIdHash(ctx, pxSa->pxID[dir], poIdHash)))
        DBG_EXIT

    /* get peer certificate's public key */
    if (0 < ctx->certNum)
    {
        if (OK > (status = IKE_certGetKey(ctx, &pPeerKey)))
            DBG_EXIT
    }
    else if (OK > (status = IKE_certLookup(ctx, poIdHash, &pPeerKey)))
    {
        DBG_EXIT
    }

    /* check certificate against auth mtd */
#if defined(__ENABLE_DIGICERT_ECC__)
    wAuthMtd = BASE_AUTH_MTD(pxSa);

    if ((OAKLEY_ECDSA_256 == wAuthMtd) || (OAKLEY_ECDSA_384 == wAuthMtd)  ||
         (OAKLEY_ECDSA_521 == wAuthMtd) || (OAKLEY_ECDSA_SIG == wAuthMtd)) /* ECDSA */
    {
        ECCKey *pECCKey;
        ubyte4 curveId = 0;
        ubyte4 elementLen = 0;
        ubyte4 vfyFail = 0;

        if (akt_ecc != pPeerKey->type)
        {
            status = ERR_IKE_BAD_CERT;
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

        if (OAKLEY_ECDSA_SIG != wAuthMtd) /* !!! */
        {
            IKE_authMtdInfo *pAuthMtd = IKE_authMtdEx(pxSa->ikePeerConfig, wAuthMtd, 0);
            if (NULL == pAuthMtd) /* jic */
            {
                status = ERR_NULL_POINTER;
                DBG_EXIT
            }

            /* check curve */
            if (curveId != pAuthMtd->curveId)
            {
                status = ERR_IKE_BAD_CERT;
                DBG_EXIT
            }

            pBHAlgo = pAuthMtd->pBHAlgo; /* ECDSA-specific SIG Hash Algo */
        }

        _CRYPTO_ALLOC_(poHash, IKE_HASH_MAX)
        if (OK > (status = DoHash(ctx, poHash, TRUE, pBHAlgo)))
            goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(pECCKey, &elementLen);
        if (OK != status)
            goto exit;
#else
        status = EC_getElementByteStringLen(pECCKey, &elementLen);
        if (OK != status)
            goto exit;
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_ECDSA_verifySignatureDigestAux (MOC_ECC(ctx->hwAccelCookie)
            pECCKey, poHash, pBHAlgo->digestSize, ctx->pBuffer - wSigLen,
            elementLen, ctx->pBuffer - elementLen, elementLen, &vfyFail);
        if (OK != status)
            goto exit;
#else
        status = ECDSA_verifySignatureDigest (MOC_ECC(ctx->hwAccelCookie)
            pECCKey, poHash, pBHAlgo->digestSize, ctx->pBuffer - wSigLen,
            elementLen, ctx->pBuffer - elementLen, elementLen, &vfyFail);
        if (OK != status)
            goto exit;
#endif

        if (0 != vfyFail)
        {
            status = ERR_ECDSA_VERIFICATION_FAILED;
            goto exit;
        }
    }
#ifdef __ENABLE_DIGICERT_PQC__
    else if (TRUE == isHybridOakleyMtd(wAuthMtd)) /* QS_HYBRID */
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

        if (akt_hybrid != pPeerKey->type)
        {
            status = ERR_IKE_BAD_CERT;
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
                                                   wAuthMtd, 0);
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

        _CRYPTO_ALLOC_(poHash, IKE_HASH_MAX)
        if (OK > (status = DoHash(ctx, poHash, TRUE, pBHAlgo)))
            goto exit;

        status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(pECCKey, &elementLen);
        if (OK != status)
            DBG_EXIT

        status = CRYPTO_INTERFACE_QS_SIG_getSignatureLen(pQsCtx, &qsSigLen);
        if (OK != status)
            DBG_EXIT

        if (((ubyte4)wSigLen <= (elementLen * 2)) || ((ubyte4)wSigLen > (elementLen * 2 + qsSigLen)))
        {
            status = ERR_IKE_BAD_SIG;
            DBG_EXIT
        }

        pR = ctx->pBuffer - wSigLen;
        pS = pR + elementLen;
        rLen = elementLen;
        sLen = elementLen;
        pQsSig = pR + elementLen * 2;
        qsSigLen = wSigLen - (2 * elementLen);

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
#endif
    else if (akt_rsa != pPeerKey->type)
    {
        status = ERR_IKE_BAD_CERT;
        DBG_EXIT
    }
    else /* RSA */
#endif
    {
        RSAKey *pRSAKey = pPeerKey->key.pRSA;
        sbyte4 compareResult;
        ubyte4 dwSigHashLen;

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

        /* calculate HASH_I/R */
        _CRYPTO_ALLOC_(poHash, IKE_HASH_MAX)
        if (OK > (status = DoHash(ctx, poHash, TRUE, pBHAlgo)))
            goto exit;

        /* verify signature data */
        CHECK_MALLOC(poSigHash, wSigLen)

        /* If signature verification fails, ERR_RSA_DECRYPTION is returned */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if (OK > (status = CRYPTO_INTERFACE_RSA_verifySignatureAux(MOC_RSA(ctx->hwAccelCookie)
                                               pRSAKey, ctx->pBuffer - wSigLen,
                                               poSigHash, &dwSigHashLen, &pVlongQueue)))
            DBG_EXIT
#else
        if (OK > (status = RSA_verifySignature(MOC_RSA(ctx->hwAccelCookie)
                                               pRSAKey, ctx->pBuffer - wSigLen,
                                               poSigHash, &dwSigHashLen, &pVlongQueue)))
            DBG_EXIT
#endif

        if ((dwSigHashLen != pBHAlgo->digestSize) ||
            (OK > (status = DIGI_MEMCMP(poHash, poSigHash,
                                       pBHAlgo->digestSize,
                                       &compareResult))) ||
            (0 != compareResult))
        {
            status = ERR_IKE_BAD_SIG;
            DBG_EXIT
        }
    }

    /* done */
    if (0 < ctx->certNum)
        IKE_certAssign(ctx, poIdHash, pPeerKey);

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

    _CRYPTO_FREE_(poHash)
    _CRYPTO_FREE_(poIdHash)
    return status;
} /* InSig */


/*------------------------------------------------------------------*/

extern MSTATUS
InHashGen(IKE_context ctx)
{
    MSTATUS status;

    ubyte2 wDigestLen;

    /* generic header */
    if (OK != (status = InGen(ctx, &wDigestLen)))
        goto exit;

    /* hash data */
    if (wDigestLen != (ubyte2) ctx->pxSa->pHashSuite->pBHAlgo->digestSize)
    {
        status = ERR_IKE_BAD_HASH;
        DBG_EXIT
    }

exit:
    return status;
} /* InHashGen */


#ifdef __ENABLE_IPSEC_NAT_T__

/*------------------------------------------------------------------*/

static MSTATUS
InNatD(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;

    ubyte2 wDigestLen;
    sbyte4 compareResult;
    ubyte  oNextNatD = ctx->oNextPayload;
    ubyte __crypto__(poHash, IKE_HASH_MAX);

    /* check NAT-D version */
    if (0 < pxSa->u.v1.iNatT) /* NAT-T Vid received from peer */
    {
        if (oNextNatD != mNatTinfo[pxSa->u.v1.iNatT - 1].oNatD) /* mismatch */
        {
            DBG_ERRCODE(ERR_IKE_BAD_NAT_D)
            /*goto exit;*/
        }
    }
    else /* no NAT-T Vid from peer */
    {
        switch (oNextNatD)
        {
        case ISAKMP_NEXT_NAT_D :
            pxSa->u.v1.iNatT = 1;
            break;
        case ISAKMP_NEXT_NAT_D_DRAFTS_48 :
            pxSa->u.v1.iNatT = 2;
            break;
        case ISAKMP_NEXT_NAT_D_DRAFTS :
            pxSa->u.v1.iNatT = 3;
            break;
        default :
            goto exit;
        }
        DBG_ERRCODE(ERR_IKE_BAD_NAT_D)
    }

    /* generic header */
    if (OK != (status = InHashGen(ctx)))
        goto exit;

    /* make sure there's 2nd NAT-D payload */
    if (oNextNatD != ctx->oNextPayload)
    {
        status = ERR_IKE_BAD_PAYLOAD;
        DBG_EXIT
    }

    /* calculate local NAT-D hash */
    _CRYPTO_ALLOC_(poHash, IKE_HASH_MAX)
    if (OK > (status = DoHashNatD(ctx, poHash, FALSE)))
        goto exit;

    /* host behind NAT? */
    wDigestLen = (ubyte2) pxSa->pHashSuite->pBHAlgo->digestSize;
    if (OK > (status = DIGI_MEMCMP(poHash, ctx->pBuffer - wDigestLen, wDigestLen, &compareResult)))
        DBG_EXIT;

    if (0 != compareResult) /* yes */
    {
        debug_printd((sbyte *)"   NAT-D (us):", poHash, wDigestLen);
        debug_printd((sbyte *)"   NAT-D (us/NAT):", ctx->pBuffer - wDigestLen, wDigestLen);
        SET_HOST_BEHIND_NAT(pxSa)
    }

    /* calculate remote NAT-D hash */
    if (OK > (status = DoHashNatD(ctx, poHash, TRUE)))
        goto exit;

    /* peer behind NAT? */
    SET_PEER_BEHIND_NAT(pxSa)
    do
    {
        /* generic header */
        if (OK != (status = InHashGen(ctx)))
            goto exit;

        /* hash data */
        if (IS_PEER_BEHIND_NAT(pxSa))
        {
            if (OK > (status = DIGI_MEMCMP(poHash, ctx->pBuffer - wDigestLen, wDigestLen, &compareResult)))
                DBG_EXIT;

            if (0 == compareResult) /* no */
                PEER_NOT_BEHIND_NAT(pxSa)
        }
    } while (oNextNatD == ctx->oNextPayload);

    if (IS_PEER_BEHIND_NAT(pxSa))
    {
        debug_printd((sbyte *)"   NAT-D (peer):", poHash, wDigestLen);
        debug_printd((sbyte *)"   NAT-D (peer/NAT):", ctx->pBuffer - wDigestLen, wDigestLen);
    }

    pxSa->natt_flags |= IKE_NATT_FLAG_D;

    /* changing to new ports */
    if (IS_INITIATOR(pxSa) && /* initiator only */
        IS_BEHIND_NAT(pxSa) && !USE_NATT_PORT(pxSa))
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
        pxSa->wPeerPort = IKE_NAT_UDP_PORT; /* FOR NOW */
        pxSa->natt_flags |= IKE_NATT_FLAG_USE_NPORT;
    }

exit:
    _CRYPTO_FREE_(poHash)
    return status;
} /* InNatD */


/*------------------------------------------------------------------*/

static MSTATUS
InNatOa(IKE_context ctx)
{
    MSTATUS status = OK;

    IPSECSA pxIPsecSa = P2XG_IPSECSA(ctx->pxP2Xg);
    ubyte oNextNatOa = ctx->oNextPayload;

    sbyte4 i;
    for (i=0; i < 2; i++)
    {
        /* NAT-OA payload */
        IN_BEGIN(struct ikeNatOaHdr, pxNatOaHdr, SIZEOF_IKE_NATOA_HDR)

        /* get original IP address */
        switch (pxNatOaHdr->oIdType)
        {
        case ID_IPV4_ADDR :
            if (4 > wBodyLen)
            {
                status = ERR_IKE_BAD_MSG;
                DBG_EXIT;
            }
            else
            {
                ubyte4 dwIpAddr;
                SET_NTOHL(dwIpAddr, pxNatOaHdr->dwIpAddr);
                if (0 == dwIpAddr) /* just in case */
                {
                    status = ERR_IKE_BAD_MSG;
                    DBG_EXIT;
                }
            }
            break;
        case ID_IPV6_ADDR :
            if (16 > wBodyLen)
            {
                status = ERR_IKE_BAD_MSG;
                DBG_EXIT;
            }
#ifdef __ENABLE_DIGICERT_IPV6__
            break;
#endif
        default :
            status = ERR_IKE_BAD_MSG;
            DBG_EXIT;
        }

        /* done */
        IN_END
        CURR_PAYLOAD /* !!! */

        /* make sure there's 2nd NAT-OA payload */
        if ((0==i) && (oNextNatOa != ctx->oNextPayload))
        {
            if (IS_CHILD_INITIATOR(pxIPsecSa))
            {
                if (!IS_PEER_BEHIND_NAT(ctx->pxSa))
                {
                    DBG_ERRCODE(ERR_IKE_BAD_PAYLOAD)
                    break;
                }
                status = ERR_IKE_BAD_PAYLOAD;
                DBG_EXIT
            }
            else
            {
                if (!IS_HOST_BEHIND_NAT(ctx->pxSa))
                {
                    DBG_ERRCODE(ERR_IKE_BAD_PAYLOAD)
                    break;
                }
                status = ERR_IKE_BAD_PAYLOAD;
                DBG_EXIT
            }
        }

    } /* for (i */

    ctx->flags |= IKE_CNTXT_FLAG_NAT_OA;

exit:
    return status;
} /* InNatOa */

#endif /* __ENABLE_IPSEC_NAT_T__ */


/*------------------------------------------------------------------*/

static MSTATUS
InHash(IKE_context ctx)
{
    MSTATUS status;

    const BulkHashAlgo *pBHAlgo = ctx->pxSa->pHashSuite->pBHAlgo;
    ubyte2 wDigestLen = (ubyte2) pBHAlgo->digestSize;
    ubyte __crypto__(poHash, IKE_HASH_MAX);
    sbyte4 compareResult;

    /* hash generic eader */
    if (OK != (status = InHashGen(ctx)))
        goto exit;

    /* calculate hash value */
    _CRYPTO_ALLOC_(poHash, IKE_HASH_MAX)
    if (OK > (status = DoHash(ctx, poHash, TRUE, pBHAlgo)))
        goto exit;

    /* verify hash data */
    if ((OK > (status = DIGI_MEMCMP(poHash, ctx->pBuffer - wDigestLen,
                                   wDigestLen, &compareResult))) ||
        (0 != compareResult))
    {
        if (!(OK > status))
        {
/*          debug_printb("HASH", ctx->pBuffer - wDigestLen, (sbyte4)wDigestLen); */
            status = ERR_IKE_BAD_HASH;
        }
        DBG_EXIT
    }

exit:
    _CRYPTO_FREE_(poHash)
    return status;
} /* InHash */


/*------------------------------------------------------------------*/

extern MSTATUS
InHash12(IKE_context ctx)
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

    /* get total length of all payloads following HASH(1/2) payload */
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
    if (OK > (status = DoHash12(ctx, ctx->dwLength - dwLength, pBuffer, poHash)))
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

    if (IS_P1_FINAL_STATE(pxSa->oState)) /* jic - aggr mode COMMIT case */
    {
        /* record when phase 2 exchange is sucessfully authenticated */
        pxSa->dwTimeStamp = RTOS_deltaMS(&gStartTime, NULL);

        /* reset DPD */
        pxSa->flags &= ~(IKE_SA_FLAG_DPD);
        pxSa->u.v1.dwDpdTimeStart = 0;

        /* final phase 1 message received by peer */
        if (!IS_MATURE(pxSa))
        {
            pxSa->flags |= IKE_SA_FLAG_MATURE;
#ifdef __ENABLE_IKE_XAUTH__
            if (!(IKE_SA_FLAG_XAUTH & pxSa->flags))
#endif
            {
                if (pxSa->dwTimeStamp == pxSa->dwTimeCreated)
                    pxSa->dwTimeStamp++; /* jic */
                IKE_finalizeSa(pxSa, pxSa->dwTimeStamp);
            }
        }
    }

    ctx->flags |= IKE_CNTXT_FLAG_HASHED;

exit:
    _CRYPTO_FREE_(poHash)
    return status;
} /* InHash12 */


/*------------------------------------------------------------------*/

static MSTATUS
InHash3(IKE_context ctx)
{
    MSTATUS status;

    ubyte2 wDigestLen = (ubyte2) ctx->pxSa->pHashSuite->pBHAlgo->digestSize;
    ubyte __crypto__(poHash, IKE_HASH_MAX);
    sbyte4 compareResult;

    /* hash generic header */
    if (OK != (status = InHashGen(ctx)))
        goto exit;

    /* calculate hash value */
    _CRYPTO_ALLOC_(poHash, IKE_HASH_MAX)
    if (OK > (status = DoHash3(ctx, poHash)))
        goto exit;

    /* verify hash data */
    if ((OK > (status = DIGI_MEMCMP(poHash, ctx->pBuffer - wDigestLen, wDigestLen, &compareResult))) ||
        (0 != compareResult))
    {
        if (!(OK > status))
        {
            status = ERR_IKE_BAD_HASH;
        }
        DBG_EXIT
    }

    ctx->flags |= IKE_CNTXT_FLAG_HASHED;

    /* record when phase 2 exchange is sucessfully authenticated */
    ctx->pxSa->dwTimeStamp = RTOS_deltaMS(&gStartTime, NULL);

exit:
    _CRYPTO_FREE_(poHash)
    return status;
} /* InHash3 */


/*------------------------------------------------------------------*/

static MSTATUS
InNotify(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    P2XG pxXg = ctx->pxP2Xg;
    struct ikeHdr *pxIkeHdr = (struct ikeHdr *) ctx->pHdrParent;

    ubyte oProtoId, oSpiSize;
    ubyte2 wMsgType;
    ubyte4 dwSpi=0;

    IPSECSA pxIPsecSa = ((NULL != pxXg) && IS_QUICK_MODE_STATE(pxXg->oState))
                      ? P2XG_IPSECSA(pxXg) : NULL;

    /* notify payload header */
    IN_BEGIN(struct ikeNotifyHdr, pxNotifyHdr, SIZEOF_IKE_NOTIFY_HDR)

    switch (pxNotifyHdr->oDoi)
    {
    case 0 :
    case ISAKMP_DOI_IPSEC :
        oSpiSize = pxNotifyHdr->oSpiSize;
        switch (oProtoId = pxNotifyHdr->oProtoId)
        {
        case PROTO_ISAKMP :
            if (IKE_P1_SPI_SIZE < oSpiSize)
            {
                DBG_ERRCODE(ERR_IKE_BAD_SPI)
            }
            break;
        case PROTO_IPSEC_AH :
        case PROTO_IPSEC_ESP :
            if ((sizeof(ubyte4) != oSpiSize) &&
                (IKE_P1_SPI_SIZE != oSpiSize))
            {
                DBG_ERRCODE(ERR_IKE_BAD_SPI)
            }
            break;
        default :
            status = ERR_IKE_BAD_PROTOCOL;
            DBG_EXIT
        }
        break;
    default :
        status = ERR_IKE_BAD_MSG;
        DBG_EXIT
    }

    if (wBodyLen < oSpiSize)
    {
        status = ERR_IKE_BAD_LEN;
        DBG_EXIT
    }

    if ((PROTO_ISAKMP != oProtoId) &&
        (sizeof(ubyte4) == oSpiSize))
    {
        SET_NTOHL(dwSpi, pxNotifyHdr->dwSpi);
    }
    SET_NTOHS(wMsgType, pxNotifyHdr->wMsgType);

    debug_print("   Notify: ");
    debug_print_ike_notify(wMsgType);
    debug_print(" (");
    debug_print_ike_proto(oProtoId);
#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
    if (oSpiSize)
    {
        debug_print(" spi=");
        if ((PROTO_ISAKMP == oProtoId) ||
            (sizeof(ubyte4) != oSpiSize))
            debug_printr(ctx->pBuffer, (sbyte4)oSpiSize, FALSE);
        else
            debug_hexint(dwSpi);
    }
#endif
    debug_printnl(")");

    switch (wMsgType)
    {
    /* CONNECTED */
    case CONNECTED :
        if ((NULL != pxIPsecSa) && /* quick mode */
            (!dwSpi || (0 > IKE_findPps(pxIPsecSa, oProtoId, dwSpi))))
        {
            /* no proposal found, based on protocol+spi */
            DBG_STATUS
        }
        ctx->flags |= IKE_CNTXT_FLAG_CONNECTED;
        break;

    /* RESPONDER-LIFETIME */
    case IPSEC_RESPONDER_LIFETIME :
    {
        ubyte4 dwBufferSize;
        ubyte4 dwLength;
        ubyte oNextPayload;
        void *pHdrParent;

        ubyte2 wType, wValue, wSize, wLifeType;
        ubyte4 dwExp;

        /* must be sent under protection */
        if (!(ISAKMP_FLAG_ENCRYPTION & pxIkeHdr->oFlags))
        {
            DBG_STATUS
            break;
        }

        /* down one level - go to data attributes */
        IN_DOWN(pxNotifyHdr, 0)

        ADVANCE(oSpiSize)

        if (PROTO_ISAKMP == oProtoId)
        {
            /* only an initiator gets this */
            if (!IS_INITIATOR(pxSa))
            {
                DBG_STATUS
                goto _skip;
            }

            /* get lifetime attributes */
            wLifeType = 0;
            debug_print("    ");
            while (0 != ctx->dwBufferSize)
            {
                if (OK != (status = InAttrBV(ctx, &wType, &wSize, &wValue, &dwExp)))
                    goto exit;

                switch (wType)
                {
                case OAKLEY_LIFE_TYPE :
                    wLifeType = wValue;
                    break;
                case OAKLEY_LIFE_DURATION :     /* B/V */
                    if (0 != wSize)
                    {
                        if ((ubyte2)sizeof(ubyte2) != wSize &&
                            (ubyte2)sizeof(ubyte4) != wSize)
                        {
                            status = ERR_IKE_BAD_ATTR;
                            DBG_EXIT
                        }
                    }
                    else dwExp = wValue;

                    /* only accept shorter lifetime */
                    if (0 != dwExp) /* jic */
                    {
                        switch (wLifeType)
                        {
                        case OAKLEY_LIFE_SECONDS :
                            debug_uint(dwExp);
                            debug_print("-SECONDS ");

                            if (pxSa->ikePeerConfig->ikeP1LifeSecsMin &&
                                (dwExp < pxSa->ikePeerConfig->ikeP1LifeSecsMin))
                                dwExp = pxSa->ikePeerConfig->ikeP1LifeSecsMin;

                            if ((0 == pxSa->dwExpSecs) ||
                                (dwExp < pxSa->dwExpSecs))
                            {
                                pxSa->dwExpSecs = dwExp;
                            }
                            break;
                        case OAKLEY_LIFE_KILOBYTES :
                            debug_uint(dwExp);
                            debug_print("-KILOBYTES ");

                            if ((0 == pxSa->dwExpKBytes) ||
                                (dwExp < pxSa->dwExpKBytes))
                            {
                                pxSa->dwExpKBytes = dwExp;
                            }
                            break;
                        default : /* ignore */
                            break;
                        }
                    }
                    wLifeType = 0;
                    break;
                default :
                    break; /* unexpected attribute - ignore */
                } /* switch (wType) */
            } /* while */

            debug_printnl(NULL);

        } /* if (PROTO_ISAKMP == oProtoId) */

        else /* PROTO_IPSEC_AH, PROTO_IPSEC_ESP */
        {
            sbyte4 i, j;

            /* FOR NOW - we must be quick mode initiator */
            if (!((NULL != pxIPsecSa) && IS_CHILD_INITIATOR(pxIPsecSa)))
            {
                DBG_STATUS
                goto _skip;
            }

            /* find proposal, based on protocol+spi */
            if (!dwSpi ||
                (0 > (i = IKE_findPps(pxIPsecSa, oProtoId, dwSpi)))) /* not found */
            {
                /* not found */
                DBG_STATUS
                goto _skip;
            }

            if (IKE_P2_SA_MAX <= i) /* jic */
            {
                DBG_STATUS
                goto _skip;
            }

            /* get lifetime attributes */
            wLifeType = 0;
            debug_print("    ");
            while (0 != ctx->dwBufferSize)
            {
                if (OK != (status = InAttrBV(ctx, &wType, &wSize, &wValue, &dwExp)))
                    goto exit;

                switch (wType)
                {
                case SA_LIFE_TYPE :
                    wLifeType = wValue;
                    break;
                case SA_LIFE_DURATION :     /* B/V */
                    if (0 != wSize)
                    {
                        if ((ubyte2)sizeof(ubyte2) != wSize &&
                            (ubyte2)sizeof(ubyte4) != wSize)
                        {
                            status = ERR_IKE_BAD_ATTR;
                            DBG_EXIT
                        }
                    }
                    else dwExp = wValue;

                    /* only accept shorter lifetime */
                    if (0 != dwExp) /* jic */
                    {
                        for (j = pxIPsecSa->axP2Sa[i].oChildSaLen - 1; j >= 0; j--)
                        {
                            IPSECPPS pxIPsecPps = &(pxIPsecSa->axP2Sa[i].axChildSa[j].ipsecPps);

                            switch (wLifeType)
                            {
                            case SA_LIFE_TYPE_SECONDS :
                                debug_uint(dwExp);
                                debug_print("-SECONDS ");

                                if (pxSa->ikePeerConfig->ikeP2LifeSecsMin &&
                                    (dwExp < pxSa->ikePeerConfig->ikeP2LifeSecsMin))
                                    dwExp = pxSa->ikePeerConfig->ikeP2LifeSecsMin;

                                if ((0 == pxIPsecPps->dwExpSecs) ||
                                    (dwExp < pxIPsecPps->dwExpSecs))
                                {
                                    pxIPsecPps->dwExpSecs = dwExp;
                                }
                                break;
                            case SA_LIFE_TYPE_KBYTES :
                                debug_uint(dwExp);
                                debug_print("-KILOBYTES ");

                                if ((0 == pxIPsecPps->dwExpKBytes) ||
                                    (dwExp < pxIPsecPps->dwExpKBytes))
                                {
                                    pxIPsecPps->dwExpKBytes = dwExp;
                                }
                                break;
                            default : /* ignore */
                                break;
                            }
                        }
                    }
                    wLifeType = 0;
                    break;
                default :
                    break; /* unexpected attribute - ignore */
                } /* switch (wType) */
            } /* while */

            debug_printnl(NULL);
        }
_skip:
        /* up one level */
        IN_UP(pxNotifyHdr)
        goto exit;
    } /* case IPSEC_RESPONDER_LIFETIME : */

    case IPSEC_REPLAY_STATUS :
        break;

    case IPSEC_INITIAL_CONTACT :
        /* must be sent under protection */
        if (!(ISAKMP_FLAG_ENCRYPTION & pxIkeHdr->oFlags))
        {
            DBG_STATUS
            break;
        }

        if (IS_IKE_SA_AUTHED(pxSa))
        {
            /* Note: Be aware of replay-attack! */
            if (!(IKE_SA_FLAG_INIT_C & pxSa->flags))
            {
                pxSa->flags |= IKE_SA_FLAG_INIT_C;
                IKE_initContSa(pxSa);
            }
        }
        else
        {
            pxSa->flags |= IKE_SA_FLAG_INIT_C;
        }
        break;

    case R_U_THERE :
    case R_U_THERE_ACK :
        if (!pxSa->u.v1.dwDpdSeqNo) /* DPD not supported by peer */
            break;

        /* must reject unencrypted */
        if (!(ISAKMP_FLAG_ENCRYPTION & pxIkeHdr->oFlags))
        {
            status = ERR_IKE_BAD_FLAGS;
            DBG_EXIT
        }

        if (PROTO_ISAKMP != oProtoId) /* RFC3706 5.3. */
        {
            status = ERR_IKE_BAD_MSG;
            DBG_EXIT
        }

        /* check sequence number (4 bytes) */
        if ((ubyte2)((ubyte2)oSpiSize + (ubyte2)sizeof(ubyte4)) != wBodyLen)
        {
            status = ERR_IKE_BAD_MSG;
            DBG_EXIT
        }

        debug_print("    SEQ #");
        debug_uint((sbyte4) DIGI_NTOHL(ctx->pBuffer + oSpiSize));
        debug_printnl(NULL);

        if ((ubyte2)R_U_THERE == wMsgType)
        {
            /* send R-U-THERE-ACK */
            struct ike_info_notify notifyInfo = { PROTO_ISAKMP, R_U_THERE_ACK, 0, 0, NULL, 0, NULL };
            struct ike_info info = { NULL };
            struct ike_context ctx1 = { NULL };

            notifyInfo.wDataLen = (ubyte2) sizeof(ubyte4);
            notifyInfo.poData = ctx->pBuffer + oSpiSize;
            notifyInfo.oSpiSize = oSpiSize;
            info.pxNotify = &notifyInfo;

            ctx1.pxInfo = &info;
            ctx1.pxSa = pxSa;

            /*status = */IKE_xchgOut(&ctx1);
        }

        break;

#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)
    case PRESHARED_KEY_HASH :
        if (!IS_HYBRID_SERVER(pxSa))
            break;

        switch (pxSa->oState)
        {
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
        case STATE_AGGR_I2 :
        case STATE_AGGR_R2 :
#endif
        case STATE_MAIN_I4 :
        case STATE_MAIN_R3 :
        {
            const BulkHashAlgo *pBHAlgo = pxSa->pHashSuite->pBHAlgo;
            ubyte2 wDigestLen = (ubyte2) pBHAlgo->digestSize;
            ubyte __crypto__(poHash, IKE_HASH_MAX);
            sbyte4 compareResult;

            if (((ubyte2)oSpiSize + wDigestLen) > wBodyLen)
            {
                status = ERR_IKE_BAD_HASH;
                DBG_EXIT
            }

            /* calculate hash value */
            _CRYPTO_ALLOC_(poHash, IKE_HASH_MAX)
            if (OK > (status = DoHashPsk(ctx, poHash, pBHAlgo)))
            {
                if (ERR_IKE_NULL_PSK == status) /* no PSK */
                {
                    status = OK; /* ignore it */
                }
            }
            else

            /* verify hash data */
            if ((OK > (status = DIGI_MEMCMP(poHash, ctx->pBuffer + oSpiSize,
                                           wDigestLen, &compareResult))) ||
                (0 != compareResult))
            {
                if (OK <= status)
                {
                    status = ERR_IKE_BAD_HASH;
                }
                DBG_STATUS
            }

            _CRYPTO_FREE_(poHash)
            break;
        }
        default :
            break;
        }

        break;
#endif /* defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__) */

    default :
    {
#ifdef CUSTOM_IKE_CATCH_EXCEPTION
        MOC_IP_ADDRESS peerAddr = REF_MOC_IPADDR(pxSa->dwPeerAddr);

        CUSTOM_IKE_CATCH_EXCEPTION(ERR_IKE_NOTIFY_PAYLOAD,
            peerAddr, pxIkeHdr,
            ISAKMP_NEXT_N, pxNotifyHdr,
            pxSa, pxXg, pxIPsecSa);
#endif
        /* NOTIFY MESSAGES - ERROR TYPES */
        if (wMsgType && (CONNECTED > wMsgType) &&
            (ISAKMP_XCHG_INFO == pxIkeHdr->oExchange) &&
            !IS_P1_FINAL_STATE(pxSa->oState) &&
            IS_INITIATOR(pxSa))
        {
            /* for local error tracking, no effect on exchange */
            ctx->wMsgType = wMsgType; /* transient!!! */
        }
        break;
    }

    } /* END switch (wMsgType) */

    /* done */
    IN_END

exit:
    return status;
} /* InNotify */


/*------------------------------------------------------------------*/

static MSTATUS
CheckInDelete(const IKESA pxSa, void *pData)
{
    IKESA pxSa0 = (IKESA)pData;
    MSTATUS status = ERR_IKE_GETSA_FAIL;

    if (pxSa == pxSa0) /* deleting self !!! */
    {
#ifdef __IKE_MULTI_THREADED__
        goto dpc; /* delaying until later */
#else
        status = OK;
        goto exit;
#endif
    }

#ifdef __IKE_MULTI_THREADED__
    if (IKE_SA_FLAG_DELETED & pxSa->flags)
    {
        goto exit;
    }
#endif

    if (IKE_isEmptyCky(pxSa->poCky_R))
    {
        goto exit;
    }

#ifdef __ENABLE_IPSEC_NAT_T__
    /* See RFC3947 6. p.11 */
    if ((pxSa0->wPeerPort != pxSa->wPeerPort) &&
        (IS_PEER_BEHIND_NAT(pxSa0) || IS_PEER_BEHIND_NAT(pxSa)))
    {
        goto exit;
    }
#endif

    if (SAME_MOC_IPADDR(REF_MOC_IPADDR(pxSa0->dwPeerAddr), pxSa->dwPeerAddr))
    {
#ifdef __IKE_MULTI_THREADED__
        if (FALSE == RTOS_sameThreadId(pxSa0->tid, pxSa->tid))
        {
dpc:
            /* relay this call to the proper thread */
            if (m_ikeSettings.funcPtrIkeThreadSend)
            {
                struct dpcDelSa ds;
                ds.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcDelSa;
                ds.hdr.dpc_len = (ubyte2)sizeof(ds);
                ds.pxSa = pxSa;
                ds.dwSaId = pxSa->dwId;
                ds.bInfo = FALSE;
                ds.merror = STATUS_IKE_DELETE_PAYLOAD;
                status = (MSTATUS) m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid,
                                            (ubyte *)&ds, (ubyte4)sizeof(ds));
                if (OK <= status) status = STATUS_IKE_GETSA_SUCCESS;
            }
            else
            {
                status = ERR_IKE_CONFIG;
            }
        }
        else
#endif
        {
            status = OK;
        }
    }

exit:
    return status;
} /* CheckInDelete */


/*------------------------------------------------------------------*/

static MSTATUS
InDelete(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
#ifdef __IKE_MULTI_HOMING__
    sbyte4 serverInstance = pxSa->serverInstance;
#endif
    struct ikeHdr *pxHdr = (struct ikeHdr *) ctx->pHdrParent;

    ubyte2 wSpiNum, i;

    /* delete payload header */
    IN_BEGIN(struct ikeDelHdr, pxDelHdr, SIZEOF_IKE_DEL_HDR)
    SET_NTOHS(wSpiNum, pxDelHdr->wSpiNum);

    debug_print("   Delete: ");
    debug_int(wSpiNum);
    debug_print3(" ",
        ((PROTO_ISAKMP == pxDelHdr->oProtoId) ? "ISAKMP" : "IPsec"),
        ((1==wSpiNum) ? " SA" : " SA's"));

    /* must always be performed under protection */
    if (!(ISAKMP_FLAG_ENCRYPTION & pxHdr->oFlags))
    {
        status = ERR_IKE_BAD_FLAGS;
        DBG_EXIT
    }

    switch (pxDelHdr->oDoi)
    {
    case 0 :
    case ISAKMP_DOI_IPSEC :
        switch (pxDelHdr->oProtoId)
        {
        case PROTO_ISAKMP :
            if (IKE_P1_SPI_SIZE != pxDelHdr->oSpiSize)
            {
                status = ERR_IKE_BAD_SPI;
                DBG_EXIT
            }
            if (wBodyLen < (IKE_P1_SPI_SIZE * wSpiNum))
            {
                status = ERR_IKE_BAD_LEN;
                DBG_EXIT
            }
            for (i=0; i < wSpiNum; i++)
            {
                ubyte *poCky_I = ctx->pBuffer + (i * IKE_P1_SPI_SIZE);
                ubyte *poCky_R = poCky_I + IKE_COOKIE_SIZE;
                IKESA pxSaTmp = NULL;
                MSTATUS st;
                INIT_MOC_IPADDR(peerAddr, pxSa->dwPeerAddr)

                debug_print("    IKE_delSa(peer=");
                debug_print_ip(peerAddr);
                debug_print(" cookies={");
                debug_printr(poCky_I, IKE_COOKIE_SIZE, FALSE);
                debug_print(" ");
                debug_printr(poCky_R, IKE_COOKIE_SIZE, FALSE);
                debug_print("})");

                if (IKE_isEmptyCky(poCky_R))
                {
                    debug_printnl("=NULL_COOKIE_R");
                }
                else
                if (OK <= (st = IKE_getSa(poCky_I, poCky_R, 0, peerAddr,
                                          &pxSaTmp, pxSa, CheckInDelete
                                          MOC_MTHM_VALUE(serverInstance))))
                {
                    if (NULL != pxSaTmp)
                    {
                        debug_printnl(NULL);
                        IKE_delSa(pxSaTmp, FALSE, STATUS_IKE_DELETE_PAYLOAD);
                    }
                    else debug_printnl("=NULL");
                }
                else debug_print_st((sbyte4)st);
            }
            break;

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
                status = ERR_IKE_BAD_SPI;
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
            for (i=0; i < wSpiNum; i++)
            {
                ubyte4 dwSpi = GET_NTOHL(pxDelHdr->adwSpi[i]);

                /* stop re-transmit of quick mode final message, if applicable */
                IPSECSA pxIPsecSa;
                pxIPsecSa = IKE_findIPsecSa(pxSa, pxDelHdr->oProtoId, dwSpi);
                if (NULL != pxIPsecSa)
                    IKE_delIPsecSa(pxIPsecSa, pxSa);

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
        break;
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

#define IN_N \
    IN_NEXT(ISAKMP_NEXT_N, InNotify)\


#define IN_ND \
    IN_N \
    IN_NEXT(ISAKMP_NEXT_D, InDelete)\


#define IN_CR \
    IN_NEXT(ISAKMP_NEXT_CR, InCR)\


#define IN_CERT \
    IN_NEXT(ISAKMP_NEXT_CERT, InCert)\


#define IN_VID \
    IN_NEXT(ISAKMP_NEXT_VID, InVid)\


#define IN_NAT_D \
    IN_NEXT(ISAKMP_NEXT_NAT_D, InNatD)\
    IN_NEXT(ISAKMP_NEXT_NAT_D_DRAFTS, InNatD)\
    IN_NEXT(ISAKMP_NEXT_NAT_D_DRAFTS_48, InNatD)\


#define IN_LOOP(_in_np) \
    IN_LOOP_BEGIN \
        _in_np \
    IN_LOOP_END \


#define IN_LOOP2(_in_np_1, _in_np_2) \
    IN_LOOP_BEGIN \
        _in_np_1 \
        _in_np_2 \
    IN_LOOP_END \


#define IN_LOOP3(_in_np_1, _in_np_2, _in_np_3) \
    IN_LOOP_BEGIN \
        _in_np_1 \
        _in_np_2 \
        _in_np_3 \
    IN_LOOP_END \


#define IN_LOOP4(_in_np_1, _in_np_2, _in_np_3, _in_np_4) \
    IN_LOOP_BEGIN \
        _in_np_1 \
        _in_np_2 \
        _in_np_3 \
        _in_np_4 \
    IN_LOOP_END \


#define IN_CR_LOOP          IN_LOOP(IN_CR)

#define IN_ND_LOOP          IN_LOOP(IN_ND)

#define IN_VID_CR_LOOP      IN_LOOP2(IN_VID,    IN_CR)


/*------------------------------------------------------------------*/

static MSTATUS
mainI1_out(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  Main Initiator 1 -->");

    /* SA --> */
    DO_FUNC(OutSa)

    /* VID --> */
    DO_FUNC(OutVid)

exit:
    return status;
} /* mainI1_out*/


/*------------------------------------------------------------------*/

static MSTATUS
mainR1_in(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  --> Main Responder 1");

    /* SA --> */
    IN_PAYLOAD(ISAKMP_NEXT_SA, InSa, ERR_IKE_BAD_SA)

    /* [VID, CR] --> */
    IN_VID_CR_LOOP

exit:
    return status;
} /* mainR1_in */


static MSTATUS
mainR1_out(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  <-- Main Responder 1");

    /* <-- SA */
    DO_FUNC(OutSa)

    /* <-- VID */
    DO_FUNC(OutVid)

exit:
    return status;
} /* mainR1_out */


/*------------------------------------------------------------------*/

static MSTATUS
mainI2_in(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  Main Initiator 2 <--");

    /* <-- SA */
    IN_PAYLOAD(ISAKMP_NEXT_SA, InSa, ERR_IKE_BAD_SA)

    /* <-- [VID, CR] */
    IN_VID_CR_LOOP

    /* set responder cookie */
    DIGI_MEMCPY(ctx->pxSa->poCky_R, ((struct ikeHdr *) ctx->pHdrParent)->poCky_R, IKE_COOKIE_SIZE);

exit:
    return status;
} /* mainI2_in */


static MSTATUS
mainI2_out(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  Main Initiator 2 -->");

    /* KE --> */
    DO_FUNC(OutKe)

    /* Ni --> */
    DO_FUNC(OutNonce)

#ifdef __ENABLE_IPSEC_NAT_T__
    /* NAT-D, NAT-D --> */
    DO_FUNC(OutNatD)
#endif

exit:
    return status;
} /* mainI2_out */


/*------------------------------------------------------------------*/

static MSTATUS
mainR2_in(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  --> Main Responder 2");

    /* loop through payloads */
    IN_LOOP_BEGIN

    /* KE --> */
    IN_NEXT(ISAKMP_NEXT_KE, InKe)

    /* [CR, N] --> */
    IN_CR
    IN_N

    /* Ni --> */
    IN_NEXT(ISAKMP_NEXT_NONCE, InNonce)

    /* [VID] --> */
    IN_VID

#ifdef __ENABLE_IPSEC_NAT_T__
    /* NAT-D, NAT-D+ --> */
    IN_NAT_D
#endif

    IN_LOOP_NONE
    IN_LOOP_NONE_END

    if (!(IKE_CNTXT_FLAG_KE & ctx->flags)) /* missing KE payload */
    {
        status = ERR_IKE_BAD_KE;
        DBG_EXIT
    }
    if (!(IKE_CNTXT_FLAG_NONCE & ctx->flags)) /* missing Nonce payload */
    {
        status = ERR_IKE_BAD_NONCE;
        DBG_EXIT
    }

    /* generate keys */
    DO_FUNC(DoKe)

exit:
    return status;
} /* mainR2_in */


static MSTATUS
mainR2_out(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  <-- Main Responder 2");

    /* <-- KE */
    DO_FUNC(OutKe)

    /* <-- Nr */
    DO_FUNC(OutNonce)

#ifdef __ENABLE_IPSEC_NAT_T__
    /* <-- NAT-D, NAT-D */
    if (IKE_NATT_FLAG_D & ctx->pxSa->natt_flags)
    DO_FUNC(OutNatD)
#endif

#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)
    if (!IS_HYBRID_SERVER(ctx->pxSa))
#endif
    /* <-- [CR] */
    if (UseCert(ctx->pxSa))
    DO_FUNC(OutCR)

exit:
    return status;
} /* mainR2_out */


/*------------------------------------------------------------------*/

static MSTATUS
mainI3_in(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  Main Initiator 3 <--");

    /* loop through payloads */
    IN_LOOP_BEGIN

    /* <-- KE */
    IN_NEXT(ISAKMP_NEXT_KE, InKe)

    /* <-- [CR, N] */
    IN_CR
    IN_N

    /* <-- Nr */
    IN_NEXT(ISAKMP_NEXT_NONCE, InNonce)

    /* <-- [VID] */
    IN_VID

#ifdef __ENABLE_IPSEC_NAT_T__
    /* <-- NAT-D, NAT-D+ */
    IN_NAT_D
#endif

    IN_LOOP_NONE
    IN_LOOP_NONE_END

    if (!(IKE_CNTXT_FLAG_KE & ctx->flags)) /* missing KE payload */
    {
        status = ERR_IKE_BAD_KE;
        DBG_EXIT
    }
    if (!(IKE_CNTXT_FLAG_NONCE & ctx->flags)) /* missing Nonce payload */
    {
        status = ERR_IKE_BAD_NONCE;
        DBG_EXIT
    }

    /* generate keys */
    DO_FUNC(DoKe)

exit:
    return status;
} /* mainI3_in */


static MSTATUS
mainI3_out(IKE_context ctx)
{
    MSTATUS status;

    IKESA pxSa = ctx->pxSa;
    struct ikeHdr *pxHdr;

    debug_printnl("  Main Initiator 3 -->");

    /* HDR* --> */
    pxHdr = (struct ikeHdr *) ctx->pHdrParent;
    pxHdr->oFlags |= ISAKMP_FLAG_ENCRYPTION;

    /* IDii --> */
    DO_FUNC(OutId)

    /* [N(INITIAL_CONTACT)] --> */
    if (IKE_SA_FLAG_TX_INIT_C & pxSa->flags)
    {
        if (OK > (status = DoOutNotify(ctx, IPSEC_INITIAL_CONTACT)))
            goto exit;
    }

    switch (BASE_AUTH_MTD(pxSa))
    {
    case OAKLEY_PRESHARED_KEY :

    /* HASH_I --> */
    DO_FUNC(OutHash)

    break;
    case OAKLEY_RSA_SIG :
#ifdef __ENABLE_DIGICERT_ECC__
    case OAKLEY_ECDSA_SIG :
    case OAKLEY_ECDSA_256 :
    case OAKLEY_ECDSA_384 :
    case OAKLEY_ECDSA_521 :
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    case OAKLEY_P256_MLDSA_44:
    case OAKLEY_P256_FNDSA512:
    case OAKLEY_P384_MLDSA_65:
    case OAKLEY_P521_FNDSA1024:
#endif

#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)
    if (!IS_HYBRID_SERVER(pxSa))
#endif
    /* [CR] --> */
    DO_FUNC(OutCR)

    /* CERT --> */
    DO_FUNC(OutCert)

#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)
    if (IS_HYBRID_CLIENT(pxSa))
    {
        /* HASH_I --> */
        DO_FUNC(OutHash)
        DO_FUNC(OutNotifyHashPsk)
        break;
    }
#endif

    /* SIG_I --> */
    DO_FUNC(OutSig)

    break;
    default : /* should not get here */
        status = ERR_IKE;
        DBG_EXIT
    }

exit:
    return status;
} /* mainI3_out */


/*------------------------------------------------------------------*/

static MSTATUS
mainR3_in(IKE_context ctx)
{
    MSTATUS status;

    IKESA pxSa = ctx->pxSa;
    struct ikeHdr *pxHdr;

    intBoolean bCertStatusCheck = FALSE;

    debug_printnl("  --> Main Responder 3");

    /* HDR* --> */
    pxHdr = (struct ikeHdr *) ctx->pHdrParent;
    if (!(ISAKMP_FLAG_ENCRYPTION & pxHdr->oFlags))
    {
        status = ERR_IKE_BAD_FLAGS;
        DBG_EXIT
    }

#ifdef __ENABLE_IPSEC_NAT_T__
    /* # --> */
    if (IS_BEHIND_NAT(pxSa) && !USE_NATT_PORT(pxSa))
    {
        status = ERR_IKE_BAD_PORT; /* should use port 4500 */
        DBG_EXIT
    }
#endif
    /* [CERT, CR, N/D, VID] --> */
    IN_LOOP4(IN_CERT, IN_CR, IN_ND, IN_VID)

    /* IDii --> */
    IN_PAYLOAD(ISAKMP_NEXT_ID, InId, ERR_IKE_BAD_ID)

    /* [CERT, CR, N/D, VID] --> */
    IN_LOOP4(IN_CERT, IN_CR, IN_ND, IN_VID)

    switch (BASE_AUTH_MTD(pxSa))
    {
    case OAKLEY_PRESHARED_KEY :

    /* HASH_I --> */
    IN_PAYLOAD(ISAKMP_NEXT_HASH, InHash, ERR_IKE_BAD_HASH)

    break;
    case OAKLEY_RSA_SIG :
#ifdef __ENABLE_DIGICERT_ECC__
    case OAKLEY_ECDSA_SIG :
    case OAKLEY_ECDSA_256 :
    case OAKLEY_ECDSA_384 :
    case OAKLEY_ECDSA_521 :
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    case OAKLEY_P256_MLDSA_44:
    case OAKLEY_P256_FNDSA512:
    case OAKLEY_P384_MLDSA_65:
    case OAKLEY_P521_FNDSA1024:
#endif

#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)
    if (IS_HYBRID_SERVER(pxSa))
    {
        /* HASH_I --> */
        IN_PAYLOAD(ISAKMP_NEXT_HASH, InHash, ERR_IKE_BAD_HASH)
        break;
    }
#endif

    /* SIG_I --> */
    IN_PAYLOAD(ISAKMP_NEXT_SIG, InSig, ERR_IKE_BAD_SIG)
    bCertStatusCheck = ((0 < ctx->certNum) ? TRUE : FALSE);

    break;
    default : /* should not get here */
        status = ERR_IKE;
        DBG_EXIT
    }

    /* [CR, N/D, VID] --> */
    IN_LOOP3(IN_CR, IN_ND, IN_VID)

    /* certificate (revocation) status check */
    CERT_STATUS_CHECK(bCertStatusCheck, pxSa, ctx, status)

exit:
    return status;
} /* mainR3_in */


static MSTATUS
mainR3_out(IKE_context ctx)
{
    MSTATUS status;

    struct ikeHdr *pxHdr;

    debug_printnl("  <-- Main Responder 3");

    /* <-- HDR* */
    pxHdr = (struct ikeHdr *) ctx->pHdrParent;
    pxHdr->oFlags |= ISAKMP_FLAG_ENCRYPTION;

    /* <-- IDir */
    DO_FUNC(OutId)

    switch (BASE_AUTH_MTD(ctx->pxSa))
    {
    case OAKLEY_PRESHARED_KEY :

    /* <-- HASH_R */
    DO_FUNC(OutHash)

    break;
    case OAKLEY_RSA_SIG :
#ifdef __ENABLE_DIGICERT_ECC__
    case OAKLEY_ECDSA_SIG :
    case OAKLEY_ECDSA_256 :
    case OAKLEY_ECDSA_384 :
    case OAKLEY_ECDSA_521 :
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    case OAKLEY_P256_MLDSA_44:
    case OAKLEY_P256_FNDSA512:
    case OAKLEY_P384_MLDSA_65:
    case OAKLEY_P521_FNDSA1024:
#endif

    /* <-- CERT */
    DO_FUNC(OutCert)

#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)
    if (IS_HYBRID_CLIENT(ctx->pxSa))
    {
        /* <-- HASH_R */
        DO_FUNC(OutHash)
        DO_FUNC(OutNotifyHashPsk)
        break;
    }
#endif

    /* <-- SIG_R */
    DO_FUNC(OutSig)

    break;
    default : /* should not get here */
        status = ERR_IKE;
        DBG_EXIT
    }

    /* <-- [N] */
    DO_FUNC(OutInfoRespLife1)

exit:
    return status;
} /* mainR3_out */


/*------------------------------------------------------------------*/

static MSTATUS
mainI4_in(IKE_context ctx)
{
    MSTATUS status;

    IKESA pxSa = ctx->pxSa;
    struct ikeHdr *pxHdr;

    intBoolean bCertStatusCheck = FALSE;

    debug_printnl("  Main Initiator 4 <--");

    /* <-- HDR* */
    pxHdr = (struct ikeHdr *) ctx->pHdrParent;
    if (!(ISAKMP_FLAG_ENCRYPTION & pxHdr->oFlags))
    {
        status = ERR_IKE_BAD_FLAGS;
        DBG_EXIT
    }

    /* <-- [CERT, N/D, VID] */
    IN_LOOP3(IN_CERT, IN_ND, IN_VID)

    /* <-- IDir */
    IN_PAYLOAD(ISAKMP_NEXT_ID, InId, ERR_IKE_BAD_ID)

    /* <-- [CERT, N/D, VID] */
    IN_LOOP3(IN_CERT, IN_ND, IN_VID)

    switch (BASE_AUTH_MTD(pxSa))
    {
    case OAKLEY_PRESHARED_KEY :

    /* <-- HASH_R */
    IN_PAYLOAD(ISAKMP_NEXT_HASH, InHash, ERR_IKE_BAD_HASH)

    break;
    case OAKLEY_RSA_SIG :
#ifdef __ENABLE_DIGICERT_ECC__
    case OAKLEY_ECDSA_SIG :
    case OAKLEY_ECDSA_256 :
    case OAKLEY_ECDSA_384 :
    case OAKLEY_ECDSA_521 :
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    case OAKLEY_P256_MLDSA_44:
    case OAKLEY_P256_FNDSA512:
    case OAKLEY_P384_MLDSA_65:
    case OAKLEY_P521_FNDSA1024:
#endif

#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)
    if (IS_HYBRID_SERVER(pxSa))
    {
        /* <-- HASH_R */
        IN_PAYLOAD(ISAKMP_NEXT_HASH, InHash, ERR_IKE_BAD_HASH)
        break;
    }
#endif

    /* <-- SIG_R */
    IN_PAYLOAD(ISAKMP_NEXT_SIG, InSig, ERR_IKE_BAD_SIG)
    bCertStatusCheck = ((0 < ctx->certNum) ? TRUE : FALSE);

    break;
    default : /* should not get here */
        status = ERR_IKE;
        DBG_EXIT
    }

    /* <-- [N/D, VID] */
    IN_LOOP2(IN_ND, IN_VID)

    pxSa->flags |= IKE_SA_FLAG_MATURE;

    /* certificate (revocation) status check */
    CERT_STATUS_CHECK(bCertStatusCheck, pxSa, ctx, status)

exit:
    return status;
} /* mainI4_in */


#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__

/*------------------------------------------------------------------*/

static MSTATUS
aggrI1_out(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  Aggr. Initiator 1 -->");

    /* SA --> */
    DO_FUNC(OutSa)

    /* KE --> */
    DO_FUNC(OutKe)

    /* Ni --> */
    DO_FUNC(OutNonce)

    /* IDii --> */
    DO_FUNC(OutId)

    /* VID --> */
    DO_FUNC(OutVid)

    /* [CR] --> */
    DO_FUNC(OutCR_aggrI1)

exit:
    AUTH_MTD(ctx->pxSa) = 0; /* see OutTfm, OutCR_aggrI1 & OutId */
    return status;
} /* aggrI1_out*/


/*------------------------------------------------------------------*/

static MSTATUS
aggrR1_in(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  --> Aggr. Responder 1");

    /* IDii, [CR] --> befroe SA */
    IN_SET
    IN_LOOP_BEGIN
        IN_NEXT(ISAKMP_NEXT_ID, InId)
        IN_CR
    IN_LOOP_NONE
    IN_LOOP_NONE_END
    IN_RESET

    if (!(IKE_CNTXT_FLAG_ID & ctx->flags)) /* missing ID payload */
    {
        status = ERR_IKE_BAD_ID;
        DBG_EXIT
    }

    /* SA --> */
    IN_PAYLOAD(ISAKMP_NEXT_SA, InSa, ERR_IKE_BAD_SA)

    /* loop through payloads */
    IN_LOOP_BEGIN

    /* KE --> */
    IN_NEXT(ISAKMP_NEXT_KE, InKe)

    /* Ni --> */
    IN_NEXT(ISAKMP_NEXT_NONCE, InNonce)

    /* IDii --> */
    IN_SKIP(ISAKMP_NEXT_ID)

    /* [CR] --> */
    IN_SKIP(ISAKMP_NEXT_CR)

    /* [VID, N] --> */
    IN_VID
    IN_N

    IN_LOOP_NONE
    IN_LOOP_NONE_END

    if (!(IKE_CNTXT_FLAG_KE & ctx->flags)) /* missing KE payload */
    {
        status = ERR_IKE_BAD_KE;
        DBG_EXIT
    }
    if (!(IKE_CNTXT_FLAG_NONCE & ctx->flags)) /* missing Nonce payload */
    {
        status = ERR_IKE_BAD_NONCE;
        DBG_EXIT
    }

    /* generate keys */
    DO_FUNC(DoKe)

exit:
    return status;
} /* aggrR1_in */


static MSTATUS
aggrR1_out(IKE_context ctx)
{
    MSTATUS status;

    IKESA pxSa = ctx->pxSa;

    debug_printnl("  <-- Aggr. Responder 1");

    /* <-- SA */
    DO_FUNC(OutSa)

    /* <-- KE */
    DO_FUNC(OutKe)

    /* <-- Nr */
    DO_FUNC(OutNonce)

    /* <-- IDir */
    DO_FUNC(OutId)

    switch (BASE_AUTH_MTD(pxSa))
    {
    case OAKLEY_PRESHARED_KEY :

    /* <-- VID */
    DO_FUNC(OutVid)

#ifdef __ENABLE_IPSEC_NAT_T__
    /* <-- NAT-D, NAT-D */
    if (IKE_NATT_FLAG_D & ctx->pxSa->natt_flags)
      DO_FUNC(OutNatD)
#endif
    /* <-- HASH_R */
    DO_FUNC(OutHash)

    break;
    case OAKLEY_RSA_SIG :
#ifdef __ENABLE_DIGICERT_ECC__
    case OAKLEY_ECDSA_SIG :
    case OAKLEY_ECDSA_256 :
    case OAKLEY_ECDSA_384 :
    case OAKLEY_ECDSA_521 :
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    case OAKLEY_P256_MLDSA_44:
    case OAKLEY_P256_FNDSA512:
    case OAKLEY_P384_MLDSA_65:
    case OAKLEY_P521_FNDSA1024:
#endif

#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)
    if (!IS_HYBRID_SERVER(pxSa))
#endif
    /* <-- [CR] */
    DO_FUNC(OutCR_aggrR1)

    /* <-- CERT */
    DO_FUNC(OutCert)

    /* <-- VID */
    DO_FUNC(OutVid)

#ifdef __ENABLE_IPSEC_NAT_T__
    /* <-- NAT-D, NAT-D */
    if (IKE_NATT_FLAG_D & ctx->pxSa->natt_flags)
      DO_FUNC(OutNatD)
#endif

#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)
    if (IS_HYBRID_CLIENT(pxSa))
    {
        /* <-- HASH_R */
        DO_FUNC(OutHash)
        DO_FUNC(OutNotifyHashPsk)
        break;
    }
#endif

    /* <-- SIG_R */
    DO_FUNC(OutSig)

    break;
    default : /* should not get here */
        status = ERR_IKE;
        DBG_EXIT
    }

exit:
    return status;
} /* aggrR1_out */


/*------------------------------------------------------------------*/

static MSTATUS
aggrI2_in(IKE_context ctx)
{
    MSTATUS status;

    IKESA pxSa = ctx->pxSa;
    intBoolean bCertStatusCheck = FALSE;

    debug_printnl("  Aggr. Initiator 2 <--");

    /* set responder cookie */
    DIGI_MEMCPY(pxSa->poCky_R, ((struct ikeHdr *) ctx->pHdrParent)->poCky_R, IKE_COOKIE_SIZE);

#if defined(CUSTOM_IKE_GET_PSK) || defined(CUSTOM_IKE_USE_CERT)
    /* get IDir befroe SA!!! */
    IN_SET
    IN_LOOP_BEGIN
    IN_NEXT(ISAKMP_NEXT_ID, InId)
    IN_LOOP_NONE
    IN_LOOP_NONE_END
    IN_RESET

    if (!(IKE_CNTXT_FLAG_ID & ctx->flags)) /* missing ID payload */
    {
        status = ERR_IKE_BAD_ID;
        DBG_EXIT
    }
#endif

    /* <-- SA */
    IN_PAYLOAD(ISAKMP_NEXT_SA, InSa, ERR_IKE_BAD_SA)

#ifdef __ENABLE_IPSEC_NAT_T__
    /* get NAT-T VID - *before* NAT-D payloads!!! */
    IN_SET
    IN_LOOP_BEGIN
    IN_VID
    IN_LOOP_NONE
    IN_LOOP_NONE_END
    IN_RESET
#endif

    /* loop through payloads */
    IN_LOOP_BEGIN

    /* <-- [CR, N] */
    IN_CR
    IN_N

    /* <-- KE */
    IN_NEXT(ISAKMP_NEXT_KE, InKe)

    /* <-- Nr */
    IN_NEXT(ISAKMP_NEXT_NONCE, InNonce)

    /* <-- IDir */
#if defined(CUSTOM_IKE_GET_PSK) || defined(CUSTOM_IKE_USE_CERT)
    IN_SKIP(ISAKMP_NEXT_ID)
#else
    IN_NEXT(ISAKMP_NEXT_ID, InId)
#endif

    /* <-- [CERT] */
    IN_CERT

#ifndef __ENABLE_IPSEC_NAT_T__
    /* <-- [VID] */
    IN_VID
#else
    IN_SKIP(ISAKMP_NEXT_VID)

    /* <-- NAT-D, NAT-D+ */
    IN_NAT_D
#endif

    IN_LOOP_END

    if (!(IKE_CNTXT_FLAG_KE & ctx->flags)) /* missing KE payload */
    {
        status = ERR_IKE_BAD_KE;
        DBG_EXIT
    }
    if (!(IKE_CNTXT_FLAG_NONCE & ctx->flags)) /* missing Nonce payload */
    {
        status = ERR_IKE_BAD_NONCE;
        DBG_EXIT
    }
#if !(defined(CUSTOM_IKE_GET_PSK) || defined(CUSTOM_IKE_USE_CERT))
    if (!(IKE_CNTXT_FLAG_ID & ctx->flags)) /* missing ID payload */
    {
        status = ERR_IKE_BAD_ID;
        DBG_EXIT
    }
#endif

    /* generate keys - *before* HASH_R/SIG_R!!! */
    DO_FUNC(DoKe)

    switch (BASE_AUTH_MTD(pxSa))
    {
    case OAKLEY_PRESHARED_KEY :

    /* <-- HASH_R */
    IN_PAYLOAD(ISAKMP_NEXT_HASH, InHash, ERR_IKE_BAD_HASH)

    break;
    case OAKLEY_RSA_SIG :
#ifdef __ENABLE_DIGICERT_ECC__
    case OAKLEY_ECDSA_SIG :
    case OAKLEY_ECDSA_256 :
    case OAKLEY_ECDSA_384 :
    case OAKLEY_ECDSA_521 :
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    case OAKLEY_P256_MLDSA_44:
    case OAKLEY_P256_FNDSA512:
    case OAKLEY_P384_MLDSA_65:
    case OAKLEY_P521_FNDSA1024:
#endif

#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)
    if (IS_HYBRID_SERVER(pxSa))
    {
        /* <-- HASH_R */
        IN_PAYLOAD(ISAKMP_NEXT_HASH, InHash, ERR_IKE_BAD_HASH)
        break;
    }
#endif

    /* <-- SIG_R */
    IN_PAYLOAD(ISAKMP_NEXT_SIG, InSig, ERR_IKE_BAD_SIG)
    bCertStatusCheck = ((0 < ctx->certNum) ? TRUE : FALSE);

    break;
    default : /* should not get here */
        status = ERR_IKE;
        DBG_EXIT
    }

    /* <-- [CR, N, VID, NAT-D, NAT-D+] */
    IN_LOOP_BEGIN
    IN_CR
    IN_N
#ifndef __ENABLE_IPSEC_NAT_T__
    IN_VID
#else
    IN_SKIP(ISAKMP_NEXT_VID)
    IN_NAT_D
#endif
    IN_LOOP_NONE
    IN_LOOP_NONE_END

    /* certificate (revocation) status check */
    CERT_STATUS_CHECK(bCertStatusCheck, pxSa, ctx, status)

exit:
    if ((OK > status) && (STATUS_IKE_PENDING != status))
    {
        /* reset responder cookie */
        DIGI_MEMSET(pxSa->poCky_R, 0x00, IKE_COOKIE_SIZE);
    }
    return status;
} /* aggrI2_in */


static MSTATUS
aggrI2_out(IKE_context ctx)
{
    MSTATUS status;

    IKESA pxSa = ctx->pxSa;
    struct ikeHdr *pxHdr;

    debug_printnl("  Aggr. Initiator 2 -->");

    if (IKE_SETTINGS_FLAG_ENCR_AGGR & m_ikeSettings.flags) /* !!! */
    {

    /* HDR* --> */
    pxHdr = (struct ikeHdr *) ctx->pHdrParent;
    pxHdr->oFlags |= ISAKMP_FLAG_ENCRYPTION;

    /* [N(INITIAL_CONTACT)] --> */
    if (IKE_SA_FLAG_TX_INIT_C & pxSa->flags)
    {
        if (OK > (status = DoOutNotify(ctx, IPSEC_INITIAL_CONTACT)))
            goto exit;
    }

    }

    switch (BASE_AUTH_MTD(pxSa))
    {
    case OAKLEY_PRESHARED_KEY :
#ifdef __ENABLE_IPSEC_NAT_T__
    /* NAT-D, NAT-D --> */
    if (IKE_NATT_FLAG_D & pxSa->natt_flags)
    DO_FUNC(OutNatD)
#endif
    /* HASH_I --> */
    DO_FUNC(OutHash)

    break;
    case OAKLEY_RSA_SIG :
#ifdef __ENABLE_DIGICERT_ECC__
    case OAKLEY_ECDSA_SIG :
    case OAKLEY_ECDSA_256 :
    case OAKLEY_ECDSA_384 :
    case OAKLEY_ECDSA_521 :
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    case OAKLEY_P256_MLDSA_44:
    case OAKLEY_P256_FNDSA512:
    case OAKLEY_P384_MLDSA_65:
    case OAKLEY_P521_FNDSA1024:
#endif

    /* CERT --> */
    DO_FUNC(OutCert)

#ifdef __ENABLE_IPSEC_NAT_T__
    /* NAT-D, NAT-D --> */
    if (IKE_NATT_FLAG_D & pxSa->natt_flags)
    DO_FUNC(OutNatD)
#endif

#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)
    if (IS_HYBRID_CLIENT(pxSa))
    {
        /* HASH_I --> */
        DO_FUNC(OutHash)
        DO_FUNC(OutNotifyHashPsk)
        break;
    }
#endif

    /* SIG_I --> */
    DO_FUNC(OutSig)

    break;
    default : /* should not get here */
        status = ERR_IKE;
        DBG_EXIT
    }

    /* check COMMIT flag (set by peer responder) */
    if (!(IKE_SA_FLAG_COMMIT & pxSa->flags))
        ++(pxSa->oState); /* skip COMMIT state */

exit:
    return status;
} /* aggrI2_out */


/*------------------------------------------------------------------*/

static MSTATUS
aggrR2_in(IKE_context ctx)
{
    MSTATUS status;

    IKESA pxSa = ctx->pxSa;
    intBoolean bCertStatusCheck = FALSE;

    debug_printnl("  --> Aggr. Responder 2");

    /* [CERT, NAT-D, NAT-D+, N/D, VID] --> */
    IN_LOOP4(IN_CERT, IN_NAT_D, IN_ND, IN_VID)

    switch (BASE_AUTH_MTD(pxSa))
    {
    case OAKLEY_PRESHARED_KEY :

    /* HASH_I --> */
    IN_PAYLOAD(ISAKMP_NEXT_HASH, InHash, ERR_IKE_BAD_HASH)

    break;
    case OAKLEY_RSA_SIG :
#ifdef __ENABLE_DIGICERT_ECC__
    case OAKLEY_ECDSA_SIG :
    case OAKLEY_ECDSA_256 :
    case OAKLEY_ECDSA_384 :
    case OAKLEY_ECDSA_521 :
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    case OAKLEY_P256_MLDSA_44:
    case OAKLEY_P256_FNDSA512:
    case OAKLEY_P384_MLDSA_65:
    case OAKLEY_P521_FNDSA1024:
#endif

#if defined(__ENABLE_IKE_XAUTH__) && defined(__ENABLE_IKE_HYBRID_RSA__)
    if (IS_HYBRID_SERVER(pxSa))
    {
        /* HASH_I --> */
        IN_PAYLOAD(ISAKMP_NEXT_HASH, InHash, ERR_IKE_BAD_HASH)
        break;
    }
#endif

    /* SIG_I --> */
    IN_PAYLOAD(ISAKMP_NEXT_SIG, InSig, ERR_IKE_BAD_SIG)
    bCertStatusCheck = ((0 < ctx->certNum) ? TRUE : FALSE);

    break;
    default : /* should not get here */
        status = ERR_IKE;
        DBG_EXIT
    }

    IN_LOOP3(IN_NAT_D, IN_ND, IN_VID)

#ifdef __ENABLE_IPSEC_NAT_T__
    if ((0 < pxSa->u.v1.iNatT) &&
        IS_BEHIND_NAT(pxSa) && !USE_NATT_PORT(pxSa))
    {
        status = ERR_IKE_BAD_PORT; /* should use port 4500 */
        DBG_EXIT
    }
#endif

    pxSa->flags |= IKE_SA_FLAG_MATURE;

    /* certificate (revocation) status check */
    CERT_STATUS_CHECK(bCertStatusCheck, pxSa, ctx, status)

exit:
    if ((OK <= status) || (STATUS_IKE_PENDING == status))
    {
        /* adjust IKE_SA lifetime(s) */
        DoRespLife1(pxSa); /* TODO: OutInfoRespLife1() later */
    }
    return status;
} /* aggrR2_in */


/*------------------------------------------------------------------*/

static MSTATUS
aggrI2c_in(IKE_context ctx)
{
    MSTATUS status;

    struct ikeHdr *pxHdr;

    debug_printnl("  Aggr. Initiator 2c <--");

    /* <-- HDR* */
    pxHdr = (struct ikeHdr *) ctx->pHdrParent;
    if (!(ISAKMP_FLAG_ENCRYPTION & pxHdr->oFlags))
    {
        status = ERR_IKE_BAD_FLAGS;
        DBG_EXIT
    }

    /* <-- HASH(1) */
    IN_PAYLOAD(ISAKMP_NEXT_HASH, InHash12, ERR_IKE_BAD_HASH)

    /* <-- N/D */
    IN_LOOP2(IN_ND, IN_VID)

    if (!(IKE_CNTXT_FLAG_CONNECTED & ctx->flags))
    {
        /* no CONNECTED message! */
        status = ERR_IKE;
        DBG_EXIT
    }

    ctx->pxSa->flags |= IKE_SA_FLAG_MATURE;

exit:
    return status;
} /* aggrI2c_in */

#endif /* __ENABLE_IKE_AGGRESSIVE_MODE__ */


/*------------------------------------------------------------------*/

static MSTATUS
quickI1_out(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  Quick Initiator 1 -->");

    /* HASH(1) --> */
    DO_FUNC(OutHashGen)

    /* SA --> */
    DO_FUNC(OutSa)

    /* Ni --> */
    DO_FUNC(OutNonce)

    /* [KE] --> */
    DO_FUNC(OutKe)

    /* IDci, IDcr --> */
    DO_FUNC(OutId2)

#ifdef __ENABLE_IPSEC_NAT_T__
    /* [NAT-OAi, NAT-OAr] --> */
    DO_FUNC(OutNatOa)
#endif
    /* HASH(1) data */
    DO_FUNC(OutHash12)

exit:
    return status;
} /* quickI1_out */


/*------------------------------------------------------------------*/

static MSTATUS
quickR1_in(IKE_context ctx)
{
    MSTATUS status;

#ifdef __ENABLE_IPSEC_NAT_T__
    IKESA pxSa = ctx->pxSa;
    ubyte oNextNatOa = ISAKMP_NEXT_NAT_OA;
#endif
    IPSECSA pxIPsecSa = P2XG_IPSECSA(ctx->pxP2Xg);

    debug_printnl("  --> Quick Responder 1");

    /* HASH(1) --> */
    IN_PAYLOAD(ISAKMP_NEXT_HASH, InHash12, ERR_IKE_BAD_HASH)

    DO_FUNC(DoId2) /* preprocess [IDci, IDcr] --> */

    /* SA --> */
    IN_PAYLOAD(ISAKMP_NEXT_SA, InSa, ERR_IKE_BAD_SA)

#ifdef __ENABLE_IPSEC_NAT_T__
    if (0 < pxSa->u.v1.iNatT)
        oNextNatOa = mNatTinfo[pxSa->u.v1.iNatT - 1].oNatOa;
#endif

    /* loop through payloads */
    IN_LOOP_BEGIN

    /* Ni --> */
    IN_NEXT(ISAKMP_NEXT_NONCE, InNonce)

    /* [KE] --> */
    IN_NEXT(ISAKMP_NEXT_KE, InKe)

    /* [IDci, IDcr] --> */
    IN_NEXT(ISAKMP_NEXT_ID, InId2)

#ifdef __ENABLE_IPSEC_NAT_T__
    /* [NAT-OAi, NAT-OAr] --> */
    IN_NEXT(oNextNatOa, InNatOa)
#endif

    /* [N/D] --> */
    IN_ND

    IN_LOOP_NONE
    IN_LOOP_NONE_END

    if (!(IKE_CNTXT_FLAG_NONCE & ctx->flags)) /* missing Nonce payload */
    {
        status = ERR_IKE_BAD_NONCE;
        DBG_EXIT
    }

    if ((0 != pxIPsecSa->wPFS) && /* KE payload is needed but missing */
        !(IKE_CNTXT_FLAG_KE & ctx->flags))
    {
        status = ERR_IKE_BAD_KE;
        DBG_EXIT
    }

#ifdef __ENABLE_IPSEC_NAT_T__
    if ((0 < pxSa->u.v1.iNatT) && /* NAT-OA's are needed but missing */
        !(IKE_CNTXT_FLAG_NAT_OA & ctx->flags) &&
        NeedNatOa(pxSa, pxIPsecSa, TRUE))
    {
        DBG_ERRCODE(ERR_IKE_BAD_PAYLOAD)
    }
#endif

#ifdef __ENABLE_DIGICERT_PFKEY__
    if (IKE_XCHG_FLAG_PENDING & ctx->pxP2Xg->x_flags)
    {
        status = STATUS_IKE_PENDING;
        pxIPsecSa->merror = status;
        goto exit;
    }
#endif

    /* generate keys */
    DO_FUNC(DoKe2)

exit:
    return status;
} /* quickR1_in */


static MSTATUS
quickR1_out(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  <-- Quick Responder 1");

    /* <-- HASH(2) */
    DO_FUNC(OutHashGen)

    /* <-- SA */
    DO_FUNC(OutSa)

    /* <-- Nr */
    DO_FUNC(OutNonce)

    /* <-- [KE] */
    DO_FUNC(OutKe)

    /* <-- [IDci, IDcr] */
    DO_FUNC(OutId2)

#ifdef __ENABLE_IPSEC_NAT_T__
    /* <-- [NAT-OAi, NAT-OAr] */
    DO_FUNC(OutNatOa)
#endif
    /* <-- [N] */
    DO_FUNC(OutInfoRespLife)

    /* HASH(2) data */
    DO_FUNC(OutHash12)

exit:
    return status;
} /* quickR1_out */


/*------------------------------------------------------------------*/

static MSTATUS
quickI2_in(IKE_context ctx)
{
    MSTATUS status;

#ifdef __ENABLE_IPSEC_NAT_T__
    IKESA pxSa = ctx->pxSa;
    ubyte oNextNatOa = ISAKMP_NEXT_NAT_OA;
#endif
    IPSECSA pxIPsecSa = P2XG_IPSECSA(ctx->pxP2Xg);

    debug_printnl("  Quick Initiator 2 <--");

    /* <-- HASH(2) */
    IN_PAYLOAD(ISAKMP_NEXT_HASH, InHash12, ERR_IKE_BAD_HASH)

    /* <-- SA */
    IN_PAYLOAD(ISAKMP_NEXT_SA, InSa, ERR_IKE_BAD_SA)

#ifdef __ENABLE_IPSEC_NAT_T__
    if (0 < pxSa->u.v1.iNatT)
    {
        oNextNatOa = mNatTinfo[pxSa->u.v1.iNatT - 1].oNatOa;
    }
#endif

    /* loop through payloads */
    IN_LOOP_BEGIN

    /* <-- Nr */
    IN_NEXT(ISAKMP_NEXT_NONCE, InNonce)

    /* <-- [KE] */
    IN_NEXT(ISAKMP_NEXT_KE, InKe)

    /* <-- [IDci, IDcr] */
    IN_NEXT(ISAKMP_NEXT_ID, InId2)

#ifdef __ENABLE_IPSEC_NAT_T__
    /* <-- [NAT-OAi, NAT-OAr] */
    IN_NEXT(oNextNatOa, InNatOa)
#endif

    /* <-- [N/D] */
    IN_ND

    IN_LOOP_NONE
    IN_LOOP_NONE_END

    if (!(IKE_CNTXT_FLAG_NONCE & ctx->flags)) /* missing Nonce payload */
    {
        status = ERR_IKE_BAD_NONCE;
        DBG_EXIT
    }

    if ((0 != pxIPsecSa->wPFS) && /* KE payload is needed but missing */
        !(IKE_CNTXT_FLAG_KE & ctx->flags))
    {
        status = ERR_IKE_BAD_KE;
        DBG_EXIT
    }

    if (!(IKE_CHILD_FLAG_ID2 & pxIPsecSa->c_flags)) /* missing IDci/IDcr payloads */
    {
        status = ERR_IKE_BAD_ID2;
        DBG_EXIT
    }

#ifdef __ENABLE_IPSEC_NAT_T__
    if ((0 < pxSa->u.v1.iNatT) && /* NAT-OA's are needed but missing */
        !(IKE_CNTXT_FLAG_NAT_OA & ctx->flags) &&
        NeedNatOa(pxSa, pxIPsecSa, TRUE))
    {
        DBG_ERRCODE(ERR_IKE_BAD_PAYLOAD)
    }
#endif

    /* generate keys */
    DO_FUNC(DoKe2)

exit:
    return status;
} /* quickI2_in */


static MSTATUS
quickI2_out(IKE_context ctx)
{
    MSTATUS status;

    P2XG pxXg = ctx->pxP2Xg;
    IPSECSA pxIPsecSa = P2XG_IPSECSA(pxXg);

    debug_printnl("  Quick Initiator 2 -->");

    /* HASH(3) --> */
    DO_FUNC(OutHash3)

    /* check COMMIT flag (set by peer responder) */
    if (!(IKE_CHILD_FLAG_COMMIT & pxIPsecSa->c_flags))
    {
        ++pxXg->oState; /* skip COMMIT state */

        if (STATE_QUICK_I != pxIPsecSa->oState) /* jic */
        {
#ifndef __IKE_KEYADD_DONT_WAIT__
            pxIPsecSa->oState = pxXg->oState;
#else
            pxIPsecSa->oState = STATE_QUICK_I;
            status = IKE_addIPsecKey(ctx);
#endif
        }
    }

exit:
    return status;
} /* quickI2_out */


/*------------------------------------------------------------------*/

static MSTATUS
quickR2_in(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  --> Quick Responder 2");

    /* HASH(3) --> */
    IN_PAYLOAD(ISAKMP_NEXT_HASH, InHash3, ERR_IKE_BAD_HASH)

    /* [N/D] --> */
    IN_ND_LOOP

    P2XG_IPSECSA(ctx->pxP2Xg)->c_flags |= IKE_CHILD_FLAG_MATURE;

exit:
    return status;
} /* quickR2_in */


/*------------------------------------------------------------------*/

static MSTATUS
quickI2c_in(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  Quick Initiator 2c <--");

    /* <-- HASH(1) */
    IN_PAYLOAD(ISAKMP_NEXT_HASH, InHash12, ERR_IKE_BAD_HASH)

    /* <-- N/D */
    IN_ND_LOOP

    if (!(IKE_CNTXT_FLAG_CONNECTED & ctx->flags))
    {
        /* no CONNECTED message! */
        status = ERR_IKE;
        DBG_EXIT
    }

    P2XG_IPSECSA(ctx->pxP2Xg)->c_flags |= IKE_CHILD_FLAG_MATURE;

exit:
    return status;
} /* quickI2c_in */


/*------------------------------------------------------------------*/

static MSTATUS
info_out(IKE_context ctx)
{
    MSTATUS status = OK;

    struct ikeHdr *pxHdr;

    debug_printnl("  N/D -->");

    /* HDR* --> */
    pxHdr = (struct ikeHdr *) ctx->pHdrParent;
    if (ISAKMP_FLAG_ENCRYPTION & pxHdr->oFlags)

    /* HASH(1) --> */
    DO_FUNC(OutHashGen)

    /* N/D --> */
    DO_FUNC(OutInfo)

    if (ISAKMP_FLAG_ENCRYPTION & pxHdr->oFlags)

    /* HASH(1) data */
    DO_FUNC(OutHash12)

exit:
    return status;
} /* info_out */


/*------------------------------------------------------------------*/

static MSTATUS
info_in(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;

    debug_printnl("  --> N/D");

    /* HDR* --> */
    if (IKE_SA_FLAG_KE & pxSa->flags)
    {
        struct ikeHdr *pxHdr = (struct ikeHdr *) ctx->pHdrParent;
        if (ISAKMP_FLAG_ENCRYPTION & pxHdr->oFlags)
        {
            if (ISAKMP_NEXT_HASH != ctx->oNextPayload)
            {
                CURR_PAYLOAD
                status = ERR_IKE_BAD_HASH;
                DBG_EXIT
            }
        }

        if (ISAKMP_NEXT_HASH == ctx->oNextPayload)
        {
    /* HASH(1) --> */
    IN_FUNC(InHash12)

            /* prevent replay attack */
#ifdef IKE_P2_REPLAY_SIZE
            pxSa->u.v1.pdwMsgId[pxSa->u.v1.msgRplyIdx] = pxHdr->dwMsgId;
            if (IKE_P2_REPLAY_SIZE <= ++(pxSa->u.v1.msgRplyIdx))
                pxSa->u.v1.msgRplyIdx = 0;
#endif
        }
    }

    /* N/D --> */
    IN_ND_LOOP

    if (ISAKMP_NEXT_NONE != ctx->oNextPayload)
    {
        CURR_PAYLOAD
        status = ERR_IKE_BAD_PAYLOAD;
        DBG_EXIT
    }

exit:
    return status;
} /* info_in */


/*------------------------------------------------------------------*/

static MSTATUS
raw_out(IKE_context ctx)
{
    MSTATUS status = OK;

    struct ikeHdr *pxHdr;

    P2RAW pxRaw = ctx->pxP2Raw;
    ubyte2 wDataLen = pxRaw->wDataLen;
    const ubyte *poData = pxRaw->poData;

    debug_printnl("  Raw -->");

    /* HDR* --> */
    pxHdr = (struct ikeHdr *) ctx->pHdrParent;
    pxHdr->oExchange = pxRaw->oExchange;

    /* HASH(1) --> */
    if (ISAKMP_FLAG_ENCRYPTION & pxHdr->oFlags)
        DO_FUNC(OutHashGen)

    *(ctx->poNextPayload) = pxRaw->oNextPayload;
    ctx->poNextPayload = NULL; /* jic */

    /* --> */
    if (0 != wDataLen) /* jic */
    {
        if (ctx->dwBufferSize < wDataLen)
        {
            status = ERR_IKE_BUFFER_OVERFLOW;
            DBG_EXIT
        }

        if (NULL != poData) /* jic */
            DIGI_MEMCPY(ctx->pBuffer, poData, wDataLen);

        ADVANCE(wDataLen)
    }

    /* HASH(1) data */
    if (ISAKMP_FLAG_ENCRYPTION & pxHdr->oFlags)
        DO_FUNC(OutHash12)

exit:
    return status;
} /* raw_out */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__)

static MSTATUS
InCfg_R(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    P2XG pxXg = ctx->pxP2Xg;

    sbyte4 i;

    ubyte oCfgType;
    ubyte *poCfgAttrs = NULL;
    ubyte2 wCfgAttrsLen = 0;

#ifdef __ENABLE_IKE_MODE_CFG__
    struct ikeIdHdr *pxId;
    ubyte *poId;
    ubyte2 wIdLen;
    sbyte4 idType;
#endif

    /* ATTR payload header */
    IN_BEGIN(struct ikeCfgHdr, pxCfgHdr, SIZEOF_IKE_CFG_HDR)

    SET_NTOHS(pxXg->wCfgId, pxCfgHdr->wIdentifier);
    oCfgType = pxCfgHdr->oType;

    debug_print("   ");
    debug_print_ike_cfgtype(oCfgType);
    if (pxXg->wCfgId)
    {
        debug_print(" #");
        debug_int(pxXg->wCfgId);
    }
    debug_printnl(NULL);

#ifdef __ENABLE_IKE_XAUTH__
    /* draft-ietf-ipsec-isakmp-xauth-01...04
       In these dratfs, the same Message ID is used for all CFG exchanges in a
       single 'configuration'.  In this case, 'pxXg' is re-used and
       pxXg->oCfgType will be non-zero.

       In later drafts, each round of CFG exchanges has a unique message ID, so
       a new 'pxXg' is created accordingly.  The following code is to remove
       existing (old) CFG exchanges for a single 'configuration' (as
       re-transmission is no longer needed).
     */
    if (0 == pxXg->oCfgType)
#endif
    for (i=0; i < IKE_P2_MAX; i++)
    {
        P2XG pxXgTmp = &(pxSa->u.v1.p2Xg[i]);
        if ((pxXgTmp != pxXg) &&
            IS_VALID_XCHG(pxXgTmp) &&
            (pxXg->wCfgId == pxXgTmp->wCfgId))
        {
            switch (pxXgTmp->oState)
            {
            case STATE_CFG_R :
                IKE_delXchg(pxXgTmp, pxSa, OK);
                break;
            case STATE_CFG_R1 :
                if (IKE_XCHG_FLAG_PENDING & pxXgTmp->x_flags)
                {
                    status = STATUS_IKE_PENDING;
                    DBG_EXIT
                }
                break;
            }
        }
    }

#ifdef __ENABLE_IKE_XAUTH__
    if (!(IKE_SA_FLAG_XAUTH & pxSa->flags))
    {
        goto no_xauth;
    }

    if (1 != pxSa->ikePeerConfig->xauthType) /* not XAUTH client! */
    {
        status = ERR_IKE_BAD_XCHG;
        DBG_EXIT
    }

    debug_print_ike_cfg_attrs(ctx->pBuffer, wBodyLen, (sbyte *)"    ", TRUE);

    /* draft-ietf-ipsec-isakmp-xauth-01...02 (CFG_AUTH_OK/FAILED) */
    /* In this special case, no more message is exchanged. */
    switch (oCfgType)
    {
    case CFG_AUTH_OK :
    case CFG_AUTH_OK_1 :
        pxSa->flags &= ~(IKE_SA_FLAG_XAUTH);
        pxXg->oState = STATE_CFG_R1x;
        pxSa->merror = OK; /* jic */
        goto end_xauth;
        break;
    case CFG_AUTH_FAILED :
    case CFG_AUTH_FAILED_1 :
        pxSa->merror = ERR_IKE_XAUTH_FAILED; /* !!! */
        pxXg->oState = STATE_CFG_R1x;
        goto end_xauth;
        break;
    }

    poCfgAttrs = ctx->pBuffer;
    wCfgAttrsLen = wBodyLen;

    if (OK > (status = IKE_xauthProcess(
                            &poCfgAttrs, &wCfgAttrsLen,
                            &oCfgType, pxXg->wCfgId, pxSa)))
    {
        poCfgAttrs = NULL; /* !!! */

        if (STATUS_IKE_PENDING == status)
        {
            pxXg->x_flags |= IKE_XCHG_FLAG_PENDING;
            pxSa->merror = STATUS_IKE_PENDING;
            goto exit;
        }

#ifdef __ENABLE_IKE_MODE_CFG__
        if ((CFG_SET == oCfgType) &&
            (ERR_IKE_XAUTH_BAD_ATTRIBUTE == status))
        {
            /* Remote gateway may combine XAUTH and MODE_CFG in a single
             * 'configuration', e.g. Juniper Netscreen
             */
            goto no_xauth;
        }
#endif
        DBG_EXIT
    }

    /* check Success or Failure */
    if ((CFG_ACK == oCfgType) &&
        (4 <= wBodyLen)) /* jic */
    {
        struct ikeAttr *pAttr = (struct ikeAttr *) ctx->pBuffer;
        ubyte2 wAttr = (0x7fff & GET_NTOHS(pAttr->wAFtype));

        if ((XAUTH_STATUS == wAttr) ||
            (XAUTH_STATUS_35 == wAttr)) /* draft-ietf-ipsec-isakmp-xauth-03...05 */
        {
            switch (GET_NTOHS(pAttr->wLenVal))
            {
            case XAUTH_STATUS_OK : /* success */
                pxSa->flags &= ~(IKE_SA_FLAG_XAUTH);
                pxSa->merror = OK; /* jic */
                break;
            case XAUTH_STATUS_FAIL : /* fail */
                pxSa->merror = ERR_IKE_XAUTH_FAILED; /* !!! */
            default :
                break;
            }
        }
    }

end_xauth:
    pxXg->oCfgType = oCfgType;

    if (NULL != pxXg->poCfgAttrs) /* jic */
        FREE(pxXg->poCfgAttrs);

    pxXg->poCfgAttrs = poCfgAttrs;
    pxXg->wCfgAttrsLen = wCfgAttrsLen;
    poCfgAttrs = NULL; /* !!! */

    IN_END
    goto exit;

no_xauth:
#endif /* __ENABLE_IKE_XAUTH__ */

#ifdef __ENABLE_IKE_MODE_CFG__
    /* get peer identification */
    pxId = (IS_INITIATOR(pxSa) ? pxSa->pxID[_R] : pxSa->pxID[_I]);
    if (NULL != pxId) /* jic */
    {
        wIdLen = GET_NTOHS(pxId->wLength) - SIZEOF_IKE_ID_HDR;
        poId = ((ubyte *)pxId) + SIZEOF_IKE_ID_HDR;
        idType = pxId->oType;
    }
    else
    {
        wIdLen = 0;
        poId = NULL;
        idType = 0;
    }

    /* invoke custom function */
    switch (oCfgType)
    {
    case CFG_SET :
        if (NULL == m_ikeSettings.funcPtrIkePutCfg)
        {
            status = ERR_IKE_BAD_CFG;
            DBG_EXIT
        }

        debug_print_ike_cfg_attrs(ctx->pBuffer, wBodyLen, (sbyte *)"    ", FALSE);

        if (OK > (status = m_ikeSettings.funcPtrIkePutCfg(
                                &poCfgAttrs, &wCfgAttrsLen,
                                ctx->pBuffer, wBodyLen,
                                poId, wIdLen, idType,
                                REF_MOC_IPADDR(pxSa->dwPeerAddr)
                                MOC_MTHM_REQ_VALUE(pxSa->serverInstance),
                                pxSa)))
            DBG_EXIT

        pxXg->oCfgType = CFG_ACK;
        break;

    case CFG_REQUEST :
    {
        /* XAUTH user name? (TBD) */
        ubyte *user = NULL;
        ubyte4 user_len = 0;

        if (NULL == m_ikeSettings.funcPtrIkeGetCfg)
        {
            status = ERR_IKE_BAD_CFG;
            DBG_EXIT
        }

        debug_print_ike_cfg_attrs(ctx->pBuffer, wBodyLen, (sbyte *)"    ", FALSE);
        /* copy the recived wCfgId into pxSa which will be used by the GDOi server to reply back keys */
        ubyte2 wCfgId = pxSa->u.v1.wCfgId;
        pxSa->u.v1.wCfgId = pxXg->wCfgId;
        if (OK > (status = m_ikeSettings.funcPtrIkeGetCfg(
                                &poCfgAttrs, &wCfgAttrsLen,
                                ctx->pBuffer, wBodyLen,
                                poId, wIdLen, idType,
                                user, user_len,
                                REF_MOC_IPADDR(pxSa->dwPeerAddr)
                                MOC_NATT_REQ_VALUE((IS_PEER_BEHIND_NAT(pxSa)
                                                    ? pxSa->wPeerPort : 0))
                                MOC_MTHM_REQ_VALUE(pxSa->serverInstance),
                                pxSa)))
            DBG_EXIT

        pxXg->oCfgType = CFG_REPLY;
        pxSa->u.v1.wCfgId = wCfgId ;
        break;
    }
    default :
        status = ERR_IKE_BAD_CFG;
        DBG_EXIT
        break;
    }

    if (NULL != pxXg->poCfgAttrs) /* jic */
    {
        FREE(pxXg->poCfgAttrs);
        pxXg->wCfgAttrsLen = 0;
    }

    if ((NULL == poCfgAttrs) || !wCfgAttrsLen) /* jic */
    {
        pxXg->poCfgAttrs = NULL;
        pxXg->wCfgAttrsLen = 0;
    }
    else
    {
        /* store ATTR payload attributes (for response) */
        CHECK_MALLOC(pxXg->poCfgAttrs, wCfgAttrsLen)
        DIGI_MEMCPY(pxXg->poCfgAttrs, poCfgAttrs, wCfgAttrsLen);
        pxXg->wCfgAttrsLen = wCfgAttrsLen;
    }
#endif /* __ENABLE_IKE_MODE_CFG__ */

    /* done */
    IN_END

exit:
#ifdef __ENABLE_IKE_MODE_CFG__
    if ((NULL != poCfgAttrs) &&
        (NULL != m_ikeSettings.funcPtrIkeReleaseCfg))
    {
        m_ikeSettings.funcPtrIkeReleaseCfg(poCfgAttrs);
    }
#endif
    return status;
} /* InCfg_R */


/*------------------------------------------------------------------*/

static MSTATUS
InCfg_I(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    P2XG pxXg = ctx->pxP2Xg;

    ubyte oCfgType;

    /* ATTR payload header */
    IN_BEGIN(struct ikeCfgHdr, pxCfgHdr, SIZEOF_IKE_CFG_HDR)
    oCfgType = pxCfgHdr->oType;

    debug_print("   ");
    debug_print_ike_cfgtype(oCfgType);
    if (pxXg->wCfgId)
    {
        debug_print(" #");
        debug_int(pxXg->wCfgId);
    }
    debug_printnl(NULL);

    if (GET_NTOHS(pxCfgHdr->wIdentifier) != pxXg->wCfgId)
    {
        DBG_ERRCODE(ERR_IKE_BAD_CFG) /* !!! */
    }

#ifdef __ENABLE_IKE_XAUTH__
    if (!(IKE_SA_FLAG_XAUTH & pxSa->flags))
        goto no_xauth;

    /* XAUTH (server) does not call this function. Should not get here!!! */
    if (2 != pxSa->ikePeerConfig->xauthType) /* not XAUTH server! */
    {
        status = ERR_IKE_BAD_XCHG;
        DBG_EXIT
    }

    /* TODO: */

no_xauth:
#endif /* __ENABLE_IKE_XAUTH__ */

#ifdef __ENABLE_IKE_MODE_CFG__
    switch (oCfgType)
    {
    case CFG_ACK :
        if (CFG_SET != pxXg->oCfgType)
        {
            status = ERR_IKE_BAD_CFG;
            DBG_EXIT
        }
        break;
    case CFG_REPLY :
        if (CFG_REQUEST != pxXg->oCfgType)
        {
            status = ERR_IKE_BAD_CFG;
            DBG_EXIT
        }
        break;
    default :
        status = ERR_IKE_BAD_CFG;
        DBG_EXIT
        break;
    }

    if (NULL == m_ikeSettings.funcPtrIkeRespCfg)
    {
        status = ERR_IKE_BAD_CFG;
        DBG_EXIT
    }

    debug_print_ike_cfg_attrs(ctx->pBuffer, wBodyLen, (sbyte *)"    ", FALSE);

    if (OK > (status = m_ikeSettings.funcPtrIkeRespCfg(
                                ctx->pBuffer, wBodyLen,
                                pxXg->wCfgId, pxSa->dwId, pxSa)))
        DBG_EXIT

#endif /* __ENABLE_IKE_MODE_CFG__ */

    /* done */
    IN_END

exit:
    return status;
} /* InCfg_I */


/*------------------------------------------------------------------*/

static MSTATUS
OutCfg(IKE_context ctx)
{
    MSTATUS status = OK;

    P2XG pxXg = ctx->pxP2Xg;
    ubyte2 wBodyLen = pxXg->wCfgAttrsLen;

    /* IKECFG payload header */
    OUT_BEGIN(struct ikeCfgHdr, pxCfgHdr, SIZEOF_IKE_CFG_HDR, ISAKMP_NEXT_ATTR)

    pxCfgHdr->oType = pxXg->oCfgType;
    SET_HTONS(pxCfgHdr->wIdentifier, pxXg->wCfgId);

    /* attributes */
    if (0 != wBodyLen)
    DIGI_MEMCPY(ctx->pBuffer, pxXg->poCfgAttrs, wBodyLen);

    /* done */
    OUT_END

exit:
    return status;
} /* OutCfg */


/*------------------------------------------------------------------*/

static MSTATUS
cfgI1_out(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  CFG Initiator -->");

    /* HASH(1) --> */
    DO_FUNC(OutHashGen)

    /* ATTR --> */
    DO_FUNC(OutCfg)

    /* HASH(1) data */
    DO_FUNC(OutHash12)

exit:
    return status;
} /* cfgI1_out */


/*------------------------------------------------------------------*/

static MSTATUS
cfgR1_in(IKE_context ctx)
{
    MSTATUS status = OK;

    debug_printnl("  --> CFG Responder");

    /* HASH(1) --> */
    IN_PAYLOAD(ISAKMP_NEXT_HASH, InHash12, ERR_IKE_BAD_HASH)

    /* ATTR --> */
    IN_PAYLOAD(ISAKMP_NEXT_ATTR, InCfg_R, ERR_IKE_BAD_ATTR)

    /* skip the rest */

exit:
    return status;
} /* cfgR1_in */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_IKE_XAUTH__

/* draft-ietf-ipsec-isakmp-xauth-01...04 (Message ID) */
static MSTATUS
cfgR_in(IKE_context ctx)
{
    MSTATUS status = OK;

    P2XG pxXg = ctx->pxP2Xg;

    debug_printnl("  --> CFG_AUTH Responder");

    /* HASH(1) --> */
    IN_PAYLOAD(ISAKMP_NEXT_HASH, InHash12, ERR_IKE_BAD_HASH)
        /* Note: If an error occurs here, then this message is probably a
           re-transmission, rather than a new exchange re-using the same
           message ID in a single 'configuration' as described in
           draft-ietf-ipsec-isakmp-xauth-01...04. Also See InCfg_R().
         */

    /* go back to starting state */
    pxXg->oState = STATE_CFG_R1; /* !!! */
    if (NULL != pxXg->poCfgAttrs) /* jic */
    {
        FREE(pxXg->poCfgAttrs);
        pxXg->poCfgAttrs = NULL;
        pxXg->wCfgAttrsLen = 0;
    }

    /* ATTR --> */
    IN_PAYLOAD(ISAKMP_NEXT_ATTR, InCfg_R, ERR_IKE_BAD_ATTR)

    /* skip the rest */

exit:
    return status;
} /* cfgR_in */


/*------------------------------------------------------------------*/

static MSTATUS
cfgI1x_out(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  CFG XAuth Initiator 1 -->");

    /* HASH(1) --> */
    DO_FUNC(OutHashGen)

    /* ATTR --> */
    DO_FUNC(OutCfg)

    /* HASH(1) data */
    DO_FUNC(OutHash12)

exit:
    return status;
} /* cfgI1x_out */


/*------------------------------------------------------------------*/

static MSTATUS
InCfg_I2x(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    P2XG pxXg = ctx->pxP2Xg;

    ubyte oCfgType;
    ubyte2 wCfgId;

    /* ATTR payload header */
    IN_BEGIN(struct ikeCfgHdr, pxCfgHdr, SIZEOF_IKE_CFG_HDR)
    oCfgType = pxCfgHdr->oType;
    wCfgId = pxXg->wCfgId;

    debug_print("   ");
    debug_print_ike_cfgtype(oCfgType);
    if (wCfgId)
    {
        debug_print(" #");
        debug_int(wCfgId);
    }
    debug_printnl(NULL);

    if (GET_NTOHS(pxCfgHdr->wIdentifier) != wCfgId)
    {
        DBG_ERRCODE(ERR_IKE_BAD_CFG) /* !!! */
/*      status = ERR_IKE_BAD_CFG;
        DBG_EXIT */
    }

    if (CFG_REPLY != oCfgType)
    {
        status = ERR_IKE_BAD_CFG;
        DBG_EXIT
    }

    debug_print_ike_cfg_attrs(ctx->pBuffer, wBodyLen, (sbyte *)"    ", TRUE);

    if (OK > (status = IKE_xauthProcessReply(ctx->pBuffer, wBodyLen,
                                             pxSa, pxXg)))
    {
        if (STATUS_IKE_PENDING == status)
        {
            goto exit;
        }
        DBG_EXIT
    }

    /* done */
    IN_END

exit:
    return status;
} /* InCfg_I2x */


/*------------------------------------------------------------------*/

static MSTATUS
cfgI2x_in(IKE_context ctx)
{
    MSTATUS status = OK;

    debug_printnl("  CFG XAuth Initiator 2 <--");

    /* <-- HASH(1) */
    IN_PAYLOAD(ISAKMP_NEXT_HASH, InHash12, ERR_IKE_BAD_HASH)

    /* <-- ATTR */
    IN_PAYLOAD(ISAKMP_NEXT_ATTR, InCfg_I2x, ERR_IKE_BAD_ATTR)

    /* skip the rest */

exit:
    return status;
} /* cfgI2x_in */


/*------------------------------------------------------------------*/

static MSTATUS
cfgI2x_out(IKE_context ctx)
{
    MSTATUS status;

    debug_printnl("  CFG XAuth Initiator 2 -->");

    /* HASH(1) --> */
    DO_FUNC(OutHashGen)

    /* ATTR --> */
    DO_FUNC(OutCfg)

    /* HASH(1) data */
    DO_FUNC(OutHash12)

exit:
    return status;
} /* cfgI12x_out */


/*------------------------------------------------------------------*/

static MSTATUS
InCfg_I3x(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    P2XG pxXg = ctx->pxP2Xg;

    ubyte oCfgType;

    /* ATTR payload header */
    IN_BEGIN(struct ikeCfgHdr, pxCfgHdr, SIZEOF_IKE_CFG_HDR)
    oCfgType = pxCfgHdr->oType;

    debug_print("   ");
    debug_print_ike_cfgtype(oCfgType);
    if (pxXg->wCfgId)
    {
        debug_print(" #");
        debug_int(pxXg->wCfgId);
    }
    debug_printnl(NULL);

    if (CFG_ACK != oCfgType)
    {
        status = ERR_IKE_BAD_CFG;
        DBG_EXIT
    }

    /* attributes are not relevant and MAY be skipped entirely */

    if (OK <= pxSa->merror) /* !!! */
        pxSa->flags &= ~(IKE_SA_FLAG_XAUTH);

    /* done */
    IN_END

exit:
    return status;
} /* InCfg_I3x */


/*------------------------------------------------------------------*/

static MSTATUS
cfgI3x_in(IKE_context ctx)
{
    MSTATUS status = OK;

    debug_printnl("  CFG XAuth Initiator 3 <--");

    /* <-- HASH(1) */
    IN_PAYLOAD(ISAKMP_NEXT_HASH, InHash12, ERR_IKE_BAD_HASH)

    /* <-- ATTR */
    IN_PAYLOAD(ISAKMP_NEXT_ATTR, InCfg_I3x, ERR_IKE_BAD_ATTR)

    /* skip the rest */

exit:
    return status;
} /* cfgI3x_in */

#endif /* __ENABLE_IKE_XAUTH__ */


/*------------------------------------------------------------------*/

static MSTATUS
cfgR1_out(IKE_context ctx)
{
    MSTATUS status = OK;

    debug_printnl("  <-- CFG Responder");

    /* <-- HASH(1) */
    DO_FUNC(OutHashGen)

    /* <-- ATTR */
    DO_FUNC(OutCfg)

    /* HASH(1) data */
    DO_FUNC(OutHash12)

exit:
    return status;
} /* cfgR1_out */


/*------------------------------------------------------------------*/

static MSTATUS
cfgI2_in(IKE_context ctx)
{
    MSTATUS status = OK;

    debug_printnl("  CFG Initiator <--");

    /* <-- HASH(1) */
    IN_PAYLOAD(ISAKMP_NEXT_HASH, InHash12, ERR_IKE_BAD_HASH)

    /* <-- ATTR */
    IN_PAYLOAD(ISAKMP_NEXT_ATTR, InCfg_I, ERR_IKE_BAD_ATTR)

    /* skip the rest */

exit:
    return status;
} /* cfgI2_in */

#endif /* defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__) */


/*------------------------------------------------------------------*/

static IKE_stateInfo finalIR    = {NULL,        NULL};

static IKE_stateInfo infoIO     = {info_in,     info_out};

static IKE_stateInfo mainI1     = {NULL,        mainI1_out};
static IKE_stateInfo mainI2     = {mainI2_in,   mainI2_out};
static IKE_stateInfo mainI3     = {mainI3_in,   mainI3_out};
static IKE_stateInfo mainI4     = {mainI4_in,   NULL};

static IKE_stateInfo mainR1     = {mainR1_in,   mainR1_out};
static IKE_stateInfo mainR2     = {mainR2_in,   mainR2_out};
static IKE_stateInfo mainR3     = {mainR3_in,   mainR3_out};

static IKE_stateInfo quickI1    = {NULL,        quickI1_out};
static IKE_stateInfo quickI2    = {quickI2_in,  quickI2_out};
static IKE_stateInfo quickI2c   = {quickI2c_in, NULL};

static IKE_stateInfo quickR1    = {quickR1_in,  quickR1_out};
static IKE_stateInfo quickR2    = {quickR2_in,  NULL};

static IKE_stateInfo rawO       = {NULL,        raw_out};

#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
static IKE_stateInfo aggrI1     = {NULL,        aggrI1_out};
static IKE_stateInfo aggrI2     = {aggrI2_in,   aggrI2_out};
static IKE_stateInfo aggrI2c    = {aggrI2c_in,  NULL};

static IKE_stateInfo aggrR1     = {aggrR1_in,   aggrR1_out};
static IKE_stateInfo aggrR2     = {aggrR2_in,   NULL};
#endif

#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__)
static IKE_stateInfo cfgR1      = {cfgR1_in,    cfgR1_out};
#ifdef __ENABLE_IKE_XAUTH__
/* draft-ietf-ipsec-isakmp-xauth-01...04 (Message ID) */
static IKE_stateInfo cfgR       = {cfgR_in,     NULL};

/* XAUTH server */
static IKE_stateInfo cfgI1x     = {NULL,        cfgI1x_out}; /* REQUEST User/Pwd */
static IKE_stateInfo cfgI2xc    = {cfgI2x_in,   NULL};       /* REPLY User/Pwd */
static IKE_stateInfo cfgI2x     = {NULL,        cfgI2x_out}; /* SET send AUTH result */
static IKE_stateInfo cfgI3x     = {cfgI3x_in,   NULL};       /* ACK recv AUTH result */
#endif
static IKE_stateInfo cfgI1      = {NULL,        cfgI1_out};
static IKE_stateInfo cfgI2      = {cfgI2_in,    NULL};
#endif

/* GDOI */
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
static IKE_stateInfo gpullI1    = {NULL,        gpullI1_out};
static IKE_stateInfo gpullI2    = {gpullI2_in,  gpullI2_out};
static IKE_stateInfo gpullI3    = {gpullI3_in,  NULL};

static IKE_stateInfo gpushR1    = {gpushR1_in,  NULL};
#endif

#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
static IKE_stateInfo gpullR1    = {gpullR1_in,  gpullR1_out};
static IKE_stateInfo gpullR2    = {gpullR2_in,  gpullR2_out};

static IKE_stateInfo gpushI1    = {NULL,        gpushI1_out};
#endif


/* Note: The following states MUST be in strict ascending order
   starting with STATE 0. (Also see "ike_state.h") */

IKE_stateInfo *m_StateInfo[] =
{
    &infoIO,    /* STATE_INFO */

    &mainI1,    /* STATE_MAIN_I1 */
    &mainI2,    /* STATE_MAIN_I2 */
    &mainI3,    /* STATE_MAIN_I3 */
    &mainI4,    /* STATE_MAIN_I4 */
    &finalIR,   /* STATE_MAIN_I */

    &mainR1,    /* STATE_MAIN_R1 */
    &mainR2,    /* STATE_MAIN_R2 */
    &mainR3,    /* STATE_MAIN_R3 */
    &finalIR,   /* STATE_MAIN_R */

    &quickI1,   /* STATE_QUICK_I1 */
    &quickI2,   /* STATE_QUICK_I2 */
    &quickI2c,  /* STATE_QUICK_I2c */
    &finalIR,   /* STATE_QUICK_I */

    &quickR1,   /* STATE_QUICK_R1 */
    &quickR2,   /* STATE_QUICK_R2 */
    &finalIR,   /* STATE_QUICK_R */

    &rawO,      /* STATE_RAW */

#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
    &aggrI1,    /* STATE_AGGR_I1 */
    &aggrI2,    /* STATE_AGGR_I2 */
    &aggrI2c,   /* STATE_AGGR_I2c */
    &finalIR,   /* STATE_AGGR_I */

    &aggrR1,    /* STATE_AGGR_R1 */
    &aggrR2,    /* STATE_AGGR_R2 */
    &finalIR,   /* STATE_AGGR_R */
#endif

#if defined(__ENABLE_IKE_MODE_CFG__) || defined(__ENABLE_IKE_XAUTH__)
    &cfgR1,     /* STATE_CFG_R1 */
#ifndef __ENABLE_IKE_XAUTH__
    &finalIR,   /* STATE_CFG_R */
#else
    /* draft-ietf-ipsec-isakmp-xauth-01...04 (Message ID) */
    &cfgR,      /* STATE_CFG_R */
#endif
    &cfgI1,     /* STATE_CFG_I1 */
    &cfgI2,     /* STATE_CFG_I2 */
    &finalIR,   /* STATE_CFG_I */

#ifdef __ENABLE_IKE_XAUTH__
    /* draft-ietf-ipsec-isakmp-xauth-01...02 (CFG_AUTH_OK/FAILED) */
    &finalIR,   /* STATE_CFG_R1x */
    &finalIR,   /* STATE_CFG_Rx */

    /* XAUTH server REQUEST/REPLY */
    &cfgI1x,    /* STATE_CFG_I1x */
    &cfgI2xc,   /* STATE_CFG_I2xc */
    &finalIR,   /* STATE_CFG_Ixc */

    /* XAUTH server SET/ACK */
    &cfgI2x,    /* STATE_CFG_I2x */
    &cfgI3x,    /* STATE_CFG_I3x */
    &finalIR,   /* STATE_CFG_Ix */
#endif
#endif

#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    &gpullI1,   /* STATE_GPULL_I1 */
    &gpullI2,   /* STATE_GPULL_I2 */
    &gpullI3,   /* STATE_GPULL_I3 */
    &finalIR,   /* STATE_GPULL_I */
#endif
#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
    &gpullR1,   /* STATE_GPULL_R1 */
    &gpullR2,   /* STATE_GPULL_R2 */
    &finalIR,   /* STATE_GPULL_R */
#endif

#ifdef __ENABLE_DIGICERT_GDOI_SERVER__
    &gpushI1,   /* STATE_GPUSH_I1 */
    &finalIR,   /* STATE_GPUSH_I */
#endif
#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__
    &gpushR1,   /* STATE_GPUSH_R1 */
    &finalIR,   /* STATE_GPUSH_R */
#endif

};


#else
static void
dummy(void)
{
    return;
}
#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */
