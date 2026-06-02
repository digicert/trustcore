/**
 * @file  ike_cert.c
 * @brief IKE certificate processing.
 *
 * @details    IKEv1 certificate validation and processing functions.
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
#include "../crypto/secmod.h"
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
#include "../crypto/rsa.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/ca_mgmt.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/cryptointerface.h"
#endif
#endif
#include "../crypto/pubcrypto.h"
#include "../crypto/ca_mgmt.h"
#ifdef __ENABLE_DIGICERT_ASYM_KEY__
#include "../crypto/mocasym.h"
#endif
#include "../harness/harness.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/tree.h"
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"
#include "../crypto/cert_store.h"
#include "../crypto/cert_chain.h"
#include "../ipsec/ipsec.h"
#include "../ipsec/ipseckey.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ikesa.h"
#include "../ike/ike_state.h"
#include "../ike/ike_utils.h"
#include "../ike/ike_cert.h"
#include "../ike/ike_crypto.h"


/*------------------------------------------------------------------*/

MOC_EXTERN_DATA_DECL moctime_t gStartTime;
extern ikeSettings m_ikeSettings;


/*------------------------------------------------------------------*/

#define _I 0
#define _R 1

#define _IN  1
#define _OUT 2

#define DBG_ERRCODE(_s) debug_print_status((sbyte *)__FILE__, __LINE__, (sbyte4)(_s));
#define DBG_STATUS      DBG_ERRCODE(status)
#define DBG_EXIT        { DBG_STATUS goto exit; }

#define CHECK_MALLOC_PTR(_t, _p, _s) \
    if (NULL == ((_p) = (_t *) MALLOC(_s))) \
    { \
        status = ERR_MEM_ALLOC_FAIL; \
        DBG_EXIT \
    } \

#define CHECK_MALLOC(p, s) CHECK_MALLOC_PTR(ubyte, p, s)
#define CHECK_FREE(p) if (NULL != (p)) { FREE(p); (p) = NULL; }


/*------------------------------------------------------------------*/

typedef struct ikecert_id
{
    ubyte4 dwTimeAccessed;

    MOC_IP_ADDRESS_S dwPeerAddr;
#ifdef __IKE_MULTI_HOMING__
    sbyte4 serverInstance;
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
    ubyte2 wPeerPort;
    ubyte2 wPeerNatPort;
#endif
    ubyte poIdHash[MD5_DIGESTSIZE];

    AsymmetricKey *pKey;

} *IKECERT_ID;


static struct ikecert_id m_ikeCertId[IKE_CERT_CACHE_MAX] = { { 0 } };
static sbyte4 m_ikeCertIdNum = 0;


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_initCertCache(void)
{
    MSTATUS status = OK;

    if (m_ikeCertIdNum) IKE_flushCertCache();
    m_ikeCertIdNum = IKE_CERT_CACHE_MAX;

    return status;
} /* IKE_initCertCache */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_flushCertCache(void)
{
    MSTATUS status = OK;

    sbyte4 i;
    for (i=0; i < m_ikeCertIdNum; i++)
    {
        AsymmetricKey *pKey = m_ikeCertId[i].pKey;
        if (NULL != pKey)
        {
            CRYPTO_uninitAsymmetricKey(pKey, NULL);
            FREE(pKey);
        }
    }
    DIGI_MEMSET((ubyte *)m_ikeCertId, 0x00, m_ikeCertIdNum * sizeof(struct ikecert_id));
    m_ikeCertIdNum = 0;

    return status;
} /* IKE_flushCertCache */


/*------------------------------------------------------------------*/

#ifndef __IKE_MULTI_THREADED__
static MSTATUS
IKE_getCertId(IKE_context ctx, ubyte *poIdHash, IKECERT_ID *ppxIkeCertId)
{
    MSTATUS status = ERR_IKE_NO_CERT;

    sbyte4 i;

    IKESA pxSa = ctx->pxSa;
    INIT_MOC_IPADDR(dwPeerAddr, pxSa->dwPeerAddr)

#ifdef __IKE_MULTI_HOMING__
    sbyte4 serverInstance = pxSa->serverInstance;
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
    ubyte2 wPeerPort = pxSa->wPeerPort;
    ubyte2 wPeerNatPort;

    if (USE_NATT_PORT(pxSa))
    {
        wPeerNatPort = wPeerPort;

        if (ctx->wPeerPort && (wPeerPort != ctx->wPeerPort))
        {
            wPeerPort = ctx->wPeerPort;
        }
        else if (IKE_NAT_UDP_PORT == wPeerPort)
        {
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
            if (IKE_SA_FLAG_GDOI & pxSa->flags)
                wPeerPort = IKE_GDOI_UDP_PORT;
            else
#endif
            wPeerPort = IKE_DEFAULT_UDP_PORT;
        }
        else
        {
            wPeerPort = 0;
        }
    }
#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)
    else if (IKE_SA_FLAG_GDOI & pxSa->flags)
    {
        if (IKE_GDOI_UDP_PORT == wPeerPort)
            wPeerNatPort = IKE_NAT_UDP_PORT;
        else
            wPeerNatPort = 0;
    }
#endif
    else
    {
        if (IKE_DEFAULT_UDP_PORT == wPeerPort)
            wPeerNatPort = IKE_NAT_UDP_PORT;
        else
            wPeerNatPort = 0;
    }
#endif /* __ENABLE_IPSEC_NAT_T__ */

    for (i=0; i < m_ikeCertIdNum; i++)
    {
        IKECERT_ID pxIkeCertId = &(m_ikeCertId[i]);

        if (SAME_MOC_IPADDR(dwPeerAddr, pxIkeCertId->dwPeerAddr))
#ifdef __IKE_MULTI_HOMING__
        if (serverInstance == pxIkeCertId->serverInstance)
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
        if ((wPeerPort && (wPeerPort == pxIkeCertId->wPeerPort)) ||
            (wPeerNatPort && (wPeerNatPort == pxIkeCertId->wPeerNatPort)))
#endif
        {
            /* found */
            if (NULL != poIdHash) /* check ID, if present */
            {
                sbyte4 result;
                if (OK > (status = DIGI_MEMCMP(poIdHash, pxIkeCertId->poIdHash,
                                              MD5_DIGESTSIZE, &result)))
                    break;

                if (0 != result)
                {
                    status = ERR_IKE_BAD_ID;
                    break;
                }
            }
            *ppxIkeCertId = pxIkeCertId;
            status = OK;
            break;
        }
    } /* for */

    return status;
} /* IKE_getCertId */
#endif


/*------------------------------------------------------------------*/

extern void
IKE_certAssign(IKE_context ctx, ubyte *poIdHash, AsymmetricKey *pKey)
{
#ifdef __IKE_MULTI_THREADED__
    MOC_UNUSED(ctx);
    MOC_UNUSED(poIdHash);
    MOC_UNUSED(pKey);
#else
    IKESA pxSa = ctx->pxSa;
    ubyte4 timenow = RTOS_deltaMS(&gStartTime, NULL);

    IKECERT_ID pxIkeCertId = NULL;

    /* find existing */
    if (OK > IKE_getCertId(ctx, NULL, &pxIkeCertId))
    {
        /* find unused */
        sbyte4 i;
        for (i=0; i < m_ikeCertIdNum; i++, pxIkeCertId = NULL)
        {
            pxIkeCertId = &(m_ikeCertId[i]);
            if (ISZERO_MOC_IPADDR(pxIkeCertId->dwPeerAddr))
                break;
        }

        if (NULL == pxIkeCertId)
        {
            /* find by access time */
            for (i=0; i < m_ikeCertIdNum; i++)
            {
                IKECERT_ID pxIkeCertIdTmp = &(m_ikeCertId[i]);
                if ((NULL == pxIkeCertId) ||
                    ((timenow - pxIkeCertId->dwTimeAccessed) <
                     (timenow - pxIkeCertIdTmp->dwTimeAccessed)))
                {
                    pxIkeCertId = pxIkeCertIdTmp;
                }
            }

            if (NULL == pxIkeCertId) /* redundant? */
                goto exit;
        }

        /* initialize */
        pxIkeCertId->dwPeerAddr = pxSa->dwPeerAddr;

#ifdef __IKE_MULTI_HOMING__
        pxIkeCertId->serverInstance = pxSa->serverInstance;
#endif
#ifdef __ENABLE_IPSEC_NAT_T__
        pxIkeCertId->wPeerPort = 0;
        pxIkeCertId->wPeerNatPort = 0;
    }

    if (USE_NATT_PORT(pxSa))
    {
        if (ctx->wPeerPort && (ctx->wPeerPort != pxSa->wPeerPort))
            pxIkeCertId->wPeerPort = ctx->wPeerPort;
        pxIkeCertId->wPeerNatPort = pxSa->wPeerPort;
    }
    else
    {
        pxIkeCertId->wPeerPort = pxSa->wPeerPort;
#endif /* __ENABLE_IPSEC_NAT_T__ */
    }

    DIGI_MEMCPY(pxIkeCertId->poIdHash, poIdHash, MD5_DIGESTSIZE);

    /* free old public key */
    if (NULL != pxIkeCertId->pKey)
    {
        CRYPTO_uninitAsymmetricKey(pxIkeCertId->pKey, NULL);
        FREE(pxIkeCertId->pKey);
        /*pxIkeCertId->pKey = NULL;*/
    }

    /* store public key */
    pxIkeCertId->pKey = pKey;
    pKey = NULL;

    /* done */
    pxIkeCertId->dwTimeAccessed = timenow;

exit:
    if (NULL != pKey) /* jic */
    {
        CRYPTO_uninitAsymmetricKey(pKey, NULL);
        FREE(pKey);
    }
#endif
    return;
} /* IKE_certAssign */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_certLookup(IKE_context ctx, ubyte *poIdHash, struct AsymmetricKey **ppKey)
{
    MSTATUS status;

#ifdef __IKE_MULTI_THREADED__
    MOC_UNUSED(ctx);
    MOC_UNUSED(poIdHash);
    MOC_UNUSED(ppKey);

    status = ERR_IKE_NO_CERT;
#else
    IKECERT_ID pxIkeCertId;
    if (OK > (status = IKE_getCertId(ctx, poIdHash, &pxIkeCertId)))
        goto exit;

    pxIkeCertId->dwTimeAccessed = RTOS_deltaMS(&gStartTime, NULL);

    if (ppKey)
        *ppKey = pxIkeCertId->pKey;

exit:
#endif
    return status;
} /* IKE_certLookup */


/*------------------------------------------------------------------*/

extern void
IKE_certUnbind(IKE_context ctx)
{
#ifdef __IKE_MULTI_THREADED__
    MOC_UNUSED(ctx);
#else
    IKECERT_ID pxIkeCertId;
    if (OK > IKE_getCertId(ctx, NULL, &pxIkeCertId))
        return;

    ZERO_MOC_IPADDR(pxIkeCertId->dwPeerAddr);

    if (NULL != pxIkeCertId->pKey)
    {
        CRYPTO_uninitAsymmetricKey(pxIkeCertId->pKey, NULL);
        FREE(pxIkeCertId->pKey);
        pxIkeCertId->pKey = NULL;
    }
#endif
    return;
} /* IKE_certUnbind */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_certGetKey(IKE_context ctx, AsymmetricKey **ppKey)
{
    MSTATUS status = OK;

    certStorePtr pCertStore;
    ubyte4 num, i;
    certDescriptor *certDesc;
    AsymmetricKey *pKey = NULL;
    certChainPtr pCertChain = NULL;
    intBoolean isComplete = FALSE;
    ValidationConfig vc = { 0 };
    TimeDate td;

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (1 > ctx->certNum)
    {
        status = ERR_IKE_NO_CERT;
        goto exit;
    }

    if (NULL == (pCertStore = ctx->pxSa->ikePeerConfig->ikeCertStore))
    {
#ifdef __ENABLE_ALL_DEBUGGING__
        DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"    No CERT_STORE found!");
#endif
        status = ERR_IKE_NO_CERT;
        goto exit;
    }

    num = (ubyte4) ctx->certNum;
    certDesc = ctx->certificates;

#ifdef __ENABLE_DIGICERT_IKE_REF_IDENTIFIER_MATCH__
    if(m_ikeSettings.ikePeerHost != NULL)
    {
        vc.commonName = (sbyte *)m_ikeSettings.ikePeerHost;
        DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"    Common Name in Validation config is set to ");
        DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)vc.commonName);
    }
#endif

    /* verify leaf certificate */
    if (m_ikeSettings.funcPtrCertificateLeafTest &&
        (OK > (status = m_ikeSettings.funcPtrCertificateLeafTest(
                                            ctx->pxSa->serverInstance,
                                            ctx->pxSa,
                                            certDesc[0].pCertificate,
                                            certDesc[0].certLength))))
    {
        goto exit;
    }

    // TODO: rearrange non-leaf certificates (to correct chain order)

    /* For CA certificate(s), check the following:
          cA bit in BasicConstraints extension
          keyCertSign (5) bit in KU extension
       See RFC5280, 4.2.1.3 & 6.1.4 (k)(l)(n)
     */

    /* validate the certificate chain w/o policy or store */
    if (OK > (status = CERTCHAIN_createFromIKE(MOC_RSA(ctx->hwAccelCookie)
                                               &pCertChain, certDesc, num)))
    {
        DEBUG_ERROR(DEBUG_IKE_MESSAGES, "CERTCHAIN_createFromIKE() failed, status = ", status);
        goto exit;
    }

    if (OK > (status = CERTCHAIN_isComplete(pCertChain, &isComplete)))
    {
        goto exit;
    }

    /* verify non-root & non-leaf certificate(s) */
    if (m_ikeSettings.funcPtrCertificateChainTest)
    {
        for (i=1; i < num; i++) /* skip leaf certificate */
        {
            if (((i+1) == num) && isComplete) /* skip root certificate */
            {
                break;
            }

            if (OK > (status = m_ikeSettings.funcPtrCertificateChainTest(
                                            ctx->pxSa->serverInstance,
                                            certDesc[i].pCertificate,
                                            certDesc[i].certLength)))
            {
                goto exit;
            }
        }
    }

    /* verify root certificate, if any */
    if (isComplete && (1 < num) &&
        m_ikeSettings.funcPtrCertificateRootTest &&
        (OK > (status = m_ikeSettings.funcPtrCertificateRootTest(
                                            ctx->pxSa->serverInstance,
                                            certDesc[num-1].pCertificate,
                                            certDesc[num-1].certLength))))
    {
        goto exit;
    }

    /* verify KU extension (leaf certificate); see RFC4945 5.1.3.2 */
    vc.keyUsage = (1 << digitalSignature);

    if (OK > (status = CERTCHAIN_validate(MOC_RSA(ctx->hwAccelCookie) pCertChain, &vc)))
    {
        if (ERR_CERT_INVALID_KEYUSAGE == status)
        {
            vc.keyUsage = (1 << nonRepudiation);

            if (OK > (status = CERTCHAIN_validate(MOC_RSA(ctx->hwAccelCookie)
                                                  pCertChain, &vc)))
            {
                goto exit;
            }
        }
        else
        {
            goto exit;
        }
    }
    vc.keyUsage = 0;

    /* validate date & verify cert store */
    RTOS_timeGMT(&td);
    vc.td = &td;
    vc.pCertStore = pCertStore;

    if (OK > (status = CERTCHAIN_validate(MOC_RSA(ctx->hwAccelCookie) pCertChain, &vc)))
    {
        goto exit;
    }

    /* verify trust anchor from cert store, if any */
    if (vc.anchorCert &&
        m_ikeSettings.funcPtrCertificateAnchorTest &&
        (OK > (status = m_ikeSettings.funcPtrCertificateAnchorTest(
                                                    ctx->pxSa->serverInstance,
                                                    (ubyte*)vc.anchorCert,
                                                    vc.anchorCertLen))))
    {
        goto exit;
    }

    /* extract public key */
    if (NULL == (pKey = (AsymmetricKey *) MALLOC(sizeof(struct AsymmetricKey))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMSET((ubyte *)pKey, 0x00, sizeof(struct AsymmetricKey));

    if (OK > (status = CERTCHAIN_getKey(MOC_RSA(ctx->hwAccelCookie) pCertChain, 0, pKey)))
    {
        goto exit;
    }

    if (ppKey) *ppKey = pKey;
    pKey = NULL;

#ifdef __ENABLE_IKE_OCSP_EXT__
    if (vc.anchorCert &&
        IS_IKE2_SA(ctx->pxSa) &&
        (IKE_SA_FLAG_CERT_OCSP & ctx->pxSa->flags))
    {
        ctx->certNum++;
        certDesc[num].pCertificate = vc.anchorCert;
        certDesc[num].certLength = vc.anchorCertLen;
    }
#endif

exit:
    if (NULL != pKey)
    {
        CRYPTO_uninitAsymmetricKey(pKey, NULL);
        FREE(pKey);
    }

    CERTCHAIN_delete(&pCertChain);

    return status;
} /* IKE_certGetKey */


/*------------------------------------------------------------------*/

extern void
IKE_certUnsetChain(IKE_certDescr pCertChain, sbyte4 certChainLen)
{
    sbyte4 i;
    for (i=0; i < certChainLen; i ++)
    {
        IKE_certDescr pxCertDesc = pCertChain + i;

        AsymmetricKey *pxPrivKey = pxCertDesc->pxPrivKey;
        if (NULL != pxPrivKey)
        {
            CRYPTO_uninitAsymmetricKey(pxPrivKey, NULL);
            FREE(pxPrivKey);
        }

        if (NULL != pxCertDesc->poCertificate)
            FREE(pxCertDesc->poCertificate);

        if (NULL != pxCertDesc->poPubKeyHash)
            FREE(pxCertDesc->poPubKeyHash);

        DIGI_MEMSET((ubyte *)pxCertDesc, 0x00, sizeof(struct ikeCertDescr));
    }

    return;
} /* IKE_certUnsetChain */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_certSetChain(MOC_HASH(hwAccelDescr hwAccelCtx)
                 certDescriptor certificates[], sbyte4 certNum,
                 IKE_certDescr pCertChain, sbyte4 *pCertChainLen,
                 ikePeerConfig *config,
                 intBoolean bCopy, intBoolean bPrivate)
{
    MSTATUS status = OK;

    sbyte4 i = 0;
    sbyte4 cmp;
    ubyte *pDerCert = NULL;
    ubyte4 derCertLen;

    ASN1_ITEMPTR pxCertRoot = NULL;
    AsymmetricKey *pxPrivKey = NULL;
    ubyte *poKeyInfoHash = NULL; /* [v2] */

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    ubyte *poKIHash = NULL; /* [v2] */

    if ((1 < certNum) &&
        (OK > (status = CRYPTO_ALLOC(hwAccelCtx, SHA1_RESULT_SIZE,
                                     TRUE, (void**) &poKIHash))))
    {
        DBG_STATUS
        goto nocleanup;
    }
#endif

    /* traverse certificate chain */
    for (; i < certNum; i++)
    {
        certDescriptor *pCertificateDescr = &certificates[i];
        IKE_certDescr pxCertDesc = pCertChain + i;

        MemFile mf;
        CStream cs;

        ASN1_ITEMPTR pxCertSubj;

        ubyte2 wAuthMtd = 0; /* [v1] */
        ubyte oAuthMtd = 0;  /* [v2] */
        ubyte oSigAlgo = 0;  /* [v2] RSA */

        ubyte4 keyType = 0;

        /* sanity-check */
        if (NULL == pCertificateDescr->pCertificate)
        {
            DBG_ERRCODE(ERR_IKE_NO_CERT)
            break; /* stop!!! */
        }

        if ((NULL == config->funcPtrSignHash) && (NULL == pCertificateDescr->pKeyBlob) && (0==i) && bPrivate)
        {
            DBG_ERRCODE(ERR_IKE_BAD_CERT)
            break; /* stop!!! */
        }

        cmp = -1;
        status = DIGI_MEMCMP((const ubyte *) certificates[i].pCertificate,(const ubyte *) "-----BEGIN CERTIFICATE-----", 27, &cmp);
        if (OK != status)
            goto exit;

        if ((0 == cmp) && (OK == CA_MGMT_decodeCertificate(certificates[i].pCertificate,
            certificates[i].certLength, &pDerCert, &derCertLen)))
        {
            DIGI_FREE((void **) &certificates[i].pCertificate);
            certificates[i].pCertificate = pDerCert;
            certificates[i].certLength = derCertLen;
            pDerCert = NULL;
        }

#ifdef __ENABLE_DIGICERT_PQC__
        if (0x10000 < pCertificateDescr->certLength)
#else
        if (0x4000 < pCertificateDescr->certLength)
#endif
        {
            status = ERR_IKE_BAD_CERT; /*ERR_SSL_INVALID_CERT_LENGTH*/
            DBG_EXIT
        }

        /* parse the certificate */
        MF_attach(&mf, (sbyte4) pCertificateDescr->certLength,
                  pCertificateDescr->pCertificate);
        CS_AttachMemFile(&cs, &mf);

        if (OK > (status = X509_parseCertificate(cs, &pxCertRoot)))
            DBG_EXIT

        /* get certificate subject (i.e. Distinguished Name) */
        if (OK > (status = X509_getCertificateSubject(ASN1_FIRST_CHILD(pxCertRoot), &pxCertSubj)))
            DBG_EXIT

        if (0==i) /* leaf */
        {
            if (bPrivate) /* get private key */
            {
#ifdef __ENABLE_DIGICERT_ECC__
                ubyte4 ht, akt;
                ASN1_ITEMPTR pSignatureAlgo = NULL;
#endif
                if (NULL == pCertificateDescr->pKeyBlob)
                {
                    if (NULL != config->funcPtrGetKeyTypeFromCertificate)
                    {

                        status = (MSTATUS)config->funcPtrGetKeyTypeFromCertificate(
                            pCertificateDescr->pCertificate, pCertificateDescr->certLength,
                            &keyType);
                        if (OK != status)
                            DBG_EXIT


                    }
                    goto rsasig_algo;
                }

                CHECK_MALLOC_PTR(AsymmetricKey, pxPrivKey, sizeof(AsymmetricKey))
                CRYPTO_initAsymmetricKey(pxPrivKey);

                status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx)
                    pCertificateDescr->pKeyBlob, pCertificateDescr->keyBlobLength,
                    NULL, pxPrivKey);
                if (OK != status)
                    goto exit;

#ifdef __ENABLE_DIGICERT_ECC__
                if ((akt_ecc == (pxPrivKey->type & 0xff)) ||
                    (akt_ecc_ed == (pxPrivKey->type & 0xff))
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                 || akt_tap_ecc == pxPrivKey->type
#endif
                    )
                {
                    /* get auth method [v2] */
                    sbyte4 j;
                    ubyte4 curveId = 0;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                    status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pxPrivKey->key.pECC, &curveId);
                    if (OK != status)
                        DBG_EXIT
#else
                    status = EC_getCurveIdFromKey(pxPrivKey->key.pECC, &curveId);
                    if (OK != status)
                        DBG_EXIT
#endif
                    for (j=0; ; j++)
                    {
                        IKE_authMtdInfo *pAuthMtd;
                        if (NULL == (pAuthMtd = IKE_getAuthMtdEx(config, j)))
                        {
                            wAuthMtd = OAKLEY_ECDSA_SIG; /* !!! */
                            break;
                        }

                        if ((0 < pAuthMtd->curveId) && (curveId == pAuthMtd->curveId)
#ifdef __ENABLE_DIGICERT_PQC__
                            && (0 == pAuthMtd->qsAlgoId)
#endif
                            )
                        {
                            wAuthMtd = pAuthMtd->wAuthMtd;
                            oAuthMtd = pAuthMtd->oAuthMtd;
                            break;
                        }
                    }
                }
                else
#endif
#ifdef __ENABLE_DIGICERT_PQC__
                if (akt_hybrid == pxPrivKey->type)
                {
                    sbyte4 j;
                    ubyte4 curveId = 0;
                    ubyte4 qsAlgoId = 0;

                    status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pxPrivKey->key.pECC, &curveId);
                    if (OK != status)
                        DBG_EXIT

                    status = CRYPTO_INTERFACE_QS_getAlg(pxPrivKey->pQsCtx, &qsAlgoId);
                    if (OK != status)
                        DBG_EXIT

                    for (j=0; ; j++)
                    {
                        IKE_authMtdInfo *pAuthMtd;
                        if (NULL == (pAuthMtd = IKE_getAuthMtdEx(config, j)))
                        {
                            wAuthMtd = 0; /* should this be an error condition? */
                            break;
                        }

                        if (((0 < pAuthMtd->curveId) && (curveId == pAuthMtd->curveId)) &&
                            ((0 < pAuthMtd->qsAlgoId) && (qsAlgoId == pAuthMtd->qsAlgoId)))
                        {
                            wAuthMtd = pAuthMtd->wAuthMtd;
                            oAuthMtd = pAuthMtd->oAuthMtd;
                            break;
                        }
                    }
                }
                else
#endif
                {
rsasig_algo:
                    /* get RSA signature hash algorithm [v2] */
#ifdef __ENABLE_DIGICERT_ECC__
                    /* algo id is the second child of signed */
                    if (OK > (status = ASN1_GetNthChild(ASN1_FIRST_CHILD(pxCertRoot),
                                                        2, &pSignatureAlgo)))
                        DBG_EXIT

                    if (OK > (status = X509_getCertSignAlgoType(pSignatureAlgo,
                                                                cs, &ht, &akt)))
                        DBG_EXIT

                    oSigAlgo = (ubyte)ht;
#else
                    if (OK > (status = X509_getRSASignatureAlgo(ASN1_FIRST_CHILD(pxCertRoot), cs,
                                                                &oSigAlgo)))
                    {
                        /* Signature Algorithm could be ecdsa-with-SHAxxx
                           when Public Key Algorithm is rsaEncryption */
                        DBG_STATUS
                        status = OK;
                        oSigAlgo = sha1withRSAEncryption; /* for now */
                    }
#endif
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                    /* check that pxPrivKey is not NULL before accessing element */
                    if ((NULL != pxPrivKey) && (akt_tap_rsa == pxPrivKey->type))
                    {
                        /* for now, only SHA256 is supported for TAP Key signing */
                        oSigAlgo = sha256withRSAEncryption;
                    }
#endif

#ifdef __ENABLE_DIGICERT_ECC__
                    if (((NULL != pxPrivKey) && (akt_ecc == (pxPrivKey->type & 0xff))) || (akt_ecc == (keyType & 0xff)))
                    {
                        switch (ht)
                        {
#ifndef __DISABLE_DIGICERT_SHA256__
                            case ht_sha256:
                                wAuthMtd = OAKLEY_ECDSA_256;
                                oAuthMtd = AUTH_MTD_ECDSA_256;
                                break;
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
                            case ht_sha384:
                                wAuthMtd = OAKLEY_ECDSA_384;
                                oAuthMtd = AUTH_MTD_ECDSA_384;
                                break;
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
                            case ht_sha512:
                                wAuthMtd = OAKLEY_ECDSA_521;
                                oAuthMtd = AUTH_MTD_ECDSA_521;
                                break;
#endif
                        }
                    }
                    else if (((NULL != pxPrivKey) && (akt_ecc_ed == (pxPrivKey->type & 0xff))) || (akt_ecc_ed == (keyType & 0xff)))
                    {
                                wAuthMtd = AUTH_MTD_SIG;
                                oAuthMtd = AUTH_MTD_SIG;
                    }
                    else
#endif
                    {
                        wAuthMtd = OAKLEY_RSA_SIG;
                        oAuthMtd = AUTH_MTD_RSA_SIG;
                    }
                }
            }
        }

        /* get certificate Subject Public Key Info [v2] */
        else
        {
            ASN1_ITEMPTR pxCertKey = ASN1_NEXT_SIBLING(pxCertSubj);
            ubyte4 keyInfoLen = pxCertKey->length + pxCertKey->headerSize;
            ubyte *poKeyInfo = pCertificateDescr->pCertificate +
                              (pxCertKey->dataOffset - pxCertKey->headerSize);

            CHECK_MALLOC(poKeyInfoHash, SHA1_RESULT_SIZE)

#if !(defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__))
            #define poKIHash poKeyInfoHash
#endif
            if (OK > (status = SHA1_completeDigest(MOC_HASH(hwAccelCtx)
                                                   poKeyInfo, keyInfoLen,
                                                   poKIHash)))
                DBG_EXIT

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
            DIGI_MEMCPY(poKeyInfoHash, poKIHash, SHA1_RESULT_SIZE);
#endif
        }

        /* store certificate */
        if (bCopy)
        {
            CHECK_MALLOC(pxCertDesc->poCertificate,
                         pCertificateDescr->certLength)
            DIGI_MEMCPY(pxCertDesc->poCertificate, pCertificateDescr->pCertificate,
                       pCertificateDescr->certLength);
        }
        else
        {
            pxCertDesc->poCertificate = pCertificateDescr->pCertificate;
            pCertificateDescr->pCertificate = NULL; /* !!! */
        }
        pxCertDesc->wCertLen = (ubyte2) pCertificateDescr->certLength;

        /* remember subject (DN) */
        pxCertDesc->wSubjLen = (ubyte2)
                            (pxCertSubj->length + pxCertSubj->headerSize);
        pxCertDesc->poSubject = pxCertDesc->poCertificate +
                            (pxCertSubj->dataOffset - pxCertSubj->headerSize);

        /* misc */
        pxCertDesc->wAuthMtd = wAuthMtd;
        pxCertDesc->oAuthMtd = oAuthMtd;
        pxCertDesc->oSigAlgo = oSigAlgo;

        pxCertDesc->pxPrivKey = pxPrivKey;
        if (NULL != pxPrivKey)
            pxPrivKey = NULL; /* !!! */

        pxCertDesc->poPubKeyHash = poKeyInfoHash;
        if (NULL != poKeyInfoHash)
            poKeyInfoHash = NULL; /* !!! */

        TREE_DeleteTreeItem((TreeItem *)pxCertRoot);
        pxCertRoot = NULL;
    } /* for */

    if (NULL != pCertChainLen)
        *pCertChainLen = i;

exit:
    if (OK > status)
        IKE_certUnsetChain(pCertChain, i);

    if (NULL != pxPrivKey)
    {
        CRYPTO_uninitAsymmetricKey(pxPrivKey, NULL);
        FREE(pxPrivKey);
    }

    if (NULL != pxCertRoot)
        TREE_DeleteTreeItem((TreeItem *)pxCertRoot);

    CHECK_FREE(poKeyInfoHash)

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    if (NULL != poKIHash)
        CRYPTO_FREE(hwAccelCtx, TRUE, (void**) &poKIHash);

nocleanup:
#endif
    return status;
} /* IKE_certSetChain */


/*------------------------------------------------------------------*/

#ifdef CUSTOM_IKE_CHECK_ID
static intBoolean
CheckCertIdPayload(struct ikeIdHdr *pxID, IKE_certDescr pxCertDesc)
{
    intBoolean ok = FALSE;

    sbyte4 idType = pxID->oType;
    const ubyte *poIdData = (ubyte *)pxID + SIZEOF_IKE_ID_HDR;
    ubyte2 wIdDataLen = GET_NTOHS(pxID->wLength) - (ubyte2)SIZEOF_IKE_ID_HDR;

    sbyte4 result;

    if (ID_DER_ASN1_DN != idType)
        goto exit; /* for now */

    if (wIdDataLen != pxCertDesc->wSubjLen)
        goto exit;

    if (OK > DIGI_MEMCMP(poIdData, pxCertDesc->poSubject, wIdDataLen, &result))
        goto exit; /* jic */

    if (0 == result)
        ok = TRUE;

exit:
    return ok;
} /* CheckCertIdPayload */
#endif


/*------------------------------------------------------------------*/

#ifdef CUSTOM_IKE_CHECK_ID

static intBoolean
CheckCertCustomId(IKESA pxSa, IKE_certDescr pxCertDesc)
{
    intBoolean ok = FALSE;

    intBoolean bInitiator = IS_INITIATOR(pxSa);

    sbyte4 idType;
    ubyte2 wIdDataLen;
    const ubyte *poIdData;

    idType = ID_DER_ASN1_DN;
    poIdData = pxCertDesc->poSubject;
    wIdDataLen = pxCertDesc->wSubjLen;

    if (OK > CUSTOM_IKE_CHECK_ID(poIdData, wIdDataLen, idType,
                            REF_MOC_IPADDR(pxSa->dwPeerAddr),
                            _OUT, bInitiator
                            MOC_MTHM_REQ_VALUE(pxSa->serverInstance)))
    {
        goto exit;
    }

    pxCertDesc->oIdType = (ubyte)idType;

    ok = TRUE;

exit:
    return ok;
} /* CheckCertCustomId */

#endif


/*------------------------------------------------------------------*/

#ifdef CUSTOM_IKE_USE_CERT

static MSTATUS
UseCustomCert(IKE_context ctx)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    intBoolean bInitiator = IS_INITIATOR(pxSa);

    sbyte4 dir = (bInitiator ? _I : _R);
    struct ikeIdHdr *pxID = pxSa->pxID[dir]; /* host ID */

    sbyte4 idType = 0;
    ubyte2 wIdDataLen = 0;
    const ubyte *poIdData = NULL;

    certDescriptor certificates[IKE_CERT_CHAIN_MAX] = { {NULL} };
    sbyte4 certNum = IKE_CERT_CHAIN_MAX;
    intBoolean bKeyOnly = FALSE;

    sbyte4 certChainLen = 0;
    IKE_certDescr pCertChain = NULL;

    /* get CR, if applicable */
    if (IS_IKE2_SA(pxSa) /* [v2] */
#ifdef __ENABLE_IKE_AGGRESSIVE_MODE__
        || (STATE_AGGR_R1 == pxSa->oState) /* [v1] aggr responder */
#endif
        )
    {
        if (!(IKE_SA_FLAG_CR & pxSa->flags))
        {
            /* certificate not requested */
            certNum = 1;
            bKeyOnly = TRUE;
        }
    }

    if (NULL != pxID) /* [v2] responder? */
    {
        wIdDataLen = GET_NTOHS(pxID->wLength) - (ubyte2)SIZEOF_IKE_ID_HDR;
        poIdData = (ubyte *)pxID + SIZEOF_IKE_ID_HDR;
        idType = pxID->oType;
    }

    if (OK > (status = CUSTOM_IKE_USE_CERT(certificates, &certNum,
                                poIdData, wIdDataLen, idType,
                                REF_MOC_IPADDR(pxSa->dwPeerAddr),
                                _OUT, bInitiator
                                MOC_MTHM_REQ_VALUE(pxSa->serverInstance))))
        goto exit;

    if (0 >= certNum) /* jic */
    {
        status = ERR_IKE_NO_CERT;
        goto exit;
    }

    if (bKeyOnly) certNum = 1;
    else
    if (IKE_CERT_CHAIN_MAX < certNum)
        certNum = IKE_CERT_CHAIN_MAX;

    CHECK_MALLOC_PTR(struct ikeCertDescr, pCertChain,
                     (sizeof(struct ikeCertDescr) * certNum))

    if (OK > (status = IKE_certSetChain(MOC_HASH(ctx->hwAccelCookie)
                                    certificates, certNum,
                                    pCertChain, &certChainLen,
                                    pxSa->ikePeerConfig,
                                    TRUE, TRUE))) /* copy (and free)!!! */
        goto exit;

    if (0 >= certChainLen) /* jic */
    {
        status = ERR_IKE_NO_CERT;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_ECC__
    if (IS_IKE2_SA(pxSa) && !pCertChain->oAuthMtd) /* [v2] non-standard ECDSA */
    {
        IKE_certUnsetChain(pCertChain, certChainLen);
        status = ERR_IKE_BAD_CERT;
        goto exit;
    }
#endif

    pxSa->certChainLen = certChainLen;
    pxSa->pCertChain = pCertChain;
    pCertChain = NULL; /* !!! */

exit:
    CHECK_FREE(pCertChain)
    return status;
} /* UseCustomCert */

#endif /* CUSTOM_IKE_USE_CERT */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_useCert(IKE_context ctx, ubyte2 wAuthMtd)
{
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    intBoolean bInitiator = IS_INITIATOR(pxSa);

    sbyte4 dir = (bInitiator ? _I : _R);
    struct ikeIdHdr *pxID = pxSa->pxID[dir]; /* host ID */

    IKE_authMtdInfo *pAuthMtd;

#ifndef __ENABLE_DIGICERT_ECC__
    MOC_UNUSED(wAuthMtd); /* [v1] */
#endif

    /* [v1] SA payload book-keeping */

    if (NULL != pxSa->pCertChain)
        goto done;

    if (0 > pxSa->certChainLen)
    {
        status = ERR_IKE_NO_CERT;
        goto exit;
    }

#ifdef __ENABLE_IKE_MULTI_AUTH__
    if (!(IS_IKE2_SA(pxSa) && (IKE_SA_FLAG_MULTI_AUTH & pxSa->flags)))
#endif
    pxSa->certChainLen = -1; /* !!! */

#ifdef CUSTOM_IKE_USE_CERT
    if (OK > (status = UseCustomCert(ctx)))
    {
        if (STATUS_IKE_CUSTOM_CONTINUE != status)
            goto exit;
        status = OK;
    }
    else goto done;
#endif

    if (0 >= pxSa->ikePeerConfig->ikeCertChainLen)
    {
        status = ERR_IKE_NO_CERT;
        goto exit;
    }

    if (IS_IKE2_SA(pxSa)) /* [v2] */
    {
        ubyte oAuthMtd = pxSa->ikePeerConfig->ikeCertChain[0].oAuthMtd;

#ifdef __ENABLE_DIGICERT_ECC__
        if (0 == oAuthMtd) /* non-standard ECDSA */
        {
            status = ERR_IKE_BAD_CERT;
            goto exit;
        }
#endif
        pAuthMtd = IKE_authMtdEx(pxSa->ikePeerConfig, 0, oAuthMtd);
        if (NULL == pAuthMtd) /* jic */
        {
            status = ERR_IKE_BAD_CERT;
            goto exit;
        }

        if (!pAuthMtd->bEnabledOut[dir])
        {
            status = ERR_IKE_MISMATCH_AUTH_METHOD;
            goto exit;
        }
    }
    else /* [v1] */
    {
        ubyte2 wCertAuthMtd = pxSa->ikePeerConfig->ikeCertChain[0].wAuthMtd;

        pAuthMtd = IKE_authMtdEx(pxSa->ikePeerConfig, wCertAuthMtd, 0);
        if (NULL == pAuthMtd) /* jic */
        {
            status = ERR_IKE_BAD_CERT;
            goto exit;
        }

        if (!pAuthMtd->bEnabled[dir])
        {
            switch (wCertAuthMtd)
            {
#ifdef __ENABLE_DIGICERT_ECC__
            case OAKLEY_ECDSA_256 :
            case OAKLEY_ECDSA_384 :
            case OAKLEY_ECDSA_521 :
                pAuthMtd = IKE_authMtdEx(pxSa->ikePeerConfig, OAKLEY_ECDSA_SIG, 0);
                if (NULL == pAuthMtd) /* jic */
                {
                    status = ERR_IKE_BAD_CERT;
                    goto exit;
                }
                if (pAuthMtd->bEnabled[dir])
                    break; /* OK!!! */
                /* fall through */
#endif
            default :
                status = ERR_IKE_MISMATCH_AUTH_METHOD;
                goto exit;
            }
        }
    }

#ifdef CUSTOM_IKE_CHECK_ID
    if ((NULL != pxID) && /* [v2] */
        CheckCertIdPayload(pxID, pxSa->ikePeerConfig->ikeCertChain))
    {
        /* match IDr sent by peer */
    }
    else if (!CheckCertCustomId(pxSa, pxSa->ikePeerConfig->ikeCertChain))
    {
        status = ERR_IKE_BAD_CERT;
        goto exit;
    }
    else if (NULL != pxID)
    {
        DBG_ERRCODE(ERR_IKE_BAD_CERT)
    }
#endif

    pxSa->pCertChain = pxSa->ikePeerConfig->ikeCertChain;
    pxSa->certChainLen = pxSa->ikePeerConfig->ikeCertChainLen;

done:
#ifdef __ENABLE_DIGICERT_ECC__
    if (wAuthMtd) /* [v1] */
    {
        IKE_certDescr pxCertDesc = pxSa->pCertChain;
        ubyte2 wCertAuthMtd = pxCertDesc->wAuthMtd;

        if (wCertAuthMtd != wAuthMtd)
        {
            switch (wCertAuthMtd)
            {
            case OAKLEY_ECDSA_256 :
            case OAKLEY_ECDSA_384 :
            case OAKLEY_ECDSA_521 :
                if (OAKLEY_ECDSA_SIG == wAuthMtd)
                {
                    IKE_authMtdInfo *pAuthMtd = IKE_authMtdEx(pxSa->ikePeerConfig, OAKLEY_ECDSA_SIG, 0);
                    if ((pxSa->ikePeerConfig->ikeCertChain != pxCertDesc) || /* !!! */
                        (pAuthMtd && pAuthMtd->bEnabled[dir]))
                    {
                        break; /* OK !!! */
                    }
                }
                /* fall through */
            default :
                status = ERR_IKE_BAD_CERT;
                goto exit;
            }
        }
    }
#endif

    if ((NULL != pxID) && IS_IKE2_SA(pxSa)) /* [v2] responder? */
    {
        /* TODO: compare/warning */
        FREE(pxID);
        pxSa->pxID[dir] = NULL;
    }

exit:
    return status;
} /* IKE_useCert */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_getCertAuth(struct ike_context *ctx, ubyte oAuthMtd)
{
    /* Note: [v2] only; auth methods can be different between host and peer! */
    /* check if 'peer' is allowed to authenticate itself using certificate. */
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    intBoolean bInitiator = IS_INITIATOR(pxSa);
    sbyte4 dir = (bInitiator ? _I : _R);

    IKE_authMtdInfo *pAuthMtd;

    /* see mAuthMtds[] in "ike_crypto.c" */
    if (oAuthMtd &&
        (0xff != oAuthMtd) &&
        (AUTH_MTD_SHARED_KEY != oAuthMtd))
    {
        pAuthMtd = IKE_authMtdEx(pxSa->ikePeerConfig, 0, oAuthMtd);
        if (pAuthMtd && !pAuthMtd->bDisabledIn[dir])
        {
            goto exit; /* found */
        }
    }
    else if (!oAuthMtd)/* traverse auth methods */
    {
        sbyte4 i;
        for (i=0; ; i++)
        {
            if (NULL == (pAuthMtd = IKE_getAuthMtdEx(pxSa->ikePeerConfig, i)))
            {
                break;
            }

            if ((AUTH_MTD_SHARED_KEY != pAuthMtd->oAuthMtd) &&
                (0xff != pAuthMtd->oAuthMtd) &&
                !pAuthMtd->bDisabledIn[dir])
            {
                goto exit; /* found */
            }
        }
    }

    status = ERR_IKE_MISMATCH_AUTH_METHOD; /* !!! */

exit:
    return status;
} /* IKE_getCertAuth */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_certGetDN(ubyte *poDn, ubyte2 wDnLen,
              struct certDistinguishedName **ppxDN)
{
    MSTATUS status;

    ASN1_ITEMPTR pDN, pRoot = NULL;
    certDistinguishedName *pxCertDN = NULL;

    MemFile mf;
    CStream cs;

    MF_attach(&mf, (sbyte4)wDnLen, poDn);
    CS_AttachMemFile(&cs, &mf);

    if (OK > (status = ASN1_Parse(cs, &pRoot)) ||
        OK > (status = ASN1_GetNthChild(pRoot, 1, &pDN)) ||
        OK > (status = CA_MGMT_allocCertDistinguishedName(&pxCertDN)) ||
        OK > (status = X509_extractDistinguishedNamesFromName(pDN, cs, pxCertDN)))
    {
        goto exit;
    }

    *ppxDN = pxCertDN;
    pxCertDN = NULL;

exit:
    if (NULL != pRoot)
        TREE_DeleteTreeItem((TreeItem *)pRoot);

    if (NULL != pxCertDN)
        CA_MGMT_freeCertDistinguishedName(&pxCertDN);

    return status;
} /* IKE_certGetDN */


#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */
