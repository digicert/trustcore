/**
 * @file  ike2_eap_any_peer.c
 * @brief IKEv2 IKEv2 EAP - Any Method Peer
 *
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *    Additionally, the following flags must be defined:
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__
 *     +   \c \__DISABLE_DIGICERT_IKE_EAP__ must not be defined.
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

#if defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/vlong.h"
#include "../common/debug_console.h"
#include "../crypto/crypto.h"
#include "../common/sizedbuffer.h"
#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../ipsec/ipsec.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ikesa.h"
#include "../ike2/ike2_eap.h"


/*------------------------------------------------------------------*/

extern ubyte4 g_ikeEapInstId; /* EAP instance */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_ANY_PeerDelFunc(IKE2EAP pxEap)
{
    MSTATUS status = OK;

    const IKE_eapSuiteInfo *pEapSuiteEx;
    if (NULL != (pEapSuiteEx = pxEap->pEapSuiteEx))
    {
        if (pEapSuiteEx->delFunc)
            status = pEapSuiteEx->delFunc(pxEap);
        pxEap->pEapSuiteEx = NULL;
    }

    return status;
} /* EAP_ANY_PeerDelFunc */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_ANY_PeerReceiveIndication(ubyte* appSessionHdl, eapIndication ind_type,
                              ubyte* data, ubyte4 len)
{
    MSTATUS status = OK;

    IKE2EAP pxEap = (IKE2EAP)appSessionHdl;
    const IKE_eapSuiteInfo *pEapSuiteEx = pxEap->pEapSuiteEx;

    if ((NULL != pEapSuiteEx) &&
        (NULL != pEapSuiteEx->pMethodDef->funcPtr_ulReceiveIndication))
    {
        status = pEapSuiteEx->pMethodDef->funcPtr_ulReceiveIndication(
                                                                 appSessionHdl,
                                                                 ind_type,
                                                                 data, len);
    }

    return status;
} /* EAP_TTLS_PeerReceiveIndication */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_ANY_PeerReceivePktCallback(ubyte *appSessionHdl,
                               eapMethodType type, eapCode code, ubyte id,
                               ubyte *data, ubyte4 len,
                               ubyte *opaque_data)
{
    MSTATUS status = OK;

    ubyte *eapResponse = NULL;
    ubyte4 eapRespLen = 0;
    eapMethodType methodType = 0;
    eapMethodState methodState = EAP_METHOD_STATE_INIT;
    eapMethodDecision decision = EAP_METHOD_DECISION_NONE;
    ubyte sendResponse = 0;

    IKE2EAP pxEap = (IKE2EAP)appSessionHdl;

    switch (code)
    {
    case EAP_CODE_REQUEST :
        break;
    case EAP_CODE_SUCCESS :
#ifdef __ENABLE_DIGICERT_EAP_LEAP__
        if (EAP_PROTO_LEAP == pxEap->proto)
            break;
#endif
    case EAP_CODE_FAILURE :
        /* will delete session */
        goto exit;
    case EAP_CODE_RESPONSE :
#ifdef __ENABLE_DIGICERT_EAP_LEAP__
        if (EAP_PROTO_LEAP == pxEap->proto)
            break;
#endif
    default:
        status = ERR_EAP_INVALID_CODE;
        DEBUG_ERROR(DEBUG_IKE_MESSAGES, (sbyte *)"Invalid EAP Code", status);
        goto exit;
    }

    switch (type)
    {
    case EAP_TYPE_NONE :
#ifdef __ENABLE_DIGICERT_EAP_LEAP__
        if ((EAP_PROTO_LEAP == pxEap->proto) && pxEap->pEapSuiteEx)
        {
            status = pxEap->pEapSuiteEx->pMethodDef->funcPtr_ulReceiveCallback(
                                                                  appSessionHdl,
                                                                  type, code,
                                                                  id, data, len,
                                                                  opaque_data);
            goto exit;
        }
#endif
        /* set error code */
        status = ERR_EAP_INVALID_METHOD_TYPE;
        break;

    case EAP_TYPE_IDENTITY :
    {
        /* Build IDENTITY response */
        const ubyte *identity = pxEap->identity;
        if (identity && (0 != (eapRespLen = pxEap->identityLen)))
        {
            if (NULL == (eapResponse = (ubyte *) MALLOC(eapRespLen)))
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            DIGI_MEMCPY(eapResponse, identity, eapRespLen);
        }
        methodType = EAP_TYPE_IDENTITY;
        methodState = EAP_METHOD_STATE_CONT;
        decision = EAP_METHOD_DECISION_FAIL;
        sendResponse = 1;
        break;
    }
    case EAP_TYPE_NOTIFICATION :
        /* Log msg */
        methodType = EAP_TYPE_NOTIFICATION;
        break;

#if defined(__ENABLE_DIGICERT_EAP_GTC__) || defined(__ENABLE_DIGICERT_EAP_MD5__)
    case EAP_TYPE_EXPANDED :
    {
        ubyte4 expVendorId = DIGI_NTOHL(data) & 0x00ffffff;
        ubyte4 expMethodId = DIGI_NTOHL(data + 4);
        eapExpandedMethod_t expanded_methods[EAP_MAX_METHODS];
        ubyte expanded_method_count = 0;

        const IKE_eapSuiteInfo *pEapSuiteEx = pxEap->pEapSuiteEx;
        if ((NULL == pEapSuiteEx) && (8 < len) &&
            (EAP_VENDOR_ID_IETF == expVendorId) &&
            (
#ifdef __ENABLE_DIGICERT_EAP_GTC__
             (EAP_TYPE_GTC == expMethodId) ||
#endif
#ifdef __ENABLE_DIGICERT_EAP_MD5__
             (EAP_TYPE_MD5 == expMethodId) ||
#endif
             FALSE))
        {
            if (OK == IKE_eapSuite((IKE_EAP_PROTO_T)expMethodId, TRUE, &pEapSuiteEx) &&
                NULL != pEapSuiteEx)
            {
#ifdef __ENABLE_IKE_EAP_ONLY__
                if ((IKE_SA_FLAG_EAP_ONLY & pxEap->pxSa->flags) &&
                    (FALSE == pEapSuiteEx->bEapOnlyOk))
                {
                    status = ERR_IKE_EAP_ONLY;
                    goto exit;
                }
#endif
                if ((NULL != pEapSuiteEx->initFunc) &&
                    (OK > (status = pEapSuiteEx->initFunc(pxEap))))
                    goto exit;

                pxEap->proto = (IKE_EAP_PROTO_T)expMethodId;
                pxEap->pEapSuiteEx = pEapSuiteEx;
            }
        }

        if (pEapSuiteEx)
        {
            status = pEapSuiteEx->pMethodDef->funcPtr_ulReceiveCallback(
                                                                appSessionHdl,
                                                                type, code,
                                                                id, data, len,
                                                                opaque_data);
            goto exit;
        }

        /* send Expanded NAK */
#ifdef __ENABLE_DIGICERT_EAP_GTC__
        DIGI_HTONL((ubyte *)&expanded_methods[expanded_method_count].vendor_id, EAP_VENDOR_ID_IETF);
        DIGI_HTONL((ubyte *)&expanded_methods[expanded_method_count++].method_type, EAP_TYPE_GTC);
#endif
#ifdef __ENABLE_DIGICERT_EAP_MD5__
        DIGI_HTONL((ubyte *)&expanded_methods[expanded_method_count].vendor_id, EAP_VENDOR_ID_IETF);
        DIGI_HTONL((ubyte *)&expanded_methods[expanded_method_count++].method_type, EAP_TYPE_MD5);
#endif
        status = EAP_buildExpandedNAK(pxEap->pSession, g_ikeEapInstId,
                                      expanded_methods, expanded_method_count,
                                      &eapResponse, &eapRespLen);
        if (OK == status)
        {
            methodType = EAP_TYPE_EXPANDED_NAK;
            decision = EAP_METHOD_DECISION_FAIL;
            sendResponse = 1;
        }
        break;
    }
#endif

    default :
    {
        ubyte methodSup[EAP_MAX_METHODS];
        sbyte4 i, j;

        const IKE_eapSuiteInfo *pEapSuiteEx = pxEap->pEapSuiteEx;
        if (NULL == pEapSuiteEx)
        {
            if (OK == IKE_eapSuite((IKE_EAP_PROTO_T)type, TRUE, &pEapSuiteEx) &&
                NULL != pEapSuiteEx)
            {
                if (NULL == pEapSuiteEx->pMethodDef)
                {
                    status = ERR_EAP;
                    goto exit;
                }

                if (NULL == pEapSuiteEx->pMethodDef->funcPtr_ulReceiveCallback)
                {
                    status = ERR_EAP_INVALID_CALLBACK_FN;
                    goto exit;
                }

#ifdef __ENABLE_IKE_EAP_ONLY__
                if ((IKE_SA_FLAG_EAP_ONLY & pxEap->pxSa->flags) &&
                    (FALSE == pEapSuiteEx->bEapOnlyOk))
                {
                    status = ERR_IKE_EAP_ONLY;
                    goto exit;
                }
#endif
                if ((NULL != pEapSuiteEx->initFunc) &&
                    (OK > (status = pEapSuiteEx->initFunc(pxEap))))
                    goto exit;

                pxEap->proto = (IKE_EAP_PROTO_T)type;
                pxEap->pEapSuiteEx = pEapSuiteEx;
            }
        }

        if (pEapSuiteEx)
        {
            status = pEapSuiteEx->pMethodDef->funcPtr_ulReceiveCallback(
                                                                appSessionHdl,
                                                                type, code,
                                                                id, data, len,
                                                                opaque_data);
            goto exit;
        }

        /* send NAK response */
        for (i=0, j=0; i < EAP_MAX_METHODS; i++)
        {
            IKE_EAP_PROTO_T proto_t;
            if (NULL == IKE_getEapSuite(TRUE, i, &proto_t))
                break;

            if (EAP_PROTO_ANY == proto_t)
                continue;

            methodSup[j++] = (ubyte)proto_t;
        }

        status = EAP_buildNAK(pxEap->pSession, g_ikeEapInstId,
                              (ubyte *)methodSup, j,
                              &eapResponse, &eapRespLen);
        if (OK == status)
        {
            methodType = EAP_TYPE_NAK;
            decision = EAP_METHOD_DECISION_FAIL;
            sendResponse = 1;
        }
        break;
    }
    }

    if (sendResponse)
    {
        status = EAP_ulTransmit(pxEap->pSession, g_ikeEapInstId,
                                methodType, EAP_CODE_RESPONSE,
                                decision, methodState,
                                eapResponse, eapRespLen);
    }

exit:
    if (eapResponse)
        FREE(eapResponse);
    return status;
} /* EAP_ANY_PeerReceivePktCallback */


/*------------------------------------------------------------------*/

static eapMethodDef_t methodDef =
{/*
        eapMethodType,
        ubyte method_name[EAP_MAX_METHOD_NAME],
        funcPtr_ulReceiveCallback,
        funcPtr_ulReceivePassthruCallback,
        funcPtr_ulReceiveIndication,
        funcPtr_ulMICVerify,
        funcPtr_ulGetMethodstate,
        funcPtr_ulGetDecision,
        funcPtr_llTransmitPacket
  */
        EAP_TYPE_NONE,
        "IKE_EAP_ANY_PEER",
        EAP_ANY_PeerReceivePktCallback,
        NULL,
        EAP_ANY_PeerReceiveIndication,
        IKE_eapVerifyMIC,
        IKE_eapGetMethodState,
        IKE_eapGetDecision,
        IKE_eapTransmitPktCallback
};

const IKE_eapSuiteInfo g_ikeEapANYpeerSuite =
{
    NULL,
    EAP_ANY_PeerDelFunc,
    &methodDef,
    EAP_SESSION_TYPE_PEER,
#ifdef __ENABLE_IKE_EAP_ONLY__
    FALSE
#endif
};


#endif /* defined(__ENABLE_DIGICERT_EAP_PEER__) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */
#else
static void
dummy(void)
{
    return;
}
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

