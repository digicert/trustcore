/**
 * @file  ike2_eap_mschapv2_peer_ms_ias.c
 * @brief IKEv2 IKEv2 EAP-MSCHAPv2 Peer (MS IAS)
 *
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__
 *     +   \c \__ENABLE_DIGICERT_EAP_MSCHAPv2__
 *     +   \c \__DISABLE_DIGICERT_IKE_EAP__ must not be defined
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

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if defined(__ENABLE_DIGICERT_IKE_SERVER__)
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && defined(__ENABLE_DIGICERT_EAP_MSCHAPv2__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"

#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_mschapv2.h"
#ifdef __ENABLE_DIGICERT_EAP_TTLS__
#include "../eap/eap_ttls.h"
#endif

#include "../ipsec/ipsec.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ikesa.h"
#include "../ike2/ike2_eap.h"


/*------------------------------------------------------------------*/

extern ubyte4 g_ikeEapInstId; /* EAP instance */
extern ikeSettings m_ikeSettings;


/*------------------------------------------------------------------*/

typedef struct appCtrlBlk_t
{
    ubyte               peerChallenge[16];
    ubyte               authChallenge[16];
    ubyte               NtAuthenticator[24];
    ubyte               chapState;

    ubyte              *password;
    ubyte4              passwordLen;

} appCtrlBlk;


/*------------------------------------------------------------------*/

static MSTATUS
EAP_MSCHAPv2_PeerInitFunc(struct ike2eap *pxEap)
{
    MSTATUS status = OK;

    ubyte *poMsk = NULL;
    appCtrlBlk *cb = NULL;

    /* allocate */
#ifdef __ENABLE_DIGICERT_EAP_TTLS__
    if (NULL == pxEap->ttls_connection)
#endif
    if (NULL == (poMsk = (ubyte *) MALLOC(64))) /* MSK */
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (NULL == (cb = (appCtrlBlk *) MALLOC(sizeof(appCtrlBlk))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMSET((ubyte *)cb, 0x0, sizeof(appCtrlBlk));

    /* done */
#ifdef __ENABLE_DIGICERT_EAP_TTLS__
    if (pxEap->ttls_connection)
    {
        pxEap->pInnerCbData = cb;
        goto exit;
    }
#endif
    pxEap->pCbData = cb;

    pxEap->dwMskLen = 64;
    pxEap->poMsk = poMsk;
    poMsk = NULL;

exit:
    if (poMsk) FREE(poMsk);
    return status;
} /* EAP_MSCHAPv2_PeerInitFunc */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_MSCHAPv2_PeerDelFunc(struct ike2eap *pxEap)
{
    MSTATUS status = OK;

    appCtrlBlk *cb;
#ifdef __ENABLE_DIGICERT_EAP_TTLS__
    if (pxEap->ttls_connection)
        cb = (appCtrlBlk *) pxEap->pInnerCbData;
    else
#endif
    cb = (appCtrlBlk *) pxEap->pCbData;

    if (NULL != cb)
    {
        if (cb->password)
        {
            DIGI_MEMSET(cb->password, 0x0, cb->passwordLen);
            FREE(cb->password);
        }
#ifdef __ENABLE_DIGICERT_EAP_TTLS__
        if (pxEap->ttls_connection)
            pxEap->pInnerCbData = NULL;
        else
#endif
        pxEap->pCbData = NULL;
        FREE(cb);
    }

    return status;
} /* EAP_MSCHAPv2_PeerDelFunc */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_MSCHAPv2_PeerReceivePktCallback(ubyte *appSessionHdl,
                                    eapMethodType type,
                                    eapCode code, ubyte id,
                                    ubyte *data, ubyte4 len,
                                    ubyte *opaque_data)
{
    MSTATUS status = OK;
    ubyte *eapResponse = NULL;
    ubyte4 eapRespLen = 0;
    ubyte sendResponse = 0;
    ubyte freebuffer = 0;
    byteBoolean cmp;
    eapMethodType methodType = 0;
    eapMethodState methodState = EAP_METHOD_STATE_INIT;
    eapMethodDecision decision = EAP_METHOD_DECISION_NONE;

    struct ike2eap *pxEap = (struct ike2eap *)appSessionHdl;

    appCtrlBlk *cb;
#ifdef __ENABLE_DIGICERT_EAP_TTLS__
    if (pxEap->ttls_connection)
        cb = (appCtrlBlk *) pxEap->pInnerCbData;
    else
#endif
    cb = (appCtrlBlk *) pxEap->pCbData;

    MOC_UNUSED(id);
    MOC_UNUSED(opaque_data);

    switch (code)
    {
        case EAP_CODE_REQUEST :
            break;
        case EAP_CODE_SUCCESS :
        case EAP_CODE_FAILURE :
            /* delete session */
            goto exit;
        case EAP_CODE_RESPONSE :
        default :
        {
            status = ERR_EAP_INVALID_CODE;
            DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte *)"Invalid EAP Code", status);
            break;
        }
    }

    if (OK != status)
        goto exit;

    switch (type)
    {
        case EAP_TYPE_NONE :
        {
            /* set error code */
            status = ERR_EAP_INVALID_METHOD_TYPE;
            break;
        }

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
            else
            {
                status = ERR_EAP_INVALID_PARAM;
                goto exit;
            }
            methodType =  EAP_TYPE_IDENTITY;
            methodState = EAP_METHOD_STATE_CONT;
            decision = EAP_METHOD_DECISION_FAIL;
            sendResponse = 1;
            freebuffer = 1;
            break;
        }

        case EAP_TYPE_NOTIFICATION :
        {
            /* Log msg */
            methodType = EAP_TYPE_NOTIFICATION;
            break;
        }

        case EAP_TYPE_MSCHAPV2 :
        {
            if (!cb->chapState)
            {
                if (NULL == m_ikeSettings.funcPtrGetToken)
                {
                    status = ERR_IKE_CONFIG;
                    goto exit;
                }
                if (OK > (status = m_ikeSettings.funcPtrGetToken(NULL, 0,
                                                 &cb->password, &cb->passwordLen,
                                                 pxEap->pxSa->serverInstance)))
                    goto exit;

                EAP_MSCHAPV2_getChallenge(cb->peerChallenge);

                status = EAP_MSCHAPProcessPeer(appSessionHdl,
                            data, len,
                            (ubyte*)pxEap->identity, pxEap->identityLen,
                            cb->password, cb->passwordLen,
                            cb->peerChallenge,
                            cb->authChallenge,
                            cb->NtAuthenticator,
                            &eapResponse, &eapRespLen);

                if (OK == status)
                {
                    ubyte  mk[16];
                    ubyte* poMsk = pxEap->poMsk;

                    methodType = EAP_TYPE_MSCHAPV2;
                    methodState = EAP_METHOD_STATE_CONT;
                    decision = EAP_METHOD_DECISION_FAIL;
                    freebuffer = 1;

#ifdef __ENABLE_DIGICERT_EAP_TTLS__
                    if (pxEap->ttls_connection) /* EAP-TTLS inner EAP tunnel */
                    {
                        sendResponse = 1;
                        cb->chapState = 1;
                        break;
                    }
#endif
                    /* get MSK */
                    if (OK > (status = EAP_MSCHAPgenerateMasterKey(
                                            cb->password, (ubyte2) cb->passwordLen,
                                            cb->NtAuthenticator,
                                            mk)))
                    {
                        break;
                    }

                    status = EAP_MSCHAPgenerateSessionKey(mk, poMsk, 16,
                                                                 1,  /* Send */
                                                                 0); /* Server */

                    if (OK > status)
                        break;

                    poMsk += 16;
                    status = EAP_MSCHAPgenerateSessionKey(mk, poMsk, 16,
                                                                 0,  /* Send */
                                                                 0); /* Server */

                    if (OK > status)
                        break;

                    poMsk += 16;
                    DIGI_MEMSET(poMsk, 0x0, 32);

#if defined(__ENABLE_ALL_DEBUGGING__) && defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__)
                    {
                        ubyte4 i;
                        DEBUG_PRINT(DEBUG_IKE_MESSAGES, (sbyte *)"MSK(64) = ");
                        for (i=0; i < 64; i++)
                            DEBUG_HEXBYTE(DEBUG_IKE_MESSAGES, pxEap->poMsk[i]);
                        DEBUG_PRINTNL(DEBUG_IKE_MESSAGES, (sbyte *)"");
                    }
#endif
                    sendResponse = 1;

                    cb->chapState = 1;
                }
            }
            else
            {
                status = EAP_MSCHAPpeerResponse(appSessionHdl,
                            data, (ubyte2)len,
                            cb->password, (ubyte2) cb->passwordLen,
                            cb->NtAuthenticator,
                            cb->peerChallenge,
                            cb->authChallenge,
                            (ubyte*)pxEap->identity, (ubyte2) pxEap->identityLen,
                            &eapResponse, &eapRespLen, &cmp);

                if (OK == status)
                {
                    methodType = EAP_TYPE_MSCHAPV2;
                    methodState = EAP_METHOD_STATE_DONE;

                    if (TRUE!=cmp)
                        decision = EAP_METHOD_DECISION_FAIL;
                    else
                        decision = EAP_METHOD_DECISION_UNCOND_SUCC;

                    sendResponse = 1;
                    freebuffer = 1;

                    cb->chapState = 2;

                    /* If working against MS IAS, it likes the fact that
                     * we return just 1 Byte of Code and not the rest of
                     * the struct  hence *eapRespLen = 1
                     */
                    if (eapResponse && MSCHAPV2_SUCCESS == *eapResponse)
                    {
                        eapRespLen = 1;
                    }
                }
            }

            break;
        }

        default :
        {
            /* send NAK response */
            ubyte methodSup = EAP_TYPE_MSCHAPV2;
            status = EAP_buildNAK(pxEap->pSession, g_ikeEapInstId,
                                  &methodSup, 1,
                                  &eapResponse, &eapRespLen);

            if (OK == status)
            {
                methodType = EAP_TYPE_NAK;
                decision = EAP_METHOD_DECISION_FAIL;
                sendResponse = 1;
                freebuffer = 1;
            }

            break;
        }
    }

    if (sendResponse)
    {
#ifdef __ENABLE_DIGICERT_EAP_TTLS__
        if (pxEap->ttls_connection) /* EAP-TTLS inner EAP tunnel */
        status = EAP_TTLSulPeerTransmit(pxEap->ttls_connection, g_ikeEapInstId,
                                        methodType, EAP_CODE_RESPONSE,
                                        decision, methodState,
                                        eapResponse, eapRespLen);
        else
#endif
        status = EAP_ulTransmit(pxEap->pSession, g_ikeEapInstId,
                                methodType, EAP_CODE_RESPONSE,
                                decision, methodState,
                                eapResponse, eapRespLen);

    }

    if (freebuffer && NULL != eapResponse)
    {
        FREE(eapResponse);
    }

exit:
    return status;
} /* EAP_MSCHAPv2_PeerReceivePktCallback */


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
        "IKE_EAP_MSCHAPv2_PEER",
        EAP_MSCHAPv2_PeerReceivePktCallback,
        NULL,
        IKE_eapReceiveIndication,
        IKE_eapVerifyMIC,
        IKE_eapGetMethodState,
        IKE_eapGetDecision,
        IKE_eapTransmitPktCallback
};

const IKE_eapSuiteInfo g_ikeEapMSCHAPv2peerSuite =
{
    EAP_MSCHAPv2_PeerInitFunc,
    EAP_MSCHAPv2_PeerDelFunc,
    &methodDef,
    EAP_SESSION_TYPE_PEER,
#ifdef __ENABLE_IKE_EAP_ONLY__
    FALSE
#endif
};


#endif /* defined(__ENABLE_DIGICERT_EAP_PEER__) && defined(__ENABLE_DIGICERT_EAP_MSCHAPv2__) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */
#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */

