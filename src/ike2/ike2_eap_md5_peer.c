/**
 * @file  ike2_eap_md5_peer.c
 * @brief IKEv2 IKEv2 EAP-MD5 Peer
 *
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__
 *     +   \c \__ENABLE_DIGICERT_EAP_MD5__
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
#if defined(__ENABLE_DIGICERT_EAP_PEER__) && defined(__ENABLE_DIGICERT_EAP_MD5__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"

#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_md5.h"
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

static MSTATUS
EAP_MD5_PeerReceivePktCallback(ubyte *appSessionHdl,
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
    eapMethodType methodType = 0;
    eapMethodState methodState = EAP_METHOD_STATE_INIT;
    eapMethodDecision decision = EAP_METHOD_DECISION_NONE;

    struct ike2eap *pxEap = (struct ike2eap *)appSessionHdl;

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

        case EAP_TYPE_MD5 :
        {
            ubyte *passwd = NULL;
            ubyte4 passwdLen = 0;

            /* md5 processing */
            if (NULL == m_ikeSettings.funcPtrGetToken)
            {
                status = ERR_IKE_CONFIG;
                goto exit;
            }
            if (OK > (status = m_ikeSettings.funcPtrGetToken(NULL, 0,
                                                 &passwd, &passwdLen,
                                                 pxEap->pxSa->serverInstance)))
                goto exit;

            status = EAP_MD5ProcessPeer(appSessionHdl,
                                        pxEap->pSession, g_ikeEapInstId,
                                        id, data, len,
                                        passwd, passwdLen,
                                        &eapResponse, &eapRespLen);
            if (passwd)
            {
                DIGI_MEMSET(passwd, 0x0, passwdLen);
                FREE(passwd);
            }

            if (OK == status)
            {
                methodType = EAP_TYPE_MD5;
                methodState = EAP_METHOD_STATE_DONE;
                decision = EAP_METHOD_DECISION_UNCOND_SUCC;
                sendResponse = 1;
                freebuffer = 1;
            }
            break;
        }

        case EAP_TYPE_EXPANDED :
        {
            ubyte4 expVendorId = DIGI_NTOHL(data) & 0x00ffffff;
            ubyte4 expMethodId = DIGI_NTOHL(data + 4);

            if ((EAP_VENDOR_ID_IETF == expVendorId) &&
                (EAP_TYPE_MD5 == expMethodId))
            {
                ubyte* temp_eapResponse = NULL;
                ubyte4 temp_eapRespLen = 0;
                ubyte *passwd = NULL;
                ubyte4 passwdLen = 0;

                if (NULL == m_ikeSettings.funcPtrGetToken)
                {
                    status = ERR_IKE_CONFIG;
                    goto exit;
                }
                if (OK > (status = m_ikeSettings.funcPtrGetToken(NULL, 0,
                                                 &passwd, &passwdLen,
                                                 pxEap->pxSa->serverInstance)))
                    goto exit;

                status = EAP_MD5ProcessPeer(appSessionHdl,
                                        pxEap->pSession, g_ikeEapInstId,
                                        id, data + 7, len - 7,
                                        passwd, passwdLen,
                                        &temp_eapResponse, &temp_eapRespLen);
                if (passwd)
                {
                    DIGI_MEMSET(passwd, 0x0, passwdLen);
                    FREE(passwd);
                }

                if (OK == status)
                {
                    status = EAP_buildExpandedResponse(
                                        pxEap->pSession, g_ikeEapInstId,
                                        expVendorId, expMethodId,
                                        temp_eapResponse, temp_eapRespLen,
                                        &eapResponse, &eapRespLen);

                    if (temp_eapResponse)
                        FREE(temp_eapResponse);

                    if (OK == status)
                    {
                        methodType = EAP_TYPE_EXPANDED;
                        methodState = EAP_METHOD_STATE_DONE;
                        decision = EAP_METHOD_DECISION_UNCOND_SUCC;
                        sendResponse = 1;
                        freebuffer = 1;
                    }
                }
            }
            else
            {
                /* send Expanded NAK */
                eapExpandedMethod_t expanded_method;
                DIGI_HTONL((ubyte *)&expanded_method.vendor_id, EAP_VENDOR_ID_IETF);
                DIGI_HTONL((ubyte *)&expanded_method.method_type, EAP_TYPE_MD5);
                status = EAP_buildExpandedNAK(pxEap->pSession, g_ikeEapInstId,
                                              &expanded_method, 1,
                                              &eapResponse, &eapRespLen);

                if (OK == status)
                {
                    methodType = EAP_TYPE_EXPANDED_NAK;
                    decision = EAP_METHOD_DECISION_FAIL;
                    sendResponse = 1;
                    freebuffer = 1;
                }
            }
            break;
        }

        default :
        {
            /* send NAK response */
            ubyte methodSup = EAP_TYPE_MD5;
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
} /* EAP_MD5_PeerReceivePktCallback */


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
        "IKE_EAP_MD5_PEER",
        EAP_MD5_PeerReceivePktCallback,
        NULL,
        IKE_eapReceiveIndication,
        IKE_eapVerifyMIC,
        IKE_eapGetMethodState,
        IKE_eapGetDecision,
        IKE_eapTransmitPktCallback
};

const IKE_eapSuiteInfo g_ikeEapMD5peerSuite =
{
    NULL,
    NULL,
    &methodDef,
    EAP_SESSION_TYPE_PEER,
#ifdef __ENABLE_IKE_EAP_ONLY__
    FALSE
#endif
};


#endif /* defined(__ENABLE_DIGICERT_EAP_PEER__) && defined(__ENABLE_DIGICERT_EAP_MD5__) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */
#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */

