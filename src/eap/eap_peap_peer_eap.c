/**
 * @file  eap_peap_peer_eap.c
 * @brief EAP-PEAP peer EAP
 *
 * @details    PEAP client-side EAP processing
 * @since      1.41
 * @version    1.41 and later
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_PEAP__
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__
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


/* Add to your makefile */
#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if ((defined(__ENABLE_DIGICERT_EAP_PEER__)) && defined(__ENABLE_DIGICERT_EAP_PEAP__))

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/vlong.h"
#include "../common/debug_console.h"
#include "../crypto/crypto.h"
#include "../crypto/md5.h"
#include "../common/redblack.h"
#include "../common/mudp.h"
#include "../common/random.h"
#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_md5.h"
#include "../eap/eap_peap.h"
#include "../eap/eap_peap_pvt.h"


/*------------------------------------------------------------------*/

extern MSTATUS
EAP_PEAP_PeerReceivePktCallback(ubyte*         appSessionHdl,
                         eapMethodType  type,
                         eapCode        code,
                         ubyte          id,
                         ubyte*         data,
                         ubyte4         len,
                         ubyte*         opaque_data);

/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_PEAP_PeerReceiveIndication(ubyte* app_session_handle,
                         eapIndication ind_type,
                         ubyte* data,
                         ubyte4 data_len)
{
/*    printf("Received Indication %d\n",ind_type); */
    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_PEAP_PeerVerifyMIC(ubyte* app_session_handle,
                 ubyte* pkt,
                 ubyte4 pkt_len)
{
    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_PEAP_PeerGetMethodState(ubyte*  app_session_handle,
                      ubyte4* methodState)
{
    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS EAP_PEAP_PeerGetDecision(ubyte*  app_session_handle,
                                  ubyte4* decision)
{
    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_PEAPPeerInit(eapPEAPCB *eapCb)
{
    MSTATUS status = OK;
    eapMethodDef_t methodDef;
    eapSessionConfig_t sessionConfig;

    /* Peer session */
        /* create a new session */
    DIGI_MEMSET((ubyte *)&methodDef, 0, sizeof(eapMethodDef_t));
    methodDef.method_type = EAP_TYPE_NONE;
    methodDef.funcPtr_ulReceiveCallback =
                                           EAP_PEAP_PeerReceivePktCallback;
    methodDef.funcPtr_llTransmitPacket =
                                        EAP_PEAP_llTransmitPktCallback;
    methodDef.funcPtr_ulReceiveIndication =
                                        EAP_PEAP_PeerReceiveIndication;
    methodDef.funcPtr_ulMICVerify =  EAP_PEAP_PeerVerifyMIC;
    methodDef.funcPtr_ulGetMethodstate =  EAP_PEAP_PeerGetMethodState;
    methodDef.funcPtr_ulGetDecision =  EAP_PEAP_PeerGetDecision;

    sessionConfig.eap_mtu = 1020;
    sessionConfig.eap_ul_timeout = 30;
    sessionConfig.eap_retrans_timeout = 0;
    sessionConfig.eap_max_retrans = 0;
    sessionConfig.sessionType = EAP_SESSION_TYPE_PEER;
    if (OK > (status = EAP_sessionCreate((ubyte *)eapCb,
                              eapCb->eapPEAPparam.instanceId,
                              methodDef,
                              sessionConfig,
                              &eapCb->eapSessionHdl)))
    {
        goto exit;
    }

    status = EAP_sessionEnable(eapCb->eapSessionHdl, eapCb->eapPEAPparam.instanceId);

    /* Set the Identity */
    status = EAP_setIdentity(eapCb->eapSessionHdl,
                             eapCb->eapPEAPparam.instanceId,
                             eapCb->eapPEAPparam.UserName,
                             eapCb->eapPEAPparam.UserNameLen);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_PEAP_PeerReceivePktCallback(ubyte *appSessionHdl,
                         eapMethodType type,
                         eapCode code, ubyte id,
                         ubyte *data, ubyte4 len,
                         ubyte *opaque_data)
{
    MSTATUS status = OK;
    ubyte* eapResponse = NULL;
    ubyte* temp_eapResponse = NULL;
    ubyte4 eapRespLen = 0;
    ubyte4 temp_eapRespLen = 0;
    ubyte4 sendResponse = 0;
    byteBoolean cmp;
    ubyte eapExtReq[6];
    ubyte2 pTlvLen;
    ubyte  isMandatory;
    ubyte  *pData;
    ubyte2 result;
    eapMethodType methodType;
    eapMethodState methodState = EAP_METHOD_STATE_INIT;
    eapMethodDecision decision = EAP_METHOD_DECISION_NONE;
    ubyte4 expVendorId = 0;
    ubyte4 expMethodId = 0;
    ubyte * eap_data;
    eapPEAPCB * eapCb = (eapPEAPCB *)appSessionHdl;

    switch(code)
    {
        case EAP_CODE_REQUEST:
        {
            status = OK;
            break;
        }

        case EAP_CODE_RESPONSE:
        {
            status = ERR_EAP_INVALID_CODE;
            DEBUG_ERROR(DEBUG_EAP_MESSAGE,"Invalid EAP Code",status);
            break;
        }

        case EAP_CODE_SUCCESS:
        {
            eapCb->eapPEAPparam.ulAuthResultTransmit(eapCb->appSessionCB,EAP_AUTH_SUCCESS);
           /*Send ACK  1 Byte with Version*/
            eap_data = MALLOC(1);
            if (!eap_data)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            *eap_data = eapCb->eapPEAPparam.version;
            eapCb->eapPEAPparam.ulTransmit(eapCb->appSessionCB,eap_data,1,TRUE);
            status = OK;
            goto exit;
        }

        case EAP_CODE_FAILURE:
        {
            /* delete session */
            eapCb->eapPEAPparam.ulAuthResultTransmit(eapCb->appSessionCB,EAP_AUTH_FAILURE);
           /*Send ACK  1 Byte with Version*/
            eap_data = MALLOC(1);
            if (!eap_data)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            *eap_data = eapCb->eapPEAPparam.version;
            eapCb->eapPEAPparam.ulTransmit(eapCb->appSessionCB,eap_data,1,TRUE);
            status = OK;
            goto exit;
        }
    }

    if (EAP_CODE_RESPONSE == code || status != OK)
        goto exit;

    switch(type)
    {
        case EAP_TYPE_NONE:
        {
            /* set error code */
            status = ERR_EAP_INVALID_METHOD_TYPE;
            break;
        }

        case EAP_TYPE_TLV:
        {
            /* Extract The Result TLV */
            /* If its Success Then Send Success else Failure */
            status = EAP_PEAPgetTLVbyType(eapCb, data+1, len -1, EAP_PEAP_RESULT_TLV,
                                 &pTlvLen, &pData, (ubyte *)&isMandatory);
            if (OK > status)
                goto exit;

            result = DIGI_NTOHS(pData);
            if ((EAP_PEAP_RESULT_SUCCESS == result) &&
                (EAP_PEAP_EAP_SUCCESS    == eapCb->eapStatus))
            {
                /* Send  Success Indication to App */
                EAP_PEAPBuildResultTlv(1, eapExtReq, &eapRespLen);
                eapResponse = eapExtReq;
                eapCb->eapPEAPparam.ulAuthResultTransmit(eapCb->appSessionCB,EAP_AUTH_SUCCESS);
                methodType = EAP_TYPE_TLV;
                methodState = EAP_METHOD_STATE_DONE;
                decision = EAP_METHOD_DECISION_UNCOND_SUCC;
                sendResponse = 1;
            }
            else
            {
                /* Send Failure  Indication to App*/
                EAP_PEAPBuildResultTlv(2, eapExtReq, &eapRespLen);
                eapResponse = eapExtReq;
                methodType = EAP_TYPE_TLV;
                methodState = EAP_METHOD_STATE_DONE;
                decision = EAP_METHOD_DECISION_FAIL;
                eapCb->eapPEAPparam.ulAuthResultTransmit(eapCb->appSessionCB,EAP_AUTH_FAILURE);
                sendResponse = 1;
            }

            break;
        }

        case EAP_TYPE_NOTIFICATION:
        {
            /* Log msg */
            methodType = EAP_TYPE_NOTIFICATION;
            break;
        }

        default:
        {
            /* Pass it to the App Layer For Processing */
            status = eapCb->eapPEAPparam.ul2ndStageReceive(eapCb->appSessionCB,
                                          type,
                                          code, id,
                                          data, len,
                                          opaque_data);
            sendResponse = 0;
            break;
        }
    }
    if (sendResponse)
    {
        status = EAP_ulTransmit(eapCb->eapSessionHdl,
                                 eapCb->eapPEAPparam.instanceId,
                                 methodType, EAP_CODE_RESPONSE,
                                 decision, methodState, eapResponse,
                                 eapRespLen);

    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Transmit packets from the peer to the authenticator through the second stage EAP stack.
This function (called by the second stage peer processing) transmits
packets from the peer to the authenticator through the second stage EAP stack.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_PEAP__$

#Include %file:#&nbsp;&nbsp;eap_peap.h

\param eapSessionHdl    EAP-PEAP session handle returned from EAP_PEAPinitSession.
\param instanceId       EAP instance ID returned from EAP_initInstance.
\param methodType       $eapMethodType$ enumerated value for the second phase (refer to eap_proto.h).
\param code             $EAP_CODE_RESPONSE$ (an $eapCode$ enumerated value, defined in eap_proto.h).
\param methodDecision   $eapMethodDecision$ enumerated value (refer to eap_proto.h)
\param methodState      $eapMethodState$ enumerated value (refer to eap_proto.h)
\param eap_data         Pointer to EAP packet to be transmitted.
\param eap_data_len     Number of bytes in EAP packet to be transmitted ($eap_data$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_PEAPulPeerTransmit (ubyte * eapSessionHdl,
                 ubyte4 instanceId,
                 eapMethodType  methodType,
                 eapCode  code,
                 eapMethodDecision  methodDecision,
                 eapMethodState methodState,
                 ubyte * eap_data,
                 ubyte4  eap_data_len)
{

    eapPEAPCB * eapCb = (eapPEAPCB *)eapSessionHdl;
    MSTATUS status;

    if ((EAP_METHOD_STATE_DONE == methodState) &&
        (EAP_METHOD_DECISION_UNCOND_SUCC == methodDecision))
    {
        eapCb->eapStatus = EAP_PEAP_EAP_SUCCESS;
        methodState = EAP_METHOD_STATE_CONT;
        methodDecision = EAP_METHOD_DECISION_FAIL;
    }

    status = EAP_ulTransmit(eapCb->eapSessionHdl,
                                 eapCb->eapPEAPparam.instanceId,
                                 methodType, EAP_CODE_RESPONSE,
                                 methodDecision, methodState, eap_data,
                                 eap_data_len);

    return status;

}

/*------------------------------------------------------------------*/

#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__)) && defined(__ENABLE_DIGICERT_EAP_PEAP__)) */
