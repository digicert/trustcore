/**
 * @file  eap_peap_auth_eap.c
 * @brief EAP-PEAP authenticator EAP
 *
 * @details    PEAP server-side EAP processing
 * @since      1.41
 * @version    1.41 and later
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_AUTH__
 *     +   \c \__ENABLE_DIGICERT_EAP_PEAP__
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

#if ((defined(__ENABLE_DIGICERT_EAP_AUTH__)) && defined(__ENABLE_DIGICERT_EAP_PEAP__))

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/vlong.h"
#include "../common/debug_console.h"
#include "../crypto/crypto.h"
#include "../crypto/md5.h"
#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_md5.h"
#include "../common/redblack.h"
#include "../common/mudp.h"
#include "../common/random.h"
#include "../eap/eap_peap.h"
#include "../eap/eap_peap_pvt.h"



/*------------------------------------------------------------------*/

extern MSTATUS
EAP_PEAP_AuthReceivePktCallback(ubyte *app_session_handle,
                         eapMethodType  method_type,
                         eapCode        code,
                         ubyte          id,
                         ubyte*         eap_data,
                         ubyte4         eap_data_len,
                         ubyte*         opaque_data);

extern MSTATUS
EAP_PEAP_Auth_llTransmitPktCallback(ubyte*    appSessionHdl,
                          eapHdr_t* eap_hdr,
                          ubyte*    eap_data,
                          ubyte4    eap_data_len);

extern MSTATUS
EAP_PEAP_ulReceiveMD5AuthPktCallback(ubyte *app_session_handle,
                             eapMethodType method_type,
                             eapCode       code,
                             ubyte         id,
                             ubyte*        eap_data,
                             ubyte4        eap_data_len,
                             ubyte*        opaque_data);

/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_PEAP_AuthReceiveIndication(ubyte* app_session_handle,
                         eapIndication ind_type,
                         ubyte* data,
                         ubyte4 data_len)
{
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "EAP_PEAP_AuthReceiveIndication : Received Indication ",ind_type);

    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_PEAP_AuthVerifyMIC(ubyte* app_session_handle,
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
EAP_PEAP_AuthGetMethodState(ubyte*  app_session_handle,
                      ubyte4* methodState)
{
    return OK;
}


/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS EAP_PEAP_AuthGetDecision(ubyte*  app_session_handle,
                                  ubyte4* decision)
{
    return OK;
}

/*------------------------------------------------------------------*/

static MSTATUS
eap_PEAPauthSendIdentityRequest(eapPEAPCB *eapPEAPCb);

/*------------------------------------------------------------------*/

/*! Build and send a result TLV packet.
This function builds a result TLV packet based on the specified $intResult$ value
and sends it to a peer.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_AUTH__$
- $__ENABLE_DIGICERT_EAP_PEAP__$

#Include %file:#&nbsp;&nbsp;eap_peap.h

\param eapHdl       EAP-PEAP session handle returned from EAP_PEAPinitSession.
\param intResult    1 to specify a success TLV; any other value to specify a failure TLV.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_PEAPSendResultTlv(ubyte * eapHdl, ubyte2 intResult)
{
    eapPEAPCB *  eapCb = (eapPEAPCB *)eapHdl;
    eapMethodType methodType;
    eapMethodState methodState;
    eapMethodDecision decision;

    MSTATUS status;

    ubyte buf[6];
    ubyte4 length;
    status = EAP_PEAPBuildResultTlv(intResult, buf, &length);

    methodType = EAP_TYPE_TLV;

    if (intResult == 1)
    {
        eapCb->eapStatus = EAP_PEAP_EAP_SUCCESS;
        methodState = EAP_METHOD_STATE_END;
        decision = EAP_METHOD_DECISION_SUCCESS;
    }
    else
    {
        eapCb->eapStatus = EAP_PEAP_EAP_FAILURE;
        methodState = EAP_METHOD_STATE_DONE;
        decision = EAP_METHOD_DECISION_FAILURE;
    }


    status = EAP_ulTransmit(eapCb->eapAuthSessionHdl,
                            eapCb->eapPEAPparam.instanceId,
                            methodType, EAP_CODE_REQUEST,
                            methodState, decision, buf,
                            length);
    return status;
}

/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_PEAPauthCreateSession(eapPEAPCB * eapPEAPCb)
{
    eapMethodDef_t methodDef;
    eapSessionConfig_t sessionConfig;
    MSTATUS status = OK;

    if (NULL == eapPEAPCb->eapAuthSessionHdl)
    {
        /* create a new session */
        DIGI_MEMSET((ubyte *)&methodDef, 0, sizeof(eapMethodDef_t));
        methodDef.method_type = EAP_TYPE_NONE;
        methodDef.funcPtr_ulReceiveCallback =  EAP_PEAP_AuthReceivePktCallback;
        methodDef.funcPtr_llTransmitPacket = EAP_PEAP_llTransmitPktCallback;
        methodDef.funcPtr_ulReceiveIndication = EAP_PEAP_AuthReceiveIndication;
        methodDef.funcPtr_ulMICVerify =  EAP_PEAP_AuthVerifyMIC;
        methodDef.funcPtr_ulGetMethodstate = EAP_PEAP_AuthGetMethodState;
        methodDef.funcPtr_ulGetDecision = EAP_PEAP_AuthGetDecision;
        sessionConfig.eap_mtu = 1020;
        sessionConfig.eap_ul_timeout = 60;
        sessionConfig.eap_retrans_timeout = 5;
        sessionConfig.eap_max_retrans = 5;

        sessionConfig.sessionType =EAP_SESSION_TYPE_AUTHENTICATOR;

        if (OK > (status = EAP_sessionCreate((ubyte *)eapPEAPCb,
                                  eapPEAPCb->eapPEAPparam.instanceId,
                                  methodDef,
                                  sessionConfig,
                                  &eapPEAPCb->eapAuthSessionHdl)))
        {
            goto exit;
        }

        if (OK > (status = EAP_sessionEnable(eapPEAPCb->eapAuthSessionHdl, eapPEAPCb->eapPEAPparam.instanceId)))
        {
            goto exit;
        }

        status = eap_PEAPauthSendIdentityRequest(eapPEAPCb);
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_PEAP_AuthReceivePktCallback(ubyte * appSessionHdl,
                         eapMethodType type,
                         eapCode code, ubyte id,ubyte *data, ubyte4 len,
                         ubyte *opaque_data)
{
    MSTATUS status = OK;
    eapPEAPCB * eapCb = (eapPEAPCB *) appSessionHdl;
    ubyte2 pTlvLen;
    ubyte  isMandatory;
    ubyte  *pData;
    ubyte2  result;

    switch(code)
    {
        case EAP_CODE_REQUEST:
        {
            status = ERR_EAP_INVALID_CODE;
            DEBUG_ERROR(DEBUG_EAP_MESSAGE,"Invalid EAP Code",status);
            break;
        }

        case EAP_CODE_RESPONSE:
        {
            status = OK;
            break;
        }

        case EAP_CODE_SUCCESS:
        case EAP_CODE_FAILURE:
        default:
        {
            status = ERR_EAP_INVALID_CODE;
            DEBUG_ERROR(DEBUG_EAP_MESSAGE,"Invalid EAP Code",status);
            break;
        }
    }

    if (status != OK)
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
                                 &pTlvLen, (ubyte **)&pData, (ubyte *)&isMandatory);

            if (OK > status)
                goto exit;

            result = (*pData >> 8)|*(pData +1);
            if ((EAP_PEAP_RESULT_SUCCESS == result) &&
                (EAP_PEAP_EAP_SUCCESS    == eapCb->eapStatus))
            {
                /* Send  Success Indication to App Layer */
                eapCb->eapPEAPparam.ulAuthResultTransmit(eapCb->appSessionCB,EAP_AUTH_SUCCESS);
            }
            else
            {
                /* Send Failure  Indication to App Layer*/
                eapCb->eapPEAPparam.ulAuthResultTransmit(eapCb->appSessionCB,EAP_AUTH_FAILURE);
            }

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
            break;
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/


/*! Transmit packets from the authenticator to the peer through the second stage EAP stack.
This function (called by the second stage authenticator processing) transmits
packets from the authenticator to the peer through the second stage EAP stack.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_AUTH__$
- $__ENABLE_DIGICERT_EAP_PEAP__$

#Include %file:#&nbsp;&nbsp;eap_peap.h

\param eapSessionHdl    EAP-PEAP session handle returned from EAP_PEAPinitSession.
\param instanceId       EAP instance ID returned from EAP_initInstance.
\param methodType       $eapMethodType$ enumerated value for the second phase (refer to eap_proto.h).
\param code             Any of the following $eapCode$ enumerated values (see eap_proto.h):\n
\n
&bull; $EAP_CODE_REQUEST$\n
&bull; $EAP_CODE_SUCCESS$\n
&bull; $EAP_CODE_FAILURE$
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
EAP_PEAPulAuthTransmit (ubyte * eapSessionHdl,
                 ubyte4 instanceId,
                 eapMethodType  methodType,
                 eapCode  code,
                 eapMethodDecision  methodDecision,
                 eapMethodState methodState,
                 ubyte * eap_data,
                 ubyte4  eap_data_len)
{

    eapPEAPCB * eapCb = (eapPEAPCB *) eapSessionHdl;
    MSTATUS status;

    status = EAP_ulTransmit(eapCb->eapAuthSessionHdl,
                            eapCb->eapPEAPparam.instanceId,
                            methodType, code,
                            methodDecision, methodState, eap_data,
                            eap_data_len);

    return status;

}


/*------------------------------------------------------------------*/

static MSTATUS
eap_PEAPauthSendIdentityRequest(eapPEAPCB *eapPEAPCb)
{
    MSTATUS status = OK;
    /* 2nd Stage Transmit */
    status = EAP_ulTransmit(eapPEAPCb->eapAuthSessionHdl,
                             eapPEAPCb->eapPEAPparam.instanceId,
                             EAP_TYPE_IDENTITY, EAP_CODE_REQUEST,
                             EAP_METHOD_DECISION_NONE,
                             EAP_METHOD_STATE_CONT, NULL, 0);
    /* Set the receive Id for Version 0 */
    if (eapPEAPCb->eapPEAPparam.version == 0)
    {
        EAP_setId_Type(eapPEAPCb->eapAuthSessionHdl,
                       eapPEAPCb->eapPEAPparam.instanceId,
                       eapPEAPCb->recvId + 1, EAP_TYPE_IDENTITY);
    }
    return status;

}

#endif /* ((defined(__ENABLE_DIGICERT_EAP_AUTH__))&& defined(__ENABLE_DIGICERT_EAP_PEAP__)) */
