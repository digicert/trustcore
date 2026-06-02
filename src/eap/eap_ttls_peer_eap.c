/**
 * @file  eap_ttls_peer_eap.c
 * @brief EAP-TTLS peer EAP
 *
 * @details    TTLS client-side EAP processing
 * @since      1.41
 * @version    2.02 and later
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__
 *     +   \c \__ENABLE_DIGICERT_EAP_TTLS__
 *     Additionally, whether the following flag is defined determines which header
 *     files are included:
 *     +   \c \__ENABLE_DIGICERT_EAP_AUTH__
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

#if ((defined(__ENABLE_DIGICERT_EAP_PEER__)) && defined(__ENABLE_DIGICERT_EAP_TTLS__))

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/vlong.h"
#include "../common/debug_console.h"
#include "../common/sizedbuffer.h"
#include "../crypto/crypto.h"
#include "../crypto/md5.h"
#include "../common/redblack.h"
#include "../common/mudp.h"
#include "../common/random.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/cert_store.h"
#include "../ssl/ssl.h"
#include "../eap/eap.h"
#include "../eap/eap_proto.h"
/* This is necessary if AUTH and PEER */
/* both flags are enabled. */
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__))
#include "../radius/radius.h"
#include "../radius/radius_req.h"
#include "../radius/radius_resp.h"
#endif
#include "../eap/eap_ttls.h"
#include "../eap/eap_ttls_pvt.h"



/*------------------------------------------------------------------*/

extern MSTATUS
EAP_TTLS_PeerReceivePktCallback(ubyte*         app_session_handle,
                         eapMethodType  method_type,
                         eapCode        code,
                         ubyte          id,
                         ubyte*         eap_data,
                         ubyte4         eap_data_len,
                         ubyte*         opaque_data);

extern MSTATUS
EAP_TTLS_Peer_llTransmitPktCallback(ubyte*    appSessionHdl,
                          eapHdr_t* eap_hdr,
                          ubyte*    eap_data,
                          ubyte4    eap_data_len);


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_TTLS_PeerReceiveIndication(ubyte* app_session_handle,
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
EAP_TTLS_PeerVerifyMIC(ubyte* app_session_handle,
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
EAP_TTLS_PeerGetMethodState(ubyte*  app_session_handle,
                      ubyte4* methodState)
{
    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS EAP_TTLS_PeerGetDecision(ubyte*  app_session_handle,
                                  ubyte4* decision)
{
    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_TTLS_PeerReceivePktCallback(ubyte * appSessionHdl,
                         eapMethodType type,
                         eapCode code, ubyte id,ubyte *data, ubyte4 len,
                         ubyte *opaque_data)
{
    MSTATUS     status = OK;
    eapTTLSCB   *eapCb = (eapTTLSCB *) appSessionHdl;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLS_PeerReceivePktCallback: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapCb);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)" Code = ", (sbyte4)code);
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)" Type = ", (sbyte4)type);
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)" Id = ", (sbyte4)id);

    switch(code)
    {
        case EAP_CODE_RESPONSE:
        {
            status = ERR_EAP_INVALID_CODE;
            DEBUG_ERROR(DEBUG_EAP_MESSAGE,(sbyte*)"Invalid EAP Code",status);
            break;
        }

        case EAP_CODE_REQUEST:
        case EAP_CODE_SUCCESS:
        case EAP_CODE_FAILURE:
        {
            status = OK;
            break;
        }

        default:
        {
            status = ERR_EAP_INVALID_CODE;
            DEBUG_ERROR(DEBUG_EAP_MESSAGE,(sbyte*)"Invalid EAP Code",status);
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

        default:
        {
            /* Pass it to the App Layer For Processing */
            status = eapCb->eapTTLSparam.ul2ndStageReceive(eapCb->appSessionCB,
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

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_TTLSPeerInit(eapTTLSCB *eapCb)
{
    MSTATUS status = OK;
    eapMethodDef_t methodDef;
    eapSessionConfig_t sessionConfig;

    /* Peer session */
        /* create a new session */
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_TTLSPeerInit: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapCb);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    DIGI_MEMSET((ubyte *)&methodDef, 0, sizeof(eapMethodDef_t));
    methodDef.method_type = EAP_TYPE_NONE;
    methodDef.funcPtr_ulReceiveCallback   = EAP_TTLS_PeerReceivePktCallback;
    methodDef.funcPtr_llTransmitPacket    = EAP_TTLS_Peer_llTransmitPktCallback;
    methodDef.funcPtr_ulReceiveIndication = EAP_TTLS_PeerReceiveIndication;
    methodDef.funcPtr_ulMICVerify         = EAP_TTLS_PeerVerifyMIC;
    methodDef.funcPtr_ulGetMethodstate    = EAP_TTLS_PeerGetMethodState;
    methodDef.funcPtr_ulGetDecision       = EAP_TTLS_PeerGetDecision;

    sessionConfig.eap_mtu = 1020;
    sessionConfig.eap_ul_timeout = 0;/*30*/
    sessionConfig.eap_retrans_timeout = 0;
    sessionConfig.eap_max_retrans = 0;
    sessionConfig.sessionType = EAP_SESSION_TYPE_PEER;
    if (OK > (status = EAP_sessionCreate((ubyte *)eapCb,
                                         eapCb->eapTTLSparam.instanceId,
                                         methodDef,
                                         sessionConfig,
                                         &eapCb->eapSessionHdl)))
    {
        goto exit;
    }

    status = EAP_sessionEnable(eapCb->eapSessionHdl, eapCb->eapTTLSparam.instanceId);

    /* Set the Identity */
    status = EAP_setIdentity(eapCb->eapSessionHdl,
                             eapCb->eapTTLSparam.instanceId,
                             eapCb->eapTTLSparam.UserName,
                             eapCb->eapTTLSparam.UserNameLen);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern  MSTATUS
EAP_TTLS_Peer_llTransmitPktCallback(ubyte *appSessionHdl,
                          eapHdr_t *eap_hdr,
                          ubyte *eap_data,
                          ubyte4 eap_data_len)
{
    MSTATUS status = OK;

    ubyte4 responseLen;
    eapTTLSCB * eapCb = (eapTTLSCB *) appSessionHdl;
    ubyte * response;

    if (NULL == eapCb)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLS_Peer_llTransmitPktCallback: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapCb);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)" Length = ", (sbyte4)eap_data_len);

    response = MALLOC(sizeof(eapHdr_t)+eap_data_len);

    responseLen =  (sizeof(eapHdr_t)+eap_data_len);

    if (NULL == response)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(response,(ubyte *)eap_hdr,sizeof(eapHdr_t));
    DIGI_MEMCPY(response+sizeof(eapHdr_t),eap_data,eap_data_len);

    /* Encapsulate this in EAP_AVP  And Call First Stage*/
    status = EAP_TTLSEncapEAPPkt(eapCb,response, responseLen);

    if(response)
        FREE(response);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Transmit (send) an EAP response to the authenticator.
This function (called by the TTLS second stage peer processing) transmits (sends)
responses from the peer to the authenticator through the second stage EAP stack.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_TTLS__$

#Include %file:#&nbsp;&nbsp;eap_ttls.h

\param eapSessionHdl    EAP-PEAP session handle returned from EAP_PEAPinitSession.
\param instanceId       EAP instance ID returned from EAP_initInstance.
\param methodType       $eapMethodType$ enumerated value for the second phase (refer to eap_proto.h).
\param code             $EAP_CODE_RESPONSE$ (an $eapCode$ enumerated value, defined in eap_proto.h).
\param methodDecision   $eapMethodDecision$ enumerated value (refer to eap_proto.h)
\param methodState      $eapMethodState$ enumerated value (refer to eap_proto.h)
\param eap_data         Pointer to response to be transmitted.
\param eap_data_len     Number of bytes in response to be transmitted ($eap_data$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_TTLSulPeerTransmit (ubyte * eapSessionHdl,
                 ubyte4 instanceId,
                 eapMethodType  methodType,
                 eapCode  code,
                 eapMethodDecision  methodDecision,
                 eapMethodState methodState,
                 ubyte * eap_data,
                 ubyte4  eap_data_len)
{

    eapTTLSCB * eapCb = (eapTTLSCB *)eapSessionHdl;
    MSTATUS status;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSulPeerTransmit: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapCb);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)" Code = ", (sbyte4)code);
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)" Type = ", (sbyte4)methodType);
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)" State = ", (sbyte4)methodState);
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)" Decision = ", (sbyte4)methodDecision);
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)" Length = ", (sbyte4)eap_data_len);

    status = EAP_ulTransmit(eapCb->eapSessionHdl,
                                 eapCb->eapTTLSparam.instanceId,
                                 methodType, EAP_CODE_RESPONSE,
                                 methodDecision, methodState, eap_data,
                                 eap_data_len);
    if (OK > status)
        goto exit;

    if ((EAP_METHOD_STATE_DONE == methodState) &&
        (EAP_METHOD_DECISION_UNCOND_SUCC == methodDecision))
    {
        if (0 == eapCb->eapTTLSparam.version)
            eapCb->eapTTLSparam.ulAuthResultTransmit(eapCb->appSessionCB,EAP_AUTH_SUCCESS);
    }

exit:
    return status;

}

#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__)) && defined(__ENABLE_DIGICERT_EAP_TTLS__)) */

