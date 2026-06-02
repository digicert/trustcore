/**
 * @file  eap_fast_peer_eap.c
 * @brief EAP-FAST peer EAP
 *
 * @details    EAP-FAST client-side EAP processing
 * @since      1.41
 * @version    1.41 and later
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__
 *     Additionally, at least one of the following flags must be defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_FAST__
 *     +   \c \__ENABLE_DIGICERT_EAP_PEAPV2__
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

#if ((defined(__ENABLE_DIGICERT_EAP_PEER__)) && (defined(__ENABLE_DIGICERT_EAP_FAST__) || defined(__ENABLE_DIGICERT_EAP_PEAPV2__)))

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
#include "../eap/eap_fast.h"
#include "../eap/eap_fast_pvt.h"


/*------------------------------------------------------------------*/

/* prototypes */
extern MSTATUS
EAP_FAST_MD5_PeerReceivePktCallback(ubyte *app_session_handle,
                         eapMethodType  method_type,
                         eapCode        code,
                         ubyte          id,
                         ubyte*         eap_data,
                         ubyte4         eap_data_len,
                         ubyte*         opaque_data);

extern MSTATUS
EAP_FAST_Peer_llTransmitPktCallback(ubyte*    appSessionHdl,
                          eapHdr_t* eap_hdr,
                          ubyte*    eap_data,
                          ubyte4    eap_data_len);


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_FAST_PeerReceiveIndication(ubyte* app_session_handle,
                         eapIndication ind_type,
                         ubyte* data,
                         ubyte4 data_len)
{
    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_FAST_PeerVerifyMIC(ubyte* app_session_handle,
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
EAP_FAST_PeerGetMethodState(ubyte*  app_session_handle,
                      ubyte4* methodState)
{
    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS EAP_FAST_PeerGetDecision(ubyte *app_session_handle,
                                  ubyte4 *decision)
{
    return OK;
}


/*------------------------------------------------------------------*/


/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_FAST_PeerReceivePktCallback(ubyte * appSessionHdl,
                         eapMethodType type,
                         eapCode code, ubyte id,ubyte *data, ubyte4 len,
                         ubyte *opaque_data)
{
    MSTATUS     status = OK;
    eapFASTCB   *eapCb = (eapFASTCB *) appSessionHdl;
    ubyte2      pTlvLen;
    ubyte       isMandatory;
    ubyte       *pData;
    ubyte2      result;

    switch(code)
    {
        case EAP_CODE_RESPONSE:
        {
            status = ERR_EAP_INVALID_CODE;
            DEBUG_ERROR(DEBUG_EAP_MESSAGE,"Invalid EAP Code",status);
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

        default:
        {
            /* Pass it to the App Layer For Processing */
            status = eapCb->eapFASTparam.ul2ndStageReceive(eapCb->appSessionCB,
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

/*! Get an EAP-FAST session's second stage EAP session handle.
This function retrieves the EAP-FAST second stage handle. (In the first stage,
TLS is negotiated with EAP payload messaging. In the second stage, the method,
such as MS-CHAP-V2, is negotiated over the already secure TLS channel.)

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_FAST__$
- $__ENABLE_DIGICERT_EAP_PEAPV2__$

#Include %file:#&nbsp;&nbsp;eap_fast.h

\param eapCb            EAP-FAST session handle returned from EAP_FASTinitSession.
\param eapSessionHdl    On return, pointer to EAP-FAST second stage session handle.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_FASTPeerGetSessionHdl(ubyte *eapCb, ubyte **eapSessionHdl)
{
    eapFASTCB *eapFastCb = (eapFASTCB *)eapCb;

    *eapSessionHdl = eapFastCb->eapSessionHdl;

    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_FASTPeerInit(ubyte *eapFastCb)
{
    MSTATUS status = OK;
    eapMethodDef_t methodDef;
    eapSessionConfig_t sessionConfig;
    eapFASTCB *eapCb = (eapFASTCB *)eapFastCb;

    /* Peer session */
    /* create a new session */
    DIGI_MEMSET((ubyte *)&methodDef, 0, sizeof(eapMethodDef_t));
    methodDef.method_type = EAP_TYPE_NONE;
    methodDef.funcPtr_ulReceiveCallback = EAP_FAST_PeerReceivePktCallback;
    methodDef.funcPtr_llTransmitPacket = EAP_FAST_Peer_llTransmitPktCallback;
    methodDef.funcPtr_ulReceiveIndication = EAP_FAST_PeerReceiveIndication;
    methodDef.funcPtr_ulMICVerify = EAP_FAST_PeerVerifyMIC;
    methodDef.funcPtr_ulGetMethodstate = EAP_FAST_PeerGetMethodState;
    methodDef.funcPtr_ulGetDecision = EAP_FAST_PeerGetDecision;

    sessionConfig.eap_mtu = 1020;
    sessionConfig.eap_ul_timeout = 30;
    sessionConfig.eap_retrans_timeout = 0;
    sessionConfig.eap_max_retrans = 0;
    sessionConfig.sessionType = EAP_SESSION_TYPE_PEER;
    if (OK > (status = EAP_sessionCreate((ubyte *)eapCb,
                              eapCb->eapFASTparam.instanceId,
                              methodDef,
                              sessionConfig,
                              &eapCb->eapSessionHdl)))
    {
        goto exit;
    }

    status = EAP_sessionEnable(eapCb->eapSessionHdl, eapCb->eapFASTparam.instanceId);

    eapCb->method_count++;
exit:
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern  MSTATUS
EAP_FAST_Peer_llTransmitPktCallback(ubyte *appSessionHdl,
                          eapHdr_t *eap_hdr,
                          ubyte *eap_data,
                          ubyte4 eap_data_len)
{
    ubyte4      responseLen;
    eapFASTCB*  eapCb = (eapFASTCB *) appSessionHdl;
    ubyte*      response = NULL;
    MSTATUS     status = OK;

    if (NULL == eapCb)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    response = MALLOC(sizeof(eapHdr_t)+eap_data_len);

    responseLen =  (sizeof(eapHdr_t)+eap_data_len);

    if (NULL == response)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(response,(ubyte *)eap_hdr,sizeof(eapHdr_t));
    DIGI_MEMCPY(response+sizeof(eapHdr_t),eap_data,eap_data_len);

    /* Encapsulate this in EAP TLV  And Call First Stage*/

    status = EAP_FASTEncapEAPPkt((ubyte *)eapCb,response, responseLen);

exit:
    if (response)
        FREE(response);

    return status;
}


/*------------------------------------------------------------------*/

/*! Delete an EAP-FAST peer second stage stack.
This function deletes an EAP-FAST peer second stage stack.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_FAST__$
- $__ENABLE_DIGICERT_EAP_PEAPV2__$

#Include %file:#&nbsp;&nbsp;eap_fast.h

\param eapFASTCb    EAP-FAST session handle returned from EAP_FASTinitSession.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_FASTulPeerSessionDelete(ubyte *eapFASTCb)
{
    eapFASTCB *eapCb = (eapFASTCB *)eapFASTCb;
    MSTATUS   status;

    status = EAP_sessionDelete(eapCb->eapSessionHdl,
                               eapCb->eapFASTparam.instanceId);
    return status;
}


/*------------------------------------------------------------------*/

/*! Transmit packets from peer to authenticator during second stage negotiation.
This function transmits packets from the peer to the authenticator during second
stage negotiation.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_FAST__$
- $__ENABLE_DIGICERT_EAP_PEAPV2__$

#Include %file:#&nbsp;&nbsp;eap_fast.h

\param eapSessionHdl    EAP-FAST session handle returned from EAP_FASTinitSession.
\param instanceId       Instance ID.
\param methodType       $eapMethodType$ enumerated value for the second phase (see eap_proto.h).
\param code             $EAP_CODE_RESPONSE$ (an $eapCode$ enumerated values defined in eap_proto.h).
\param methodDecision   $eapMethodDecision$ enumerated value (see eap_proto.h).
\param methodState      $eapMethodState$ enumerated value (see eap_proto.h).
\param eap_data         Pointer to EAP packet to be transmitted.
\param eap_data_len     Number of bytes in EAP packet to be transmitted ($eap_data$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_FASTulPeerTransmit (ubyte *eapSessionHdl,
                 ubyte4 instanceId,
                 eapMethodType  methodType,
                 eapCode  code,
                 eapMethodDecision  methodDecision,
                 eapMethodState methodState,
                 ubyte * eap_data,
                 ubyte4  eap_data_len)
{
    eapFASTCB *eapCb = (eapFASTCB *)eapSessionHdl;
    MSTATUS   status;

    status = EAP_ulTransmit(eapCb->eapSessionHdl,
                                 eapCb->eapFASTparam.instanceId,
                                 methodType, code,
                                 methodDecision, methodState, eap_data,
                                 eap_data_len);
    return status;
}

#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__)) && defined(__ENABLE_DIGICERT_EAP_FAST__)) */
