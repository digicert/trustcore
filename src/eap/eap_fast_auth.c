/**
 * @file  eap_fast_auth.c
 * @brief EAP-FAST authenticator
 *
 * @details    EAP-FAST server-side functions
 * @since      1.41
 * @version    1.41 and later
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_AUTH__
 *     Additionally, at least one of the following flags (or set of flags) must be defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_FAST__ and one of the asynchronous SSL flags (\c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__ or \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
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

#if ((defined(__ENABLE_DIGICERT_EAP_AUTH__)) && ( ( defined(__ENABLE_DIGICERT_EAP_FAST__) && (defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__) )  ) || defined(__ENABLE_DIGICERT_EAP_PEAPV2__)))

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
#include "../eap/eap_fast.h"
#include "../eap/eap_fast_pvt.h"


/*------------------------------------------------------------------*/

extern MSTATUS
EAP_FAST_Auth_llTransmitPktCallback(ubyte*    appSessionHdl,
                          eapHdr_t* eap_hdr,
                          ubyte*    eap_data,
                          ubyte4    eap_data_len);


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_FAST_AuthReceiveIndication(ubyte* app_session_handle,
                         eapIndication ind_type,
                         ubyte* data,
                         ubyte4 data_len)
{
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "EAP_FAST_MD5_AuthReceiveIndication : Received Indication ",ind_type);

    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_FAST_AuthVerifyMIC(ubyte* app_session_handle,
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
EAP_FAST_AuthGetMethodState(ubyte*  app_session_handle,
                      ubyte4* methodState)
{
    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS EAP_FAST_AuthGetDecision(ubyte*  app_session_handle,
                                  ubyte4* decision)
{
    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern  MSTATUS
EAP_FAST_Auth_llTransmitPktCallback(ubyte *appSessionHdl,
                          eapHdr_t* eap_hdr,
                          ubyte*    eap_data,
                          ubyte4    eap_data_len)
{
    MSTATUS     status = OK;
    ubyte4      responseLen;
    eapFASTCB   *eapCb = (eapFASTCB *) appSessionHdl;
    ubyte       *response;

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

    /* Encapsulate this in EAP_TLV  And Call First Stage*/

    status = EAP_FASTEncapEAPPkt((ubyte *)eapCb, response, responseLen);

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_fast_authSendIdentityRequest(eapFASTCB *eapCb)
{
    MSTATUS status = OK;
    status = EAP_ulTransmit(eapCb->eapAuthSessionHdl,
                            eapCb->eapFASTparam.instanceId,
                             EAP_TYPE_IDENTITY, EAP_CODE_REQUEST,
                             EAP_METHOD_DECISION_NONE,
                             EAP_METHOD_STATE_CONT, NULL, 0);
    return status;

}


/*------------------------------------------------------------------*/

/*! Get an EAP-FAST session's second stage EAP session handle.
This function retrieves the specified EAP-FAST session's second stage EAP session
handle.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_AUTH__$

Additionally, at least one of the following flags (or set of flags) must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_FAST__$ and one of the asynchronous SSL flags ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$ or $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)
- $__ENABLE_DIGICERT_EAP_PEAPV2__$

#Include %file:#&nbsp;&nbsp;eap_fast.h

\param eapCb                EAP-FAST session handle returned from EAP_FASTinitSession.
\param eapAuthSessionHdl    On return, pointer to EAP-FAST second stage session handle.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_FASTAuthGetSessionHdl(ubyte *eapCb, ubyte **eapAuthSessionHdl)
{
    eapFASTCB *eapFastCb = (eapFASTCB *)eapCb;

    *eapAuthSessionHdl = eapFastCb->eapAuthSessionHdl;
    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_FAST_AuthReceivePktCallback(ubyte * appSessionHdl,
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

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_FASTAuthInit(ubyte *eapFastCb)
{
    eapMethodDef_t methodDef;
    eapSessionConfig_t sessionConfig;
    MSTATUS status = OK;
    eapFASTCB *eapCb = (eapFASTCB *)eapFastCb;

    /* create a new session */
    DIGI_MEMSET((ubyte *)&methodDef, 0, sizeof(eapMethodDef_t));
    methodDef.method_type = EAP_TYPE_NONE;
    methodDef.funcPtr_ulReceiveCallback = EAP_FAST_AuthReceivePktCallback;
    methodDef.funcPtr_llTransmitPacket = EAP_FAST_Auth_llTransmitPktCallback;
    methodDef.funcPtr_ulReceiveIndication = EAP_FAST_AuthReceiveIndication;
    methodDef.funcPtr_ulMICVerify =  EAP_FAST_AuthVerifyMIC;
    methodDef.funcPtr_ulGetMethodstate = EAP_FAST_AuthGetMethodState;
    methodDef.funcPtr_ulGetDecision = EAP_FAST_AuthGetDecision;
    sessionConfig.eap_mtu = 1020;
    sessionConfig.eap_ul_timeout = 60;
    sessionConfig.eap_retrans_timeout = 10005;
    sessionConfig.eap_max_retrans = 5;

    sessionConfig.sessionType = EAP_SESSION_TYPE_AUTHENTICATOR;

    if (OK > (status = EAP_sessionCreate((ubyte *)eapCb,
                                  eapCb->eapFASTparam.instanceId,
                                  methodDef,
                                  sessionConfig,
                                  &eapCb->eapAuthSessionHdl)))
    {
        goto exit;
    }

    if (OK > (status = EAP_sessionEnable(eapCb->eapAuthSessionHdl,
                                         eapCb->eapFASTparam.instanceId)))
    {
        goto exit;
    }
    eapCb->method_count++;
exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Send an $Identity$ request to the peer.
This function (called by the authenticator) sends an identity request to the
peer during the second phase of EAP-FAST.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_AUTH__$

Additionally, at least one of the following flags (or set of flags) must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_FAST__$ and one of the asynchronous SSL flags ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$ or $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)
- $__ENABLE_DIGICERT_EAP_PEAPV2__$

#Include %file:#&nbsp;&nbsp;eap_fast.h

\param eapFastCb    EAP-FAST session handle returned from EAP_FASTinitSession.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_FASTAuthInit2(ubyte *eapFastCb)
{
    MSTATUS status = OK;
    eapFASTCB *eapCb = (eapFASTCB *)eapFastCb;

    status = eap_fast_authSendIdentityRequest(eapCb);
    return status;
}


/*------------------------------------------------------------------*/

/*! Delete an EAP-FAST authenticator second stage stack.
This function deletes an EAP-FAST authenticator second stage stack.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_AUTH__$

Additionally, at least one of the following flags (or set of flags) must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_FAST__$ and one of the asynchronous SSL flags ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$ or $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)
- $__ENABLE_DIGICERT_EAP_PEAPV2__$

#Include %file:#&nbsp;&nbsp;eap_fast.h

\param eapFASTCb    EAP-FAST session handle returned from EAP_FASTinitSession.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_FASTulAuthSessionDelete(ubyte *eapFASTCb)
{
    eapFASTCB *eapCb = (eapFASTCB *)eapFASTCb;
    MSTATUS status;

    status = EAP_sessionDelete(eapCb->eapAuthSessionHdl, eapCb->eapFASTparam.instanceId);
    return status;
}


/*------------------------------------------------------------------*/

/*! Transmit packets from authenticator to peer during second stage negotiation.
This function transmits packets from the authenticator to the peer during second
stage negotiation.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_AUTH__$

Additionally, at least one of the following flags (or set of flags) must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_FAST__$ and one of the asynchronous SSL flags ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$ or $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)
- $__ENABLE_DIGICERT_EAP_PEAPV2__$

#Include %file:#&nbsp;&nbsp;eap_fast.h

\param eapSessionHdl    EAP-FAST session handle returned from EAP_FASTinitSession.
\param instanceId       Instance ID.
\param methodType       $eapMethodType$ enumerated value for the second phase (see eap_proto.h).
\param code             Any of the following $eapCode$ enumerated values (defined in eap_proto.h):\n
\n
&bull; $EAP_CODE_REQUEST$\n
&bull; $EAP_CODE_SUCCESS$\n
&bull; $EAP_CODE_FAILURE$\n
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
EAP_FASTulAuthTransmit (ubyte *eapSessionHdl,
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

    status = EAP_ulTransmit(eapCb->eapAuthSessionHdl,
                                 eapCb->eapFASTparam.instanceId,
                                 methodType, code,
                                 methodDecision, methodState, eap_data,
                                 eap_data_len);
    if (OK > status)
        goto exit;

    if ((EAP_METHOD_STATE_DONE == methodState) &&
        (EAP_METHOD_DECISION_UNCOND_SUCC == methodDecision))
    {
        status = eapCb->eapFASTparam.ulAuthResultTransmit(eapCb->appSessionCB,
                                                 eapCb->crypto_binding_verified,
                                                 EAP_CODE_SUCCESS);
    }

exit:
    return status;
}

#endif /* ((defined(__ENABLE_DIGICERT_EAP_AUTH__))&& defined(__ENABLE_DIGICERT_EAP_FAST__)) */
