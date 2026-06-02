/**
 * @file  eap_ttls.c
 * @brief EAP-TTLS method implementation
 *
 * @details    EAP Tunneled TLS
 * @since      1.41
 * @version    2.02 and later
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_TTLS__
 *     Additionally, at least one flag in each of the following flag pairs must be defined in moptions.h:
 *     +   Enable EAP peer/authenticator (\c \__ENABLE_DIGICERT_EAP_PEER__, \c \__ENABLE_DIGICERT_EAP_AUTH__)
 *     +   Enable asynchronous SSL client/server (\c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__, \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
 *     Whether the following flag is defined determines which functions are enabled:
 *     +   \c \__ENABLE_DIGICERT_INNER_APP__
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

#if ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) && (defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)))

#if (defined(__ENABLE_DIGICERT_EAP_TTLS__))

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/vlong.h"
#include "../common/debug_console.h"
#include "../common/sizedbuffer.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/md5.h"
#include "../common/redblack.h"
#include "../common/timer.h"
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__))
#include "../radius/radius.h"
#if defined(__ENABLE_DIGICERT_RADIUS_CLIENT__)
#include "../radius/radius_req.h"
#include "../radius/radius_resp.h"
#endif
#endif
#include "../crypto/cert_store.h"
#include "../ssl/ssl.h"
#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_auth.h"
#include "../eap/eap_tls.h"
#include "../eap/eap_md5.h"
#include "../eap/eap_mschapv2.h"
#include "../eap/eap_ttls.h"
#include "../eap/eap_ttls_pvt.h"
#include "../eap/eap_avp.h"
#include "../eap/eap_session.h"
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_RADIUS_CLIENT__))
#include "../eap/eap_radius.h"
#endif


/*------------------------------------------------------------------*/

#define TTLS_NAS_PORT  5
#define TTLS_NAS_PORT_TYPE_IEEE_802_11 19
#define SSL_ALERT                           (21)
#define SSL_HANDSHAKE                       (22)
#define SSL_APPLICATION_DATA                (23)
#define SSL_INNER_APPLICATION               (24)


/*------------------------------------------------------------------*/

/* prototypes */
static MSTATUS eap_TTLSsendPendingBytes(eapTTLSCB *tlscon, ubyte **eapRespData, ubyte4 *eapRespLen);
static MSTATUS eap_ttlsVerifyInterFinished(eapTTLSCB * eapCb,ubyte * data, ubyte4 len);
static MSTATUS eap_ttlsVerifyFinalFinished(eapTTLSCB * eapCb,ubyte * data, ubyte4 len);

#ifdef __ENABLE_DIGICERT_IPV6__
#define GET_MOC_IPADDR4(_a) ((_a) ? (_a)->uin.addr : 0)
#else
#ifndef GET_MOC_IPADDR4
#define GET_MOC_IPADDR4(_a) _a
#endif
#endif


/*------------------------------------------------------------------*/

/*! Process second stage packets.
This function (typically called from the TTLS application) processes second
stage packets received after the first stage TLS connection is established.
Second stage packet processing includes any required reassembly.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TTLS__$

Additionally, for each of the following flag pairs at least one of the pair must be defined in moptions.h:
- Enable EAP peer/authenticator ($__ENABLE_DIGICERT_EAP_PEER__$, $__ENABLE_DIGICERT_EAP_AUTH__$)
- Enable asynchronous SSL client/server ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$, $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)

#Include %file:#&nbsp;&nbsp;eap_ttls.h

\param eapTTLSCb    EAP-TTLS session handle returned from EAP_TTLSinitSession.
\param pkt          Pointer to input data (packet).
\param pktLen       Number of bytes of input data ($pkt$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_TTLSFormSendPacket
\sa EAP_TTLSSendData

*/
extern MSTATUS
EAP_TTLSreceiveLLPacket(void * eapTTLSCb,ubyte *pkt,ubyte4 pktLen)
{
    eapTTLSCB* tlscon = (eapTTLSCB *)eapTTLSCb;
    ubyte*     eapRespData = NULL;
    ubyte4     eapRespLen;
    ubyte*     innerBuf = NULL;
    ubyte4     innerBufLen = 0;
    ubyte*     eapClearRespData = NULL;
    ubyte4     eapClearRespLen =0;
    ubyte*     eapRemData = NULL;
    ubyte4     eapRemLen;
    /* 1st Byte is Method, 2nd Byte is Flag */
    ubyte      tlsFlags = 0;
    /* Depending on Length Flag, this could vary */
    ubyte      *tlsData = NULL;
    ubyte4     tlsLength = 0;
    /*intBoolean isTlsPkt = FALSE;*/
    ubyte      tlsType = 0;
    MSTATUS    status1 = OK ;
    MSTATUS    status = OK;

    /* We can recv 3 kinds of messages */
    /* Regular Message with L Flag */
    /* Frag Message with L & M Flag */
    /* Frag Message with  M Flag */
    /* Last Frag Message with  0  as Flag */
    /* Frag ACK Message Len ==1   */

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSreceiveLLPacket: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, tlscon);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    if (!tlscon)
    {
        status = ERR_EAP_TLS_SESSION_NOT_FOUND;
        goto exit;
    }

    /*Initial Packet Generated by the TTLS App  */
    if (0 == pktLen)
        goto process;

    if (pkt)
    {
        tlsFlags = *(pkt+1);
        tlsData  = pkt +2;
        tlsLength = pktLen  - 2;
    }

    if (0 == tlscon->ttls_frag_flag)
    {
        /* its an ACK or Other side has recd full pkt . */
        if (1 == pktLen || 2 == pktLen)
        {
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" Received Completion ACK");
            if (EAP_METHOD_TYPE_MSCHAPV2 == tlscon->eapTTLSparam.methodType)
            {
                if (EAP_TTLS_MSCHAPV2_SUCCESS == tlscon->msChapV2Status)
                {
                    if (0 == tlscon->eapTTLSparam.version)
                        tlscon->eapTTLSparam.ulAuthResultTransmit(tlscon->appSessionCB,EAP_AUTH_SUCCESS);
                    goto exit;
                }
            }

            goto exit;
        }

        if ((tlsFlags & EAP_TLS_LENGTH_FLAG))
        {
            /* Check the Length */
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Received TTLS Pkt, Length ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, tlsLength);
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

            if (tlsLength <= EAP_TLS_LENGTH_BYTES)
            {
                status = ERR_EAP_TLS_INVALID_LEN;
                goto exit;
            }

            /* Copy The length Over */
            DIGI_MEMCPY((ubyte *) &tlscon->ttls_data_recv_total_len, tlsData, EAP_TLS_LENGTH_BYTES);
            tlsData  += EAP_TLS_LENGTH_BYTES;
            tlsLength-= EAP_TLS_LENGTH_BYTES;
            tlscon->ttls_data_recv_total_len = DIGI_NTOHL((ubyte *)&tlscon->ttls_data_recv_total_len) ;

            if ((tlsFlags & EAP_TLS_MORE_FLAG))
            {
               /* Move it to the buffer */
               DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" Initial TTLS Fragment");
               tlscon->ttls_data_recv = MALLOC(tlscon->ttls_data_recv_total_len);

               if (NULL == tlscon->ttls_data_recv)
               {
                   status = ERR_MEM_ALLOC_FAIL;
                   goto exit;
               }

               DIGI_MEMCPY(tlscon->ttls_data_recv,tlsData,tlsLength);
               tlscon->ttls_data_recv_len = tlsLength;
               tlscon->ttls_frag_flag = EAP_TTLS_FRAG_FLAG_RECV;
               /* Send ACK Just the Flag == Version */
               eapRespLen = 1;
               eapRespData = (ubyte *) MALLOC(eapRespLen);
               if (NULL == eapRespData)
               {
                   status = ERR_MEM_ALLOC_FAIL;
                   goto exit;
               }
               *eapRespData = tlscon->eapTTLSparam.version;
               status = tlscon->eapTTLSparam.ulTransmit(tlscon->appSessionCB,
                                                eapRespData,eapRespLen,TRUE);
               goto exit;
            }
        }
    }
    else
    {
        if (1 == pktLen || 2 == pktLen) /*its an ACK.. Send Pending Bytes */
        {
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" Received ACK, Send Pending Bytes");
            if (EAP_TTLS_FRAG_FLAG_SEND == tlscon->ttls_frag_flag)
            {
                status = eap_TTLSsendPendingBytes(tlscon,
                                                  &eapRespData, &eapRespLen);
                if (OK > status)
                    goto exit;

                status = tlscon->eapTTLSparam.ulTransmit(tlscon->appSessionCB,
                                                 eapRespData,eapRespLen,TRUE);
                goto exit;
            }
            else
            {
                /* getting an ACK when we've already sent all the data.? */
                 status = ERR_EAP_TLS_NO_DATA_TO_SEND;
                 goto exit;
            }
        }
        else
        {
            if (EAP_TTLS_FRAG_FLAG_RECV == tlscon->ttls_frag_flag)
            {
                /* coallese packets..  */
                if (tlsLength + tlscon->ttls_data_recv_len >= tlscon->ttls_data_recv_total_len)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" Received Last Fragment, Processing");
                    /*Should be the last Fragment */
                    if ((tlsFlags & EAP_TLS_MORE_FLAG))
                    {
                        /* We seem to be overshootingt the total length */
                        status = ERR_EAP_TLS_INVALID_LEN;
                        goto exit;
                    }

                    if ((tlsFlags & EAP_TLS_LENGTH_FLAG))
                    {
                        tlsData  += EAP_TLS_LENGTH_BYTES;
                        tlsLength-= EAP_TLS_LENGTH_BYTES;
                    }

                    DIGI_MEMCPY(tlscon->ttls_data_recv+tlscon->ttls_data_recv_len,
                           tlsData,tlsLength);
                    tlscon->ttls_data_recv_len += tlsLength;
                    tlscon->ttls_frag_flag = 0;
                }
                else
                {
                    /* SHoudl have the more flag set */
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" Received Fragment, sending ACK");
                    if (!(tlsFlags & EAP_TLS_MORE_FLAG))
                    {
                        status = ERR_EAP_TLS_INVALID_FLAG;
                        goto exit;
                    }

                    if ((tlsFlags & EAP_TLS_LENGTH_FLAG))
                    {
                        tlsData  += EAP_TLS_LENGTH_BYTES;
                        tlsLength-= EAP_TLS_LENGTH_BYTES;
                    }

                    DIGI_MEMCPY(tlscon->ttls_data_recv+tlscon->ttls_data_recv_len,
                           tlsData,tlsLength);
                    tlscon->ttls_data_recv_len += tlsLength;
                    /*Send ACK */
                    eapRespLen = 1;

                    eapRespData = (ubyte *) MALLOC(eapRespLen);
                    if (NULL == eapRespData)
                    {
                        status = ERR_MEM_ALLOC_FAIL;
                        goto exit;
                    }
                    *eapRespData = tlscon->eapTTLSparam.version;
                    status = tlscon->eapTTLSparam.ulTransmit(tlscon->appSessionCB,
                                                 eapRespData,eapRespLen,TRUE);
                    goto exit;
                }
            }
        }
    }

    if ((tlscon->ttls_data_recv) && (tlscon->ttls_data_recv_total_len))
    {
      /* First Decrypt the data packet */
        tlsType = *tlscon->ttls_data_recv;
        /*if (tlsType != SSL_APPLICATION_DATA)
            isTlsPkt = TRUE;*/
        status = EAP_TLSRecvData((ubyte *)tlscon, tlscon->eapTTLSparam.tls_con,
                                 tlscon->ttls_data_recv,
                                 tlscon->ttls_data_recv_total_len,
                                 &eapClearRespData, &eapClearRespLen,
                                 &eapRemData, &eapRemLen);

        FREE(tlscon->ttls_data_recv);
        tlscon->ttls_data_recv = NULL;
        tlscon->ttls_data_recv_total_len = 0;
        tlscon->ttls_data_recv_len = 0;

        if (OK > status)
            goto exit;
    }
    else
    {
        if ((pkt) && (pktLen))
        {
            /* Data Starts an Offset 6 (TTLSByte,Flag Byte,Length 4 Bytes */
            tlsType = *tlsData;
            /*if (tlsType != SSL_APPLICATION_DATA)
                isTlsPkt = TRUE;*/
            status = EAP_TLSRecvData((ubyte *)tlscon,
                                     tlscon->eapTTLSparam.tls_con,
                                     tlsData,tlsLength,
                                     &eapClearRespData, &eapClearRespLen,
                                     &eapRemData, &eapRemLen);
            if (OK > status)
                goto exit;
        }
    }

process:

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" TLS Record Type ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, tlsType);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    if (SSL_ALERT == tlsType)
    {
        sbyte4  alertClass;
        /*sbyte4  alertId;*/

        if (2 != eapClearRespLen)
        {
            status = ERR_SSL_PROTOCOL_BAD_LENGTH;
            goto exit;
        }

        alertClass = eapClearRespData[0];
        /*alertId    = eapClearRespData[1];*/

        if (SSLALERTLEVEL_WARNING == alertClass)
            status = ERR_SSL_WARNING_ALERT;
        else
            status = ERR_SSL_FATAL_ALERT;

        goto exit;
    }

    if (SSL_HANDSHAKE == tlsType)
    {
        /* Session Resumption */
        /* Inform the App about this  App to harvest data Out from the Send Buffer*/
        status = ERR_EAP_TLS_RECEIVED_HANDSHAKE;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_INNER_APP__
    if (SSL_INNER_APPLICATION == tlsType)
    {
        InnerAppType innerAppType;
        ubyte4  innerLen;

        /* Received Inner Application data for TTLS Version 1*/
        /* Check App Msg Type */
        if (4 > eapClearRespLen)
        {
            status = ERR_EAP_TTLS_BAD_LENGTH;
            goto exit;
        }

        innerLen = (ubyte4)eapClearRespData[1] << 16 |
                   (ubyte4)eapClearRespData[2] << 8 |
                   (ubyte4)eapClearRespData[3] ;

        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" INNER LEN");
        DEBUG_INT(DEBUG_EAP_MESSAGE, innerLen);
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

        innerAppType = eapClearRespData[0];

        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" INNER APPLICATION TYPE ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, innerAppType);
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

        switch (innerAppType)
        {
            case SSL_INNER_APPLICATION_DATA:
            {
                eapClearRespData = eapClearRespData + 4;
                eapClearRespLen = eapClearRespLen   - 4;
                break;
            }
            case SSL_INNER_INTER_FINISHED:
            {
                /* Verify Incoming verifyRecord */
                if ((EAP_SESSION_TYPE_AUTHENTICATOR == tlscon->eapTTLSparam.sessionType) &&
                    (EAP_TTLS_INNER_INTER != tlscon->eapInnerAppState))
                {
                    /* If We have not sent an INTER FINISHED ,
                       we shoudl not be getting one back */
                    status = ERR_EAP_TTLS_BAD_STATE;
                    goto exit;
                }

                if (16 != eapClearRespLen)
                {
                    status = ERR_EAP_TTLS_BAD_LENGTH;
                    goto exit;
                }
                status = eap_ttlsVerifyInterFinished(tlscon,eapClearRespData,
                                                     eapClearRespLen);
                if (OK > status)
                {
                    /* Send ALERT  */
                    status1 = EAP_TTLSsendAlert((ubyte *)tlscon,
                                 SSL_ALERT_INNER_APPLICATION_VERIFICATION ,
                                 SSLALERTLEVEL_FATAL);

                    tlscon->eapTTLSparam.ulAuthResultTransmit(tlscon->appSessionCB,EAP_AUTH_FAILURE);
                    goto exit;
                }

                if (EAP_SESSION_TYPE_PEER == tlscon->eapTTLSparam.sessionType)
                {
                    /* Respond Back with INTER_FINISHED */
                    status = EAP_TTLSSendData((ubyte *)tlscon,
                                     NULL,0,
                                     SSL_INNER_INTER_FINISHED,
                                     &innerBuf, &innerBufLen);
                    if (OK >  status)
                        goto exit;

                    status = EAP_TTLSFormSendPacket(tlscon,innerBuf,innerBufLen,
                                                    &eapRespData,&eapRespLen);
                    if (OK > status)
                        goto exit;

                    status = tlscon->eapTTLSparam.ulTransmit(tlscon->appSessionCB,
                                                 eapRespData,eapRespLen,TRUE);
                    goto exit;
                }
                goto exit;
            }

            case SSL_INNER_FINAL_FINISHED:
            {
                /* Verify Incoming verifyRecord */
                if ((EAP_SESSION_TYPE_AUTHENTICATOR == tlscon->eapTTLSparam.sessionType) &&
                    (EAP_TTLS_INNER_FINAL != tlscon->eapInnerAppState))
                {
                    /* If We have not sent an INTER FINISHED ,
                       we shoudl not be getting one back */
                    status = ERR_EAP_TTLS_BAD_STATE;
                    goto exit;
                }

                if (16 != eapClearRespLen)
                {
                    status = ERR_EAP_TTLS_BAD_LENGTH;
                    goto exit;
                }
                status = eap_ttlsVerifyFinalFinished(tlscon,eapClearRespData,
                                                     eapClearRespLen);
                if (OK > status)
                {
                    /* Send ALERT  */
                    status1 = EAP_TTLSsendAlert((ubyte *)tlscon,
                                 SSL_ALERT_INNER_APPLICATION_VERIFICATION ,
                                 SSLALERTLEVEL_FATAL);

                    tlscon->eapTTLSparam.ulAuthResultTransmit(tlscon->appSessionCB,EAP_AUTH_FAILURE);
                    goto exit;
                }

                if (EAP_SESSION_TYPE_PEER == tlscon->eapTTLSparam.sessionType)
                {
                    /* Respond Back with FINAL_FINISHED */
                    status = EAP_TTLSSendData((ubyte *)tlscon,
                                     NULL,0,
                                     SSL_INNER_FINAL_FINISHED,
                                     &innerBuf, &innerBufLen);
                    if (OK > status)
                        goto exit;

                    status = EAP_TTLSFormSendPacket(tlscon,innerBuf,innerBufLen,
                                                    &eapRespData,&eapRespLen);
                    if (OK > status)
                        goto exit;

                    status = tlscon->eapTTLSparam.ulTransmit(tlscon->appSessionCB,
                                                 eapRespData,eapRespLen,TRUE);
                }

                tlscon->eapTTLSparam.ulAuthResultTransmit(tlscon->appSessionCB,EAP_AUTH_SUCCESS);

                goto exit;
            }

            default:
                goto exit;
        }
    }
#endif /* __ENABLE_DIGICERT_INNER_APP__ */

    if (EAP_SESSION_TYPE_PEER == tlscon->eapTTLSparam.sessionType)
    {
        /* AVPs processed if any */
        /* The AVPS will come in only for EAP and MSCHAPv2 */
        if (EAP_METHOD_TYPE_PAP == tlscon->eapTTLSparam.methodType)
        {
            status = EAP_TTLSProcessPAPPeerRequest(eapTTLSCb);
            goto exit;
        }

        if (EAP_METHOD_TYPE_CHAP == tlscon->eapTTLSparam.methodType)
        {
            status = EAP_TTLSProcessChapPeerRequest(eapTTLSCb);
            goto exit;
        }

        if (EAP_METHOD_TYPE_MSCHAP == tlscon->eapTTLSparam.methodType)
        {
            status = EAP_TTLSProcessMSChapPeerRequest(eapTTLSCb);
            goto exit;
        }

        if (EAP_METHOD_TYPE_MSCHAPV2 == tlscon->eapTTLSparam.methodType)
        {
            if (EAP_TTLS_MSCHAPV2_INIT == tlscon->msChapV2Status)
            {
                status = EAP_TTLSProcessMSChapV2PeerRequest(eapTTLSCb);
                tlscon->msChapV2Status = EAP_TTLS_MSCHAPV2_CHALLENGE;
                goto exit;
            }
        }

        if (EAP_METHOD_TYPE_EAP == tlscon->eapTTLSparam.methodType)
        {
            if (EAP_TTLS_EAP_INIT == tlscon->eapStatus)
            {
                status = EAP_TTLSInitEAPPeerRequest(eapTTLSCb);
                tlscon->eapStatus = EAP_TTLS_EAP_IDENTITY;
                goto exit;
            }
        }
    }

    status = EAP_TTLSProcessAVP(tlscon, eapClearRespData,eapClearRespLen);

exit:
    if (eapRespData)
        FREE(eapRespData);

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSreceiveLLPacket: Error, status = ", (sbyte4)status);
    }

    if (innerBuf)
        FREE(innerBuf);
    return status;
}


/*------------------------------------------------------------------*/

static  MSTATUS
eap_TTLSsendPendingBytes(eapTTLSCB *tlscon,
                         ubyte **eapRespData, ubyte4 *eapRespLen)
{
    ubyte*  eapResponse = NULL;
    MSTATUS status = OK;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_TTLSsendPendingBytes: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, tlscon);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    if (MAX_EAP_TLS_MTU >= tlscon->ttls_data_send_remaining)
    {
        *eapRespLen = tlscon->ttls_data_send_remaining+1;
        eapResponse = (ubyte *) MALLOC(*eapRespLen);

        if (NULL == eapResponse)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        *eapResponse = tlscon->eapTTLSparam.version;
        tlscon->ttls_data_send_remaining = 0;
        tlscon->ttls_frag_flag = 0;
        FREE(tlscon->ttls_data_send);
        tlscon->ttls_data_send = NULL;
        tlscon->ttls_data_send_cur = NULL;
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Sending Last Fragment Length ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)*eapRespLen);
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");
    }
    else
    {
       /* Will need fragmentation */
        *eapRespLen = MAX_EAP_TLS_MTU + 1;
        eapResponse = (ubyte *) MALLOC(*eapRespLen);
        if (NULL == eapResponse)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        *eapResponse = EAP_TLS_MORE_FLAG| tlscon->eapTTLSparam.version;
        tlscon->ttls_data_send_remaining -= MAX_EAP_TLS_MTU;
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Sending Fragment Length ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)*eapRespLen);
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");
    }

    if (tlscon->ttls_data_send_remaining)
    {
        status = DIGI_MEMCPY((eapResponse+1),tlscon->ttls_data_send_cur,*eapRespLen-1);
        tlscon->ttls_data_send_cur+=*eapRespLen - 1;
    }
    else
    {
        /* Last Fragment */
        status = DIGI_MEMCPY(eapResponse+1,tlscon->ttls_data_send_cur,*eapRespLen-1);
    }

    *eapRespData = eapResponse;
    eapResponse = NULL;

exit:
    if (eapResponse)
        FREE(eapResponse);

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"eap_TTLSsendPendingBytes: Error, status = ", (sbyte4)status);
    }

    return status;
}


/*------------------------------------------------------------------*/

/*! Build the second stage payload.
This function (typically called by the TTLS application) builds the second stage
payload, including managing any required fragmentation, and then passes the result
back to the calling function (which will then typically call EAP_ulTransmit to
send the packet).

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TTLS__$

Additionally, for each of the following flag pairs at least one of the pair must be defined in moptions.h:
- Enable EAP peer/authenticator ($__ENABLE_DIGICERT_EAP_PEER__$, $__ENABLE_DIGICERT_EAP_AUTH__$)
- Enable asynchronous SSL client/server ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$, $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)

#Include %file:#&nbsp;&nbsp;eap_ttls.h

\param eapTTLSCb    EAP-TTLS session handle returned from EAP_TTLSinitSession.
\param pkt          Pointer to input data (payload).
\param pktLen       Number of bytes of input data (payload).
\param eapResponse  On return, pointer to resultant EAP output packet.
\param eapRespLen   On return, pointer to number of bytes in EAP output packet ($eapResponse).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_TTLSSendData
\sa EAP_TTLSreceiveLLPacket

*/
extern MSTATUS
EAP_TTLSFormSendPacket(void *eapTTLSCb,ubyte *pkt, ubyte4 pktLen,
                       ubyte **eapResponse, ubyte4 *eapRespLen)
{
    eapTTLSCB* tlscon = (eapTTLSCB *)eapTTLSCb;
    ubyte4     length;
    ubyte*     resp = NULL;
    MSTATUS    status = OK;

    *eapResponse = NULL;
    *eapRespLen = 0;

    if (!tlscon)
    {
        status = ERR_EAP_TLS_SESSION_NOT_FOUND;
        goto exit;
    }

    /*Create the TTLS Header with L or M bytes */
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSFormSendPacket: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, tlscon);

    if (MAX_EAP_TLS_MTU >= pktLen+5)
    {
        *eapRespLen = pktLen + 5;
        resp = MALLOC(*eapRespLen);

        if (NULL == resp)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        *resp = EAP_TLS_LENGTH_FLAG | (tlscon->eapTTLSparam.version & EAP_TLS_VERSION_MASK);
        length = *eapRespLen-5;
        DIGI_HTONL((ubyte*)&length,length);
        DIGI_MEMCPY((ubyte *)(resp +1),(ubyte *)&length,4);
        DIGI_MEMCPY((ubyte *)(resp +5),(ubyte *)pkt,pktLen);
        tlscon->ttls_data_send_remaining = 0;

        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" FLAG ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)*resp);
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Length ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)*eapRespLen);
    }
    else
    {
        /* Will need fragmentation */
        *eapRespLen = MAX_EAP_TLS_MTU + 5;
        resp = (ubyte *) MALLOC(*eapRespLen);
        if (NULL == resp)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        *resp = EAP_TLS_LENGTH_FLAG | EAP_TLS_MORE_FLAG | (tlscon->eapTTLSparam.version & EAP_TLS_VERSION_MASK);
        length = *eapRespLen-5;
        DIGI_HTONL((ubyte*)&length,length);
        DIGI_MEMCPY(resp +1,(ubyte *)&length,4);
        tlscon->ttls_data_send_remaining =pktLen - MAX_EAP_TLS_MTU;
        tlscon->ttls_frag_flag = EAP_TTLS_FRAG_FLAG_SEND;

        DIGI_MEMCPY(resp +5,(ubyte *)pkt+5,MAX_EAP_TLS_MTU);

        /*Cache the packet for Future Frag Data to be sent*/
        tlscon->ttls_data_send = pkt;
        tlscon->ttls_data_send_cur = pkt+MAX_EAP_TLS_MTU;

        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" FRAG-FLAG ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)*resp);
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Length ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)*eapRespLen);
    }

    *eapResponse = resp;
    resp = NULL;

exit:
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSFormSendPacket: Error, status = ", (sbyte4)status);
    }

    if (resp)
        FREE(resp);

    return status;
}


/*------------------------------------------------------------------*/

/*! Get an EAP-TTLS session's session status.
This function retrieves an EAP-TTLS session's session status.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TTLS__$

Additionally, for each of the following flag pairs at least one of the pair must be defined in moptions.h:
- Enable EAP peer/authenticator ($__ENABLE_DIGICERT_EAP_PEER__$, $__ENABLE_DIGICERT_EAP_AUTH__$)
- Enable asynchronous SSL client/server ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$, $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)

#Include %file:#&nbsp;&nbsp;TBD.

\param eapTTLSCb            EAP-TTLS session handle returned from EAP_TTLSinitSession.
\param eapSessionStatus     On return, pointer to the session's current status:
one of the $eap_ttls_eap_state$ enumerated values (defined in eap_ttls_pvt.h).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_TTLSgetSessionStatus(void * eapTTLSCb,ubyte  *eapSessionStatus)
{
    eapTTLSCB*  tlscon = (eapTTLSCB *)eapTTLSCb;
    MSTATUS     status = OK;

    if (!tlscon)
    {
        status = ERR_EAP_TLS_SESSION_NOT_FOUND;
        goto exit;
    }
    *eapSessionStatus = tlscon->sessionStatus;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Create and initialize a second stage TTLS session as a peer or passthrough authenticator.
This function (typically called by your application) creates and initializes the
second stage TTLS session as a peer or passthrough authenticator. On success,
the function returns the TTLS session handle to the application.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TTLS__$

Additionally, for each of the following flag pairs at least one of the pair must be defined in moptions.h:
- Enable EAP peer/authenticator ($__ENABLE_DIGICERT_EAP_PEER__$, $__ENABLE_DIGICERT_EAP_AUTH__$)
- Enable asynchronous SSL client/server ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$, $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)

#Include %file:#&nbsp;&nbsp;eap_ttls.h

\param appSessionCB     Application-specific session identifier.
\param eapTTLSSession   On return, pointer to EAP-TTLS session handle.
\param eapTTLSparams    Pointer to structure containing desired EAP-TTLS session
configuration settings and callback function pointers.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_TTLSSendData
\sa EAP_TTLSreceiveLLPacket
\sa EAP_TTLSdeleteSession

*/
extern MSTATUS
EAP_TTLSinitSession(ubyte *appSessionCB, ubyte **eapTTLSSession, EAP_TTLS_params *eapTTLSparams)
{
    eapTTLSCB* sessionCB = NULL;
    MSTATUS    status = OK;

    if ((NULL == eapTTLSparams) || (NULL == eapTTLSparams->ulTransmit) || (NULL == eapTTLSparams->ulAuthResultTransmit))
    {
        status = ERR_EAP_TTLS_MISSING_PARAMS;
        goto exit;
    }

    if ((EAP_SESSION_TYPE_PEER != eapTTLSparams->sessionType) &&
        (EAP_SESSION_TYPE_AUTHENTICATOR != eapTTLSparams->sessionType))
    {
        status = ERR_EAP_TTLS_MISSING_PARAMS;
        goto exit;
    }

    if (EAP_SESSION_TYPE_AUTHENTICATOR == eapTTLSparams->sessionType)
    {
        if (NULL == eapTTLSparams->ulAuthTransmit)
        {
            status = ERR_EAP_TTLS_MISSING_PARAMS;
            goto exit;
        }
    }

    if (EAP_SESSION_TYPE_PEER == eapTTLSparams->sessionType)
    {
        if (0 == eapTTLSparams->UserNameLen)
        {
            status = ERR_EAP_TTLS_MISSING_PARAMS;
            goto exit;
        }

        if (EAP_METHOD_TYPE_EAP == eapTTLSparams->methodType)
        {
            if (NULL == eapTTLSparams->ul2ndStageReceive)
            {
                status = ERR_EAP_TTLS_MISSING_PARAMS;
                goto exit;
            }
        }
    }

    sessionCB = MALLOC(sizeof(eapTTLSCB));

    if (NULL == sessionCB)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)sessionCB,0,sizeof(eapTTLSCB));

    DIGI_MEMCPY((ubyte *)&sessionCB->eapTTLSparam,(ubyte *)eapTTLSparams,
               sizeof(EAP_TTLS_params));

    *eapTTLSSession = (void *)sessionCB;
    sessionCB->appSessionCB = appSessionCB;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSinitSession: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, sessionCB);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Session Type ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, sessionCB->eapTTLSparam.sessionType);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Method Type ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, sessionCB->eapTTLSparam.methodType);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Version ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, sessionCB->eapTTLSparam.version);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSinitSession: Error, status = ", (sbyte4)status);
        if (sessionCB)
        {
            FREE(sessionCB);
            sessionCB = NULL;
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

/*! Delete a second (upper) stage EAP TTLS session.
This function deletes a second (upper) stage TTLS session.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TTLS__$

Additionally, for each of the following flag pairs at least one of the pair must be defined in moptions.h:
- Enable EAP peer/authenticator ($__ENABLE_DIGICERT_EAP_PEER__$, $__ENABLE_DIGICERT_EAP_AUTH__$)
- Enable asynchronous SSL client/server ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$, $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)

#Include %file:#&nbsp;&nbsp;eap_ttls.h

\param eapTTLSSession   EAP-TTLS session handle returned from EAP_TTLSinitSession.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_TTLSSendData
\sa EAP_TTLSreceiveLLPacket
\sa EAP_TTLSinitSession

*/
extern MSTATUS
EAP_TTLSdeleteSession(void *eapTTLSSession)
{
    /* Free any Pending Fragment Buffers */
    eapTTLSCB *tlscon = (eapTTLSCB*) eapTTLSSession;
    MSTATUS status = OK;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSdeleteSession: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, tlscon);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    if (!tlscon)
    {
        status = ERR_EAP_TLS_SESSION_NOT_FOUND;
        goto exit;
    }
    if (tlscon->ttls_data_send)
        FREE(tlscon->ttls_data_send);

    if (tlscon->ttls_data_recv)
        FREE(tlscon->ttls_data_recv);

    if ((EAP_SESSION_TYPE_PEER == tlscon->eapTTLSparam.sessionType) &&
        (tlscon->eapSessionHdl))
    {
        EAP_sessionDelete(tlscon->eapSessionHdl,tlscon->eapTTLSparam.instanceId);
    }
    else if ((EAP_SESSION_TYPE_AUTHENTICATOR == tlscon->eapTTLSparam.sessionType) &&
             tlscon->eapAuthSessionHdl)
    {
        EAP_sessionDelete(tlscon->eapAuthSessionHdl,tlscon->eapTTLSparam.instanceId);
    }

    FREE(eapTTLSSession);

exit:
    return status;
}


/*------------------------------------------------------------------*/
/****f* src/eap/EAP_TTLSProcessAVP
*
*  NAME
    *   EAP_TTLSdeleteSession : Delete the EAP TTLS Session
*  SYNOPSIS
*
*   #include "../eap/eap.h"
*   #include "../eap/eap_tls.h"
*   #include "../eap/eap_ttls.h"
*
*   extern  MSTATUS
*   EAP_TTLSProcessAVP(eapTTLSCB *eapCb, ubyte *pPkt, ubyte4 pktLen)
*
*  FUNCTION
*   Process Incoming AVPs
*
*
*  INPUTS
*    eapCb : EAP TTLS Session Handle
*    pPkt  : Incoming payload
*    pktLen: Payload Length
*
*
*  RESULT
*   Returns an error code, or OK
*  SEE ALSO
*   src/eap/EAP_TTLSSendData
*   src/eap/EAP_TTLSreceiveLLPacket
*   src/eap/EAP_TTLSFormSendPkt
*   src/eap/EAP_TTLSinitSession
*   src/eap/EAP_TTLSdeleteSession
******/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_TTLSProcessAVP(eapTTLSCB *eapCb, ubyte *pPkt, ubyte4 pktLen)
{
    ubyte* userName =NULL;
    ubyte* passWord =NULL;
    ubyte* chapPassword = NULL;
    ubyte* msChapChal = NULL;
    ubyte* msChapv2Resp = NULL;
    ubyte* msChapResp = NULL;
    ubyte* chapChal =NULL;
    ubyte* eapPkt =NULL;
    ubyte* msChapv2Success =NULL;
    ubyte4 msChapChalLen =0;
    ubyte4 msChapRespLen =0;
    ubyte4 msChapv2RespLen =0;
    ubyte4 eapPktLen =0;
    ubyte4 userNameLen= 0;
    ubyte4 passWordLen =0;
    ubyte4 msChapv2SuccessLen= 0;
    ubyte4 attributes = 0;
    ubyte4 chapChalLen =0;
    ubyte4 chapPasswordLen =0;
    ubyte  itr =0;
    ubyte  pFlags =0;
    ubyte4 pType =0;
    ubyte4 pVendorId =0;
    ubyte4 pLength =0;
    ubyte* ppValue = NULL;
    MSTATUS status = OK;

    MOC_UNUSED(chapChalLen);
    MOC_UNUSED(msChapChalLen);

    if ((NULL == pPkt) || (0 == pktLen))
        goto exit;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessAVP: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapCb);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    while (OK <= status)
    {
        status = AVP_getAttributeByIndex(pPkt, pktLen, itr,
                            &pType, &pFlags, &pVendorId,
                            &ppValue, &pLength);
        if (OK > status)
            break;

           switch (pType)
           {
               case EAP_RADIUS_ATTR_USER_NAME:
               {
               /*case RADIUS_ATTR_MSCHAP_RESPONSE:*/
                   if (EAP_RADIUS_VENDOR_ID_MS == pVendorId)
                   {
                       msChapResp = ppValue;
                       attributes |= EAP_TTLS_MSCHAP_RESPONSE_AVP;
                       msChapRespLen = pLength;
                       DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" EAP_TTLS_MSCHAP_RESPONSE_AVP");
                   }
                   else
                   {
                       userName = ppValue;
                       attributes |= EAP_TTLS_USERNAME_AVP;
                       userNameLen = pLength;
                       DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" EAP_TTLS_USERNAME_AVP");
                   }
                   break;
               }

               case EAP_RADIUS_ATTR_USER_PASSWORD:
               {
                   passWord = ppValue;
                   attributes |= EAP_TTLS_PASSWORD_AVP;
                   passWordLen = pLength;
                   DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" EAP_TTLS_PASSWORD_AVP");
                   break;
               }

               case EAP_RADIUS_ATTR_CHAP_PASSWORD:
               {
                   chapPassword = ppValue;
                   attributes |= EAP_TTLS_CHAP_PASSWORD_AVP;
                   chapPasswordLen = pLength;
                   DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" EAP_TTLS_CHAP_PASSWORD_AVP");
                   break;
               }

               case EAP_RADIUS_ATTR_CHAP_CHALLENGE:
               {
                   chapChal = ppValue;
                   attributes |= EAP_TTLS_CHAP_CHALLENGE_AVP;
                   chapChalLen = pLength;
                   DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" EAP_TTLS_CHAP_CHALLENGE_AVP");
                   break;
               }

               case EAP_RADIUS_ATTR_MSCHAP_CHALLENGE:
               {
                   if (EAP_RADIUS_VENDOR_ID_MS == pVendorId)
                   {
                       msChapChal = ppValue;
                       attributes |= EAP_TTLS_MSCHAP_CHALLENGE_AVP;
                       msChapChalLen = pLength;
                       DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" EAP_TTLS_MSCHAP_CHALLENGE_AVP");
                   }
                   break;
               }

               case EAP_RADIUS_ATTR_MSCHAPV2_RESPONSE:
               {
                   if (EAP_RADIUS_VENDOR_ID_MS == pVendorId)
                   {
                       msChapv2Resp = ppValue;
                       attributes |= EAP_TTLS_MSCHAPV2_RESPONSE_AVP;
                       msChapv2RespLen = pLength;
                       DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" EAP_TTLS_MSCHAPV2_RESPONSE_AVP");
                   }
                   break;
               }

               case EAP_RADIUS_ATTR_MSCHAPV2_SUCCESS:
               {
                   if (EAP_RADIUS_VENDOR_ID_MS == pVendorId)
                   {
                       msChapv2Success = ppValue;
                       attributes |= EAP_TTLS_MSCHAPV2_SUCCESS_AVP;
                       msChapv2SuccessLen = pLength;
                       DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" EAP_TTLS_MSCHAPV2_SUCCESS_AVP");
                   }
                   break;
               }

               case EAP_RADIUS_ATTR_EAP_MESSAGE:
               {
                   eapPkt = ppValue;
                   attributes |= EAP_TTLS_EAP_AVP;
                   eapPktLen = pLength;
                   DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" EAP_TTLS_EAP_AVP");
                   break;
               }

               default:
                   break;
           }
           itr++;
    }

    if ((attributes & EAP_TTLS_USERNAME_AVP) &&
        (attributes & EAP_TTLS_PASSWORD_AVP))
    {
        /* Call Auth PAP with Username /Password */
        eapCb->eapTTLSparam.methodType = EAP_METHOD_TYPE_PAP;
        status = EAP_TTLSProcessPAPAuthRequest(eapCb,userName, userNameLen,passWord, passWordLen);
        goto exit;
    }

    /* Call AuthChap with Username/Chap Chal/Password */
    if ((attributes & EAP_TTLS_CHAP_CHALLENGE_AVP) &&
        (attributes & EAP_TTLS_CHAP_PASSWORD_AVP)  &&
        (attributes & EAP_TTLS_USERNAME_AVP))
    {
        eapCb->eapTTLSparam.methodType = EAP_METHOD_TYPE_CHAP;
        status = EAP_TTLSProcessChapAuthRequest(eapCb,userName, userNameLen,chapPassword,chapPasswordLen,chapChal);
        goto exit;
    }

    /* if the AVPS sent are Username MSChallenge MSChapResponse then
     * its a MSCHAP Request */
    /* Call AuthChap with Username/Chap Chal/Password */
    if ((attributes & EAP_TTLS_MSCHAP_CHALLENGE_AVP) &&
        (attributes & EAP_TTLS_MSCHAP_RESPONSE_AVP)  &&
        (attributes & EAP_TTLS_USERNAME_AVP))
    {
        eapCb->eapTTLSparam.methodType = EAP_METHOD_TYPE_MSCHAP;
        status = EAP_TTLSProcessMSChapAuthRequest(eapCb,userName, userNameLen,msChapResp,msChapRespLen,msChapChal);
        goto exit;
    }

    /* if the AVPS sent are Username MSV2Challenge MSV2Password
     * then its a MSV2CHAP Request */
    /* Call AuthMSChapV2 with Username/Chap Chal/Password */
    if ((attributes & EAP_TTLS_MSCHAP_CHALLENGE_AVP) &&
        (attributes & EAP_TTLS_MSCHAPV2_RESPONSE_AVP) &&
        (attributes & EAP_TTLS_USERNAME_AVP))
    {
        eapCb->eapTTLSparam.methodType = EAP_METHOD_TYPE_MSCHAPV2;
        status = EAP_TTLSProcessMSChapV2AuthRequest(eapCb,userName, userNameLen,msChapv2Resp,msChapv2RespLen,msChapChal);
        goto exit;
    }

    /* Call AuthMSChapV2 with  Success AVP on the peer */
    if ((attributes & EAP_TTLS_MSCHAPV2_SUCCESS_AVP)  &&
        (eapCb->eapTTLSparam.methodType == EAP_METHOD_TYPE_MSCHAPV2))
    {
        status = EAP_TTLSProcessMSChapV2AuthResponse(eapCb,msChapv2Success,msChapv2SuccessLen);
        goto exit;
    }

    /* if the AVPS sent are EAP then its a EAP Request */
    if ((attributes & EAP_TTLS_EAP_AVP) &&
        (EAP_SESSION_TYPE_PEER == eapCb->eapTTLSparam.sessionType))
    {
        status = EAP_TTLSProcessEAPPeerRequest(eapCb,eapPkt,eapPktLen);
        goto exit;
    }

    if ((attributes & EAP_TTLS_EAP_AVP) &&
        (EAP_SESSION_TYPE_AUTHENTICATOR == eapCb->eapTTLSparam.sessionType))
    {
        status = EAP_TTLSProcessEAPAuthRequest(eapCb,eapPkt,eapPktLen);
        goto exit;
    }

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessAVP: Error, status = ", (sbyte4)status);
    }
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_TTLSProcessPAPAuthRequest(eapTTLSCB *eapCb,ubyte *papUsername,ubyte4 userLen,ubyte *papPassword, ubyte4 passLen)
{
    MSTATUS             status = -1;
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_RADIUS_CLIENT__))
    RADIUS_RqstRecord*  pRadiusReq;
    ubyte4 myaddr;
    MOC_UNUSED(passLen);
    MOC_UNUSED(userLen);

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLS_ProcessPAPAuthRequest: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapCb);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    /*Form a Radius Access Request  Packet and Send it */
    if (OK > (status = RADIUS_requestNew(&pRadiusReq, eapCb->eapTTLSparam.authServerId, RADIUS_CODE_ACCESS_REQUEST)))
        goto exit;
    if (OK > (status = RADIUS_requestAppendStringAttribute(pRadiusReq, RADIUS_ATTR_USER_NAME, papUsername)))
        goto exit;

    if (OK > (status = RADIUS_requestAppendUserPassword(pRadiusReq, (ubyte *)papPassword, (ubyte)DIGI_STRLEN((sbyte *)papPassword))))
        goto exit;

    myaddr = GET_MOC_IPADDR4(eapCb->eapTTLSparam.myaddr);
    if (OK > (status = RADIUS_requestAppendUByte4Attribute(pRadiusReq,
                                                           RADIUS_ATTR_NAS_IP_ADDRESS, myaddr)))
    {
        goto exit;
    }

    /* Hand it over to the App to organise the Radius Request Response */
    /* Call the Auth Transmit Function and wait for a Callback */
    status = eapCb->eapTTLSparam.ulAuthTransmit(eapCb->appSessionCB,(ubyte *)eapCb,(ubyte *)pRadiusReq,0);

exit:
    if (OK > status)
    {
        eapCb->eapTTLSparam.ulAuthResultTransmit(eapCb->appSessionCB,EAP_AUTH_FAILURE);
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessPAPAuthRequest: Error, status = ", (sbyte4)status);
    }
#endif /*(defined(__ENABLE_DIGICERT_EAP_AUTH__))*/

    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_TTLSProcessChapAuthRequest(eapTTLSCB *eapCb,ubyte *Username,ubyte4 userLen,ubyte *password, ubyte4 passLen,ubyte *challenge)
{
    MSTATUS             status = -1;
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_RADIUS_CLIENT__))
    RADIUS_RqstRecord*  pRadiusReq;
    ubyte               Challenge[17];
    sbyte4              cmp;
    ubyte4              myaddr;
    MOC_UNUSED(passLen);
    MOC_UNUSED(userLen);

    if (NULL == password)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessChapAuthRequest: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapCb);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    /* Generate Challenge based upon the TLS Random */
    if (0 == eapCb->eapTTLSparam.version)
        status = SSL_generateTLSExpansionKey(eapCb->eapTTLSparam.connectionInstance,Challenge,17,(ubyte *)TTLS_CHALLENGE_PHRASE,TTLS_CHALLENGE_PHRASE_LEN);
    else
        status = SSL_generateTLSExpansionKey(eapCb->eapTTLSparam.connectionInstance,Challenge,17,(ubyte *)TTLS_INNER_APP_CHALLENGE_PHRASE,TTLS_INNER_APP_CHALLENGE_PHRASE_LEN);

    /* Compare the Challenge and the ID received from the Other Side */
    DIGI_MEMCMP(Challenge, challenge,16,&cmp);

    if ((cmp !=0) || (Challenge[16] != password[0]))
    {
        /* Return FAILURE CODE */
        status = ERR_EAP_TTLS_INVALID_CHALLENGE;
        goto exit;
    }

    /* Form a Radius Access Request  Packet and Send it */
    if (OK > (status = RADIUS_requestNew(&pRadiusReq, eapCb->eapTTLSparam.authServerId, RADIUS_CODE_ACCESS_REQUEST)))
        goto exit;

    if (OK > (status = RADIUS_requestAppendStringAttribute(pRadiusReq, RADIUS_ATTR_USER_NAME, Username)))
        goto exit;

    /* Send, Chap Password, Challenge etc */
    if (OK > (status = RADIUS_requestAppendAttribute(pRadiusReq, RADIUS_ATTR_CHAP_PASSWORD,
                                     password, 1 + RADIUS_CHAP_DIGESTSIZE)))
    {
        goto exit;
    }

    if (OK > (status = RADIUS_requestAppendAttribute(pRadiusReq, RADIUS_ATTR_CHAP_CHALLENGE,
                                     challenge, RADIUS_CHAP_DIGESTSIZE)))
    {
        goto exit;
    }

    myaddr = GET_MOC_IPADDR4(eapCb->eapTTLSparam.myaddr);
    if (OK > (status = RADIUS_requestAppendUByte4Attribute(pRadiusReq,
                                                           RADIUS_ATTR_NAS_IP_ADDRESS, myaddr)))
    {
        goto exit;
    }

    /* Hand it over to the App to organise the Radius Request Response */
    /*Call the Auth Transmit Function and wait for a Callback */
    status = eapCb->eapTTLSparam.ulAuthTransmit(eapCb->appSessionCB,(ubyte *)eapCb,(ubyte *)pRadiusReq,0);

exit:
    if (OK > status)
    {
        eapCb->eapTTLSparam.ulAuthResultTransmit(eapCb->appSessionCB,EAP_AUTH_FAILURE);
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessChapAuthRequest: Error, status = ", (sbyte4)status);
    }
#endif /*(defined(__ENABLE_DIGICERT_EAP_AUTH__)) */

    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_TTLSProcessMSChapAuthRequest(eapTTLSCB *eapCb,ubyte *Username,ubyte4 userLen,ubyte *password, ubyte4 passLen,ubyte *challenge)
{
    MSTATUS             status = -1;
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_RADIUS_CLIENT__))
    RADIUS_RqstRecord*  pRadiusReq;
    ubyte               Challenge[9];
    sbyte4              cmp;
    ubyte*              pVSAttr = NULL;
    ubyte4              myaddr;
    MOC_UNUSED(userLen);

    if (NULL == password)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessMSChapAuthRequest: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapCb);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    /* Generate Challenge based upon the TLS Random */
    if (0 == eapCb->eapTTLSparam.version)
        status = SSL_generateTLSExpansionKey(eapCb->eapTTLSparam.connectionInstance,Challenge,9,(ubyte *)TTLS_CHALLENGE_PHRASE,TTLS_CHALLENGE_PHRASE_LEN);
    else
        status = SSL_generateTLSExpansionKey(eapCb->eapTTLSparam.connectionInstance,Challenge,9,(ubyte *)TTLS_INNER_APP_CHALLENGE_PHRASE,TTLS_INNER_APP_CHALLENGE_PHRASE_LEN);

    /* Compare the Challenge and the ID received from the Other Side */
    DIGI_MEMCMP(Challenge, challenge,8,&cmp);

    if ((cmp !=0) || (Challenge[8] != password[0]))
    {
        /* Return FAILURE CODE */
        status = ERR_EAP_TTLS_INVALID_CHALLENGE;
        goto exit;
    }

    /* Form a Radius Access Request  Packet and Send it */
    if (OK > (status = RADIUS_requestNew(&pRadiusReq, eapCb->eapTTLSparam.authServerId, RADIUS_CODE_ACCESS_REQUEST)))
        goto exit;

    if (OK > (status = RADIUS_requestAppendStringAttribute(pRadiusReq, RADIUS_ATTR_USER_NAME, Username)))
        goto exit;

    /* Send, MSChap Password, Challenge etc */
    if (OK > (status = RADIUS_newVendorSpecificAttributeBuffer(&pVSAttr, RADIUS_VENDOR_ID_MS)))
        goto exit;

    if (OK > (status = RADIUS_appendSubAttributeToAttributeBuffer(pVSAttr,
                           RADIUS_ATTR_MSCHAP_CHALLENGE, challenge, 8)))
    {
        goto exit;
    }

    if (OK > (status = RADIUS_appendSubAttributeToAttributeBuffer(pVSAttr,
                           RADIUS_ATTR_MSCHAP_RESPONSE, password, (ubyte)passLen)))
    {
        goto exit;
    }

    if (OK > (status = RADIUS_requestAppendVendorSpecificAttributeBuffer(pRadiusReq, pVSAttr)))
        goto exit;

    myaddr = GET_MOC_IPADDR4(eapCb->eapTTLSparam.myaddr);
    if (OK > (status = RADIUS_requestAppendUByte4Attribute(pRadiusReq,
                                                           RADIUS_ATTR_NAS_IP_ADDRESS, myaddr)))
    {
        goto exit;
    }

    /* Hand it over to the App to organise the Radius Request Response */
    /* Call the Auth Transmit Function and wait for a Callback */
    status = eapCb->eapTTLSparam.ulAuthTransmit(eapCb->appSessionCB,(ubyte *)eapCb,(ubyte *)pRadiusReq,0);

exit:
    if (OK > status)
    {
        eapCb->eapTTLSparam.ulAuthResultTransmit(eapCb->appSessionCB,EAP_AUTH_FAILURE);
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessMSChapAuthRequest: Error, status = ", (sbyte4)status);
    }
#endif /*(defined(__ENABLE_DIGICERT_EAP_AUTH__))*/

    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_TTLSProcessMSChapV2AuthRequest(eapTTLSCB *eapCb,ubyte *Username,ubyte4 userLen,ubyte *password, ubyte4 passLen,ubyte *challenge)
{
    MSTATUS             status = -1;
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_RADIUS_CLIENT__))
    RADIUS_RqstRecord*  pRadiusReq;
    ubyte               Challenge[17];
    sbyte4              cmp;
    ubyte*              pVSAttr = NULL;
    ubyte4              myaddr;
    MOC_UNUSED(userLen);

    if (NULL == password)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessMSChapV2AuthRequest: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapCb);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    /* Generate Challenge based upon the TLS Random */
    if (0 == eapCb->eapTTLSparam.version)
        status = SSL_generateTLSExpansionKey(eapCb->eapTTLSparam.connectionInstance,Challenge,17,(ubyte *)TTLS_CHALLENGE_PHRASE,TTLS_CHALLENGE_PHRASE_LEN);
    else
        status = SSL_generateTLSExpansionKey(eapCb->eapTTLSparam.connectionInstance,Challenge,17,(ubyte *)TTLS_INNER_APP_CHALLENGE_PHRASE,TTLS_INNER_APP_CHALLENGE_PHRASE_LEN);

    /* Compare the Challenge and the ID received from the Other Side */
    DIGI_MEMCMP(Challenge, challenge,16,&cmp);

    if ((cmp !=0) || (Challenge[16] != password[0]))
    {
        /* Return FAILURE CODE */
        status = ERR_EAP_TTLS_INVALID_CHALLENGE;
        goto exit;
    }

    eapCb->msChapV2Id = password[0];

    /* Form a Radius Access Request  Packet and Send it  */
    if (OK > (status = RADIUS_requestNew(&pRadiusReq, eapCb->eapTTLSparam.authServerId, RADIUS_CODE_ACCESS_REQUEST)))
        goto exit;

    if (OK > (status = RADIUS_requestAppendStringAttribute(pRadiusReq, RADIUS_ATTR_USER_NAME, Username)))
        goto exit;

    /* Send , MSChap Password, Challenge etc */
    if (OK > (status = RADIUS_newVendorSpecificAttributeBuffer(&pVSAttr, RADIUS_VENDOR_ID_MS)))
        goto exit;

    if (OK > (status = RADIUS_appendSubAttributeToAttributeBuffer(pVSAttr,
                           RADIUS_ATTR_MSCHAP_CHALLENGE, challenge, 16)))
    {
        goto exit;
    }

    if (OK > (status = RADIUS_appendSubAttributeToAttributeBuffer(pVSAttr,
                           RADIUS_ATTR_MSCHAPV2_RESPONSE, password, (ubyte)passLen)))
    {
        goto exit;
    }

    if (OK > (status = RADIUS_requestAppendVendorSpecificAttributeBuffer(pRadiusReq, pVSAttr)))
        goto exit;

    myaddr = GET_MOC_IPADDR4(eapCb->eapTTLSparam.myaddr);
    if (OK > (status = RADIUS_requestAppendUByte4Attribute(pRadiusReq,
                                                           RADIUS_ATTR_NAS_IP_ADDRESS, myaddr)))
    {
        goto exit;
    }

    /* Hand it over to the App to organise the Radius Request Response */
    /* Call the Auth Transmit Function and wait for a Callback */
    status = eapCb->eapTTLSparam.ulAuthTransmit(eapCb->appSessionCB,(ubyte *)eapCb,(ubyte *)pRadiusReq,0);

exit:
    if (OK > status)
    {
        eapCb->eapTTLSparam.ulAuthResultTransmit(eapCb->appSessionCB,EAP_AUTH_FAILURE);
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessMSChapV2AuthRequest: Error, status = ", (sbyte4)status);
   }
#endif /*(defined(__ENABLE_DIGICERT_EAP_AUTH__))*/

    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_TTLSProcessMSChapV2AuthResponse(eapTTLSCB *eapCb,ubyte *success, ubyte4 successLen)
{
    sbyte4  cmp;
    MSTATUS status = OK;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessMSChapV2AuthResponse: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapCb);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE,(sbyte*)" AuthResponse is");
    EAP_PrintBytes(eapCb->AuthenticatorResponse, 42);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE,(sbyte*)" Success Msg is");
    EAP_PrintBytes(success, successLen);
#endif

    if (42 == successLen)
        DIGI_MEMCMP(eapCb->AuthenticatorResponse,success,42,&cmp);
    else if (43 == successLen)  /* Some Impleentations Send the First Byte as MSCHAP ID */
    {
        if (success[0] != eapCb->msChapV2Id)
            cmp = -1;
        else
            DIGI_MEMCMP(eapCb->AuthenticatorResponse,success+1,42,&cmp);
    }
    else
        cmp = -1;

    if (cmp)
    {
        eapCb->eapTTLSparam.ulAuthResultTransmit(eapCb->appSessionCB,EAP_AUTH_FAILURE);
        status = ERR_EAP_TTLS_INVALID_MSCHAPV2_RESP;
        goto exit;
    }

    eapCb->eapTTLSparam.ulAuthResultTransmit(eapCb->appSessionCB,EAP_AUTH_SUCCESS);

    /* Send ACK with the EAPTTLS Flag Byte == 0| Version */
    if (0 == eapCb->eapTTLSparam.version)
    {
        ubyte*  eapResponse;
        ubyte4  eapRespLen = 1;

        eapResponse = (ubyte *) MALLOC(eapRespLen);
        if (NULL == eapResponse)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        *eapResponse = eapCb->eapTTLSparam.version;
        status = eapCb->eapTTLSparam.ulTransmit(eapCb->appSessionCB,
                                                eapResponse,eapRespLen,TRUE);
        FREE(eapResponse);
    }
    else /* Version 1 */
    {
        status = eapCb->eapTTLSparam.ulTransmit(eapCb->appSessionCB,0,0,FALSE);
    }

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessMSChapV2AuthResponse: Error, status = ", (sbyte4)status);
    }
    return status;
}


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_EAP_AUTH__))
static MSTATUS
eap_ttlsExtractIdentity(eapTTLSCB *eapCb, ubyte *eapPkt, ubyte4 eapPktLen)
{

    eapHdr_t *          eapHdr = (eapHdr_t *) eapPkt;
    ubyte    *          method;
    MSTATUS             status = OK;

    if (sizeof(eapHdr_t) + 1  >= eapPktLen)
    {
        status = ERR_EAP_INVALID_PKT;
        goto exit;
    }

    if (EAP_CODE_RESPONSE != eapHdr->code)
    {
        status = ERR_EAP_INVALID_PKT;
        goto exit;
    }

    method = eapPkt + sizeof(eapHdr_t);

    if (EAP_TYPE_IDENTITY == *method)
    {
       eapCb->eapTTLSparam.UserNameLen = DIGI_NTOHS(eapPkt+2) - sizeof(eapHdr_t)-1;
       DIGI_MEMCPY(eapCb->eapTTLSparam.UserName,
                  (ubyte *)(eapHdr)+sizeof(eapHdr_t)+ 1,
                  eapCb->eapTTLSparam.UserNameLen);
    }

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_TTLSRadius_llTransmitPktCallback(ubyte*    appSessionHdl,
                                     eapHdr_t* eap_hdr,
                                     ubyte*    eap_data,
                                     ubyte4    eap_data_len)
{
    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_TTLSRadiusReceivePassthruCallback(ubyte *appSessionHdl,
                                      eapMethodType type,
                                      eapCode code, ubyte id,ubyte *data, ubyte4 len,
                                      ubyte *opaque_data)
{
    return OK;
}


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_EAP_AUTH__))
static MSTATUS
eap_TTLSRadius_passthru_authCreateSession(eapTTLSCB *eapCb)
{
    eapMethodDef_t methodDef;
    eapSessionConfig_t sessionConfig;
    MSTATUS status = OK;

    if (NULL == eapCb->eapAuthSessionHdl)
    {
        /* create a new session */
        DIGI_MEMSET((ubyte *)&methodDef, 0, sizeof(eapMethodDef_t));
        methodDef.method_type = EAP_TYPE_NONE;
        methodDef.funcPtr_ulReceivePassthruCallback =
                                            EAP_TTLSRadiusReceivePassthruCallback;
        methodDef.funcPtr_llTransmitPacket = EAP_TTLSRadius_llTransmitPktCallback;
        methodDef.funcPtr_ulReceiveIndication = NULL;
        methodDef.funcPtr_ulMICVerify = NULL;
        methodDef.funcPtr_ulGetMethodstate = NULL;
        methodDef.funcPtr_ulGetDecision = NULL;
        sessionConfig.eap_mtu = 1020;
        sessionConfig.eap_ul_timeout = 0;/*60*/
        sessionConfig.eap_retrans_timeout = 0;/*5*/
        sessionConfig.eap_max_retrans = 0;/*5*/

        sessionConfig.sessionType = EAP_SESSION_TYPE_PASSTHROUGH;

        if (OK > (status = EAP_sessionCreate((ubyte *)eapCb,
                                  eapCb->eapTTLSparam.instanceId,
                                  methodDef,
                                  sessionConfig,
                                  &eapCb->eapAuthSessionHdl)))
        {
            goto exit;
        }

        if (OK > (status = EAP_sessionEnable(eapCb->eapAuthSessionHdl, eapCb->eapTTLSparam.instanceId)))
        {
            goto exit;
        }
    }

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_TTLSProcessEAPAuthRequest(eapTTLSCB *tlscon,ubyte* eapPkt, ubyte4 eapPktLen)
{
    MSTATUS             status = -1;
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__))
    RADIUS_RqstRecord*  pRadiusReq = NULL;
    eapSessionCb_t *    eapSession;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessEAPAuthRequest: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, tlscon);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    /* Form a Radius Access Request  Packet and Send it */
    /* If the State is EAP_INIT , then retrieve the IDENTITY of the user */
    if (EAP_TTLS_EAP_INIT == tlscon->eapStatus)
    {
        tlscon->eapTTLSparam.methodType = EAP_METHOD_TYPE_EAP;
        status = eap_ttlsExtractIdentity(tlscon,eapPkt,eapPktLen);
        if (OK > status)
            goto exit;

        tlscon->eapStatus = EAP_TTLS_EAP_IDENTITY;
        /* Create a Dummy EAP Passythrough Session to use the EAP Radius Code */
        status = eap_TTLSRadius_passthru_authCreateSession(tlscon);
        if (OK > status)
            goto exit;

        /* Set the Identty Here */
        status = EAP_setIdentity(tlscon->eapAuthSessionHdl,
                                 tlscon->eapTTLSparam.instanceId,
                                 tlscon->eapTTLSparam.UserName,
                                 tlscon->eapTTLSparam.UserNameLen);
    }

    /* Hand it over to the App to organise the Radius Request Response */
    /* Call the Auth Transmit Function and wait for a Callback */
    /* Set the recvHdrLen to eapPktLen */
    /* Lookup Session */
    status = eap_lookupSession((ubyte4)((uintptr)tlscon->eapAuthSessionHdl),
                               tlscon->eapTTLSparam.instanceId,
                               &eapSession);
    if (OK > status)
        goto exit;

    eapSession->recvEapHdr.len = eapPktLen;

    status = EAP_radiusEncapsulate(tlscon->eapAuthSessionHdl,
                                   tlscon->eapTTLSparam.instanceId,
                                   tlscon->eapTTLSparam.authServerId,
                                   tlscon->eapTTLSparam.myaddr,
                                   TTLS_NAS_PORT,
                                   TTLS_NAS_PORT_TYPE_IEEE_802_11,
                                   tlscon->eapTTLSparam.radiusSecret,
                                   (tlscon->eapTTLSparam.radiusSecretLen),
                                   eapPkt,
                                   &pRadiusReq);
    if (OK > status)
        goto exit;

    status = tlscon->eapTTLSparam.ulAuthTransmit(tlscon->appSessionCB,(ubyte *)tlscon,(ubyte *)pRadiusReq,0);

exit:
    if (OK > status)
    {
        tlscon->eapTTLSparam.ulAuthResultTransmit(tlscon->appSessionCB,EAP_AUTH_FAILURE);
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessEAPAuthRequest: Error, status = ", (sbyte4)status);
    }
#endif /*(defined(__ENABLE_DIGICERT_EAP_AUTH__))*/
    return status;
}


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_EAP_AUTH__))
/*! Process a received RADIUS packet and respond appropriately.
This function (called from the TTLS passthrough server or
authenticator) processes a RADIUS packet received from a RADIUS server. On
receiving Access Accept or Reject, an EAP Success or Failure response is sent to
the peer. On receiving other RADIUS attributes, the RADIUS packet is
decapsulated and a corresponding EAP Request is sent to the peer.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TTLS__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$
- $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$

#Include %file:#&nbsp;&nbsp;eap_ttls.h

\param eapCb        EAP-TTLS session handle returned from EAP_TTLSinitSession.
\param pRadiusReq   Pointer to the received RADIUS packet.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_TTLSSendData
\sa EAP_TTLSreceiveLLPacket
\sa EAP_TTLSdeleteSession

*/
extern MSTATUS
EAP_TTLSProcessRadiusAuthResponse(void *eapCb,RADIUS_RqstRecord *pRadiusReq)
{
    MSTATUS         status = -1;
#if defined(__ENABLE_DIGICERT_RADIUS_CLIENT__)
    eapTTLSCB*      eapTTLSCb = (eapTTLSCB*)eapCb;
    ubyte           type;
    ubyte           len;
    ubyte*          pValue;
    ubyte*          success = NULL;
    ubyte4          ubyte4Value;
    ubyte4          successLen = 0;
    ubyte4          vendorID;
    ubyte4          attribute = 0;
    ubyte*          pAttr;
    ubyte*          newEapReq;
    ubyte4          newEapReqLen;
    ubyte           attrLength;
    ubyte           subType;
    ubyte           subLength;
    ubyte           *pSubData;
    sbyte*          pStringValue;
    intBoolean      done;
    ubyte           code;
    sbyte4          i=0;
    sbyte4          j;

    if (!eapTTLSCb)
    {
        status = ERR_EAP_TLS_SESSION_NOT_FOUND;
        goto exit;
    }

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessRadiusAuthResponse: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapTTLSCb);

    /* Assuming the packet has already been validated by the App Layer */
    status = RADIUS_responseGetCode(pRadiusReq, &code);
    if (OK > status)
    {
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");
        goto exit;
    }
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Code ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)code);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    if ((EAP_METHOD_TYPE_PAP    == eapTTLSCb->eapTTLSparam.methodType) ||
        (EAP_METHOD_TYPE_CHAP   == eapTTLSCb->eapTTLSparam.methodType) ||
        (EAP_METHOD_TYPE_MSCHAP == eapTTLSCb->eapTTLSparam.methodType))
    {
        /* Call the App  Result Function */
        if (RADIUS_CODE_ACCESS_ACCEPT == code)
            eapTTLSCb->eapTTLSparam.ulAuthResultTransmit(eapTTLSCb->appSessionCB,EAP_AUTH_SUCCESS);
        else if (RADIUS_CODE_ACCESS_REJECT == code)
            eapTTLSCb->eapTTLSparam.ulAuthResultTransmit(eapTTLSCb->appSessionCB,EAP_AUTH_FAILURE);

        goto exit;
    }

    if (EAP_METHOD_TYPE_EAP == eapTTLSCb->eapTTLSparam.methodType)
    {
        if (RADIUS_CODE_ACCESS_ACCEPT == code)
        {
            eapTTLSCb->eapTTLSparam.ulAuthResultTransmit(eapTTLSCb->appSessionCB,EAP_AUTH_SUCCESS);
            goto exit;
        }
        else if (RADIUS_CODE_ACCESS_REJECT == code)
        {
            eapTTLSCb->eapTTLSparam.ulAuthResultTransmit(eapTTLSCb->appSessionCB,EAP_AUTH_FAILURE);
            goto exit;
        }

        /* Decapsulate the Radius Packet */
        /* We have to Send the EAP attribute */
        status = EAP_radiusDecapsulate(eapTTLSCb->eapAuthSessionHdl,
                                       eapTTLSCb->eapTTLSparam.instanceId,
                                       eapTTLSCb->eapTTLSparam.radiusSecret,
                                       eapTTLSCb->eapTTLSparam.radiusSecretLen,
                                       pRadiusReq, &newEapReq, &newEapReqLen);

        if (status != OK)
        {
            goto exit;
        }

        status = EAP_TTLSEncapEAPPkt(eapCb,newEapReq, newEapReqLen);

        if (newEapReq)
            FREE(newEapReq);

        goto exit;
    }

    /* Extract Radius Reponse Attributes */
    while (OK == RADIUS_responseGetAttributeByIndex(pRadiusReq, i, &type, &pValue, &len))
    {
        /* printf("Attribute: #%d\n", i);
        printf("     Type: %d\n", (int)type);
        printf("    Value: ");
        radius_printChars(pValue, len);
        printf("\n");
        */

        if (sizeof(ubyte4) == len)
        {
            if (OK == RADIUS_responseGetAttributeAsUByte4(pRadiusReq, type, &ubyte4Value))
            {
            }
        }
        else if (RADIUS_ATTR_VENDOR_SPECIFIC == type)
        {
            if (OK == RADIUS_responseGetAttributeByIndexAsVendorSpecific(pRadiusReq, i, &vendorID, &pAttr, &attrLength))
            {
                /* printf("Vendor-Specific attribute\n");
                printf("Vendor ID: %d\n", vendorID);
                */

                if (RADIUS_attributeHasSubAttributes(pAttr, attrLength))
                {
                    done = FALSE;
                    j = 0;

                    while (!done)
                    {
                        if (OK == RADIUS_getSubAttributeByIndex(pAttr, attrLength, j, &subType, &pSubData, &subLength))
                        {
                            /*
                            printf("    Sub-Attribute: #%d\n", j);
                            printf("             Type: %d\n", (int)subType);
                            printf("            Value: ");
                            radius_printChars(pSubData, subLength);
                            printf("\n");
                            */
                            j++;

                            if ((RADIUS_VENDOR_ID_MS == vendorID) &&
                               (RADIUS_ATTR_MSCHAPV2_SUCCESS == subType))
                            {
                                success = pSubData;
                                successLen = subLength;
                                attribute = RADIUS_ATTR_MSCHAPV2_SUCCESS;
                            }

                            if ((RADIUS_VENDOR_ID_MS == vendorID) &&
                               (RADIUS_ATTR_MSCHAP_ERROR == subType))
                            {
                                success = pSubData;
                                successLen = subLength;
                                attribute = RADIUS_ATTR_MSCHAP_ERROR;
                            }
                        }
                        else
                        {
                            done = TRUE;
                        }
                    }
                }
            }
        }
        else
        {
            if (OK == RADIUS_responseGetAttributeAsCString(pRadiusReq, type, &pStringValue))
            {
                RADIUS_responseFreeString(&pStringValue);
            }
        }
        i++;
    }

    if (EAP_METHOD_TYPE_MSCHAPV2 == eapTTLSCb->eapTTLSparam.methodType)
    {
        /* We have to Send the MSCHaPv2 SUCCESS AVP with the Authenticator */
        /* Extract the  SUCCESS Attribute */
        if ((RADIUS_CODE_ACCESS_ACCEPT == code) &&
           (RADIUS_ATTR_MSCHAPV2_SUCCESS == attribute))
        {
            status = EAP_TTLSSendMSChapV2AuthSuccess(eapTTLSCb, success,successLen);
        }
    }

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

exit:
    if (pRadiusReq)
        RADIUS_requestRelease(&pRadiusReq);
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessRadiusAuthResponse: Error, status = ", (sbyte4)status);
    }
#endif
    return status;
}

#endif /*(defined(__ENABLE_DIGICERT_EAP_AUTH__))*/


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_TTLSProcessPAPPeerRequest(eapTTLSCB *eapCb)
{
    ubyte*  response = NULL;
    ubyte4  responseLen = 0;
    ubyte*  cur;
    ubyte4  length;
    ubyte   flags =0;
    MSTATUS status = OK;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessPAPPeerRequest: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapCb);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    response = MALLOC(MAX_EAP_PACKET);
    if (NULL == response)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    cur = response;

    /* Add Username/Password AVP to the packet and call Transmit Function */
    status = AVP_appendAttribute(cur, EAP_RADIUS_ATTR_USER_NAME,
                                 flags, 0,
                                 eapCb->eapTTLSparam.UserName,
                                 eapCb->eapTTLSparam.UserNameLen, &length);
    if (OK > status)
        goto exit;

    responseLen += length;
    cur         += length;

    status = AVP_appendAttribute(cur, EAP_RADIUS_ATTR_USER_PASSWORD,
                                 flags, 0,
                                 eapCb->eapTTLSparam.Password,
                                 eapCb->eapTTLSparam.PasswordLen, &length);
    if (OK > status)
        goto exit;

    responseLen += length;
    cur         += length;

    if (0 == eapCb->eapTTLSparam.version)
        eapCb->eapTTLSparam.ulAuthResultTransmit(eapCb->appSessionCB,EAP_AUTH_SUCCESS);

    status = eapCb->eapTTLSparam.ulTransmit(eapCb->appSessionCB,
                                            response,responseLen,FALSE);

exit:
    if (response)
        FREE(response);
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessPAPPeerRequest: Error, status = ", (sbyte4)status);
    }

    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_TTLSProcessChapPeerRequest(eapTTLSCB *eapCb)
{
    ubyte*  response = NULL;
    ubyte4  responseLen = 0;
    ubyte4  chalRespLen;
    ubyte   chapResponse[17];
    ubyte   Challenge[17];
    ubyte*  cur;
    ubyte4  length;
    ubyte   flags =0;
    MSTATUS status;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessChapPeerRequest: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapCb);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

   /* Generate Challenge based upon the TLS Random */
    if (0 == eapCb->eapTTLSparam.version)
        status = SSL_generateTLSExpansionKey(eapCb->eapTTLSparam.connectionInstance,
                                      Challenge,17,(ubyte *)TTLS_CHALLENGE_PHRASE,
                                      TTLS_CHALLENGE_PHRASE_LEN);
    else
        status = SSL_generateTLSExpansionKey(eapCb->eapTTLSparam.connectionInstance,
                                      Challenge,17,(ubyte *)TTLS_INNER_APP_CHALLENGE_PHRASE,
                                      TTLS_INNER_APP_CHALLENGE_PHRASE_LEN);
    if (OK > status)
        goto exit;

    response = MALLOC(MAX_EAP_PACKET);
    if (NULL == response)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    cur = response;

    status = AVP_appendAttribute(cur, EAP_RADIUS_ATTR_USER_NAME,
                                 flags, 0,
                                 eapCb->eapTTLSparam.UserName,
                                 eapCb->eapTTLSparam.UserNameLen, &length);
    if (OK > status)
        goto exit;

    responseLen += length;
    cur         += length;

    status = AVP_appendAttribute(cur, EAP_RADIUS_ATTR_CHAP_CHALLENGE,
                                 flags, 0,
                                 Challenge, 16, &length);
    if (OK > status)
        goto exit;

    responseLen += length;
    cur         += length;

    /*
      Add Username AVP
      Add 16 Byte Challenge AVP
      Compute Chap Response  based upon Challenge
      MD5(Ident + Password + Challenge)
    */

    status = EAP_MD5ChallengeResponse(Challenge[16],
                                      Challenge, 16,
                                      eapCb->eapTTLSparam.Password,
                                      eapCb->eapTTLSparam.PasswordLen,
                                      &chapResponse[1], &chalRespLen);
    if (OK > status)
        goto exit;

    /*Add 17 Byte Chap Password (1 Byte of Identifier + Chap Response) AVP */
    chapResponse[0] = *(Challenge + 16);

    status = AVP_appendAttribute(cur, EAP_RADIUS_ATTR_CHAP_PASSWORD,  flags, 0,
                                 chapResponse, 17, &length);
    if (OK > status)
        goto exit;

    responseLen += length;
    cur         += length;

    if (0 == eapCb->eapTTLSparam.version)
        eapCb->eapTTLSparam.ulAuthResultTransmit(eapCb->appSessionCB,EAP_AUTH_SUCCESS);

    status = eapCb->eapTTLSparam.ulTransmit(eapCb->appSessionCB,
                                            response,responseLen,FALSE);

exit:
    if (response)
        FREE(response);
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessChapPeerRequest: Error, status = ", (sbyte4)status);
    }

    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_TTLSProcessMSChapPeerRequest(eapTTLSCB *eapCb)
{
    ubyte*  response = NULL;
    ubyte4  responseLen = 0;
    ubyte   mschapResponse[50];
    ubyte   Challenge[9];
    ubyte*  ptr = mschapResponse;
    ubyte*  cur;
    ubyte   flags =0;
    ubyte4  length;
    MSTATUS status = OK;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessMSChapPeerRequest: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapCb);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    response = MALLOC(MAX_EAP_PACKET);
    if (NULL == response)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* Generate Challenge based upon the TLS Random */
    if (0 == eapCb->eapTTLSparam.version)
        status = SSL_generateTLSExpansionKey(eapCb->eapTTLSparam.connectionInstance,
                                             Challenge,9,(ubyte *)TTLS_CHALLENGE_PHRASE,
                                             TTLS_CHALLENGE_PHRASE_LEN);
    else
        status = SSL_generateTLSExpansionKey(eapCb->eapTTLSparam.connectionInstance,
                                             Challenge,9,(ubyte *)TTLS_INNER_APP_CHALLENGE_PHRASE,
                                             TTLS_INNER_APP_CHALLENGE_PHRASE_LEN);
    if (OK > status)
        goto exit;

    cur = response;

    /* Add Username AVP */
    status = AVP_appendAttribute(cur, EAP_RADIUS_ATTR_USER_NAME,
                                 flags, 0,
                                 eapCb->eapTTLSparam.UserName,
                                 eapCb->eapTTLSparam.UserNameLen, &length);
    if (OK > status)
        goto exit;

    responseLen += length;
    cur         += length;

    /* Add 8 Byte Challenge AVP */
    status = AVP_appendAttribute(cur, EAP_RADIUS_ATTR_MSCHAP_CHALLENGE,  flags,
                                 EAP_RADIUS_VENDOR_ID_MS,
                                 Challenge, 8, &length);
    if (OK > status)
        goto exit;

    responseLen += length;
    cur         += length;

    /* Add Chap Password AVP (1 Byte of Identifier + Flag =1 + LM Response 24 bytes =0 + NT  Response (24 bytes)) AVP */

    /* Id */
    *ptr++ = Challenge[8];
    /* Flags */
    *ptr++ = 1;
    /* LM Response */
    DIGI_MEMSET(ptr,0,24);

    ptr+=24;

    /* Compute MSChap LM and NT Response based upon Challenge */
    status = EAP_MSCHAPv0generateNTResponse(Challenge,
                                            eapCb->eapTTLSparam.Password,
                                            eapCb->eapTTLSparam.PasswordLen,
                                            ptr);
    if (OK > status)
        goto exit;

    ptr += 24;

    status = AVP_appendAttribute(cur, EAP_RADIUS_ATTR_MSCHAP_RESPONSE,
                                 flags, EAP_RADIUS_VENDOR_ID_MS,
                                 mschapResponse, 50, &length);
    if (OK > status)
        goto exit;

    responseLen += length;
    cur         += length;

    if (0 == eapCb->eapTTLSparam.version)
        eapCb->eapTTLSparam.ulAuthResultTransmit(eapCb->appSessionCB,EAP_AUTH_SUCCESS);

    status = eapCb->eapTTLSparam.ulTransmit(eapCb->appSessionCB,
                                            response,responseLen,FALSE);

exit:
    if (response)
        FREE(response);
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessMSChapPeerRequest: Error, status = ", (sbyte4)status);
    }

    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_TTLSSendMSChapV2AuthSuccess(eapTTLSCB *eapCb,ubyte* success,ubyte4 successLen)
{
    ubyte*  response = NULL;
    ubyte*  cur;
    ubyte4  responseLen = 0;
    ubyte4  length;
    ubyte   flags=0;
    MSTATUS status = OK;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSSendMSChapV2AuthSuccess: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapCb);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    response = MALLOC(MAX_EAP_PACKET);
    if (NULL == response)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    cur = response;

    status = AVP_appendAttribute(cur, EAP_RADIUS_ATTR_MSCHAPV2_SUCCESS,  flags,
                                 EAP_RADIUS_VENDOR_ID_MS,
                                 success, successLen, &length);
    if (OK > status)
        goto exit;

    eapCb->msChapV2Status = EAP_TTLS_MSCHAPV2_SUCCESS;
    responseLen += length;
    cur         += length;

    status = eapCb->eapTTLSparam.ulTransmit(eapCb->appSessionCB,
                                            response,responseLen,FALSE);

exit:
    if (response)
        FREE(response);
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSSendMSChapV2AuthSuccess: Error, status = ", (sbyte4)status);
    }

    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_TTLSProcessMSChapV2PeerRequest(eapTTLSCB *eapCb)
{
    ubyte*  response = NULL;
    ubyte4  responseLen = 0;
    ubyte   mschapResponse[50];
    ubyte*  ptr = mschapResponse;
    ubyte   AuthChallenge[33];
    ubyte   AuthResponse[20];
    ubyte*  PeerChallenge = AuthChallenge + 17;
    ubyte   NtResponse[24];
    ubyte*  cur;
    ubyte   flags = 0;
    ubyte4  length;
    MSTATUS status;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessMSChapV2PeerRequest: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapCb);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    /* Generate Challenge based upon the TLS Random */
    if (0 == eapCb->eapTTLSparam.version)
        status = SSL_generateTLSExpansionKey(eapCb->eapTTLSparam.connectionInstance,
                                      AuthChallenge,33,(ubyte *)TTLS_CHALLENGE_PHRASE,
                                      TTLS_CHALLENGE_PHRASE_LEN);
    else
        status = SSL_generateTLSExpansionKey(eapCb->eapTTLSparam.connectionInstance,
                                      AuthChallenge,33,(ubyte *)TTLS_INNER_APP_CHALLENGE_PHRASE,
                                      TTLS_INNER_APP_CHALLENGE_PHRASE_LEN);
    if (OK > status)
        goto exit;

#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE,(sbyte*)" AuthChallenge is");
    EAP_PrintBytes(AuthChallenge, 33);
#endif

    response = MALLOC(MAX_EAP_PACKET);
    if (NULL == response)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    cur = response;

    /* Add Username AVP */
    status = AVP_appendAttribute(cur, EAP_RADIUS_ATTR_USER_NAME,  flags, 0,
                                 eapCb->eapTTLSparam.UserName,
                                 eapCb->eapTTLSparam.UserNameLen, &length);
    if (OK > status)
        goto exit;

    responseLen += length;
    cur         += length;

    status = AVP_appendAttribute(cur, EAP_RADIUS_ATTR_MSCHAP_CHALLENGE,
                                 flags, EAP_RADIUS_VENDOR_ID_MS,
                                 AuthChallenge, 16, &length);
    if (OK > status)
        goto exit;

    responseLen += length;
    cur         += length;

    /* Add 16 Byte Challenge AVP */
    /* Get the Username and Password from the Client */
    /* Compute MSV2 Chap  NT Response  based upon Challenge */
    /* generate a peer challenge from the challenege */

    status = EAP_MSCHAPgenerateNTResponse(
                AuthChallenge,
                PeerChallenge,
                eapCb->eapTTLSparam.UserName,
                eapCb->eapTTLSparam.UserNameLen,
                eapCb->eapTTLSparam.Password,
                eapCb->eapTTLSparam.PasswordLen,
                NtResponse);

    if (OK > status)
        goto exit;

    /* Add Chap Password (1 Byte of Identifier + Flag=0 + Peer Challenge(16 Bytes) +8bytes Reserved+NT  Response(24 Bytes)) AVP */

    /* Id */
    eapCb->msChapV2Id = *ptr++ = *(AuthChallenge+16);
    /* Flag */
    *ptr++ = 0;
    DIGI_MEMCPY(ptr,PeerChallenge,16);
    ptr+= 16;
    /* Reserved */
    DIGI_MEMSET(ptr,0,8);
    ptr+= 8;
    DIGI_MEMCPY(ptr,NtResponse,24);
    ptr+= 24;

    /* Generate Authenticator for checking the response when it comes */
    status = EAP_MSCHAPgenerateAuthenticatorResponse(
                                        eapCb->eapTTLSparam.Password,
                                        eapCb->eapTTLSparam.PasswordLen,
                                        NtResponse,
                                        PeerChallenge,
                                        AuthChallenge,
                                        eapCb->eapTTLSparam.UserName,
                                        eapCb->eapTTLSparam.UserNameLen,
                                        AuthResponse);
    if (OK > status)
        goto exit;

    DIGI_MEMCPY(eapCb->AuthenticatorResponse,(ubyte *)"S=",2);

    EAP_MSCHAPbin2hex((const ubyte *)AuthResponse,(sbyte *)(eapCb->AuthenticatorResponse+2),20);

    status = AVP_appendAttribute(cur, EAP_RADIUS_ATTR_MSCHAPV2_RESPONSE,
                                 flags, EAP_RADIUS_VENDOR_ID_MS,
                                 mschapResponse, 50, &length);
    if (OK > status)
        goto exit;

    responseLen += length;
    cur         += length;

    /* The Auth then sends a 42 byte Response in MSCHAP Success Packet
     * based upon the peer challenge
     * If Peer accepts the response then it send a TTLS packet with
     * 0 data (ACK) before the Auth Sends a Success ..
     */
    status = eapCb->eapTTLSparam.ulTransmit(eapCb->appSessionCB,
                                            response,responseLen,FALSE);

exit:
    if (response)
        FREE(response);
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessMSChapV2PeerRequest: Error, status = ", (sbyte4)status);
    }

    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_TTLSProcessEAPPeerRequest(eapTTLSCB *eapCb, ubyte *pkt, ubyte4 pktLen)
{
    /* Pass the packet up  to the Peer  Second Stage */
    MSTATUS status =OK;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessEAPPeerRequest: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapCb);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    status = EAP_llReceivePacket(eapCb->eapSessionHdl,
                                 eapCb->eapTTLSparam.instanceId,
                                 pkt,pktLen,NULL);

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSProcessEAPPeerRequest: Error, status = ", (sbyte4)status);
    }
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_TTLSInitEAPPeerRequest(eapTTLSCB *eapCb)
{
#ifdef __ENABLE_DIGICERT_EAP_PEER__
    ubyte*      eapPkt;
    ubyte4      eapPktLen;
    ubyte2      length;
    eapHdr_t*   eapHdr;
#endif
    MSTATUS     status =OK;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSInitEAPPeerRequest: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapCb);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

#ifdef __ENABLE_DIGICERT_EAP_PEER__
    status = eap_TTLSPeerInit(eapCb);
    if (OK > status)
        goto exit;

    eapPktLen = sizeof(eapHdr_t)+1+eapCb->eapTTLSparam.UserNameLen;
    eapPkt = MALLOC(eapPktLen);
    if (NULL == eapPkt)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    eapHdr = (eapHdr_t *)eapPkt;

    eapHdr->code = EAP_CODE_RESPONSE;
    eapHdr->id   = 1;

    length = sizeof(eapHdr_t)+1+eapCb->eapTTLSparam.UserNameLen;

    DIGI_HTONS(eapPkt+2, length);

    *(eapPkt+sizeof(eapHdr_t)) = EAP_TYPE_IDENTITY;

    DIGI_MEMCPY(eapPkt+sizeof(eapHdr_t)+1,eapCb->eapTTLSparam.UserName,eapCb->eapTTLSparam.UserNameLen);

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Sending TTLS Inner Identity Response: Length ");
    DEBUG_INT(DEBUG_EAP_MESSAGE,length);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    /* Encapsulate this in EAP_AVP */

    status = EAP_TTLSEncapEAPPkt(eapCb,eapPkt, eapPktLen);

    FREE(eapPkt);

exit:
#endif
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSInitEAPPeerRequest: Error, status = ", (sbyte4)status);
    }
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_TTLSEncapEAPPkt(eapTTLSCB *eapCb,ubyte *eapPkt, ubyte4 eapPktLen)
{
    ubyte*  response = NULL;
    ubyte  *cur = NULL;
    ubyte   flags = 0;
    ubyte4  responseLen = 0;
    ubyte4  length = 0;
    ubyte4  avpLen = AVP_CODE_PLUS_FLAGS_PLUS_LEN_SIZE + eapPktLen;
    ubyte4  pad =0;
    MSTATUS status;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSEncapEAPPkt: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapCb);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" Adding EAP_AVP");

    pad = avpLen % 4;
    if (pad != 0)
    {
        pad = 4 - pad;
    }
    avpLen +=pad;
    response = MALLOC(avpLen);

    if (NULL == response)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    cur = response;

    /* Add EAP AVP */
    status = AVP_appendAttribute(cur, EAP_RADIUS_ATTR_EAP_MESSAGE,  flags, 0,
                                 eapPkt,
                                 eapPktLen, &length);
    if (OK > status)
        goto exit;

    responseLen += length;
    cur         += length;

    /* Send the EAP Packet */
    status = eapCb->eapTTLSparam.ulTransmit(eapCb->appSessionCB,
                                            response,responseLen,FALSE);

exit:
    if (response)
        FREE(response);
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSEncapEAPPkt: Error, status = ", (sbyte4)status);
    }
    return status;
}


/*------------------------------------------------------------------*/

/*! Generate a session key.
This function (typically called by your application) generates a session key for
the specified TTLS session.

The first 64 bits of the returned key represent the MSK (master session key),
while the remaining bits represent the EMSK (extended master session key).

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TTLS__$

Additionally, for each of the following flag pairs at least one of the pair must be defined in moptions.h:
- Enable EAP peer/authenticator ($__ENABLE_DIGICERT_EAP_PEER__$, $__ENABLE_DIGICERT_EAP_AUTH__$)
- Enable asynchronous SSL client/server ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$, $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)

#Include %file:#&nbsp;&nbsp;eap_ttls.h

\param eapCb    EAP-TTLS session handle returned from EAP_TTLSinitSession.
\param key      On return, pointer to generated session key.
\param keyLen   Length (number of bytes) of key to generate.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_TTLSSendData

*/
extern MSTATUS
EAP_TTLSgetKey(void *eapCb,ubyte *key,ubyte2 keyLen)
{
   /* Generate TLS Expansion Key */
    eapTTLSCB * eapTTLSCb = (eapTTLSCB *) eapCb;
    MSTATUS status;

    if (!eapTTLSCb)
    {
        status = ERR_EAP_TLS_SESSION_NOT_FOUND;
        goto exit;
    }

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSgetKey: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapCb);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    status = SSL_generateTLSExpansionKey(eapTTLSCb->eapTTLSparam.connectionInstance,
                                         key,keyLen,(ubyte *)TTLS_KEYING_PHRASE,
                                         TTLS_KEYING_PHRASE_LEN);

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSgetKey: Error, status = ", (sbyte4)status);
    }
    return status;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_INNER_APP__
/*! Send data using the TLS inner application extension.
This function encrypts and sends data using the TLS inner application extension.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TTLS__$
- $__ENABLE_DIGICERT_INNER_APP__$

Additionally, for each of the following flag pairs at least one of the pair must be defined in moptions.h:
- Enable EAP peer/authenticator ($__ENABLE_DIGICERT_EAP_PEER__$, $__ENABLE_DIGICERT_EAP_AUTH__$)
- Enable asynchronous SSL client/server ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$, $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)

#Include %file:#&nbsp;&nbsp;eap_ttls.h

\param ttls_connection  EAP-TTLS session handle returned from EAP_TTLSinitSession.
\param data             Pointer to data to encrypt and send.
\param len              Number of bytes of data to encrypt and send ($data$).
\param innerApp         Inner application extension type; any of the $eap_ttls_inner_appState$ enumerated values (defined in eap_ttls_pvt.h).
\param eapRespData      On return, pointer to encrypted data.
\param eapRespLen       On return, pointer to number of bytes of encrypted data ($eapRespData$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_TTLSSendData(ubyte *ttls_connection,
                 ubyte *data, ubyte4 len,
                 InnerAppType innerApp,ubyte **eapRespData, ubyte4 *eapRespLen)
{
    MSTATUS status = OK;
    eapTTLSCB * eapTTLSCb = (eapTTLSCB *) ttls_connection;
    ubyte * eapResponse= NULL;
    sbyte4 length;

    if (!eapTTLSCb)
    {
        status = ERR_EAP_TLS_SESSION_NOT_FOUND;
        goto exit;
    }
    *eapRespLen = 0;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSSendData: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapTTLSCb);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Inner App Type ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)innerApp);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    status = SSL_sendInnerApp(eapTTLSCb->eapTTLSparam.connectionInstance,innerApp,data,len,(ubyte4 *)&length);

    /* If Error is ERR_SSL_SEND_BUFFER_NOT_EMPTY  then the app should retry sending this buffer as the pending data was what is presented to the app currently */
    if (((OK > status) && (ERR_SSL_SEND_BUFFER_NOT_EMPTY != status)) || (0 == length))
        goto exit;

    *eapRespLen = length;
    eapResponse = (ubyte *) MALLOC(*eapRespLen);
    if (NULL == eapResponse)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = SSL_ASYNC_getSendBuffer(eapTTLSCb->eapTTLSparam.connectionInstance,(eapResponse), eapRespLen)))
    {
        goto exit;
    }

    *eapRespData = eapResponse;

    if (SSL_INNER_APPLICATION_DATA == innerApp)
        eapTTLSCb->eapInnerAppState = EAP_TTLS_INNER_APP;
    else if (SSL_INNER_INTER_FINISHED == innerApp)
        eapTTLSCb->eapInnerAppState = EAP_TTLS_INNER_INTER;
    else if (SSL_INNER_FINAL_FINISHED == innerApp)
        eapTTLSCb->eapInnerAppState = EAP_TTLS_INNER_FINAL;

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSSendData: Error, status = ", (sbyte4)status);
        if (eapResponse)
            FREE(eapResponse);
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_ttlsVerifyInterFinished(eapTTLSCB * eapCb,ubyte * data, ubyte4 len)
{
    MSTATUS status = OK;
    ubyte4    innerLen = (ubyte4)data[1] << 16 |
                         (ubyte4)data[2] << 8 |
                         (ubyte4)data[3] ;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_ttlsVerifyInterFinished: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapCb);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    if (12 != innerLen)
    {
        status = ERR_EAP_TTLS_BAD_LENGTH;
        goto exit;
    }

    status = SSL_verifyInnerAppVerifyData(eapCb->eapTTLSparam.connectionInstance,
                                          data + 4, SSL_INNER_INTER_FINISHED);

    goto exit;

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"eap_ttlsVerifyInterFinished: Error, status = ", (sbyte4)status);
    }
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_ttlsVerifyFinalFinished(eapTTLSCB * eapCb,ubyte * data, ubyte4 len)
{
    MSTATUS status = OK;
    ubyte4    innerLen = (ubyte4)data[1] << 16 |
                         (ubyte4)data[2] << 8 |
                         (ubyte4)data[3] ;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_ttlsVerifyFinalFinished: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapCb);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    if (12 != innerLen)
    {
        status = ERR_EAP_TTLS_BAD_LENGTH;
        goto exit;
    }

    status = SSL_verifyInnerAppVerifyData(eapCb->eapTTLSparam.connectionInstance,
                                          data + 4, SSL_INNER_FINAL_FINISHED);

    goto exit;

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"eap_ttlsVerifyFinalFinished: Error, status = ", (sbyte4)status);
    }
    return status;
}


/*------------------------------------------------------------------*/

/*! Build a TLS $Alert Message$ to be sent over EAP.
This function builds a TLS $Alert Message$ to be sent over EAP.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_TTLS__$

Additionally, for each of the following flag pairs at least one of the pair must be defined in moptions.h:
- Enable EAP peer/authenticator ($__ENABLE_DIGICERT_EAP_PEER__$, $__ENABLE_DIGICERT_EAP_AUTH__$)
- Enable asynchronous SSL client/server ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$, $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)

#Include %file:#&nbsp;&nbsp;eap_ttls.h

\note This funcitn is used during TTLS v1 negotiation.

\param eapSessionHdl    EAP-TTLS session handle returned from EAP_TTLSinitSession.
\param alertClass       One of the following alert class definitions: $SSLALERTLEVEL_WARNING$ or $SSLALERTLEVEL_FATAL$.
\param alertId          SSL alert ID code (see "SSL Alert Codes").

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_TTLSsendAlert(ubyte * eapSessionHdl,sbyte4 alertClass,sbyte4 alertId)
{
    ubyte *alertBuf = NULL;
    ubyte4 alertLen;
    ubyte *eapRespData = NULL;
    ubyte4 eapRespLen;
    eapTTLSCB * eapCb = (eapTTLSCB *)eapSessionHdl;
    MSTATUS status = OK;

    if (!eapCb)
    {
        status = ERR_EAP_TLS_SESSION_NOT_FOUND;
        goto exit;
    }

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSsendAlert: Session Handle ");
    DEBUG_PTR(DEBUG_EAP_MESSAGE, eapCb);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" alertId ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, alertId);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");

    status = SSL_sendAlert(eapCb->eapTTLSparam.connectionInstance,
                           alertId,
                           alertClass);
    if (0 < status)
    {
        alertLen = status;
        alertBuf = (ubyte *) MALLOC(alertLen);
        if (NULL == alertBuf)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        if (OK > (status = SSL_ASYNC_getSendBuffer(eapCb->eapTTLSparam.connectionInstance,alertBuf, &alertLen)))
        {
            goto exit;
        }

        status = EAP_TTLSFormSendPacket(eapCb,alertBuf,alertLen,&eapRespData,&eapRespLen);
        if (OK > status)
            goto exit;

        status = eapCb->eapTTLSparam.ulTransmit(eapCb->appSessionCB,
                                                eapRespData,eapRespLen,TRUE);
    }

exit:
    if (alertBuf)
        FREE(alertBuf);

    if (eapRespData)
        FREE(eapRespData);

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_TTLSSendAlert: Error, status = ", (sbyte4)status);
    }

    return status;
}

#endif /*(defined(__ENABLE_DIGICERT_INNER_APP__)) */


/*------------------------------------------------------------------*/

#endif /*(defined(__ENABLE_DIGICERT_EAP_TTLS__)) */
#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */
