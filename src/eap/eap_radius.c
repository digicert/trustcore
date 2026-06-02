/**
 * @file  eap_radius.c
 * @brief EAP RADIUS integration
 *
 * @details    RADIUS passthrough functions
 * @since      1.41
 * @version    2.02 and later
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_RADIUS__
 *     +   \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
 *     Additionally, at least one of the following flags must be defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_AUTH__
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


#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)
#if defined(__ENABLE_DIGICERT_RADIUS_CLIENT__)
#if defined(__ENABLE_DIGICERT_EAP_RADIUS__)
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mudp.h"
#include "../common/debug_console.h"
#include "../crypto/md5.h"
#include "../crypto/crypto.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/hmac.h"
#include "../common/redblack.h"
#include "../common/timer.h"
#include "../radius/radius.h"
#include "../radius/radius_req.h"
#include "../radius/radius_resp.h"
#include "../eap/eap.h"
#include "../eap/eap_auth.h"
#include "../eap/eap_md5.h"
#include "../eap/eap_session.h"


/*------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_IPV6__
#define GET_MOC_IPADDR4(a) a
#else
#define GET_MOC_IPADDR4(a) (a)->uin.addr
#endif


/*------------------------------------------------------------------*/

/*! Encapsulate an EAP packet into a RADIUS packet.
This function encapsulates a given EAP packet into a RADIUS packet, appending
the required attributes and returning the encapsulated packet through the
$radiusReq$ parameter. Typically the upper layer calls this function to provide
passthrough authentication (sending packets to a backend RADIUS authentication
%server).

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$
- $__ENABLE_DIGICERT_EAP_RADIUS__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_radius.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID returned from EAP_initInstance.
\param authServerID     Backend RADIUS authentication server ID (index specified by Mocana internal code).
\param addr             Interface address of NAS (network authentication server).
\param nas_port         NAS port number.
\param nas_port_type    NAS port type (see "NAS Port Types").
\param password         User password.
\param secret           Shared secret between RADIUS %client and backend RADIUS
authentication %server.
\param secretlen        Number of bytes in $secret$.
\param eap_pkt          Pointer to EAP packet to be encapsulated.
\param radiusReq        On return, pointer to encapsulated RADIUS EAP packet..

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_radiusEncapsulate(ubyte * eapSessionHdl,
                      ubyte4 instanceId,
                      ubyte4 authServerID,
                      MOC_IP_ADDRESS addr,
                      ubyte4 nas_port,
                      ubyte4 nas_port_type,
                      ubyte *secret,
                      sbyte4 secretlen,
                      ubyte *eap_pkt, RADIUS_RqstRecord **radiusReq)
{
    eapSessionCb_t     *eapSession = NULL;
    MSTATUS            status = OK;
    RADIUS_RqstRecord  *pRadiusReq = NULL;
    ubyte*              p;
    ubyte2              len, len_save, auth_offset;
    ubyte               result[MD5_DIGESTSIZE];
    ubyte               *ptr;
    ubyte4              bytes_to_send = 0;
    ubyte               eap_msg_len = 0;
    hwAccelDescr        hwAccelCtx;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    /* Lookup Session */
    status = eap_lookupSession ((ubyte4)((uintptr)eapSessionHdl),
                                  instanceId, &eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    if (!(*radiusReq))
    {
        if (OK > (status = RADIUS_requestNew(&pRadiusReq, authServerID, RADIUS_CODE_ACCESS_REQUEST)))
            goto exit;
    }
    else
    {
        pRadiusReq = *radiusReq;
    }

    if (eapSession->eapIdentity != NULL)
    {
        if (OK > (status = RADIUS_requestAppendStringAttribute(pRadiusReq, RADIUS_ATTR_USER_NAME, eapSession->eapIdentity)))
            goto exit;
    }
    if (eapSession->radiusAttrState != NULL)
    {
        if (OK > (status = RADIUS_requestAppendAttribute(pRadiusReq, RADIUS_ATTR_STATE, eapSession->radiusAttrState, eapSession->radiusAttrStateLen)))
            goto exit;
    }

    if (OK > (status = RADIUS_requestAppendUByte4Attribute(pRadiusReq,
                                                  RADIUS_ATTR_NAS_IP_ADDRESS,
                                                  GET_MOC_IPADDR4(addr))))
    {
        goto exit;
    }

    if (0 > (status = RADIUS_requestAppendUByte4Attribute(pRadiusReq, RADIUS_ATTR_NAS_PORT, nas_port)))
    {
        goto exit;
    }

    if (0 > (status = RADIUS_requestAppendUByte4Attribute(pRadiusReq, RADIUS_ATTR_NAS_PORT_TYPE, nas_port_type)))
    {
        goto exit;
    }

    if (0 > (status = RADIUS_requestAppendUByte4Attribute(pRadiusReq, RADIUS_ATTR_FRAMED_MTU, eapSession->eapSessionCfg.eap_mtu)))
    {
        goto exit;
    }

    ptr = eap_pkt;
    bytes_to_send = eapSession->recvEapHdr.len;
    if (eapSession->recvEapHdr.len > 253)
        eap_msg_len = 253;
    else
        eap_msg_len = bytes_to_send;

    while (bytes_to_send)
    {
        if (OK > (status = RADIUS_requestAppendAttribute(pRadiusReq,
                                               RADIUS_ATTR_EAP_MESSAGE,
                                               ptr,
                                               eap_msg_len)))
        {
            goto exit;
        }
        ptr += eap_msg_len;
        bytes_to_send -= eap_msg_len;
        if (bytes_to_send < 253)
            eap_msg_len = bytes_to_send;
    }

    len_save = pRadiusReq->rqstLength;
    DIGI_MEMSET(result, 0, MD5_DIGESTSIZE);

    if (OK > (status = RADIUS_requestAppendAttribute(pRadiusReq,
                                             RADIUS_ATTR_MESSAGE_AUTHENTICATOR,
                                             result, MD5_DIGESTSIZE)))
    {
        goto exit;
    }
    auth_offset = len_save + 2;

    len = pRadiusReq->rqstLength;
    p = pRadiusReq->rqstData + RADIUS_CODE_FIELD_SIZE + RADIUS_IDENTIFIER_FIELD_SIZE;

    *p++ = (ubyte)(len >> 8);
    *p++ = (ubyte)(len);

    HMAC_MD5(MOC_HASH(hwAccelCtx) secret, secretlen,
             pRadiusReq->rqstData, len, 0, 0, result);

    DIGI_MEMCPY(pRadiusReq->rqstData + auth_offset, result, MD5_DIGESTSIZE);

    if (!(*radiusReq))
        *radiusReq = pRadiusReq;

exit:
    if ((OK > status) && (pRadiusReq))
    {
        if (!(*radiusReq))
            RADIUS_requestRelease(&pRadiusReq);
    }
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_radiusValidate(ubyte *eap_pkt)
{
    MSTATUS status = OK;
    eapHdr_t *eapHdr = (eapHdr_t *) eap_pkt;
    ubyte4 len;

    if (NULL == eap_pkt)
    {
        status = ERR_EAP_RADIUS_INVALID_EAP_PKT;
        goto exit;
    }

    len = DIGI_NTOHS(eap_pkt + 2);

    switch(eapHdr->code)
    {
        case EAP_CODE_RESPONSE:
        {
            status = ERR_EAP_RADIUS_INVALID_CODE;
            break;
        }

        case EAP_CODE_REQUEST:
        {
            if (len < sizeof(eapHdr_t) + 1)
            {
                status = ERR_EAP_INVALID_PKT_SIZE;
            }
            break;
        }

        case EAP_CODE_SUCCESS:
        case EAP_CODE_FAILURE:
        {
            if (len != sizeof(eapHdr_t))
            {
                status = ERR_EAP_INVALID_PKT_SIZE;
            }
            break;
        }

        default:
        {
            status = ERR_EAP_RADIUS_INVALID_CODE;
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
eap_buildEapPacket(ubyte **eapPkt, RADIUS_RqstRecord *pRadiusReq)
{
    MSTATUS status = OK;
    ubyte *pkt = *eapPkt;
    ubyte *pos = NULL, *pValue;
    ubyte  i = 0, type, len;
    ubyte4 eap_total_len = 0;
    eapHdr_t *eapHdr = NULL;

    while (OK == RADIUS_responseGetAttributeByIndex(pRadiusReq, i, &type, &pValue, &len))
    {
        if (0 == len)
            break;

        if (RADIUS_ATTR_EAP_MESSAGE == type)
            eap_total_len = eap_total_len + len;

        i++;
    }

    if (0 == eap_total_len)
    {
        status = ERR_EAP_RADIUS_EAP_MSG_NOT_FOUND;
        goto exit;
    }

    pkt = MALLOC(eap_total_len);
    if (NULL == pkt)
    {
        status =  ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    pos = pkt;
    i = 0;

    while (OK == RADIUS_responseGetAttributeByIndex(pRadiusReq, i, &type, &pValue, &len))
    {
        if (RADIUS_ATTR_EAP_MESSAGE == type)
        {
            DIGI_MEMCPY(pos, pValue, len);
            pos += len;
        }

        i++;
    }

    eapHdr = (eapHdr_t *)pkt;

    if (DIGI_NTOHS(pkt+2) != (ubyte2)(pos - pkt))
    {
        status = ERR_EAP_INVALID_PKT_SIZE;
        FREE(pkt);
        goto exit;
    }

    *eapPkt = pkt;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Decapsulate (extract) an EAP packet from a RADIUS packet.
This function  decapsulates (extracts) an EAP packet from a RADIUS packet.
Typically the upper layer calls this function and then subsequently passes the
decapsulated packet to the lower layer for transmission to a peer, thereby
providing passthrough authentication service (sending packets to a backend
RADIUS authentication server).

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$
- $__ENABLE_DIGICERT_EAP_RADIUS__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_radius.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID returned from EAP_initInstance.
\param secret           Shared secret between RADIUS %client and backend RADIUS
authentication %server.
\param secretlen        Number of bytes in $secret$.
\param pRadiusReq       Pointer to RADIUS packet (received from backend RADIUS
authentication %server) containing encapsulated EAP packet.
\param eap_pkt          On return, pointer to decapsulated EAP packet.
\param eapLen           On return, pointer to number of bytes in $eap_pkt$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_MD5_getChallenge
\sa EAP_MD5ProcessAuth

*/
extern MSTATUS
EAP_radiusDecapsulate(ubyte * eapSessionHdl,
                      ubyte4 instanceId,
                      ubyte *secret,
                      sbyte4 secretlen,
                      RADIUS_RqstRecord *pRadiusReq,
                      ubyte **eap_pkt,
                      ubyte4 *eapLen)
{
    eapSessionCb_t  *eapSession = NULL;
    ubyte           *pValue, *eapPkt = NULL;
    ubyte           code, len, type, msgAuthLen;
    sbyte4          cmp;
    ubyte           result[MD5_DIGESTSIZE];
    ubyte4          i, j;
    ubyte           *pMsgAuth = NULL, *origMsgAuth = NULL;
    eapHdr_t        *eapHdr = NULL;
    intBoolean      done;
    ubyte4          vendorID;
    ubyte*          pAttr;
    ubyte           attrLength;
    ubyte           subType;
    ubyte           subLength;
    ubyte*          pSubData;
    ubyte*          ppPwd= NULL;
    ubyte2          pwdLen;
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status = OK;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    /* Lookup Session */
    status = eap_lookupSession ((ubyte4)((uintptr)eapSessionHdl),
                                  instanceId, &eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    RADIUS_responseGetCode(pRadiusReq, &code);

    /* copy authenticator from original request for verifying message auth */
    DIGI_MEMCPY((pRadiusReq->rspData + RADIUS_AUTHENTICATOR_OFFSET),
               (pRadiusReq->rqstData + RADIUS_AUTHENTICATOR_OFFSET),
                RADIUS_AUTHENTICATOR_SIZE);

    status = RADIUS_responseGetAttributeByType(pRadiusReq,
                                        RADIUS_ATTR_MESSAGE_AUTHENTICATOR,
                                        &pMsgAuth, &msgAuthLen);
    if (status != OK)
    {
        status = ERR_EAP_RADIUS_MSG_AUTH_NOT_FOUND;
        goto exit;
    }

    /* save original Msg Auth */
    origMsgAuth = MALLOC(msgAuthLen);
    if (NULL == origMsgAuth)
    {
        status =  ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(origMsgAuth, pMsgAuth, msgAuthLen);

    /* Calculate msg Auth */
    DIGI_MEMSET(pMsgAuth, 0, msgAuthLen);
    HMAC_MD5(MOC_HASH(hwAccelCtx) secret, secretlen,
             pRadiusReq->rspData, pRadiusReq->rspLength, 0, 0, result);

    status = DIGI_MEMCMP(result, origMsgAuth, msgAuthLen, &cmp);
    if (OK > status || cmp != 0)
    {
        status = ERR_EAP_RADIUS_INVALID_MSG_AUTH;
        goto exit;
    }

    if (OK > (status = eap_buildEapPacket(&eapPkt, pRadiusReq)))
        goto exit;

    i = 0;
    while (OK == RADIUS_responseGetAttributeByIndex(pRadiusReq, i, &type, &pValue, &len))
    {
        switch(type)
        {
            case RADIUS_ATTR_SESSION_TIMEOUT:
            {
                /* copy session timeout to session CB */
                if (4 == len)
                {
                    eapSession->radiusRetransTimeout = (((ubyte4)*(pValue)   << 24) |
                                                        ((ubyte4)*(pValue+1) << 16) |
                                                        ((ubyte4)*(pValue+2) << 8)  |
                                                        ((ubyte4)*(pValue+3)) );
                }
                break;
            }

            case RADIUS_ATTR_STATE:
            {
                if (eapSession->radiusAttrState)
                {
                    FREE(eapSession->radiusAttrState);
                    eapSession->radiusAttrState = NULL;
                }
                eapSession->radiusAttrState = MALLOC(len);
                if (NULL == eapSession->radiusAttrState)
                {
                    status =  ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }
                DIGI_MEMCPY(eapSession->radiusAttrState, pValue, len);
                eapSession->radiusAttrStateLen = len;
                break;
            }

            case RADIUS_ATTR_TUNNEL_PASSWORD:
            {
                status = RADIUS_responseDecryptPassword(pRadiusReq, pValue,len,&ppPwd,&pwdLen);
                if (OK > status)
                    break;
                if (ppPwd)
                    FREE(ppPwd);
                break;
            }

            default:
            {
                /* Extract the MS_MPPE_RECV_Key/Send Key  VS Attributes Here*/
                DEBUG_ERROR(DEBUG_EAP_MESSAGE,"Recv Radius Attr =",type);
                if (OK == RADIUS_responseGetAttributeByIndexAsVendorSpecific(pRadiusReq, i, &vendorID, &pAttr, &attrLength))
                {
                    if (RADIUS_attributeHasSubAttributes(pAttr, attrLength))
                    {
                        done = FALSE;
                        j = 0;

                        while (!done)
                        {
                            if (OK == RADIUS_getSubAttributeByIndex(pAttr, attrLength, j, &subType, &pSubData, &subLength))
                            {
                                j++;

                                if ((RADIUS_VENDOR_ID_MS == vendorID) &&
                                   (RADIUS_ATTR_MSCHAPV2_MPPE_RECV_KEY == subType))
                                {
                                    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"Recv MPPE_KEY Attr =",subType);
                                    if (!subLength)
                                        continue;

                                    if (eapSession->radiusMPPERecvKey)
                                        FREE(eapSession->radiusMPPERecvKey);

                                    eapSession->radiusMPPERecvKey = NULL;
                                    eapSession->radiusMPPERecvKeyLen = 0;
                                    status = RADIUS_responseDecryptMPPEKey(pRadiusReq, pSubData, subLength, &ppPwd, &pwdLen);
                                    if (OK > status)
                                        goto exit;

                                    eapSession->radiusMPPERecvKey = MALLOC(pwdLen);
                                    if (!eapSession->radiusMPPERecvKey)
                                    {
                                        status = ERR_MEM_ALLOC_FAIL;
                                        goto exit;
                                    }
                                    eapSession->radiusMPPERecvKeyLen = pwdLen;
                                    DIGI_MEMCPY(eapSession->radiusMPPERecvKey, ppPwd + 1, pwdLen);
                                    FREE(ppPwd);

                                }

                                if ((RADIUS_VENDOR_ID_MS == vendorID) &&
                                   (RADIUS_ATTR_MSCHAPV2_MPPE_SEND_KEY == subType))
                                {
                                    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"Send MPPE_KEY Attr =",subType);
                                    if (!subLength)
                                        continue;

                                    if (eapSession->radiusMPPESendKey)
                                        FREE(eapSession->radiusMPPESendKey);

                                    eapSession->radiusMPPESendKey = NULL;
                                    eapSession->radiusMPPESendKeyLen = 0;

                                    status = RADIUS_responseDecryptMPPEKey(pRadiusReq, pSubData, subLength, &ppPwd, &pwdLen);
                                    if (OK > status)
                                        goto exit;

                                    eapSession->radiusMPPESendKey = MALLOC(pwdLen);
                                    if (!eapSession->radiusMPPESendKey)
                                    {
                                        status = ERR_MEM_ALLOC_FAIL;
                                        goto exit;
                                    }
                                    eapSession->radiusMPPESendKeyLen = pwdLen;
                                    DIGI_MEMCPY(eapSession->radiusMPPESendKey, ppPwd + 1, pwdLen);
                                    FREE(ppPwd);

                                }
                            }
                            else
                            {
                                done = TRUE;
                            }
                        }
                    }
                }

                break;
            }
        }

        i++;
    }

    if (OK > (status = eap_radiusValidate(eapPkt)))
        goto exit;

    eapHdr = (eapHdr_t *) eapPkt;

    /* save id sent by RADIUS */
    eapSession->eapLastId = eapHdr->id;
    *eapLen =  DIGI_NTOHS(eapPkt+2);
    *eap_pkt = eapPkt;

    if (RADIUS_CODE_ACCESS_ACCEPT == code &&
       eapHdr->code != EAP_CODE_SUCCESS)
    {
        /* verify that it is an EAP success */
        status = ERR_EAP_RADIUS_INVALID_ACCESS_ACCEPT;
        goto exit;
    }

    if ((RADIUS_CODE_ACCESS_REJECT == code) && (EAP_CODE_FAILURE != eapHdr->code))
    {
        /* verify that it is an EAP Failure */
        status = ERR_EAP_RADIUS_INVALID_ACCESS_REJECT;
        goto exit;
    }

exit:
    if (origMsgAuth)
        FREE(origMsgAuth);
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;
}

/*------------------------------------------------------------------*/

/*! Get a session's MPPE keys.
This function retrieves a session's MPPE (Microsoft Point-to-Point Encryption)
keys that the RADIUS server sent to the passthrough authenticator in the Access
Accept Message.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_RADIUS_CLIENT__$
- $__ENABLE_DIGICERT_EAP_RADIUS__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_radius.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID returned from EAP_initInstance.
\param mppeSendKey      On return, pointer to sent MPPE key.
\param mppeSendKeyLen   On return, pointer to length of sent MPPE key ($mppeSendKey$).
\param mppeRecvKey      On return, pointer to received MPPE key.
\param mppeRecvKeyLen   On return, pointer to length of received MPPE key ($mppeRecvKey$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_radiusGetMPPEKeys(ubyte * eapSessionHdl,
                      ubyte4 instanceId,
                      ubyte **mppeSendKey,ubyte4 *mppeSendKeyLen,
                      ubyte **mppeRecvKey,ubyte4 *mppeRecvKeyLen)
{
    MSTATUS             status = OK;
    eapSessionCb_t     *eapSession = NULL;

    /* Lookup Session */
    status = eap_lookupSession ((ubyte4)((uintptr)eapSessionHdl),
                                  instanceId, &eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    *mppeSendKey  = eapSession->radiusMPPESendKey;
    *mppeSendKeyLen  = eapSession->radiusMPPESendKeyLen;
    *mppeRecvKey  = eapSession->radiusMPPERecvKey;
    *mppeRecvKeyLen  = eapSession->radiusMPPERecvKeyLen;

exit:

    return status;

}

#endif /*defined(__ENABLE_DIGICERT_EAP_RADIUS__) */
#endif /* defined(__ENABLE_DIGICERT_RADIUS_CLIENT__) */
#endif /* defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__) */
