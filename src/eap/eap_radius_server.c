/**
 * @file  eap_radius_server.c
 * @brief EAP RADIUS server
 *
 * @details    RADIUS server implementation
 * @since      1.41
 * @version    2.02 and later
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_RADIUS__
 *     +   \c \__ENABLE_DIGICERT_RADIUS_CLIENT__
 *     +   \c \__ENABLE_RADIUS_SERVER__
 *     Additionally, at least one of the following flags must be defined in moptions.h:
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


#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_EAP_AUTH__)
#if defined(__ENABLE_DIGICERT_RADIUS_CLIENT__)
#if defined(__ENABLE_DIGICERT_EAP_RADIUS__) && defined(__ENABLE_RADIUS_SERVER__)
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
EAP_radiusServerEncapsulate(ubyte * eapSessionHdl,
                      ubyte4 instanceId,
                      ubyte4 authServerID,
                      ubyte *secret,
                      sbyte4 secretlen,
                      ubyte *eap_pkt,
                      ubyte4 eap_pkt_len,
                      RADIUS_RqstRecord *pRadiusReq)
{
    eapSessionCb_t     *eapSession = NULL;
    MSTATUS            status = OK;
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
    status = eap_lookupSession ((ubyte4)eapSessionHdl,
                                  instanceId, &eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    if (eapSession->eapIdentity != NULL)
    {
        if (OK > (status = RADIUS_responseAppendStringAttribute(pRadiusReq, RADIUS_ATTR_USER_NAME, eapSession->eapIdentity)))
            goto exit;
    }
    if (eapSession->radiusAttrState != NULL)
    {
        if (OK > (status = RADIUS_responseAppendAttribute(pRadiusReq, RADIUS_ATTR_STATE, eapSession->radiusAttrState, eapSession->radiusAttrStateLen)))
            goto exit;
    }

    ptr = eap_pkt;
    bytes_to_send = eap_pkt_len;
    if (eap_pkt_len > 253)
        eap_msg_len = 253;
    else
        eap_msg_len = bytes_to_send;

    while (bytes_to_send)
    {
        if (OK > (status = RADIUS_responseAppendAttribute(pRadiusReq,
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

    /* copy authenticator from original request for verifying message auth */
    DIGI_MEMCPY((pRadiusReq->rspData + RADIUS_AUTHENTICATOR_OFFSET),
               (pRadiusReq->rqstData + RADIUS_AUTHENTICATOR_OFFSET),
                RADIUS_AUTHENTICATOR_SIZE);

    len_save = pRadiusReq->rspLength;
    DIGI_MEMSET(result, 0, MD5_DIGESTSIZE);

    if (OK > (status = RADIUS_responseAppendAttribute(pRadiusReq,
                                             RADIUS_ATTR_MESSAGE_AUTHENTICATOR,
                                             result, MD5_DIGESTSIZE)))
    {
        goto exit;
    }
    auth_offset = len_save + 2;

    len = pRadiusReq->rspLength;
    p = pRadiusReq->rspData + RADIUS_CODE_FIELD_SIZE + RADIUS_IDENTIFIER_FIELD_SIZE;

    *p++ = (ubyte)(len >> 8);
    *p++ = (ubyte)(len);

    HMAC_MD5(MOC_HASH(hwAccelCtx) secret, secretlen,
             pRadiusReq->rspData, len, 0, 0, result);

    DIGI_MEMCPY(pRadiusReq->rspData + auth_offset, result, MD5_DIGESTSIZE);

exit:
    if ((OK > status) && (pRadiusReq))
    {
        RADIUS_requestRelease(&pRadiusReq);
    }
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_radiusServerValidate(ubyte *eap_pkt)
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
        case EAP_CODE_REQUEST:
        case EAP_CODE_SUCCESS:
        case EAP_CODE_FAILURE:
        {
            status = ERR_EAP_RADIUS_INVALID_CODE;
            break;
        }

        case EAP_CODE_RESPONSE:
        {
            if (len < sizeof(eapHdr_t) + 1)
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
static MSTATUS
eap_buildServerEapPacket(ubyte **eapPkt, RADIUS_RqstRecord *pRadiusReq)
{
    MSTATUS status = OK;
    ubyte *pkt = *eapPkt;
    ubyte *pos = NULL, *pValue;
    ubyte  i = 0, type, len;
    ubyte4 eap_total_len = 0;
    eapHdr_t *eapHdr = NULL;

    while (OK == RADIUS_requestGetAttributeByIndex(pRadiusReq, i, &type, &pValue, &len))
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

    while (OK == RADIUS_requestGetAttributeByIndex(pRadiusReq, i, &type, &pValue, &len))
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
EAP_radiusServerDecapsulate(ubyte * eapSessionHdl,
                      ubyte4 instanceId,
                      ubyte *secret,
                      sbyte4 secretlen,
                      ubyte* stateAttr,
                      ubyte4 stateAttrLen,
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
    status = eap_lookupSession ((ubyte4)eapSessionHdl,
                                  instanceId, &eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    RADIUS_requestGetCode(pRadiusReq, &code);

    /* copy authenticator from original request for verifying message auth
    DIGI_MEMCPY((pRadiusReq->rqstData + RADIUS_AUTHENTICATOR_OFFSET),
               (pRadiusReq->rspData + RADIUS_AUTHENTICATOR_OFFSET),
                RADIUS_AUTHENTICATOR_SIZE);
    */

    status = RADIUS_requestGetAttributeByType(pRadiusReq,
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
             pRadiusReq->rqstData, pRadiusReq->rqstLength, 0, 0, result);

    status = DIGI_MEMCMP(result, origMsgAuth, msgAuthLen, &cmp);
    if (OK > status || cmp != 0)
    {
        status = ERR_EAP_RADIUS_INVALID_MSG_AUTH;
        goto exit;
    }

    if (stateAttrLen)
    {
        if (eapSession->radiusAttrState)
        {
            FREE(eapSession->radiusAttrState);
            eapSession->radiusAttrState = NULL;
        }
        eapSession->radiusAttrState = MALLOC(stateAttrLen);
        if (NULL == eapSession->radiusAttrState)
        {
            status =  ERR_MEM_ALLOC_FAIL;
            goto exit;

        }
        DIGI_MEMCPY(eapSession->radiusAttrState, stateAttr, stateAttrLen);
        eapSession->radiusAttrStateLen = stateAttrLen;
    }

    if (OK > (status = eap_buildServerEapPacket(&eapPkt, pRadiusReq)))
        goto exit;


    if (OK > (status = eap_radiusServerValidate(eapPkt)))
        goto exit;

    eapHdr = (eapHdr_t *) eapPkt;

    /* save id sent by RADIUS */
    *eapLen =  DIGI_NTOHS(eapPkt+2);
    *eap_pkt = eapPkt;

exit:
    if (origMsgAuth)
        FREE(origMsgAuth);
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;
}


#endif /*defined(__ENABLE_DIGICERT_EAP_RADIUS__) */
#endif /* defined(__ENABLE_DIGICERT_RADIUS_CLIENT__) */
#endif /* defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__) */
