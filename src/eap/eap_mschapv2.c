/**
 * @file  eap_mschapv2.c
 * @brief EAP-MSCHAPv2 method implementation
 *
 * @details    Microsoft Challenge Handshake Authentication Protocol v2
 * @since      1.41
 * @version    1.41 and later
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   $__ENABLE_DIGICERT_EAP_MSCHAPv2__$
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

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))
#if defined(__ENABLE_DIGICERT_EAP_MSCHAPv2__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/debug_console.h"
#include "../crypto/crypto.h"
#include "../crypto/blowfish.h"
#include "../crypto/aes.h"
#include "../crypto/des.h"
#include "../crypto/three_des.h"
#include "../crypto/rc4algo.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/md4.h"
#include "../harness/harness.h"
#include "../common/redblack.h"
#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_mschapv2.h"
#include "../eap/eap_md5.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_des.h"
#endif

/*------------------------------------------------------------------*/

typedef EAP_PACKED struct eapmschap_s
{
    ubyte  opCode;
    ubyte  msId;
    ubyte2 length;
} EAP_PACKED_POST eapMSChap;


/*------------------------------------------------------------------*/

/* RFC 2759 Functions */
static MSTATUS  eap_MSCHAPChallengeHash(
            ubyte * PeerChallenge,
            ubyte * AuthenticatorChallenge,
            ubyte * UserName,
            ubyte2  UserNameLen,
            ubyte * Challenge);

static MSTATUS    eap_MSCHAPDesEncrypt(
            ubyte * Clear,
            ubyte * Key,
            ubyte * Cypher);

static void eap_MSCHAPdes56to64(ubyte *k56, ubyte *k64);
static void eap_MSCHAPbin2hex (const ubyte *szBin, sbyte *szHex, ubyte4 len);


/*------------------------------------------------------------------*/

/*! Build a response to send to the authenticator.
This function builds a response to send to the authenticator based on a
challenge received by a peer.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_MSCHAPv2__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_mschapv2.h

\param appSessionHdl    Application session handle (cookie given by the application to identify the session).
\param data             Pointer to received challenge packet, which must be in the format $<Type, MSCHAP packet>$.
\param datalen          Number of bytes in received challenge packet ($data$).
\param UserName         Pointer to MS-CHAP-V2 session username to use for EAP response.
\param UserNameLen      Number of bytes in session username ($UserName$).
\param passwordString   Pointer to MS-CHAP-V2 session password to use for response.
\param passLen          Number of bytes in session password ($passwordString$).
\param peerChallenge    On return, pointer to peer challenge sent to
authenticator (piggybacked to the response to the challenge originally sent by
the authenticator).
\param authChallenge    On return, pointer to authenticator challenge value
extracted from the data packet; returned to the application for subsequent
inclusion in a call to EAP_MSCHAPpeerResponse.
\param NtAuthenticator  On return, pointer to NT Authenticator (the
$eapResponse$ plus the $UserName$); returned to the application for subsequent
inclusion in a call to EAP_MSCHAPpeerResponse or
EAP_MSCHAPcheckAuthenticatorResponse.
\param eapRespData      On return, pointer to resultant authentication response.
\param eapRespLen       On return, pointer to number of bytes resultant authentication response ($eapRespData$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_MSCHAPstartRequest
\sa EAP_MSCHAPProcessAuth

*/
extern  MSTATUS
EAP_MSCHAPProcessPeer (ubyte *appSessionHdl,
                    ubyte *data,ubyte4 datalen,
                    ubyte *UserName,ubyte4 UserNameLen,
                    ubyte *passwordString,ubyte4 passLen,
                    ubyte *peerChallenge,ubyte *authChallenge,
                    ubyte *NtAuthenticator,
                    ubyte **eapRespData, ubyte4 *eapRespLen)
{
    MSTATUS status = OK;
    ubyte *eapResponse = NULL;
    eapMSChap *eapMSChapPtr = NULL;
    eapMSChap eapRequest ;
    MOC_UNUSED(appSessionHdl);


    if (datalen < sizeof(eapMSChap)+ 1)
    {
        status = ERR_EAP_MSCHAPV2_INVALID_LEN;
        goto exit;
    }

    DIGI_MEMCPY(&eapRequest,data+1,sizeof(eapRequest));
    *eapRespData = NULL;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_MSCHAPProcessPeer: Received Packet  ");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Code ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, eapRequest.opCode);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Id ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, eapRequest.msId);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Len ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, DIGI_NTOHS((ubyte *)&eapRequest.length));
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" ");

    if (eapRequest.opCode != MSCHAPV2_CHALLENGE)
    {
        status = ERR_EAP_MSCHAPV2_INVALID_CODE;
        goto exit;
    }
    if (DIGI_NTOHS((ubyte *)&(eapRequest.length)) != datalen - 1)
    {
        status = ERR_EAP_MSCHAPV2_INVALID_LEN;
        goto exit;
    }

    if (data[sizeof(eapMSChap)+1] != MSCHAPV2_CHAL_LENGTH)
    {
        status = ERR_EAP_MSCHAPV2_INVALID_LEN;
        goto exit;
    }

    *eapRespLen = sizeof(eapMSChap) + 1 + MSCHAPV2_RESP_LENGTH+UserNameLen;

    eapResponse = (ubyte *) MALLOC(*eapRespLen);
    if(NULL == eapResponse)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *eapRespData = eapResponse;
    DIGI_MEMSET(eapResponse, 0, *eapRespLen);

    eapMSChapPtr = (eapMSChap *) eapResponse;
    eapMSChapPtr->opCode = MSCHAPV2_RESPONSE;
    eapMSChapPtr->msId  =  eapRequest.msId;
    /* Set the Length */
    DIGI_HTONS(eapResponse + 2,*eapRespLen);
    eapResponse[sizeof(eapMSChap)] = MSCHAPV2_RESP_LENGTH;
    eapResponse += sizeof(eapMSChap)+1;

    DIGI_MEMCPY(authChallenge,(ubyte *)data+1+sizeof(eapMSChap)+1,16);

    DIGI_MEMCPY(eapResponse, peerChallenge, 16);
    eapResponse += 16;
    eapResponse += 8; /* Reserved */

    if (OK > (status =    EAP_MSCHAPgenerateNTResponse(
                                             authChallenge,
                                             peerChallenge,
                                             UserName,
                                             (ubyte2)UserNameLen,
                                             passwordString,
                                             (ubyte2)passLen,
                                             eapResponse)))
    {
        goto exit;
    }

    DIGI_MEMCPY(NtAuthenticator,eapResponse,24);
    eapResponse += 24;
    eapResponse += 1 /* Flag */;
    DIGI_MEMCPY(eapResponse, UserName, UserNameLen);

exit:
    if ((OK > status) && (*eapRespData))
    {
        FREE (*eapRespData);
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_MSCHAPProcessPeer: Error  ", status);
    }
    return status;
}


/*------------------------------------------------------------------*/

/*! Build a challenge request.
This function builds a challenge request based on the specified challenge data
for the authenticator to transmit to the peer.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_MSCHAPv2__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_mschapv2.h

\param appSessionHdl    Application session handle (cookie given by the application to identify the session).
\param identity         Pointer to user identity.
\param identityLen      Number of bytes in user identity ($identity$).
\param challenge        Pointer to challenge data to use in challenge request.
\param eapReqData       On return, pointer to resultant challenge request.
\param eapReqLen        On return, pointer to number of bytes of resultant challenge request ($eapReqData$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern  MSTATUS
EAP_MSCHAPstartRequest (ubyte *appSessionHdl,
                    ubyte *identity, ubyte2 identityLen,
                    ubyte *challenge,
                    ubyte **eapReqData, ubyte4 *eapReqLen)
{
    MSTATUS status = OK;
    eapMSChap *eapMSChapPtr = NULL;
    ubyte *eapRequest = NULL;
    MOC_UNUSED(appSessionHdl);

    *eapReqLen = sizeof(eapMSChap) + 1 + MSCHAPV2_CHAL_LENGTH+identityLen;
    eapRequest = (ubyte *) MALLOC(*eapReqLen);

    if (NULL == eapRequest)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *eapReqData = eapRequest;
    eapMSChapPtr = (eapMSChap *)eapRequest;
    eapMSChapPtr->opCode = MSCHAPV2_CHALLENGE;

    if (OK > (status = RANDOM_numberGenerator(g_pRandomContext, &eapMSChapPtr->msId, 1)))
    {
        FREE(eapRequest);
        goto exit;
    }

    DIGI_HTONS(eapRequest + 2, *eapReqLen);
    eapRequest[sizeof(eapMSChap)] = MSCHAPV2_CHAL_LENGTH;
    eapRequest += sizeof(eapMSChap)+1;
    DIGI_MEMCPY(eapRequest, challenge, 16);
    eapRequest += MSCHAPV2_CHAL_LENGTH;
    DIGI_MEMCPY(eapRequest, identity, identityLen);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get a 16-byte challenge value for an MSCHAPv2 exchange.
This function returns (through the $buf$ parameter) a 16-byte challenge value.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_MSCHAPv2__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_mschapv2.h

\param buf  On return, pointer to 16-byte challenge value.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern  MSTATUS
EAP_MSCHAPV2_getChallenge(ubyte *buf)
{
    return RANDOM_numberGenerator(g_pRandomContext, buf, MD5_DIGESTSIZE);
}


/*------------------------------------------------------------------*/

/*! Determine whether a peer response is valid, build the resultant SUCCESS/FAIL response, and if SUCCESS, send the response.
This function (called by the authenticator) validates an MSCHAP peer response
and in turn builds an EAP response indicating success or failure. In the case of
success, the authenticator also sends the response to the peer's challenge.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_MSCHAPv2__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_mschapv2.h

\param appSessionHdl    Application session handle (cookie given by the application to identify the session).
\param data             Pointer to EAP payload containing MSCHAP peer response, which must be in the format $<Type, MSCHAP packet>$.
\param datalen          Number of bytes in EAP payload ($data$).
\param UserName         Pointer to MS-CHAP-V2 session username to use for EAP response.
\param UserNameLen      Number of bytes in session username ($UserName$).
\param succMsg          Pointer to desired success message string to send to peer
\param succMsgLen       Number of bytes in desired success message ($succMsg$).
\param failMsg          Pointer to desired fail message string to send to peer.
\param failMsgLen       Number of bytes in desired fail message ($failMsg$).
\param passwordString   Pointer to MS-CHAP-V2 session password to use for response.
\param passLen          Number of bytes in session password ($passwordString$).
\param authChallenge    Pointer to original authenticator challenge that was sent to the peer by EAP_MSCHAPstartRequest.
\param NtResponse       On return, pointer to NT Authenticator for this session.
\param eapReqData       On return, pointer to EAP response message.
\param eapReqLen        On return, pointer to number of bytes in EAP response message ($eapReqData$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_MSCHAPstartRequest
\sa EAP_MSCHAPProcessAuth

*/
extern  MSTATUS
EAP_MSCHAPProcessAuth (ubyte *appSessionHdl,
                    ubyte *data,ubyte4 datalen,
                    ubyte *UserName,ubyte4 UserNameLen,
                    ubyte *succMsg,ubyte4 succMsgLen,
                    ubyte *failMsg,ubyte4 failMsgLen,
                    ubyte *passwordString,ubyte4 passLen,
                    ubyte *authChallenge,ubyte *NtResponse,
                    ubyte **eapReqData, ubyte4 *eapReqLen)
{
    MSTATUS status = OK;
    ubyte *eapRequest = NULL;
    eapMSChap *eapMSChapPtr = NULL;
    eapMSChap eapResponse ;
    ubyte *peerChallenge , *p_PeerResp;
    ubyte peerResponse[24],authResponse[20];
    ubyte failMessage[] = "E=691 R=0 C=cccccccccccccccccccccccccccccccc V=3 M=";
    sbyte4 cmp[1];
    ubyte2 shVal;
    MOC_UNUSED(failMsg);
    MOC_UNUSED(appSessionHdl);

    if (datalen < sizeof(eapMSChap)+ 2)
    {
        status = ERR_EAP_MSCHAPV2_INVALID_LEN;
        goto exit;
    }

    DIGI_MEMCPY((ubyte *)&eapResponse,data+1,sizeof(eapMSChap));


    if (eapResponse.opCode != MSCHAPV2_RESPONSE)
    {
        status = ERR_EAP_MSCHAPV2_INVALID_CODE;
        goto exit;
    }

    DIGI_HTONS((ubyte *)&shVal,eapResponse.length);

    if (shVal != datalen - 1)
    {
        status = ERR_EAP_MSCHAPV2_INVALID_LEN;
        goto exit;
    }

    if (data[sizeof(eapMSChap)+1] != MSCHAPV2_RESP_LENGTH)
    {
        status = ERR_EAP_MSCHAPV2_INVALID_LEN;
        goto exit;
    }

    /* Validate that the full response payload (Value-Size byte +
     * 16-byte PeerChallenge + 8 reserved + 24-byte NT-Response +
     * 1 Flag byte + UserName) fits within datalen, before dereferencing.
     * Otherwise the memcmp's below would read out-of-bounds. */
    if (datalen < ((ubyte4)sizeof(eapMSChap) + 1 + 1 + 16 + 8 + 24 + 1 + UserNameLen))
    {
        status = ERR_EAP_MSCHAPV2_INVALID_LEN;
        goto exit;
    }

    peerChallenge = ((ubyte *)data+1)+sizeof(eapMSChap)+1;

    p_PeerResp = (ubyte *)data +1 +sizeof(eapMSChap)+1+16+8;
    if (OK > (status =    EAP_MSCHAPgenerateNTResponse(
                                             authChallenge,
                                             peerChallenge,
                                             UserName,
                                             (ubyte2)UserNameLen,
                                             passwordString,
                                             (ubyte2)passLen,
                                             peerResponse)))
       goto exit;

    if (OK > (status = DIGI_MEMCMP(peerResponse,p_PeerResp, 24,cmp)) || (0 != *cmp))
    {
        status = ERR_EAP_MSCHAP_AUTH_FAILURE;
        goto failure;
    }

   /* Copy Over the NT Response for Auth Usage , Key Derivation */
    DIGI_MEMCPY(NtResponse,peerResponse,sizeof(peerResponse));

    p_PeerResp += 24;
    p_PeerResp += 1 /* Flag */;

    /* Check That Identity Matches */

    if (OK > (status = DIGI_MEMCMP(UserName,p_PeerResp, UserNameLen,cmp)) || (0 != *cmp))
    {
        status = ERR_EAP_MSCHAP_AUTH_FAILURE;
        goto exit;
    }

/* success */
    *eapReqLen = sizeof(eapMSChap) + 1 +MSCHAPV2_AUTHENTICATOR_LENGTH+3+succMsgLen;

    eapRequest = (ubyte *) MALLOC(*eapReqLen);
    if(NULL == eapRequest)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    *eapReqData = eapRequest;
    DIGI_MEMSET(eapRequest, 0, *eapReqLen);

    eapMSChapPtr = (eapMSChap *) eapRequest;
    eapMSChapPtr->opCode = MSCHAPV2_SUCCESS;
    eapMSChapPtr->msId  =  eapResponse.msId;

    DIGI_HTONS(eapRequest+2, *eapReqLen);
    eapRequest += sizeof(eapMSChap);

    if (OK > (status =    EAP_MSCHAPgenerateAuthenticatorResponse(
                                                       passwordString,
                                                       (ubyte2)passLen,
                                                       peerResponse,
                                                       peerChallenge,
                                                       authChallenge,
                                                       UserName,
                                                       (ubyte2)UserNameLen,
                                                       authResponse)))
           goto exit;

    DIGI_MEMCPY(eapRequest,(ubyte *)"S=",2);
    eapRequest += 2;
    eap_MSCHAPbin2hex((const ubyte*)authResponse,(sbyte*)eapRequest,20);
    eapRequest += 40;
    DIGI_MEMCPY(eapRequest,(ubyte *)" M=",3);
    eapRequest += 3;
    DIGI_MEMCPY(eapRequest,succMsg,succMsgLen);
    eapRequest +=succMsgLen;
    *eapRequest ='\0';

    goto exit;

failure:

  /*  "E=691 R=0 C=cccccccccccccccccccccccccccccccc V=3 M=<msg>" */

    *eapReqLen = sizeof(eapMSChap) + DIGI_STRLEN((const sbyte*)failMessage) + failMsgLen;

    eapRequest = (ubyte *) MALLOC(*eapReqLen);
    if(NULL == eapRequest)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    *eapReqData = eapRequest;
    DIGI_MEMSET(eapRequest, 0, *eapReqLen);

    eapMSChapPtr = (eapMSChap *) eapRequest;
    eapMSChapPtr->opCode = MSCHAPV2_FAILURE;
    eapMSChapPtr->msId   = eapResponse.msId;
    DIGI_HTONS(eapRequest+2, *eapReqLen);
    eapRequest += sizeof(eapMSChap);
    DIGI_MEMCPY(eapRequest, failMessage, DIGI_STRLEN((const sbyte*)failMessage));
    eapRequest += DIGI_STRLEN((const sbyte*)failMessage);
    DIGI_MEMCPY(eapRequest,succMsg,failMsgLen);
    eapRequest += failMsgLen;
    *eapRequest ='\0';
    status = OK;
    return status;


exit:
    if ((OK > status) && (*eapReqData))
        FREE (*eapReqData);

    return status;
}


/*------------------------------------------------------------------*/

/*! Determine whether an authenticator response to a peer challenge is valid and build the resultant SUCCESS/FAIL response.
This function (used by the peer) determines whether the authenticator response
to the peer's previous challenge is valid, returns the results ($TRUE$ or $FALSE$)
through the $cmp$ parameter, and builds the resultant SUCCESS/FAIL response.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_MSCHAPv2__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_mschapv2.h

\param appSessionHdl    Application session handle (cookie given by the application to identify the session).
\param data             Pointer to EAP payload containing MSCHAP authenticator response, which must be in the format $<Type, MSCHAP packet>$.
\param datalen          Number of bytes in EAP payload ($data$).
\param passwordString   Pointer to MS-CHAP-V2 session password to use for response.
\param passLen          Number of bytes in session password ($passwordString$).
\param peerResponse     Calculated NT Authenticator value (returned from EAP_MSCHAPProcessPeer) originally sent to the authenticator.
\param peerChallenge    Pointer to original peer challenge that was sent to the authenticator
\param authChallenge    Pointer to original challenge response received from the authenticator by EAP_MSCHAPProcessPeer.
\param UserName         Pointer to MS-CHAP-V2 session username to use for EAP response.
\param UserNameLen      Number of bytes in session username ($UserName$).
\param eapRespData      On return, pointer to EAP response message.
\param eapRespLen       On return, pointer to number of bytes in EAP response message ($eapRespData$).
\param cmp              On return, pointer to result of authenticator-peer mutual challenge result: $TRUE$ or $FALSE$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_MSCHAPstartRequest
\sa EAP_MSCHAPProcessAuth
\sa EAP_MSCHAPProcessPeer

*/
extern  MSTATUS
EAP_MSCHAPpeerResponse (ubyte *appSessionHdl,
                    ubyte *data,ubyte2 datalen,
                    ubyte *passwordString,ubyte2 passLen,
                    ubyte * peerResponse/*NT */,
                    ubyte * peerChallenge,
                    ubyte * authChallenge,
                    ubyte * UserName,ubyte2 UserNameLen,
                    ubyte **eapRespData, ubyte4 *eapRespLen,
                    byteBoolean *cmp)
{
    MSTATUS status = OK;
    eapMSChap *eapMSChapPtr = NULL;
    eapMSChap eapRequest;
    ubyte   opCode = MSCHAPV2_SUCCESS;
    ubyte *eapResponse = NULL,*eapReq;
    MOC_UNUSED(appSessionHdl);
    MOC_UNUSED(datalen);

    if (datalen < sizeof(eapMSChap)+ 1)
    {
        status = ERR_EAP_MSCHAPV2_INVALID_LEN;
        goto exit;
    }

    DIGI_MEMCPY(&eapRequest,data+1,sizeof(eapRequest));

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_MSCHAPpeerResponse: Received Packet  ");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Code ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, eapRequest.opCode);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Id ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, eapRequest.msId);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Len ");
    DEBUG_INT(DEBUG_EAP_MESSAGE,DIGI_NTOHS((ubyte *)&eapRequest.length));
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" ");

    eapReq = data+sizeof(eapMSChap)+1;

    if (MSCHAPV2_SUCCESS != eapRequest.opCode)
    {
        opCode = MSCHAPV2_FAILURE;
        *cmp = FALSE;
    }
    else
    {
        if (OK > (status = EAP_MSCHAPcheckAuthenticatorResponse(
                                                   passwordString,
                                                   passLen,
                                                   peerResponse,
                                                   peerChallenge,
                                                   authChallenge,
                                                   UserName,
                                                   UserNameLen,
                                                   eapReq,
                                                   cmp)))
        {
           opCode = MSCHAPV2_FAILURE;
           *cmp = FALSE;
        }

        if (TRUE != *cmp)
        {
            opCode = MSCHAPV2_FAILURE;
        }
    }

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" Returning OpCode ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, opCode);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" ");

    *eapRespLen = sizeof(eapMSChap);
    eapResponse = (ubyte *) MALLOC(*eapRespLen);

    if(NULL == eapResponse)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *eapRespData = eapResponse;
    eapMSChapPtr = (eapMSChap *)eapResponse;
    eapMSChapPtr->opCode = opCode;
    eapMSChapPtr->msId  =  eapRequest.msId;
    DIGI_HTONS(eapResponse + 2, 4);

/* If working against MS IAS, it likes the fact that we return just 1 Byte of Code and not the rest of the struct  hence *eapRespLen = 1  */

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_MSCHAPpeerResponse: Error  ", status);
    return status;
}


/*------------------------------------------------------------------*/

/*! Build an MS-CHAP-V0 NT response.
This function builds an NT Response for MS-CHAP-V0 based on the specified
authenticator challenge and peer password.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_MSCHAPv2__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_mschapv2.h

\param AuthenticatorChallenge   Pointer to original authenticator challenge built by EAP_MSCHAPProcessPeer.
\param Password                 Pointer to peer password to use for response.
\param PasswordLen              Number of bytes in peer password ($Password$).
\param Response                 On return, pointer to resultant response.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_MSCHAPv0generateNTResponse(ubyte * AuthenticatorChallenge,
                               ubyte * Password,
                               ubyte2  PasswordLen,
                               ubyte * Response)
{
    ubyte  PasswordHash[16];
    MSTATUS status = OK;


    if (OK > (status = EAP_MSCHAPNtPasswordHash(Password, PasswordLen, PasswordHash)))
        goto exit;

    if (OK > (status = EAP_MSCHAPChallengeResponse(AuthenticatorChallenge, PasswordHash, Response)))
        goto exit;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Build an MS-CHAP-V2 NT response.
This function builds an NT Response for MS-CHAP-V2 based on the specified
authenticator and peer challenges, peer username, and peer password.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_MSCHAPv2__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_mschapv2.h

\param AuthenticatorChallenge   Pointer to original authenticator challenge built by EAP_MSCHAPProcessPeer.
\param PeerChallenge            Pointer to original peer challenge sent by EAP_MSCHAPProcessPeer.
\param UserName                 Pointer to peer username.
\param UserNameLen              Number of bytes in peer username ($UserName$).
\param Password                 Pointer to MS-CHAP-V2 session password to use for response.
\param PasswordLen              Number of bytes in MS-CHAP-V2 session password ($Password$).
\param Response                 On return, pointer to resultant response.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_MSCHAPstartRequest
\sa EAP_MSCHAPProcessAuth

*/
extern MSTATUS
EAP_MSCHAPgenerateNTResponse(ubyte * AuthenticatorChallenge,
                             ubyte * PeerChallenge,
                             ubyte * UserName,
                             ubyte2  UserNameLen,
                             ubyte * Password,
                             ubyte2  PasswordLen,
                             ubyte * Response)
{
      ubyte  Challenge[8];
      ubyte  PasswordHash[16];
      MSTATUS status = OK;

      if (OK > (status = eap_MSCHAPChallengeHash(PeerChallenge, AuthenticatorChallenge,
                                                 UserName, UserNameLen, Challenge)))
          goto exit;

    if (OK > (status = EAP_MSCHAPNtPasswordHash(Password, PasswordLen, PasswordHash)))
          goto exit;

    if (OK > (status = EAP_MSCHAPChallengeResponse(Challenge, PasswordHash, Response)))
          goto exit;

exit:
      return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_MSCHAPChallengeHash(ubyte * PeerChallenge,
                        ubyte * AuthenticatorChallenge,
                        ubyte * UserName,
                        ubyte2  UserNameLen,
                        ubyte * Challenge)
{
      /*
       * SHAInit(), SHAUpdate() and SHAFinal() functions are an
       * implementation of Secure Hash Algorithm (SHA-1) [11]. These are
       * available in public domain or can be licensed from
       * RSA Data Security, Inc.
       */
    ubyte*          pShaOutput;
    shaDescr*       p_shaContext = NULL;
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    pShaOutput = (ubyte *)    MALLOC(SHA_HASH_RESULT_SIZE);

    if (OK > (status = SHA1_allocDigest(MOC_HASH(hwAccelCtx)(BulkCtx*) &p_shaContext)))
        goto exit;

    if ((NULL == pShaOutput) || (NULL == p_shaContext))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) p_shaContext)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) p_shaContext, PeerChallenge, 16)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) p_shaContext, AuthenticatorChallenge, 16)))
        goto exit;

      /*
       * Only the user name (as presented by the peer and
       * excluding any prepended domain name)
       * is used as input to SHAUpdate().
       */
    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) p_shaContext, UserName, UserNameLen)))
        goto exit;

    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) p_shaContext, pShaOutput)))
        goto exit;

    DIGI_MEMCPY(Challenge, pShaOutput, 8);

exit:
    if (NULL != pShaOutput)
        FREE(pShaOutput);

    SHA1_freeDigest(MOC_HASH(hwAccelCtx) (BulkCtx*) &p_shaContext);
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get a password hash (using MD4).
This function generates a password hash (disregarding any terminating $NULL$) using MD4.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_MSCHAPv2__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_mschapv2.h

\param Password         Pointer to peer password.
\param PasswordLen      Number of bytes in peer password ($Password$).
\param PasswordHash     On return, pointer to generated password hash.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_MSCHAPNtPasswordHash(
          ubyte * Password,
          ubyte2  PasswordLen,
          ubyte * PasswordHash)
{
      /*
       * Use the MD4 algorithm [5] to irreversibly hash Password
       * into PasswordHash.  Only the password is hashed without
       * including any terminating 0.
       */

        /* Unicode the password  */
    ubyte*          pUCBuf;
    ubyte2          itr;
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status = OK;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    pUCBuf = (ubyte *)MALLOC(PasswordLen * 2);

    if ((NULL == pUCBuf))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET(pUCBuf, 0, PasswordLen * 2);

    for (itr = 0; itr < PasswordLen; itr++)
    {
        pUCBuf[2 * itr] = Password[itr];
    }

    status = MD4_completeDigest(MOC_HASH(hwAccelCtx) pUCBuf, (PasswordLen * 2), PasswordHash);

exit:
    if (NULL != pUCBuf)
        FREE(pUCBuf);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get an irreversible hash of a password hash (using MD4).
This function generates an irreversible hash of a password hash (using MD4).

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_MSCHAPv2__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_mschapv2.h

\param PasswordHash         Pointer to password hash.
\param PasswordHashHash     On return, pointer to generated hash.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_MSCHAPstartRequest
\sa EAP_MSCHAPProcessAuth

*/
extern MSTATUS
EAP_MSCHAPHashNtPasswordHash(
          ubyte * PasswordHash,
          ubyte * PasswordHashHash)
{
   /*
    * Use the MD4 algorithm [5] to irreversibly hash
    * PasswordHash into PasswordHashHash.
    */
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto exit;

    status = MD4_completeDigest(MOC_HASH(hwAccelCtx) PasswordHash, 16, PasswordHashHash);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
exit:
    return status;

}


/*------------------------------------------------------------------*/

/*! Build an MSCHAP v0 response to the specified challenge and password hash.
This function builds an MSCHAP v0 response to the specified challenge and
password hash.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_MSCHAPv2__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_mschapv2.h

\param Challenge    Pointer to challenge value.
\param PasswordHash Pointer to password hash.
\param Response     On return, pointer to response.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_MSCHAPChallengeResponse(
          ubyte*  Challenge,
          ubyte*  PasswordHash,
          ubyte*  Response)
{
      MSTATUS status = OK;
      ubyte ZPasswordHash[7];

      DIGI_MEMCPY(ZPasswordHash,PasswordHash+14,2);
      DIGI_MEMSET(ZPasswordHash+2,0,5);

      if (OK > (status = eap_MSCHAPDesEncrypt(Challenge, PasswordHash, Response)))
          goto exit;

      if (OK > (status = eap_MSCHAPDesEncrypt(Challenge, PasswordHash+7, Response+8)))
          goto exit;

      if (OK > (status = eap_MSCHAPDesEncrypt(Challenge, ZPasswordHash, Response+16)))
          goto exit;

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_MSCHAPDesEncrypt(ubyte * Clear,
                     ubyte * Key,
                     ubyte * Cypher)
{
    MSTATUS status = OK;
    ubyte k64[8];
    des_ctx * p_desCtx = NULL;    /*
     * Use the DES encryption algorithm [4] in ECB mode [10]
     * to encrypt Clear into Cypher such that Cypher can
     * only be decrypted back to Clear by providing Key.
     * Note that the DES algorithm takes as input a 64-bit
     * stream where the 8th, 16th, 24th, etc.  bits are
     * parity bits ignored by the encrypting algorithm.
     * Unless you write your own DES to accept 56-bit input
     * without parity, you will need to insert the parity bits
     * yourself.
     */

    if (OK > (status = DIGI_MALLOC((void**)&p_desCtx, sizeof(des_ctx))))
        goto exit;

    if (OK > (status = DIGI_MEMSET((ubyte*)p_desCtx, 0x00, sizeof(des_ctx))))
        goto exit;

    if ((NULL == p_desCtx))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    eap_MSCHAPdes56to64(Key, k64);

#ifndef __DISABLE_3DES_CIPHERS__     /* not needed when 3DES cipher are not enabled*/
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_DES_initKey(p_desCtx,k64,8)))
        goto exit;

    if (OK > (status = CRYPTO_INTERFACE_DES_encipher(p_desCtx, Clear, Cypher, 8)))
        goto exit;
#else
    if (OK > (status = DES_initKey(p_desCtx,k64,8)))
        goto exit;

    if (OK > (status = DES_encipher(p_desCtx, Clear, Cypher, 8)))
        goto exit;
#endif
#endif

exit:

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DES_clearKey(p_desCtx);
#endif

    if (NULL != p_desCtx)
        DIGI_FREE((void**)&p_desCtx);
    return status;
}


/*------------------------------------------------------------------*/

/*! Generate an authenticator response.
This function (used by Mocana internal code) generates an authenticator response.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_MSCHAPv2__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_mschapv2.h

\param Password         Pointer to MS-CHAP-V2 session password to use for response.
\param PasswordLen      Number of bytes in MS-CHAP-V2 session password ($Password$).
\param NtResponse       Calculated NT Authenticator value (returned from EAP_MSCHAPProcessPeer).
\param PeerChallenge    Pointer to original peer challenge sent by EAP_MSCHAPProcessPeer.
\param AuthenticatorChallenge   Pointer to original authenticator challenge built by EAP_MSCHAPProcessPeer.
\param UserName         Pointer to MS-CHAP-V2 session username to use for EAP response.
\param UserNameLen      Number of bytes in MS-CHAP-V2 session username ($Username$).
\param AuthenticatorResponse    On return, pointer to response sent by the
authenticator to the peer in the challenge Success message, in the format "S="
followed by 40 ASCII hexadecimal digits.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_MSCHAPstartRequest
\sa EAP_MSCHAPProcessAuth

*/
extern MSTATUS
EAP_MSCHAPgenerateAuthenticatorResponse(ubyte * Password,
                                        ubyte2  PasswordLen,
                                        ubyte*  NtResponse,
                                        ubyte*  PeerChallenge,
                                        ubyte*  AuthenticatorChallenge,
                                        ubyte*  UserName,
                                        ubyte2  UserNameLen,
                                        ubyte*  AuthenticatorResponse)
{
    ubyte              PasswordHash[16];
    ubyte              PasswordHashHash[16];
    ubyte              Challenge[8];
    ubyte*      pShaOutput;
    shaDescr*   p_shaContext = NULL;
    MSTATUS     status;

    /* "Magic" constants used in response generation */
    ubyte Magic1[39] =
         {0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
          0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
          0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
          0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74};

    ubyte Magic2[41] =
         {0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
          0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
          0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
          0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
          0x6E};

    /* Unicode the password  */
    ubyte * pUCBuf = NULL;
    ubyte2 itr;
    hwAccelDescr    hwAccelCtx;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    pShaOutput   = (ubyte *)MALLOC(SHA_HASH_RESULT_SIZE);

    if (OK > (status = SHA1_allocDigest(MOC_HASH(hwAccelCtx)(BulkCtx*) &p_shaContext)))
        goto exit;

    pUCBuf = (ubyte *)MALLOC(PasswordLen * 2);
    if ((NULL == pUCBuf))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET(pUCBuf, 0, PasswordLen * 2);

    for (itr = 0; itr < PasswordLen; itr++)
    {
            pUCBuf[2 * itr] = Password[itr];
    }

    /* Hash the password with MD4 */
    if (OK > (status = EAP_MSCHAPNtPasswordHash(Password, PasswordLen, PasswordHash)))
        goto exit;

    /* Now hash the hash */
    if (OK > (status = EAP_MSCHAPHashNtPasswordHash(PasswordHash, PasswordHashHash)))
        goto exit;

    if ((NULL == pShaOutput) || (NULL == p_shaContext))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) p_shaContext)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) p_shaContext, PasswordHashHash, 16)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) p_shaContext, NtResponse, 24)))
        goto exit;

      /*
       * Only the user name (as presented by the peer and
       * excluding any prepended domain name)
       * is used as input to SHAUpdate().
       */
    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) p_shaContext, Magic1, 39)))
        goto exit;

    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) p_shaContext, pShaOutput)))
        goto exit;

    if (OK > (status = eap_MSCHAPChallengeHash(PeerChallenge, AuthenticatorChallenge, UserName, UserNameLen, Challenge)))
        goto exit;

    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) p_shaContext)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) p_shaContext, pShaOutput, 20)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) p_shaContext, Challenge, 8)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) p_shaContext, Magic2 , 41)))
        goto exit;

    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) p_shaContext, pShaOutput)))
        goto exit;

    /*
     * Encode the value of 'Digest' as "S=" followed by
     * 40 ASCII hexadecimal digits and return it in
     * AuthenticatorResponse.
     * For example,
     *   "S=0123456789ABCDEF0123456789ABCDEF01234567"
     */

    DIGI_MEMCPY(AuthenticatorResponse,pShaOutput,20);

exit:
    if (NULL != pUCBuf)
        FREE(pUCBuf);

    if (NULL != pShaOutput)
        FREE(pShaOutput);

    SHA1_freeDigest(MOC_HASH(hwAccelCtx) (BulkCtx*) &p_shaContext);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;
}


/*------------------------------------------------------------------*/

static const ubyte *letters = (ubyte *)"0123456789ABCDEF";

/*
 *      eap_MSCHAPbin2hex creates hexadecimal presentation
 *      of binary data
 */
static void
eap_MSCHAPbin2hex (const ubyte *szBin, sbyte *szHex, ubyte4 len)
{
    ubyte4 i;

    for (i = 0; i < len; i++)
    {
        szHex[i<<1] = letters[szBin[i] >> 4];
        szHex[(i<<1) + 1] = letters[szBin[i] & 0x0F];
    }
}


/*------------------------------------------------------------------*/

/*! Get a hexadecimal representation of binary data.
This function creates a hexadecimal representation of binary data.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_MSCHAPv2__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_mschapv2.h

\param szBin    Pointer to binary data to represent as hexadecimal.
\param szHex    On return, pointer to hexadecimal representation of the $szBin$ data.
\param len      Number of bytes of binary data ($szBin$).

\return None.

*/
extern void
EAP_MSCHAPbin2hex (const ubyte *szBin, sbyte *szHex, ubyte4 len)
{

    eap_MSCHAPbin2hex (szBin, szHex, len);

}


/*------------------------------------------------------------------*/

/*! Determine an MSCHAP authenticator response's status and include it in a new EAP response.
This function (called by the peer) validates an MSCHAP authenticator response
(by calling EAP_MSCHAPgenerateAuthenticatorResponse) and in turn builds an EAP
response indicating the authenticator's response status.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_MSCHAPv2__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_mschapv2.h

\param Password         Pointer to MS-CHAP-V2 session password to use for response.
\param PasswordLen      Number of bytes in session password ($Password$).
\param NtResponse       Calculated NT Authenticator value (returned from
EAP_MSCHAPProcessPeer).
\param PeerChallenge    Pointer to original peer challenge sent by
EAP_MSCHAPProcessPeer.
\param AuthenticatorChallenge   Pointer to original authenticator challenge
built by EAP_MSCHAPProcessPeer.
\param UserName         Pointer to MS-CHAP-V2 session username to use for
response.
\param UserNameLen      Number of bytes in session username ($Username$).
\param ReceivedResponse Pointer to response sent by the authenticator to the
peer in the challenge Success message. (If the challenge fails, this value doesn't change.)
\param ResponseOK       On return, pointer to result to return to peer: $TRUE$
if the challenge succeeded, $FALSE$ otherwise.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_MSCHAPstartRequest
\sa EAP_MSCHAPProcessAuth

*/
extern MSTATUS
EAP_MSCHAPcheckAuthenticatorResponse(
   ubyte * Password,
   ubyte2  PasswordLen,
   ubyte * NtResponse,
   ubyte * PeerChallenge,
   ubyte * AuthenticatorChallenge,
   ubyte * UserName,
   ubyte2  UserNameLen,
   ubyte*  ReceivedResponse,
   byteBoolean * ResponseOK)
{
    ubyte   MyResponse[20];
    ubyte   MyResponseHex[40];
    sbyte4  cmp[1];
    MSTATUS status = OK;

    *ResponseOK = FALSE;

    status = EAP_MSCHAPgenerateAuthenticatorResponse(Password,
                                    PasswordLen,
                                    NtResponse, PeerChallenge,
                                    AuthenticatorChallenge, UserName,
                                    UserNameLen,
                                    MyResponse);

    eap_MSCHAPbin2hex(MyResponse,(sbyte *)MyResponseHex,20);

    if ((OK > (status = DIGI_MEMCMP(MyResponseHex , ReceivedResponse+2,40,cmp))) ||
        (0 != *cmp))
    {
        *ResponseOK = FALSE;
    }
    else
    {
        *ResponseOK = TRUE;
    }

    return status;
}


/*------------------------------------------------------------------*/

static ubyte parity[128] =
{
    0x01, 0x02, 0x04, 0x07, 0x08, 0x0b, 0x0d, 0x0e,
    0x10, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f,
    0x20, 0x23, 0x25, 0x26, 0x29, 0x2a, 0x2c, 0x2f,
    0x31, 0x32, 0x34, 0x37, 0x38, 0x3b, 0x3d, 0x3e,
    0x40, 0x43, 0x45, 0x46, 0x49, 0x4a, 0x4c, 0x4f,
    0x51, 0x52, 0x54, 0x57, 0x58, 0x5b, 0x5d, 0x5e,
    0x61, 0x62, 0x64, 0x67, 0x68, 0x6b, 0x6d, 0x6e,
    0x70, 0x73, 0x75, 0x76, 0x79, 0x7a, 0x7c, 0x7f,
    0x80, 0x83, 0x85, 0x86, 0x89, 0x8a, 0x8c, 0x8f,
    0x91, 0x92, 0x94, 0x97, 0x98, 0x9b, 0x9d, 0x9e,
    0xa1, 0xa2, 0xa4, 0xa7, 0xa8, 0xab, 0xad, 0xae,
    0xb0, 0xb3, 0xb5, 0xb6, 0xb9, 0xba, 0xbc, 0xbf,
    0xc1, 0xc2, 0xc4, 0xc7, 0xc8, 0xcb, 0xcd, 0xce,
    0xd0, 0xd3, 0xd5, 0xd6, 0xd9, 0xda, 0xdc, 0xdf,
    0xe0, 0xe3, 0xe5, 0xe6, 0xe9, 0xea, 0xec, 0xef,
    0xf1, 0xf2, 0xf4, 0xf7, 0xf8, 0xfb, 0xfd, 0xfe
};


/*------------------------------------------------------------------*/

/*
 *  convert a 7 byte key to an 8 byte one
 */
static void
eap_MSCHAPdes56to64(ubyte *k56, ubyte *k64)
{
    ubyte4 hi, lo;

    hi = ((ubyte4)k56[0]<<24)|((ubyte4)k56[1]<<16)|((ubyte4)k56[2]<<8)|k56[3];
    lo = ((ubyte4)k56[4]<<24)|((ubyte4)k56[5]<<16)|((ubyte4)k56[6]<<8);

    k64[0] = parity[(hi>>25)&0x7f];
    k64[1] = parity[(hi>>18)&0x7f];
    k64[2] = parity[(hi>>11)&0x7f];
    k64[3] = parity[(hi>>4)&0x7f];
    k64[4] = parity[((hi<<3)|(lo>>29))&0x7f];
    k64[5] = parity[(lo>>22)&0x7f];
    k64[6] = parity[(lo>>15)&0x7f];
    k64[7] = parity[(lo>>8)&0x7f];
}

/*! Generate an MSK (master session key).
This function generates an MSK (master session key).

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_MSCHAPv2__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_mschapv2.h

\param Password         Pointer to MS-CHAP-V2 session password to use for response.
\param PasswordLen      Number of bytes in MS-CHAP-V2 session password ($Password$).
\param NtResponse       Calculated NT Authenticator value (returned from EAP_MSCHAPProcessPeer).
\param MasterKey        On return, pointer to MSK value.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_MSCHAPstartRequest
\sa EAP_MSCHAPProcessAuth

*/
extern MSTATUS
EAP_MSCHAPgenerateMasterKey(
   ubyte * Password,
   ubyte2  PasswordLen,
   ubyte*  NtResponse,
   ubyte*  MasterKey)
{
    ubyte              PasswordHash[16];
    ubyte              PasswordHashHash[16];
    ubyte*      pShaOutput = NULL;
    shaDescr*   p_shaContext = NULL;
    MSTATUS     status = OK;

   /*
    * "Magic" constants used in response generation
    */
    ubyte Magic1[27] =
        {0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74,
         0x68, 0x65, 0x20, 0x4d, 0x50, 0x50, 0x45, 0x20, 0x4d,
         0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4b, 0x65, 0x79};

    /* Unicode the password  */
    ubyte * pUCBuf = NULL;
    ubyte2 itr;
    hwAccelDescr    hwAccelCtx;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    pShaOutput   = (ubyte *)MALLOC(SHA_HASH_RESULT_SIZE);

    if (OK > (status = SHA1_allocDigest(MOC_HASH(hwAccelCtx)(BulkCtx*) &p_shaContext)))
        goto exit;

    pUCBuf = (ubyte *)MALLOC(PasswordLen * 2);
    if ((NULL == pUCBuf))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET(pUCBuf, 0, PasswordLen * 2);

    for (itr = 0; itr < PasswordLen; itr++)
    {
            pUCBuf[2 * itr] = Password[itr];
    }



      /*
       * Hash the password with MD4
       */

    if (OK > (status = EAP_MSCHAPNtPasswordHash(Password, PasswordLen, PasswordHash)))
        goto exit;

    /*
     * Now hash the hash
     */

    if (OK > (status = EAP_MSCHAPHashNtPasswordHash(PasswordHash, PasswordHashHash)))
        goto exit;


    if ((NULL == pShaOutput) || (NULL == p_shaContext))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) p_shaContext)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) p_shaContext, PasswordHashHash, 16)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) p_shaContext, NtResponse, 24)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) p_shaContext, Magic1, 27)))
        goto exit;

    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) p_shaContext, pShaOutput)))
        goto exit;

       DIGI_MEMCPY(MasterKey,pShaOutput,16);

#if defined(__ENABLE_ALL_DEBUGGING__)
#ifndef __ENABLE_KEYVPN_LOG_SUPPRESSION__
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"  ");
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"MSCHAPv2 Master Key ");
    EAP_PrintBytes( MasterKey, 16);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"  ");
#endif
#endif

exit:
    if (NULL != pUCBuf)
        FREE(pUCBuf);

    if (NULL != pShaOutput)
        FREE(pShaOutput);

    SHA1_freeDigest(MOC_HASH(hwAccelCtx) (BulkCtx*) &p_shaContext);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;
}


/*------------------------------------------------------------------*/

/*! Generate a send/receive client/server session key.
This function generates a session key for send/receive and client/server, as
specified, from the specified MSK (master session key). The combination of the
send and server parameter values determine which keys are generated. The
send-side key on the server (authenticator) must match the receive-side key on
the client (peer).

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_MSCHAPv2__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_mschapv2.h

\param masterKey        Pointer to MSK value.
\param sessionKey       On return, pointer to resultant session key.
\param sessionKeyLen    Length (number of bytes) of session key to generate.
\param send             $0$ to specify a receive session key; non-zero for a send session key.
\param server           $0$ to specify a server-side (authenticator) key; non-zero for a client-side (peer) key.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_MSCHAPstartRequest
\sa EAP_MSCHAPProcessAuth

*/
extern MSTATUS
EAP_MSCHAPgenerateSessionKey(
   ubyte*  masterKey ,
   ubyte*  sessionKey ,
   ubyte2  sessionKeyLen,
   byteBoolean send,
   byteBoolean server)
{
    ubyte*      pShaOutput;
    shaDescr*   p_shaContext = NULL;
    ubyte       *magic;
    MSTATUS     status = OK;

    /*
    * "Magic" constants used in response generation
    */
    ubyte SHAPAD1[40] =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

    ubyte SHAPAD2[40] =
        {
            0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2,
            0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2,
            0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2,
            0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2, 0xF2
        };
    ubyte Magic2[84] =
        {
            0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
            0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
            0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
            0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79,
            0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
            0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, 0x64, 0x65,
            0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
            0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
            0x6b, 0x65, 0x79, 0x2e
        };

    ubyte Magic3[84] =
        {
            0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
            0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
            0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
            0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
            0x6b, 0x65, 0x79, 0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68,
            0x65, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73,
            0x69, 0x64, 0x65, 0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73,
            0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20,
            0x6b, 0x65, 0x79, 0x2e
        };

    hwAccelDescr    hwAccelCtx;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    pShaOutput   = (ubyte *)MALLOC(SHA_HASH_RESULT_SIZE);
    if (OK > (status = SHA1_allocDigest(MOC_HASH(hwAccelCtx)(BulkCtx*) &p_shaContext)))
        goto exit;

    if ((NULL == pShaOutput) || (NULL == p_shaContext))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) p_shaContext)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) p_shaContext, masterKey, 16)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) p_shaContext, SHAPAD1, 40)))
        goto exit;

    if (send)
    {
        magic = server ? Magic3 : Magic2;
    }
    else
    {
        magic = server ? Magic2 : Magic3;
    }

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) p_shaContext, magic, 84)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) p_shaContext, SHAPAD2, 40)))
        goto exit;

    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) p_shaContext, pShaOutput)))
        goto exit;

    if (SHA_HASH_RESULT_SIZE > sessionKeyLen)
        sessionKeyLen =   SHA_HASH_RESULT_SIZE;

    DIGI_MEMCPY(sessionKey,pShaOutput,sessionKeyLen);
#if defined(__ENABLE_ALL_DEBUGGING__)
#ifndef __ENABLE_KEYVPN_LOG_SUPPRESSION__
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"  ");
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"MSCHAPv2 Session Key ");
    EAP_PrintBytes( sessionKey, sessionKeyLen);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"  ");
#endif
#endif

exit:
    if (NULL != pShaOutput)
        FREE(pShaOutput);

    SHA1_freeDigest(MOC_HASH(hwAccelCtx) (BulkCtx*) &p_shaContext);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;
}

#endif /*defined(__ENABLE_DIGICERT_EAP_MSCHAPv2__)*/
#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */
