/**
 * @file  eap_leap.c
 * @brief EAP-LEAP method implementation
 *
 * @details    Lightweight EAP
 * @since      1.41
 * @version    1.41 and later
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_LEAP__
 *     Additionally, at least one of the following flags must be defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__
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

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))
#if defined(__ENABLE_DIGICERT_EAP_LEAP__)

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/vlong.h"
#include "../common/debug_console.h"
#include "../crypto/crypto.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../harness/harness.h"
#include "../common/random.h"
#include "../common/redblack.h"
#include "../common/timer.h"
#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_auth.h"
#include "../eap/eap_leap.h"
#include "../eap/eap_mschapv2.h"
#include "../eap/eap_session.h"


/*------------------------------------------------------------------*/

/*! Create and initialize an EAP-LEAP session.
This function creates and initializes an EAP-LEAP session using the specified
parameters. The session handle is returned through the $p_eapLeapCb$ parameter,
and should be passed in all subsequent function calls for the EAP-LEAP session.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_LEAP__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_leap.h

\param appCb        Application session handle (cookie given by the application to identify the session).
\param p_eapLeapCb  On return, pointer to EAP-LEAP session handle.
\param sessionType  Either of the following $eapSessionType$ enumerated values (defined in eap_proto.h):\n
\n
&bull; $EAP_SESSION_TYPE_PEER$\n
&bull; $EAP_SESSION_TYPE_AUTHENTICATOR$

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_LEAPinitSession(void *appCb, void **p_eapLeapCb, ubyte sessionType)
{
    eapLeapCb_t* eapLeap;
    MSTATUS      status = OK;

    eapLeap = MALLOC(sizeof(eapLeapCb_t));
    if (NULL == eapLeap)
    {
        status = ERR_EAP_LEAP_INVALID_SESSION;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)eapLeap,0,sizeof(eapLeapCb_t));

    if (EAP_SESSION_TYPE_AUTHENTICATOR == sessionType)
        eapLeap->state = LEAP_AUTH_INIT;
    else if (EAP_SESSION_TYPE_PEER == sessionType)
        eapLeap->state = LEAP_PEER_INIT;
    else
    {
        FREE(eapLeap);
        status = ERR_EAP_LEAP_INVALID_SESSION_TYPE;
        goto exit;
    }

    *p_eapLeapCb = eapLeap;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Delete an EAP-LEAP session.
This function frees (releases) EAP LEAP resources and deletes an EAP-LEAP session.

\since 2.45
\version 2.45 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_LEAP__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_leap.h

\param p_eapLeapCb  EAP-LEAP session handle returned from EAP_LEAPinitSession.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_LEAPdeleteSession(void *p_eapLeapCb)
{
    MSTATUS      status = OK;

    if ( p_eapLeapCb)
        FREE(p_eapLeapCb);

    return status;
}

/*------------------------------------------------------------------*/

/*! Generate a LEAP challenge packet.
This function (which can be called by the authenticator or peer) builds the
initial LEAP challenge, returning it through the $eapRespData$ parameter.
Additionally, this function updates the session handle's state (to
$LEAP_AUTH_CHALLENGE_SENT$ or $LEAP_PEER_CHALLENGE_SENT$), eliminating the need to
call an additional function to manage the state flag.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_LEAP__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_leap.h

\param leapCb       EAP-LEAP session handle returned from EAP_LEAPinitSession.
\param sessionType  One of the following $eapSessionType$ enumerated values:
$EAP_SESSION_TYPE_PEER$ or $EAP_SESSION_TYPE_AUTHENTICATOR$ (see eap_proto.h).
\param eapRespData  On return, pointer to response packet.
\param eapRespLen   On return, pointer to number of bytes in response packet ($eapRespData$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_LEAP_buildChallenge(eapLeapCb_t *leapCb, ubyte sessionType,
                        ubyte *identity, ubyte2 identityLen,
                        ubyte **eapRespData, ubyte4 *eapRespLen)
{
    ubyte*  pos;
    ubyte*  eapResponse;
    ubyte*  challengeBuf = NULL;
    MSTATUS status;

    if (NULL == leapCb)
    {
        status = ERR_EAP_LEAP_INVALID_SESSION;
        goto exit;
    }

    if (EAP_SESSION_TYPE_AUTHENTICATOR == sessionType)
        challengeBuf = leapCb->authChallenge;
    else if (EAP_SESSION_TYPE_PEER == sessionType)
        challengeBuf = leapCb->peerChallenge;

    if (NULL == challengeBuf)
    {
        status = ERR_EAP_LEAP_INVALID_CHALLENGE;
        goto exit;
    }

    status = RANDOM_numberGenerator(g_pRandomContext, challengeBuf,
                                    LEAP_CHALLENGE_LEN);
    if (OK > status)
        goto exit;

    //Comment Original: Add identity Leangth
    //*eapRespLen = LEAP_HDR_LEN + LEAP_CHALLENGE_LEN;
    *eapRespLen = LEAP_HDR_LEN + LEAP_CHALLENGE_LEN + identityLen;
    eapResponse = (ubyte *) MALLOC(*eapRespLen);

    if (NULL == eapResponse)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    pos = eapResponse;
    *pos++ = LEAP_VERSION;
    *pos++ = 0;
    *pos++ = LEAP_CHALLENGE_LEN;
    DIGI_MEMCPY(pos, challengeBuf, LEAP_CHALLENGE_LEN);

    //Add identity
    pos += LEAP_CHALLENGE_LEN;
    DIGI_MEMCPY(pos, identity, (sbyte4)identityLen);
    *eapRespData = eapResponse;

    if (EAP_SESSION_TYPE_AUTHENTICATOR == sessionType)
        leapCb->state = LEAP_AUTH_CHALLENGE_SENT;
    else if (EAP_SESSION_TYPE_PEER == sessionType)
        leapCb->state = LEAP_PEER_CHALLENGE_SENT;

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_leapPeerBuildChallengeResponse(eapLeapCb_t *leapCb, ubyte *challenge,
                               ubyte *passwd, ubyte2 passwdLen,
                               ubyte *identity, ubyte2 identityLen,
                               ubyte **eapRespData, ubyte4 *eapRespLen)
{
    ubyte*  pos;
    ubyte*  eapResponse;
    ubyte   respBuf[LEAP_CHALLENGE_RESPONSE_LEN];
    MSTATUS status = OK;

    if (LEAP_PEER_INIT != leapCb->state)
    {
        status = ERR_EAP_LEAP_INVALID_STATE;
        goto exit;
    }

    if (OK > (status = EAP_MSCHAPv0generateNTResponse(challenge,
                                            passwd, passwdLen, respBuf)))
    {
        goto exit;
    }

    *eapRespLen = LEAP_HDR_LEN + LEAP_CHALLENGE_RESPONSE_LEN + identityLen;
    eapResponse = MALLOC(*eapRespLen);

    if (NULL == eapResponse)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    pos = eapResponse;
    *pos++ = LEAP_VERSION;
    *pos++ = 0;
    *pos++ = LEAP_CHALLENGE_RESPONSE_LEN;

    DIGI_MEMCPY(pos, respBuf, LEAP_CHALLENGE_RESPONSE_LEN);
    pos += LEAP_CHALLENGE_RESPONSE_LEN;

    DIGI_MEMCPY(leapCb->authChallenge,challenge,LEAP_CHALLENGE_LEN);
    DIGI_MEMCPY(leapCb->authResponse,respBuf,LEAP_CHALLENGE_RESPONSE_LEN);

    DIGI_MEMCPY(pos, identity, identityLen);

    *eapRespData = eapResponse;
    leapCb->state = LEAP_PEER_WAIT_SUCCESS;

exit:
    return status;

}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_LEAPauthVerifyChallengeResponse(eapLeapCb_t *leapCb, ubyte *peerResponse,
                               ubyte *passwd, ubyte2 passwdLen)
{
    ubyte*  pos;
    ubyte*  eapResponse;
    ubyte   authResp[LEAP_CHALLENGE_RESPONSE_LEN];
    sbyte4  result;
    MSTATUS status = OK;

    if (NULL == leapCb)
    {
        status = ERR_EAP_LEAP_INVALID_SESSION;
        goto exit;
    }

    if (LEAP_AUTH_CHALLENGE_SENT != leapCb->state)
    {
        status = ERR_EAP_LEAP_INVALID_STATE;
        goto exit;
    }

    if (OK > (status = EAP_MSCHAPv0generateNTResponse(leapCb->authChallenge,
                                            passwd, passwdLen, authResp)))
    {
        goto exit;
    }

    if (OK > (status = DIGI_MEMCMP(authResp, peerResponse,
                                  LEAP_CHALLENGE_RESPONSE_LEN, &result)))
    {
        goto exit;
    }

    DIGI_MEMCPY(leapCb->authResponse,authResp,LEAP_CHALLENGE_RESPONSE_LEN);

    if (0 != result)
    {
        /* Auth failed, so clear leapCb and return FAILURE */
        DIGI_MEMSET(leapCb->authChallenge, 0, LEAP_CHALLENGE_LEN);
        leapCb->state = LEAP_AUTH_INIT;
        status = ERR_EAP_LEAP_AUTH_FAILED;
        goto exit;
    }

    leapCb->state = LEAP_AUTH_WAIT_CHALLENGE;

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_LEAPauthBuildChallengeResponse(eapLeapCb_t *leapCb, ubyte *challenge,
                               ubyte *passwd, ubyte2 passwdLen,
                               ubyte **eapRespData, ubyte4 *eapRespLen)
{
    ubyte*  pos;
    ubyte*  eapResponse;
    ubyte   respBuf[LEAP_CHALLENGE_RESPONSE_LEN];
    ubyte   passwordHash[16];
    ubyte   passwordHashHash[16];
    MSTATUS status = OK;

    if (NULL == leapCb)
    {
        status = ERR_EAP_LEAP_INVALID_SESSION;
        goto exit;
    }

    if (LEAP_AUTH_WAIT_CHALLENGE != leapCb->state)
    {
        status = ERR_EAP_LEAP_INVALID_STATE;
        goto exit;
    }

    if (OK > (status = EAP_MSCHAPNtPasswordHash(passwd, passwdLen,
                                                passwordHash)))
    {
        goto exit;
    }

    if (OK > (status = EAP_MSCHAPHashNtPasswordHash(passwordHash,
                                                    passwordHashHash)))
    {
        goto exit;
    }

    if (OK > (status = EAP_MSCHAPChallengeResponse(challenge,
                                                   passwordHashHash, respBuf)))
    {
        goto exit;
    }

    DIGI_MEMCPY(leapCb->pw_hash_hash,passwordHashHash,LEAP_PW_HASH_HASH_LEN);
    DIGI_MEMCPY(leapCb->peerChallenge,challenge,LEAP_CHALLENGE_LEN);
    DIGI_MEMCPY(leapCb->peerResponse,respBuf,LEAP_CHALLENGE_RESPONSE_LEN);

    *eapRespLen = LEAP_HDR_LEN + LEAP_CHALLENGE_RESPONSE_LEN;
    eapResponse = MALLOC(*eapRespLen);
    if (NULL == eapResponse)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    pos = eapResponse;
    *pos++ = LEAP_VERSION;
    *pos++ = 0;
    *pos++ = LEAP_CHALLENGE_RESPONSE_LEN;
    DIGI_MEMCPY(pos, respBuf, LEAP_CHALLENGE_RESPONSE_LEN);
    pos += LEAP_CHALLENGE_RESPONSE_LEN;

    *eapRespData = eapResponse;
    leapCb->state = LEAP_AUTH_DONE;

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_LEAPpeerVerifyChallengeResponse(eapLeapCb_t *leapCb, ubyte *authResponse,
                                    ubyte *passwd, ubyte2 passwdLen)
{
    ubyte*  pos;
    ubyte*  eapResponse;
    ubyte   peerResp[LEAP_CHALLENGE_RESPONSE_LEN];
    ubyte   passwordHash[16];
    ubyte   passwordHashHash[16];
    sbyte4  result;
    MSTATUS status = OK;

    if (NULL == leapCb)
    {
        status = ERR_EAP_LEAP_INVALID_SESSION;
        goto exit;
    }

    if (LEAP_PEER_CHALLENGE_SENT != leapCb->state)
    {
        status = ERR_EAP_LEAP_INVALID_STATE;
        goto exit;
    }

    if (OK > (status = EAP_MSCHAPNtPasswordHash(passwd, passwdLen,
                                                passwordHash)))
    {
        goto exit;
    }

    if (OK > (status = EAP_MSCHAPHashNtPasswordHash(passwordHash,
                                                    passwordHashHash)))
    {
        goto exit;
    }

    if (OK > (status = EAP_MSCHAPChallengeResponse(leapCb->peerChallenge,
                                                   passwordHashHash, peerResp)))
    {
        goto exit;
    }

    if (OK > (status = DIGI_MEMCMP(peerResp, authResponse,
                                  LEAP_CHALLENGE_RESPONSE_LEN, &result)))
    {
        goto exit;
    }

    DIGI_MEMCPY(leapCb->pw_hash_hash,passwordHashHash,LEAP_PW_HASH_HASH_LEN);
    DIGI_MEMCPY(leapCb->peerResponse,peerResp,LEAP_CHALLENGE_RESPONSE_LEN);

    if (0 != result)
    {
        /* Auth failed, so clear leapCb and return FAILURE */
        DIGI_MEMSET(leapCb->peerChallenge, 0, LEAP_CHALLENGE_LEN);
        leapCb->state = LEAP_PEER_INIT;
        status = ERR_EAP_LEAP_AUTH_FAILED;
        goto exit;
    }
    else
    {
        leapCb->state = LEAP_PEER_DONE;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Process a LEAP packet received by a peer.
This function processes a LEAP packet received by a peer, and returns the EAP
code to be sent in reply through the $p_sendCode$ parameter, the key (if any)
through the $pKey$ parameter, and the response packet through the $eapRespData$
parameter. (The response packet can subsequently be transmitted by calling
EAP_ulTransmit.)

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_LEAP__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_leap.h

\param eapLeapCb    EAP-LEAP session handle returned from EAP_LEAPinitSession.
\param code         Any of the $eapCode$ enumerated values (see eap_proto.h).
\param data         Pointer to payload to process, in the format <Type, LEAP packet>
\param len          Number of bytes in payload to process ($data$).
\param passwd       Pointer to password of the identity (EAP-LEAP session) being authenticated.
\param passwdLen    Number of bytes in password ($passwd$).
\param identity     Pointer to peer identity (sent during identity request/response).
\param identityLen  Number of bytes in peer identity string ($identity$).
\param p_sendCode   On return, pointer to EAP code to send in EAP response packet.
\param pKey         On return, pointer to generated session key (if any) based on MSCHAP encryption.
\param eapRespData  On return, pointer to LEAP response data packet.
\param eapRespLen   On return, pointer to number of bytes in LEAP response packet ($eapRespData$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_LEAP_processPeer(void *eapLeapCb, ubyte code,
                     ubyte *data, ubyte4 len,
                     ubyte *passwd, ubyte2 passwdLen,
                     ubyte *identity, ubyte2 identityLen,
                     eapCode *p_sendCode, ubyte **pKey,
                     ubyte **eapRespData, ubyte4 *eapRespLen)
{
    eapLeapCb_t* leapCb = (eapLeapCb_t *)eapLeapCb;
    MSTATUS      status = OK;

    if (NULL == leapCb)
    {
        status = ERR_EAP_LEAP_INVALID_SESSION;
        goto exit;
    }

    if (EAP_CODE_SUCCESS != code && LEAP_VERSION != *(data + 1))
    {
        status = ERR_EAP_LEAP_UNSUPPORTED_VERSION;
        goto exit;
    }

    switch(code)
    {
        case EAP_CODE_REQUEST:
        {
            status = EAP_leapPeerBuildChallengeResponse(leapCb, (data + 4),
                                                        passwd, passwdLen,
                                                        identity, identityLen,
                                                        eapRespData,
                                                        eapRespLen);

            if (OK == status)
                *p_sendCode = EAP_CODE_RESPONSE;

            break;
        }

        case EAP_CODE_SUCCESS:
        {
            status = EAP_LEAP_buildChallenge(leapCb, EAP_SESSION_TYPE_PEER,
                                             identity, identityLen,
                                             eapRespData, eapRespLen);

            if (OK == status)
                *p_sendCode = EAP_CODE_REQUEST;

            break;

        }
        case EAP_CODE_RESPONSE:
        {
            status = EAP_LEAPpeerVerifyChallengeResponse(leapCb, (data + 4),
                                                         passwd, passwdLen);
            if (OK == status)
            {
                *p_sendCode = 0;
                if (*(data + 3) > LEAP_CHALLENGE_RESPONSE_LEN)
                    *pKey = data + 4 + LEAP_CHALLENGE_RESPONSE_LEN;
            }

            break;
        }

        default:
        {
            status = ERR_EAP_INVALID_CODE;
            DEBUG_ERROR(DEBUG_EAP_MESSAGE,"Invalid EAP Code",status);
            break;
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/
/*! Process a LEAP packet received by an authenticator.
This function processes a LEAP packet received by an authenticator, and returns
the EAP code to be sent in reply through the $p_sendCode$ parameter, and the
response packet through the $eapRespData$ parameter. (The response packet can
subsequently be transmitted by calling EAP_ulTransmit.)

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_LEAP__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_leap.h

\param eapLeapCb    EAP-LEAP session handle returned from EAP_LEAPinitSession.
\param code         Any of the $eapCode$ enumerated values (see eap_proto.h).
\param data         Pointer to payload to process, in the format <Type, LEAP packet>
\param len          Number of bytes in payload to process ($data$).
\param passwd       Pointer to password of the identity (EAP-LEAP session) being authenticated.
\param passwdLen    Number of bytes in password ($passwd$).
\param p_sendCode   On return, pointer to EAP code to send in EAP response packet.
\param eapRespData  On return, pointer to LEAP response data packet.
\param eapRespLen   On return, pointer to number of bytes in LEAP response packet ($eapRespData$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_LEAP_processAuth(void *eapLeapCb, ubyte code,
                     ubyte *data, ubyte4 len,
                     ubyte *passwd, ubyte2 passwdLen,
                     eapCode *p_sendCode, ubyte **eapRespData, ubyte4 *eapRespLen)
{
    eapLeapCb_t* leapCb = (eapLeapCb_t *)eapLeapCb;
    MSTATUS      status = OK;

    if (NULL == leapCb)
    {
        status = ERR_EAP_LEAP_INVALID_SESSION;
        goto exit;
    }

    if (LEAP_VERSION != *(data + 1))
    {
        status = ERR_EAP_LEAP_UNSUPPORTED_VERSION;
        goto exit;
    }

    switch(code)
    {
        case EAP_CODE_REQUEST:
        {
            status = EAP_LEAPauthBuildChallengeResponse(leapCb, (data + 4),
                                                        passwd, passwdLen,
                                                        eapRespData,
                                                        eapRespLen);
            if (OK == status)
                *p_sendCode = EAP_CODE_RESPONSE;
            break;
        }

        case EAP_CODE_RESPONSE:
        {
            status = EAP_LEAPauthVerifyChallengeResponse(leapCb, (data + 4),
                                                         passwd, passwdLen);
            if (OK == status)
                *p_sendCode = EAP_CODE_SUCCESS;
            else
                *p_sendCode = EAP_CODE_FAILURE;
            break;

        }

        default:
        {
            status = ERR_EAP_INVALID_CODE;
            DEBUG_ERROR(DEBUG_EAP_MESSAGE,"Invalid EAP Code",status);
            break;
        }
    }

exit:
    return status;
}

/*------------------------------------------------------------------------*/
/*! Get EAP-LEAP session's shared key.
This function retrieves the EAP-LEAP session's shared key.


\warning Before calling this function, be sure that the buffer pointed to by the
$key$ parameter is at least $LEAP_KEY_LEN$ bytes (see eap_leap.h); otherwise
buffer overflow may occur.

\since 2.45
\version 2.45 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_LEAP__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_leap.h

\param eapLeapCb    EAP-LEAP session handle returned from EAP_LEAPinitSession.
\param key          Pointer to allocated buffer that on return contains the
shared key. (#The allocated buffer must contain at least $LEAP_KEY_LEN$ bytes;
otherwise buffer overflow may occur.#)
\param keyLen       (Reserved for future use.)

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern  MSTATUS
EAP_LEAP_getKey (void *eapLeapCb,
                ubyte *key, ubyte4 keyLen /* 16 Bytes */)
{
    MSTATUS status = OK;
    ubyte result[MD5_DIGESTSIZE];
    MD5_CTX *pCtx = NULL;
    eapLeapCb_t* leapCb = (eapLeapCb_t *)eapLeapCb;
    hwAccelDescr    hwAccelCtx;

    if (LEAP_KEY_LEN != keyLen)
    {
        status = ERR_EAP_INVALID_KEYLEN;
        goto nocleanup;
    }

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    if (OK > (status = MD5Alloc_m(MOC_HASH(hwAccelCtx)(BulkCtx*) &pCtx)))
        goto exit;
    if (OK > (status = MD5Init_m(MOC_HASH(hwAccelCtx) pCtx)))
        goto exit;
    if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) pCtx, leapCb->pw_hash_hash, LEAP_PW_HASH_HASH_LEN)))
        goto exit;
    if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) pCtx, leapCb->peerChallenge, LEAP_CHALLENGE_LEN)))
        goto exit;
    if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) pCtx, leapCb->peerResponse, LEAP_CHALLENGE_RESPONSE_LEN)))
        goto exit;
    if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) pCtx, leapCb->authChallenge, LEAP_CHALLENGE_LEN)))
        goto exit;
    if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) pCtx, leapCb->authResponse, LEAP_CHALLENGE_RESPONSE_LEN)))
        goto exit;
    if (OK > (status = MD5Final_m(MOC_HASH(hwAccelCtx) pCtx, result)))
        goto exit;

    DIGI_MEMCPY(key,result,LEAP_KEY_LEN);

#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "PW HASH HASH is ");
    EAP_PrintBytes( leapCb->pw_hash_hash ,LEAP_PW_HASH_HASH_LEN);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Peer Challenge is ");
    EAP_PrintBytes( leapCb->peerChallenge ,LEAP_CHALLENGE_LEN);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Peer  Response is ");
    EAP_PrintBytes( leapCb->peerResponse ,LEAP_CHALLENGE_RESPONSE_LEN);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Auth Challenge is ");
    EAP_PrintBytes( leapCb->authChallenge ,LEAP_CHALLENGE_LEN);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Auth  Response is ");
    EAP_PrintBytes( leapCb->authResponse ,LEAP_CHALLENGE_RESPONSE_LEN);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Master Key is ");
    EAP_PrintBytes( result ,LEAP_KEY_LEN);
#endif

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "EAP_LEAPgetKey: Error generating Key status = ", (sbyte4)status);

    MD5Free_m(MOC_HASH(hwAccelCtx) (BulkCtx*) &pCtx);
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;
}

/*------------------------------------------------------------------------*/

#endif /*defined(__ENABLE_DIGICERT_EAP_LEAP__)  */
#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */

