/**
 * @file  eap_md5.c
 * @brief EAP-MD5 method implementation
 *
 * @details    EAP MD5 Challenge
 * @since      1.41
 * @version    1.41 and later
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_MD5__
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


/* Add to your makefile */
#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))
#if defined(__ENABLE_DIGICERT_EAP_MD5__)

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/vlong.h"
#include "../common/debug_console.h"
#include "../crypto/crypto.h"
#include "../crypto/md5.h"
#include "../harness/harness.h"
#include "../common/random.h"

#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_md5.h"


/*------------------------------------------------------------------*/

/*! Generate an MD5 challenge response.
This function calculates an MD5 hash (the challenge response) and returns the
resultant EAP payload. Your application should use this function for MD5 peer
packet processing.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_MD5__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_md5.h

\param appSessionHdl    Cookie given by the application to identify the session.
\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID returned from EAP_initInstance.
\param code             Any of the $eapCode$ enumerated values (see eap_proto.h).
\param id               EAP packet ID
\param data             EAP request payload, in the following format: $<Type,&nbsp;Chlg&nbsp;Len, Challenge>$.
\param len              Number of bytes in EAP request payload.
\param passwordString   Session password for the response.
\param passLen          Number of bytes in $passwordString$.
\param eapRespData      On return, pointer to EAP response payload.
\param eapRespLen       On return, pointer to number of bytes in $eapRespData$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_MD5_getChallenge
\sa EAP_MD5ProcessAuth

*/
extern  MSTATUS
EAP_MD5ProcessPeer (ubyte *appSessionHdl, ubyte *eapSessionHdl,
                    ubyte4 instanceId, ubyte id,
                    ubyte *data, ubyte4 len,
                    ubyte *passwordString,ubyte4 passLen,
                    ubyte **eapRespData, ubyte4 *eapRespLen)
{
    hwAccelDescr    hwAccelCtx;
    ubyte           result[MD5_DIGESTSIZE];
    MD5_CTX         *pCtx = NULL;
    ubyte*          eapResponse = NULL;
    ubyte4          challengeLen = 0;
    MSTATUS         status = OK;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    MOC_UNUSED(instanceId);
    MOC_UNUSED(eapSessionHdl);
    MOC_UNUSED(appSessionHdl);

    challengeLen = data[1];

    if (challengeLen > len -1)
    {
        status = ERR_EAP_MD5_INVALID_CHALLENGE_LENGTH;
        goto exit;
    }

    status = MD5Alloc_m(MOC_HASH(hwAccelCtx) (BulkCtx*) &pCtx);
    if (OK != status)
        goto exit;

    status = MD5Init_m(MOC_HASH(hwAccelCtx) pCtx);
    if (OK != status)
        goto exit;

    status = MD5Update_m(MOC_HASH(hwAccelCtx) pCtx, &id, 1);
    if (OK != status)
        goto exit;

    status = MD5Update_m(MOC_HASH(hwAccelCtx) pCtx, passwordString, passLen);
    if (OK != status)
        goto exit;

    status = MD5Update_m(MOC_HASH(hwAccelCtx) pCtx, &data[2], challengeLen);
    if (OK != status)
        goto exit;

    status = MD5Final_m(MOC_HASH(hwAccelCtx) pCtx, result);

    *eapRespLen = MD5_DIGESTSIZE + 1;
    eapResponse = (ubyte *) MALLOC(*eapRespLen);

    if (NULL == eapResponse)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    eapResponse[0] = MD5_DIGESTSIZE;
    DIGI_MEMCPY(eapResponse+1, result, *eapRespLen-1);
    *eapRespData = eapResponse;

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_MD5ProcessPeer: Error Processing Auth Challenge, status = ", (sbyte4)status);
    MD5Free_m(MOC_HASH(hwAccelCtx) (BulkCtx*) &pCtx);
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;
}


/*------------------------------------------------------------------*/


/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern  MSTATUS
EAP_MD5ChallengeResponse (ubyte id,
                           ubyte *challenge, ubyte4 challengeLen,
                           ubyte *passwordString,ubyte4 passLen,
                           ubyte *eapRespData, ubyte4 *eapRespLen)
{
    hwAccelDescr    hwAccelCtx;
    ubyte           result[MD5_DIGESTSIZE];
    MD5_CTX         *pCtx = NULL;
    MSTATUS         status = OK;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    status = MD5Alloc_m(MOC_HASH(hwAccelCtx) (BulkCtx*) &pCtx);
    if (OK != status)
        goto exit;

    status = MD5Init_m(MOC_HASH(hwAccelCtx) pCtx);
    if (OK != status)
        goto exit;

    status = MD5Update_m(MOC_HASH(hwAccelCtx) pCtx, &id, 1);
    if (OK != status)
        goto exit;

    status = MD5Update_m(MOC_HASH(hwAccelCtx) pCtx, passwordString, passLen);
    if (OK != status)
        goto exit;

    status = MD5Update_m(MOC_HASH(hwAccelCtx) pCtx, challenge, challengeLen);
    if (OK != status)
        goto exit;

    status = MD5Final_m(MOC_HASH(hwAccelCtx) pCtx, result);
    if (OK != status)
        goto exit;


    *eapRespLen = MD5_DIGESTSIZE;
    DIGI_MEMCPY(eapRespData, result, *eapRespLen);


    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_MD5ChallengeResponse: Error in Challenge Response , status = ", (sbyte4)status);

    MD5Free_m(MOC_HASH(hwAccelCtx) (BulkCtx*) &pCtx);
nocleanup:
    return status;
}


/*------------------------------------------------------------------*/

/*! Generate a challenge for an MD5 request.
This function generates a challenge for an MD5 request. The challenge is in the
form of random data that's used as a nonce&mdash;a unique, random value inserted
into a message to protect against replays&mdash;to hash a user's password using
the MD5 algorithm. The challenge sequence is as follows:

-# The server (authenticator) sends the nonce.
-# The client (peer) hashes a clear text password using the nonce with MD5, and
then sends the reply to the server.
-# The server hashes the same clear text password using the same nonce and MD5
algorithm, and then compares the result with the result sent by the peer.
Matching client and server results indicate a successful challenge.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_MD5__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_md5.h

\param buf  On return, pointer to buffer containing the challenge.
\param len  Length of challenge to generate.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_MD5ProcessAuth
\sa EAP_MD5ProcessPeer

*/
extern  MSTATUS
EAP_MD5_getChallenge(ubyte *buf, ubyte4 len)
{
    return RANDOM_numberGenerator(g_pRandomContext, buf, len);
}


/*------------------------------------------------------------------*/

/*! Validate an MD5 challenge response.
This function validates an MD5 challenge response, indicating the result by its
function return: $OK$, $ERR_EAP_MD5_INVALID_CHALLENGE_LENGTH$, or
$ERR_EAP_MD5_AUTH_FAILURE$. Your application should use this function to process
responses received from peers.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_MD5__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_md5.h

\param appSessionHdl    Cookie given by the application to identify the session.
\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID returned from EAP_initInstance.
\param code             Any of the $eapCode$ enumerated values (see eap_proto.h).
\param id               EAP packet ID
\param data             EAP request payload, in the following format: $<Type,&nbsp;Chlg&nbsp;Len, Challenge>$.
\param len              Number of bytes in EAP request payload.
\param passwordString   Session password for the response.
\param passLen          Number of bytes in $passwordString$.
\param challenge        Pointer to previously sent challenge.
\param challengeLen     Number of bytes in $challenge$.
\param cmp              On return, pointer to challenge comparison result (0 indicates a match).

\return One of the following:\n
\n
- $OK$ (0) if successful.\n
$ERR_EAP_MD5_INVALID_CHALLENGE_LENGTH$ if the EAP request's $Chlg&nbsp;Len$ doesn't match the length of the previously sent challenge (as specified by teh $challengeLen$ parameter value.\n
$ERR_EAP_MD5_AUTH_FAILURE$ if the challenge is invalid.

\sa EAP_MD5_getChallenge
\sa EAP_MD5ProcessPeer

*/
extern MSTATUS
EAP_MD5ProcessAuth (ubyte *appSessionHdl, ubyte *eapSessionHdl,
                    ubyte4 instanceId, eapCode code, ubyte id,
                    ubyte *data, ubyte4 len,ubyte *passwordString,
                    ubyte4 passLen, ubyte *challenge, ubyte4 challengeLen,
                    sbyte4 *cmp)
{
    ubyte           result[MD5_DIGESTSIZE];
    hwAccelDescr    hwAccelCtx;
    MD5_CTX         *pCtx = NULL;
    MSTATUS         status = OK;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    MOC_UNUSED(code);
    MOC_UNUSED(instanceId);
    MOC_UNUSED(eapSessionHdl);
    MOC_UNUSED(appSessionHdl);

    challengeLen = data[1];
    if (challengeLen > len -1)
    {
        status = ERR_EAP_MD5_INVALID_CHALLENGE_LENGTH;
        goto exit;
    }

    status = MD5Alloc_m(MOC_HASH(hwAccelCtx) (BulkCtx*) &pCtx);
    if (OK != status)
        goto exit;

    status = MD5Init_m(MOC_HASH(hwAccelCtx) pCtx);
    if (OK != status)
        goto exit;

    status = MD5Update_m(MOC_HASH(hwAccelCtx) pCtx, &id, 1);
    if (OK != status)
        goto exit;

    status = MD5Update_m(MOC_HASH(hwAccelCtx) pCtx, passwordString, passLen);
    if (OK != status)
        goto exit;

    status = MD5Update_m(MOC_HASH(hwAccelCtx) pCtx, challenge, challengeLen);
    if (OK != status)
        goto exit;

    status = MD5Final_m(MOC_HASH(hwAccelCtx) pCtx, result);
    if (OK != status)
        goto exit;


    if (OK > (status = DIGI_MEMCMP(result,(ubyte *)(data + 2), MD5_DIGESTSIZE,cmp)) || (0 != *cmp))
    {
        status = ERR_EAP_MD5_AUTH_FAILURE;
        goto exit;
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_MD5ProcessAuth: Error in Processing , status = ", (sbyte4)status);

    MD5Free_m(MOC_HASH(hwAccelCtx) (BulkCtx*) &pCtx);
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;
}

#endif /*defined(__ENABLE_DIGICERT_EAP_MD5__) */
#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */
