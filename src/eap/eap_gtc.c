/**
 * @file  eap_gtc.c
 * @brief EAP-GTC method implementation
 *
 * @details    EAP Generic Token Card
 * @since      1.41
 * @version    1.41 and later
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_GTC__
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
#if defined(__ENABLE_DIGICERT_EAP_GTC__)

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/vlong.h"
#include "../common/debug_console.h"

#include "../eap/eap.h"
#include "../eap/eap_proto.h"


/*------------------------------------------------------------------*/

/*! Generate a token response.
This function generates a token response and returns the resultant EAP payload.
Your application should use this function for GTC peer packet processing.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_GTC__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_gtc.h

\param appSessionHdl    Cookie given by the application to identify the session.
\param passwordString   Session password for the response.
\param passLen          Number of bytes in $passwordString$.
\param eapRespData      On return, pointer to EAP response payload.
\param eapRespLen       On return, pointer to number of bytes in $eapRespData$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_GTCstartRequest
\sa EAP_GTCProcessAuth

*/
extern  MSTATUS
EAP_GTCProcessPeer (ubyte *appSessionHdl,
                    ubyte *passwordString,ubyte4 passLen,
                    ubyte **eapRespData, ubyte4 *eapRespLen)
{
    MSTATUS status = OK;
    ubyte *eapResponse = NULL;
    MOC_UNUSED(appSessionHdl);

    *eapRespLen = passLen;
    eapResponse = (ubyte *) MALLOC(*eapRespLen);

    if (NULL == eapResponse)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(eapResponse, passwordString, *eapRespLen);
    *eapRespData = eapResponse;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Builds an EAP request.
This builds an EAP request based on the specified data.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_GTC__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_gtc.h

\param appSessionHdl    Cookie given by the application to identify the session.
\param msgString        Pointer to message data.
\param msgLen           Number of bytes in $msgString$.
\param eapReqData       On return, pointer to EAP request payload.
\param eapReqLen        On return, pointer to number of bytes in $eapReqData$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_GTCProcessAuth
\sa EAP_GTCProcessPeer

*/
extern  MSTATUS
EAP_GTCstartRequest (ubyte *appSessionHdl,
                    ubyte *msgString,ubyte4 msgLen,
                    ubyte **eapReqData, ubyte4 *eapReqLen)
{
    MSTATUS status = OK;
    ubyte *eapRequest = NULL;
    MOC_UNUSED(appSessionHdl);

    *eapReqLen = msgLen;
    eapRequest = (ubyte *) MALLOC(*eapReqLen);

    if (NULL == eapRequest)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(eapRequest, msgString, *eapReqLen);
    *eapReqData = eapRequest;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Validate a token response.
This function validates a token response, indicating the result by its
function return: $OK$, $ERR_EAP_GTC_INVALID_TOKEN_LENGTH$, or
$ERR_EAP_GTC_AUTH_FAILURE$. Your application should use this function to process
responses received from peers.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_GTC__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_gtc.h

\param appSessionHdl    Cookie given by the application to identify the session.
\param data             EAP request payload, in the following format: $<Type,&nbsp;Chlg&nbsp;Len, Challenge>$.
\param len              Number of bytes in EAP request payload.
\param passwordString   Session password for the response.
\param passLen          Number of bytes in $passwordString$.
\param cmp              On return, pointer to challenge comparison result (0 indicates a match).

\return One of the following:\n
\n
&bull; $OK$ (0) if successful.\n
&bull; $ERR_EAP_GTC_INVALID_TOKEN_LENGTH$ if the EAP request's $Chlg&nbsp;Len$ doesn't match the length of the previously sent challenge (as specified by the $passLen$ parameter value.\n
&bull; $ERR_EAP_GTC_AUTH_FAILURE$ if the token is invalid.

\sa EAP_GTCstartRequest
\sa EAP_GTCProcessAuth

*/
extern MSTATUS
EAP_GTCProcessAuth (ubyte *appSessionHdl,
                    ubyte *data, ubyte4 len,ubyte *passwordString,
                    ubyte4 passLen,
                    sbyte4 *cmp)
{

    MSTATUS status = OK;
    ubyte4 respLen = len -1;
    MOC_UNUSED(appSessionHdl);

    if (2  > len)
    {
        status = ERR_EAP_GTC_INVALID_TOKEN_LENGTH;
        goto exit;
    }

    if (respLen != passLen)
    {
        status = ERR_EAP_GTC_AUTH_FAILURE;
        *cmp = status;
        goto exit;
    }

    if (OK > (status = DIGI_MEMCMP(passwordString,(ubyte *)(data + 1), passLen,cmp)) || (0 != *cmp))
    {
        status = ERR_EAP_GTC_AUTH_FAILURE;
        goto exit;
    }

exit:
    return status;
}

#endif /*defined(__ENABLE_DIGICERT_EAP_GTC__) */
#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */
