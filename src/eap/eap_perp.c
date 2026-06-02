/**
 * @file  eap_perp.c
 * @brief EAP-PERP method implementation
 *
 * @details    Protected EAP Roaming Protocol
 * @since      1.41
 * @version    1.41 and later
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_PERP__
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
#if defined(__ENABLE_DIGICERT_EAP_PERP__)

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/vlong.h"
#include "../common/debug_console.h"
#include "../crypto/crypto.h"
#include "../crypto/md5.h"
#include "../crypto/harness.h"
#include "../common/random.h"

#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../eap/eap_perp.h"

sbyte4 IKEv2_EapperpCallback(ubyte *appSessionHdl, const sbyte* perp);
sbyte4 IKEv2_Eapperp_auth_Callback(ubyte *appSessionHdl,
                                   const sbyte* perp, ubyte cfgType,
                                   ubyte2 Status);


/*------------------------------------------------------------------*/

/*! Fetch initial PERP request message from AAA.
This function fetches the initial perp request message that need to be requested
to user during PERP exchanges.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PERP__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_perp.h

\param appSessionHdl    Cookie given by the application to identify the session.
\param reqData          On return, pointer to PERP response payload.
\param reqLen           On return, pointer to number of bytes in $reqData$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/

#ifdef __ENABLE_DIGICERT_EAP_AUTH__
extern  MSTATUS
EAP_Perp_request_auth (ubyte *appSessionHdl,ubyte **reqData, ubyte4 *reqLen )
{
    MSTATUS status;
    int len=0;
    ikeSettings *is=NULL;
    sbyte *perp=NULL;
    ubyte *eapRequest=NULL;

    is = IKE_ikeSettings();

    if( !is || !(is->funcPtrInteractWithAAAEAP))
    {
        status = ERR_NULL_POINTER;
        DEBUG_ERROR(DEBUG_EAP_MESSAGE," Null pointer status = ",status);
        return status;
    }

    /* Call to AAA to fetch initial perp request */
    status = (MSTATUS) is->funcPtrInteractWithAAAEAP(appSessionHdl,&perp,NULL);

    if( NULL == perp )
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE,"PERP request from AAA is NUll staus = ",status);
        return status;
    }

    len = DIGI_STRLEN(perp);
    eapRequest = (ubyte *) MALLOC(len);
    if(NULL == eapRequest)
    {
        status = ERR_MEM_ALLOC_FAIL;
        return status;
    }
    DIGI_MEMCPY(eapRequest, perp,len);
    *reqData = eapRequest;
    *reqLen = len;

    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_EAP_PEER__
extern  MSTATUS
EAP_Perp_process_peer (ubyte *appSessionHdl, ubyte *reqData, ubyte **resp, ubyte4 *resplen )
{
    MSTATUS status;
    ubyte4 len=0;
    ikeSettings *is = NULL;
    sbyte *perp = NULL;
    sbyte *eapRequest = NULL;

    is = IKE_ikeSettings();

    if( !is || !(is->funcPtrInteractWithUsereap))
    {
        status = ERR_NULL_POINTER;
        DEBUG_ERROR(DEBUG_EAP_MESSAGE," Null pointer status = ",status);
        return status;
    }

    status = (MSTATUS) is->funcPtrInteractWithUsereap((void *)appSessionHdl,
                                                      (sbyte *)reqData,
                                                      &perp,
                                                      &len,
                                                      IKEv2_EapperpCallback);
    if( status == OK && len !=0 )
    {
        eapRequest = (ubyte *) MALLOC(len);
        if(NULL == eapRequest)
        {
            status = ERR_MEM_ALLOC_FAIL;
            return status;
        }
        DIGI_MEMCPY(eapRequest, perp,len);
        *resp = eapRequest;
        *resplen = len;
    }
    return status;
}
#endif


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/

/*! Process PERP response message from peer.
This function requestes AAA to process the perp response message from peer .

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PERP__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_perp.h

\param appSessionHdl    Cookie given by the application to identify the session.
\param perp             pointer to PERP response from peer.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/

#ifdef __ENABLE_DIGICERT_EAP_AUTH__
extern  MSTATUS
EAP_Perp_process_auth(ubyte *appSessionHdl,ubyte *perp)
{
    MSTATUS status = OK;
    ikeSettings *is=NULL;

    is = IKE_ikeSettings();

    if( !is || !(is->funcPtrInteractWithAAAEAP))
    {
        status = ERR_NULL_POINTER;
        DEBUG_ERROR(DEBUG_EAP_MESSAGE," Null pointer status = ",status);
        return status;
    }

    status = (MSTATUS) is->funcPtrInteractWithAAAEAP(appSessionHdl,
                                                     (sbyte **)&perp,
                                                     (EAPPERP_aaaCallbackFun)
                                                     &IKEv2_Eapperp_auth_Callback);
    return status;
}
#endif

#endif /*defined(__ENABLE_DIGICERT_EAP_PERP__) */
#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */
