/**
 * @file  eap1x_pvt.h
 * @brief 802.1X private definitions
 *
 * @details    Internal 802.1X definitions
 *
 * @flags      Compilation flags required:
 *     To use this header file, the following flag must be defined in moptions.h:
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

/*------------------------------------------------------------------*/

#ifndef __EAP1X_PVT_HEADER__
#define __EAP1X_PVT_HEADER__

#ifdef __cplusplus
extern "C" {
#endif
#if defined(__ENABLE_DIGICERT_EAP_AUTH__)

typedef enum eap1XAuthState_e
{
    EAP1X_AUTH_STATE_NONE,
    EAP1X_AUTH_STATE_INIT,
    EAP1X_AUTH_STATE_DISCONNECTED,
    EAP1X_AUTH_STATE_RESTART,
    EAP1X_AUTH_STATE_CONNECTING,
    EAP1X_AUTH_STATE_AUTHENTICATING,
    EAP1X_AUTH_STATE_AUTHENTICATED,
    EAP1X_AUTH_STATE_ABORTING,
    EAP1X_AUTH_STATE_HELD,
    EAP1X_AUTH_STATE_FORCE_AUTH,
    EAP1X_AUTH_STATE_FORCE_UNAUTH,
} eap1XAuthState_t;

typedef struct eap1XAuthStateBits_s
{
     eap1XAuthState_t eapState;
     const ubyte * stateDescription;
     MSTATUS  (*stateFn) (void *,void *);

} eap1XAuthStateBits_t;

typedef struct eap1xAuthGlobal_s
{
   ubyte*                   portTimer;
   ubyte*                   reAuthTimer;
   ubyte*                   heldTimer;

} eap1xAuthGlobal_t;

typedef struct eap1xSessionCB_s
{

    eap1xPortMode    portMode;
    eap1xPortMode    portControl;
    intBoolean       initialize;
    intBoolean       eapolStart;
    intBoolean       eapolLogoff;
    intBoolean       eapRestart;
    intBoolean       eapReq;
    eap1xPortStatus  authPortStatus;
    ubyte4           reAuthCount;
    intBoolean       reAuthenticate;
    intBoolean       authSuccess;
    intBoolean       authFail;
    intBoolean       authTimeout;
    intBoolean       eapFail;
    intBoolean       eapSuccess;
    intBoolean       authStart;
    intBoolean       keyRun;
    intBoolean       keyDone;
    intBoolean       authAbort;
    eap1XAuthState_t eapAuthCurrentState;
    eap1XAuthState_t eapAuthPrevState;
    intBoolean       portValid;
    intBoolean       portEnabled;
    eap1xAuthSessionCfg cfg;
    ubyte*           appHdl;
    eap1xSessionStats stats;

}eap1xSessionCb_t;

#endif /* defined(__ENABLE_DIGICERT_EAP_AUTH__)  */
#ifdef __cplusplus
}
#endif
#endif /* __EAP1X_PVT_HEADER__*/
