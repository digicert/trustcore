/**
 * @file  eap1x_peer_pvt.h
 * @brief 802.1X peer private definitions
 *
 * @details    Internal 802.1X structures
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
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



/*------------------------------------------------------------------*/

#ifndef __EAP1X_PEER_PVT_HEADER__
#define __EAP1X_PEER_PVT_HEADER__

#ifdef __cplusplus
extern "C" {
#endif
#if defined(__ENABLE_DIGICERT_EAP_PEER__)


typedef struct eap1XPeerStateBits_s
{
     eap1XPeerState_t eapState;
     const ubyte * stateDescription;
     MSTATUS  (*stateFn) (void *,void *);

} eap1XPeerStateBits_t;

typedef struct eap1xPeerGlobal_s
{
   ubyte*                   startTimer;
   ubyte*                   heldTimer;

} eap1xPeerGlobal_t;

typedef struct eap1xPeerCB_s
{

    eap1xPortMode    sPortMode;
    eap1xPortMode    portControl;
    intBoolean       initialize;
    intBoolean       logoffSent;
    intBoolean       userLogoff;
    intBoolean       eapolEap;
    intBoolean       eapRestart;
    eap1xPortStatus  suppPortStatus;
    ubyte4           startCount;
    intBoolean       eapSuccess;
    intBoolean       eapFail;
    intBoolean       suppTimeout;
    intBoolean       suppFail;
    intBoolean       suppSuccess;
    intBoolean       keyRun;
    intBoolean       keyDone;
    eap1XPeerState_t eapPeerCurrentState;
    eap1XPeerState_t eapPeerPrevState;
    intBoolean       portValid;
    intBoolean       portEnabled;
    intBoolean       suppAbort;
    eap1xPeerSessionCfg cfg;
    ubyte*           appHdl;
    eap1xPeerStats stats;

}eap1xPeerCb_t;

#endif /* defined(__ENABLE_DIGICERT_EAP_PEER__)  */
#ifdef __cplusplus
}
#endif
#endif /* __EAP1X_PEER_PVT_HEADER__*/
