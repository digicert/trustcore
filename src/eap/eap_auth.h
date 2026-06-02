/**
 * @file  eap_auth.h
 * @brief EAP authenticator API
 *
 * @details    EAP authenticator interface definitions
 *
 * @flags      Compilation flags required:
 *     *     + \c \__ENABLE_DIGICERT_EAP_AUTH__

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

#ifndef __EAP_AUTH_HEADER__
#define __EAP_AUTH_HEADER__

#ifdef __cplusplus
extern "C" {
#endif
#if defined(__ENABLE_DIGICERT_EAP_AUTH__)

typedef enum eapAuthState_e
{
    EAP_AUTH_STATE_NONE,
    EAP_AUTH_STATE_DISABLED,
    EAP_AUTH_STATE_INIT,
    EAP_AUTH_STATE_IDLE,
    EAP_AUTH_STATE_RECEIVED,
    EAP_AUTH_STATE_DISCARD,
    EAP_AUTH_STATE_SEND_REQUEST,
    EAP_AUTH_STATE_SUCCESS,
    EAP_AUTH_STATE_FAILURE,
    EAP_AUTH_STATE_RETRANSMIT,
    EAP_AUTH_STATE_VERIFY_MIC,
    EAP_AUTH_STATE_NAK,
    EAP_AUTH_STATE_METHOD,
} eapAuthState_t;

typedef struct eapAuthStateBits_s
{
     eapAuthState_t eapState;
     const ubyte * stateDescription;
     MSTATUS  (*stateFn) (void *,void *);

} eapAuthStateBits_t;

MSTATUS EAP_authRetransmitTimeout (void *session);

#endif /* defined(__ENABLE_DIGICERT_EAP_AUTH__)  */
#ifdef __cplusplus
}
#endif
#endif
