/**
 * @file  eap_session.h
 * @brief EAP session management API
 *
 * @details    EAP session interface definitions
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__ or \c \__ENABLE_DIGICERT_EAP_AUTH__
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

#ifndef __EAP_SESSION_H__
#define __EAP_SESSION_H__

#ifdef __cplusplus
extern "C" {
#endif
#if(defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))

#define EAP_SESSION_ID_START        1
#ifndef EAP_SESSION_ID_END
#define EAP_SESSION_ID_END          65535
#endif
#define EAP_INSTANCE_ID_START       1
#ifndef EAP_INSTANCE_ID_END
#define EAP_INSTANCE_ID_END         64
#endif


#if defined(__ENABLE_DIGICERT_EAP_PEER__)

typedef enum eapState_e
{
    EAP_PEER_STATE_NONE,
    EAP_PEER_STATE_DISABLED,
    EAP_PEER_STATE_INIT,
    EAP_PEER_STATE_IDLE,
    EAP_PEER_STATE_RECEIVED,
    EAP_PEER_STATE_DISCARD,
    EAP_PEER_STATE_SEND_RESPONSE,
    EAP_PEER_STATE_SUCCESS,
    EAP_PEER_STATE_FAILURE,
    EAP_PEER_STATE_RETRANSMIT,
    EAP_PEER_STATE_GET_METHOD,
    EAP_PEER_STATE_IDENTITY,
    EAP_PEER_STATE_NOTIFICATION,
    EAP_PEER_STATE_METHOD,
} eapState_t;

typedef struct eapStateBits_s
{
     eapState_t             eapState;
     const ubyte*           stateDescription;

     MSTATUS (*stateFn)(void *,void *);

} eapStateBits_t;

#endif /* defined(__ENABLE_DIGICERT_EAP_PEER__) */


/*------------------------------------------------------------------*/

struct redBlackTreeDescr;

typedef struct eapGlobal_s
{
   struct redBlackTreeDescr *instanceTree;
   ubyte*                   instanceIdbMap;
   ubyte4                   no_instance_create;
   ubyte4                   no_instance_delete;
   ubyte4                   no_instance_fail;
   RTOS_MUTEX               instanceMutex;

} eapGlobal_t;

MOC_EXTERN eapGlobal_t gEapGlobalState;

typedef struct eapInstanceCb_s
{
   struct redBlackTreeDescr *sessionTree;
   ubyte*                   sessionIdbMap;
   ubyte4                   instanceId;
   eapGlobalStats_t         gStats;
   RTOS_MUTEX               sessionMutex;
   ubyte*                   timerSession;
   ubyte*                   timerRetrans;

} eapInstanceCb_t;

typedef struct eapSessionCb_s
{
    ubyte4                  sessionId;
    ubyte4                  eapPeerTimeout;
    ubyte                   eapDecision;
    ubyte                   eapMethodState;
    ubyte                   eapSelectedMethod;
    byteBoolean             eapAllowNotification;
    ubyte                   eapCurrentId;
    ubyte                   eapLastId;
    ubyte                   eapSendCode;
    byteBoolean             eapSuccess;
    byteBoolean             eapFail;
    byteBoolean             eapPortEnabled;
    byteBoolean             eapRestart;
    byteBoolean             eapKeyAvailable;
    ubyte4                  eapKeyDataLen;
    ubyte*                  eapKeyData;
    ubyte*                  eapRespData;
    ubyte4                  eapRespDataLen;
    ubyte*                  eapReqData;
    ubyte4                  eapReqDataLen;
    ubyte*                  eapIdentity;
    ubyte4                  eapIdentityLen;
    eapSessionType          session_type;
    eapMethodDef_t          methodDef;
    ubyte4                  eapSessionHdl;
    ubyte*                  appSessionHandle;
    eapIndication           eap_ind;
#if defined(__ENABLE_DIGICERT_EAP_PEER__)
    eapState_t              eapCurrentState;
    eapState_t              eapPrevState;
#endif
#if defined(__ENABLE_DIGICERT_EAP_AUTH__)
    eapAuthState_t          eapAuthCurrentState;
    eapAuthState_t          eapAuthPrevState;
    ubyte4                  sentVendorId;
    ubyte4                  sentMethodId;
    ubyte4                  eapRetransCount;
#endif
    eapSessionConfig_t      eapSessionCfg;
    eapSessionStats_t       eapSessionStats;
    eapInstanceCb_t*        eapInstance;
    eapHdr_t                recvEapHdr;
    ubyte4                  recvVendorId;
    ubyte4                  recvMethodId;
    ubyte                   recvType;
    ubyte                   sentType;
    ubyte                   lastMD5[MD5_DIGESTSIZE];
    ubyte                   recvMD5[MD5_DIGESTSIZE];
    ubyte4                  eapVendorId;
    ubyte4                  eapRounds;
    ubyte4                  eapMethodId;
    void*                   opaque_data;
#if defined(__ENABLE_DIGICERT_RADIUS_CLIENT__)
    ubyte*                  radiusAttrState;
    ubyte                   radiusAttrStateLen;
    ubyte4                  radiusRetransTimeout;
    ubyte*                  radiusMPPERecvKey;
    ubyte4                  radiusMPPERecvKeyLen;
    ubyte*                  radiusMPPESendKey;
    ubyte4                  radiusMPPESendKeyLen;
#endif
    ubyte*                  srpUsername;
    ubyte4                  srpUsernameLen;
    ubyte*                  srpPassword;
    ubyte*                  srpSalt;
    ubyte                   srpPasswordLen;
    ubyte                   srp_state;
    ubyte                   srpSaltLen;
    ubyte                   srpGenLen;
    ubyte*                  srpGenerator;
    ubyte4                  srpModulusLen;
    ubyte*                  srpModulus;
    sbyte4                  len_A;
    ubyte*                  srpValueA;
    ubyte4                  len_a;
    ubyte*                  srpValue_a;
    sbyte4                  len_b;
    ubyte*                  srpValue_b;
    sbyte4                  len_B;
    ubyte*                  srpValueB;
    ubyte*                  srpValue_x;
    sbyte4                  len_v;
    ubyte*                  srpValue_v;
    ubyte*                  srpRechallenge;
    ubyte                   srpValue_M1[20];
    ubyte                   srpKey[40];
    ubyte                   srpId;
    byteBoolean             eapRecvdStartRequest;

} eapSessionCb_t;

typedef struct eapSessionStatus_s
{
    ubyte4                  sessionId;
    ubyte                   eapDecision;
    ubyte                   eapMethodState;
    ubyte                   eapSelectedMethod;
    byteBoolean             eapAllowNotification;
    ubyte                   eapCurrentId;
    ubyte                   eapLastId;
    ubyte                   eapSendCode;
    byteBoolean             eapSuccess;
    byteBoolean             eapFail;
    byteBoolean             eapPortEnabled;
    byteBoolean             eapRestart;
    byteBoolean             eapKeyAvailable;
    ubyte*                  eapIdentity;
    ubyte4                  eapIdentityLen;
    eapSessionType          session_type;
    ubyte4                  eapSessionHdl;
    ubyte*                  appSessionHandle;
#if defined(__ENABLE_DIGICERT_EAP_PEER__)
    eapState_t              eapCurrentState;
    eapState_t              eapPrevState;
#endif
#if defined(__ENABLE_DIGICERT_EAP_AUTH__)
    eapAuthState_t          eapAuthCurrentState;
    eapAuthState_t          eapAuthPrevState;
    ubyte4                  eapRetransCount;
#endif
    eapSessionConfig_t      eapSessionCfg;
    eapSessionStats_t       eapSessionStats;
    ubyte4                  eapRounds;

} eapSessionStatus_t;


/*------------------------------------------------------------------*/


#if defined(__ENABLE_DIGICERT_EAP_PEER__)
/* Data Traversing APIs */
MOC_EXTERN MSTATUS EAP_peerProcessllReceivePacket(eapSessionCb_t *eapSession, ubyte * eap_pkt, ubyte4 eap_pkt_len, ubyte * opaque_data);
MOC_EXTERN MSTATUS EAP_peerProcessRestart(eapSessionCb_t * eapSession);
MOC_EXTERN MSTATUS EAP_peerProcessAltEvent(eapSessionCb_t *eapSession, eapCode code);
MOC_EXTERN MSTATUS EAP_peerProcessULTransmit(eapSessionCb_t * eapSession, eapMethodType  method_type, eapCode  code, eapMethodDecision  methodDecision, eapMethodState methodState, ubyte * eap_data, ubyte4  eap_data_len);
MOC_EXTERN MSTATUS EAP_peerSessionDisable(eapSessionCb_t * eapSession);
#endif /* defined(__ENABLE_DIGICERT_EAP_PEER__) */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_EAP_AUTH__)
MOC_EXTERN MSTATUS EAP_authProcessRestart(eapSessionCb_t * eapSession);

MOC_EXTERN MSTATUS EAP_authProcessULTransmit(eapSessionCb_t * eapSession,
                           eapMethodType  method_type,
                           eapCode  code,
                           eapMethodDecision  methodDecision,
                           eapMethodState methodState,
                           ubyte * eap_data,
                           ubyte4  eap_data_len);

MOC_EXTERN MSTATUS EAP_authProcessllReceivePacket(eapSessionCb_t *eapSession,
                                ubyte * eap_pkt,
                                ubyte4 eap_pkt_len,
                                ubyte * opaque_data);

MOC_EXTERN MSTATUS EAP_passthruProcessULTransmit(eapSessionCb_t * eapSession,
                              ubyte * eap_pkt);
MOC_EXTERN MSTATUS EAP_authSessionDisable(eapSessionCb_t * eapSession);

#endif /* defined(__ENABLE_DIGICERT_EAP_AUTH__) */

MOC_EXTERN MSTATUS eap_lookupSession (ubyte4 sessionId,
                                  ubyte4 instanceId,
                                  eapSessionCb_t **eapSession);

#ifdef __ENABLE_DIGICERT_EAP_SRP__
MOC_EXTERN MSTATUS flushSRPstate(eapSessionCb_t *eapSession, ubyte srpState);
#endif /*__ENABLE_DIGICERT_EAP_SRP__ */

MOC_EXTERN void EAP_timeoutCallback(void * session,ubyte *type);

MOC_EXTERN MSTATUS EAP_peerSessionTimeout(eapSessionCb_t  *session);

MOC_EXTERN MSTATUS
eap_buildExpandedNAK(eapSessionCb_t *eapSession,
                     eapExpandedMethod_t *expMethods, ubyte expMethodCount,
                     ubyte **eapResponse, ubyte4 *eapRespLen);

MOC_EXTERN MSTATUS
eap_buildExpandedResponse(eapSessionCb_t *eapSession,
                          ubyte4 expVendorId, ubyte4 expMethodId,
                          ubyte *eapPayload, ubyte4 eapPayloadLen,
                          ubyte **eapResponse, ubyte4 *eapRespLen);

MOC_EXTERN MSTATUS
eap_buildNAK(eapSessionCb_t *eapSession,
             ubyte* nakMethods, ubyte4 nakMethodCount,
             ubyte **eapResponse, ubyte4 *eapRespLen);

#endif /*(defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */
#ifdef __cplusplus
}
#endif

#endif /* __EAP_SESSION_H__ */
