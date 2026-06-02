/**
 * @file  eap_sim.h
 * @brief EAP-SIM method API
 *
 * @details    EAP-SIM interface
 * @since      1.41
 * @version    2.02 and later
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_SIM__
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

#ifndef __EAP_SIM_H__
#define __EAP_SIM_H__

#ifdef __cplusplus
extern "C" {
#endif

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))

#define EAP_SIM_AT_RAND                         (1)
#define EAP_AKA_AT_AUTN                         (2)
#define EAP_AKA_AT_RES                          (3)
#define EAP_AKA_AT_AUTS                         (4)
#define EAP_SIM_AT_PADDING                      (6)
#define EAP_SIM_AT_NONCE_MT                     (7)
#define EAP_SIM_AT_PERMANENT_ID_REQ             (10)
#define EAP_SIM_AT_MAC                          (11)
#define EAP_SIM_AT_NOTIFICATION                 (12)
#define EAP_SIM_AT_ANY_ID_REQ                   (13)
#define EAP_SIM_AT_IDENTITY                     (14)
#define EAP_SIM_AT_VERSION_LIST                 (15)
#define EAP_SIM_AT_SELECTED_VERSION             (16)
#define EAP_SIM_AT_FULLAUTH_ID_REQ              (17)
#define EAP_SIM_AT_COUNTER                      (19)
#define EAP_SIM_AT_COUNTER_TOO_SMALL            (20)
#define EAP_SIM_AT_NONCE_S                      (21)
#define EAP_SIM_AT_CLIENT_ERROR_CODE            (22)
#define EAP_SIM_AT_IV                           (129)
#define EAP_SIM_AT_ENCR_DATA                    (130)
#define EAP_SIM_AT_NEXT_PSEUDONYM               (132)
#define EAP_SIM_AT_NEXT_REAUTH_ID               (133)
#define EAP_AKA_AT_CHECKCODE                    (134)
#define EAP_SIM_AT_RESULT_IND                   (135)

#define EAP_SIM_AT_RAND_PRESENT                 (0x1)
#define EAP_SIM_AT_PADDING_PRESENT              (0x2)
#define EAP_SIM_AT_NONCE_MT_PRESENT             (0x4)
#define EAP_SIM_AT_PERMANENT_ID_REQ_PRESENT     (0x8)
#define EAP_SIM_AT_MAC_PRESENT                  (0x10)
#define EAP_SIM_AT_NOTIFICATION_PRESENT         (0x20)
#define EAP_SIM_AT_ANY_ID_REQ_PRESENT           (0x40)
#define EAP_SIM_AT_IDENTITY_PRESENT             (0x80)
#define EAP_SIM_AT_VERSION_LIST_PRESENT         (0x100)
#define EAP_SIM_AT_SELECTED_VERSION_PRESENT     (0x200)
#define EAP_SIM_AT_FULLAUTH_ID_REQ_PRESENT      (0x400)
#define EAP_SIM_AT_COUNTER_PRESENT              (0x800)
#define EAP_SIM_AT_COUNTER_TOO_SMALL_PRESENT    (0x1000)
#define EAP_SIM_AT_NONCE_S_PRESENT              (0x2000)
#define EAP_SIM_AT_CLIENT_ERROR_CODE_PRESENT    (0x4000)
#define EAP_SIM_AT_IV_PRESENT                   (0x8000)
#define EAP_SIM_AT_ENCR_DATA_PRESENT            (0x10000)
#define EAP_SIM_AT_NEXT_PSEUDONYM_PRESENT       (0x20000)
#define EAP_SIM_AT_NEXT_REAUTH_ID_PRESENT       (0x40000)
#define EAP_SIM_AT_RESULT_IND_PRESENT           (0x80000)
#define EAP_AKA_AT_AUTN_PRESENT                 (0x100000)
#define EAP_AKA_AT_RES_PRESENT                  (0x200000)
#define EAP_AKA_AT_AUTS_PRESENT                 (0x400000)
#define EAP_AKA_AT_CHECKCODE_PRESENT            (0x800000)

#define EAP_AKA_SUBTYPE_CHALLENGE               (1)
#define EAP_AKA_SUBTYPE_AUTH_REJECT             (2)
#define EAP_AKA_SUBTYPE_SYNC_FAIL               (4)
#define EAP_AKA_SUBTYPE_IDENTITY                (5)
#define EAP_SIM_SUBTYPE_START                   (10)
#define EAP_SIM_SUBTYPE_CHALLENGE               (11)
#define EAP_SIM_SUBTYPE_NOTIFICATION            (12)
#define EAP_AKA_SUBTYPE_NOTIFICATION            (12)
#define EAP_SIM_SUBTYPE_REAUTHENTICATION        (13)
#define EAP_AKA_SUBTYPE_REAUTHENTICATION        (13)
#define EAP_SIM_SUBTYPE_CLIENT_ERROR            (14)
#define EAP_AKA_SUBTYPE_CLIENT_ERROR            (14)

#define EAP_SIM_MAC_LEN                         (16)
#define EAP_SIM_KAUT_LEN                        (16)
#define EAP_SIM_KENCR_LEN                       (16)
#define EAP_SIM_MK_LEN                          (20)
#define EAP_SIM_MSK_LEN                         (64)
#define EAP_SIM_EMSK_LEN                        (64)
#define EAP_SIM_KC_LEN                          (8)
#define EAP_SIM_SRES_LEN                        (4)
#define EAP_SIM_MAX_RAND                        (3)
#define EAP_SIM_RAND_LEN                        (16)
#define EAP_SIM_NONCE_MT_LEN                    (16)
#define EAP_SIM_NONCE_S_LEN                     (16)
#define EAP_SIM_IV_LEN                          (16)
#define EAP_AKA_AUTN_LEN                        (16)
#define EAP_AKA_AUTS_LEN                        (14)
#define EAP_AKA_MAX_RES_LEN                     (16) /* Max 128 Bits */
#define EAP_AKA_IK_LEN                          (16)
#define EAP_AKA_CK_LEN                          (16)

#define EAP_SIM_NOTIF_S_BIT                     (0x8000)
#define EAP_SIM_NOTIF_P_BIT                     (0x4000)

#define EAP_SIM_PACKET_SIZE                     (1024)


/*------------------------------------------------------------------*/

/** @private @internal */
typedef enum eapSimKeyType_e
{
    EAP_SIM_MASTER_KEY = 1,
    EAP_SIM_ENCR_KEY   = 2,
    EAP_SIM_AUT_KEY    = 3,
    EAP_SIM_MSK_KEY    = 4,
    EAP_SIM_EMSK_KEY   = 5,

} eapSimKeyType;

/** @private @internal */
typedef enum eapSimNotifCode_e
{
    EAP_SIM_NOTIF_GENERAL_ERROR = 0,
    EAP_SIM_NOTIF_DENIED_ACCESS=1026,
    EAP_SIM_NOTIF_NOT_SUBSCRIBED=1031,
    EAP_SIM_NOTIF_GENERAL_FAILURE = 16384,
    EAP_SIM_NOTIF_SUCCESS=32768

} eapSimNotifCode;

/** @private @internal */
typedef enum eapSimClientErrCode_e
{
    EAP_SIM_CLERR_PROCESSING = 0,
    EAP_SIM_CLERR_UNSUPPORT_VER=1,
    EAP_SIM_CLERR_LESS_CHALLENGES=2,
    EAP_SIM_CLERR_STALE_RAND = 3

} eapSimClientErrCode;

/** @private @internal */
typedef enum eapSimIdType_e
{
    EAP_SIM_PERMANENT_ID_TYPE = 1,
    EAP_SIM_FULLAUTH_ID_TYPE,
    EAP_SIM_FASTREAUTH_ID_TYPE

} eapSimIdType;

/** @private @internal */
typedef enum eapSimPdus_e {
  EAP_SIM_START_REQ,
  EAP_SIM_START_RESP,
  EAP_SIM_CHALLENGE_REQ,
  EAP_SIM_CHALLENGE_RESP,
  EAP_SIM_NOTIFICATION_REQ,
  EAP_SIM_NOTIFICATION_RESP,
  EAP_SIM_CLIENT_ERROR,
  EAP_SIM_REAUTH_REQ,
  EAP_SIM_REAUTH_RESP,
  EAP_AKA_IDENTITY_REQ,
  EAP_AKA_IDENTITY_RESP,
  EAP_AKA_AUTH_REJECT_RESP,
  EAP_AKA_SYNC_FAIL_RESP

} eapSimPdus;

/** @private @internal */
typedef enum eapSimStatus_e {
  EAP_SIM_STATUS_INIT,
  EAP_SIM_STATUS_RECV_START_RESP,
  EAP_SIM_STATUS_RECV_START_REQ,
  EAP_SIM_STATUS_RECV_CHALLENGE_RESP,
  EAP_SIM_STATUS_RECV_CHALLENGE_REQ,
  EAP_SIM_STATUS_RECV_NOTIFICATION_RESP,
  EAP_SIM_STATUS_RECV_NOTIFICATION_REQ,
  EAP_SIM_STATUS_RECV_NOTIFICATION_ERROR,
  EAP_SIM_STATUS_RECV_REAUTH_REQ,
  EAP_SIM_STATUS_RECV_REAUTH_RESP,
  EAP_SIM_STATUS_RECV_CLIENT_ERROR_CODE,
  EAP_AKA_STATUS_RECV_IDENTITY_REQ,
  EAP_AKA_STATUS_RECV_IDENTITY_RESP,
  EAP_AKA_STATUS_RECV_AUTH_REJECT_RESP,
  EAP_AKA_STATUS_RECV_SYNC_FAIL_RESP

} eapSimStatus;


/*------------------------------------------------------------------*/

/**
@brief      Configuration settings and callback function pointers for EAP-SIM
            EAP-AKA methods.
@details    This structure is used to store configuration settings and to
            register callback function pointers for EAP-SIM and EAP-AKA methods.

@since 1.41
@version 1.41 and later

@flags
To enable thie callbacks, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__
+ \c \__ENABLE_DIGICERT_EAP_PEER__

*/
typedef struct eapSimConfig_s
{
    /**
     @brief      Support Result_IND Attribute.
     @details    Support Result_IND Attribute:  \c FALSE (0); otherwise, \c TRUE.
     */
    ubyte send_result_ind;                                          /* Support Result_IND Attr */

/**
@brief      Get SRES and KC values from application.
@details    This function gets SRES and KC values from application.

@ingroup    eap_callback_functions

@since 1.41
@version 2.02 and later

@flags
To enable this callback function, the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@param appCb         Application Handle.
@param eapSim        EAP-SIM Handle.
@param rand          Array of Random Value.
@param numRand       Number of elements in rand.
@param Sres          SRES value returned by the application.
@param Kc            KC value returned by the application.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    eap_sim.h
*/
    MSTATUS(*getSresKc)(void * appCb,void *eapSim,ubyte *rand,ubyte numRand,
                          ubyte *Sres,ubyte *Kc);                   /* Function that gets called once RAND from AUTH are received */

/**
@brief      Get AKA IK and CK values from the application.
@details    This function gets AKA IK and CK values from the application.

@ingroup    eap_callback_functions

@since 1.41
@version 2.02 and later

@flags
To enable this callback function, the following flags must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__
+ \c \__ENABLE_DIGICERT_EAP_PEER__

@param appCb        Application Handle.
@param eapSim       EAP-SIM Handle.
@param rand         128 bit random number.
@param autn         128bit AUTN Value.
@param ik           output IK value.
@param ck           output CK value.
@param Res          32 to 128 RES value.
@param resLen       Length of Res.
@param auts         112 bits AUTS value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    eap_sim.h
*/
    MSTATUS(*getAKARes)(void * appCb,void *eapSim,ubyte *rand,ubyte *autn,
                          ubyte *ik,ubyte * ck,
                          ubyte *Res,ubyte2 *resLen,ubyte *auts);   /* Function that gets called once RAND from AUTN are received  */
                                                                    /*It can return back OK/ AUTHREJECT or SYNC FAIL.. */
                                                                    /*If it returns sync fail then it has to fill the auts value*/

    /**
     @brief      EAP session type.
     @details    EAP session type: either \c PEER or \c AUTH.
    */
    eapSessionType sessionType;                                     /* PEER- AUTH */

    /**
     @brief      Minimum number of Rands that the Auth needs to send.
     @details    Minimum number of Rands that the Auth needs to send.
     */
    ubyte minNumRand;                                               /* Minimum number of Rands That the Auth Needs to Send */

    /**
     @brief      Deny the PERM ID attribute to the server.
     @details    Deny the PERM ID attribute to the server.
     */
    ubyte dontSendPerm;                                             /* Deny The PERM ID attribute to the Server */

    /**
     @brief      AKA Session.
     @details    AKA Session: \c FALSE (0); otherwise, \c TRUE.
     */
    ubyte aka;                                                      /* AKA Session */

} eapSimConfig;

/** @private @internal */
typedef struct eapSimCb_s {

    void*           appSessionHdl;
    ubyte*          permanentIdentity;              /* Based upon IMSI*/
    ubyte2          permanentIdentityLen;
    ubyte*          psuedonym;                      /* Received from NEXT_PSUEDONYM For Identity Hiding*/
    ubyte2          psuedonymLen;
    ubyte*          reauthId;                       /* For Reauth ,received from REAUTH_ID*/
    ubyte2          reauthIdLen;
    ubyte           numIdReq;
    ubyte*          identity;
    ubyte           id_requested;                   /*The Type of ID requested by AUTH(ANY,FULL,PERM)*/
    ubyte2          identityLen;
    ubyte           sRes[EAP_SIM_SRES_LEN* EAP_SIM_MAX_RAND];
    ubyte           kC[EAP_SIM_KC_LEN* EAP_SIM_MAX_RAND];
    ubyte2*         versionListImpl;
    ubyte2          numVersionListImpl;             /* Has to be atleast 1*/
    ubyte2*         versionList;                    /* Version List Sent by AUTH*/
    ubyte2          numVersionList;
    ubyte2          selectedVersion;                /* Version Selected by Peer*/
    ubyte           nonce_mt[EAP_SIM_NONCE_MT_LEN]; /* Nonce Sent by PEER*/
    ubyte           nonce_s[EAP_SIM_NONCE_S_LEN];   /* Nonce sent by AUTH during Fast Reauth*/
    ubyte           numRand;                        /* Number of Rands sent by AUTH*/
    ubyte           rand[EAP_SIM_MAX_RAND][EAP_SIM_RAND_LEN];
    ubyte           mac[EAP_SIM_MAC_LEN];
    ubyte           autn[EAP_AKA_AUTN_LEN];
    ubyte           auts[EAP_AKA_AUTS_LEN];
    ubyte           res[EAP_AKA_MAX_RES_LEN];
    ubyte2          resLen;
    ubyte           authRes[EAP_AKA_MAX_RES_LEN];
    ubyte2          authResLen;
    ubyte           masterKey[EAP_SIM_MK_LEN];
    ubyte           k_aut[EAP_SIM_KAUT_LEN];
    ubyte           k_encr[EAP_SIM_KENCR_LEN];
    ubyte           k_msk[EAP_SIM_MSK_LEN];
    ubyte           k_emsk[EAP_SIM_EMSK_LEN];
    ubyte           IK[EAP_AKA_IK_LEN];
    ubyte           CK[EAP_AKA_CK_LEN];
    ubyte*          encr_data;
    ubyte2          encr_dataLen;
    ubyte           iv[EAP_SIM_IV_LEN];
    ubyte4          attrPresent;                    /* Bit map of attr present in any message received*/
    ubyte2          counter;                        /* AT_COUNTER Sent by AUTH*/
    ubyte2          notifCode;
    ubyte2          clientErrCode;
    eapSimConfig    eapSimCfg;                      /* Initial Params set during Session Create*/
    eapSimStatus    sessionStatus;                  /* Session Stataus*/
    ubyte           recvResultInd;
    ubyte           reAuthRoundSuccess;             /* Doing Reauth Istead of Full Auth*/
    ubyte           attemptreAuthRound;
    ubyte           fullAuthRoundSuccess;
    ubyte           attemptfullAuthRound;
    ubyte           counterTooSmall;
} eapSimCb;


/*------------------------------------------------------------------*/

/**
@brief      Build a Sim Challenge Request packet.
@details    This function (typically called by the authenticator) builds a Sim
            Challenge Request packet based on the specified parameters. (For
            details about how the random numbers and keys are used, refer to the
            following Web page:
            http://www.gsm-security.net/faq/gsm-ki-kc-rand-sres.shtml .)

@ingroup    eap_sim_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_sim.h

@param eapSim           EAP-SIM session handle returned from EAP_SIMInitSession.
@param pkt              On return, pointer to generated EAP-SIM Challenge
                        Request packet.
@param pktLen           On return, pointer to umber of bytes in generated packet
                        (\p pkt).
@param rand             Pointer to 16-byte random number to send to the peer.
@param num_rand         Number of 16-byte random numbers to send, from 1 to 3.
                        (Recommended values are 2 or 3.)
@param kC               64-bit ciphering key used as a session key.
@param sRes             32-bit SRES (signed response) generated by the SIM
                        device.
@param at_next_psuedo   Pseudo identity to send to the peer.
@param at_psuedo_len    Number of bytes in pseudo identity (\p at_next_psuedo).
@param at_next_reauthid Reauthorization ID to send to the peer.
@param at_reauthid_len  Number of bytes in reauthorization ID (\p
                        at_next_reauthid).
@param id               EAP request header ID (unique to this session).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_SIMSendStartReq
@sa EAP_SIMSendNotificationReq
@sa EAP_SIMSendReauthReq

@funcdoc    eap_sim.h
*/
MOC_EXTERN MSTATUS
EAP_SIMSendChallengeReq(eapSimCb *eapSim, ubyte **pkt, ubyte4 *pktLen,
                        ubyte *rand, ubyte2 num_rand,
                        ubyte *kC, ubyte *sRes,
                        ubyte *at_next_psuedo, ubyte2 at_psuedo_len,
                        ubyte *at_next_reauthid, ubyte2 at_reauthid_len,
                        ubyte id);

/**
@brief      Build a Sim Notification Request packet.
@details    This function (typically called by the authenticator) builds a Sim
            Notification Request packet based on the specified parameters.

@ingroup    eap_sim_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_sim.h

@param eapSim           EAP-SIM session handle returned from EAP_SIMInitSession.
@param pkt              On return, pointer to generated EAP-SIM Notification
                        Request packet.
@param pktLen           On return, pointer to umber of bytes in generated packet
                        (\p pkt).
@param at_counter       \c AT_COUNTER value to send to the peer; once the
                        counter reaches the configurable maximum value, a full
                        authentication instead of a FAST reauthentication is
                        required.
@param notification_code    Notification code as defined in RFC&nbsp;4186 (refer
                        to sections 6 and 10.18).
@param id               EAP request header ID (unique to this session).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_SIMSendStartReq
@sa EAP_SIMSendChallengeReq
@sa EAP_SIMSendReauthReq

@funcdoc    eap_sim.h
*/
MOC_EXTERN MSTATUS
EAP_SIMSendNotificationReq(eapSimCb *eapSim, ubyte **pkt, ubyte4 *pktLen,
                           ubyte2 at_counter,
                           ubyte4 notification_code, ubyte id);

/**
@brief      Process a received packet and build a response.
@details    This function processes a packet received by the specified EAP-SIM
            session, builds a response (which is returned through the \p resp
            parameter), and informs the calling application of the current state
            (the EAP-SIM state machine's state).

@ingroup    eap_sim_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_sim.h

@param eapSim   EAP-SIM session handle returned from EAP_SIMInitSession.
@param pkt      Pointer to packet to process.
@param pktLen   Number of bytes in packet to process (\p pkt).
@param resp     On return, pointer to response packet to be transmitted.
@param respLen  On return, pointer to number of bytes in response packet (\p
                resp).
@param state    On return, pointer to \c eapSimStatus enumerated value (refer to
                @ref eap_sim.h).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_sim.h
*/
MOC_EXTERN MSTATUS
EAP_SIMProcessPkt(eapSimCb *eapSim, ubyte *pkt, ubyte2 pktLen,
                  ubyte **resp, ubyte4 *respLen, eapSimStatus *state);

/**
@brief      Create and initialize an EAP-SIM or EAP-AKA session.
@details    This function creates and initializes an EAP-SIM or EAP-AKA session.

@ingroup    eap_sim_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_sim.h

@param appCb        Application session handle (cookie given by the application
                    to identify the session).
@param eapSim       On return, pointer to EAP-SIM/EAP-AKA session handle.
@param eapSimCfg    Parameters for the SIM/AKA session to be created.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_sim.h
*/
MOC_EXTERN MSTATUS
EAP_SIMInitSession(void *appCb, void **eapSim, eapSimConfig eapSimCfg);

/**
@brief      Determine whether a challenge negotiation included a \c RESULT_IND
            attribute.
@details    This function, called by the authenticator or peer, determines
            whether the peer or authenticator, respectively, sent the \c
            RESULT_IND attribute during challenge negotiation. If the result
            indication attribute is sent by either side, \c SUCCESS/\c FALURE is
            sent by the authenticator in a Notification Request.

@ingroup    eap_sim_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_sim.h

@param eap_sim  EAP-SIM session handle returned from EAP_SIMInitSession.
@param rInd     On return, pointer to determination value: \c 1 if the other
                side sent a \c RESULT_IND attribute; otherwise \c 0.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_sim.h
*/
MOC_EXTERN MSTATUS
EAP_SIMGetResultInd(void *eap_sim, ubyte *rInd);

/**
@brief      Build a Sim Start Request packet.
@details    This function (typically called by the authenticator) builds a Sim
            Start Request packet based on the specified identity. The resultant
            packet, returned through the \p pkt parameter, can then be
            transmitted by making a call to EAP_ulTransmit.

@ingroup    eap_sim_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_sim.h

@param eapSim           EAP-SIM session handle returned from EAP_SIMInitSession.
@param pkt              On return, pointer to generated EAP-SIM Notification
                        Request packet.
@param pktLen           On return, pointer to umber of bytes in generated packet
                        (\p pkt).
@param id_type          Any of the \c eapSimIdType enumeration values (defined
                        in @ref eap_sim.h):\n
\n
- \c EAP_SIM_PERMANENT_ID_TYPE
- \c EAP_SIM_FULLAUTH_ID_TYPE
- \c EAP_SIM_FASTREAUTH_ID_TYPE

@param id               EAP request header ID (unique to this session).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_SIMSendChallengeReq
@sa EAP_SIMSendNotificationReq
@sa EAP_SIMSendReauthReq

@funcdoc    eap_sim.h
*/
MOC_EXTERN MSTATUS
EAP_SIMSendStartReq(eapSimCb *eapSim, ubyte **pkt, ubyte4 *pktLen,
                    ubyte id_type, ubyte id);

/**
@brief      Build a SIM FAST Reauthentication Request packet.
@details    This function builds a SIM FAST Reauthentication Request packet
            based on the specified parameters. It is used by the SIM
            authenticator for fast (quick) reauthentication.

@ingroup    eap_sim_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_sim.h

@param eapSim           EAP-SIM session handle returned from EAP_SIMInitSession.
@param pkt              On return, pointer to generated EAP-SIM Reauthorization
                        Request packet.
@param pktLen           On return, pointer to umber of bytes in generated packet
                        (\p pkt).
@param at_next_reauthid Pointer to reauthorization ID to send to the peer.
@param at_reauthid_len  Number of bytes in reauthorization ID (\p
                        at_next_reauthid).
@param id               EAP request header ID (unique to this session).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_SIMSendStartReq
@sa EAP_SIMSendChallengeReq
@sa EAP_SIMSendNotificationReq

@funcdoc    eap_sim.h
*/
extern MSTATUS
EAP_SIMSendReauthReq(eapSimCb *eapSim, ubyte **pkt, ubyte4 *pktLen,
                     ubyte *at_next_reauthid, ubyte2 at_reauthid_len,
                     ubyte id);

/**
@brief      Get an EAP-SIM session's session status.
@details    This function retrieves an EAP-SIM session's session status.

@ingroup    eap_sim_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_sim.h

@param eap_sim  EAP-SIM session handle returned from EAP_SIMInitSession.
@param status   On return, pointer to the session's status: an \c eapSimStatus
                enumeration (see @ref eap_sim.h).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_sim.h
*/
MOC_EXTERN MSTATUS
EAP_SIMGetSessionStatus(void *eap_sim, eapSimStatus *status);

/**
@brief      Get the client error code returned by the peer.
@details    This function (typically called by the authenticator) retrieves the
            client error code returned by the peer for the specified EAP-SIM
            session.

@ingroup    eap_sim_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_sim.h

@param eapSim   EAP-SIM session handle returned from EAP_SIMInitSession.
@param clCode   On return, pointer to the %client error code value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_sim.h
*/
MOC_EXTERN MSTATUS
EAP_SIMGetClientErrorCode(eapSimCb *eapSim, ubyte2 *clCode);

/**
@brief      Get the authenticator's notification code.
@details    This function  (typically called by the peer) retrieves the
            notification code received from the authenticator for the specified
            EAP-SIM session.

@ingroup    eap_sim_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_sim.h

@param eapSim       EAP-SIM session handle returned from EAP_SIMInitSession.
@param notifCode    On return, pointer to notification code value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_sim.h
*/
MOC_EXTERN MSTATUS
EAP_SIMGetNotification(eapSimCb *eapSim, ubyte2 *notifCode);

/**
@brief      Get the EAP-SIM session ID returned by the peer.
@details    This function (typically called by the authenticator) retrieves the
            identity returned by the peer for the specified EAP-SIM session.
            That returned identity can then be used by the authenticator's
            application-specific logic to decide whether to process the
            identity, to get the tuple (the RAND, SRES and Kc), or to ask for a
            different identity from the peer.

@ingroup    eap_sim_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_sim.h

@param eapSim   EAP-SIM session handle returned from EAP_SIMInitSession.
@param identity On return, pointer to peer's identity.
@param len      On return, pointer to number of bytes in peer's ideneity (\p
                identity).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_sim.h
*/
MOC_EXTERN MSTATUS
EAP_SIMGetIdentity(eapSimCb *eapSim, ubyte **identity, ubyte4 *len);

/**
@brief      Add version(s) to an EAP-SIM session's supported versions list.
@details    This function (called by the authenticator or peer) adds the
            specified version(s) to the specified EAP-SIM session's list of
            supported versions. This version information is required during the
            EAP-SIM Identity phase negotiation, where the first version found to
            be common to the peer and authenticator is used for communication.

@ingroup    eap_sim_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_sim.h

@param eapSim           EAP-SIM session handle returned from EAP_SIMInitSession.
@param versionList      Pointer to array containing list of versions that the
                        node (calling authenticator or peer) is to support.
@param numVersion       Number of entries in the \p versionList array.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_sim.h
*/
MOC_EXTERN MSTATUS
EAP_SIMSetImplementedVersion(eapSimCb *eapSim,
                             ubyte2 *versionList, ubyte2 numVersion);

/**
@brief      Set the EAP-SIM session's permanent identity.
@details    This function (typically called by the peer) assigns the specified
            value to the EAP-SIM session's permanent identity. (The
            IMSI&mdash;International Mobile Subscriber Identity&mdash;is
            commonly used as the permanent identity.)

@ingroup    eap_sim_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_sim.h

@param eapSim   EAP-SIM session handle returned from EAP_SIMInitSession.
@param id       Pointer to desired permanent identity.
@param idLen    Number of bytes in permanent identity (\p id).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     The permanent identity is different from the final identity, which
            is used during identity phase negotiation (see EAP_SIMSetIdentity).

@funcdoc    eap_sim.h
*/
MOC_EXTERN MSTATUS
EAP_SIMSetPermIdentity(eapSimCb *eapSim, ubyte *id, ubyte2 idLen);

/**
@brief      Get the version selected during negotiation.
@details    This function (called by the peer) retrieves the version that was
            selected during authenticator-peer version negotiation for the
            specified EAP-SIM session.

@ingroup    eap_sim_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_sim.h

@param eap_sim  EAP-SIM session handle returned from EAP_SIMInitSession.
@param rVer     On return, pointer to selected version value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_sim.h
*/
MOC_EXTERN MSTATUS
EAP_SIMGetSelectedVersion(void *eap_sim, ubyte2 *rVer);

/**
@brief      Set the EAP-SIM session's final identity.
@details    This function (called by the authenticator or peer) assigns the
            specified identity value to the specified EAP-SIM session's final
            identity (used after identity negotiation is complete). The final
            identity is typically the IMSI (International Mobile Subscriber
            Identity) or the reauthorization ID negotiated between the peer and
            authenticator.

@ingroup    eap_sim_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_sim.h

@param eapSim   EAP-SIM session handle returned from EAP_SIMInitSession.
@param id       Pointer to desired final identity.
@param idLen    Number of bytes in final identity (\p id).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark The }final} identity is different from the }permanent} identity, which
is typically the IMSI (see EAP_SIMSetPermIdentity).

@funcdoc    eap_sim.h
*/
MOC_EXTERN MSTATUS
EAP_SIMSetIdentity(eapSimCb *eapSim, ubyte *id, ubyte2 idLen);

/**
@brief      Determine whether an authenticator Notification's \c S Bit is set.
@details    This function (called by the peer) determines whether the
            Notification received from the authenticator has the \c S Bit set
            (which indicates a Success Notification).

@ingroup    eap_sim_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_sim.h

@param eap_sim  EAP-SIM session handle returned from EAP_SIMInitSession.
@param rCode    On return, pointer to determination value: \c 1 if the \c S Bit
                is set; otherwise \c 0.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_sim.h
*/
MOC_EXTERN MSTATUS
EAP_SIMGetSuccessNotifCode(void *eap_sim, ubyte *rCode);

/**
@brief      Delete an EAP-SIM connection.
@details    This function deletes an EAP-SIM connection.

@ingroup    eap_sim_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_sim.h

@param eapSim   EAP-SIM session handle returned from EAP_SIMInitSession.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_sim.h
*/
MOC_EXTERN MSTATUS
EAP_SIMDeleteSession(eapSimCb *eapSim);

/**
@brief      Send EAP-AKA Start Request.
@details    Generate EAP-AKA Identity Request Packet to send to the Peer.

@ingroup    eap_sim_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_sim.h

@param eapSim           EAP SIM Session Handle.
@param pkt              Pointer to EAP packet formed \c
                        <EAPHdr,Type,SubType,Payload>.
@param pktLen           EAP payload length.
@param id_type          ID type to send (PERM,FULL,ANY ID)
@param id               EAP packet ID.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_SIMSendChallengeReq
@sa EAP_SIMSendNotificationReq
@sa EAP_SIMSendReauthReq

@funcdoc    eap_sim.h
*/
MOC_EXTERN MSTATUS
EAP_AKASendIdentityReq(eapSimCb *eapSim, ubyte **pkt, ubyte4 *pktLen,
                       ubyte id_type, ubyte id);

/**
@brief      Send EAP-AKA Challenge Request.
@details    Generate EAP-AKA Challenge Request packet to send to the Peer.

@ingroup    eap_sim_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_sim.h

@param eapSim           EAP SIM Session Handle.
@param pkt              Pointer to EAP packet formed \c
                        <EAPHdr,Type,SubType,Payload>.
@param pktLen           EAP payload length.
@param rand             Random bytes 16 bytes received from AuC.
@param autn             Autn value received from AuC 16 Bytes.
@param ck               CK value received from AuC 16 Bytes.
@param ik               IK value received from AuC 16 Bytes.
@param res              RES value received from AuC (32 to 128 Bits).
@param resLen           RES length (32 to 128 Bits).
@param at_next_psuedo   Pseudo identity to send to the peer.
@param at_psuedo_len    Number of bytes in pseudo identity (\p at_next_psuedo).
@param at_next_reauthid Next reauth ID.
@param at_reauthid_len  Next reauth ID length.
@param id               EAP packet ID.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_AKASendIdentityReq
@sa EAP_SIMSendChallengeReq
@sa EAP_SIMSendNotificationReq
@sa EAP_SIMSendReauthReq

@funcdoc    eap_sim.h
*/
MOC_EXTERN MSTATUS
EAP_AKASendChallengeReq(eapSimCb *eapSim, ubyte **pkt, ubyte4 *pktLen,
                        ubyte *rand, ubyte *autn,
                        ubyte *ck, ubyte *ik, ubyte* res, ubyte2 resLen,
                        ubyte *at_next_psuedo, ubyte2 at_psuedo_len,
                        ubyte *at_next_reauthid, ubyte2 at_reauthid_len,
                        ubyte id);

/**
@brief      Process received EAP-AKA packet.
@details    Process received packet and do SM functions.

@ingroup    eap_sim_functions

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_sim.h

@param eapSim           EAP SIM Session Handle.
@param pkt              Received EAP packet.
@param pktLen           Received EAP packet length.
@param resp             Pointer to EAP packet formed \c
                        <EAPHdr,Type,SubType,Payload>.
@param respLen          EAP payload length.
@param state            EAP SM state returned.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa EAP_SIMSendStartReq
@sa EAP_SIMSendChallengeReq
@sa EAP_SIMSendNotificationReq
@sa EAP_SIMSendReauthReq

@funcdoc    eap_sim.h
*/
MOC_EXTERN MSTATUS
EAP_AKAProcessPkt(eapSimCb *eapSim, ubyte *pkt, ubyte2 pktLen,
                  ubyte **resp, ubyte4 *respLen, eapSimStatus *state);

/** @private @internal */
MOC_EXTERN MSTATUS
EAP_AKAGetAuts(eapSimCb *eapSim, ubyte **auts);

/**
@brief      Get an EAP-SIM session key.
@details    This function (called by the authenticator or peer) retrieves the
            specified type of EAP-SIM session key.

@ingroup    eap_sim_functions

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_SIM__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_EAP_PEER__
+ \c \__ENABLE_DIGICERT_EAP_AUTH__

@inc_file   eap_sim.h

@param eapSim   EAP-SIM session handle returned from EAP_SIMInitSession.
@param keyType  Any of the \c eapSimKeyType enumerated values (defined in @ref
                eap_sim.h).
@param key      On return, pointer to the key.
@param keyLen   On return, pointer to the number of bytes in the key (\p key).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    eap_sim.h
*/
MOC_EXTERN MSTATUS
EAP_SIMgetKey(eapSimCb *eapSim, eapSimKeyType keyType,
              ubyte **key, ubyte4 *keyLen);


#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */
#ifdef __cplusplus
}
#endif
#endif /* __EAP_SIM_H__  */

