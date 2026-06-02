/**
 * @file  eap_peap_pvt.h
 * @brief EAP-PEAP private definitions
 *
 * @details    Internal PEAP structures
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

#ifndef EAP_PEAP_PVT_H
#define EAP_PEAP_PVT_H
#ifdef __cplusplus
extern "C" {
#endif
/*------------------------------------------------------------------*/

#define MAX_EAP_PACKET                          (2048)

#define EAP_PEAP_RESULT_TLV                     3
#define EAP_PEAP_RESULT_SUCCESS                 1
#define EAP_PEAP_RESULT_FAILURE                 2


/*------------------------------------------------------------------*/

typedef enum eap_peap_frag_flag
{

    EAP_PEAP_FRAG_FLAG_RECV = 1,
    EAP_PEAP_FRAG_FLAG_SEND

} eap_peap_frag_flag_e;


typedef enum eap_peap_eap_state_e
{

    EAP_PEAP_EAP_INIT     = 0,
    EAP_PEAP_EAP_IDENTITY = 1,
    EAP_PEAP_EAP_METHOD   = 2,
    EAP_PEAP_EAP_SUCCESS  = 3,
    EAP_PEAP_EAP_FAILURE  = 4,

} eap_peap_eap_state;


/*------------------------------------------------------------------*/

typedef struct
{
    void*                   appSessionCB;
    ubyte*                  eapAuthSessionHdl;
    EAP_PEAP_params         eapPEAPparam;
    ubyte                   sessionStatus;
    eap_peap_eap_state      eapStatus;
    ubyte                   AuthenticatorResponse[42];
    ubyte*                  peap_data_recv;
    ubyte4                  peap_data_recv_total_len;
    ubyte4                  peap_data_recv_len;
    ubyte*                  peap_data_send;
    ubyte*                  peap_data_send_cur;
    ubyte4                  peap_data_send_total_len;
    ubyte4                  peap_data_send_remaining;
    eap_peap_frag_flag_e    peap_frag_flag;
    eap_peap_eap_state      eapStageStatus;
    ubyte*                  eapSessionHdl;
    eapCode                 recvCode;
    ubyte                   recvId;
    ubyte4                  eapMTU; /*P: Variable holding the MAX MTU value */
} eapPEAPCB;


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS EAP_PEAPauthCreateSession(eapPEAPCB * eapPEAPCb);
MOC_EXTERN MSTATUS EAP_PEAPProcessAVP(eapPEAPCB *eapCb, ubyte *pPkt, ubyte4 pktLen);
MOC_EXTERN MSTATUS EAP_PEAPInitEAPPeerRequest(eapPEAPCB *eapCb);
MOC_EXTERN MSTATUS EAP_PEAPEncapEAPPkt(eapPEAPCB *eapCb,ubyte *eapPkt, ubyte4 eapPktLen);
MOC_EXTERN MSTATUS EAP_PEAPProcessEAPAuthRequest(eapPEAPCB *eapCb,ubyte* eapPkt, ubyte4 eapPktLen);
MOC_EXTERN MSTATUS EAP_PEAPProcessEAPRequest(eapPEAPCB *eapCb, ubyte *pkt, ubyte4 pktLen);
MOC_EXTERN MSTATUS eap_PEAPPeerInit(eapPEAPCB *eapCb);
MOC_EXTERN MSTATUS EAP_PEAP_llTransmitPktCallback(ubyte* appSessionHdl, eapHdr_t* eap_hdr, ubyte* eap_data, ubyte4 eap_data_len);
MOC_EXTERN MSTATUS EAP_PEAPgetTLVbyType(eapPEAPCB *eapCb, ubyte *pPkt, ubyte4 pktLen, ubyte2 type, ubyte2 *pTlvLen, ubyte **pData, ubyte *isMandatory);
MOC_EXTERN MSTATUS EAP_PEAPBuildResultTlv(ubyte2 intResult, ubyte *buf, ubyte4 *length);
#ifdef __cplusplus
}
#endif

#endif

