/**
 * @file  ike2_eap.h
 * @brief IKEv2 IKEv2 EAP Integration Header
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     +   \c \__ENABLE_DIGICERT_EAP_AUTH__ or \c \__ENABLE_DIGICERT_EAP_PEER__
 *     +   \c \__DISABLE_DIGICERT_IKE_EAP__ must not be defined.
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
/* internal use only */

#ifndef __IKE2_EAP_HEADER__
#define __IKE2_EAP_HEADER__

#if defined(__ENABLE_DIGICERT_IKE_SERVER__)
#if (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

struct ike2eap;
struct eapMethodDef_s;
enum eapSessionType_e;

typedef struct IKE_eapSuiteInfo
{
    MSTATUS (*initFunc) (struct ike2eap *);
    MSTATUS (*delFunc) (struct ike2eap *);

    struct eapMethodDef_s *pMethodDef;
    enum eapSessionType_e sessionType;

#ifdef __ENABLE_IKE_EAP_ONLY__
    intBoolean bEapOnlyOk;
#endif
} IKE_eapSuiteInfo;


/*------------------------------------------------------------------*/

typedef struct ike_eapperp_requestData
{
    ubyte   ikeVer;         /* Identifies Ike version in AAA context*/
    ubyte4  ikeSaId;        /* for IKE engine to find back the ikesa */
    sbyte4  ikeSaLoc;       /* for IKE engine to find back the ikesa */
    ubyte2  dwMsgId;        /* required by IKE interface */
    ubyte2  dwId;           /* required by IKE interface */
    ubyte4  pSession;       /* eap session handle */

} IKE_EAPPERP_requestData;


/*------------------------------------------------------------------*/

struct ikesa;
struct ike2xg;
struct eapMsgHdr;

MOC_EXTERN MSTATUS IKE_eapProcess(struct eapMsgHdr *pxMsg,
                              struct ikesa *pxSa, struct ike2xg *pxXg);
MOC_EXTERN MSTATUS IKE_eapSuite(IKE_EAP_PROTO_T proto_t, intBoolean bInitiator,
                            const IKE_eapSuiteInfo **ppEapSuite);
MOC_EXTERN const IKE_eapSuiteInfo *IKE_getEapSuite(intBoolean bInitiator,
                                                   sbyte4 i,
                                                   IKE_EAP_PROTO_T *proto_t);

MOC_EXTERN MSTATUS IKE_eapReceiveIndication(
                                ubyte* app_session_handle,
                                eapIndication ind_type,
                                ubyte* data,
                                ubyte4 data_len);
MOC_EXTERN MSTATUS IKE_eapVerifyMIC(ubyte* app_session_handle,
                                ubyte* pkt,
                                ubyte4 pkt_len);
MOC_EXTERN MSTATUS IKE_eapGetMethodState(ubyte*  app_session_handle,
                                     ubyte4* methodState);
MOC_EXTERN MSTATUS IKE_eapGetDecision(ubyte*  app_session_handle,
                                  ubyte4* decision);
MOC_EXTERN MSTATUS IKE_eapTransmitPktCallback(
                                ubyte*    appSessionHdl,
                                eapHdr_t* eap_hdr,
                                ubyte*    eap_data,
                                ubyte4    eap_data_len);

#if defined(__ENABLE_DIGICERT_EAP_RADIUS__) && defined(__ENABLE_DIGICERT_RADIUS_CLIENT__)
enum RADIUS_RESULT;
struct RADIUS_RqstRecord;
MOC_EXTERN sbyte4 IKE_radIndCallback(ubyte* appSessionHdl,
                                 enum RADIUS_RESULT result,
                                 struct RADIUS_RqstRecord *pRadiusReq);
#endif


#ifdef __cplusplus
}
#endif

#endif /* (defined(__ENABLE_DIGICERT_EAP_AUTH__) || defined(__ENABLE_DIGICERT_EAP_PEER__)) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

#endif /* __IKE2_EAP_HEADER__ */

