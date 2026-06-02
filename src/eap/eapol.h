/**
 * @file  eapol.h
 * @brief EAPOL API
 *
 * @details    EAPOL interface definitions
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAPOL__
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

#ifndef __EAPOL_H__
#define __EAPOL_H__

/* check for possible build configuration errors */

#if defined(__ENABLE_DIGICERT_EAPOL__)

#ifndef EAP_PACKED
#define EAP_PACKED
#endif

#ifndef EAP_PACKED_POST
#define EAP_PACKED_POST __attribute__((__packed__))
#endif

/* Used with KeyAlgoLen */
#define EAPOL_CCMP_SIZE      (16)
#define EAPOL_TKIP_SIZE      (32)
#define EAPOL_GTK_SIZE       (32)
#define EAPOL_WEP40_KEYLEN   (5 )
#define EAPOL_WEP104_KEYLEN  (13)


#define EAPOL_MAC_SIZE       (6)
#define EAPOL_MIC_SIZE       (16)
#define EAPOL_NONCE_LEN      (32)
#define EAPOL_REPLAYCOUNTER_LEN      (8)

#define EAPOL_KEY_IV_SIZE    (16)
#define EAPOL_KCK_SIZE       (16)
#define EAPOL_KEK_SIZE       (16)
#define EAPOL_PMK_SIZE       (32)
#define EAPOL_PTK_SIZE       (64) /* or 48 Bytes for CCMP */

typedef EAP_PACKED struct eapolKeyFrame_s
{
    ubyte     keyDesc;
    ubyte2    keyInfo;
    ubyte2    keyLen;
    ubyte     keyReplayCounter[EAPOL_REPLAYCOUNTER_LEN];
    ubyte     keyNonce[EAPOL_NONCE_LEN];
    ubyte     keyIV[16];
    ubyte     keyRSC[8];
    ubyte     reserved[8];
    ubyte     keyMIC[EAPOL_MIC_SIZE];
    ubyte2    keyDataLen;

} EAP_PACKED_POST eapolKeyFrame;

#define EAPOL_KEY_TYPE        (0x0008)
#define EAPOL_KEY_INSTALL     (0x0040)
#define EAPOL_KEY_ACK         (0x0080)
#define EAPOL_KEY_MIC         (0x0100)
#define EAPOL_KEY_SECURE      (0x0200)
#define EAPOL_KEY_ERROR       (0x0400)
#define EAPOL_KEY_REQUEST     (0x0800)
#define EAPOL_KEY_ENCRYPT     (0x1000)

typedef EAP_PACKED struct eapolKeyInfo_s
{
#ifndef MOC_LITTLE_ENDIAN
    ubyte keyDesVersion:3;
    ubyte keyType:1;
    ubyte keyReserved0:2;
    ubyte keyInstall:1;
    ubyte keyAck:1;
    ubyte keyMIC:1;
    ubyte keySecure:1;
    ubyte keyError:1;
    ubyte keyRequest:1;
    ubyte keyEncrypt:1;
    ubyte keyReserved1:3;
#else
    ubyte keyReserved1:3;
    ubyte keyEncrypt:1;
    ubyte keyRequest:1;
    ubyte keyError:1;
    ubyte keySecure:1;
    ubyte keyMIC:1;
    ubyte keyAck:1;
    ubyte keyInstall:1;
    ubyte keyReserved0:2;
    ubyte keyType:1;
    ubyte keyDesVersion:3;
#endif

} EAP_PACKED_POST eapolKeyInfo;



typedef enum eapolFrameType_e
{
    EAPOL_TYPE_EAP_PACKET    = 0,
    EAPOL_TYPE_EAPOL_START   = 1,
    EAPOL_TYPE_EAPOL_LOGOFF  = 2,
    EAPOL_TYPE_EAPOL_KEY     = 3
} eapolFrameType;

typedef enum eapolKeyType_e
{
    EAPOL_KEY_TYPE_RC4 = 1,
    EAPOL_KEY_TYPE_RSN = 2,/* Also Known as WPA2/RSNA*/
    EAPOL_KEY_TYPE_WPA = 254
} eapolKeyType;


typedef struct eapRSN_IE_s
{
    ubyte type;
    ubyte length;
    ubyte oui[3];
    ubyte kde;
} eapRSN_IE;


typedef enum keyAlgo_e
{
    EAPOL_GROUP_KEYALGO   = 0,
    EAPOL_WEP40_KEYALGO   = 1,
    EAPOL_TKIP_KEYALGO    = 2,
    EAPOL_CCMP_KEYALGO    = 4,
    EAPOL_WEP104_KEYALGO  = 5
} KeyAlgo;

/* DescVersion Neither Pairwise or Group is CCMP */
#define EAPOL_KEY_DESC_HMAC_MD5_RC4    (1)
/* DescVersion Either Pairwise or Group is CCMP */
#define EAPOL_KEY_DESC_HMAC_SHA1_AES   (2)

#define EAPOL_RSN_IETYPE                (0xDD)
#define EAPOL_RSN_OIU_1                 (0x00)
#define EAPOL_RSN_OIU_2                 (0x0F)
#define EAPOL_RSN_OIU_3                 (0xAC)

#define EAPOL_RSN_KDE_PMKID             (0x04)
#define EAPOL_RSN_KDE_MACADDR           (0x03)
#define EAPOL_RSN_KDE_GTK               (0x01)
#define EAPOL_RSN_KDE_STAKEY            (0x02)

#define EAPOL_PMKID_LEN                 (16)

#define EAPOL_TYPE_STA                  (0)
#define EAPOL_TYPE_AA                   (1)

typedef struct eapolCfgParam_s
{
    eapolKeyType keyType;
    KeyAlgo      keyAlgo;
    ubyte        keyAlgoLen;/* WIll decide TKIP 32 or CCMP 16 */
    ubyte        keyInstall;
    ubyte        keyDesVersion;
    ubyte        pmk[EAPOL_PMK_SIZE];
    ubyte        sta_mac[EAPOL_MAC_SIZE];
    ubyte        aa_mac [EAPOL_MAC_SIZE];
    ubyte        type; /* STA or AA */
    ubyte*       rsnIE;
    ubyte4       rsnIELen;
    ubyte*       beaconRsnIE;
    ubyte4       beaconRsnIELen;
    ubyte*       newPairwiseCipher;
    ubyte4       pairwiseCipherLen;
    ubyte        gtkKey[EAPOL_GTK_SIZE];
    ubyte        gtkKeyFlag;
    ubyte4       gtkKeyLen;
    ubyte        keyReplayCounter[EAPOL_REPLAYCOUNTER_LEN];
    MSTATUS (*funcPtrGetSeqNum)(ubyte *appCb,ubyte *keyRSC,ubyte4 keyRSCLen);
} eapolCfgParam;


typedef enum eapolState_e
{
    EAPOL_STATE_SENT_1of4 = 0,
    EAPOL_STATE_SENT_2of4,
    EAPOL_STATE_SENT_3of4,
    EAPOL_STATE_SENT_4of4
} eapolState;

typedef struct eapolCB_s
{
    eapolCfgParam eapolCfg;
    ubyte*       appCb;
    ubyte4       keycount;
    intBoolean   init;
    intBoolean   deauthRequest;
    intBoolean   portEnable;
    intBoolean   portValid;
    intBoolean   portControl;
    ubyte        SNonce[EAPOL_NONCE_LEN];
    ubyte        ANonce[EAPOL_NONCE_LEN];
    ubyte        ptk[EAPOL_PTK_SIZE];
    ubyte        tkip[EAPOL_TKIP_SIZE];
    ubyte        ccmp[EAPOL_CCMP_SIZE];
    ubyte        kck[EAPOL_KCK_SIZE];
    ubyte        kek[EAPOL_KEK_SIZE];
    void*        pmkIdList;
    ubyte        pmkId[EAPOL_PMKID_LEN];
    eapolState   state;

} eapolCB;

MOC_EXTERN MSTATUS
EAPOL_generateGTK(ubyte * GMK, ubyte4 gmkLen /* 32  bytes */, ubyte *aa_mac,KeyAlgo keyAlgo,ubyte * gtk);

MOC_EXTERN MSTATUS
EAPOL_initSession(ubyte * appSessionHdl, ubyte **eapolHdl,eapolCfgParam cfgParam);

MOC_EXTERN MSTATUS
EAPOL_create1of4HandshakeReq(ubyte * eapolHdl,ubyte** ppReq,ubyte4 *pReqLen);
MOC_EXTERN MSTATUS
EAPOL_verify1of4HandshakeReq(ubyte * eapolHdl,ubyte* pPkt,ubyte4 pktLen);
MOC_EXTERN MSTATUS
EAPOL_create2of4HandshakeReq(ubyte * eapolHdl,ubyte** ppReq,ubyte4 *pReqLen);
MOC_EXTERN MSTATUS
EAPOL_verify2of4HandshakeReq(ubyte * eapolHdl,ubyte* pPkt,ubyte4 pktLen);
MOC_EXTERN MSTATUS
EAPOL_create3of4HandshakeReq(ubyte * eapolHdl,ubyte** ppReq,ubyte4 *pReqLen);
MOC_EXTERN MSTATUS
EAPOL_verify3of4HandshakeReq(ubyte * eapolHdl,ubyte* pPkt,ubyte4 pktLen);
MOC_EXTERN MSTATUS
EAPOL_create4of4HandshakeReq(ubyte * eapolHdl,ubyte** ppReq,ubyte4 *pReqLen);
MOC_EXTERN MSTATUS
EAPOL_verify4of4HandshakeReq(ubyte * eapolHdl,ubyte* pPkt,ubyte4 pktLen);
MOC_EXTERN MSTATUS
EAP1X_sendEAPOLKeyPkt (ubyte* session,ubyte** ppPkt, ubyte4 *pPktLen,ubyte *pData, ubyte4 dataLen, ubyte4 headRoom);

#endif /*defined(__ENABLE_DIGICERT_EAPOL__) */
#endif /*__EAPOL_H__*/


