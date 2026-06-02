/**
 * @file  eapol.c
 * @brief EAPOL implementation
 *
 * @details    EAP over LAN protocol
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flag must be defined in
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

#include "../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_EAPOL__))

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../crypto/hw_accel.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/mocana.h"
#include "../common/debug_console.h"
#include "../common/sizedbuffer.h"
#include "../crypto/crypto.h"
#include "../crypto/aes_keywrap.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/rsa.h"
#include "../crypto/hmac.h"
#include "../crypto/des.h"
#include "../crypto/dh.h"
#include "../crypto/rc4algo.h"
#include "../eap/eap.h"
#include "../eap/eapol.h"
#include "../eap/eap1x.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_arc4.h"
#endif

/*------------------------------------------------------------------*/

static MSTATUS
PRF_X(ubyte* secret, sbyte4 secretLen,
      ubyte* labelSeed, sbyte4 labelSeedLen,ubyte *data, ubyte4 dataLen,
      ubyte* result, sbyte4 resultLen);

static MSTATUS eapol_CalcPMKId(eapolCB *eapolCb,ubyte *pmkId);
static MSTATUS eapol_initNonce(eapolCB *eapolCb);
static MSTATUS eapol_IncByteBinary(ubyte * bArray, ubyte4 bArrayLen);
static MSTATUS eapol_derivePTK(eapolCB *eapolCb);
static MSTATUS eapol_deriveMIC(eapolCB *eapolCb,ubyte *pPkt, ubyte4 pktLen,ubyte *pMic);

/*------------------------------------------------------------------*/

static MSTATUS
EAPOL_PTK_encryptDecryptRC4(eapolKeyFrame *keyFrame, ubyte* kek, ubyte *pPkt, ubyte4 pktLen, sbyte4 encryptFlag)
{
    BulkCtx         ctx = NULL;
    hwAccelDescr    hwAccelCtx;
    ubyte           keyMaterial[EAPOL_KEY_IV_SIZE + EAPOL_KEK_SIZE];
    ubyte           discard_buffer[256];
    MSTATUS         status = OK;

    if (!keyFrame || !kek)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    DIGI_MEMCPY(keyMaterial, keyFrame->keyIV, EAPOL_KEY_IV_SIZE);
    DIGI_MEMCPY((ubyte *)(keyMaterial + EAPOL_KEY_IV_SIZE), kek, EAPOL_KEK_SIZE);

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    ctx = CRYPTO_INTERFACE_CreateRC4Ctx(MOC_SYM(hwAccelCtx) keyMaterial, EAPOL_KEY_IV_SIZE + EAPOL_KEK_SIZE, encryptFlag);
#else
    ctx = CreateRC4Ctx(MOC_SYM(hwAccelCtx) keyMaterial, EAPOL_KEY_IV_SIZE + EAPOL_KEK_SIZE, encryptFlag);
#endif
    if (NULL == ctx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* We pass a discard buffer to DoRC4, so that the first 256 bytes are discarded - pg 84 of the std*/
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_DoRC4(MOC_SYM(hwAccelCtx)ctx, discard_buffer, 256, encryptFlag, NULL)))
        goto exit;
#else
    if (OK > (status = DoRC4(MOC_SYM(hwAccelCtx)ctx, discard_buffer, 256, encryptFlag, NULL)))
        goto exit;
#endif

    /* Now pass the actual pkt to be encrypted */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_DoRC4(MOC_SYM(hwAccelCtx)ctx, pPkt, pktLen, encryptFlag, NULL)))
        goto exit;
#else
    if (OK > (status = DoRC4(MOC_SYM(hwAccelCtx)ctx, pPkt, pktLen, encryptFlag, NULL)))
        goto exit;
#endif

exit:
    if (NULL != ctx)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_DeleteRC4Ctx(MOC_SYM(hwAccelCtx) &ctx);
#else
        status = DeleteRC4Ctx(MOC_SYM(hwAccelCtx) &ctx);
#endif
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAPOL_PTK_encryptDecryptAES(eapolKeyFrame *keyFrame, ubyte* kek, ubyte *pPkt, sbyte4 pktLen, ubyte encryptFlag)
{
    hwAccelDescr    hwAccelCtx;
    ubyte*          pRetData = NULL;
    MSTATUS         status = OK;

    if (!keyFrame || !kek)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto exit;

    if (NULL == (pRetData = MALLOC(pktLen + 8)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (0 == encryptFlag)
    {
        if (OK > (status = AESKWRAP_decrypt(MOC_SYM(hwAccelCtx) kek,(sbyte4)EAPOL_KEK_SIZE,
                     pPkt, pktLen, pRetData)))
            goto exit;

        DIGI_MEMCPY(pPkt, pRetData, pktLen);
    }
    else if (1 == encryptFlag)
    {
        if (OK > (status = AESKWRAP_encrypt(MOC_SYM(hwAccelCtx) kek,(sbyte4)EAPOL_KEK_SIZE,
                     pPkt, pktLen, pRetData)))
            goto exit;

        DIGI_MEMCPY(pPkt, pRetData, pktLen + 8);
    }

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
    if (pRetData)
    {
        FREE(pRetData);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
EAPOL_create1of4HandshakeReq(ubyte * eapolHdl,ubyte** ppReq,ubyte4 *pReqLen)
{
    ubyte * pPkt    = NULL;
    ubyte4  pktLen = 0;
    eapolCB * eapolCb = (eapolCB *)eapolHdl;
    eapolKeyFrame *keyFrame;
    eapRSN_IE     *eapRSNie;
    ubyte2        pmkidLen = sizeof(eapRSN_IE) + EAPOL_PMKID_LEN;
    MSTATUS       status;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAPOL_create1of4HandshakeReq SessionHdl:",(sbyte4)((uintptr)eapolCb));

    if (NULL == eapolCb)
    {
        status = ERR_EAPOL_INVALID_HANDLE;
        goto exit;
    }

    status = eapol_initNonce(eapolCb);
    if ( OK > status)
        goto exit;

    pPkt = MALLOC(sizeof(eapolKeyFrame) + pmkidLen);

    if (NULL == pPkt)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET(pPkt,0,sizeof(eapolKeyFrame)+pmkidLen);
    pktLen = sizeof(eapolKeyFrame)+pmkidLen;

    keyFrame = (eapolKeyFrame *)pPkt;
    eapRSNie = (eapRSN_IE *) ((ubyte * )pPkt+sizeof(eapolKeyFrame))    ;

    keyFrame->keyDesc  =  eapolCb->eapolCfg.keyType;

    keyFrame->keyInfo = EAP_HTONS(eapolCb->eapolCfg.keyDesVersion | EAPOL_KEY_TYPE | EAPOL_KEY_ACK);

    keyFrame->keyLen = EAP_HTONS(eapolCb->eapolCfg.keyAlgoLen);

    status =  eapol_IncByteBinary(eapolCb->eapolCfg.keyReplayCounter, EAPOL_REPLAYCOUNTER_LEN);
    if (OK > status)
        goto exit;

    DIGI_MEMCPY(keyFrame->keyReplayCounter, eapolCb->eapolCfg.keyReplayCounter,EAPOL_REPLAYCOUNTER_LEN);

    DIGI_MEMCPY(keyFrame->keyNonce, eapolCb->ANonce,EAPOL_NONCE_LEN);

    /* These remain as 0
    ubyte     keyIV[16];
    ubyte     keyRSC[8];
    ubyte     keyMIC[EAPOL_MIC_SIZE];
    */
    keyFrame->keyDataLen = EAP_HTONS(pmkidLen);

    eapRSNie->type = EAPOL_RSN_IETYPE;
    eapRSNie->length   = sizeof(eapRSN_IE) + EAPOL_PMKID_LEN - 2;
    eapRSNie->oui[0] = EAPOL_RSN_OIU_1;
    eapRSNie->oui[1] = EAPOL_RSN_OIU_2;
    eapRSNie->oui[2] = EAPOL_RSN_OIU_3;
    eapRSNie->kde    = EAPOL_RSN_KDE_PMKID;

    status = eapol_CalcPMKId(eapolCb,eapolCb->pmkId);
    if (OK > status)
        goto exit;

    DIGI_MEMCPY((ubyte *)eapRSNie + sizeof(eapRSN_IE),eapolCb->pmkId,EAPOL_PMKID_LEN);

    eapolCb->state = EAPOL_STATE_SENT_1of4;
    *ppReq = pPkt;
    *pReqLen = pktLen;

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAPOL_createKeyRequest Status:",status);
        if (pPkt)
            FREE(pPkt);
    }
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
EAPOL_verify1of4HandshakeReq(ubyte * eapolHdl,ubyte* pPkt,ubyte4 pktLen)
{
    MSTATUS       status;
    eapolKeyFrame *keyFrame;
    eapRSN_IE     *eapRSNie;
    ubyte2        pmkidLen = sizeof(eapRSN_IE) + EAPOL_PMKID_LEN;
    ubyte         pmkId[EAPOL_PMKID_LEN];
    sbyte4        cmp;
    eapolCB*      eapolCb = (eapolCB*)eapolHdl;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAPOL_verify1of4HandshakeReq SessionHdl:",(sbyte4)((uintptr)eapolCb));

    if (NULL == eapolCb)
    {
        status = ERR_EAPOL_INVALID_HANDLE;
        goto exit;
    }

    if ( pktLen != sizeof(eapolKeyFrame)+pmkidLen)
    {
        status = ERR_EAPOL_INVALID_LEN;
        goto exit;
    }

    keyFrame = (eapolKeyFrame *)pPkt;
    eapRSNie = (eapRSN_IE *) ((ubyte * )pPkt+sizeof(eapolKeyFrame));

    if (keyFrame->keyDesc  !=  eapolCb->eapolCfg.keyType)
    {
        status = ERR_EAPOL_INVALID_PARAM;
        goto exit;
    }

    if ((EAP_NTOHS(keyFrame->keyInfo) & 0x07)  != eapolCb->eapolCfg.keyDesVersion)
    {
        status = ERR_EAPOL_INVALID_PARAM;
        goto exit;
    }

    if (!(EAP_NTOHS(keyFrame->keyInfo) & EAPOL_KEY_TYPE))
    {
        status = ERR_EAPOL_INVALID_PARAM;
        goto exit;
    }

    if (!(EAP_NTOHS(keyFrame->keyInfo) & EAPOL_KEY_ACK))
    {
        status = ERR_EAPOL_INVALID_PARAM;
        goto exit;
    }

    if (EAP_NTOHS(keyFrame->keyLen) != eapolCb->eapolCfg.keyAlgoLen)
    {
        status = ERR_EAPOL_INVALID_PARAM;
        goto exit;
    }

    DIGI_MEMCPY(eapolCb->ANonce, keyFrame->keyNonce, EAPOL_NONCE_LEN);
    DIGI_MEMCPY(pmkId,(ubyte *)eapRSNie+ sizeof(eapRSN_IE),EAPOL_PMKID_LEN);

    /* Retrive the PMKID from the received Packet */
    /* And comapre it with this .. SHoudl match. App Manages PMKSA */

    status = eapol_CalcPMKId(eapolCb,eapolCb->pmkId);
    if ( OK > status)
        goto exit;

    DIGI_MEMCMP(pmkId,eapolCb->pmkId,EAPOL_PMKID_LEN,&cmp);
    if ( 0 != cmp )
    {
        status = ERR_EAPOL_INVALID_PMKID;
        goto exit;
    }

    /* Verify that the Replay COunter is > than the current Replay Counter for this PMK ID */
    DIGI_MEMCMP(keyFrame->keyReplayCounter, eapolCb->eapolCfg.keyReplayCounter,EAPOL_REPLAYCOUNTER_LEN,&cmp);
    if (0 >= cmp)
    {
        status = ERR_EAPOL_INVALID_REPLAY_CTR;
        goto exit;
    }

    DIGI_MEMCPY(eapolCb->eapolCfg.keyReplayCounter, keyFrame->keyReplayCounter, EAPOL_REPLAYCOUNTER_LEN);

    /* Create a New SNonce */
    status = eapol_initNonce(eapolCb);
    if ( OK > status)
        goto exit;

    /* Generate PTK based upon ANonce/S Nonce */
    status = eapol_derivePTK(eapolCb);
    if ( OK > status)
        goto exit;

exit:
    /* If the status is OK , then the App shoudl send 2of4 */
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
EAPOL_create2of4HandshakeReq(ubyte * eapolHdl,ubyte** ppReq,ubyte4 *pReqLen)
{
    ubyte * pPkt    = NULL;
    ubyte4  pktLen = 0;
    eapolCB * eapolCb = (eapolCB *)eapolHdl;
    eapolKeyFrame *keyFrame;
    eapRSN_IE     *eapRSNie;
    ubyte2        rsnIELen ;
    MSTATUS       status;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAPOL_create2of4HandshakeReq SessionHdl:",(sbyte4)((uintptr)eapolCb));

    if (NULL == eapolCb)
    {
        status = ERR_EAPOL_INVALID_HANDLE;
        goto exit;

    }

    rsnIELen = eapolCb->eapolCfg.rsnIELen;

    pPkt = MALLOC(sizeof(eapolKeyFrame) + rsnIELen);

    if (NULL == pPkt)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;

    }

    pktLen = (sizeof(eapolKeyFrame) + rsnIELen);

    DIGI_MEMSET(pPkt,0,sizeof(eapolKeyFrame)+rsnIELen);

    keyFrame = (eapolKeyFrame *)pPkt;
    eapRSNie = (eapRSN_IE *) ((ubyte * )pPkt+sizeof(eapolKeyFrame))    ;


    keyFrame->keyDesc  =  eapolCb->eapolCfg.keyType;

    keyFrame->keyInfo = EAP_HTONS(eapolCb->eapolCfg.keyDesVersion | EAPOL_KEY_TYPE | EAPOL_KEY_MIC);

    keyFrame->keyLen = 0;

    DIGI_MEMCPY(keyFrame->keyReplayCounter, eapolCb->eapolCfg.keyReplayCounter,EAPOL_REPLAYCOUNTER_LEN);

    DIGI_MEMCPY(keyFrame->keyNonce, eapolCb->SNonce,EAPOL_NONCE_LEN);

    /* These remain as 0
    ubyte     keyIV[16];
    ubyte     keyRSC[8];
    */
    keyFrame->keyDataLen = EAP_HTONS(rsnIELen);

    DIGI_MEMCPY((ubyte *)pPkt+ sizeof(eapolKeyFrame),eapolCb->eapolCfg.rsnIE,rsnIELen);

    /* Calculate MIC over the Whole Frame */
    status = eapol_deriveMIC(eapolCb,pPkt, pktLen,keyFrame->keyMIC);

    *ppReq = pPkt;
    *pReqLen = pktLen;

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAPOL_create2of4HandShakeReq Status:",status);
        if (pPkt)
            FREE(pPkt);

    }
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
EAPOL_verify2of4HandshakeReq(ubyte * eapolHdl,ubyte* pPkt,ubyte4 pktLen)
{
    /* Verify the RSN IE is the as received in the Assoc Req */
    /* If Error Returns MLME_DEAUTHENTICATE Error */
    MSTATUS       status;
    eapolKeyFrame *keyFrame;
    eapRSN_IE     *eapRSNie;
    ubyte         mic[EAPOL_MIC_SIZE];
    ubyte4        rsnIELen ;
    sbyte4        cmp = 0;
    eapolCB*      eapolCb = (eapolCB *)eapolHdl;
    ubyte         mic_input[EAPOL_MIC_SIZE];

    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAPOL_verify1of4HandshakeReq SessionHdl:",(sbyte4)((uintptr)eapolCb));

    if (NULL == eapolCb)
    {
        status = ERR_EAPOL_INVALID_HANDLE;
        goto exit;
    }

    rsnIELen = eapolCb->eapolCfg.rsnIELen;

    if ( pktLen != sizeof(eapolKeyFrame)+rsnIELen)
    {
        status = ERR_EAPOL_INVALID_LEN;
        goto exit;
    }

    keyFrame = (eapolKeyFrame *)pPkt;
    eapRSNie = (eapRSN_IE *) ((ubyte * )pPkt+sizeof(eapolKeyFrame));

    if (keyFrame->keyDesc  !=  eapolCb->eapolCfg.keyType)
    {
        status = ERR_EAPOL_INVALID_PARAM;
        goto exit;
    }

    if ((EAP_NTOHS(keyFrame->keyInfo) & 0x07)  != eapolCb->eapolCfg.keyDesVersion)
    {
        status = ERR_EAPOL_INVALID_PARAM;
        goto exit;
    }

    if (!(EAP_NTOHS(keyFrame->keyInfo) & EAPOL_KEY_TYPE))
    {
        status = ERR_EAPOL_INVALID_PARAM;
        goto exit;
    }

    if (!(EAP_NTOHS(keyFrame->keyInfo) & EAPOL_KEY_MIC))
    {
        status = ERR_EAPOL_INVALID_PARAM;
        goto exit;
    }

    if (keyFrame->keyLen != 0)
    {
        status = ERR_EAPOL_INVALID_PARAM;
        goto exit;
    }

    /* Compare the RSN IE ( Asso/REAssoc IE ) That the STA sent to US. If IBSS then verify that the cipher suites are valid and can be negotiated */
    DIGI_MEMCMP((ubyte *)pPkt+ sizeof(eapolKeyFrame),eapolCb->eapolCfg.rsnIE,rsnIELen,&cmp);

    if (cmp)
    {
        /*RSN IE Does not Match */
        status = ERR_EAPOL_INVALID_RSNIE;
        goto exit;
    }

    /* Verify that the Replay COunter is = to the current Replay Counter for this */
    DIGI_MEMCMP(keyFrame->keyReplayCounter, eapolCb->eapolCfg.keyReplayCounter,EAPOL_REPLAYCOUNTER_LEN,&cmp);
    if (cmp)
    {
        status = ERR_EAPOL_INVALID_REPLAY_CTR;
        goto exit;
    }

    DIGI_MEMCPY(eapolCb->SNonce, keyFrame->keyNonce, EAPOL_NONCE_LEN);
    /* Generate PTK based upon ANonce/S Nonce */
    status = eapol_derivePTK(eapolCb);
    if ( OK > status)
        goto exit;

    DIGI_MEMCPY(mic_input, keyFrame->keyMIC, EAPOL_MIC_SIZE);
    DIGI_MEMSET(keyFrame->keyMIC, 0x00, EAPOL_MIC_SIZE);
    /* Verifies MIC sent by the Client */
    eapol_deriveMIC(eapolCb,pPkt, pktLen,mic);

    /* COmpare the received MIC over the Whole Frame */
    DIGI_MEMCMP(mic_input,mic,EAPOL_MIC_SIZE,&cmp);

    if (cmp)
    {
        status = ERR_EAPOL_INVALID_MIC;
        goto exit;
    }

exit:
    /* If the status is OK , then the App shoudl send 2of4 */
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
EAPOL_create3of4HandshakeReq(ubyte * eapolHdl,ubyte** ppReq,ubyte4 *pReqLen)
{
    ubyte * pPkt    = NULL;
    ubyte * pData   = NULL;
    ubyte * pTempData   = NULL;
    ubyte4  pktLen = 0;
    eapolCB * eapolCb = (eapolCB *)eapolHdl;
    eapolKeyFrame *keyFrame;
    eapolKeyInfo  *keyInfo;
    eapRSN_IE     *eapRSNie;
    ubyte2        pairwiseCipherLen  = 0;
    ubyte2        gtkKeyLen  = 0;
    ubyte2        rsnIELen  = 0;
    ubyte2        kdeLen;
    ubyte2        padLen = 0;
    MSTATUS       status;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAPOL_create3of4HandshakeReq SessionHdl:",(sbyte4)((uintptr)eapolCb));

    if (NULL == eapolCb)
    {
        status = ERR_EAPOL_INVALID_HANDLE;
        goto exit;
    }

    rsnIELen = eapolCb->eapolCfg.beaconRsnIELen;

    if (eapolCb->eapolCfg.pairwiseCipherLen)
        pairwiseCipherLen = eapolCb->eapolCfg.pairwiseCipherLen;
    if (eapolCb->eapolCfg.gtkKeyLen)
        gtkKeyLen = eapolCb->eapolCfg.gtkKeyLen + 6;

    /* for AES keywrap we need min 16 bytes and should be multiple of 8 bytes */
    /* Hence we need to pad the key Data Accordingly */
    kdeLen = rsnIELen + pairwiseCipherLen + gtkKeyLen;

    if (EAPOL_KEY_DESC_HMAC_SHA1_AES == eapolCb->eapolCfg.keyDesVersion)
    {
        if ( 16 > kdeLen )
            padLen = 16 - kdeLen;
        else
            padLen = 8 - (kdeLen % 8);

        padLen += 8;
    }

    pPkt = MALLOC(sizeof(eapolKeyFrame) + rsnIELen + pairwiseCipherLen + gtkKeyLen + padLen);

    if (NULL == pPkt)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;

    }

    pktLen = (sizeof(eapolKeyFrame) + rsnIELen + pairwiseCipherLen + gtkKeyLen + padLen);

    DIGI_MEMSET(pPkt,0,sizeof(eapolKeyFrame)+rsnIELen);

    keyFrame = (eapolKeyFrame *)pPkt;
    keyInfo  = (eapolKeyInfo *)&keyFrame->keyInfo;
    eapRSNie = (eapRSN_IE *) ((ubyte * )pPkt+sizeof(eapolKeyFrame));

    keyFrame->keyDesc  =  eapolCb->eapolCfg.keyType;

    keyFrame->keyInfo = EAP_HTONS(eapolCb->eapolCfg.keyDesVersion | EAPOL_KEY_TYPE | EAPOL_KEY_MIC | EAPOL_KEY_INSTALL | EAPOL_KEY_ACK | EAPOL_KEY_SECURE | EAPOL_KEY_ENCRYPT);
    keyFrame->keyLen = EAP_HTONS(eapolCb->eapolCfg.keyAlgoLen);
    status =  eapol_IncByteBinary(eapolCb->eapolCfg.keyReplayCounter, EAPOL_REPLAYCOUNTER_LEN);
    if (OK > status)
        goto exit;

    DIGI_MEMCPY(keyFrame->keyReplayCounter, eapolCb->eapolCfg.keyReplayCounter,EAPOL_REPLAYCOUNTER_LEN);
    /*Send the Same Nonce as in Message 1 */
    DIGI_MEMCPY(keyFrame->keyNonce, eapolCb->ANonce,EAPOL_NONCE_LEN);

    /* 0 (version 2 ) or Random (version 1)*/
    if ( 1 == eapolCb->eapolCfg.keyDesVersion )
    {
        /* Take the Current Global COunter and Increment it by 1 */
        DIGI_MEMCPY(keyFrame->keyIV, eapolCb->eapolCfg.keyReplayCounter + EAPOL_REPLAYCOUNTER_LEN-sizeof(keyFrame->keyIV),sizeof(keyFrame->keyIV));
        status =  eapol_IncByteBinary(keyFrame->keyIV,sizeof(keyFrame->keyIV));
        if (OK > status)
            goto exit;
    }

    /* Starting Seq# that AUth STA will use in MPDUs protected by GTK */
    eapolCb->eapolCfg.funcPtrGetSeqNum(eapolCb->appCb,keyFrame->keyRSC,8);
    /* RSN IE is the Beacon/ Probe Response Frame  + Pairwise CiperSuite Assignement or + GTK & GKT Key Identifier if group cipher negotiated*/
    keyFrame->keyDataLen = EAP_HTONS(rsnIELen+ pairwiseCipherLen+ gtkKeyLen + padLen);

    /* This Needs to be Encrypted as per 8.5.2.0 Page 84 using the KEK and KeyIV*/
    DIGI_MEMCPY((ubyte *)pPkt+ sizeof(eapolKeyFrame),eapolCb->eapolCfg.beaconRsnIE,rsnIELen);
    /* The KeyData Frame may also contain new Cipher Suites of AA and Or GTK IE*/
    if (eapolCb->eapolCfg.newPairwiseCipher)
        DIGI_MEMCPY((ubyte *)pPkt+ sizeof(eapolKeyFrame) + rsnIELen,eapolCb->eapolCfg.newPairwiseCipher,pairwiseCipherLen);

    eapRSNie = (eapRSN_IE *) ((ubyte *)pPkt+ sizeof(eapolKeyFrame) + rsnIELen + pairwiseCipherLen);
    eapRSNie->type = EAPOL_RSN_IETYPE;
    eapRSNie->length   = gtkKeyLen - 2;
    eapRSNie->oui[0] = EAPOL_RSN_OIU_1;
    eapRSNie->oui[1] = EAPOL_RSN_OIU_2;
    eapRSNie->oui[2] = EAPOL_RSN_OIU_3;
    eapRSNie->kde    = EAPOL_RSN_KDE_GTK;

    DIGI_MEMCPY(((ubyte*)(eapRSNie + 1)),eapolCb->eapolCfg.gtkKey,gtkKeyLen - 6);

    pTempData = pData = (ubyte *)pPkt+ sizeof(eapolKeyFrame) + rsnIELen + pairwiseCipherLen + gtkKeyLen;

    /* Pad the values with 0xdd,0,0,...*/
    if (padLen != 0)
    {
        padLen--;
       *pData++  = 0xdd;
       while (padLen--)
       {
          *pData++ = 0;
       }
    }

    /* AESKWRAP_encrypt  final value will be 8 bytes more*/
    if (EAPOL_KEY_DESC_HMAC_SHA1_AES == eapolCb->eapolCfg.keyDesVersion)
    {
        if (OK > (status = EAPOL_PTK_encryptDecryptAES(keyFrame, eapolCb->kek, (ubyte*)eapRSNie, EAP_NTOHS(keyFrame->keyDataLen)-8, 1)))
            goto exit;
    }
    else
    {
        if (OK > (status = EAPOL_PTK_encryptDecryptRC4(keyFrame, eapolCb->kek, (ubyte*)eapRSNie, gtkKeyLen, 1)))
            goto exit;
    }


    /* Calculate MIC over the Whole Frame */
    status = eapol_deriveMIC(eapolCb,pPkt, pktLen,keyFrame->keyMIC);

    *ppReq = pPkt;
    *pReqLen = pktLen;

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAPOL_create3of4HandShakeReq Status:",status);
        if (pPkt)
            FREE(pPkt);

    }
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
EAPOL_verify3of4HandshakeReq(ubyte * eapolHdl,ubyte* pPkt,ubyte4 pktLen)
{
    MSTATUS       status = OK;
    eapolKeyFrame *keyFrame;
    eapolKeyInfo  *keyInfo;
    eapRSN_IE     *eapRSNie;
    ubyte         mic[EAPOL_MIC_SIZE];
    ubyte4        rsnIELen ;
    sbyte4        cmp = 0;
    eapolCB*      eapolCb = (eapolCB *)eapolHdl;
    ubyte         mic_input[EAPOL_MIC_SIZE];

    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAPOL_verify3of4HandshakeReq SessionHdl:",(sbyte4)((uintptr)eapolCb));

    if (NULL == eapolCb)
    {
        status = ERR_EAPOL_INVALID_HANDLE;
        goto exit;
    }

    rsnIELen = eapolCb->eapolCfg.beaconRsnIELen;

    if ( pktLen  < sizeof(eapolKeyFrame)+rsnIELen)
    {
        status = ERR_EAPOL_INVALID_LEN;
        goto exit;
    }

    keyFrame = (eapolKeyFrame *)pPkt;
    keyInfo  = (eapolKeyInfo *)&keyFrame->keyInfo;
    eapRSNie = (eapRSN_IE *) ((ubyte * )pPkt+sizeof(eapolKeyFrame))    ;

    if (keyFrame->keyDesc  !=  eapolCb->eapolCfg.keyType)
    {
        status = ERR_EAPOL_INVALID_PARAM;
        goto exit;
    }

    if ((EAP_NTOHS(keyFrame->keyInfo) & 0x07)  != eapolCb->eapolCfg.keyDesVersion)
    {
        status = ERR_EAPOL_INVALID_PARAM;
        goto exit;
    }

    if (!(EAP_NTOHS(keyFrame->keyInfo) & EAPOL_KEY_TYPE))
    {
        status = ERR_EAPOL_INVALID_PARAM;
        goto exit;
    }

    if (!(EAP_NTOHS(keyFrame->keyInfo) & EAPOL_KEY_MIC))
    {
        status = ERR_EAPOL_INVALID_PARAM;
        goto exit;
    }

    if (keyFrame->keyLen == 0)
    {
        status = ERR_EAPOL_INVALID_PARAM;
        goto exit;
    }

    /* More RSN IE elements may be present (Pairwise Cuipher + GTK Key ) .. extract that  and verify that the the new Pairwise ciphers are valid*/

    DIGI_MEMCPY(mic_input, keyFrame->keyMIC, EAPOL_MIC_SIZE);
    DIGI_MEMSET(keyFrame->keyMIC, 0x00, EAPOL_MIC_SIZE);

    /* Verifies MIC sent by the Client */
    eapol_deriveMIC(eapolCb,pPkt, pktLen,mic);

    /* COmpare the received MIC over the Whole Frame */
    DIGI_MEMCMP(mic_input,mic,EAPOL_MIC_SIZE,&cmp);

    if (cmp)
    {
        status = ERR_EAPOL_INVALID_MIC;
        goto exit;
    }

    /* AESKWRPA_decrypt */
    if (EAPOL_KEY_DESC_HMAC_SHA1_AES == eapolCb->eapolCfg.keyDesVersion)
    {
        if (OK > (status = EAPOL_PTK_encryptDecryptAES(keyFrame, eapolCb->kek, (ubyte*)eapRSNie, EAP_NTOHS(keyFrame->keyDataLen), 0)))
            goto exit;
    }
    else
    {
        if (OK > (status = EAPOL_PTK_encryptDecryptRC4(keyFrame, eapolCb->kek, (ubyte*)eapRSNie, EAP_NTOHS(keyFrame->keyDataLen), 0)))
            goto exit;
    }

    if (EAPOL_RSN_IETYPE != eapRSNie->type)
    {
        status = ERR_EAPOL_INVALID_RSNIE;
        goto exit;
    }

    if (eapRSNie->length <= 0)
    {
        status = ERR_EAPOL_INVALID_RSNIE;
        goto exit;
    }

    if ((eapRSNie->oui[0] != EAPOL_RSN_OIU_1) || (eapRSNie->oui[1] != EAPOL_RSN_OIU_2) || (eapRSNie->oui[2] != EAPOL_RSN_OIU_3))
    {
        status = ERR_EAPOL_INVALID_RSNIE;
        goto exit;
    }

    if (eapRSNie->kde != EAPOL_RSN_KDE_GTK)
    {
        status = ERR_EAPOL_INVALID_RSNIE;
        goto exit;
    }

    /* Verify the RSN  IE is the as received in the Beacon or Probe Respo frame */
    /* Compare the RSN IE ( Asso/REAssoc IE ) That AP sent to the STA */
    DIGI_MEMCMP((ubyte *)pPkt+ sizeof(eapolKeyFrame),eapolCb->eapolCfg.beaconRsnIE,rsnIELen,&cmp);

    if (cmp)
    {
        /*RSN IE Does not Match */
        status = ERR_EAPOL_INVALID_RSNIE;
        goto exit;
    }

    /* Update the Replay Counter the current Replay Counter for this */
    DIGI_MEMCPY( eapolCb->eapolCfg.keyReplayCounter,keyFrame->keyReplayCounter,EAPOL_REPLAYCOUNTER_LEN);

    /* MLME-SETKEYs Primitive to configure the keys */
exit:

   /* If Error Returns MLME_DEAUTHENTICATE Error */
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
EAPOL_create4of4HandshakeReq(ubyte * eapolHdl,ubyte** ppReq,ubyte4 *pReqLen)
{
    ubyte * pPkt    = NULL;
    ubyte4  pktLen = 0;
    eapolCB * eapolCb = (eapolCB *)eapolHdl;
    eapolKeyFrame *keyFrame;
    eapolKeyInfo  *keyInfo;
    MSTATUS       status;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAPOL_create4of4HandshakeReq SessionHdl:",(sbyte4)((uintptr)eapolCb));

    if (NULL == eapolCb)
    {
        status = ERR_EAPOL_INVALID_HANDLE;
        goto exit;
    }

    pPkt = MALLOC(sizeof(eapolKeyFrame));

    if (NULL == pPkt)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    pktLen = (sizeof(eapolKeyFrame));

    DIGI_MEMSET(pPkt,0,sizeof(eapolKeyFrame));

    keyFrame = (eapolKeyFrame *)pPkt;
    keyInfo  = (eapolKeyInfo *)&keyFrame->keyInfo;

    keyFrame->keyDesc  =  eapolCb->eapolCfg.keyType;

    keyFrame->keyInfo = EAP_HTONS(eapolCb->eapolCfg.keyDesVersion | EAPOL_KEY_TYPE | EAPOL_KEY_ACK | EAPOL_KEY_SECURE);
    keyFrame->keyLen =  0;

    DIGI_MEMCPY(keyFrame->keyReplayCounter, eapolCb->eapolCfg.keyReplayCounter,EAPOL_REPLAYCOUNTER_LEN);

    /*keyFrame->keyNonce ; IS 0 */
    /*keyFrame->keyIV =   IS 0 */
    /* ubyte     keyRSC[8];  IS 0 */

    keyFrame->keyDataLen =  0;

    /* Calculate MIC over the Whole Frame */
    status = eapol_deriveMIC(eapolCb,pPkt, pktLen,keyFrame->keyMIC);

    *ppReq = pPkt;
    *pReqLen = pktLen;

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAPOL_create4of4HandShakeReq Status:",status);
        if (pPkt)
            FREE(pPkt);

    }
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
EAPOL_verify4of4HandshakeReq(ubyte * eapolHdl,ubyte* pPkt,ubyte4 pktLen)
{
    MSTATUS       status;
    eapolKeyFrame *keyFrame;
    eapolKeyInfo  *keyInfo;
    eapRSN_IE     *eapRSNie;
    ubyte         mic[EAPOL_MIC_SIZE];
    sbyte4        cmp = 0;
    eapolCB*      eapolCb = (eapolCB *)eapolHdl;
    ubyte         mic_input[EAPOL_MIC_SIZE];

    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAPOL_verify3of4HandshakeReq SessionHdl:",(sbyte4)((uintptr)eapolCb));

    if (NULL == eapolCb)
    {
        status = ERR_EAPOL_INVALID_HANDLE;
        goto exit;
    }

    if ( pktLen != sizeof(eapolKeyFrame))
    {
        status = ERR_EAPOL_INVALID_LEN;
        goto exit;
    }

    keyFrame = (eapolKeyFrame *)pPkt;
    keyInfo  = (eapolKeyInfo *)&keyFrame->keyInfo;
    eapRSNie = (eapRSN_IE *) ((ubyte * )pPkt+sizeof(eapolKeyFrame))    ;

    DIGI_MEMCPY(mic_input, keyFrame->keyMIC, EAPOL_MIC_SIZE);
    DIGI_MEMSET(keyFrame->keyMIC, 0x00, EAPOL_MIC_SIZE);
    /* Verifies MIC sent by the Client */
    eapol_deriveMIC(eapolCb,pPkt, pktLen,mic);

    /* COmpare the received MIC over the Whole Frame */
    DIGI_MEMCMP(mic_input,mic,EAPOL_MIC_SIZE,&cmp);

    if (cmp)
    {
        status = ERR_EAPOL_INVALID_MIC;
        goto exit;
    }

    /* Verify that the Replay COunter is = to the current Replay Counter for this */
    DIGI_MEMCMP(keyFrame->keyReplayCounter, eapolCb->eapolCfg.keyReplayCounter,EAPOL_REPLAYCOUNTER_LEN,&cmp);
    if (0 > cmp)
    {
        status = ERR_EAPOL_INVALID_REPLAY_CTR;
        goto exit;
    }
    /* Increment this for the next time*/
    status =  eapol_IncByteBinary(eapolCb->eapolCfg.keyReplayCounter, EAPOL_REPLAYCOUNTER_LEN);

    /* MLME-SETKEYs Primitive to configure the keys */
exit:

   /* If Error Returns MLME_DEAUTHENTICATE Error */
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eapol_IncByteBinary(ubyte * bArray, ubyte4 bArrayLen)
{
    MSTATUS status = OK;

    if (0 >= bArrayLen)
    {
        status = ERR_EAPOL_INVALID_ARRAY_LEN;
        goto exit;

    }

    while (bArrayLen-- )
    {
       if (++bArray[bArrayLen])
           break;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/
/* As per 8.5.8 of 802.11i */
/*PRF-256(Random number, "Init Counter", Local MAC Address || NTP Format Time)*/

static MSTATUS
eapol_initNonce(eapolCB *eapolCb)
{
    ubyte secret[32];
    sbyte4 secretLen = 32;
    ubyte  data[14];
    moctime_t ntpTime;
    ubyte  *labelSeed = (ubyte *) "Init Counter";
    MSTATUS status = OK;
    /* Page 108 from 802.11i Doc Nonce Generation*/

    RANDOM_numberGenerator(g_pRandomContext, secret, secretLen);
    /*data+6    = time_from NTP (8 bytes); FIX THIS*/
    RTOS_deltaMS(NULL,&ntpTime);
    DIGI_MEMCPY(data+6,(ubyte *)&ntpTime,sizeof(ntpTime));

    if (EAPOL_TYPE_STA == eapolCb->eapolCfg.type)
    {
        /* First 6 Bytes are the MAC Addr */
        DIGI_MEMCPY(data,eapolCb->eapolCfg.sta_mac,EAPOL_MAC_SIZE);

        PRF_X(secret, secretLen,
              labelSeed, DIGI_STRLEN((sbyte *) labelSeed),data, 14,
              eapolCb->SNonce, EAPOL_NONCE_LEN);
    }
    else
    {
        DIGI_MEMCPY(data,eapolCb->eapolCfg.aa_mac,EAPOL_MAC_SIZE);

        PRF_X(secret, secretLen,
              labelSeed, DIGI_STRLEN((sbyte *) labelSeed),data, 14,
              eapolCb->ANonce, EAPOL_NONCE_LEN);
    }

    return status;
}


/*--------------------------------------------------------------------------------*/
/* As per 8.5.1.3 of 802.11i */
/*PRF-X(GMK, "Group key expansion", AA || GNonce)*/

extern MSTATUS
EAPOL_generateGTK(ubyte * GMK, ubyte4 gmkLen /* 32  bytes */, ubyte *aa_mac,KeyAlgo keyAlgo,ubyte *gtk)
{
    ubyte  data[22];
    ubyte4 gtkSize = EAPOL_CCMP_SIZE;
    ubyte  *labelSeed = (ubyte *) "Group key expansion";
    MSTATUS status = OK;
    /* Page 76 from 802.11i Doc GTK Generation*/

    DIGI_MEMCPY(data,aa_mac,EAPOL_MAC_SIZE);
     /* GNonce generation */
    RANDOM_numberGenerator(g_pRandomContext, data+6, 16);

    if (EAPOL_CCMP_KEYALGO == keyAlgo)
        gtkSize = EAPOL_CCMP_SIZE; /* 32 for TKIP */

    status = PRF_X(GMK, gmkLen,
              labelSeed, DIGI_STRLEN((sbyte *) labelSeed),data, 22,
              gtk, gtkSize);

    return status;
}


/*--------------------------------------------------------------------------------*/

static MSTATUS
PRF_X(ubyte* secret, sbyte4 secretLen,
      ubyte* labelSeed, sbyte4 labelSeedLen,ubyte *data, ubyte4 dataLen,
      ubyte* result, sbyte4 resultLen)
{
    ubyte*          texts[4];               /* argument to HMAC_SHA1Ex */
    sbyte4          textLens[4];            /* argument to HMAC_SHA1Ex */
    ubyte           suffix[2];              /* output length + counter */
    sbyte4          numTexts;
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto exit;

    /* initialize variables for first round */
    suffix[0] = 0;
    suffix[1] = 0;

    texts[0]= labelSeed;
    textLens[0] = labelSeedLen;
    texts[1] = &suffix[0];
    textLens[1] = 1;
    texts[2] = data;
    textLens[2] = dataLen;
    texts[3] = &suffix[1];
    textLens[3] = 1;
    numTexts = 4;

    while ( resultLen >= SHA1_RESULT_SIZE)
    {
        if ( OK > (status = HMAC_SHA1Ex(MOC_HASH(hwAccelCtx) secret, secretLen,
                                            (const ubyte**)texts, textLens,
                                            numTexts, result)))
        {
            goto exit;
        }

        /* increment counters and pointers */
        ++suffix[1];
        resultLen -= SHA1_RESULT_SIZE;
        result += SHA1_RESULT_SIZE;
    }

    if ( resultLen > 0)
    {
        ubyte   temp[SHA1_RESULT_SIZE]; /* last result */
        if ( OK > (status = HMAC_SHA1Ex(MOC_HASH(hwAccelCtx) secret, secretLen,
                                            (const ubyte**)texts, textLens,
                                            numTexts, temp)))
        {
            goto exit;
        }

        DIGI_MEMCPY( result, temp, resultLen);
    }

    status = OK;
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/* PMKID = HMAC-SHA1-128(PMK,"PMK Name" || AA || STA) */
static MSTATUS
eapol_CalcPMKId(eapolCB *eapolCb,ubyte *pmkId)
{
    ubyte*          texts[3];               /* argument to HMAC_SHA1Ex */
    sbyte4          textLens[3];            /* argument to HMAC_SHA1Ex */
    sbyte4          numTexts;
    ubyte*          labelSeed = (ubyte *) "PMK Name";
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto exit;

    texts[0]= labelSeed;
    textLens[0] = DIGI_STRLEN((sbyte *) labelSeed);
    texts[1] = eapolCb->eapolCfg.aa_mac;
    textLens[1] = EAPOL_MAC_SIZE;
    texts[2] = eapolCb->eapolCfg.sta_mac;
    textLens[2] = EAPOL_MAC_SIZE;
    numTexts = 3;

    if ( OK > (status = HMAC_SHA1Ex(MOC_HASH(hwAccelCtx) eapolCb->eapolCfg.pmk, EAPOL_PMK_SIZE,
                                            (const ubyte**)texts, textLens,
                                            numTexts, pmkId)))
    {
        goto exit;
    }

    status = OK;
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
EAPOL_initSession(ubyte * appSessionHdl, ubyte **eapolHdl,eapolCfgParam cfgParam)
{
    MSTATUS status = OK;
    eapolCB * eapolCb = NULL;

    eapolCb = MALLOC(sizeof(eapolCB));

    if (NULL == eapolCb)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;

    }

    DIGI_MEMSET((ubyte *)eapolCb,0,sizeof(eapolCB));
    DIGI_MEMCPY((ubyte *)&eapolCb->eapolCfg,(ubyte *)&cfgParam,sizeof(eapolCfgParam));

    status = eapol_initNonce(eapolCb);
    if (OK > status)
        goto exit;

    eapolCb->appCb = appSessionHdl;
    *eapolHdl = (ubyte *)eapolCb;

exit:
    if (OK > status)
    {
        if (eapolCb)
            FREE(eapolCb);

    }
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eapol_derivePTK(eapolCB *eapolCb)
{
    ubyte*  labelSeed = (ubyte *) "Pairwise key expansion";
    MSTATUS status = OK;
    ubyte data[76];
    sbyte4 cmp;
    ubyte4 keySize;

    DIGI_MEMSET(data, 0x00, 76);
   /* MIN(AA,SPA) || MAX(AA,SPA) || MIN (ANONCE,SNONCE) || MAX(ANONCE,SNONCE) */
    ubyte *pData = data;

    cmp = DIGI_STRNICMP((sbyte *)eapolCb->eapolCfg.sta_mac,(sbyte *)eapolCb->eapolCfg.aa_mac ,EAPOL_MAC_SIZE);

    if (cmp <=0)
    {
        DIGI_MEMCPY(pData,eapolCb->eapolCfg.sta_mac,EAPOL_MAC_SIZE);
        pData += EAPOL_MAC_SIZE;
        DIGI_MEMCPY(pData,eapolCb->eapolCfg.aa_mac,EAPOL_MAC_SIZE);
    }
    else
    {
        DIGI_MEMCPY(pData,eapolCb->eapolCfg.aa_mac,EAPOL_MAC_SIZE);
        pData += EAPOL_MAC_SIZE;
        DIGI_MEMCPY(pData,eapolCb->eapolCfg.sta_mac,EAPOL_MAC_SIZE);
    }

    pData += EAPOL_MAC_SIZE;

    cmp = DIGI_STRNICMP((sbyte *)eapolCb->ANonce,(sbyte *)eapolCb->SNonce,EAPOL_NONCE_LEN);

    if (cmp <=0)
    {
        DIGI_MEMCPY(pData,eapolCb->ANonce,EAPOL_NONCE_LEN);
        pData += EAPOL_NONCE_LEN;
        DIGI_MEMCPY(pData,eapolCb->SNonce,EAPOL_NONCE_LEN);
    }
    else
    {
        DIGI_MEMCPY(pData,eapolCb->SNonce,EAPOL_NONCE_LEN);
        pData += EAPOL_NONCE_LEN;
        DIGI_MEMCPY(pData,eapolCb->ANonce,EAPOL_NONCE_LEN);
    }

    /* If RSNA keySize = 384, else 512 ( if using TKIP ) */
    if (eapolCb->eapolCfg.keyAlgoLen == EAPOL_TKIP_SIZE)
        keySize = 64;
    else
        keySize = 48;

    status =  PRF_X(eapolCb->eapolCfg.pmk, EAPOL_PMK_SIZE,
              labelSeed, DIGI_STRLEN((sbyte *) labelSeed),data, 76,
              eapolCb->ptk, keySize);

    if (OK > status)
        goto exit;

    /*eapol->kck = L(ptk,0,128);*/
    pData = eapolCb->ptk;
    DIGI_MEMCPY(eapolCb->kck,pData,EAPOL_KCK_SIZE);
    /*eapol->kek = L(ptk,128,128);*/
    pData+= EAPOL_KCK_SIZE;
    DIGI_MEMCPY(eapolCb->kek,pData,EAPOL_KEK_SIZE);
    pData+= EAPOL_KEK_SIZE;

    if (eapolCb->eapolCfg.keyAlgoLen == EAPOL_TKIP_SIZE)
    /*eapol->tkip = L(ptk,256,256); or*/
        DIGI_MEMCPY(eapolCb->tkip,pData,EAPOL_TKIP_SIZE);
    else
    /*eapol->ccmp = L(ptk,256,128);*/
        DIGI_MEMCPY(eapolCb->ccmp,pData,EAPOL_CCMP_SIZE);

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eapol_deriveMIC(eapolCB *eapolCb,ubyte *pPkt, ubyte4 pktLen,ubyte *pMic)
{
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status = OK;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto exit;
    if ( 1 == eapolCb->eapolCfg.keyDesVersion )
         HMAC_MD5(MOC_HASH(hwAccelCtx) (ubyte*) eapolCb->kck, EAPOL_KCK_SIZE, pPkt, pktLen, NULL, 0, pMic);
    else
    {
        ubyte pMicBuf[SHA_HASH_RESULT_SIZE];
        HMAC_SHA1(MOC_HASH(hwAccelCtx) (ubyte*) eapolCb->kck, EAPOL_KCK_SIZE, pPkt, pktLen, NULL, 0, pMicBuf);
        DIGI_MEMCPY(pMic, pMicBuf, 16);
    }
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/****f* src/eap/EAPOL_sendEAPOLKeyPkt
*
*  NAME
*   EAP1X_sendEAPOLStart
*  SYNOPSIS
*
*   #include "../eap/eap1x.h"
*   #include "../eap/eapol.h"
*
*   extern  MSTATUS
*   EAP1X_sendEAPOLkeyPkt (ubyte* session,ubyte** ppPkt, ubyte4 *pPktLen,ubyte4 headRoom)
*
*  FUNCTION
*  Called by the application to send EAPOL Key Packet
*
*  INPUTS
*    session : EAPOL Session Handle
*    ppPkt   : Pointer to returned packet formed by the function. The App is
*               responsible for freeing this packet
*    pPktLen : Length of the returned packet
*    headRoom: Length of Extra Buffer the App want to fill in the Lower Layer Header (Pkt Len includes this space)
*
*  RESULT
*   Returns an error code, or OK
*  SEE ALSO
*   src/eap/EAP1x_sendEAPOLLogoff
*   src/eap/EAP1x_sendEAPOLStart
******/

extern MSTATUS
EAP1X_sendEAPOLKeyPkt (ubyte* session,ubyte** ppPkt, ubyte4 *pPktLen,ubyte *pData, ubyte4 dataLen, ubyte4 headRoom)
{
    MSTATUS status = OK;
    ubyte *pPkt = NULL;
    eap1xHdr_t *eap1xHdr;
    eapolCB *eapSession = (eapolCB *) session;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    pPkt = MALLOC(sizeof(eap1xHdr_t)+headRoom + dataLen);

    if (NULL == pPkt)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *ppPkt = pPkt;
    eap1xHdr = (eap1xHdr_t *)((ubyte *)pPkt + headRoom);

    eap1xHdr->ethType = EAP_HTONS(EAP1X_ETH_TYPE);
    eap1xHdr->version = EAP1X_EAPOL_VERSION;
    eap1xHdr->pktType = EAP1X_EAPOL_KEY_TYPE;
    eap1xHdr->pktLen  = EAP_HTONS(dataLen);
    pPkt = (ubyte*) (eap1xHdr + 1);
    DIGI_MEMCPY(pPkt, pData, dataLen);

    *pPktLen = sizeof(eap1xHdr_t) + headRoom + dataLen;

exit:
    return status;
}


/*------------------------------------------------------------------*/
extern MSTATUS
EAPOL_llReceivePacket(ubyte *session, ubyte *pPkt, ubyte4 pktLen )
{
    MSTATUS status = OK;
    eapolCB *eapSession = (eapolCB *) session;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    if (EAPOL_TYPE_AA == eapSession->eapolCfg.type)
    {
    }

exit:
    return status;
}


#endif /*(defined(__ENABLE_DIGICERT_EAPOL__) */
