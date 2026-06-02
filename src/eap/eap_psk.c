/**
 * @file  eap_psk.c
 * @brief EAP-PSK method implementation
 *
 * @details    EAP Pre-Shared Key
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__ or \c \__ENABLE_DIGICERT_EAP_AUTH__
 *     Additionally, the following flag must be defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_PSK__
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
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))
#if defined(__ENABLE_DIGICERT_EAP_PSK__)
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/debug_console.h"
#include "../crypto/crypto.h"
#include "../crypto/blowfish.h"
#include "../crypto/aes.h"
#include "../crypto/aes_ctr.h"
#include "../crypto/aes_cmac.h"
#include "../crypto/aes_eax.h"
#include "../crypto/des.h"
#include "../crypto/three_des.h"
#include "../crypto/rc4algo.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/md4.h"
#include "../harness/harness.h"
#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_psk.h"
#include "../eap/eap_psk_pvt.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_aes.h"
#include "../crypto_interface/crypto_interface_aes_cmac.h"
#endif



static MSTATUS eap_pskCalculateMAC_S(eapPSKCb * eapPSK, ubyte *mac);
static MSTATUS eap_pskCalculateMAC_P(eapPSKCb * eapPSK, ubyte *mac);
static MSTATUS eap_pskVerifyMac_P(eapPSKCb * eapPSK,ubyte *mac) ;
static MSTATUS eap_pskVerifyMac_S(eapPSKCb * eapPSK,ubyte *mac) ;
static MSTATUS eap_pskDeriveKeys(eapPSKCb * eapPSK);
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
static MSTATUS eap_pskEAX(eapPSKCb * eapPSK,ubyte * ext,ubyte2 extLen,ubyte result_ind,ubyte * chan, ubyte2 dataLen,ubyte flag,ubyte id);
#endif
static MSTATUS eap_pskDecryptEAX(eapPSKCb * eapPSK,ubyte * data,ubyte4 dataLen,ubyte id);
static MSTATUS EAP_PSKAesCMAC(ubyte * key,ubyte2 keyLen,ubyte *encr_data,ubyte2 encrLen,ubyte *iv);
/*------------------------------------------------------------------*/
/****f* src/eap/EAP_PSKKeySetup
*
*  NAME
*   EAP_PSKKeySetup  -- Generates the AK/KDK Based upon PSK
*  SYNOPSIS
*
*   #include "../eap/eap.h"
*   #include "../eap/eap_psk.h"
*
*   extern  MSTATUS
*   EAP_PSKKeySetup (ubyte *eapPSKHdl,
*                    ubyte * psk)
*
*  FUNCTION
*  Generate AK and KDK based upon PSK for the session
*
*  INPUTS
*    eapPSKHdl     : EAP PSK Session Handle
*    psk           : Pointer to the 16 Byte PSK
*
*
*  RESULT
*   Returns an error code, or OK
*  SEE ALSO
*   src/eap/EAP_PSKInitSession
*   src/eap/EAP_PSKDeleteSession
*   src/eap/EAP_PSKRequestFirst
*   src/eap/EAP_PSKReplySecond
*   src/eap/EAP_PSKRequestThird
*   src/eap/EAP_PSKReplyFourth
******/

extern  MSTATUS
EAP_PSKKeySetup (ubyte *eapPSKHdl, ubyte *psk)
{
    eapPSKCb * eapPSK = (eapPSKCb *)eapPSKHdl;
    ubyte zero[16];
    ubyte iv[16];
    ubyte out[16];
    MSTATUS status = OK;

    if (!eapPSKHdl || !psk)
    {
        status = ERR_EAP_PSK_INVALID_PARAMS;
        goto exit;
    }

    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAP_PSKKeySetup Handle = ",(sbyte4)((uintptr)eapPSKHdl));

    DIGI_MEMSET(zero,0,16);
    DIGI_MEMSET(iv,0,16);

    status = EAP_PSKAes128(psk,16,zero,16,iv);
    if (OK > status)
        goto exit;

    DIGI_MEMCPY(out,zero,16);

    out[15] ^= 0x01;
    DIGI_MEMSET(iv,0,16);
    status = EAP_PSKAes128(psk,16,out,16,iv);
    if (OK > status)
        goto exit;
    DIGI_MEMCPY(eapPSK->ak,out,16);

    DIGI_MEMCPY(out,zero,16);
    out[15] ^= 0x02;
    DIGI_MEMSET(iv,0,16);
    status = EAP_PSKAes128(psk,16,out,16,iv);
    if (OK > status)
        goto exit;
    DIGI_MEMCPY(eapPSK->kdk,out,16);

#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "PSK is ");
    EAP_PrintBytes( psk, 16);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "AK is ");
    EAP_PrintBytes( eapPSK->ak, 16);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "KDK is ");
    EAP_PrintBytes( eapPSK->kdk, 16);
#endif

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAP_PSKKeySetup Error = ",status);

    return status;

}


/*------------------------------------------------------------------*/

extern MSTATUS
EAP_PSKAes128(ubyte * key,ubyte2 keyLen,ubyte *encr_data,ubyte2 encrLen,ubyte *iv)
{
    BulkCtx         ctx;
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status = OK;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    ctx = CRYPTO_INTERFACE_CreateAESCtx(MOC_SYM(hwAccelCtx) key, keyLen, 1);
    if(!ctx)
    {
        status = ERR_EAP_PSK_AES_CTX;
        goto exit;
    }

    status = CRYPTO_INTERFACE_DoAESEx(MOC_SYM(hwAccelCtx) ctx,
                   encr_data,encrLen,
                   1/*encrypt */, iv);

    CRYPTO_INTERFACE_DeleteAESCtx(MOC_SYM(hwAccelCtx) &ctx);
#else
    ctx = CreateAESCtx(MOC_SYM(hwAccelCtx) key, keyLen, 1);
    if(!ctx)
    {
        status = ERR_EAP_PSK_AES_CTX;
        goto exit;
    }

    status = DoAES(MOC_SYM(hwAccelCtx) ctx,
                   encr_data,encrLen,
                   1/*encrypt */, iv);

    DeleteAESCtx(MOC_SYM(hwAccelCtx) &ctx);
#endif

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
EAP_PSKAesCMAC(ubyte * key,ubyte2 keyLen,ubyte *encr_data,ubyte2 encrLen,ubyte *iv)
{
    AESCMAC_Ctx     ctx;
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status = OK;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_AESCMAC_init(MOC_SYM(hwAccelCtx) key, 16 /* 128 bit key */, &ctx);
    if (OK > status)
        goto exit;

    status = CRYPTO_INTERFACE_AESCMAC_update(MOC_SYM(hwAccelCtx) encr_data,(sbyte4) encrLen, &ctx);
    if (OK > status)
        goto exit;

    status = CRYPTO_INTERFACE_AESCMAC_final(MOC_SYM(hwAccelCtx) iv, &ctx);
    if (OK > status)
        goto exit;
#else
    status = AESCMAC_init(MOC_SYM(hwAccelCtx) key, 16 /* 128 bit key */, &ctx);
    if (OK > status)
        goto exit;

    status = AESCMAC_update(MOC_SYM(hwAccelCtx) encr_data,(sbyte4) encrLen, &ctx);
    if (OK > status)
        goto exit;

    status = AESCMAC_final(MOC_SYM(hwAccelCtx) iv, &ctx);
    if (OK > status)
        goto exit;
#endif
exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;

}

/*------------------------------------------------------------------*/
/****f* src/eap/EAP_PSKInitSession
*
*  NAME
*   EAP_PSKInitSession  -- Inits the EAP PSK Session
*  SYNOPSIS
*
*   #include "../eap/eap.h"
*   #include "../eap/eap_psk.h"
*
*   extern  MSTATUS
*   EAP_PSKInitSession (ubyte *eappSessionHdl,
*                       ubyte *eapPSKHdl,
*                       eapPSKConfig * eapPSKCfg)
*
*  FUNCTION
*  Inititializes the EAP PSK Session and Returns the EAP PSK Handle
*
*  INPUTS
*    appSessionHdl : Application Session Handle
*    eapPSKHdl     : Ptr to EAP PSK Session Handle
*    eapPSKCfg     : EAP PSK Config params like Session Type/ CallBack Func Ptr
*
*
*  RESULT
*   Returns an error code, or OK
*
*  SEE ALSO
*   src/eap/EAP_PSKDeleteSession
*   src/eap/EAP_PSKRequestFirst
*   src/eap/EAP_PSKReplySecond
*   src/eap/EAP_PSKRequestThird
*   src/eap/EAP_PSKReplyFourth
******/
/*------------------------------------------------------------------*/

extern MSTATUS
EAP_PSKInitSession(ubyte * appCb,ubyte **eapPSK, eapPSKConfig eapPSKCfg)
{
    eapPSKCb*   eapPSKTmp = MALLOC(sizeof(eapPSKCb));
    MSTATUS     status = OK;

    if (NULL == eapPSKTmp)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)eapPSKTmp,0,sizeof(eapPSKCb));

    *eapPSK = (void *) eapPSKTmp;

    /* Check a few attributes here, AUTH PEER Supported etc */
    DIGI_MEMCPY((ubyte *)&eapPSKTmp->eapPSKCfg,(ubyte *)&eapPSKCfg,sizeof(eapPSKConfig));

    if ((EAP_SESSION_TYPE_AUTHENTICATOR != eapPSKTmp->eapPSKCfg.sessionType) &&
        (EAP_SESSION_TYPE_PEER != eapPSKTmp->eapPSKCfg.sessionType))
    {
        status = ERR_EAP_PSK_INVALID_SESSION_TYPE;
        goto exit;
    }

    eapPSKTmp->appCbHdl = appCb;
    eapPSKTmp->state =  EAP_PSK_STATE_INIT;
    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAP_PSKInitSession Handle = ",(sbyte4)((uintptr)eapPSKTmp));

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAP_PSKInitSession Error ",(sbyte4)status);
        if (eapPSKTmp)
        {
            FREE(eapPSKTmp);
            *eapPSK = NULL;
        }
    }

    return status;

}

/*------------------------------------------------------------------*/
/****f* src/eap/EAP_PSKDeleteSession
*
*  NAME
*   EAP_PSKDeleteSession  -- Deletes the EAP PSK Session
*  SYNOPSIS
*
*   #include "../eap/eap.h"
*   #include "../eap/eap_psk.h"
*
*   extern  MSTATUS
*   EAP_PSKDeleteSession (ubyte *eapPSKHdl)
*
*  FUNCTION
*  Deletes the EAP PSK Session
*
*  INPUTS
*    eapPSKHdl     : Ptr to EAP PSK Session Handle
*
*
*  RESULT
*   Returns an error code, or OK
*
*  SEE ALSO
*   src/eap/EAP_PSKInitSession
*   src/eap/EAP_PSKRequestFirst
*   src/eap/EAP_PSKReplySecond
*   src/eap/EAP_PSKRequestThird
*   src/eap/EAP_PSKReplyFourth
******/
/*------------------------------------------------------------------*/

extern MSTATUS
EAP_PSKDeleteSession(ubyte *eapPSKHdl)
{
    MSTATUS status = OK;
    eapPSKCb * eapPSK  = (eapPSKCb *) eapPSKHdl;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAP_PSKDeleteSession Handle = ",(sbyte4)((uintptr)eapPSKHdl));
    if (eapPSK->id_s)
    {
        FREE(eapPSK->id_s);
        eapPSK->id_s  = NULL;
    }

    if (eapPSK->id_p)
    {
        FREE(eapPSK->id_p);
        eapPSK->id_p  = NULL;
    }

    if (eapPSK->pChan.ext)
    {
        FREE(eapPSK->pChan.ext);
        eapPSK->pChan.ext = NULL;
        eapPSK->pChan.extLen = 0;
    }

    FREE(eapPSK);

    return status;
}


/*------------------------------------------------------------------*/
/****f* src/eap/EAP_PSKAuthRequestFirst
*
*  NAME
*   EAP_PSKAuthRequestFirst  -- Forms the First Packet to be sent by the Auth
*  SYNOPSIS
*
*   #include "../eap/eap.h"
*   #include "../eap/eap_psk.h"
*
*   extern  MSTATUS
*   EAP_PSKAuthRequestFirst(ubyte * eapPSKHdl,ubyte * rand_s,
*                              ubyte * id_s, ubyte2 id_s_len,
*                              ubyte ** request,ubyte4 *requestLen)
*
*  FUNCTION
*  Forms the First Request to be sent by the Auth
*
*  INPUTS
*    eapPSKHdl     : EAP PSK Session Handle
*    rand_s        : 16 Byte Rand Generated by the Auth
*    id_s          : ID of the Auth to be sent
*    id_s_len      : ID Length
*    request       : Ptr to the buffer where the Request is Stored. App need to delete it after use
*    requestLen    : Request Buffer Length
*
*
*  RESULT
*   Returns an error code, or OK
*  SEE ALSO
*   src/eap/EAP_PSKInitSession
*   src/eap/EAP_PSKDeleteSession
*   src/eap/EAP_PSKReplySecond
*   src/eap/EAP_PSKRequestThird
*   src/eap/EAP_PSKReplyFourth
******/
/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_EAP_AUTH__)
extern MSTATUS
EAP_PSKAuthRequestFirst(ubyte * eapPSKHdl,ubyte * rand_s,
                               ubyte * id_s, ubyte2 id_s_len,
                               ubyte ** request,ubyte4 *requestLen)
{

    MSTATUS status = OK;
    eapPSKCb * eapPSK  = (eapPSKCb *) eapPSKHdl;
    ubyte4 length = EAP_PSK_FLAG_LEN + EAP_PSK_RAND_LEN + id_s_len;
    ubyte  *reqbuf = MALLOC(length);
    ubyte  *req    = reqbuf;

    if (NULL == req)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (!eapPSKHdl || !rand_s)
    {
        status = ERR_EAP_PSK_INVALID_PARAMS;
        goto exit;
    }


    if ((NULL == id_s) ||
        (0 == id_s_len))
    {
        status = ERR_EAP_PSK_INVALID_ID;
        goto exit;
    }

    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAP_PSKAuthRequestFirst Handle  ",(sbyte4)((uintptr)eapPSKHdl));
    *req++  = 0;

    DIGI_MEMCPY(req,rand_s,EAP_PSK_RAND_LEN);
    DIGI_MEMCPY(eapPSK->rand_s,rand_s,EAP_PSK_RAND_LEN);
    req+=16;

    if (eapPSK->id_s)
    {
        FREE(eapPSK->id_s);
        eapPSK->id_s = NULL;
        eapPSK->id_s_len = 0;
    }

    eapPSK->id_s = MALLOC(id_s_len);
    if(NULL == eapPSK->id_s)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    eapPSK->id_s_len = id_s_len;

    DIGI_MEMCPY(eapPSK->id_s,id_s,id_s_len);
    DIGI_MEMCPY(req,id_s,id_s_len);
    req+=id_s_len;

    *request = reqbuf;
    *requestLen = length;
    eapPSK->state = EAP_PSK_STATE_FIRST;

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAP_PSKAuthRequestFirst Error = ",status);
        if (reqbuf)
            FREE (reqbuf);

    }
    return status;

}

#endif /*defined(__ENABLE_DIGICERT_EAP_AUTH__)*/



/*------------------------------------------------------------------*/
/****f* src/eap/EAP_PSKAuthReplySecond
*
*  NAME
*   EAP_PSKAuthReplySecond  -- Forms the Second Packet to be sent by the Peer
*  SYNOPSIS
*
*   #include "../eap/eap.h"
*   #include "../eap/eap_psk.h"
*
*   extern  MSTATUS
*   EAP_PSKAuthReplySecond(ubyte * eapPSKHdl,ubyte * rand_s,
*                              ubyte * id_s, ubyte2 id_s_len,
*                              ubyte ** request,ubyte4 *requestLen)
*
*  FUNCTION
*  Forms the Second Reply to be sent by the Peer after receving the First Reques*  t from the Auth
*
*  INPUTS
*    eapPSKHdl     : EAP PSK Session Handle
*    rand_p        : 16 Byte Rand Generated by the Peer
*    id_p          : ID of the Peer to be sent
*    id_p_len      : ID Length
*    reply         : Ptr to the buffer where the Reply is Stored. App need to delete it after use
*    replytLen     : Request Buffer Length
*
*
*  RESULT
*   Returns an error code, or OK
*  SEE ALSO
*   src/eap/EAP_PSKInitSession
*   src/eap/EAP_PSKDeleteSession
*   src/eap/EAP_PSKRequestFirst
*   src/eap/EAP_PSKRequestThird
*   src/eap/EAP_PSKReplyFourth
******/
/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_EAP_PEER__)
extern MSTATUS
EAP_PSKPeerReplySecond(ubyte * eapPSKHdl,ubyte * rand_p,
                             ubyte * id_p, ubyte2 id_p_len,
                             ubyte ** reply,ubyte4 *replyLen)
{

    MSTATUS status = OK;
    eapPSKCb * eapPSK  = (eapPSKCb *) eapPSKHdl;
    ubyte4 length = EAP_PSK_FLAG_LEN + 2 * EAP_PSK_RAND_LEN + EAP_PSK_MAC_LEN + id_p_len;

    ubyte  *repbuf = MALLOC(length);
    ubyte  *rep = repbuf;

    if (NULL == rep)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (!eapPSKHdl || !rand_p)
    {
        status = ERR_EAP_PSK_INVALID_PARAMS;
        goto exit;
    }

    if ((NULL == id_p) ||
        (0 == id_p_len))
    {
        status = ERR_EAP_PSK_INVALID_ID;
        goto exit;
    }

    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAP_PSKPeerReplySecond Handle  ",(sbyte4)((uintptr)eapPSKHdl));
    *rep++  = (1 << EAP_PSK_FLAG_SHIFT) & EAP_PSK_FLAG_MASK;

    DIGI_MEMCPY(rep,eapPSK->rand_s,EAP_PSK_RAND_LEN);
    rep+=EAP_PSK_RAND_LEN;

    DIGI_MEMCPY(rep,rand_p,EAP_PSK_RAND_LEN);
    DIGI_MEMCPY(eapPSK->rand_p,rand_p,EAP_PSK_RAND_LEN);
    rep+=EAP_PSK_RAND_LEN;

    if (eapPSK->id_p)
    {
        FREE(eapPSK->id_p);
        eapPSK->id_p = NULL;
        eapPSK->id_p_len = 0;
    }

    eapPSK->id_p = MALLOC(id_p_len);
    if(NULL == eapPSK->id_p)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    eapPSK->id_p_len = id_p_len;
    DIGI_MEMCPY(eapPSK->id_p,id_p,id_p_len);

    eap_pskCalculateMAC_P(eapPSK,rep);
    rep+=EAP_PSK_MAC_LEN;

    DIGI_MEMCPY(rep,id_p,id_p_len);
    rep+=id_p_len;

    *reply = repbuf;
    *replyLen = length;
    eapPSK->state = EAP_PSK_STATE_SECOND;
exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAP_PSKPeerReplySecond Error = ",status);
        if (repbuf)
            FREE (repbuf);

    }
    return status;

}

#endif /*defined(__ENABLE_DIGICERT_EAP_PEER__)*/
/*------------------------------------------------------------------*/
/****f* src/eap/EAP_PSKAuthRequestThird
*
*  NAME
*   EAP_PSKAuthRequestThird  -- Forms the Third Request Packet to be sent by the Auth
*  SYNOPSIS
*
*   #include "../eap/eap.h"
*   #include "../eap/eap_psk.h"
*
*   extern  MSTATUS
*   EAP_PSKAuthRequestThird(ubyte * eapPSKHdl,eapPSKResultInd  resultInd,
*                              ubyte * ext, ubyte2 extLen,ubyte id,
*                              ubyte ** request,ubyte4 *requestLen)
*
*  FUNCTION
*  Forms the Third Request to be sent by the Auth after receving the Second Packet from the Peer
*
*  INPUTS
*    eapPSKHdl     : EAP PSK Session Handle
*    resultInd     : Result Indication to be sent to the Peer
*    ext           : Any EXTENSION Data to be Sent to the Peer
*    extLen        : EXTENSION Data Length
*    id            : EAP ID from the Received EAP Hdr for Calculation of Channel
*    request       : Ptr to the buffer where the Request is Stored. App need to delete it after use
*    requestLen    : Request Buffer Length
*
*
*  RESULT
*   Returns an error code, or OK
*  SEE ALSO
*   src/eap/EAP_PSKInitSession
*   src/eap/EAP_PSKDeleteSession
*   src/eap/EAP_PSKReplySecond
*   src/eap/EAP_PSKRequestThird
*   src/eap/EAP_PSKReplyFourth
******/
/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_EAP_AUTH__)
extern MSTATUS
EAP_PSKAuthRequestThird(ubyte * eapPSKHdl,eapPSKResultInd result_ind,
                             ubyte * ext, ubyte2 extLen,ubyte eapId,
                             ubyte ** request,ubyte4 *requestLen)
{

    MSTATUS status = OK;
    eapPSKCb * eapPSK  = (eapPSKCb *) eapPSKHdl;
    ubyte  channel[980];
    ubyte4 length = EAP_PSK_FLAG_LEN + EAP_PSK_RAND_LEN + EAP_PSK_MAC_LEN ;
    ubyte  flag  = (2 << EAP_PSK_FLAG_SHIFT) & EAP_PSK_FLAG_MASK;
    ubyte2  chanLen = 4 + 16 + 1 + extLen;
    ubyte  *reqbuf = NULL;
    ubyte  *req = NULL;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAP_PSKAuthRequestThird Handle  ",(sbyte4)((uintptr)eapPSKHdl));

    status = eap_pskDeriveKeys(eapPSK);
    if (OK > status)
        goto exit;


#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    status = eap_pskEAX(eapPSK,ext,extLen,result_ind,channel,length,flag,eapId);
#endif

    if (OK > status)
        goto exit;

    length+= chanLen;

    reqbuf = MALLOC(length);
    req = reqbuf;

    if (NULL == req)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *req++  = (2 << EAP_PSK_FLAG_SHIFT) & EAP_PSK_FLAG_MASK;

    DIGI_MEMCPY(req,eapPSK->rand_s,EAP_PSK_RAND_LEN);
    req+=EAP_PSK_RAND_LEN;


    eap_pskCalculateMAC_S(eapPSK,req);
    req+=EAP_PSK_MAC_LEN;

    DIGI_MEMCPY(req,channel,chanLen);
    req+=chanLen;

    *request = reqbuf;
    *requestLen = length;
    eapPSK->state = EAP_PSK_STATE_THIRD;
exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAP_PSKAuthRequestThird Error = ",status);
        if (reqbuf)
            FREE (reqbuf);

    }
    return status;

}
#endif /*defined(__ENABLE_DIGICERT_EAP_AUTH__)*/

/*------------------------------------------------------------------*/
/****f* src/eap/EAP_PSKAuthReplyFourth
*
*  NAME
*   EAP_PSKAuthReplyFourth  -- Forms the Fourth Reply Packet to be sent by the  Peer
*  SYNOPSIS
*
*   #include "../eap/eap.h"
*   #include "../eap/eap_psk.h"
*
*   extern  MSTATUS
*   EAP_PSKAuthReplyFourth(ubyte * eapPSKHdl,eapPSKResultInd  resultInd,
*                              ubyte * ext, ubyte2 extLen,ubyte id,
*                              ubyte ** reply,ubyte4 *replyLen)
*
*  FUNCTION
*  Forms the Fourth Reply to be sent by the Peer after receving the Third Packet from the Auth
*
*  INPUTS
*    eapPSKHdl     : EAP PSK Session Handle
*    resultInd     : Result Indication to be sent to the Auth
*    ext           : Any EXTENSION Data to be Sent to the AUth
*    extLen        : EXTENSION Data Length
*    id            : EAP ID from the Received EAP Hdr for Calculation of Channel
*    reply         : Ptr to the buffer where the Reply is Stored. App needs to delete it after use
*    replyLen      : Reply Buffer Length
*
*
*  RESULT
*   Returns an error code, or OK
*  SEE ALSO
*   src/eap/EAP_PSKInitSession
*   src/eap/EAP_PSKDeleteSession
*   src/eap/EAP_PSKRequestFirst
*   src/eap/EAP_PSKReplySecond
*   src/eap/EAP_PSKRequestThird
*   src/eap/EAP_PSKReplyFourth
******/
/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_EAP_PEER__)
extern MSTATUS
EAP_PSKPeerReplyFourth(ubyte * eapPSKHdl,eapPSKResultInd result_ind,
                             ubyte * ext, ubyte2 extLen,ubyte eapId,
                             ubyte ** reply,ubyte4 *replyLen)
{

    eapPSKCb * eapPSK  = (eapPSKCb *) eapPSKHdl;
    ubyte4 length = EAP_PSK_FLAG_LEN + EAP_PSK_RAND_LEN ;
    ubyte flag    = (3 << EAP_PSK_FLAG_SHIFT) & EAP_PSK_FLAG_MASK;
    ubyte2  chanLen = 4 + 16 + 1 + extLen;
    ubyte  channel[980];
    ubyte  *repbuf = NULL ;
    ubyte  *rep  = NULL;
    MSTATUS status = OK;


    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAP_PSKPeerReplyFourth Handle  ",(sbyte4)((uintptr)eapPSKHdl));

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    status = eap_pskEAX(eapPSK,ext,extLen,result_ind,channel,length,flag,eapId);
    if (OK > status)
        goto exit;
#endif

    length+= chanLen;
    repbuf = MALLOC(length);
    rep = repbuf;

    if (NULL == rep)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *rep++  = (3 << EAP_PSK_FLAG_SHIFT) & EAP_PSK_FLAG_MASK;

    DIGI_MEMCPY(rep,eapPSK->rand_s,EAP_PSK_RAND_LEN);
    rep+=EAP_PSK_RAND_LEN;


    DIGI_MEMCPY(rep,channel,chanLen);
    rep+=chanLen;

    *reply = repbuf;
    *replyLen = length;
    eapPSK->state = EAP_PSK_STATE_THIRD;
exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAP_PSKPeerReplyFourth Error = ",status);
        if (repbuf)
            FREE (repbuf);

    }
    return status;

}
#endif /*defined(__ENABLE_DIGICERT_EAP_PEER__)*/


/*------------------------------------------------------------------*/
/****f* src/eap/EAP_PSKProcessMsg
*
*  NAME
*   EAP_PSKProcessMsg  -- Processes the Incoming EAP PSK Data Msg
*  SYNOPSIS
*
*   #include "../eap/eap.h"
*   #include "../eap/eap_psk.h"
*
*   extern  MSTATUS
*   EAP_PSKProcessMsg(ubyte * eapPSKHdl,
*                    ubyte * data, ubyte4 len,ubyte id)
*
*  FUNCTION
*  Processes the Incoming EAP PSK Msg and Verifies the Responses and Informs the App about the State Change and Status
*
*  INPUTS
*    eapPSKHdl     : EAP PSK Session Handle
*    data          : Incoming PSK Data
*    len           : EXTENSION Data Length
*    id            : EAP ID from the Received EAP Hdr for Calculation of Channel
*
*
*  RESULT
*   Returns an error code, or OK
*  SEE ALSO
*   src/eap/EAP_PSKInitSession
*   src/eap/EAP_PSKDeleteSession
*   src/eap/EAP_PSKReplySecond
*   src/eap/EAP_PSKRequestThird
*   src/eap/EAP_PSKReplyFourth
******/
/*------------------------------------------------------------------*/

extern MSTATUS
EAP_PSKProcessMsg(ubyte * eapPSKHdl,ubyte * data,
                         ubyte4 dataLen,ubyte id)
{

    MSTATUS status = OK;
    eapPSKCb * eapPSK  = (eapPSKCb *) eapPSKHdl;
    ubyte flag;
    sbyte4 cmp;

    if (!eapPSKHdl || !data)
    {
        status = ERR_EAP_PSK_INVALID_PARAMS;
        goto exit;
    }

    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAP_PSKProcessMsg Handle = ",(sbyte4)((uintptr)eapPSKHdl));
    if (eapPSK->pChan.ext)
    {
        FREE(eapPSK->pChan.ext);
        eapPSK->pChan.ext = NULL;
        eapPSK->pChan.extLen = 0;
    }

    /* Store the Incoming DataLen to be used with EAX Decrypt */
    eapPSK->inDataLen = dataLen;
    /* PEER */
    if (EAP_SESSION_TYPE_PEER == eapPSK->eapPSKCfg.sessionType)
    {

        DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAP_PSKProcessMsg Peer State ",(sbyte4)eapPSK->state);
        switch(eapPSK->state)
        {
         case EAP_PSK_STATE_INIT:
             /* 1 Byte Type, 1 Byte  Flag, 16 Byte Rand, atleast 1 Byte Id_s */
             if (19 > dataLen)
             {
                 status = ERR_EAP_PSK_INVALID_LENGTH;
                 goto exit;
             }

             flag = *(data+1);

             if (0 != flag)
             {
                 status = ERR_EAP_PSK_INVALID_FLAG;
                 goto exit;
             }

             eapPSK->inFlag = flag;
             DIGI_MEMCPY(eapPSK->rand_s,data+2,EAP_PSK_RAND_LEN);
             if (eapPSK->id_s)
             {
                 FREE(eapPSK->id_s);
                 eapPSK->id_s = NULL;
                 eapPSK->id_s_len = 0;
             }

             eapPSK->id_s = MALLOC(dataLen-18);
             if(NULL == eapPSK->id_s)
             {
                 status = ERR_MEM_ALLOC_FAIL;
                 goto exit;
             }

             eapPSK->id_s_len = dataLen-18;

             DIGI_MEMCPY(eapPSK->id_s,data+18,dataLen-18);

             status = eapPSK->eapPSKCfg.functionPtrEvtCallback(eapPSK->appCbHdl,
                                                               (ubyte *)eapPSK,
                                                      EAP_PSK_EVT_RECV_FIRST_PKT);
             break;
         case EAP_PSK_STATE_SECOND:
             /* 1 Byte Type, 1 Byte  Flag, 16 Byte Rand, 16 Byte MAC , atleast 20 Byte PChannel */
             if (54 > dataLen)
             {
                 status = ERR_EAP_PSK_INVALID_LENGTH;
                 goto exit;
             }

             flag = *(data+1);

             if (2 != (flag & EAP_PSK_FLAG_MASK)>> EAP_PSK_FLAG_SHIFT)
             {
                 status = ERR_EAP_PSK_INVALID_FLAG;
                 goto exit;
             }

             eapPSK->inFlag = flag;

             DIGI_MEMCMP(eapPSK->rand_s,data+2,EAP_PSK_RAND_LEN,&cmp);
             if(cmp)
             {
                 status = ERR_EAP_PSK_INVALID_RAND;
                 goto exit;
             }
             status = eap_pskVerifyMac_S(eapPSK,data+18);

             if (OK > status)
             {
                 status = ERR_EAP_PSK_INVALID_MAC;
                 goto exit;
             }

             status = eap_pskDeriveKeys(eapPSK);
             if (OK > status)
                 goto exit;

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
             status = eap_pskDecryptEAX(eapPSK,data+34,dataLen-34,id);
             if (OK > status)
             {
                 status = ERR_EAP_PSK_INVALID_CHAN;
                 goto exit;
             }
#endif

             if (( 0 == eapPSK->pChan.extLen) && (eapPSK->pChan.extensionBit))
             {
                 status = ERR_EAP_PSK_INVALID_EXT;
                 goto exit;
             }


             status = eapPSK->eapPSKCfg.functionPtrEvtCallback(eapPSK->appCbHdl,
                                                               (ubyte *)eapPSK,
                                                          EAP_PSK_EVT_RECV_THIRD_PKT);

             break;
         case EAP_PSK_STATE_EXT:
             /* 1 Byte Type, 1 Byte  Flag, 16 Byte Rand, atleast 20 Byte PChannel */
             if (38 > dataLen)
             {
                 status = ERR_EAP_PSK_INVALID_LENGTH;
                 goto exit;
             }

             flag = *(data+1);

             if (3 != ((flag & EAP_PSK_FLAG_MASK)>> EAP_PSK_FLAG_SHIFT))
             {
                 status = ERR_EAP_PSK_INVALID_FLAG;
                 goto exit;
             }

             eapPSK->inFlag = flag;

             DIGI_MEMCMP(eapPSK->rand_s,data+2,EAP_PSK_RAND_LEN,&cmp);
             if(cmp)
             {
                 status = ERR_EAP_PSK_INVALID_RAND;
                 goto exit;
             }

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
             status = eap_pskDecryptEAX(eapPSK,data+18,dataLen-18,id);
             if (OK > status)
             {
                 status = ERR_EAP_PSK_INVALID_CHAN;
                 goto exit;
             }
#endif

             if (( 0 == eapPSK->pChan.extLen) && (eapPSK->pChan.extensionBit))
             {
                 status = ERR_EAP_PSK_INVALID_EXT;
                 goto exit;
             }

             status = eapPSK->eapPSKCfg.functionPtrEvtCallback(eapPSK->appCbHdl,
                                                               (ubyte *)eapPSK,
                                                          EAP_PSK_EVT_RECV_EXT_PKT);
             break;
         default:
                 status = ERR_EAP_PSK_INVALID_PKT;
                 goto exit;
             break;
        }

    }
    else
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAP_PSKProcessMsg Auth State ",(sbyte4)eapPSK->state);
        switch(eapPSK->state)
        {
         case EAP_PSK_STATE_FIRST:
             /* 1 Byte Type, 1 Byte  Flag, 16 Byte Rand_s, 16 Byte Rand_p ,16 Byte MAC_p ,atleast 1 Byte Id_s */
             if (51 > dataLen)
             {
                 status = ERR_EAP_PSK_INVALID_LENGTH;
                 goto exit;
             }

             flag = *(data+1);

             if (1 != ((flag & EAP_PSK_FLAG_MASK)>> EAP_PSK_FLAG_SHIFT))
             {
                 status = ERR_EAP_PSK_INVALID_FLAG;
                 goto exit;
             }

             eapPSK->inFlag = flag;

             DIGI_MEMCMP(eapPSK->rand_s,data+2,EAP_PSK_RAND_LEN,&cmp);
             if(cmp)
             {
                 status = ERR_EAP_PSK_INVALID_RAND;
                 goto exit;
             }

             DIGI_MEMCPY(eapPSK->rand_p,data+18,EAP_PSK_RAND_LEN);
             if (eapPSK->id_p)
             {
                 FREE(eapPSK->id_p);
                 eapPSK->id_p = NULL;
                 eapPSK->id_p_len = 0;
             }

             eapPSK->id_p = MALLOC(dataLen-50);
             if(NULL == eapPSK->id_p)
             {
                 status = ERR_MEM_ALLOC_FAIL;
                 goto exit;
             }

             eapPSK->id_p_len = dataLen-50;

             DIGI_MEMCPY(eapPSK->id_p,data+50,dataLen-50);

             status = eapPSK->eapPSKCfg.functionPtrEvtCallback(eapPSK->appCbHdl,
                                                               (ubyte *)eapPSK,
                                                      EAP_PSK_EVT_RECV_SECOND_PKT);

             status = eap_pskVerifyMac_P(eapPSK,data+34);

             if (OK > status)
             {
                 status = ERR_EAP_PSK_INVALID_MAC;
                 goto exit;
             }

             break;
         case EAP_PSK_STATE_THIRD:
             /* 1 Byte Type, 1 Byte  Flag, 16 Byte Rand, atleast 20 Byte PChannel */
             if (38 > dataLen)
             {
                 status = ERR_EAP_PSK_INVALID_LENGTH;
                 goto exit;
             }

             flag = *(data+1);

             if (3 != ((flag & EAP_PSK_FLAG_MASK)>> EAP_PSK_FLAG_SHIFT))
             {
                 status = ERR_EAP_PSK_INVALID_FLAG;
                 goto exit;
             }

             eapPSK->inFlag = flag;

             DIGI_MEMCMP(eapPSK->rand_s,data+2,EAP_PSK_RAND_LEN,&cmp);
             if(cmp)
             {
                 status = ERR_EAP_PSK_INVALID_RAND;
                 goto exit;
             }

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
             status = eap_pskDecryptEAX(eapPSK,data+18,dataLen-18,id);
             if (OK > status)
             {
                 status = ERR_EAP_PSK_INVALID_CHAN;
                 goto exit;
             }
#endif

             if (( 0 == eapPSK->pChan.extLen) && (eapPSK->pChan.extensionBit))
             {
                 status = ERR_EAP_PSK_INVALID_EXT;
                 goto exit;
             }

             status = eapPSK->eapPSKCfg.functionPtrEvtCallback(eapPSK->appCbHdl,
                                                               (ubyte *)eapPSK,
                                                          EAP_PSK_EVT_RECV_FOURTH_PKT);
             break;
         case EAP_PSK_STATE_EXT:
             /* 1 Byte Type, 1 Byte  Flag, 16 Byte Rand, atleast 20 Byte PChannel */
             if (38 > dataLen)
             {
                 status = ERR_EAP_PSK_INVALID_LENGTH;
                 goto exit;
             }

             flag = *(data+1);

             if (3 != ((flag & EAP_PSK_FLAG_MASK)>> EAP_PSK_FLAG_SHIFT))
             {
                 status = ERR_EAP_PSK_INVALID_FLAG;
                 goto exit;
             }

             eapPSK->inFlag = flag;

             DIGI_MEMCMP(eapPSK->rand_s,data+2,EAP_PSK_RAND_LEN,&cmp);
             if(cmp)
             {
                 status = ERR_EAP_PSK_INVALID_RAND;
                 goto exit;
             }

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
             status = eap_pskDecryptEAX(eapPSK,data+18,dataLen-18,id);
             if (OK > status)
             {
                 status = ERR_EAP_PSK_INVALID_CHAN;
                 goto exit;
             }
#endif

             if (( 0 == eapPSK->pChan.extLen) && (eapPSK->pChan.extensionBit))
             {
                 status = ERR_EAP_PSK_INVALID_EXT;
                 goto exit;
             }

             status = eapPSK->eapPSKCfg.functionPtrEvtCallback(eapPSK->appCbHdl,
                                                               (ubyte *)eapPSK,
                                                          EAP_PSK_EVT_RECV_FOURTH_PKT);
             break;
         default:
                 status = ERR_EAP_PSK_INVALID_PKT;
                 goto exit;
             break;
        }
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAP_PSKProcessMsg Error = ",status);

    return status;
}


/*------------------------------------------------------------------*/


static MSTATUS
eap_pskCalculateMAC_P(eapPSKCb * eapPSK, ubyte *mac)
{

   /* MAC_P = CMAC-AES-128(AK, ID_P||ID_S||RAND_S||RAND_P) */
    ubyte input[512];
    ubyte *pInput = input;
    ubyte4 length = eapPSK->id_s_len+eapPSK->id_p_len+2*EAP_PSK_RAND_LEN;
    MSTATUS status = OK;

    DIGI_MEMCPY(pInput,eapPSK->id_p,eapPSK->id_p_len);
    pInput+=eapPSK->id_p_len;
    DIGI_MEMCPY(pInput,eapPSK->id_s,eapPSK->id_s_len);
    pInput+=eapPSK->id_s_len;
    DIGI_MEMCPY(pInput,eapPSK->rand_s,EAP_PSK_RAND_LEN);
    pInput+=EAP_PSK_RAND_LEN;
    DIGI_MEMCPY(pInput,eapPSK->rand_p,EAP_PSK_RAND_LEN);
    pInput+=EAP_PSK_RAND_LEN;


#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    status = EAP_PSKAesCMAC ( eapPSK->ak,128, input, length, mac );
    if (OK > status)
        goto exit;
#endif
#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"ID_P is: Length= ",eapPSK->id_p_len);
    EAP_PrintBytes( eapPSK->id_p, eapPSK->id_p_len);
    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"ID_S is: Length= ",eapPSK->id_s_len);
    EAP_PrintBytes( eapPSK->id_s, eapPSK->id_s_len);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RAND_S is: ");
    EAP_PrintBytes( eapPSK->rand_s, 16);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RAND_P is: ");
    EAP_PrintBytes( eapPSK->rand_p, 16);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "MAC is: ");
    EAP_PrintBytes( mac, 16);
#endif
exit:
    return status;

}


/*------------------------------------------------------------------*/


static MSTATUS
eap_pskCalculateMAC_S(eapPSKCb * eapPSK, ubyte *mac)
{

    /*MAC_S = CMAC-AES-128(AK, ID_S||RAND_P)*/
    ubyte input[512];
    ubyte *pInput = input;
    ubyte4 length = eapPSK->id_s_len+EAP_PSK_RAND_LEN;
    MSTATUS status = OK;

    DIGI_MEMCPY(pInput,eapPSK->id_s,eapPSK->id_s_len);
    pInput+=eapPSK->id_s_len;
    DIGI_MEMCPY(pInput,eapPSK->rand_p,EAP_PSK_RAND_LEN);
    pInput+=EAP_PSK_RAND_LEN;

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    status = EAP_PSKAesCMAC ( eapPSK->ak, 128, input, length, mac );
    if (OK > status)
        goto exit;
#endif
#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"ID_S is: Length= ",eapPSK->id_s_len);
    EAP_PrintBytes( eapPSK->id_s, eapPSK->id_s_len);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RAND_P is: ");
    EAP_PrintBytes( eapPSK->rand_p, 16);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "MAC is: ");
    EAP_PrintBytes( mac, 16);
#endif
exit:
    return status;

}

/*------------------------------------------------------------------*/


static MSTATUS
eap_pskVerifyMac_S(eapPSKCb * eapPSK,ubyte *mac)
{

    ubyte mac_s[EAP_PSK_MAC_LEN];
    sbyte4 cmp =0;
    MSTATUS status = OK;
    status = eap_pskCalculateMAC_S(eapPSK, mac_s);
    if (OK > status)
        goto exit;

    DIGI_MEMCMP(mac,mac_s,EAP_PSK_MAC_LEN,&cmp);

    if (cmp)
    {
        status =  ERR_EAP_PSK_INVALID_MAC;
        goto exit;
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/


static MSTATUS
eap_pskVerifyMac_P(eapPSKCb * eapPSK,ubyte *mac)
{

    ubyte mac_p[EAP_PSK_MAC_LEN];
    sbyte4 cmp =0;
    MSTATUS status = OK;

    status = eap_pskCalculateMAC_P(eapPSK, mac_p);
    if (OK > status)
        goto exit;

    DIGI_MEMCMP(mac,mac_p,EAP_PSK_MAC_LEN,&cmp);

    if (cmp)
    {
        status =  ERR_EAP_PSK_INVALID_MAC;
        goto exit;
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/


static MSTATUS
eap_pskDeriveKeys(eapPSKCb * eapPSK)
{
    ubyte iv[16];
    ubyte out[16];
    ubyte output[16];
    ubyte i,j=0;
    MSTATUS status = OK;

    DIGI_MEMSET(iv,0,sizeof(iv));
    DIGI_MEMCPY(out,eapPSK->rand_p,16);

    status = EAP_PSKAes128(eapPSK->kdk,16,out,16,iv);
    if (OK > status)
        goto exit;

    DIGI_MEMCPY(output,out,16);
    output[15] ^= 0x01;
    DIGI_MEMSET(iv,0,sizeof(iv));
    status = EAP_PSKAes128(eapPSK->kdk,16,output,16,iv);
    if (OK > status)
        goto exit;
    DIGI_MEMCPY(eapPSK->tek,output,16);


    for (i=0x02;i<0x06;i++) {
        DIGI_MEMCPY(output,out,16);
        output[15] ^= i;
        DIGI_MEMSET(iv,0,sizeof(iv));
        status = EAP_PSKAes128(eapPSK->kdk,16,output,16,iv);
        if (OK > status)
            goto exit;
        DIGI_MEMCPY(eapPSK->msk+16*j++,output,16);
    }


    j =0;

    for (i=0x06;i<0x0A;i++) {
        DIGI_MEMCPY(output,out,16);
        output[15] ^= i;
        DIGI_MEMSET(iv,0,sizeof(iv));
        status = EAP_PSKAes128(eapPSK->kdk,16,output,16,iv);
        if (OK > status)
            goto exit;
        DIGI_MEMCPY(eapPSK->emsk+16*j++,output,16);
    }

#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "TEK is ");
    EAP_PrintBytes( eapPSK->tek, 16);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "MSK is ");
    EAP_PrintBytes( eapPSK->msk, 64);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "EMSK is ");
    EAP_PrintBytes( eapPSK->emsk, 64);
#endif
exit:
    return status;

}

/*------------------------------------------------------------------*/


#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
static MSTATUS
eap_pskEAX(eapPSKCb * eapPSK,ubyte * ext,ubyte2 extLen,ubyte result_ind,ubyte *channel,ubyte2 dataLen,ubyte flag,ubyte id)
{

    AES_EAX_Ctx     Ctx;
    eapPSKHdr       eaxHdr;
    ubyte2          chanLen;
    ubyte           extBit = 0;
    ubyte4          value;
    ubyte           nonce[16];
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status = OK;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    if ( 980 < extLen)
    {
        status = ERR_EAP_PSK_INVALID_CHAN_LEN;
        goto exit;
    }

    DIGI_MEMSET(nonce,0,16);

    /* Recreate the EAP Hdr */
    if (EAP_SESSION_TYPE_PEER == eapPSK->eapPSKCfg.sessionType)
        eaxHdr.eapHdr.code = EAP_CODE_RESPONSE;
    else
        eaxHdr.eapHdr.code = EAP_CODE_REQUEST;
    eaxHdr.eapHdr.id   = id;
    eaxHdr.eapHdr.len  = EAP_HTONS(dataLen + extLen + 21/* PChan Nonce/Tag/flag*/ + 4 + 1/*EAP Hdr Len + Flag*/);

    eaxHdr.eapType        = EAP_TYPE_PSK;
    eaxHdr.flag        = flag;

    DIGI_MEMCPY(eaxHdr.rand_s,eapPSK->rand_s,EAP_PSK_RAND_LEN);

    value = EAP_HTONL(eapPSK->nonce);
    DIGI_MEMCPY(channel, (ubyte *)&value,4);
    DIGI_MEMCPY(nonce+12, (ubyte *)&value,4);

#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAX ID  is ",id);
    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAX EAP LEN  is ",eaxHdr.eapHdr.len);
    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAX Flag  is ",eaxHdr.flag);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "NONCE is ");
    EAP_PrintBytes( channel, 4);
#endif

    eapPSK->nonce++;

    if (ext && extLen)
    {
        DIGI_MEMCPY(channel+21, ext,extLen);
        extBit = (1 << EAP_PSK_EBIT_SHIFT ) & EAP_PSK_EXT_MASK;
    }
    chanLen = 4 + 16 + 1 + extLen;


    *(channel + 20) = (ubyte ) (((result_ind << EAP_PSK_RESULT_IND_SHIFT ) & EAP_PSK_RESULT_IND_MASK) | extBit);

#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "TEK is ");
    EAP_PrintBytes( eapPSK->tek, 16);
#endif

    status = AES_EAX_init(MOC_SYM(hwAccelCtx) eapPSK->tek,
                                16,
                                nonce,
                                16,
                                &Ctx);

    if (OK > status)
        goto exit;

    status = AES_EAX_updateHeader(MOC_SYM(hwAccelCtx) (const ubyte *) &eaxHdr,
                                    sizeof(eaxHdr),
                                    &Ctx);
    if (OK > status)
        goto exit;

    status =  AES_EAX_encryptMessage(MOC_SYM(hwAccelCtx) channel+20,
                                     chanLen -20 , &Ctx);
    if (OK > status)
        goto exit;

#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Chan Msg is ");
    EAP_PrintBytes( channel + 20,chanLen - 20);
#endif

    status =  AES_EAX_final(MOC_SYM(hwAccelCtx) channel+4,
                                    EAP_PSK_TAG_LEN, &Ctx);
    if (OK > status)
        goto exit;

#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Generated Tag is ");
    EAP_PrintBytes( channel + 4,EAP_PSK_TAG_LEN);
#endif

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;

}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__ */

/*------------------------------------------------------------------*/


#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
static MSTATUS
eap_pskDecryptEAX(eapPSKCb * eapPSK,ubyte * data,ubyte4 dataLen,ubyte id)
{
    AES_EAX_Ctx     Ctx;
    eapPSKHdr       eaxHdr;
    sbyte4          cmp;
    ubyte           tag[EAP_PSK_TAG_LEN];
    ubyte4          encrDataLen = dataLen - 20;
    ubyte*          encrData;
    ubyte4          value;
    ubyte           nonce[16];
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status = OK;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    if (1 > encrDataLen || 980 < encrDataLen )
    {
        status = ERR_EAP_PSK_INVALID_CHAN_LEN;
        goto exit;
    }

    DIGI_MEMSET(nonce,0,16);

    /* Replay Protection */

    DIGI_MEMCPY((ubyte *)&value,data,4);
    /* Padding Initial 96 Bits with 0  */
    DIGI_MEMCPY((ubyte *)nonce+12,data,4);

    value = EAP_HTONL(value);

    if (eapPSK->nonce != value)
    {
        status = ERR_EAP_PSK_INVALID_NONCE;
        goto exit;
    }

    eapPSK->nonce++;

    /* Recreate the EAP Hdr */
    if (EAP_SESSION_TYPE_PEER == eapPSK->eapPSKCfg.sessionType)
        eaxHdr.eapHdr.code = EAP_CODE_REQUEST;
    else
        eaxHdr.eapHdr.code = EAP_CODE_RESPONSE;
    eaxHdr.eapHdr.id   = id;
    eaxHdr.eapHdr.len  = EAP_HTONS(eapPSK->inDataLen + 4);

    eaxHdr.eapType     = EAP_TYPE_PSK;
    eaxHdr.flag        = eapPSK->inFlag;


    DIGI_MEMCPY(eaxHdr.rand_s,eapPSK->rand_s,EAP_PSK_RAND_LEN);

    encrData = data + 20 ; /* 4 Bytes Nonce + 16 Bytes TAG + Encr Data */

#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"Nonce is ",value);
    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAX EAP Len ",eaxHdr.eapHdr.len);
    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"Id is ",id);
    DEBUG_ERROR(DEBUG_EAP_MESSAGE,"EAX Flag ",eaxHdr.flag);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "ENCr Data is ");
    EAP_PrintBytes( encrData, encrDataLen);

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "TEK is ");
    EAP_PrintBytes( eapPSK->tek, 16);
#endif

    status = AES_EAX_init(MOC_SYM(hwAccelCtx) eapPSK->tek,
                                16,
                                nonce,/* 16 Byte Nonce */
                                16,
                                &Ctx);

    if (OK > status)
        goto exit;

    status =  AES_EAX_generateTag(MOC_SYM(hwAccelCtx)
                                   encrData, (sbyte4)encrDataLen,
                                   (ubyte *)&eaxHdr, sizeof(eaxHdr),
                                   tag, EAP_PSK_TAG_LEN,
                                   &Ctx);

    if (OK > status)
        goto exit;
#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Tag is ");
    EAP_PrintBytes( tag,EAP_PSK_TAG_LEN);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Incoming Tag is ");
    EAP_PrintBytes( data+ 4,EAP_PSK_TAG_LEN);
#endif
    /* Compare the incoming Tag */
    DIGI_MEMCMP(tag,data+4/* Incoming Tag */,EAP_PSK_TAG_LEN,&cmp);

    if (cmp)
    {
        status = ERR_EAP_PSK_INVALID_TAG;
        goto exit;
    }

    status =  AES_EAX_getPlainText(MOC_SYM(hwAccelCtx)
                                    encrData, encrDataLen,
                                    &Ctx);

    if (OK > status)
        goto exit;

    if (1 == encrDataLen)
    {
    /* Only the 1 Byte Pchan Hdr Sent */

        eapPSK->pChan.extLen = 0;
        eapPSK->pChan.resultInd = (*(data + 20 ) >> EAP_PSK_RESULT_IND_SHIFT ) & 0x3;
        /* This should be 0*/
        eapPSK->pChan.extensionBit    = (*(data + 20 ) >> EAP_PSK_EBIT_SHIFT ) & 0x1;

        if (0 != eapPSK->pChan.extensionBit)
        {
            status = ERR_EAP_PSK_INVALID_EXT;
            goto exit;
        }
    }
    else
    {

        eapPSK->pChan.extLen = encrDataLen - 1;
        eapPSK->pChan.resultInd = (*(data + 20 ) >> EAP_PSK_RESULT_IND_SHIFT ) & 0x3;
        /* This should be 1*/
        eapPSK->pChan.extensionBit    = (*(data + 20 ) >> EAP_PSK_EBIT_SHIFT ) & 0x1;

        if (0 == eapPSK->pChan.extensionBit)
        {
            /* This would indicate that the other side does not support E Bit*/
            /* Its just returning the E Bit data that we sent earlier */
            status = ERR_EAP_PSK_INVALID_EXT;
            goto exit;
        }

        if (eapPSK->pChan.ext)
        {
            FREE(eapPSK->pChan.ext);
            eapPSK->pChan.ext = NULL;
        }

        eapPSK->pChan.ext = MALLOC(dataLen -20 - 1);
        if (!eapPSK->pChan.ext)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMCPY(eapPSK->pChan.ext,encrData + 1,encrDataLen - 1);

    }

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;

}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__ */

/*------------------------------------------------------------------*/
/****f* src/eap/EAP_PSKgetKeys
*
*  NAME
*   EAP_PSKgetKeys  -- Returns the Session Keys generated
*  SYNOPSIS
*
*   #include "../eap/eap.h"
*   #include "../eap/eap_psk.h"
*
*   extern  MSTATUS
*   EAP_PSKgetkeys(ubyte * eapPSKHdl,
*                  ubyte **tek, ubyte **msk, ubyte **emsk)
*
*  FUNCTION
*  Returns the  generated Keys for the Session
*
*  INPUTS
*    eapPSKHdl     : EAP PSK Session Handle
*    tek           : Pointer to the TEK (16 bytes)
*    msk           : Pointer to the MSKa(64 Bytes)
*    emsk          : Pointer to the EMSK (64bytes)
*
*
*  RESULT
*   Returns an error code, or OK
*  SEE ALSO
*   src/eap/EAP_PSKInitSession
*   src/eap/EAP_PSKDeleteSession
*   src/eap/EAP_PSKAuthRequestFirst
*   src/eap/EAP_PSKPeerReplySecond
*   src/eap/EAP_PSKAuthRequestThird
*   src/eap/EAP_PSKPeerReplyFourth
******/
/*------------------------------------------------------------------*/

extern MSTATUS
EAP_PSKgetKeys(ubyte * eapPSKHdl,ubyte **tek,ubyte **msk,ubyte **emsk)
{

    MSTATUS status = OK;
    eapPSKCb * eapPSK  = (eapPSKCb *) eapPSKHdl;
    *tek = eapPSK->tek;
    *msk = eapPSK->msk;
    *emsk = eapPSK->emsk;

    return OK;
}

/*------------------------------------------------------------------*/
/****f* src/eap/EAP_PSKgetID_S
*
*  NAME
*   EAP_PSKgetID_S  -- Returns the ID_S Received from the Auth
*  SYNOPSIS
*
*   #include "../eap/eap.h"
*   #include "../eap/eap_psk.h"
*
*   extern  MSTATUS
*   EAP_PSKgetID_S(ubyte * eapPSKHdl,
*                  ubyte **id_s, ubyte2 *id_s_len)
*
*  FUNCTION
*  Returns the  ID_S Received from the Auth
*
*  INPUTS
*    eapPSKHdl     : EAP PSK Session Handle
*    id_s          : Pointer to the ID_S
*    id_s_len      : Pointer to the Length of the ID_S
*
*
*  RESULT
*   Returns an error code, or OK
*  SEE ALSO
*   src/eap/EAP_PSKInitSession
*   src/eap/EAP_PSKDeleteSession
*   src/eap/EAP_PSKAuthRequestFirst
*   src/eap/EAP_PSKPeerReplySecond
*   src/eap/EAP_PSKAuthRequestThird
*   src/eap/EAP_PSKPeerReplyFourth
******/
/*------------------------------------------------------------------*/

extern MSTATUS
EAP_PSKgetID_S(ubyte * eapPSKHdl,ubyte **id_s,ubyte2 *id_s_len)
{

    MSTATUS status = OK;
    eapPSKCb * eapPSK  = (eapPSKCb *) eapPSKHdl;
    *id_s = eapPSK->id_s;
    *id_s_len = eapPSK->id_s_len;

    return OK;
}

/*------------------------------------------------------------------*/
/****f* src/eap/EAP_PSKgetID_P
*
*  NAME
*   EAP_PSKgetID_P  -- Returns the ID_P Received from the Peer
*  SYNOPSIS
*
*   #include "../eap/eap.h"
*   #include "../eap/eap_psk.h"
*
*   extern  MSTATUS
*   EAP_PSKgetID_P(ubyte * eapPSKHdl,
*                  ubyte **id_p, ubyte2 *id_p_len)
*
*  FUNCTION
*  Returns the  ID_P Received from the Peer
*
*  INPUTS
*    eapPSKHdl     : EAP PSK Session Handle
*    id_p          : Pointer to the ID_P
*    id_p_len      : Pointer to the Length of the ID_P
*
*
*  RESULT
*   Returns an error code, or OK
*  SEE ALSO
*   src/eap/EAP_PSKInitSession
*   src/eap/EAP_PSKDeleteSession
*   src/eap/EAP_PSKAuthRequestFirst
*   src/eap/EAP_PSKPeerReplySecond
*   src/eap/EAP_PSKAuthRequestThird
*   src/eap/EAP_PSKPeerReplyFourth
******/
/*------------------------------------------------------------------*/
extern MSTATUS
EAP_PSKgetID_P(ubyte * eapPSKHdl,ubyte **id_p,ubyte2 *id_p_len)
{

    MSTATUS status = OK;
    eapPSKCb * eapPSK  = (eapPSKCb *) eapPSKHdl;
    *id_p = eapPSK->id_p;
    *id_p_len = eapPSK->id_p_len;

    return OK;
}

/*------------------------------------------------------------------*/
/****f* src/eap/EAP_PSKgetEXT
*
*  NAME
*   EAP_PSKgetEXT  -- Returns the EXTENSION Data  Received
*  SYNOPSIS
*
*   #include "../eap/eap.h"
*   #include "../eap/eap_psk.h"
*
*   extern  MSTATUS
*   EAP_PSKgetEXT(ubyte * eapPSKHdl,
*                  ubyte **ext, ubyte2 *extLen)
*
*  FUNCTION
*  Returns the  EXT Data  Received
*
*  INPUTS
*    eapPSKHdl     : EAP PSK Session Handle
*    ext           : Pointer to the ext data
*    extLen        : Pointer to the Length of the extData
*
*
*  RESULT
*   Returns an error code, or OK
*  SEE ALSO
*   src/eap/EAP_PSKInitSession
*   src/eap/EAP_PSKDeleteSession
*   src/eap/EAP_PSKAuthRequestFirst
*   src/eap/EAP_PSKPeerReplySecond
*   src/eap/EAP_PSKAuthRequestThird
*   src/eap/EAP_PSKPeerReplyFourth
******/
/*------------------------------------------------------------------*/
extern MSTATUS
EAP_PSKgetEXT(ubyte * eapPSKHdl,ubyte **ext,ubyte2 *extLen)
{

    MSTATUS status = OK;
    eapPSKCb * eapPSK  = (eapPSKCb *) eapPSKHdl;
    if ((eapPSK->pChan.ext)  && (eapPSK->pChan.extLen))
        *ext = eapPSK->pChan.ext;

    *extLen = eapPSK->pChan.extLen;
    return OK;
}

/*------------------------------------------------------------------*/
/****f* src/eap/EAP_PSKgetResultInd
*
*  NAME
*   EAP_PSKgetEXT  -- Returns the ResultInd received
*  SYNOPSIS
*
*   #include "../eap/eap.h"
*   #include "../eap/eap_psk.h"
*
*   extern  MSTATUS
*   EAP_PSKgetEXT(ubyte * eapPSKHdl,
*                  ubyte *resultInd)
*
*  FUNCTION
*  Returns the  resultr Indication  Received
*
*  INPUTS
*    eapPSKHdl     : EAP PSK Session Handle
*    resultInd     : Pointer to the Result Indication
*
*
*  RESULT
*   Returns an error code, or OK
*  SEE ALSO
*   src/eap/EAP_PSKInitSession
*   src/eap/EAP_PSKDeleteSession
*   src/eap/EAP_PSKAuthRequestFirst
*   src/eap/EAP_PSKPeerReplySecond
*   src/eap/EAP_PSKAuthRequestThird
*   src/eap/EAP_PSKPeerReplyFourth
******/
/*------------------------------------------------------------------*/

extern MSTATUS
EAP_PSKgetResultInd(ubyte * eapPSKHdl,eapPSKResultInd *resInd)
{

    MSTATUS status = OK;
    eapPSKCb * eapPSK  = (eapPSKCb *) eapPSKHdl;

    *resInd = eapPSK->pChan.resultInd;
    return OK;
}

/*------------------------------------------------------------------*/

#endif /*defined(__ENABLE_DIGICERT_EAP_PSK__) */
#endif /*(defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))*/
