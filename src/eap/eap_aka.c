/**
 * @file  eap_aka.c
 * @brief EAP-AKA method implementation
 *
 * @details    EAP Authentication and Key Agreement
 * @flags      Compilation flags required:
 *     To enable this file's functions, one of the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__ and \c \__ENABLE_DIGICERT_EAP_SIM__
 *     +   \c \__ENABLE_DIGICERT_EAP_AUTH__ and \c \__ENABLE_DIGICERT_EAP_SIM__
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
#if defined(__ENABLE_DIGICERT_EAP_SIM__)
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
#include "../crypto/des.h"
#include "../crypto/three_des.h"
#include "../crypto/rc4algo.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/md4.h"
#include "../harness/harness.h"
#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_sim.h"


/*------------------------------------------------------------------*/

extern MSTATUS eap_akaProcessIdentityReqPkt(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen);
extern MSTATUS eap_akaProcessIdentityRespPkt(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen);
extern MSTATUS eap_akaProcessChallengeReqPkt(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen);
extern MSTATUS eap_akaProcessChallengeRespPkt(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen);
extern MSTATUS eap_akaProcessSyncFailRespPkt(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen);
extern MSTATUS eap_akaProcessAuthRejectRespPkt(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen);
extern MSTATUS eap_simAddIdentityReq(eapSimCb *eapSim, ubyte *pkt, ubyte identityReq);
extern MSTATUS eap_simAddRand(eapSimCb *eapSim, ubyte *pkt);
extern MSTATUS eap_simAddPad(eapSimCb *eapSim, ubyte *pkt, ubyte2 padLen);
extern MSTATUS eap_simAddEncr(eapSimCb *eapSim, ubyte *pkt);
extern MSTATUS eap_simAddMAC(eapSimCb *eapSim, ubyte *pkt);
extern MSTATUS eap_simAddIV(eapSimCb *eapSim, ubyte *pkt);
extern MSTATUS eap_simAddNextIdentity(eapSimCb *eapSim, ubyte *pkt, ubyte identityReq, ubyte2 *len);
extern MSTATUS eap_simAddResultInd(eapSimCb *eapSim, ubyte *pkt);
extern MSTATUS eap_simAddIdentity(eapSimCb *eapSim, ubyte *pkt, ubyte identityReq, ubyte2 *len);
extern MSTATUS eap_simGenerateKeys(eapSimCb *eapSim);
extern MSTATUS eap_simEncryptBuf(eapSimCb *eapSim, ubyte *pkt, ubyte2 pktLen);
extern MSTATUS eap_simCalculateMac(eapSimCb *eapSim,ubyte *pkt, ubyte2 pktLen,ubyte *mac,ubyte *exData, ubyte2 exDataLen);

extern MSTATUS eap_sim_prf(ubyte *key, ubyte *x, ubyte2 xlen);
extern MSTATUS eap_simSendClientErrCodeReq(eapSimCb *eapSim, ubyte **pkt, ubyte4 *pktLen,sbyte4 errCode, ubyte id);
extern MSTATUS eap_simSendNotificationResp(eapSimCb *eapSim, ubyte **pkt, ubyte4 *pktLen, sbyte4 errCode, ubyte id);
extern MSTATUS eap_simSendReauthResp(eapSimCb *eapSim, ubyte **pkt, ubyte4 *pktLen, ubyte id);
extern MSTATUS eap_simDecodeAttr(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen,eapSimPdus pdu);
extern MSTATUS eap_simDecryptBuf(eapSimCb *eapSim);
extern MSTATUS eap_simProcessNotificationReqPkt(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen);
extern MSTATUS eap_simProcessClientErrorPkt(eapSimCb *eapSim,ubyte *pkt,ubyte4 pktLen);
extern MSTATUS eap_simProcessNotificationRespPkt(eapSimCb *eapSim,ubyte *pkt,ubyte4 pktLen);
extern MSTATUS eap_simProcessReauthRespPkt(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen);
extern MSTATUS eap_simProcessReauthReqPkt(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen);


/*------------------------------------------------------------------*/

extern MSTATUS
eap_akaValidateMandAttrs(eapSimCb *eapSim,eapSimPdus pdu)
{
    MSTATUS status = OK;

    switch (pdu)
    {
        case EAP_AKA_IDENTITY_REQ:
        {
            if (!((eapSim->attrPresent & EAP_SIM_AT_PERMANENT_ID_REQ_PRESENT) ||
                (eapSim->attrPresent & EAP_SIM_AT_FULLAUTH_ID_REQ_PRESENT) ||
                (eapSim->attrPresent & EAP_SIM_AT_ANY_ID_REQ_PRESENT)))
            {
                status = ERR_EAP_AKA_MANDATORY_ATTR_MISSING;
                goto exit;
            }

            break;
        }

        case EAP_AKA_IDENTITY_RESP:
        {
            if (!(eapSim->attrPresent & EAP_SIM_AT_IDENTITY_PRESENT))
            {
                status = ERR_EAP_AKA_MANDATORY_ATTR_MISSING;
                goto exit;
            }

            break;
        }

        case EAP_SIM_CHALLENGE_REQ:
        {
            if (!(eapSim->attrPresent & EAP_SIM_AT_RAND_PRESENT))
            {
                status = ERR_EAP_AKA_MANDATORY_ATTR_MISSING;
                goto exit;
            }

            if (!(eapSim->attrPresent & EAP_SIM_AT_MAC_PRESENT))
            {
                status = ERR_EAP_AKA_MANDATORY_ATTR_MISSING;
                goto exit;
            }

            if (!(eapSim->attrPresent & EAP_AKA_AT_AUTN_PRESENT))
            {
                status = ERR_EAP_AKA_MANDATORY_ATTR_MISSING;
                goto exit;
            }

            break;
        }

        case EAP_SIM_CHALLENGE_RESP:
        {
            if (!(eapSim->attrPresent & EAP_SIM_AT_MAC_PRESENT))
            {
                status = ERR_EAP_AKA_MANDATORY_ATTR_MISSING;
                goto exit;
            }

            if (!(eapSim->attrPresent & EAP_AKA_AT_RES_PRESENT))
            {
                status = ERR_EAP_AKA_MANDATORY_ATTR_MISSING;
                goto exit;
            }

            break;
        }

        case EAP_AKA_AUTH_REJECT_RESP:
        {
            break;
        }

        case EAP_AKA_SYNC_FAIL_RESP:
        {
            if (!(eapSim->attrPresent & EAP_AKA_AT_AUTS_PRESENT))
            {
                status = ERR_EAP_AKA_MANDATORY_ATTR_MISSING;
                goto exit;
            }

            break;
        }

        case EAP_SIM_NOTIFICATION_REQ:
        {
            if (!(eapSim->attrPresent & EAP_SIM_AT_NOTIFICATION_PRESENT))
            {
                status = ERR_EAP_AKA_MANDATORY_ATTR_MISSING;
                goto exit;
            }

            break;
        }

        case EAP_SIM_NOTIFICATION_RESP:
        {
            break;
        }

        case EAP_SIM_CLIENT_ERROR:
        {
            if (!(eapSim->attrPresent & EAP_SIM_AT_CLIENT_ERROR_CODE_PRESENT))
            {
                status = ERR_EAP_AKA_MANDATORY_ATTR_MISSING;
                goto exit;
            }

            break;
        }

        case EAP_SIM_REAUTH_REQ:
        {
            if (!(eapSim->attrPresent & EAP_SIM_AT_MAC_PRESENT))
            {
                status = ERR_EAP_AKA_MANDATORY_ATTR_MISSING;
                goto exit;
            }

            if (!(eapSim->attrPresent & EAP_SIM_AT_IV_PRESENT))
            {
                status = ERR_EAP_AKA_MANDATORY_ATTR_MISSING;
                goto exit;
            }

            if (!(eapSim->attrPresent & EAP_SIM_AT_ENCR_DATA_PRESENT))
            {
                status = ERR_EAP_AKA_MANDATORY_ATTR_MISSING;
                goto exit;
            }

            break;
        }

        case EAP_SIM_REAUTH_RESP:
        {
            if (!(eapSim->attrPresent & EAP_SIM_AT_MAC_PRESENT))
            {
                status = ERR_EAP_AKA_MANDATORY_ATTR_MISSING;
                goto exit;
            }

            if (!(eapSim->attrPresent & EAP_SIM_AT_IV_PRESENT))
            {
                status = ERR_EAP_AKA_MANDATORY_ATTR_MISSING;
                goto exit;
            }

            if (!(eapSim->attrPresent & EAP_SIM_AT_ENCR_DATA_PRESENT))
            {
                status = ERR_EAP_AKA_MANDATORY_ATTR_MISSING;
                goto exit;
            }

            break;
        }

        default:
        {
            status = ERR_EAP_AKA_UNKNOWN_PDU;
            goto exit;
        }
    }

    /* Both the Attributes must Exists Together  if present*/
    if ((eapSim->attrPresent & EAP_SIM_AT_IV_PRESENT))
    {
        if (!(eapSim->attrPresent & EAP_SIM_AT_ENCR_DATA_PRESENT))
        {
            status = ERR_EAP_AKA_MANDATORY_ATTR_MISSING;
            goto exit;
        }
    }

    if ((eapSim->attrPresent & EAP_SIM_AT_ENCR_DATA_PRESENT))
    {
        if (!(eapSim->attrPresent & EAP_SIM_AT_IV_PRESENT))
        {
            status =  ERR_EAP_AKA_MANDATORY_ATTR_MISSING;
            goto exit;
        }
    }

    /* Check that The certain parameters are not send in Clear Text */
    if ((eapSim->attrPresent & EAP_SIM_AT_COUNTER_PRESENT)  ||
        (eapSim->attrPresent & EAP_SIM_AT_NEXT_PSEUDONYM_PRESENT)  ||
        (eapSim->attrPresent & EAP_SIM_AT_COUNTER_TOO_SMALL_PRESENT)  ||
        (eapSim->attrPresent & EAP_SIM_AT_PADDING_PRESENT)  ||
        (eapSim->attrPresent & EAP_SIM_AT_NONCE_S_PRESENT)  ||
        (eapSim->attrPresent & EAP_SIM_AT_NEXT_REAUTH_ID_PRESENT))
    {
        status = ERR_EAP_SIM_ATTR_NOT_ENCRYPTED;
        goto exit;
    }

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_akaValidateMandAttr: Error, status = ", status);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
eap_akaAddRes(eapSimCb *eapSim, ubyte *pkt, ubyte2 *attrLen)
{
    /* Can be between 32 Bits to 128 Bits  Add padding if necessary*/
    ubyte   pad;
    ubyte*  len;
    ubyte2  val = EAP_HTONS(eapSim->resLen);
    MSTATUS status =OK;

    *pkt = EAP_AKA_AT_RES;
    pkt++;

    /*Length */
    len = pkt;
    *pkt = 1;
    pkt++;

    /* Res Length  */
    DIGI_MEMCPY(pkt, (ubyte *)&val,2);
    pkt+=2;

    val = eapSim->resLen / 8; /* Its in Bits */
    pad = eapSim->resLen % 8;

    if (pad)
        val++;

    DIGI_MEMCPY(pkt, eapSim->res,val);
    pkt+= val;

    pad = val % 4;

    *attrLen = 4 + val;

    if (pad)
    {
        pad = 4 - pad;
        DIGI_MEMSET(pkt,0,pad);
        *attrLen+=pad;
    }

    *len = *attrLen/4;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE,"Adding AT_RES");

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_akaAddRes: Error, status = ", status);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
eap_akaAddAutn(eapSimCb *eapSim,ubyte *pkt)
{
    MSTATUS status =OK;

    *pkt = EAP_AKA_AT_AUTN;
    pkt++;

    /*Length */
    *pkt = 5;
    pkt++;

    /* Reserved */
    DIGI_MEMSET(pkt, 0,2);
    pkt+=2;

    DIGI_MEMCPY(pkt, eapSim->autn,EAP_AKA_AUTN_LEN);
    pkt+=16;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE,"Adding AT_AUTN");

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_akaAddAutn: Error, status = ", status);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
eap_akaAddAuts(eapSimCb *eapSim,ubyte *pkt)
{
    MSTATUS status =OK;

    *pkt = EAP_AKA_AT_AUTS;
    pkt++;

    /*Length */
    *pkt = 4;
    pkt++;

    DIGI_MEMCPY(pkt, eapSim->auts,EAP_AKA_AUTS_LEN);
    pkt+=EAP_AKA_AUTS_LEN; /* 14 Bytes */

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Adding AT_AUTS");

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_akaAddAuts: Error, status = ", status);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
eap_akaGenerateMasterKey(eapSimCb *eapSim)
{
    ubyte           shaOutput[SHA_HASH_RESULT_SIZE];
    shaDescr        *shaContext = NULL;
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    if (OK > (status = SHA1_allocDigest(MOC_HASH(hwAccelCtx)(BulkCtx*) &shaContext)))
        goto exit;

    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) shaContext)))
        goto exit;

    /* Master Key = SHA1(Identity|IK|CK) */

    /* Last Identity Used (AT_IDENTITY or Identity Resp) */
    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) shaContext, eapSim->identity, eapSim->identityLen)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) shaContext, eapSim->IK, EAP_AKA_IK_LEN)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) shaContext, eapSim->CK, EAP_AKA_CK_LEN)))
        goto exit;

    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) shaContext, shaOutput)))
        goto exit;

    DIGI_MEMCPY(eapSim->masterKey, shaOutput, 20);

#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE,  (sbyte *) "Identity is ");
    EAP_PrintBytes(eapSim->identity, eapSim->identityLen);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE,  (sbyte *) "IK is ");
    EAP_PrintBytes(eapSim->IK, EAP_AKA_IK_LEN);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "CK is ");
    EAP_PrintBytes(eapSim->CK, EAP_AKA_CK_LEN);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Master Key is ");
    EAP_PrintBytes( eapSim->masterKey ,SHA_HASH_RESULT_SIZE);
#endif

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_akaGenerateMasterKey: Error, status = ", status);
    }

    SHA1_freeDigest(MOC_HASH(hwAccelCtx) (BulkCtx*)&shaContext);
nocleanup:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
    return status;
}


/*------------------------------------------------------------------*/

/****f* src/eap/EAP_AKAIdentityReq
*
*  NAME
*   EAP_SIMStartReq  -- Send EAP-SIM Start Req
*  SYNOPSIS
*
*   #include "../eap/eap.h"
*   #include "../eap/eap_aka.h"
*
*   extern  MSTATUS
*   EAP_AKASendIdentityReq(eapSimCb *eapSim,ubyte **pkt,ubyte4 *pktLen,
*                       ubyte id_type,ubyte id)
*
*  FUNCTION
*  Generate  EAP-AKA Identity Request Packet to send to the Peer
*
*  INPUTS
*    eapSim        : EAP SIM Session Handle
*    pkt           : Ptr to EAP Packet Formed <EAPHdr,Type,SubType,Payload>
*    pktLen        : EAP Payload Len
*    id_type       : ID Type to Send (PERM,FULL,ANY ID)
*    id            : EAP Packet Id
*
*
*
*  RESULT
*   Returns an error code, or OK
*  SEE ALSO
*   src/eap/EAP_AKASendIdentityReq
*   src/eap/EAP_SIMSendChallengeReq
*   src/eap/EAP_SIMSendNotificationReq
*   src/eap/EAP_SIMSendReauthReq
******/

extern MSTATUS
EAP_AKASendIdentityReq(eapSimCb *eapSim,ubyte **pkt,ubyte4 *pktLen,
                    ubyte id_type,ubyte id)
{
    ubyte*      cur = NULL;
    eapHdr_t*   eapHdr;
    MSTATUS     status = OK;

    /* Order of Id is ANY/FAST/PERM */

    /* Limit # Start Req per round to 3 */
    if (3 < eapSim->numIdReq)
    {
        status  = ERR_EAP_SIM_TOO_MANY_ID_REQ;
        goto exit;
    }

    if ((0 == id_type))
    {
        status = ERR_EAP_SIM_INVALID_ID_REQ;
        goto exit;
    }

    /* If its the First Time its Sending a ID_REQ, it has to be ANY_ID */
    if ((eapSim->numIdReq) && (EAP_SIM_AT_ANY_ID_REQ == id_type))
    {
        status = ERR_EAP_SIM_INVALID_ID_REQ;
        goto exit;
    }

    /* If PERM has been Sent then the Previous Ones Cannot Be sent */
    /* If Full has been Sent then the Previous Ones Cannot Be sent */

    *pkt = MALLOC(EAP_SIM_PACKET_SIZE);

    if (NULL == *pkt)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    eapHdr = (eapHdr_t *)*pkt;

    eapHdr->code = EAP_CODE_REQUEST;
    eapHdr->id = id;

    *pktLen = sizeof(eapHdr_t);
    cur = *pkt + sizeof(eapHdr_t);

    *cur++ = EAP_TYPE_AKA;
    *cur++ = EAP_AKA_SUBTYPE_IDENTITY;
    *cur++ = 0;
    *cur++ = 0;

    *pktLen +=4;

    /* Send the ID Request Attribute */
    status = eap_simAddIdentityReq(eapSim,cur,id_type);
    if (OK > status)
        goto exit;

    *pktLen +=4;
    cur+=4;

    DIGI_HTONS((ubyte *)*pkt + 2,*pktLen);
    eapSim->numIdReq++;

exit:
    if (OK > status)
    {
        if (*pkt)
            FREE(*pkt);

        *pkt = NULL;
        *pktLen = 0;

        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "EAP_AKASendIdentityReq: Error, status = ", status);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
eap_akaSendIdentityResp(eapSimCb *eapSim,ubyte **pkt,ubyte4 *pktLen,ubyte id)
{
    ubyte*      cur = NULL;
    ubyte2      attrLen = 0;
    eapHdr_t*   eapHdr;
    MSTATUS     status = OK;

    *pkt = MALLOC(EAP_SIM_PACKET_SIZE);

    if (NULL == *pkt)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    eapHdr = (eapHdr_t *)*pkt;

    eapHdr->code = EAP_CODE_RESPONSE;
    eapHdr->id = id;

    *pktLen = sizeof(eapHdr_t);
    cur = *pkt + sizeof(eapHdr_t);

    *cur++ = EAP_TYPE_AKA;
    *cur++ = EAP_AKA_SUBTYPE_IDENTITY;
    *cur++ = 0;
    *cur++ = 0;

    *pktLen +=4;

    status = eap_simAddIdentity(eapSim,cur,eapSim->id_requested,&attrLen);
    if (OK > status)
        goto exit;

    *pktLen +=attrLen;
    cur+=attrLen;

    DIGI_HTONS((ubyte *)*pkt + 2,*pktLen);

exit:
    if (OK > status)
    {
        if (*pkt)
            FREE(*pkt);

        *pkt = NULL;
        *pktLen = 0;

        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_akaSendIdentityResp: Error, status = ", status);
    }

    return status;

} /* eap_akaSendIdentityResp */


/*------------------------------------------------------------------*/

/****f* src/eap/EAP_AKAChallengeReq
*
*  NAME
*   EAP_AKAChallengeReq  -- Send EAP-AKA Challenge Request
*  SYNOPSIS
*
*   #include "../eap/eap.h"
*   #include "../eap/eap_sim.h"
*
*   extern  MSTATUS
*   EAP_AKASendChallengeReq(eapSimCb *eapSim,ubyte **pkt,ubyte4 *pktLen,
*                           ubyte *rand,ubyte* autn,
*                           ubyte *at_next_psuedo,ubyte2 at_psuedo_len,
*                           ubyte *at_next_reauthid,ubyte2 at_reauthid_len,
*                           ubyte id)
*
*  FUNCTION
*  Generate  Challenge Request Packet to send to the Peer
*
*  INPUTS
*    eapSim        : EAP SIM Session Handle
*    pkt           : Ptr to EAP Packet Formed <EAPHdr,Type,SubType,Payload>
*    pktLen        : EAP Payload Len
*    rand          : Random Bytes 16 Bytes received from AuC
*    autn          : Autn Value Received from AuC 16 Bytes
*    CK            : CK Value Received from AuC 16 Bytes
*    IK            : IK Value Received from AuC 16 Bytes
*    res           : RES Value Received from AuC (32 to 128 Bits )
*    resLen        : RES Len  (32 to 128 Bits )
*    at_next_reauthid : Next reauth ID
*    at_reauthid_len  : Next reauth ID  Length
*    id            : EAP Packet Id
*
*
*
*  RESULT
*   Returns an error code, or OK
*  SEE ALSO
*   src/eap/EAP_AKASendIdentityReq
*   src/eap/EAP_SIMSendChallengeReq
*   src/eap/EAP_SIMSendNotificationReq
*   src/eap/EAP_SIMSendReauthReq
******/

extern MSTATUS
EAP_AKASendChallengeReq(eapSimCb *eapSim,ubyte **pkt,ubyte4 *pktLen,
                        ubyte *rand,ubyte *autn,
                        ubyte *ck,ubyte *ik, ubyte* res,ubyte2 resLen,
                        ubyte *at_next_psuedo,ubyte2 at_psuedo_len,
                        ubyte *at_next_reauthid,ubyte2 at_reauthid_len,
                        ubyte id)
{
    ubyte*      cur = NULL;
    ubyte*      encrData;
    ubyte*      encrDataLen;
    ubyte2      attrLen = 0;
    ubyte2      plainTxtLen = 0;
    ubyte2      pad = 0;
    eapHdr_t*   eapHdr;
    MSTATUS     status = OK;


    if (( 32 > resLen ) || (128 < resLen ))
    {
        status = ERR_EAP_AKA_INVALID_LEN;
        goto exit;
    }

    *pkt = MALLOC(EAP_SIM_PACKET_SIZE);

    if (NULL == *pkt)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    eapHdr = (eapHdr_t *)*pkt;

    eapHdr->code = EAP_CODE_REQUEST;
    eapHdr->id = id;
    eapSim->counter = 0;
    eapSim->numIdReq = 0;
    /* These are use to generate Keys and Compare the result from Peer */
    DIGI_MEMCPY(eapSim->CK, ck, EAP_AKA_CK_LEN);
    DIGI_MEMCPY(eapSim->IK, ik, EAP_AKA_IK_LEN);
    /* ResLen is in Bits   */
    DIGI_MEMSET(eapSim->authRes, 0, 16);
    if (resLen % 8 )
        DIGI_MEMCPY(eapSim->authRes, res, (resLen / 8) + 1);
    else
        DIGI_MEMCPY(eapSim->authRes, res, (resLen / 8));

    eapSim->authResLen = resLen;

    *pktLen = sizeof(eapHdr_t);
    cur = *pkt + sizeof(eapHdr_t);

    *cur++ = EAP_TYPE_AKA;
    *cur++ = EAP_AKA_SUBTYPE_CHALLENGE;
    *cur++ = 0;
    *cur++ = 0;

    *pktLen +=4;

    DIGI_MEMCPY(eapSim->rand[0],rand,EAP_SIM_RAND_LEN);
    DIGI_MEMCPY(eapSim->autn,autn,EAP_AKA_AUTN_LEN);

    eapSim->numRand = 1;

    status = eap_simAddRand(eapSim,cur);
    if (OK > status)
        goto exit;

    *pktLen += EAP_SIM_RAND_LEN  + 4;
    cur+=      EAP_SIM_RAND_LEN +4;

    status = eap_akaAddAutn(eapSim,cur);
    if (OK > status)
        goto exit;

    *pktLen += EAP_AKA_AUTN_LEN  + 4;
    cur+=      EAP_AKA_AUTN_LEN +4;

    if (eapSim->eapSimCfg.send_result_ind)
    {
        status = eap_simAddResultInd(eapSim,cur);
        if (OK > status)
            goto exit;

        *pktLen +=4;
        cur+=4;
    }

    /* Calculate Keys */
    status = eap_akaGenerateMasterKey(eapSim);
    if (OK > status)
        goto exit;

    /* Generate K_AUT/MSK/EMSK */
    status = eap_simGenerateKeys(eapSim);
    if (OK > status)
        goto exit;

    if ((at_psuedo_len) || (at_reauthid_len))
    {
        /* Encrypt these  and Add the IV and ENCR */
        status = eap_simAddIV(eapSim,cur);
        if (OK > status)
           goto exit;

        cur+=20;
        *pktLen +=20;

        status = eap_simAddEncr(eapSim,cur);
        if (OK > status)
            goto exit;

        encrDataLen = cur+1;
        *encrDataLen = 1; /*Set It to 1 */
        cur+=4;
        *pktLen +=4;
        encrData = cur;

        if (at_psuedo_len)
        {
            if (eapSim->psuedonym)
            {
                FREE(eapSim->psuedonym);
                eapSim->psuedonym = NULL;
                eapSim->psuedonymLen = 0;
            }

            eapSim->psuedonym = MALLOC(at_psuedo_len);
            if (NULL == eapSim->psuedonym)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }

            eapSim->psuedonymLen = at_psuedo_len;
            DIGI_MEMCPY(eapSim->psuedonym,at_next_psuedo,at_psuedo_len);

            status = eap_simAddNextIdentity(eapSim,cur,
                                            EAP_SIM_AT_NEXT_PSEUDONYM,&attrLen);
            plainTxtLen +=attrLen;
            cur += attrLen;

        }
        if (at_reauthid_len)
        {
            if (eapSim->reauthId)
            {
                FREE(eapSim->reauthId);
                eapSim->reauthId = NULL;
                eapSim->reauthIdLen = 0;
            }

            eapSim->reauthId = MALLOC(at_reauthid_len);
            if (NULL == eapSim->reauthId)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }

            eapSim->reauthIdLen = at_reauthid_len;
            DIGI_MEMCPY(eapSim->reauthId,at_next_reauthid,at_reauthid_len);
            status = eap_simAddNextIdentity(eapSim,cur,
                                            EAP_SIM_AT_NEXT_REAUTH_ID,&attrLen);
            plainTxtLen +=attrLen;
            cur += attrLen;

        }
        /* Plain Text Should be a multiple of 16 */
        pad = plainTxtLen % 16;

        if (pad)  /* Should be 4,8 or 12 */
        {
            /* Actual Pad */
            pad = 16 - pad;
            status = eap_simAddPad(eapSim,cur,pad);
            if (OK > status)
                goto exit;

            plainTxtLen += pad;
        }

        cur+=pad;
        *pktLen+=plainTxtLen;
        *encrDataLen =  *encrDataLen + (plainTxtLen/4);
        /* Encrypt the whole PLaintxt buffer */
        status = eap_simEncryptBuf(eapSim,encrData,plainTxtLen);
        if (OK > status)
            goto exit;

    }

    DIGI_MEMSET(eapSim->mac,0,EAP_SIM_MAC_LEN);
    status = eap_simAddMAC(eapSim,cur);
    *pktLen +=20;
    cur+=4;

    DIGI_HTONS((ubyte *)*pkt + 2,*pktLen);

    if (OK > (status = eap_simCalculateMac(eapSim,*pkt,*pktLen,eapSim->mac,0,0)))
        goto exit;

    DIGI_MEMCPY(cur,eapSim->mac,EAP_SIM_MAC_LEN);
    eapSim->attemptfullAuthRound = 1;
    eapSim->fullAuthRoundSuccess = 0;
    eapSim->attemptreAuthRound = 0;
    eapSim->reAuthRoundSuccess = 0;

exit:
    if (OK > status)
    {
        if (*pkt)
            FREE(*pkt);

        *pkt = NULL;
        *pktLen = 0;

        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "EAP_AKASendChallengeReq: Error, status = ", status);
    }

    return status;

} /* EAP_AKASendChallengeReq */


/*------------------------------------------------------------------*/

extern MSTATUS
eap_akaSendChallengeRespPkt(eapSimCb *eapSim,ubyte **pkt,ubyte4 *pktLen, ubyte id)
{
    ubyte*      cur = NULL;
    ubyte2      attrLen = 0;
    eapHdr_t*   eapHdr;
    MSTATUS     status = OK;

    *pkt = MALLOC(EAP_SIM_PACKET_SIZE);

    if (NULL == *pkt)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    eapHdr = (eapHdr_t *)*pkt;

    eapHdr->code = EAP_CODE_RESPONSE;
    eapHdr->id = id;

    *pktLen = sizeof(eapHdr_t);
    cur = *pkt + sizeof(eapHdr_t);

    *cur++ = EAP_TYPE_AKA;
    *cur++ = EAP_AKA_SUBTYPE_CHALLENGE;
    *cur++ = 0;
    *cur++ = 0;

    *pktLen +=4;

    if ((eapSim->eapSimCfg.send_result_ind) &&
        (eapSim->attrPresent & EAP_SIM_AT_RESULT_IND_PRESENT))
    {
        status = eap_simAddResultInd(eapSim,cur);
        if (OK > status)
            goto exit;

        *pktLen +=4;
        cur+=4;
    }


    status = eap_akaAddRes(eapSim,cur,&attrLen);
    if (OK > status)
        goto exit;

    *pktLen +=attrLen;
    cur+=attrLen;

    DIGI_MEMSET(eapSim->mac,0,EAP_SIM_MAC_LEN);

    status = eap_simAddMAC(eapSim,cur);
    if (OK > status)
        goto exit;

    *pktLen +=20;
    cur+=4;

    DIGI_HTONS((ubyte *)*pkt + 2,*pktLen);
    status = eap_simCalculateMac(eapSim,*pkt,*pktLen,
                                 eapSim->mac,0,0);

    if (OK > status)
        goto exit;

    DIGI_MEMCPY(cur,eapSim->mac,EAP_SIM_MAC_LEN);

    eapSim->attemptfullAuthRound = 1;
    eapSim->fullAuthRoundSuccess = 1;
    eapSim->attemptreAuthRound = 0;
    eapSim->reAuthRoundSuccess = 0;

exit:
    if (OK > status)
    {
        if (*pkt)
            FREE(*pkt);

        *pkt = NULL;
        *pktLen = 0;

        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_akaSendChallengeResp: Error, status = ", status);
    }

    return status;

} /* eap_akaSendChallengeRespPkt */


/*------------------------------------------------------------------*/

extern MSTATUS
eap_akaSendAuthRejectRespPkt(eapSimCb *eapSim,ubyte **pkt,ubyte4 *pktLen,
                      ubyte id)
{

    ubyte*      cur = NULL;
    eapHdr_t*   eapHdr;
    MSTATUS     status = OK;

    *pkt = MALLOC(EAP_SIM_PACKET_SIZE);

    if (NULL == *pkt)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    eapHdr = (eapHdr_t *)*pkt;

    eapHdr->code = EAP_CODE_RESPONSE;
    eapHdr->id = id;

    *pktLen = sizeof(eapHdr_t);
    cur = *pkt + sizeof(eapHdr_t);

    *cur++ = EAP_TYPE_AKA;
    *cur++ = EAP_AKA_SUBTYPE_AUTH_REJECT;
    *cur++ = 0;
    *cur++ = 0;

    *pktLen +=4;

    DIGI_HTONS((ubyte *)*pkt + 2,*pktLen);

exit:
    if (OK > status)
    {
        if (*pkt)
            FREE(*pkt);

        *pkt = NULL;
        *pktLen = 0;

        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_akaSendAuthReject: Error, status = ", status);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
eap_akaSendSyncFailRespPkt(eapSimCb *eapSim,ubyte **pkt,ubyte4 *pktLen,
                    ubyte id)
{

    ubyte*      cur = NULL;
    eapHdr_t*   eapHdr;
    MSTATUS     status = OK;

    *pkt = MALLOC(EAP_SIM_PACKET_SIZE);

    if (NULL == *pkt)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    eapHdr = (eapHdr_t *)*pkt;

    eapHdr->code = EAP_CODE_RESPONSE;
    eapHdr->id = id;

    *pktLen = sizeof(eapHdr_t);
    cur = *pkt + sizeof(eapHdr_t);

    *cur++ = EAP_TYPE_AKA;
    *cur++ = EAP_AKA_SUBTYPE_SYNC_FAIL;
    *cur++ = 0;
    *cur++ = 0;

    *pktLen +=4;

    status = eap_akaAddAuts(eapSim,cur);

    *pktLen +=16; /* AUTS_LEN + 2 Bytes */
    cur+=16;
    DIGI_HTONS((ubyte *)*pkt + 2,*pktLen);

exit:
    if (OK > status)
    {
        if (*pkt)
            FREE(*pkt);

        *pkt = NULL;
        *pktLen = 0;

        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_akaSendSyncFail: Error, status = ", status);
    }

    return status;
}


/*------------------------------------------------------------------*/

/****f* src/eap/EAP_AKAProcessPkt
*
*  NAME
*   EAP_SIMProcessPkt  -- Process Received Packet
*  SYNOPSIS
*
*   #include "../eap/eap.h"
*   #include "../eap/eap_aka.h"
*
*   extern  MSTATUS
*   EAP_SIMSendProcessPkt(eapSimCb *eapSim,ubyte *pkt,ubyte4 pktLen,
*                         ubyte **resp,ubyte4 *respLen,eapSimStatus *state)
*
*  FUNCTION
*   Process  Recv'd Packet and Do SM functions
*
*  INPUTS
*    eapSim        : EAP SIM Session Handle
*    pkt           : Received EAP Packet
*    pktLen        : Received EAP Packet Length
*    resp           : Ptr to EAP Packet Formed <EAPHdr,Type,SubType,Payload>
*    respLen        : EAP Payload Len
*    state          : EAP SM State Returned
*
*
*
*  RESULT
*   Returns an error code, or OK
*  SEE ALSO
*   src/eap/EAP_SIMSendStartReq
*   src/eap/EAP_SIMSendChallengeReq
*   src/eap/EAP_SIMSendNotificationReq
*   src/eap/EAP_SIMSendReauthReq
******/

extern MSTATUS
EAP_AKAProcessPkt(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen,
                  ubyte **resp,ubyte4 *respLen,eapSimStatus *state)
{
    eapHdr_t*   eapHdr  = (eapHdr_t *)pkt;
    ubyte*      cur     = pkt + sizeof(eapHdr_t);
    ubyte       type    = *cur++;
    ubyte       subtype = *cur++;
    MSTATUS     status = ERR_EAP_AKA_UNKNOWN_PDU;

    cur+=2; /* Reserved */

    /* reset a few of the params */
    eapSim->attrPresent = 0;
    eapSim->counterTooSmall = 0;
    eapSim->notifCode = 0;

    if (eapHdr->code == EAP_CODE_REQUEST)
    {
        switch (subtype)
        {
            case EAP_AKA_SUBTYPE_IDENTITY:
            {
                status = eap_akaProcessIdentityReqPkt(eapSim,cur,
                                                pktLen-4-sizeof(eapHdr_t));
                if (OK > status)
                {
                    status = eap_simSendClientErrCodeReq(eapSim,resp,respLen,
                                                        status,eapHdr->id);

                    if (OK > status)
                        goto exit;

                    break;
                }

                /* call EAP_AKA_IDENTITY_RESP */
                status = eap_akaSendIdentityResp(eapSim,resp,respLen,eapHdr->id);

                if (OK > status)
                    goto exit;

                *state = EAP_AKA_STATUS_RECV_IDENTITY_REQ;

                break;
            }

            case EAP_AKA_SUBTYPE_CHALLENGE:
            {
                status = eap_akaProcessChallengeReqPkt(eapSim,pkt,pktLen);

                if (OK > status)
                {
                    if (ERR_EAP_AKA_AUTH_REJECT == status)
                    {
                        status = eap_akaSendAuthRejectRespPkt(eapSim,resp,respLen,
                                                              eapHdr->id);

                        if (OK > status)
                            goto exit;

                        break;
                    }

                    if (ERR_EAP_AKA_SYNC_FAIL == status)
                    {
                        status = eap_akaSendSyncFailRespPkt(eapSim,resp,respLen,
                                                    eapHdr->id);
                        if (OK > status)
                            goto exit;

                        break;
                    }

                    /*Send Client Error */
                    status = eap_simSendClientErrCodeReq(eapSim,resp,respLen,
                                                        status,eapHdr->id);
                    break;
                }
                /* If the user does not like the AUTN Parameter
                 * it can send AUTH_REJECT or SYNC FAILURE
                 */

                /*Send Challenge Resp */
                status = eap_akaSendChallengeRespPkt(eapSim,resp,respLen,
                                                     eapHdr->id);

                if (OK > status)
                    goto exit;

                /* Reset Some Variables */
                eapSim->numIdReq = 0;
                *state = EAP_SIM_STATUS_RECV_CHALLENGE_REQ;

                break;
            }

            case EAP_SIM_SUBTYPE_NOTIFICATION:
            {
                status = eap_simProcessNotificationReqPkt(eapSim,pkt,pktLen);

                if (OK > status)
                {
                    /*Send Client Error */
                    status = eap_simSendClientErrCodeReq(eapSim,resp,respLen,
                                                         status,eapHdr->id);
                    break;
                }

                status = eap_simSendNotificationResp(eapSim,resp,respLen,
                                                     status,eapHdr->id);

                if (OK > status)
                    goto exit;

                *state = EAP_SIM_STATUS_RECV_NOTIFICATION_REQ;

                break;
            }

            case EAP_SIM_SUBTYPE_REAUTHENTICATION:
            {
                status = eap_simProcessReauthReqPkt(eapSim,pkt,pktLen);

                if (OK > status)
                {
                    /*Send Client Error */
                    status = eap_simSendClientErrCodeReq(eapSim,resp,respLen,
                                                        status,eapHdr->id);
                    break;
                }

                status = eap_simSendReauthResp(eapSim,resp,respLen, eapHdr->id);

                if (OK > status)
                    goto exit;

                *state = EAP_SIM_STATUS_RECV_REAUTH_REQ;

                break;
            }

            default:
            {
                status = ERR_EAP_AKA_UNKNOWN_PDU;
                goto exit;
            }
        }
    }

    if (eapHdr->code == EAP_CODE_RESPONSE)
    {
        switch (subtype)
        {
            case EAP_AKA_SUBTYPE_IDENTITY:
            {
                status = eap_akaProcessIdentityRespPkt(eapSim,cur,pktLen-4-sizeof(eapHdr_t));
                *state = EAP_AKA_STATUS_RECV_IDENTITY_RESP;
                /*App to Check on Valid Identity  and then send Challenge Req
                or a Notification packet with error if reuiqred */
                break;
            }

            case EAP_AKA_SUBTYPE_CHALLENGE:
            {
                status = eap_akaProcessChallengeRespPkt(eapSim,pkt,pktLen);
                /*App to Check on status  and send SUCCESS/FAIL
                or a Notification packet with error/reauthid  if required */
                *state = EAP_SIM_STATUS_RECV_CHALLENGE_RESP;
                break;
            }

            case EAP_SIM_SUBTYPE_CLIENT_ERROR:
            {
                status = eap_simProcessClientErrorPkt(eapSim,pkt,pktLen);
                *state = EAP_SIM_STATUS_RECV_CLIENT_ERROR_CODE;
                /* Send EAP Failure */
                break;
            }

            case EAP_SIM_SUBTYPE_NOTIFICATION:
            {
                status = eap_simProcessNotificationRespPkt(eapSim,pkt,pktLen);
                /* Send EAP Success/Failure */
                *state = EAP_SIM_STATUS_RECV_NOTIFICATION_RESP;
                break;
            }

            case EAP_SIM_SUBTYPE_REAUTHENTICATION:
            {
                status = eap_simProcessReauthRespPkt(eapSim,pkt,pktLen);
                *state = EAP_SIM_STATUS_RECV_REAUTH_RESP;
                break;
            }

            case EAP_AKA_SUBTYPE_AUTH_REJECT:
            {
                status = eap_akaProcessAuthRejectRespPkt(eapSim,pkt,pktLen);
                *state = EAP_AKA_STATUS_RECV_AUTH_REJECT_RESP;
                break;
            }

            case EAP_AKA_SUBTYPE_SYNC_FAIL:
            {
                status = eap_akaProcessSyncFailRespPkt(eapSim,pkt,pktLen);
                *state = EAP_AKA_STATUS_RECV_SYNC_FAIL_RESP;
                break;
            }

            default:
            {
                status = ERR_EAP_AKA_UNKNOWN_PDU;
                goto exit;
            }
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
eap_akaProcessIdentityReqPkt(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen)
{
    MSTATUS status = OK;

    status = eap_simDecodeAttr(eapSim,pkt,pktLen,EAP_AKA_IDENTITY_REQ);

    if (OK > status)
        goto exit;

    status = eap_akaValidateMandAttrs(eapSim,EAP_AKA_IDENTITY_REQ);

    if (OK > status)
        goto exit;

    if (eapSim->id_requested)
    {
        /* The Sequence Should be ANY,FULL,PERM */
        eapSim->numIdReq++;

        if (3 < eapSim->numIdReq)
        {
           status = ERR_EAP_SIM_TOO_MANY_ID_REQ;
           goto exit;
        }
    }

    eapSim->sessionStatus = EAP_AKA_STATUS_RECV_IDENTITY_REQ;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
eap_akaProcessIdentityRespPkt(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen)
{
    MSTATUS status = OK;

    status = eap_simDecodeAttr(eapSim,pkt,pktLen,EAP_AKA_IDENTITY_RESP);

    if (OK > status)
        goto exit;

    status = eap_akaValidateMandAttrs(eapSim,EAP_AKA_IDENTITY_RESP);

    if (OK > status)
        goto exit;

    eapSim->sessionStatus = EAP_AKA_STATUS_RECV_IDENTITY_RESP;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
eap_akaProcessChallengeReqPkt(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen)
{
    ubyte       mac[EAP_SIM_MAC_LEN];
    sbyte4      cmp;
    MSTATUS     status;

    status = eap_simDecodeAttr(eapSim,pkt+sizeof(eapHdr_t)+4,/* From the attr */
                               pktLen-sizeof(eapHdr_t)-4,/* Attr Len*/
                               EAP_SIM_CHALLENGE_REQ);

    if (OK > status)
        goto exit;

    status = eap_akaValidateMandAttrs(eapSim,EAP_SIM_CHALLENGE_REQ);
    if (OK > status)
        goto exit;

    /* Call the App and Get the IK and CK from the USIM CARD */
    /* Checked for NULL during Session Creation */
    status = eapSim->eapSimCfg.getAKARes(eapSim->appSessionHdl,eapSim,
                                         eapSim->rand[0],eapSim->autn,
                                         eapSim->IK,eapSim->CK,
                                         eapSim->res,&eapSim->resLen,
                                         eapSim->auts);

    if (OK > status)
        goto exit;

    if (( 32 > eapSim->resLen) || (128 < eapSim->resLen))
    {
        status = ERR_EAP_AKA_INVALID_LEN;
        goto exit;
    }
    /* Calculate Keys */
    status = eap_akaGenerateMasterKey(eapSim);
    if (OK > status)
        goto exit;

    /* Generate K_AUT/MSK/EMSK */
    status = eap_simGenerateKeys(eapSim);
    if (OK > status)
        goto exit;

    /* Validate MAC */
    status = eap_simCalculateMac(eapSim,pkt,pktLen,mac,0,0);
    if (OK > status)
        goto exit;

    if (DIGI_MEMCMP(eapSim->mac,mac,EAP_SIM_MAC_LEN,&cmp))
    {
        status =  ERR_EAP_SIM_INVALID_MAC;
        goto exit;
    }

    if (cmp)
    {
        status =  ERR_EAP_SIM_INVALID_MAC;
        goto exit;
    }

    /* Decrypt any ENCR Attrs */
    if (eapSim->attrPresent & EAP_SIM_AT_IV_PRESENT)
    {
        status = eap_simDecryptBuf(eapSim);

        if (OK > status)
            goto exit;

        status = eap_simDecodeAttr(eapSim,eapSim->encr_data,
                                   eapSim->encr_dataLen,
                                   EAP_SIM_CHALLENGE_REQ);

        if (OK > status)
            goto exit;
    }

    /*if the reauth Id is not present in the challenge Req, Set it to NULL */
    if (!(eapSim->attrPresent & EAP_SIM_AT_NEXT_REAUTH_ID_PRESENT))
    {
        if (eapSim->reauthId)
        {
            FREE(eapSim->reauthId);
            eapSim->reauthId = NULL;
            eapSim->reauthIdLen = 0;
        }
    }

    eapSim->attemptfullAuthRound = 1;
    eapSim->fullAuthRoundSuccess = 0;
    eapSim->attemptreAuthRound = 0;
    eapSim->reAuthRoundSuccess = 0;
    eapSim->sessionStatus = EAP_SIM_STATUS_RECV_CHALLENGE_REQ;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
eap_akaProcessChallengeRespPkt(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen)
{
    ubyte       mac[EAP_SIM_MAC_LEN];
    sbyte4      cmp;
    ubyte2      len;
    MSTATUS     status = OK;

    status = eap_simDecodeAttr(eapSim,pkt+sizeof(eapHdr_t)+4,/* From the attr */
                               pktLen-sizeof(eapHdr_t)-4,/* Attr Len*/
                               EAP_SIM_CHALLENGE_RESP);

    if (OK > status)
        goto exit;

    status = eap_akaValidateMandAttrs(eapSim,EAP_SIM_CHALLENGE_RESP);

    if (OK > status)
        goto exit;

    /* Validate MAC */
    eap_simCalculateMac(eapSim,pkt,pktLen,mac,0,0);

    if (OK > (status = DIGI_MEMCMP(eapSim->mac, mac, EAP_SIM_MAC_LEN, &cmp)))
        goto exit;

    if (cmp)
    {
        status = ERR_EAP_SIM_INVALID_MAC;
        goto exit;
    }

    /* Validate RES */
    if (eapSim->authResLen != eapSim->resLen)
    {
        status = ERR_EAP_AKA_INVALID_RES;
        goto exit;
    }

    len = eapSim->authResLen / 8;

    if (eapSim->authResLen % 8 )
        len++;

    if (OK > (status = DIGI_MEMCMP(eapSim->authRes, eapSim->res, len, &cmp)))
        goto exit;

    if (cmp)
    {
        status = ERR_EAP_AKA_INVALID_RES;
        goto exit;
    }

    eapSim->fullAuthRoundSuccess = 1;
    eapSim->counter++;

    eapSim->sessionStatus = EAP_SIM_STATUS_RECV_CHALLENGE_RESP;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
eap_akaProcessAuthRejectRespPkt(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen)
{
    MSTATUS status = OK;

    status = eap_simDecodeAttr(eapSim,pkt+sizeof(eapHdr_t)+4,/* From the attr */
                               pktLen-sizeof(eapHdr_t)-4,/* Attr Len*/
                               EAP_AKA_AUTH_REJECT_RESP);

    if (OK > status)
        goto exit;

    status = eap_akaValidateMandAttrs(eapSim,EAP_AKA_AUTH_REJECT_RESP);

    if (OK > status)
        goto exit;

    eapSim->sessionStatus = EAP_AKA_STATUS_RECV_AUTH_REJECT_RESP;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
eap_akaProcessSyncFailRespPkt(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen)
{
    MSTATUS status;

    status = eap_simDecodeAttr(eapSim,pkt+sizeof(eapHdr_t)+4,/* From the attr */
                               pktLen-sizeof(eapHdr_t)-4,/* Attr Len*/
                               EAP_AKA_SYNC_FAIL_RESP);

    if (OK > status)
        goto exit;

    status = eap_akaValidateMandAttrs(eapSim,EAP_AKA_SYNC_FAIL_RESP);

    if (OK > status)
        goto exit;

    eapSim->sessionStatus = EAP_AKA_STATUS_RECV_SYNC_FAIL_RESP;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
EAP_AKAGetAuts(eapSimCb *eapSim,
                ubyte **auts)
{
    *auts = eapSim->auts;

    return OK;
}

#endif /*defined(__ENABLE_DIGICERT_EAP_SIM__)  */
#endif /* (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))*/
