/**
 * @file  eap_sim.c
 * @brief EAP-SIM method implementation
 *
 * @details    EAP Subscriber Identity Module
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


#include "../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))
#if defined(__ENABLE_DIGICERT_EAP_SIM__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
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
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/hmac.h"
#include "../crypto/md4.h"
#include "../harness/harness.h"
#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_sim.h"


/*------------------------------------------------------------------*/

extern MSTATUS eap_simProcessStartReqPkt(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen);
extern MSTATUS eap_simProcessStartRespPkt(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen);
extern MSTATUS eap_simProcessChallengeReqPkt(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen);
extern MSTATUS eap_simProcessChallengeRespPkt(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen);
extern MSTATUS eap_simProcessNotificationReqPkt(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen);
extern MSTATUS eap_simProcessClientErrorPkt(eapSimCb *eapSim,ubyte *pkt,ubyte4 pktLen);
extern MSTATUS eap_simProcessNotificationRespPkt(eapSimCb *eapSim,ubyte *pkt,ubyte4 pktLen);
extern MSTATUS eap_simProcessReauthRespPkt(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen);
extern MSTATUS eap_simProcessReauthReqPkt(eapSimCb *eapSim,ubyte *pkt,ubyte2 pktLen);
extern MSTATUS eap_sim_prf(ubyte *key, ubyte *x, ubyte2 xlen);


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simDecodeAttr(eapSimCb *eapSim,
                  ubyte *pkt,ubyte2 pktLen,eapSimPdus pdu)
{
    ubyte2 i,attrLen,prevnumRand= 0,prevCounter = 0;
    ubyte  attr;
    ubyte *cur = pkt;
    MSTATUS status = OK;
    ubyte2 val,pad;
    sbyte4 cmp;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simDecodeAttr: Handle = ", (sbyte4)((uintptr)eapSim));
    while (cur < pkt+pktLen)
    {
        attr = *cur++;
        attrLen = *cur++;

        if ((attrLen * 4 -2) + cur > pkt + pktLen)
        {
            status = ERR_EAP_SIM_INVALID_ATTR_LEN;
            goto exit;
        }

        switch (attr)
        {
            case EAP_SIM_AT_RAND:
            {
                if (eapSim->attrPresent & EAP_SIM_AT_RAND_PRESENT)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Duplicate AT_RAND  Attr Sent");
                    status = ERR_EAP_SIM_DUPLICATE_ATTR;
                    goto exit;
                }

                if (pdu != EAP_SIM_CHALLENGE_REQ)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_RAND  Attr Sent with PDU");
                    status = ERR_EAP_SIM_INVALID_ATTR;
                    goto exit;
                }

                /* Should be at least 2 or 3 Rands */
                if (attrLen *4 == 36)
                {
                    prevnumRand = eapSim->numRand;
                    eapSim->numRand = 2;
                }
                else
                {
                    if (attrLen *4 == 52)
                    {
                        prevnumRand = eapSim->numRand;
                        eapSim->numRand = 3;
                    }
                    else
                    {
                        if ((attrLen *4 == 20) && (eapSim->eapSimCfg.aka))
                        {
                            prevnumRand = eapSim->numRand;
                            eapSim->numRand = 1;
                        }
                        else
                        {
                            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_RAND  Len Attr Sent");
                            status = ERR_EAP_SIM_INVALID_ATTRLEN;
                            goto exit;
                        }
                    }
                }

                /* AKA has only 16 Byte Rand */
                if (eapSim->eapSimCfg.aka)
                {
                    if (1 != eapSim->numRand)
                    {
                        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_RAND  Len Attr Sent");
                        status = ERR_EAP_SIM_INVALID_ATTRLEN;
                        goto exit;
                    }
                }

                cur+=2; /* Reserved 2 Bytes */

                /* Compare that the Previous Rands are different than the Current Rands  and that  all the rands in the 16byte seq are unique*/
                /* If error then Swap back the prevnumRand */

                DIGI_MEMCMP(cur,(ubyte *)eapSim->rand,EAP_SIM_RAND_LEN,&cmp);

                if (0 == cmp)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Stale AT_RAND Attr Sent");
                    status = ERR_EAP_SIM_INVALID_RAND;
                    goto exit;
                }

                if (eapSim->numRand == 1)
                {
                    DIGI_MEMCPY(eapSim->rand[0],cur,EAP_SIM_RAND_LEN);
                    cur+=16;
                }

                if (eapSim->numRand == 2)
                {
                    DIGI_MEMCPY(eapSim->rand[0],cur,EAP_SIM_RAND_LEN);
                    cur+=16;
                    DIGI_MEMCPY(eapSim->rand[1],cur,EAP_SIM_RAND_LEN);
                    cur+=16;
                }

                if (eapSim->numRand == 3)
                {
                    DIGI_MEMCPY(eapSim->rand[0],cur,EAP_SIM_RAND_LEN);
                    cur+=16;
                    DIGI_MEMCPY(eapSim->rand[1],cur,EAP_SIM_RAND_LEN);
                    cur+=16;
                    DIGI_MEMCPY(eapSim->rand[2],cur,EAP_SIM_RAND_LEN);
                    cur+=16;
                }

                eapSim->attrPresent |= EAP_SIM_AT_RAND_PRESENT;

                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECEIVED AT_RAND");

                break;
            }

            case EAP_AKA_AT_AUTS:
            {
                if (!(eapSim->eapSimCfg.aka))
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_AUTS  Attr Sent with PDU");
                    status = ERR_EAP_SIM_INVALID_ATTR;
                    goto exit;
                }

                if (eapSim->attrPresent & EAP_AKA_AT_AUTS_PRESENT)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Duplicate AT_AUTS  Attr Sent");
                    status  = ERR_EAP_SIM_DUPLICATE_ATTR;
                    goto exit;
                }

                if (pdu != EAP_AKA_SYNC_FAIL_RESP)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_AUTS  Attr Sent with PDU");
                    status = ERR_EAP_SIM_INVALID_ATTR;
                    goto exit;
                }

                /* Should be 5 */
                if (attrLen != 4)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_AUTS Attr Lenght Sent");
                    status = ERR_EAP_SIM_INVALID_ATTRLEN;
                    goto exit;
                }

                DIGI_MEMCPY(eapSim->auts,cur,EAP_AKA_AUTS_LEN);
                cur+=14;
                eapSim->attrPresent |= EAP_AKA_AT_AUTS_PRESENT;

                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECEIVED AT_AUTS");

                break;
            }

            case EAP_AKA_AT_AUTN:
            {
                if (eapSim->attrPresent & EAP_AKA_AT_AUTN_PRESENT)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Duplicate AT_AUTN  Attr Sent");
                    status  = ERR_EAP_SIM_DUPLICATE_ATTR;
                    goto exit;
                }

                if (pdu != EAP_SIM_CHALLENGE_REQ)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_AUTN  Attr Sent with PDU");
                    status = ERR_EAP_SIM_INVALID_ATTR;
                    goto exit;
                }

                /* Should be 5 */
                if (attrLen != 5)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_AUTN Attr Lenght Sent");
                    status = ERR_EAP_SIM_INVALID_ATTRLEN;
                    goto exit;
                }

                cur+=2; /* Reserved */

                DIGI_MEMCPY(eapSim->autn,cur,EAP_AKA_AUTN_LEN);
                cur+=16;
                eapSim->attrPresent |= EAP_AKA_AT_AUTN_PRESENT;

                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECEIVED AT_AUTN");

                break;
            }

            case EAP_AKA_AT_RES:
            {
                if (!(eapSim->eapSimCfg.aka))
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_RES  Attr Sent with PDU");
                    status = ERR_EAP_SIM_INVALID_ATTR;
                    goto exit;
                }

                if (eapSim->attrPresent & EAP_AKA_AT_RES_PRESENT)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Duplicate AT_RES  Attr Sent");
                    status  = ERR_EAP_SIM_DUPLICATE_ATTR;
                    goto exit;
                }

                if (pdu != EAP_SIM_CHALLENGE_RESP)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_RES  Attr Sent with PDU");
                    status = ERR_EAP_SIM_INVALID_ATTR;
                    goto exit;
                }

                /* Should be between 2 and 5 bytes  32 bits to 128 bits */
                if ((2 >  attrLen) || (5 < attrLen))
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_RES Attr Lenght Sent");
                    status = ERR_EAP_SIM_INVALID_ATTRLEN;
                    goto exit;
                }

                DIGI_MEMCPY((ubyte *)&eapSim->resLen,cur,2);
                eapSim->resLen = EAP_HTONS(eapSim->resLen);
                cur+=2; /* RES Len in Bits */

                val = eapSim->resLen / 8;
                pad = eapSim->resLen % 8;
                if (pad)
                    val++;

                DIGI_MEMCPY(eapSim->res,cur,val);
                cur+=val;
                pad = val % 4; /* Padding to make a multiple of 4 bytes */

                if (pad)
                {
                    pad = 4 - pad;
                    cur+= pad;
                }

                eapSim->attrPresent |= EAP_AKA_AT_RES_PRESENT;

                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECEIVED AT_RES");

                break;
            }

            case EAP_SIM_AT_NONCE_MT:
            {
                if ((eapSim->eapSimCfg.aka))
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_NONCE_MT  Attr Sent with PDU");
                    status = ERR_EAP_SIM_INVALID_ATTR;
                    goto exit;
                }

                if (eapSim->attrPresent & EAP_SIM_AT_NONCE_MT_PRESENT)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Duplicate AT_NONCE_MT  Attr Sent");
                    status  = ERR_EAP_SIM_DUPLICATE_ATTR;
                    goto exit;
                }

                if (pdu != EAP_SIM_START_RESP)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_NONCE_MT  Attr Sent with PDU");
                    status = ERR_EAP_SIM_INVALID_ATTR;
                    goto exit;
                }

                /* Should be 5 */
                if (attrLen != 5)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_NONCE_MT Attr Lenght Sent");
                    status = ERR_EAP_SIM_INVALID_ATTRLEN;
                    goto exit;
                }

                cur+=2; /* Reserved 2 Bytes */

                /* Ensure that the NONCE value is a fresh one if this a new Auth Attempt */
                DIGI_MEMCMP(eapSim->nonce_mt,cur,EAP_SIM_NONCE_MT_LEN,&cmp);
                if (0 == cmp)
                {
                    status = ERR_EAP_SIM_INVALID_NONCE_MT;
                    goto exit;
                }

                DIGI_MEMCPY(eapSim->nonce_mt,cur,EAP_SIM_NONCE_MT_LEN);
                cur+=16;
                eapSim->attrPresent |= EAP_SIM_AT_NONCE_MT_PRESENT;

                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECEIVED AT_NONCE_MT");

                break;
            }

            case EAP_SIM_AT_PERMANENT_ID_REQ:
            {
                if (eapSim->attrPresent & EAP_SIM_AT_PERMANENT_ID_REQ_PRESENT)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Duplicate AT_PERMANENT_ID  Attr Sent");
                    status = ERR_EAP_SIM_DUPLICATE_ATTR;
                    goto exit;
                }

                if ((eapSim->attrPresent & EAP_SIM_AT_FULLAUTH_ID_REQ_PRESENT) ||
                    (eapSim->attrPresent & EAP_SIM_AT_ANY_ID_REQ_PRESENT))
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Multiple AT_ID Attr Sent");
                    status = ERR_EAP_SIM_MULTIPLE_ID_ATTR;
                    goto exit;
                }

                if (eapSim->eapSimCfg.aka)
                {
                    if (EAP_AKA_IDENTITY_REQ != pdu)
                    {
                        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_PERMANENT_ID  AttrSent with PDU");
                        status = ERR_EAP_SIM_INVALID_ATTR;
                        goto exit;
                    }
                }
                else
                {
                    if (EAP_SIM_START_REQ != pdu)
                    {
                            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_PERMANENT_ID  Attr Sent with PDU");
                        status = ERR_EAP_SIM_INVALID_ATTR;
                        goto exit;
                    }
                }

                /* Should be 1 */
                if (1 != attrLen)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_ID  Attr ID Sent");
                    status = ERR_EAP_SIM_INVALID_ATTRLEN;
                    goto exit;
                }

                cur+=2; /* Reserved 2 Bytes */

                eapSim->attrPresent |= EAP_SIM_AT_PERMANENT_ID_REQ_PRESENT;
                eapSim->id_requested = EAP_SIM_AT_PERMANENT_ID_REQ;

                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECEIVED AT_PERMANENT_ID_REQ");

                break;
            }

            case EAP_SIM_AT_FULLAUTH_ID_REQ:
            {
                if (eapSim->attrPresent & EAP_SIM_AT_FULLAUTH_ID_REQ_PRESENT)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Duplicate AT_FULLAUTH_ID  Attr Sent");
                    status = ERR_EAP_SIM_DUPLICATE_ATTR;
                    goto exit;
                }

                if ((eapSim->attrPresent & EAP_SIM_AT_PERMANENT_ID_REQ_PRESENT)||
                    (eapSim->attrPresent & EAP_SIM_AT_ANY_ID_REQ_PRESENT))
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Multiple AT_ID Attr Sent");
                    status = ERR_EAP_SIM_MULTIPLE_ID_ATTR;
                    goto exit;
                }

                if (eapSim->eapSimCfg.aka)
                {
                    if (EAP_AKA_IDENTITY_REQ != pdu)
                    {
                        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_FULLAUTH_ID  Attr Sent with PDU");

                        status = ERR_EAP_SIM_INVALID_ATTR;
                        goto exit;
                    }
                }
                else
                {
                    if (EAP_SIM_START_REQ != pdu)
                    {
                        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_FULLAUTH_ID  Attr Sent with PDU");

                        status = ERR_EAP_SIM_INVALID_ATTR;
                        goto exit;
                    }
                }

                /* Should be 1 */
                if (1 != attrLen)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_PERMANENT_ID  Len Attr Sent");
                    status = ERR_EAP_SIM_INVALID_ATTRLEN;
                    goto exit;
                }

                cur+=2; /* Reserved 2 Bytes */

                eapSim->attrPresent |= EAP_SIM_AT_FULLAUTH_ID_REQ_PRESENT;
                eapSim->id_requested = EAP_SIM_AT_FULLAUTH_ID_REQ;

                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECEIVED AT_FULL_AUTH_ID_REQ");

                break;
            }

            case EAP_SIM_AT_ANY_ID_REQ:
            {
                if (eapSim->attrPresent & EAP_SIM_AT_ANY_ID_REQ_PRESENT)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Duplicate AT_ANY_ID_REQ  Attr Sent");
                    status = ERR_EAP_SIM_DUPLICATE_ATTR;
                    goto exit;
                }

                if ((eapSim->attrPresent & EAP_SIM_AT_PERMANENT_ID_REQ_PRESENT)||
                    (eapSim->attrPresent & EAP_SIM_AT_FULLAUTH_ID_REQ_PRESENT))
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Multiple AT_ID Attr Sent");
                    status = ERR_EAP_SIM_MULTIPLE_ID_ATTR;
                    goto exit;
                }

                if (eapSim->eapSimCfg.aka)
                {
                    if (EAP_AKA_IDENTITY_REQ != pdu)
                    {
                        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_ANY_ID  Attr Sent with PDU");
                        status = ERR_EAP_SIM_INVALID_ATTR;
                        goto exit;
                    }
                }
                else
                {
                    if (EAP_SIM_START_REQ != pdu)
                    {
                            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_ANY_ID  Attr Sent with PDU");
                        status = ERR_EAP_SIM_INVALID_ATTR;
                        goto exit;
                    }
                }

                /* Should be 1 */
                if (1 != attrLen)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_ANY_ID_REQ  Len Attr Sent");
                    status = ERR_EAP_SIM_INVALID_ATTRLEN;
                    goto exit;
                }

                cur+=2; /* Reserved 2 Bytes */

                eapSim->attrPresent |= EAP_SIM_AT_ANY_ID_REQ_PRESENT;
                eapSim->id_requested = EAP_SIM_AT_ANY_ID_REQ;

                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECEIVED AT_ANY_ID_REQ");

                break;
            }

            case EAP_SIM_AT_MAC:
            {
                if (eapSim->attrPresent & EAP_SIM_AT_MAC_PRESENT)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Duplicate AT_RAND  Attr Sent");
                    status = ERR_EAP_SIM_DUPLICATE_ATTR;
                    goto exit;
                }

                if ((EAP_SIM_START_REQ == pdu) ||
                    (EAP_SIM_START_RESP == pdu) ||
                    (EAP_AKA_IDENTITY_RESP == pdu) ||
                    (EAP_AKA_IDENTITY_RESP == pdu) ||
                    (EAP_AKA_AUTH_REJECT_RESP == pdu) ||
                    (EAP_AKA_SYNC_FAIL_RESP == pdu) ||
                    (EAP_SIM_CLIENT_ERROR == pdu))
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_MAC  Attr Sent with PDU");
                    status = ERR_EAP_SIM_INVALID_ATTR;
                    goto exit;
                }

                /* Should be 5 */
                if (5 != attrLen)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_MAC Attr Len Sent");
                    status = ERR_EAP_SIM_INVALID_ATTRLEN;
                    goto exit;
                }

                cur+=2; /* Reserved 2 Bytes */

                DIGI_MEMCPY(eapSim->mac,cur,EAP_SIM_MAC_LEN);

                /* Set it to 0 so that MAC can be calculated */
                DIGI_MEMSET(cur,0,EAP_SIM_MAC_LEN);
                cur+=16;
                eapSim->attrPresent |= EAP_SIM_AT_MAC_PRESENT;

                /* To Verify MAC before any other attributes are verified */

                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECEIVED AT_MAC");

                break;
            }

            case EAP_SIM_AT_NOTIFICATION:
            {
                if (eapSim->attrPresent & EAP_SIM_AT_NOTIFICATION_PRESENT)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Duplicate AT_NOTIFICATION  Attr Sent");
                    status = ERR_EAP_SIM_DUPLICATE_ATTR;
                    goto exit;
                }

                if (EAP_SIM_NOTIFICATION_REQ != pdu)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_NOTIFICATION  Attr Sent with PDU");
                    status = ERR_EAP_SIM_INVALID_ATTR;
                    goto exit;
                }

                /* Should be 1 */
                if (1 != attrLen)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_NOTIFICATION Attr Len Sent");
                    status = ERR_EAP_SIM_INVALID_ATTRLEN;
                    goto exit;
                }

                DIGI_MEMCPY((ubyte *)&eapSim->notifCode,cur,2);
                eapSim->notifCode  = EAP_HTONS(eapSim->notifCode);
                cur+=2; /* Reserved 2 Bytes */
                eapSim->attrPresent |= EAP_SIM_AT_NOTIFICATION_PRESENT;

                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECEIVED AT_NOTIFICATION");

                break;
            }

            case EAP_SIM_AT_IDENTITY:
            {
                if (eapSim->attrPresent & EAP_SIM_AT_IDENTITY_PRESENT)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Duplicate AT_IDENTITY  Attr Sent");
                    status = ERR_EAP_SIM_DUPLICATE_ATTR;
                    goto exit;
                }

                if (eapSim->eapSimCfg.aka)
                {
                    if (EAP_AKA_IDENTITY_RESP != pdu)
                    {
                        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_IDENTITY  Attr Sent with PDU");
                        status = ERR_EAP_SIM_INVALID_ATTR;
                        goto exit;
                    }
                }
                else
                {
                    if (EAP_SIM_START_RESP != pdu)
                    {
                        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_IDENTITY  Attr Sent with PDU");
                        status = ERR_EAP_SIM_INVALID_ATTR;
                        goto exit;
                    }
                }

                /* Should be  > 1 */
                if (2 > attrLen)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_IDENTITY  Len Attr Sent");
                    status = ERR_EAP_SIM_INVALID_ATTRLEN;
                    goto exit;
                }

                DIGI_MEMCPY((ubyte *)&eapSim->identityLen,cur,2);
                eapSim->identityLen = EAP_HTONS(eapSim->identityLen);

                /* If Identity Len is greater than the packet its an error*/
                if (eapSim->identityLen > (attrLen * 4)  - 4)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_IDENTITY  Len Attr Sent");
                    status = ERR_EAP_SIM_INVALID_ID_LEN;
                    goto exit;
                }

                cur+=2; /* Actual Identity Len */

                if (eapSim->identity)
                {
                    FREE(eapSim->identity);
                    eapSim->identity = NULL;
                }

                eapSim->identity  = MALLOC(eapSim->identityLen);
                if (NULL == eapSim->identity)
                {
                    status=  ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }

                DIGI_MEMCPY(eapSim->identity,cur,eapSim->identityLen);

                cur+= attrLen *4 - 4;
                eapSim->attrPresent |= EAP_SIM_AT_IDENTITY_PRESENT;

                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECEIVED AT_IDENTITY");

                break;
            }

            case EAP_SIM_AT_VERSION_LIST:
            {
                if ((eapSim->eapSimCfg.aka))
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_VERSION_LIST  Attr Sent with AKA PDU");
                    status = ERR_EAP_SIM_INVALID_ATTR;
                    goto exit;
                }

                if (eapSim->attrPresent & EAP_SIM_AT_VERSION_LIST_PRESENT)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Duplicate AT_VERSION_LIST  Attr Sent");
                    status = ERR_EAP_SIM_DUPLICATE_ATTR;
                    goto exit;
                }

                if (EAP_SIM_START_REQ != pdu)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_VERSION_LIST  Attr Sent with PDU");
                    status = ERR_EAP_SIM_INVALID_ATTR;
                    goto exit;
                }

                DIGI_MEMCPY((ubyte *)&eapSim->numVersionList,cur,2);
                eapSim->numVersionList = EAP_HTONS(eapSim->numVersionList);
                /* What it returns is Actual number of bytes in List.. Need to divide by 2 */
                eapSim->numVersionList = (eapSim->numVersionList)/2;

                if ((eapSim->numVersionList * 2) > (attrLen * 4) - 4)
                {
                    status = ERR_EAP_SIM_INVALID_NUM_VERSION_LIST;
                    goto exit;
                }

                cur+=2; /* Num Version 2 Bytes */

                if (eapSim->versionList)
                {
                    FREE(eapSim->versionList);
                    eapSim->versionList = NULL;
                }

                eapSim->versionList = MALLOC(eapSim->numVersionList * sizeof(ubyte2));
                if (NULL == eapSim->versionList)
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }

                for (i=0;i<eapSim->numVersionList;i++)
                {
                    DIGI_MEMCPY((ubyte *)&eapSim->versionList[i],cur,2);
                    eapSim->versionList[i] = EAP_HTONS(eapSim->versionList[i]);
                    cur+=2;
                }

                /* If the Version List is odd Number then there is a padding of two bytes */
                if (eapSim->numVersionList % 2)
                    cur+=2;

                eapSim->attrPresent |= EAP_SIM_AT_VERSION_LIST_PRESENT;

                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECEIVED AT_VERSION_LIST");

                break;
            }

            case EAP_SIM_AT_SELECTED_VERSION:
            {
                if ((eapSim->eapSimCfg.aka))
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_SELECTED_VERSION  Attr Sent with PDU");
                    status = ERR_EAP_SIM_INVALID_ATTR;
                    goto exit;
                }

                if (eapSim->attrPresent & EAP_SIM_AT_SELECTED_VERSION_PRESENT)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Duplicate AT_SELECTED_VERSION  Attr Sent");
                    status = ERR_EAP_SIM_DUPLICATE_ATTR;
                    goto exit;
                }

                if (EAP_SIM_START_RESP != pdu)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_SELECTED_VERSION Attr Sent with PDU");
                    status = ERR_EAP_SIM_INVALID_ATTR;
                    goto exit;
                }

                /* Should be 1 */
                if (1 != attrLen)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_SELECTED_VERSION  Len Attr Sent");
                    status = ERR_EAP_SIM_INVALID_ATTRLEN;
                    goto exit;
                }

                DIGI_MEMCPY((ubyte *)&eapSim->selectedVersion,cur,2);
                eapSim->selectedVersion = EAP_HTONS(eapSim->selectedVersion);
                cur+=2; /* Version 2 Bytes */

                /* User to verify that the Selected version is Fine */
                eapSim->attrPresent |= EAP_SIM_AT_SELECTED_VERSION_PRESENT;

                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECEIVED AT_SELECTED_VERSION");

                break;
            }

            case EAP_SIM_AT_COUNTER: /* Encrypted */
            {
                if (eapSim->attrPresent & EAP_SIM_AT_COUNTER_PRESENT)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Duplicate AT_COUNTER  Attr Sent");
                    status = ERR_EAP_SIM_DUPLICATE_ATTR;
                    goto exit;
                }

                if ((EAP_SIM_START_REQ      == pdu) ||
                    (EAP_SIM_START_RESP     == pdu) ||
                    (EAP_SIM_CHALLENGE_REQ  == pdu)||
                    (EAP_SIM_CHALLENGE_RESP == pdu)||
                    (EAP_SIM_CLIENT_ERROR   == pdu))
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_COUNTER  Attr Sent with PDU");
                    status = ERR_EAP_SIM_INVALID_ATTR;
                    goto exit;
                }

                /* Should be 1 */
                if (1 != attrLen)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_RAND  Len Attr Sent");
                    status = ERR_EAP_SIM_INVALID_ATTRLEN;
                    goto exit;
                }

                prevCounter = eapSim->counter;

                DIGI_MEMCPY((ubyte *)&eapSim->counter,cur,2);
                eapSim->counter = EAP_HTONS(eapSim->counter);

                if (prevCounter >= eapSim->counter)
                {
                    eapSim->counter = prevCounter;
                    eapSim->counterTooSmall = 1;
                    status = ERR_EAP_SIM_COUNTER_TOO_SMALL;
                    goto exit;
                }

                cur+=2; /* Reserved 2 Bytes */
                eapSim->attrPresent |= EAP_SIM_AT_COUNTER_PRESENT;

                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECEIVED AT_COUNTER");

                break;
            }

            case EAP_SIM_AT_COUNTER_TOO_SMALL:
            {
                if (eapSim->attrPresent & EAP_SIM_AT_COUNTER_TOO_SMALL_PRESENT)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Duplicate AT_COUNTER_TOO_SMALL  Attr Sent");
                    status = ERR_EAP_SIM_DUPLICATE_ATTR;
                    goto exit;
                }

                if ((EAP_SIM_REAUTH_RESP       != pdu) &&
                    (EAP_SIM_NOTIFICATION_RESP != pdu))
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_COUNTER_TOO_SMALL Attr Sent with PDU");
                    status = ERR_EAP_SIM_INVALID_ATTR;
                    goto exit;
                }

                /* Should be 1 */
                if (1 != attrLen)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_COUNTER_TOO_SMALL Len Attr Sent");
                    status = ERR_EAP_SIM_INVALID_ATTRLEN;
                    goto exit;
                }

                cur+=2; /* Reserved 2 Bytes */
                eapSim->counterTooSmall = 1;
                eapSim->attrPresent |= EAP_SIM_AT_COUNTER_TOO_SMALL_PRESENT;

                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECEIVED AT_COUNTER_TOO_SMALL");

                break;
            }

            case EAP_SIM_AT_NONCE_S:
            {
                if (eapSim->attrPresent & EAP_SIM_AT_NONCE_S_PRESENT)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Duplicate AT_NONCE_S  Attr Sent");
                    status = ERR_EAP_SIM_DUPLICATE_ATTR;
                    goto exit;
                }

                if (EAP_SIM_REAUTH_REQ != pdu)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_NONSE_S Attr Sent with PDU");
                    status = ERR_EAP_SIM_INVALID_ATTR;
                    goto exit;
                }

                /* Should be 5 */
                if (5 != attrLen)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_NONCE_S  Len Attr Sent");
                    status = ERR_EAP_SIM_INVALID_ATTRLEN;
                    goto exit;
                }

                cur+=2; /* Reserved 2 Bytes */

                /* Ensure that the NONCE value is a fresh one if this a new Auth Attempt */
                DIGI_MEMCMP(eapSim->nonce_s,cur,EAP_SIM_NONCE_S_LEN,&cmp);
                if (0 == cmp)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Stale AT_NONCE_S  Sent");
                    status = ERR_EAP_SIM_INVALID_NONCE_S;
                    goto exit;
                }

                DIGI_MEMCPY(eapSim->nonce_s,cur,EAP_SIM_NONCE_S_LEN);
                cur+=16;
                eapSim->attrPresent |= EAP_SIM_AT_NONCE_S_PRESENT;

                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECEIVED AT_NONCE_S");

                break;
            }

            case EAP_SIM_AT_CLIENT_ERROR_CODE:
            {
                if (eapSim->attrPresent & EAP_SIM_AT_CLIENT_ERROR_CODE_PRESENT)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Duplicate AT_CLIENT_ERROR_CODE  Attr Sent");
                    status = ERR_EAP_SIM_DUPLICATE_ATTR;
                    goto exit;
                }

                if (EAP_SIM_CLIENT_ERROR != pdu)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_CLIENT_ERROR_CODE Attr Sent with PDU");
                    status = ERR_EAP_SIM_INVALID_ATTR;
                    goto exit;
                }

                /* Should be 1 */
                if (attrLen != 1)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_CLIENT_ERROR_CODE  Len Attr Sent");
                    status = ERR_EAP_SIM_INVALID_ATTRLEN;
                    goto exit;
                }

                DIGI_MEMCPY((ubyte *)&eapSim->clientErrCode,cur,2);
                eapSim->clientErrCode = EAP_HTONS(eapSim->clientErrCode);
                cur+=2; /* Reserved 2 Bytes */
                eapSim->attrPresent |= EAP_SIM_AT_CLIENT_ERROR_CODE_PRESENT;

                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECEIVED AT_CLIENT_ERR_CODE");

                break;
            }

            case EAP_SIM_AT_RESULT_IND:
            {
                if (eapSim->attrPresent & EAP_SIM_AT_RESULT_IND_PRESENT)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Duplicate AT_RESULT_IND  Attr Sent");
                    status = ERR_EAP_SIM_DUPLICATE_ATTR;
                    goto exit;
                }

                if ((EAP_SIM_START_REQ         == pdu) ||
                    (EAP_SIM_START_RESP        == pdu) ||
                    (EAP_SIM_NOTIFICATION_REQ  == pdu)||
                    (EAP_SIM_NOTIFICATION_RESP == pdu)||
                    (EAP_SIM_CLIENT_ERROR      == pdu))
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_RESULT_IND  Attr Sent with PDU");
                    status = ERR_EAP_SIM_INVALID_ATTR;
                    goto exit;
                }

                /* Should be 1 */
                if (1 != attrLen)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_RESULT_IND  Len Attr Sent");
                    status = ERR_EAP_SIM_INVALID_ATTRLEN;
                    goto exit;
                }

                cur+=2; /* Reserved 2 Bytes */

                eapSim->attrPresent |= EAP_SIM_AT_RESULT_IND_PRESENT;
                eapSim->recvResultInd = 1;

                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECEIVED AT_RESULT_IND");

                break;
            }

            case EAP_SIM_AT_IV:
            {
                if (eapSim->attrPresent & EAP_SIM_AT_IV_PRESENT)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Duplicate AT_IV  Attr Sent");
                    status = ERR_EAP_SIM_DUPLICATE_ATTR;
                    goto exit;
                }

                if ((EAP_SIM_START_REQ      == pdu)  ||
                    (EAP_SIM_START_RESP     == pdu) ||
                    (EAP_SIM_CHALLENGE_RESP == pdu) ||
                    (EAP_SIM_CLIENT_ERROR   == pdu))
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_IV Attr Sent with PDU");
                    status = ERR_EAP_SIM_INVALID_ATTR;
                    goto exit;
                }

                /* Should be 5 */
                if (5 != attrLen)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_IV  Len Attr Sent");
                    return ERR_EAP_SIM_INVALID_ATTRLEN;
                }

                cur+=2; /* Reserved 2 Bytes */

                /* Ensure that the iv value is a fresh one if this a new Auth Attempt */
                DIGI_MEMCMP(eapSim->iv,cur,EAP_SIM_IV_LEN,&cmp);

                if (0 == cmp)
                {
                    status = ERR_EAP_SIM_INVALID_IV;
                    goto exit;
                }

                DIGI_MEMCPY(eapSim->iv,cur,EAP_SIM_IV_LEN);
                cur+=16;
                eapSim->attrPresent |= EAP_SIM_AT_IV_PRESENT;

                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECEIVED AT_IV");

                break;
            }

            case EAP_SIM_AT_ENCR_DATA:
            {
                if (eapSim->attrPresent & EAP_SIM_AT_ENCR_DATA_PRESENT)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Duplicate AT_ENCR  Attr Sent");
                    status = ERR_EAP_SIM_DUPLICATE_ATTR;
                    goto exit;
                }

                if ((EAP_SIM_START_REQ      == pdu)  ||
                    (EAP_SIM_START_RESP     == pdu) ||
                    (EAP_SIM_CHALLENGE_RESP == pdu) ||
                    (EAP_SIM_CLIENT_ERROR   == pdu))
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_ENCR Attr Sent with PDU");
                    status = ERR_EAP_SIM_INVALID_ATTR;
                    goto exit;
                }

                cur+=2; /* Reserved 2 Bytes */

                eapSim->encr_dataLen = attrLen * 4 -4;
                if (eapSim->encr_data)
                {
                    FREE(eapSim->encr_data);
                    eapSim->encr_data = NULL;
                }

                eapSim->encr_data = MALLOC(eapSim->encr_dataLen);
                if (NULL == eapSim->encr_data)
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }

                DIGI_MEMCPY(eapSim->encr_data,cur,eapSim->encr_dataLen);
                cur+=eapSim->encr_dataLen;
                eapSim->attrPresent |= EAP_SIM_AT_ENCR_DATA_PRESENT;

                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECEIVED AT_ENCR_DATA");

                break;
            }

            case EAP_SIM_AT_NEXT_PSEUDONYM:
            {
                if (eapSim->attrPresent & EAP_SIM_AT_NEXT_PSEUDONYM_PRESENT)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Duplicate AT_NEXT_PSEUDONYM  Attr Sent");
                    status = ERR_EAP_SIM_DUPLICATE_ATTR;
                    goto exit;
                }

                if (EAP_SIM_CHALLENGE_REQ != pdu) {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_NEXT_PSEUDONYM  Attr Sent with PDU");
                    status = ERR_EAP_SIM_INVALID_ATTR;
                    goto exit;
                }

                /* Should be  > 1 */
                if (2 > attrLen)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_IDENTITY  Len Attr Sent");
                    status = ERR_EAP_SIM_INVALID_ATTRLEN;
                    goto exit;
                }

                DIGI_MEMCPY((ubyte *)&eapSim->psuedonymLen,cur,2);
                eapSim->psuedonymLen = EAP_HTONS(eapSim->psuedonymLen);
                cur+=2; /* Actual Identity Len */

                if (eapSim->psuedonym)
                {
                    FREE(eapSim->psuedonym);
                    eapSim->psuedonym = NULL;
                }

                eapSim->psuedonym  = MALLOC(eapSim->psuedonymLen);
                if (NULL == eapSim->psuedonym)
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }

                DIGI_MEMCPY(eapSim->psuedonym,cur,eapSim->psuedonymLen);

                cur+= attrLen *4 - 4;
                eapSim->attrPresent |= EAP_SIM_AT_NEXT_PSEUDONYM_PRESENT;

                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECEIVED AT_NEXT_PSUEDONYM");

                break;
            }

            case EAP_SIM_AT_NEXT_REAUTH_ID:
            {
                /* Sent us the REAUTH ID  Insert it in fastIdentity*/
                if (eapSim->attrPresent & EAP_SIM_AT_NEXT_REAUTH_ID_PRESENT)
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Duplicate AT_NEXT_REAUTH_ID  Attr Sent");
                    status = ERR_EAP_SIM_DUPLICATE_ATTR;
                    goto exit;
                }

                if ((EAP_SIM_REAUTH_REQ    != pdu) &&
                    (EAP_SIM_CHALLENGE_REQ != pdu))
                {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_NEXT_REAUTH_ID  Attr Sent with PDU");
                    status = ERR_EAP_SIM_INVALID_ATTR;
                    goto exit;
                }

                /* Should be  > 1 */
                if (2 > attrLen )  {
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid AT_NEXT_REAUTH_ID  Len Attr Sent");
                    status = ERR_EAP_SIM_INVALID_ATTRLEN;
                    goto exit;
                }

                DIGI_MEMCPY((ubyte *)&eapSim->reauthIdLen,cur,2);
                eapSim->reauthIdLen = EAP_HTONS(eapSim->reauthIdLen);
                cur+=2; /* Actual Identity Len */

                if (eapSim->reauthId)
                {
                    FREE(eapSim->reauthId);
                    eapSim->reauthId = NULL;
                }

                eapSim->reauthId  = MALLOC(eapSim->reauthIdLen);
                if (NULL == eapSim->reauthId)
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }

                DIGI_MEMCPY(eapSim->reauthId,cur,eapSim->reauthIdLen);

                cur+= attrLen *4 - 4;
                eapSim->attrPresent |= EAP_SIM_AT_NEXT_REAUTH_ID_PRESENT;

                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECEIVED AT_NEXT_REAUTH_ID");

                break;
            }

            case EAP_SIM_AT_PADDING:
                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECEIVED AT_PADDING");
                /* intentionally fall-thru */
            default:
            {
                cur+= attrLen * 4 - 2;
                break;
            }
        }
    }

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simDecodeAttr: Error Decodong Attr, status = ", status);
    }

    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simValidateMandAttrs(eapSimCb *eapSim, eapSimPdus pdu)
{
    MSTATUS status = OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simValidateMandAttr: Handle = ", (sbyte4)((uintptr)eapSim));
    switch (pdu)
    {
        case EAP_SIM_START_REQ:
        {
            if (!(eapSim->attrPresent & EAP_SIM_AT_VERSION_LIST_PRESENT))
            {
                status = ERR_EAP_SIM_MANDATORY_ATTR_MISSING;
                goto exit;
            }

            break;
        }

        case EAP_SIM_START_RESP:
        {

            break;
        }

        case EAP_SIM_CHALLENGE_REQ:
        {
            if (!(eapSim->attrPresent & EAP_SIM_AT_RAND_PRESENT))
            {
                status = ERR_EAP_SIM_MANDATORY_ATTR_MISSING;
                goto exit;
            }
            if (!(eapSim->attrPresent & EAP_SIM_AT_MAC_PRESENT))
            {
                status = ERR_EAP_SIM_MANDATORY_ATTR_MISSING;
                goto exit;
            }

            break;
        }

        case EAP_SIM_CHALLENGE_RESP:
        {
            if (!(eapSim->attrPresent & EAP_SIM_AT_MAC_PRESENT))
            {
                 status = ERR_EAP_SIM_MANDATORY_ATTR_MISSING;
                 goto exit;
            }

            break;
        }

        case EAP_SIM_NOTIFICATION_REQ:
        {
            if (!(eapSim->attrPresent & EAP_SIM_AT_NOTIFICATION_PRESENT))
            {
                 status = ERR_EAP_SIM_MANDATORY_ATTR_MISSING;
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
                 status = ERR_EAP_SIM_MANDATORY_ATTR_MISSING;
                 goto exit;
            }

            break;
        }

        case EAP_SIM_REAUTH_REQ:
        {
            if (!(eapSim->attrPresent & EAP_SIM_AT_MAC_PRESENT))
            {
                 status = ERR_EAP_SIM_MANDATORY_ATTR_MISSING;
                 goto exit;
            }
            if (!(eapSim->attrPresent & EAP_SIM_AT_IV_PRESENT))
            {
                 status = ERR_EAP_SIM_MANDATORY_ATTR_MISSING;
                 goto exit;
            }
            if (!(eapSim->attrPresent & EAP_SIM_AT_ENCR_DATA_PRESENT))
            {
                 status = ERR_EAP_SIM_MANDATORY_ATTR_MISSING;
                 goto exit;
            }

            break;
        }

        case EAP_SIM_REAUTH_RESP:
        {
            if (!(eapSim->attrPresent & EAP_SIM_AT_MAC_PRESENT))
            {
                 status = ERR_EAP_SIM_MANDATORY_ATTR_MISSING;
                 goto exit;
            }
            if (!(eapSim->attrPresent & EAP_SIM_AT_IV_PRESENT))
            {
                 status = ERR_EAP_SIM_MANDATORY_ATTR_MISSING;
                 goto exit;
            }
            if (!(eapSim->attrPresent & EAP_SIM_AT_ENCR_DATA_PRESENT))
            {
                 status = ERR_EAP_SIM_MANDATORY_ATTR_MISSING;
                 goto exit;
            }

            break;
        }
        default:
        {
            status = ERR_EAP_SIM_UNKNOWN_PDU;
            goto exit;
        }
    }

    /* Both the Attributes must Exists Together  if present*/
    if ((eapSim->attrPresent & EAP_SIM_AT_IV_PRESENT))
    {
        if (!(eapSim->attrPresent & EAP_SIM_AT_ENCR_DATA_PRESENT))
        {
            status = ERR_EAP_SIM_MANDATORY_ATTR_MISSING;
            goto exit;
        }
    }

    if ((eapSim->attrPresent & EAP_SIM_AT_ENCR_DATA_PRESENT))
    {
        if (!(eapSim->attrPresent & EAP_SIM_AT_IV_PRESENT))
        {
            status = ERR_EAP_SIM_MANDATORY_ATTR_MISSING;
            goto exit;
        }
    }

    /*  Check that The certain parameters are not send in Clear Text */
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
         DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simValidateMandAttr: Error, status = ", status);
    }

    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simSelectVersion(eapSimCb *eapSim)
{
    /* From our list of Versions supported Match the first Version */
    MSTATUS status = ERR_EAP_SIM_VERSION_NOT_SELECTED;
    ubyte i=0,j =0;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simSelectVersion: Handle = ", (sbyte4)((uintptr)eapSim));

    while (i < eapSim->numVersionListImpl)
    {
        while (j < eapSim->numVersionList)
        {
            if (eapSim->versionListImpl[i] == eapSim->versionList[j])
            {
                eapSim->selectedVersion = eapSim->versionList[j];
                status = OK;
                goto exit;
            }

            j++;
        }

        i++;
    }
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simSelectVersion: Selected Version ", eapSim->selectedVersion);

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simSelectVersion: Error, status = ", status);
    }

    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simAddVersionList(eapSimCb *eapSim, ubyte *pkt, ubyte2 *attrLen)
{
    ubyte   i=0;
    ubyte   evenOdd;
    ubyte2  val;
    MSTATUS status = OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simAddVersionList: Handle = ", (sbyte4)((uintptr)eapSim));
    if (0 == eapSim->numVersionListImpl)
    {
        status = ERR_EAP_SIM_VERSION_LIST_NUM;
        goto exit;
    }

    *pkt = EAP_SIM_AT_VERSION_LIST;
    pkt++;

    evenOdd = (ubyte)(eapSim->numVersionListImpl % 2);

    /* Total Length */
    *pkt = (ubyte)(1 + eapSim->numVersionListImpl / 2);

    if (evenOdd)
    {
        *pkt = *pkt+1;
    }

    *attrLen = *pkt * 4;

    pkt++;

    /* Actual Version List  Bytes*/
    val = (eapSim->numVersionListImpl * 2);

    *pkt++  = (ubyte)((val >> 8) & 0xff);
    *pkt++ = (ubyte)(val & 0xff);

    while (i < eapSim->numVersionListImpl)
    {
        val = (eapSim->versionListImpl[i]);
        *pkt++  = (ubyte)((val >> 8) & 0xff);
        *pkt++ = (ubyte)(val & 0xff);
        i++;
    }

    /* Pad it up */
    if (evenOdd)
    {
       DIGI_MEMSET(pkt,0,2);
       pkt+=2;
    }

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Adding AT_VERSION_LIST");

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simAddVersionList: Error, status = ", status);
    }

    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simAddSelectedVersion(eapSimCb *eapSim, ubyte *pkt)
{
    ubyte2 val = (eapSim->selectedVersion);

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simAddSelectedVersion: Handle = ", (sbyte4)((uintptr)eapSim));

    *pkt = EAP_SIM_AT_SELECTED_VERSION;
    pkt++;

    /*Length */
    *pkt = 1;
    pkt++;

    /* Actual Version List */
    *pkt++  = (ubyte)((val >> 8) & 0xff);
    *pkt++ = (ubyte)(val & 0xff);

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Adding AT_SELECTED_VERSION");

    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simAddResultInd(eapSimCb *eapSim, ubyte *pkt)
{
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simAddresultInd: Handle = ", (sbyte4)((uintptr)eapSim));

    *pkt = EAP_SIM_AT_RESULT_IND;
    pkt++;

    /*Length */
    *pkt = 1;
    pkt++;

    /* Reserved */
    DIGI_MEMSET(pkt, 0,2);
    pkt+=2;

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Adding AT_RESULT_IND");

    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simAddClientErrCode(eapSimCb *eapSim, ubyte *pkt, ubyte2 clientErrCode)
{
    ubyte2 val = (clientErrCode);
    MOC_UNUSED(eapSim);

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simAddClientErrCode: Handle = ", (sbyte4)((uintptr)eapSim));

    *pkt = EAP_SIM_AT_CLIENT_ERROR_CODE;
    pkt++;

    /*Length */
    *pkt = 1;
    pkt++;

    /* Error Code */
    *pkt++  = (ubyte)((val >> 8) & 0xff);
    *pkt++ = (ubyte)(val & 0xff);

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Adding AT_CLIENT_ERR_CODE");

    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simAddCounterTooSmall(eapSimCb *eapSim, ubyte *pkt)
{
    MOC_UNUSED(eapSim);
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simAddCounterTooSmall: Handle = ", (sbyte4)((uintptr)eapSim));

    *pkt = EAP_SIM_AT_COUNTER_TOO_SMALL;
    pkt++;

    /*Length */
    *pkt = 1;
    pkt++;

    /* Reserved */
    DIGI_MEMSET(pkt,0,2);
    pkt+=2;

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Adding AT_COUNTER_TOO_SMALL");

    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simAddCounter(eapSimCb *eapSim, ubyte *pkt)
{
    ubyte2 val = (eapSim->counter);

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simAddCounter: Handle = ", (sbyte4)((uintptr)eapSim));

    *pkt = EAP_SIM_AT_COUNTER;
    pkt++;

    /*Length */
    *pkt = 1;
    pkt++;

    /* Counter */
    *pkt++  = (ubyte)((val >> 8) & 0xff);
    *pkt++ = (ubyte)(val & 0xff);

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Adding AT_COUNTER");

    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simAddNotificationCode(eapSimCb *eapSim, ubyte *pkt, ubyte2 notifCode)
{
    ubyte2 val = (notifCode);
    MOC_UNUSED(eapSim);

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simAddNotificationCode: Handle = ", (sbyte4)((uintptr)eapSim));

    *pkt = EAP_SIM_AT_NOTIFICATION;
    pkt++;

    /*Length */
    *pkt = 1;
    pkt++;

    /* Notif Code */
    *pkt++  = (ubyte)((val >> 8) & 0xff);
    *pkt++ = (ubyte)(val & 0xff);

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Adding AT_NOTIFICATION");

    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simAddIdentityReq(eapSimCb *eapSim, ubyte *pkt, ubyte identityReq)
{
    MOC_UNUSED(eapSim);
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simAddIdentityReq: Handle = ", (sbyte4)((uintptr)eapSim));

    *pkt = identityReq;
    pkt++;

    /*Length */
    *pkt = 1;
    pkt++;

    /* Reserved */
    DIGI_MEMSET(pkt, 0,2);
    pkt+=2;

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Adding AT_IDENTITY_REQ");

    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simAddNextIdentity(eapSimCb *eapSim, ubyte *pkt, ubyte identityReq, ubyte2 *len)
{
    /* Choose from Permanent/ Full Auth or Reauth Id */
    ubyte   filler;
    ubyte*  attrLen = 0;
    ubyte2  val;
    MSTATUS status = OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simAddNextIdentity: Handle = ", (sbyte4)((uintptr)eapSim));
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simAddNextIdentity: Type   = ", (sbyte4)identityReq);

    *pkt = identityReq;
    pkt++;

    /*Length */
    *pkt = 1;
    attrLen = pkt;
    pkt++;

    /* Reserved */

    if (EAP_SIM_AT_NEXT_PSEUDONYM == identityReq)
    {
        if ((0 == eapSim->psuedonymLen) || (NULL == eapSim->psuedonym))
        {
            status = ERR_EAP_SIM_IDENTITY_NOT_PRESENT;
            goto exit;
        }

        val = (eapSim->psuedonymLen);
    }
    else if (EAP_SIM_AT_NEXT_REAUTH_ID == identityReq)
    {
        if ((0 == eapSim->reauthIdLen) || (NULL == eapSim->reauthId))
        {
            status = ERR_EAP_SIM_IDENTITY_NOT_PRESENT;
            goto exit;
        }

        val = (eapSim->reauthIdLen);
    }
    else
    {
        status = ERR_EAP_SIM_INVALID_ID_TYPE;   /* EAP-TEAM: is this okay?  */
        goto exit;
    }

    *pkt++  = (ubyte)((val >> 8) & 0xff);
    *pkt++ = (ubyte)(val & 0xff);

    if (EAP_SIM_AT_NEXT_REAUTH_ID == identityReq)
        DIGI_MEMCPY(pkt, eapSim->reauthId,eapSim->reauthIdLen);
    else if (EAP_SIM_AT_NEXT_PSEUDONYM == identityReq)
        DIGI_MEMCPY(pkt, eapSim->psuedonym,eapSim->psuedonymLen);
    else
    {
        status = ERR_EAP_SIM_INVALID_ID_TYPE;
        goto exit;
    }

    filler = (ubyte)((val) % 4);
    *attrLen = *attrLen + (ubyte)((val) / 4);

    if (filler)
    {
        /* Actual Filler */
        filler = 4 - filler;
        *attrLen = *attrLen + 1;
    }

    pkt+=(val) + filler;

    *len = *attrLen * 4;

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Adding AT_NEXT_IDENTITY");

exit:
    if (OK > status)
         DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simAddnextIdentity: Error, status = ", status);

    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simAddIdentity(eapSimCb *eapSim, ubyte *pkt, ubyte identityReq, ubyte2 *len)
{
    /* Choose from Permanent/ Full Auth or Reauth Id */
    ubyte*  attrLen;
    ubyte   filler;
    ubyte2  val;
    MSTATUS status = OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simAddIdentity: Handle = ", (sbyte4)((uintptr)eapSim));
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simAddIdentity: Type   = ", (sbyte4)identityReq);

    *pkt = EAP_SIM_AT_IDENTITY;
    pkt++;

    /*Length */
    *pkt = 1;
    attrLen = pkt;
    pkt++;

    /* Reserved */

    /* Check That Atleast One Identity is present to send */
    if (0 == eapSim->permanentIdentityLen)
    {
        status = ERR_EAP_SIM_IDENTITY_NOT_PRESENT;
        goto exit;
    }

    if (EAP_SIM_AT_PERMANENT_ID_REQ == identityReq)
    {
        val = (eapSim->permanentIdentityLen);
        *pkt++  = (ubyte)((val >> 8) & 0xff);
        *pkt++ = (ubyte)(val & 0xff);

        DIGI_MEMCPY(pkt, eapSim->permanentIdentity, eapSim->permanentIdentityLen);

        filler = (ubyte)(eapSim->permanentIdentityLen % 4);
        *attrLen = *attrLen + (ubyte)(eapSim->permanentIdentityLen / 4);

        if (filler)
        {
            /* Actual Filler */
            filler = 4 - filler;
            *attrLen = *attrLen + 1;
        }

        pkt+=eapSim->permanentIdentityLen + filler;
        status = EAP_SIMSetIdentity(eapSim,
                   eapSim->permanentIdentity,eapSim->permanentIdentityLen);

        if (OK > status)
            goto exit;
    }

    /* If its requesting Full Auth, we should send psuedoUsername,if available,
       from the previous transaction , else send permanent id*/
    if (EAP_SIM_AT_FULLAUTH_ID_REQ == identityReq)
    {
        if (eapSim->psuedonym)
        {
            val = (eapSim->psuedonymLen);
            *pkt++  = (ubyte)((val >> 8) & 0xff);
            *pkt++ = (ubyte)(val & 0xff);

            DIGI_MEMCPY(pkt, eapSim->psuedonym,eapSim->psuedonymLen);

            filler = (ubyte)(eapSim->psuedonymLen % 4);
            *attrLen = *attrLen + (ubyte)(eapSim->psuedonymLen / 4);

            if (filler)
            {
                /* Actual Filler */
                filler = 4 - filler;
                *attrLen = *attrLen + 1;
            }

            pkt+=eapSim->psuedonymLen + filler;

            status = EAP_SIMSetIdentity(eapSim, eapSim->psuedonym, eapSim->psuedonymLen);

            if (OK > status)
                goto exit;
        }
        else
        {
            val = (eapSim->permanentIdentityLen);
            *pkt++  = (ubyte)((val >> 8) & 0xff);
            *pkt++ = (ubyte)(val & 0xff);

            DIGI_MEMCPY(pkt, eapSim->permanentIdentity,eapSim->permanentIdentityLen);

            filler = (ubyte)(eapSim->permanentIdentityLen % 4);
            *attrLen = *attrLen + (ubyte)(eapSim->permanentIdentityLen / 4);

            if (filler)
            {
                /* Actual Filler */
                filler = 4 - filler;
                *attrLen = *attrLen + 1;
            }

            pkt+=eapSim->permanentIdentityLen + filler;
            status = EAP_SIMSetIdentity(eapSim, eapSim->permanentIdentity,eapSim->permanentIdentityLen);

            if (OK > status)
                goto exit;
        }
    }

    if (EAP_SIM_AT_ANY_ID_REQ == identityReq)
    {
        /* Could be any .. If Reauthid is present send that, else if Psuedoname
           then send that else send permanent*/
        if (eapSim->reauthId)
        {
            val = (eapSim->reauthIdLen);

            *pkt++  = (ubyte)((val >> 8) & 0xff);
            *pkt++ = (ubyte)(val & 0xff);

            DIGI_MEMCPY(pkt, eapSim->reauthId,eapSim->reauthIdLen);

            filler = (ubyte)(eapSim->reauthIdLen % 4);
            *attrLen = *attrLen + (ubyte)(eapSim->reauthIdLen / 4);

            if (filler)
            {
                /* Actual Filler */
                filler = 4 - filler;
                *attrLen = *attrLen + 1;
            }

            pkt+=eapSim->reauthIdLen + filler;

            status = EAP_SIMSetIdentity(eapSim,
                       eapSim->reauthId,eapSim->reauthIdLen);

            if (OK > status)
                goto exit;

            /* Discard the Reauth Identity */
            FREE(eapSim->reauthId);
            eapSim->reauthId = NULL;
            eapSim->reauthIdLen = 0;

        }
        else if (eapSim->psuedonym)
        {
            val = (eapSim->psuedonymLen);
            *pkt++  = (ubyte)((val >> 8) & 0xff);
            *pkt++ = (ubyte)(val & 0xff);

            DIGI_MEMCPY(pkt, eapSim->psuedonym,eapSim->psuedonymLen);

            filler = (ubyte)(eapSim->psuedonymLen % 4);
            *attrLen = *attrLen + (ubyte)(eapSim->psuedonymLen / 4);

            if (filler)
            {
                /* Actual Filler */
                filler = 4 - filler;
                *attrLen = *attrLen + 1;
            }

            pkt+=eapSim->psuedonymLen + filler;

            status = EAP_SIMSetIdentity(eapSim,
                       eapSim->psuedonym,eapSim->psuedonymLen);

            if (OK > status)
                goto exit;
        }
        else
        {
            val = (eapSim->permanentIdentityLen);

            *pkt++  = (ubyte)((val >> 8) & 0xff);
            *pkt++ = (ubyte)(val & 0xff);

            DIGI_MEMCPY(pkt, eapSim->permanentIdentity,eapSim->permanentIdentityLen);

            filler = (ubyte)(eapSim->permanentIdentityLen % 4);
            *attrLen = *attrLen + (ubyte)(eapSim->permanentIdentityLen / 4);

            if (filler)
            {
                /* Actual Filler */
                filler = 4 - filler;
                *attrLen = *attrLen + 1;
            }

            pkt+=eapSim->permanentIdentityLen + filler;

            status = EAP_SIMSetIdentity(eapSim,
                       eapSim->permanentIdentity,eapSim->permanentIdentityLen);

            if (OK > status)
                goto exit;
        }
    }

    *len = *attrLen * 4;

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Adding AT_IDENTITY");

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simAddIdentity: Error, status = ", status);
    }

    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simAddIV(eapSimCb *eapSim, ubyte *pkt)
{
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simAddIV: Handle = ", (sbyte4)((uintptr)eapSim));
    *pkt = EAP_SIM_AT_IV;
    pkt++;

    /*Length */
    *pkt = 5;
    pkt++;

    /* Reserved */
    DIGI_MEMSET(pkt, 0,2);
    pkt+=2;

    RANDOM_numberGenerator(g_pRandomContext, eapSim->iv, EAP_SIM_IV_LEN);

    DIGI_MEMCPY(pkt, eapSim->iv,EAP_SIM_IV_LEN);
    pkt+=16;

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Adding AT_IV");

    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simAddNonce_S(eapSimCb *eapSim, ubyte *pkt)
{
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simAddNonce_S: Handle = ", (sbyte4)((uintptr)eapSim));
    *pkt = EAP_SIM_AT_NONCE_S;
    pkt++;

    /*Length */
    *pkt = 5;
    pkt++;

    /* Reserved */
    DIGI_MEMSET(pkt, 0,2);
    pkt+=2;

    RANDOM_numberGenerator(g_pRandomContext, eapSim->nonce_s, EAP_SIM_NONCE_S_LEN);

    DIGI_MEMCPY(pkt, eapSim->nonce_s,EAP_SIM_NONCE_S_LEN);
    pkt+=16;

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Adding AT_NONCE_S");

    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simAddNonceMT(eapSimCb *eapSim, ubyte *pkt)
{
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simAddNonceMT: Handle = ", (sbyte4)((uintptr)eapSim));
    *pkt = EAP_SIM_AT_NONCE_MT;
    pkt++;

    /*Length */
    *pkt = 5;
    pkt++;

    /* Reserved */
    DIGI_MEMSET(pkt, 0,2);
    pkt+=2;

    RANDOM_numberGenerator(g_pRandomContext, eapSim->nonce_mt, EAP_SIM_NONCE_MT_LEN);

    DIGI_MEMCPY(pkt, eapSim->nonce_mt,EAP_SIM_NONCE_MT_LEN);
    pkt+=16;

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Adding AT_NONCE_MT");

    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simAddMAC(eapSimCb *eapSim, ubyte *pkt)
{
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simAddMAC: Handle = ", (sbyte4)((uintptr)eapSim));

    *pkt = EAP_SIM_AT_MAC;
    pkt++;

    /*Length */
    *pkt = 5;
    pkt++;

    /* Reserved */
    DIGI_MEMSET(pkt,0,2);
    pkt+=2;

    DIGI_MEMCPY(pkt, eapSim->mac,EAP_SIM_MAC_LEN);
    pkt+=16;

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Adding AT_MAC");

    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simAddEncr(eapSimCb *eapSim, ubyte *pkt)
{
    MOC_UNUSED(eapSim);
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simAddEncr: Handle = ", (sbyte4)((uintptr)eapSim));

    *pkt = EAP_SIM_AT_ENCR_DATA;
    pkt++;

    /*Length */
    *pkt = 0;
    pkt++;

    /* Reserved */
    DIGI_MEMSET(pkt,0,2);

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Adding AT_ENCR_DATA");

    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simAddPad(eapSimCb *eapSim, ubyte *pkt, ubyte2 padLen)
{
    MOC_UNUSED(eapSim);
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simAddPad: Handle = ", (sbyte4)((uintptr)eapSim));

    *pkt = EAP_SIM_AT_PADDING;
    pkt++;

    /*Length */
    *pkt = (ubyte)(padLen / 4);
    pkt++;

    /* Reserved Padding*/
    DIGI_MEMSET(pkt,0,padLen - 2);

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Adding AT_PADDING");

    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simAddRand(eapSimCb *eapSim, ubyte *pkt)
{
    ubyte   i;
    MSTATUS status =OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simAddRand: Handle = ", (sbyte4)((uintptr)eapSim));

    *pkt = EAP_SIM_AT_RAND;
    pkt++;

    /*Length */
    *pkt = 1 +  eapSim->numRand * 4;
    pkt++;

    /* Reserved */
    DIGI_MEMSET(pkt, 0,2);
    pkt+=2;

    if (!(eapSim->eapSimCfg.aka))
    {
        if ((2 > eapSim->numRand) || (3 < eapSim->numRand))
        {
            status = ERR_EAP_SIM_INVALID_NUM_RAND;
            goto exit;
        }
    }

    for (i=0;i< eapSim->numRand;i++)
    {
        DIGI_MEMCPY(pkt, eapSim->rand[i],EAP_SIM_RAND_LEN);
        pkt+=16;
    }

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Adding AT_RAND");

exit:
    if (OK > status)
    {
         DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simAddRand: Error, status = ", status);
    }

    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simCalculateMac(eapSimCb *eapSim,
                    ubyte *pkt, ubyte2 pktLen,
                    ubyte *mac,
                    ubyte *exData, ubyte2 exDataLen)
{
    ubyte           hmac[SHA_HASH_RESULT_SIZE];
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status = OK;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto exit;

    status = HMAC_SHA1(MOC_HASH(hwAccelCtx) eapSim->k_aut,
                      EAP_SIM_KAUT_LEN, pkt, pktLen, exData, exDataLen, hmac);

    DIGI_MEMCPY(mac,hmac,EAP_SIM_MAC_LEN);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
exit:
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simDecryptBuf(eapSimCb *eapSim)
{
    BulkCtx         ctx = NULL;
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status = OK;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_Process(MOC_SYM(hwAccelCtx) &CRYPTO_AESSuite, eapSim->k_encr, 16, eapSim->iv,
        eapSim->encr_data,eapSim->encr_dataLen, 0);
#else
    ctx = CreateAESCtx(MOC_SYM(hwAccelCtx) eapSim->k_encr, 16, 0);

    status = DoAES(MOC_SYM(hwAccelCtx) ctx,
                   eapSim->encr_data,eapSim->encr_dataLen,
                   0/*encrypt */, eapSim->iv);

    DeleteAESCtx(MOC_SYM(hwAccelCtx) &ctx);
#endif

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
exit:
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simEncryptBuf(eapSimCb *eapSim, ubyte *pkt, ubyte2 pktLen)
{
    BulkCtx         ctx = NULL;
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status = OK;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_Process(MOC_SYM(hwAccelCtx) &CRYPTO_AESSuite, eapSim->k_encr, 16, eapSim->iv,
        (ubyte *)pkt,(sbyte4)pktLen, 1);
#else
    ctx = CreateAESCtx(MOC_SYM(hwAccelCtx) (ubyte *)eapSim->k_encr, (sbyte4)16,(sbyte4) 1);

    if (NULL == ctx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    status = DoAES(MOC_SYM(hwAccelCtx) ctx,
                   (ubyte *)pkt,(sbyte4)pktLen,
                   (sbyte4)1, (ubyte *)eapSim->iv);

    DeleteAESCtx(MOC_SYM(hwAccelCtx) &ctx);
exit:
#endif

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simGenerateKeys(eapSimCb *eapSim)
{
    ubyte   buf[160];
    MSTATUS status;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simGenerateKey: Handle = ", (sbyte4)((uintptr)eapSim));

    DIGI_MEMSET(buf,0,sizeof(buf));

    status = eap_sim_prf(eapSim->masterKey,buf,sizeof(buf));

    /*First 16 Bytes ENCR */
    DIGI_MEMCPY(eapSim->k_encr,buf,16);

    /*Next  16 Bytes K_Aut */
    DIGI_MEMCPY(eapSim->k_aut,buf+16,16);


    /*Next  64 Bytes msk */
    DIGI_MEMCPY(eapSim->k_msk,buf+32,64);


    /*Next  64 Bytes emsk */
    DIGI_MEMCPY(eapSim->k_emsk,buf+96,64);

#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "ENCR Key is ");
    EAP_PrintBytes( eapSim->k_encr ,16);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "AUT Key is ");
    EAP_PrintBytes( eapSim->k_aut ,16);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "MSK  is ");
    EAP_PrintBytes( eapSim->k_msk ,64);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "EMSK  is ");
    EAP_PrintBytes( eapSim->k_emsk ,64);
#endif

    return status;

}

/*------------------------------------------------------------------*/
/* Return Keys Common for both SIM/AKA*/

/*! Get an EAP-SIM session key.
This function (called by the authenticator or peer) retrieves the specified
type of EAP-SIM session key.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_SIM__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_sim.h

\param eapSim   EAP-SIM session handle returned from EAP_SIMInitSession.
\param keyType  Any of the $eapSimKeyType$ enumerated values (defined in eap_sim.h).
\param key      On return, pointer to the key.
\param keyLen   On return, pointer to the number of bytes in the key ($key$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_SIMgetKey(eapSimCb *eapSim, eapSimKeyType keyType, ubyte **key, ubyte4 *keyLen)
{
    MSTATUS status = OK;

    switch (keyType)
    {
        case EAP_SIM_MASTER_KEY:
        {
            *key = eapSim->masterKey;
            *keyLen = SHA_HASH_RESULT_SIZE;
            status = OK;
            break;
        }
        case EAP_SIM_ENCR_KEY:
        {
            *key = eapSim->k_encr;
            *keyLen = 16;
            status = OK;
            break;
        }
        case EAP_SIM_AUT_KEY:
        {
            *key = eapSim->k_aut;
            *keyLen = 16;
            status = OK;
            break;
        }
        case EAP_SIM_MSK_KEY:
        {
            *key = eapSim->k_msk;
            *keyLen = 64;
            status = OK;
            break;
        }
        case EAP_SIM_EMSK_KEY:
        {
            *key = eapSim->k_emsk;
            *keyLen = 64;
            status = OK;
            break;
        }
        default:
        {
            status = ERR_EAP_SIM_INVALID_KEY_TYPE;
            break;
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simGenerateReauthKeys(eapSimCb *eapSim, ubyte *rmk)
{
    ubyte   buf[160];
    MSTATUS status;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simGenerateReauthKey: Handle = ", (sbyte4)((uintptr)eapSim));
    DIGI_MEMSET(buf,0,sizeof(buf));

    status = eap_sim_prf(rmk,buf,sizeof(buf));

    /* First 64 Byte Master Session Key */
    DIGI_MEMCPY(eapSim->k_msk,buf,64);


    /*Next  64 Bytes emsk */
    DIGI_MEMCPY(eapSim->k_emsk,buf+64,64);


#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Reauth MSK  is ");
    EAP_PrintBytes( eapSim->k_msk ,64);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Reauth EMSK  is ");
    EAP_PrintBytes( eapSim->k_emsk ,64);
#endif
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
eap_simGenerateReauthMasterKey(eapSimCb *eapSim, ubyte *rmk)
{
    ubyte           shaOutput[SHA_HASH_RESULT_SIZE];
    shaDescr        *pShaContext = NULL;
    ubyte           counter[2];
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simGenerateReauthMasterKey: Handle = ", (sbyte4)((uintptr)eapSim));

    if (OK > (status = SHA1_allocDigest(MOC_HASH(hwAccelCtx)(BulkCtx*) &pShaContext)))
        goto exit;

    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) pShaContext)))
        goto exit;

    /* Master Key = SHA1(Identity|Counter|NONCE_S|MK) */

    /* Last Identity Used (AT_IDENTITY or Identity Resp) */
    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) pShaContext, eapSim->identity, eapSim->identityLen)))
        goto exit;

    counter[0] = (eapSim->counter >> 8) & 0xFF;
    counter[1] = (eapSim->counter) & 0xFF;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) pShaContext, (ubyte *)counter, 2)))
        goto exit;


    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) pShaContext, eapSim->nonce_s, EAP_SIM_NONCE_S_LEN)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) pShaContext, (ubyte *)eapSim->masterKey, EAP_SIM_MK_LEN)))
        goto exit;


    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) pShaContext, shaOutput)))
        goto exit;

    DIGI_MEMCPY(rmk, shaOutput, SHA_HASH_RESULT_SIZE);

#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Reauth MasterKey   is ");
    EAP_PrintBytes( rmk ,16);
#endif
exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simGenerateReauthMasterKey: Error, status = ", status);
    }
    SHA1_freeDigest(MOC_HASH(hwAccelCtx) (BulkCtx*)&pShaContext);
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simGenerateMasterKey(eapSimCb *eapSim)
{
    ubyte           shaOutput[SHA_HASH_RESULT_SIZE];
    shaDescr        *pShaContext = NULL;
    ubyte2          i,j;
    ubyte           selVer[2];
    ubyte*          listVer=NULL;
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simGenerateMasterKey: Handle = ", (sbyte4)((uintptr)eapSim));

    if (OK > (status = SHA1_allocDigest(MOC_HASH(hwAccelCtx)(BulkCtx*) &pShaContext)))
        goto exit;

    if (OK > (status = SHA1_initDigest(MOC_HASH(hwAccelCtx) pShaContext)))
        goto exit;

    /* Master Key = SHA1(Identity|n*Kc|NONCE_MT|Version List|Sel Ver) */

    /* Last Identity Used (AT_IDENTITY or Identity Resp) */
    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) pShaContext, eapSim->identity, eapSim->identityLen)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) pShaContext, eapSim->kC, eapSim->numRand*EAP_SIM_KC_LEN)))
        goto exit;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) pShaContext, eapSim->nonce_mt, EAP_SIM_NONCE_MT_LEN)))
        goto exit;

    listVer   = MALLOC(eapSim->numVersionList * 2);
    if (!listVer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

        for (i = 0;i < eapSim->numVersionList;i++)
        {
            j = EAP_HTONS(eapSim->versionList[i]);
            DIGI_MEMCPY(listVer + 2 * i,(ubyte *)&j,2);
        }


    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) pShaContext, (ubyte *)listVer, eapSim->numVersionList * 2 )))
        goto exit;

    selVer[0] = (eapSim->selectedVersion >> 8) & 0xFF;
    selVer[1] = eapSim->selectedVersion & 0xFF;

    if (OK > (status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) pShaContext, (ubyte *)selVer, 2)))
        goto exit;

    if (OK > (status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) pShaContext, shaOutput)))
        goto exit;

    DIGI_MEMCPY(eapSim->masterKey, shaOutput, SHA_HASH_RESULT_SIZE);

#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Identity is ");
    EAP_PrintBytes(eapSim->identity, eapSim->identityLen);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Kc is ");
    EAP_PrintBytes(eapSim->kC, eapSim->numRand*EAP_SIM_KC_LEN);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "NonceMT is ");
    EAP_PrintBytes(eapSim->nonce_mt, EAP_SIM_NONCE_MT_LEN);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "VersionList is ");
    EAP_PrintBytes(listVer, eapSim->numVersionList * 2);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Sel Version is ");
    EAP_PrintBytes(selVer, 2);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Master Key is ");
    EAP_PrintBytes( eapSim->masterKey ,SHA_HASH_RESULT_SIZE);
#endif
exit:
    if (listVer)
        FREE(listVer);

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simGenerateMasterKey: Error, status = ", status);
    }

    SHA1_freeDigest(MOC_HASH(hwAccelCtx) (BulkCtx*)&pShaContext);

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simParseNotification(eapSimCb *eapSim)
{

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simParseNotification: Handle = ", (sbyte4)((uintptr)eapSim));
    switch(eapSim->notifCode)
    {
        case 1031:
        {
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "User has not subscribed to the requested service");
            break;
        }

        case 1026:
        {
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Temporarily denied access to the requested service");
            break;
        }

        case 16384:
        case 0:
        {
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "General Failure");
            break;
        }

        case 32768:
        {
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Success");
            break;
        }

        default:
        {
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Default Notif Value ");
            DEBUG_INT(DEBUG_EAP_MESSAGE,eapSim->notifCode);
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "");

            break;
        }
    }

    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simParseClientError(eapSimCb *eapSim)
{
    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simParseClientError: Handle = ", (sbyte4)((uintptr)eapSim));
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, "eap_simParseClientError: Client Error Code Received : ");

    switch(eapSim->clientErrCode)
    {
        case 0:
        {
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Unable to process Packet");
            break;
        }

        case 1:
        {
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Unsupported Version");
            break;
        }

        case 2:
        {
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Insufficient number of challenges");
            break;
        }

        case 3:
        {
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Rands are not fresh");
            break;
        }

        default:
        {
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Default Client Err Value ");
            DEBUG_INT(DEBUG_EAP_MESSAGE,eapSim->clientErrCode);
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "");
            break;
        }
    }

    return OK;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_EAP_AUTH__

/*! Build a $Sim Start Request$ packet.
This function (typically called by the authenticator) builds a $Sim Start
Request$ packet based on the specified identity. The resultant packet, returned
through the $pkt$ parameter, can then be transmitted by making a call to
EAP_ulTransmit.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_SIM__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_sim.h

\param eapSim           EAP-SIM session handle returned from EAP_SIMInitSession.
\param pkt              On return, pointer to generated EAP-SIM Notification Request packet.
\param pktLen           On return, pointer to umber of bytes in generated packet ($pkt$).
\param id_type          Any of the $eapSimIdType$ enumeration values (defined in eap_sim.h):\n
\n
&bull; $EAP_SIM_PERMANENT_ID_TYPE$\n
&bull; $EAP_SIM_FULLAUTH_ID_TYPE$\n
&bull; $EAP_SIM_FASTREAUTH_ID_TYPE$
\param id               EAP request header ID (unique to this session).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_SIMSendStartReq
\sa EAP_SIMSendChallengeReq
\sa EAP_SIMSendNotificationReq
\sa EAP_SIMSendReauthReq

*/
extern MSTATUS
EAP_SIMSendStartReq(eapSimCb *eapSim, ubyte **pkt, ubyte4 *pktLen,
                    ubyte id_type, ubyte id)
{
    ubyte*      cur = NULL;
    ubyte2      attrLen = 0;
    eapHdr_t*   eapHdr;
    MSTATUS     status = OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simSendStartReq: Handle = ", (sbyte4)((uintptr)eapSim));
    /* Order of Id is ANY/FAST/PERM */

    /* Limit # Start Req per round to 3 */
    if (3 < eapSim->numIdReq)
    {
        status  = ERR_EAP_SIM_TOO_MANY_ID_REQ;
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

    *cur++ = EAP_TYPE_SIM;
    *cur++ = EAP_SIM_SUBTYPE_START;
    *cur++ = 0;
    *cur++ = 0;

    *pktLen +=4;
    status = eap_simAddVersionList(eapSim,cur,&attrLen);
    if (OK > status)
        goto exit;

    *pktLen +=attrLen;
    cur+=attrLen;

    /* Send the ID Request Attribute */
    if (id_type)
    {
        status = eap_simAddIdentityReq(eapSim,cur,id_type);
        if (OK > status)
            goto exit;

        *pktLen +=4;
        cur+=4;
    }

    DIGI_HTONS((ubyte *)*pkt + 2,*pktLen);
    eapSim->numIdReq++;

exit:
    if (OK > status)
    {
        if (*pkt)
            FREE(*pkt);

        *pkt = NULL;
        *pktLen = 0;

        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "EAP_SIMSendStartReq: Error, status = ", status);
    }

    return status;
}

#endif /*__ENABLE_DIGICERT_EAP_AUTH__*/

/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simSendStartResp(eapSimCb *eapSim, ubyte **pkt, ubyte4 *pktLen, ubyte id)
{
    ubyte*      cur = NULL;
    ubyte2      attrLen = 0;
    eapHdr_t*   eapHdr;
    MSTATUS     status = OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simSendStartResp: Handle = ", (sbyte4)((uintptr)eapSim));
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

    *cur++ = EAP_TYPE_SIM;
    *cur++ = EAP_SIM_SUBTYPE_START;
    *cur++ = 0;
    *cur++ = 0;

    *pktLen +=4;

    status = eap_simAddSelectedVersion(eapSim,cur);
    if (OK > status)
        goto exit;

    *pktLen +=4;
    cur+=4;

    if (eapSim->id_requested)
    {
        status = eap_simAddIdentity(eapSim,cur,eapSim->id_requested,&attrLen);
        if (OK > status)
            goto exit;

        *pktLen +=attrLen;
        cur+=attrLen;
    }

    status = eap_simAddNonceMT(eapSim,cur);
    if (OK > status)
        goto exit;

    *pktLen +=20;
    cur+=20;

    DIGI_HTONS((ubyte *)*pkt + 2,*pktLen);

exit:
    if (OK > status)
    {
        if (*pkt)
            FREE(*pkt);

        *pkt = NULL;
        *pktLen = 0;

        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eapsimSendStartResp: Error, status = ", status);
    }

    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simSendReauthResp(eapSimCb *eapSim, ubyte **pkt, ubyte4 *pktLen, ubyte id)
{
    ubyte*      cur = NULL;
    ubyte*      encrData;
    ubyte*      encrDataLen;
    ubyte2      plainTxtLen = 0;
    ubyte2      pad = 0;
    eapHdr_t*   eapHdr;
    MSTATUS     status = OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simSendReauthResp: Handle = ", (sbyte4)((uintptr)eapSim));
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

    if (eapSim->eapSimCfg.aka)
        *cur++ = EAP_TYPE_AKA;
    else
        *cur++ = EAP_TYPE_SIM;
   *cur++ = EAP_SIM_SUBTYPE_REAUTHENTICATION;
   *cur++ = 0;
   *cur++ = 0;

   *pktLen +=4;

   if (eapSim->eapSimCfg.send_result_ind)
   {
       status = eap_simAddResultInd(eapSim,cur);

       if (OK > status)
           goto exit;

       *pktLen +=4;
       cur+=4;
   }

    /* Calculate Keys */
    status = eap_simGenerateMasterKey(eapSim);
    if (OK > status)
        goto exit;

    /* Generate K_AUT/MSK/EMSK */
    status = eap_simGenerateKeys(eapSim);
    if (OK > status)
        goto exit;

    /* Encrypt these  and Add the IV and ENCR */
    status = eap_simAddIV(eapSim,cur);
    if (OK > status)
        goto exit;

    cur += 20;
    *pktLen += 20;

    if (OK > (status = eap_simAddEncr(eapSim,cur)))
        goto exit;

    encrDataLen = cur+1;
    *encrDataLen = 1; /*Set It to 1 */
    cur+=4;
    *pktLen +=4;

    encrData = cur;

    /* Add Counter*/
    status = eap_simAddCounter(eapSim,cur);
    if (OK > status)
        goto exit;


    cur+=4;
    plainTxtLen +=4;

    /* Add Counter Too Small if required*/
    if (eapSim->counterTooSmall)
    {
        status = eap_simAddCounterTooSmall(eapSim,cur);
        if (OK > status)
            goto exit;
    }

    cur+=4;
    plainTxtLen +=4;

    /* Plain Text Should be a multiple of 16 */
    pad = plainTxtLen % 16;

    if (pad)  /* Should be 4,8 or 12 */
    {
        /* Actual Pad */
        pad = 16 - pad;
        status = eap_simAddPad(eapSim,cur,pad);
        if (OK > status)
            goto exit;

        plainTxtLen = plainTxtLen + pad;
    }

    cur+=pad;
    *pktLen+=plainTxtLen;
    *encrDataLen = *encrDataLen + (ubyte)(plainTxtLen/4);

    /* Encrypt the whole PLaintxt buffer */
    status = eap_simEncryptBuf(eapSim,encrData,plainTxtLen);
    if (OK > status)
        goto exit;

    DIGI_MEMSET(eapSim->mac,0,EAP_SIM_MAC_LEN);
    status = eap_simAddMAC(eapSim,cur);
    *pktLen +=20;
    cur+=4;

    DIGI_HTONS((ubyte *)*pkt + 2,*pktLen);

    status = eap_simCalculateMac(eapSim,*pkt,(ubyte2)(*pktLen),eapSim->mac,
                        eapSim->nonce_s,EAP_SIM_NONCE_S_LEN);
    if (OK > status)
        goto exit;

    DIGI_MEMCPY(cur,eapSim->mac,EAP_SIM_MAC_LEN);

    eapSim->attemptfullAuthRound = 0;
    eapSim->fullAuthRoundSuccess = 0;
    eapSim->attemptreAuthRound = 1;

    if (!(eapSim->counterTooSmall))
        eapSim->reAuthRoundSuccess = 1;

exit:
    if (OK > status)
    {
        if (*pkt)
            FREE(*pkt);

        *pkt = NULL;
        *pktLen = 0;

        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simSendReauthResp: Error, status = ", status);
    }

    return status;
}


/*------------------------------------------------------------------*/

/*! Build a $SIM FAST Reauthentication Request$ packet.
This function builds a $SIM FAST Reauthentication Request$ packet based on the
specified parameters. It is used by the SIM authenticator for fast (quick)
reauthentication.

\since 2.02
\version 2.02 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_SIM__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_sim.h

\param eapSim           EAP-SIM session handle returned from EAP_SIMInitSession.
\param pkt              On return, pointer to generated EAP-SIM Reauthorization Request packet.
\param pktLen           On return, pointer to umber of bytes in generated packet ($pkt$).
\param at_next_reauthid Pointer to reauthorization ID to send to the peer.
\param at_reauthid_len  Number of bytes in reauthorization ID ($at_next_reauthid$).
\param id               EAP request header ID (unique to this session).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_SIMSendStartReq
\sa EAP_SIMSendChallengeReq
\sa EAP_SIMSendNotificationReq

*/
extern MSTATUS
EAP_SIMSendReauthReq(eapSimCb *eapSim, ubyte **pkt, ubyte4 *pktLen,
                     ubyte *at_next_reauthid, ubyte2 at_reauthid_len,
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

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simSendReauthReq: Handle = ", (sbyte4)((uintptr)eapSim));
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

    if (eapSim->eapSimCfg.aka)
        *cur++ = EAP_TYPE_AKA;
    else
        *cur++ = EAP_TYPE_SIM;
    *cur++ = EAP_SIM_SUBTYPE_REAUTHENTICATION;
    *cur++ = 0;
    *cur++ = 0;

    *pktLen +=4;

    if (eapSim->eapSimCfg.send_result_ind)
    {
        if (OK > (status = eap_simAddResultInd(eapSim,cur)))
            goto exit;

        *pktLen +=4;
        cur+=4;
    }

     /* Calculate Keys */
     status = eap_simGenerateMasterKey(eapSim);
     if (OK > status)
         goto exit;

     /* Generate K_AUT/MSK/EMSK */
     status = eap_simGenerateKeys(eapSim);
     if (OK > status)
         goto exit;

    eapSim->counter++;

    /* Encrypt these  and Add the IV and ENCR */
    status = eap_simAddIV(eapSim,cur);
    if (OK > status)
        goto exit;

    cur+=20;
    *pktLen +=20;

    status = eap_simAddEncr(eapSim,cur);
    encrDataLen = cur+1;
    *encrDataLen = 1; /*Set It to 1 */
    cur+=4;
    *pktLen +=4;

    encrData = cur;

    /* Add Counter  And NONCE_S*/
    status = eap_simAddCounter(eapSim,cur);
    if (OK > status)
        goto exit;

    cur+=4;
    plainTxtLen +=4;

    status = eap_simAddNonce_S(eapSim,cur);
    if (OK > status)
        goto exit;

    cur+=20;
    plainTxtLen +=20;

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

        if (OK > status)
            goto exit;

        plainTxtLen = plainTxtLen + attrLen;
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

        plainTxtLen = plainTxtLen + pad;
    }

    cur+=pad;
    *pktLen+=plainTxtLen;
    *encrDataLen = *encrDataLen + (ubyte)(plainTxtLen/4);

    /* Encrypt the whole PLaintxt buffer */
    status = eap_simEncryptBuf(eapSim,encrData,plainTxtLen);
    if (OK > status)
        goto exit;

    DIGI_MEMSET(eapSim->mac,0,EAP_SIM_MAC_LEN);

    status = eap_simAddMAC(eapSim,cur);
    if (OK > status)
        goto exit;

    *pktLen +=20;
    cur+=4;

    DIGI_HTONS((ubyte *)*pkt + 2,*pktLen);

    status = eap_simCalculateMac(eapSim,*pkt,(ubyte2)(*pktLen),eapSim->mac, 0,0);

    DIGI_MEMCPY(cur,eapSim->mac,EAP_SIM_MAC_LEN);

    eapSim->attemptfullAuthRound = 0;
    eapSim->fullAuthRoundSuccess = 0;
    eapSim->attemptreAuthRound = 1;
    eapSim->reAuthRoundSuccess = 0;

exit:
    if (OK > status)
    {
        if (*pkt)
            FREE(*pkt);

        *pkt = NULL;
        *pktLen = 0;

        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "EAP_SIMSendReauthReq: Error, status = ", status);
    }

    return status;

}


/*------------------------------------------------------------------*/

/*! Build a $Sim Challenge Request$ packet.
This function (typically called by the authenticator) builds a $Sim Challenge
Request$ packet based on the specified parameters. (For details about how the
random numbers and keys are used, refer to the following Web page:
http://www.gsm-security.net/faq/gsm-ki-kc-rand-sres.shtml .)

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_SIM__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_sim.h

\param eapSim           EAP-SIM session handle returned from EAP_SIMInitSession.
\param pkt              On return, pointer to generated EAP-SIM Challenge Request packet.
\param pktLen           On return, pointer to umber of bytes in generated packet ($pkt$).
\param rand             Pointer to 16-byte random number to send to the peer.
\param num_rand         Number of 16-byte random numbers to send, from 1 to 3. (Recommended values are 2 or 3.)
\param kC               64-bit ciphering key used as a session key.
\param sRes             32-bit SRES (signed response) generated by the SIM device.
\param at_next_psuedo   Pseudo identity to send to the peer.
\param at_psuedo_len    Number of bytes in pseudo identity ($at_next_psuedo$).
\param at_next_reauthid Reauthorization ID to send to the peer.
\param at_reauthid_len  Number of bytes in reauthorization ID ($at_next_reauthid$).
\param id               EAP request header ID (unique to this session).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_SIMSendStartReq
\sa EAP_SIMSendChallengeReq
\sa EAP_SIMSendNotificationReq
\sa EAP_SIMSendReauthReq

*/
extern MSTATUS
EAP_SIMSendChallengeReq(eapSimCb *eapSim, ubyte **pkt, ubyte4 *pktLen,
                        ubyte *rand, ubyte2 num_rand,
                        ubyte *kC, ubyte *sRes,
                        ubyte *at_next_psuedo, ubyte2 at_psuedo_len,
                        ubyte *at_next_reauthid, ubyte2 at_reauthid_len,
                        ubyte id)
{
    ubyte*      cur = NULL;
    ubyte       i;
    ubyte*      encrData;
    ubyte*      encrDataLen;
    ubyte2      attrLen = 0;
    ubyte2      plainTxtLen = 0;
    ubyte2      pad = 0;
    eapHdr_t*   eapHdr;
    MSTATUS     status = OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simSendChallengeReq: Handle = ", (sbyte4)((uintptr)eapSim));
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

    *pktLen = sizeof(eapHdr_t);
    cur = *pkt + sizeof(eapHdr_t);

    *cur++ = EAP_TYPE_SIM;
    *cur++ = EAP_SIM_SUBTYPE_CHALLENGE;
    *cur++ = 0;
    *cur++ = 0;

    *pktLen +=4;

    for (i=0;i<num_rand;i++)
    {
        DIGI_MEMCPY(eapSim->rand[i],rand+i*16,EAP_SIM_RAND_LEN);
    }

    DIGI_MEMCPY(eapSim->kC,kC,num_rand*8);
    DIGI_MEMCPY(eapSim->sRes,sRes,num_rand*4);

    eapSim->numRand = (ubyte)num_rand;

    status = eap_simAddRand(eapSim,cur);
    if (OK > status)
        goto exit;

    *pktLen +=num_rand * EAP_SIM_RAND_LEN  + 4;
    cur+= num_rand * EAP_SIM_RAND_LEN +4;

    if (eapSim->eapSimCfg.send_result_ind)
    {
        status = eap_simAddResultInd(eapSim,cur);
        if (OK > status)
            goto exit;
        *pktLen +=4;
        cur+=4;
    }

    /* Calculate Keys */
    status = eap_simGenerateMasterKey(eapSim);
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
            if (OK > status)
                goto exit;
            plainTxtLen = plainTxtLen + attrLen;
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

            if (OK > status)
                goto exit;

            plainTxtLen = plainTxtLen + attrLen;
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

            plainTxtLen = plainTxtLen + pad;
        }

        cur+=pad;
        *pktLen+=plainTxtLen;
        *encrDataLen = *encrDataLen + (ubyte)(plainTxtLen/4);

        /* Encrypt the whole PLaintxt buffer */
        status = eap_simEncryptBuf(eapSim,encrData,plainTxtLen);
        if (OK > status)
            goto exit;

    }

    DIGI_MEMSET(eapSim->mac,0,EAP_SIM_MAC_LEN);
    status = eap_simAddMAC(eapSim,cur);
    if (OK > status)
        goto exit;

    *pktLen +=20;
    cur+=4;

    DIGI_HTONS((ubyte *)*pkt + 2,*pktLen);

    status = eap_simCalculateMac(eapSim,*pkt,(ubyte2)(*pktLen),eapSim->mac,
                        eapSim->nonce_mt,EAP_SIM_NONCE_MT_LEN);

    if (OK > status)
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

        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "EAP_SIMSendChallengeReq: Error, status = ", status);
    }

    return status;

}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simSendChallengeRespPkt(eapSimCb *eapSim, ubyte **pkt,
                            ubyte4 *pktLen, ubyte id)
{
    ubyte*      cur = NULL;
    eapHdr_t*   eapHdr;
    MSTATUS     status = OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simSendChallengeRespPkt: Handle = ", (sbyte4)((uintptr)eapSim));
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

    *cur++ = EAP_TYPE_SIM;
    *cur++ = EAP_SIM_SUBTYPE_CHALLENGE;
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

    DIGI_MEMSET(eapSim->mac,0,EAP_SIM_MAC_LEN);

    status = eap_simAddMAC(eapSim,cur);
    if (OK > status)
        goto exit;

    *pktLen +=20;
    cur+=4;

    DIGI_HTONS((ubyte *)*pkt + 2,*pktLen);

    status = eap_simCalculateMac(eapSim,*pkt,(ubyte2)(*pktLen),
                                 eapSim->mac,eapSim->sRes,eapSim->numRand*4);
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

        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simSendChallengeResp: Error, status = ", status);
    }

    return status;
}


/*------------------------------------------------------------------*/

/*! Build a $Sim Notification Request$ packet.
This function (typically called by the authenticator) builds a $Sim Notification
Request$ packet based on the specified parameters.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_SIM__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_sim.h

\param eapSim           EAP-SIM session handle returned from EAP_SIMInitSession.
\param pkt              On return, pointer to generated EAP-SIM Notification Request packet.
\param pktLen           On return, pointer to umber of bytes in generated packet ($pkt$).
\param at_counter       $AT_COUNTER$ value to send to the peer; once the counter
reaches the configurable maximum value, a full authentication instead of a FAST
reauthentication is required.
\param notification_code    Notification code as defined in RFC&nbsp;4186 (refer to
sections 6 and 10.18).
\param id               EAP request header ID (unique to this session).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_SIMSendStartReq
\sa EAP_SIMSendChallengeReq
\sa EAP_SIMSendNotificationReq
\sa EAP_SIMSendReauthReq

*/
extern MSTATUS
EAP_SIMSendNotificationReq(eapSimCb *eapSim, ubyte **pkt, ubyte4 *pktLen,
                           ubyte2 at_counter, ubyte4 notification_code, ubyte id)
{
    ubyte*      cur = NULL;
    ubyte*      encrData;
    ubyte*      encrDataLen;
    ubyte2      plainTxtLen = 0;
    ubyte2      pad = 0;
    eapHdr_t*   eapHdr;
    MSTATUS     status = OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simSendNotificationReq: Handle = ", (sbyte4)((uintptr)eapSim));
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

    if (eapSim->eapSimCfg.aka)
        *cur++ = EAP_TYPE_AKA;
    else
        *cur++ = EAP_TYPE_SIM;
    *cur++ = EAP_SIM_SUBTYPE_NOTIFICATION;
    *cur++ = 0;
    *cur++ = 0;

    *pktLen +=4;

    /* if P Bit is Set to 0 then Notification can be used only after the Full AUth or Reauth Success Section 6.1 rfc 4186*/
    if (!(notification_code & EAP_SIM_NOTIF_P_BIT))
    {
        if ((!(eapSim->reAuthRoundSuccess))  &&
            (!(eapSim->fullAuthRoundSuccess)))
        {
            status = ERR_EAP_SIM_P_BIT_NOT_PRESENT;
            goto exit;
        }
    }

    /* P Bit is Set to 1 then Notification can be used before  the Full AUth Challenge or  Reauth  Success Section 6.1 rfc 4186*/
    if (notification_code & EAP_SIM_NOTIF_P_BIT)
    {
        if ((eapSim->reAuthRoundSuccess) ||
            (eapSim->fullAuthRoundSuccess))
        {
            status = ERR_EAP_SIM_P_BIT_PRESENT;
            goto exit;
        }

        /* If P Bit Present, SBit Cannot be present */
        if (notification_code & EAP_SIM_NOTIF_S_BIT)
        {
            status = ERR_EAP_SIM_S_P_BIT_PRESENT;
            goto exit;
        }
    }

    /* Section 9.8 Rfc 4186 */
    if (eapSim->attemptreAuthRound)
    {
        if (!(notification_code & EAP_SIM_NOTIF_P_BIT))
        {
             /* AT _COUNTER Has to be Present */
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

            /* Add Counter  */
            status = eap_simAddCounter(eapSim,cur);
            if (OK > status)
                goto exit;

            cur+=4;
            plainTxtLen +=4;

            /* Plain Text Should be a multiple of 16 */
            pad = plainTxtLen % 16;

            if (pad)  /* Should be 4,8 or 12 */
            {
               /* Actual Pad */
                pad = 16 - pad;

                status = eap_simAddPad(eapSim,cur,pad);
                if (OK > status)
                    goto exit;

                plainTxtLen = plainTxtLen + pad;
            }

            cur+=pad;
            *pktLen+=plainTxtLen;
            *encrDataLen = *encrDataLen + (ubyte)(plainTxtLen/4);

            /* Encrypt the whole PLaintxt buffer */
            status = eap_simEncryptBuf(eapSim,encrData,plainTxtLen);
            if (OK > status)
                goto exit;
        }
    }

    status = eap_simAddNotificationCode(eapSim,cur,(ubyte2)notification_code);
    if (OK > status)
        goto exit;

    *pktLen +=4;
    cur +=4;

    DIGI_HTONS((ubyte *)*pkt + 2,*pktLen);

    /* Section 9.8 Rfc 4186 */
    /* if P Bit set to 0 Include MAC*/
    if (!(notification_code & EAP_SIM_NOTIF_P_BIT))
    {
        DIGI_MEMSET(eapSim->mac,0,EAP_SIM_MAC_LEN);

        status = eap_simAddMAC(eapSim,cur);
        if (OK > status)
            goto exit;

        *pktLen +=20;
        cur+=4;

        DIGI_HTONS((ubyte *)*pkt + 2,*pktLen);

        status = eap_simCalculateMac(eapSim,*pkt,(ubyte2)(*pktLen),
                                     eapSim->mac,NULL,0);
        if (OK > status)
            goto exit;

        DIGI_MEMCPY(cur,eapSim->mac,EAP_SIM_MAC_LEN);
    }

exit:
    if (OK > status)
    {
        if (*pkt)
            FREE(*pkt);

        *pkt = NULL;
        *pktLen = 0;

        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "EAP_SIMSendNotificationReq: Error, status = ", status);
    }

    return  status;

}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simSendClientErrCodeReq(eapSimCb *eapSim, ubyte **pkt, ubyte4 *pktLen,
                            sbyte4 errCode, ubyte id)
{
    ubyte*      cur = NULL;
    ubyte2      clientErrCode = 0;
    eapHdr_t*   eapHdr;
    MSTATUS     status;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simSendClientErrCodeReq: Handle = ", (sbyte4)((uintptr)eapSim));
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

    if (eapSim->eapSimCfg.aka)
        *cur++ = EAP_TYPE_AKA;
    else
        *cur++ = EAP_TYPE_SIM;
    *cur++ = EAP_SIM_SUBTYPE_CLIENT_ERROR;
    *cur++ = 0;
    *cur++ = 0;

    *pktLen +=4;

    switch (errCode)
    {
        case ERR_EAP_SIM_INVALID_MAC:
        {
            clientErrCode = 0;

            break;
        }

        default:
        {
            clientErrCode = 0;

            break;
        }
    }

    status = eap_simAddClientErrCode(eapSim,cur,clientErrCode);

    *pktLen +=4;
    cur+=4;
    DIGI_HTONS((ubyte *)*pkt + 2,*pktLen);

exit:
    if (OK > status)
    {
        if (*pkt)
            FREE(*pkt);

        *pkt = NULL;
        *pktLen = 0;

        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simSendClientErrCode: Error, status = ", status);
    }

    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simSendNotificationResp(eapSimCb *eapSim, ubyte **pkt,
                            ubyte4 *pktLen, sbyte4 errCode, ubyte id)
{
    ubyte*      cur = NULL;
    ubyte*      encrData;
    ubyte*      encrDataLen;
    ubyte2      plainTxtLen = 0;
    ubyte2      pad = 0;
    eapHdr_t*   eapHdr;
    MSTATUS     status = OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simSendNotificationResp: Handle = ", (sbyte4)((uintptr)eapSim));
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

    if (eapSim->eapSimCfg.aka)
        *cur++ = EAP_TYPE_AKA;
    else
        *cur++ = EAP_TYPE_SIM;
    *cur++ = EAP_SIM_SUBTYPE_NOTIFICATION;
    *cur++ = 0;
    *cur++ = 0;

    *pktLen +=4;

    /* if P Bit is Set to 0 then Notification can be used only after the Full AUth or Reauth Success Section 6.1 rfc 4186*/
    if (!(eapSim->notifCode & EAP_SIM_NOTIF_P_BIT))
    {
        if ((!(eapSim->reAuthRoundSuccess))  &&
            (!(eapSim->fullAuthRoundSuccess)))
        {
            status = ERR_EAP_SIM_P_BIT_NOT_PRESENT;
            goto exit;
        }
    }

    /* P Bit is Set to 1 then Notification can be used before  the Full AUth Challenge or  Reauth  Success Section 6.1 rfc 4186*/
    if (eapSim->notifCode & EAP_SIM_NOTIF_P_BIT)
    {
        if ((eapSim->reAuthRoundSuccess) ||
            (eapSim->fullAuthRoundSuccess))
        {
            status = ERR_EAP_SIM_P_BIT_PRESENT;
            goto exit;
        }
        /* If P Bit Present, SBit Cannot be present */
        if (eapSim->notifCode & EAP_SIM_NOTIF_S_BIT)
        {
            status = ERR_EAP_SIM_S_P_BIT_PRESENT;
            goto exit;
        }

    }

    /* Section 9.8 Rfc 4186 */
    if (eapSim->attemptreAuthRound)
    {
        if (!(eapSim->notifCode & EAP_SIM_NOTIF_P_BIT))
        {
             /* COUNTER Has to be Present */
            /* Encrypt these  and Add the IV and ENCR */
            status = eap_simAddIV(eapSim,cur);
            if (OK > status)
                goto exit;

            cur+=20;
            *pktLen +=20;

            status = eap_simAddEncr(eapSim,cur);
            encrDataLen = cur+1;
            *encrDataLen = 1; /*Set It to 1 */
            cur+=4;
            *pktLen +=4;

            encrData = cur;

            /* Add Counter  And NONCE_S*/
            status = eap_simAddCounter(eapSim,cur);
            if (OK > status)
                goto exit;

            cur+=4;
            plainTxtLen +=4;

            /* Plain Text Should be a multiple of 16 */
            pad = plainTxtLen % 16;

            if (pad)  /* Should be 4,8 or 12 */
            {
               /* Actual Pad */
                pad = 16 - pad;
                status = eap_simAddPad(eapSim,cur,pad);
                if (OK > status)
                    goto exit;

                plainTxtLen = plainTxtLen + pad;
            }

            cur+=pad;
            *pktLen = *pktLen + plainTxtLen;
            *encrDataLen = *encrDataLen + (ubyte)(plainTxtLen/4);

            /* Encrypt the whole PLaintxt buffer */
            status = eap_simEncryptBuf(eapSim,encrData,plainTxtLen);
            if (OK > status)
                goto exit;
        }
    }

    DIGI_HTONS((ubyte *)*pkt + 2,*pktLen);

   /* Section 9.8 Rfc 4186 */
   /* if P Bit set to 0 Include MAC*/
    if (!(eapSim->notifCode & EAP_SIM_NOTIF_P_BIT))
    {
        DIGI_MEMSET(eapSim->mac,0,EAP_SIM_MAC_LEN);

        status = eap_simAddMAC(eapSim,cur);
        if (OK > status)
            goto exit;

        *pktLen +=20;
        cur+=4;

        DIGI_HTONS((ubyte *)*pkt + 2,*pktLen);

        status = eap_simCalculateMac(eapSim,*pkt,(ubyte2)(*pktLen),
                                     eapSim->mac,NULL,0);
        if (OK > status)
            goto exit;

        DIGI_MEMCPY(cur,eapSim->mac,EAP_SIM_MAC_LEN);
    }

exit:
    if (OK > status)
    {
        if (*pkt)
            FREE(*pkt);

        *pkt = NULL;
        *pktLen = 0;

        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simSendNotificationResp: Error, status = ", status);
    }

    return status;
}


/*------------------------------------------------------------------*/

/*! Process a received packet and build a response.
This function processes a packet received by the specified EAP-SIM session,
builds a response (which is returned through the $resp$ parameter), and informs
the calling application of the current state (the EAP-SIM state machine's
state).

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_SIM__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_sim.h

\param eapSim   EAP-SIM session handle returned from EAP_SIMInitSession.
\param pkt      Pointer to packet to process.
\param pktLen   Number of bytes in packet to process ($pkt$).
\param resp     On return, pointer to response packet to be transmitted.
\param respLen  On return, pointer to number of bytes in response packet ($resp$).
\param state    On return, pointer to $eapSimStatus$ enumerated value (refer to eap_sim.h).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_SIMProcessPkt(eapSimCb *eapSim, ubyte *pkt, ubyte2 pktLen,
                  ubyte **resp, ubyte4 *respLen, eapSimStatus *state)
{
    eapHdr_t*   eapHdr = (eapHdr_t *)pkt;
    ubyte*      cur = pkt + sizeof(eapHdr_t);
    ubyte       type;
    ubyte       subtype;
    MSTATUS     status = OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simProcessPkt: Handle = ", (sbyte4)((uintptr)eapSim));
    /* Check that the Packet has atleast  4 Bytes of Data After EAP Hdr
       Type,SubType,Reserved (4 Bytes)  */
    if (4 + sizeof(eapHdr_t) > pktLen)
    {
        status = ERR_EAP_SIM_INVALID_PKT_LENGTH;
        goto exit;
    }

    type  = *cur++;
    subtype  = *cur++;

    cur+=2; /* Reserved */

    /* reset a few of the params */
    eapSim->attrPresent = 0;
    eapSim->counterTooSmall = 0;
    eapSim->notifCode = 0;

    if (eapHdr->code == EAP_CODE_REQUEST)
    {
        switch (subtype)
        {
            case EAP_SIM_SUBTYPE_START:
            {
                status = eap_simProcessStartReqPkt(eapSim,cur,
                                                pktLen-4-sizeof(eapHdr_t));
                if (OK > status)
                {
                    status = eap_simSendClientErrCodeReq(eapSim,resp,respLen,
                                                        status,eapHdr->id);
                    if (OK > status)
                        goto exit;

                    break;
                }

                /* call EAP_SIM_START_RESP */
                status = eap_simSendStartResp(eapSim,resp,respLen,eapHdr->id);
                if (OK > status)
                    goto exit;

                *state = EAP_SIM_STATUS_RECV_START_REQ;

                break;
            }

            case EAP_SIM_SUBTYPE_CHALLENGE:
            {
                status = eap_simProcessChallengeReqPkt(eapSim,pkt,pktLen);
                if (OK > status)
                {
                    /*Send Client Error */
                    status = eap_simSendClientErrCodeReq(eapSim,resp,respLen,
                                                        status,eapHdr->id);
                    break;
                }

                /*Send Challenge Resp */
                status = eap_simSendChallengeRespPkt(eapSim,resp,respLen,
                                                    eapHdr->id);
                if (OK > status)
                    goto exit;

                /*  Reset Some Variables */
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

                status = eap_simSendReauthResp(eapSim,resp,respLen,
                                                        eapHdr->id);
                *state = EAP_SIM_STATUS_RECV_REAUTH_REQ;

                break;
            }

            default:
            {
                status = ERR_EAP_SIM_UNKNOWN_PDU;
                goto exit;
            }
        }
    }

    if (eapHdr->code == EAP_CODE_RESPONSE)
    {
        switch (subtype)
        {
            case EAP_SIM_SUBTYPE_START:
            {
                status = eap_simProcessStartRespPkt(eapSim,cur,pktLen-4-sizeof(eapHdr_t));
                *state = EAP_SIM_STATUS_RECV_START_RESP;
                /*App to Check on Valid Identity  and then send Challenge Req
                or a Notification packet with error if reuiqred */

                break;
            }

            case EAP_SIM_SUBTYPE_CHALLENGE:
            {
                status = eap_simProcessChallengeRespPkt(eapSim,pkt,pktLen);
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

            default:
            {
                status = ERR_EAP_SIM_UNKNOWN_PDU;
                goto exit;
            }
        }
    }

exit:
    return status;

}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simProcessStartReqPkt(eapSimCb *eapSim, ubyte *pkt, ubyte2 pktLen)
{

    MSTATUS status = OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simProcessStartReqPkt: Handle = ", (sbyte4)((uintptr)eapSim));
    status = eap_simDecodeAttr(eapSim,pkt,pktLen,EAP_SIM_START_REQ);
    if (OK > status)
        goto exit;

    status = eap_simValidateMandAttrs(eapSim,EAP_SIM_START_REQ);
    if (OK > status)
        goto exit;

    status = eap_simSelectVersion(eapSim);
    if (OK > status)
        goto exit;

    if (eapSim->id_requested)
    {
        /*  The Sequence Should be ANY,FULL,PERM */
        eapSim->numIdReq++;

        if (3 < eapSim->numIdReq)
        {
            status = ERR_EAP_SIM_TOO_MANY_ID_REQ;
            goto exit;
        }
    }

    eapSim->sessionStatus = EAP_SIM_STATUS_RECV_START_REQ;

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simProcessStartReqPkt: Error Processing Start Req, status = ", status);
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simProcessStartRespPkt(eapSimCb *eapSim, ubyte *pkt, ubyte2 pktLen)
{
    MSTATUS status;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simProcessStartRespPkt: Handle = ", (sbyte4)((uintptr)eapSim));
    status = eap_simDecodeAttr(eapSim,pkt,pktLen,EAP_SIM_START_RESP);
    if (OK > status)
        goto exit;

    status = eap_simValidateMandAttrs(eapSim,EAP_SIM_START_RESP);
    if (OK > status)
        goto exit;

    eapSim->sessionStatus = EAP_SIM_STATUS_RECV_START_RESP;

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simProcessStartRespPkt: Error Processing Start Resp, status = ", status);
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simProcessReauthRespPkt(eapSimCb *eapSim, ubyte *pkt, ubyte2 pktLen)
{
    ubyte       mac[EAP_SIM_MAC_LEN];
    ubyte       rmk[EAP_SIM_MK_LEN];
    sbyte4      cmp;
    MSTATUS     status = OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simProcessReauthRespPkt: Handle = ", (sbyte4)((uintptr)eapSim));
    status = eap_simDecodeAttr(eapSim,pkt+sizeof(eapHdr_t)+4,/* From the attr */
                               pktLen-sizeof(eapHdr_t)-4,/* Attr Len*/
                               EAP_SIM_REAUTH_RESP);
    if (OK > status)
        goto exit;

    status = eap_simValidateMandAttrs(eapSim,EAP_SIM_REAUTH_RESP);
    if (OK > status)
        goto exit;

    /* Validate MAC */
    status = eap_simCalculateMac(eapSim,pkt,pktLen,mac,eapSim->nonce_s,EAP_SIM_NONCE_S_LEN);
    if (OK > status)
        goto exit;

    if (DIGI_MEMCMP(eapSim->mac,mac,EAP_SIM_MAC_LEN,&cmp))
    {
        status = ERR_EAP_SIM_INVALID_MAC;
        goto exit;
    }

    if (cmp)
    {
        status = ERR_EAP_SIM_INVALID_MAC;
        goto exit;
    }

    /* Decrypt any ENCR Attrs */

    if (eapSim->attrPresent & EAP_SIM_AT_IV_PRESENT)
    {
        status = eap_simDecryptBuf(eapSim);
        if (OK > status)
        {
            goto exit;
        }

        status = eap_simDecodeAttr(eapSim,eapSim->encr_data,
                                   eapSim->encr_dataLen,
                                   EAP_SIM_REAUTH_RESP);
        if (OK > status)
        {
            goto exit;
        }

        if (!(eapSim->attrPresent & EAP_SIM_AT_COUNTER_PRESENT))
        {
             status = ERR_EAP_SIM_MANDATORY_ATTR_MISSING;
             goto exit;
        }
    }

    eapSim->attemptfullAuthRound = 0;
    eapSim->fullAuthRoundSuccess = 0;
    eapSim->attemptreAuthRound = 1;

    if (eapSim->counterTooSmall)
    {
        eapSim->reAuthRoundSuccess = 0;
        status = ERR_EAP_SIM_COUNTER_TOO_SMALL;
        goto exit;
    }

    /* Calculate Seed Keys */
    status = eap_simGenerateReauthMasterKey(eapSim,rmk);
    if (OK > status)
    {
        goto exit;
    }

    /* Generate MSK/EMSK */
    status = eap_simGenerateReauthKeys(eapSim,rmk);
    if (OK > status)
    {
        goto exit;
    }

    eapSim->sessionStatus = EAP_SIM_STATUS_RECV_REAUTH_REQ;

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simProcessReauthRespPkt: Error Processing Reauth Resp Pkt, status = ", status);
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simProcessReauthReqPkt(eapSimCb *eapSim, ubyte *pkt, ubyte2 pktLen)
{

    sbyte4      cmp;
    ubyte       mac[EAP_SIM_MAC_LEN];
    ubyte       rmk[EAP_SIM_MK_LEN];
    MSTATUS     status = OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simProcessReauthReqPkt: Handle = ", (sbyte4)((uintptr)eapSim));
    status = eap_simDecodeAttr(eapSim,pkt+sizeof(eapHdr_t)+4,/* From the attr */
                               pktLen-sizeof(eapHdr_t)-4,/* Attr Len*/
                               EAP_SIM_REAUTH_REQ);
    if (OK > status)
        goto exit;

    status = eap_simValidateMandAttrs(eapSim,EAP_SIM_REAUTH_REQ);
    if (OK > status)
        goto exit;

    /* Validate MAC */
    status = eap_simCalculateMac(eapSim,pkt,pktLen,mac,0,0);
    if (OK > status)
        goto exit;

    if (DIGI_MEMCMP(eapSim->mac,mac,EAP_SIM_MAC_LEN,&cmp))
    {
        status = ERR_EAP_SIM_INVALID_MAC;
        goto exit;
    }

    if (cmp)
    {
        status = ERR_EAP_SIM_INVALID_MAC;
        goto exit;
    }

    /* Calculate Seed Keys */
    status = eap_simGenerateReauthMasterKey(eapSim,rmk);
    if (OK > status)
        goto exit;

    /* Generate MSK/EMSK */
    status = eap_simGenerateReauthKeys(eapSim,rmk);
    if (OK > status)
        goto exit;

    /* Decrypt any ENCR Attrs */
    if (eapSim->attrPresent & EAP_SIM_AT_IV_PRESENT)
    {
        status = eap_simDecryptBuf(eapSim);
        if (OK > status)
            goto exit;

        status = eap_simDecodeAttr(eapSim,eapSim->encr_data,
                                   eapSim->encr_dataLen,
                                   EAP_SIM_REAUTH_REQ);
        if (OK > status)
            goto exit;

        if (!(eapSim->attrPresent & EAP_SIM_AT_NONCE_S_PRESENT))
        {
             status = ERR_EAP_SIM_MANDATORY_ATTR_MISSING;
             goto exit;
        }

        if (!(eapSim->attrPresent & EAP_SIM_AT_COUNTER_PRESENT))
        {
             status = ERR_EAP_SIM_MANDATORY_ATTR_MISSING;
             goto exit;
        }
    }

    /*if the reauth Id is not present in the Reauth Req, Set it to NULL */
    if (!(eapSim->attrPresent & EAP_SIM_AT_NEXT_REAUTH_ID_PRESENT))
    {
        if (eapSim->reauthId)
        {
            FREE(eapSim->reauthId);
            eapSim->reauthId = NULL;
            eapSim->reauthIdLen = 0;
        }
    }

    eapSim->attemptfullAuthRound = 0;
    eapSim->fullAuthRoundSuccess = 0;
    eapSim->attemptreAuthRound = 1;
    eapSim->reAuthRoundSuccess = 0;
    eapSim->sessionStatus = EAP_SIM_STATUS_RECV_REAUTH_REQ;

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simProcessReauthReqPkt: Error Processing Reauth Req, status = ", status);
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simProcessChallengeReqPkt(eapSimCb *eapSim, ubyte *pkt, ubyte2 pktLen)
{

    ubyte       mac[EAP_SIM_MAC_LEN];
    sbyte4      cmp;
    MSTATUS     status = OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simProcessChallengeReqPkt: Handle = ", (sbyte4)((uintptr)eapSim));
    status = eap_simDecodeAttr(eapSim,pkt+sizeof(eapHdr_t)+4,/* From the attr */
                               pktLen-sizeof(eapHdr_t)-4,/* Attr Len*/
                               EAP_SIM_CHALLENGE_REQ);
    if (OK > status)
        goto exit;

    status = eap_simValidateMandAttrs(eapSim,EAP_SIM_CHALLENGE_REQ);
    if (OK > status)
        goto exit;

    /* Call the App and Get the SRES and KC from the SIM CARD */
    status = eapSim->eapSimCfg.getSresKc(eapSim->appSessionHdl,eapSim,
                                         eapSim->rand[0],eapSim->numRand,
                                         eapSim->sRes,eapSim->kC);
    if (OK > status)
        goto exit;

    /* Calculate Keys */
    status = eap_simGenerateMasterKey(eapSim);
    if (OK > status)
        goto exit;

    /* Generate K_AUT/MSK/EMSK */
    status = eap_simGenerateKeys(eapSim);
    if (OK > status)
        goto exit;

    /* Validate MAC */
    status = eap_simCalculateMac(eapSim,pkt,pktLen,mac,eapSim->nonce_mt,EAP_SIM_NONCE_MT_LEN);
    if (OK > status)
        goto exit;

    if (DIGI_MEMCMP(eapSim->mac,mac,EAP_SIM_MAC_LEN,&cmp))
    {
        status = ERR_EAP_SIM_INVALID_MAC;
        goto exit;
    }

    if (cmp)
    {
        status = ERR_EAP_SIM_INVALID_MAC;
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
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simProcessChallengeReqPkt: Error Processing Challenge Req, status = ", status);
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simProcessChallengeRespPkt(eapSimCb *eapSim, ubyte *pkt, ubyte2 pktLen)
{
    ubyte       mac[EAP_SIM_MAC_LEN];
    sbyte4      cmp;
    MSTATUS     status = OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simProcessChallengeRespPkt: Handle = ", (sbyte4)((uintptr)eapSim));
    status = eap_simDecodeAttr(eapSim,pkt+sizeof(eapHdr_t)+4,/* From the attr */
                               pktLen-sizeof(eapHdr_t)-4,/* Attr Len*/
                               EAP_SIM_CHALLENGE_RESP);
    if (OK > status)
        goto exit;

    status = eap_simValidateMandAttrs(eapSim,EAP_SIM_CHALLENGE_RESP);
    if (OK > status)
        goto exit;

    /* Validate MAC */
    eap_simCalculateMac(eapSim,pkt,pktLen,mac,eapSim->sRes,eapSim->numRand *4);
    if (DIGI_MEMCMP(eapSim->mac,mac,EAP_SIM_MAC_LEN,&cmp))
    {
        status = ERR_EAP_SIM_INVALID_MAC;
        goto exit;
    }

    if (cmp)
    {
        status = ERR_EAP_SIM_INVALID_MAC;
        goto exit;
    }

    eapSim->fullAuthRoundSuccess = 1;
    eapSim->counter++;

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simProcessChallengePkt: Error Processing Challenge Resp, status = ", status);
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simProcessNotificationRespPkt(eapSimCb *eapSim, ubyte *pkt, ubyte4 pktLen)
{
    ubyte       mac[EAP_SIM_MAC_LEN];
    sbyte4      cmp;
    MSTATUS     status = OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simProcessNotificationRespPkt: Handle = ", (sbyte4)((uintptr)eapSim));
    status = eap_simDecodeAttr(eapSim,pkt+sizeof(eapHdr_t)+4,/* From the attr */
                               pktLen-sizeof(eapHdr_t)-4,/* Attr Len*/
                               EAP_SIM_NOTIFICATION_RESP);
    if (OK > status)
        goto exit;

    status = eap_simValidateMandAttrs(eapSim,EAP_SIM_NOTIFICATION_RESP);

    if (OK > status)
        goto exit;

    if (!(eapSim->notifCode & EAP_SIM_NOTIF_P_BIT))
    {
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "P Bit Not Sent to the Client, MAC has to be present");

        if (eapSim->attrPresent & EAP_SIM_AT_MAC_PRESENT)
        {
            eap_simCalculateMac(eapSim,pkt,pktLen,mac,0,0);
            if (DIGI_MEMCMP(eapSim->mac,mac,EAP_SIM_MAC_LEN,&cmp))
            {
                status = ERR_EAP_SIM_INVALID_MAC;
                goto exit;
            }

            if (cmp)
            {
                status = ERR_EAP_SIM_INVALID_MAC;
                goto exit;
            }
        }

        if (eapSim->attrPresent & EAP_SIM_AT_IV_PRESENT)
        {
            /* Decrypt any ENCR Attrs */
            status = eap_simDecryptBuf(eapSim);
            if (OK > status)
                goto exit;

            status = eap_simDecodeAttr(eapSim,eapSim->encr_data,
                                       eapSim->encr_dataLen,
                                       EAP_SIM_NOTIFICATION_REQ);
            if (OK > status)
                goto exit;

            /*  Validate any Mandatory ENCR Attributes */
        }
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simProcessNotifRespPkt: Error Processing Notification Resp, status = ", status);
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simProcessClientErrorPkt(eapSimCb *eapSim, ubyte *pkt, ubyte4 pktLen)
{
    MSTATUS     status = OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simProcessClientErrPkt: Handle = ", (sbyte4)((uintptr)eapSim));
    status = eap_simDecodeAttr(eapSim,pkt+sizeof(eapHdr_t)+4,/* From the attr */
                               pktLen-sizeof(eapHdr_t)-4,/* Attr Len*/
                               EAP_SIM_CLIENT_ERROR);
    if (OK > status)
        goto exit;

    status = eap_simValidateMandAttrs(eapSim,EAP_SIM_CLIENT_ERROR);
    if (OK > status)
        goto exit;

    status = eap_simParseClientError(eapSim);
    if (OK > status)
        goto exit;

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simProcessClientErrorPkt: Error Processing Client Error, status = ", status);
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_simProcessNotificationReqPkt(eapSimCb *eapSim, ubyte *pkt, ubyte2 pktLen)
{
    ubyte       mac[EAP_SIM_MAC_LEN];
    sbyte4      cmp;
    MSTATUS     status = OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simProcessNotificationReqPkt: Handle = ", (sbyte4)((uintptr)eapSim));
    eapSim->notifCode = 0;

    status = eap_simDecodeAttr(eapSim,pkt+sizeof(eapHdr_t)+4,/* From the attr */
                               pktLen-sizeof(eapHdr_t)-4,/* Attr Len*/
                               EAP_SIM_NOTIFICATION_REQ);

    if (OK > status)
        goto exit;

    status = eap_simValidateMandAttrs(eapSim,EAP_SIM_NOTIFICATION_REQ);

    if (OK > status)
        goto exit;

    if (!(eapSim->notifCode & EAP_SIM_NOTIF_P_BIT))
    {
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Received P Bit Set from Server");

        if (eapSim->attrPresent & EAP_SIM_AT_MAC_PRESENT)
        {
            eap_simCalculateMac(eapSim,pkt,pktLen,mac,0,0);
            if (DIGI_MEMCMP(eapSim->mac,mac,EAP_SIM_MAC_LEN,&cmp))
            {
                status = ERR_EAP_SIM_INVALID_MAC;
                goto exit;
            }

            if (cmp)
            {
                status = ERR_EAP_SIM_INVALID_MAC;
                goto exit;
            }
        }

        if (eapSim->attrPresent & EAP_SIM_AT_IV_PRESENT)
        {
            /* Decrypt any ENCR Attrs */
            status = eap_simDecryptBuf(eapSim);
            if (OK > status)
                goto exit;

            status = eap_simDecodeAttr(eapSim,eapSim->encr_data,
                                       eapSim->encr_dataLen,
                                       EAP_SIM_NOTIFICATION_REQ);
            if (OK > status)
                goto exit;
        }
    }

    status = eap_simParseNotification(eapSim);
    if (OK > status)
        goto exit;

    if (eapSim->notifCode & EAP_SIM_NOTIF_S_BIT)
    {
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Received Success Notification (S Bit) from Server");
    }
    else
    {
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " Received Error from Server");
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "eap_simProcessNotifReqPkt: Error Processing Notif Req, status = ", status);
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_sim_prf(ubyte *key, ubyte *x, ubyte2 xlen)
{
    randomContext* ctx = NULL;
    MSTATUS status;

    /* Key derivation is based on the PRF specified in FIPS 186-2 change
       notice 1. See RFC4186 7. Page 44 */
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    if ( OK > ( status = RANDOM_newFIPS186Context( &ctx, EAP_SIM_MK_LEN , key, 0, NULL)))
        goto exit;
#endif

    status = RANDOM_numberGenerator(ctx, x, xlen);
    RANDOM_releaseContext( &ctx);
exit:

    return status;
}


/*------------------------------------------------------------------*/

/*! Create and initialize an EAP-SIM or EAP-AKA session.
This function creates and initializes an EAP-SIM or EAP-AKA session.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_SIM__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_sim.h

\param appCb        Application session handle (cookie given by the application to identify the session).
\param eapSim       On return, pointer to EAP-SIM/EAP-AKA session handle.
\param eapSimCfg    Parameters for the SIM/AKA session to be created.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_SIMInitSession(void * appCb,void **eapSim, eapSimConfig eapSimCfg)
{
    eapSimCb*   eapSimTmp = MALLOC(sizeof(eapSimCb));
    MSTATUS     status = OK;

    if (NULL == eapSimTmp)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)eapSimTmp,0,sizeof(eapSimCb));

    *eapSim = (void *) eapSimTmp;

    /* Check a few attributes here, Num Rand Supported etc */
    DIGI_MEMCPY((ubyte *)&eapSimTmp->eapSimCfg,(ubyte *)&eapSimCfg,sizeof(eapSimConfig));

    if ((EAP_SESSION_TYPE_AUTHENTICATOR != eapSimTmp->eapSimCfg.sessionType) &&
        (EAP_SESSION_TYPE_PEER != eapSimTmp->eapSimCfg.sessionType))
    {
        status = ERR_EAP_SIM_INVALID_SESSION_TYPE;
        goto exit;
    }

    if (!eapSimCfg.aka)
    {
        if ((NULL == eapSimCfg.getSresKc) &&
            (EAP_SESSION_TYPE_PEER == eapSimTmp->eapSimCfg.sessionType))
        {
            status = ERR_EAP_SIM_GETSRESKC_NOT_PRESENT;
            goto exit;
        }
    }
    else
    {
        if ((NULL == eapSimCfg.getAKARes) &&
            (EAP_SESSION_TYPE_PEER == eapSimTmp->eapSimCfg.sessionType))
        {
            status = ERR_EAP_SIM_GETAKARES_NOT_PRESENT;
            goto exit;
        }
    }

    eapSimTmp->appSessionHdl = appCb;
    eapSimTmp->sessionStatus = EAP_SIM_STATUS_INIT;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "EAP_SIMinitSession: Initing Session, Handle = ", (sbyte4)((uintptr)eapSimTmp));

exit:
    if (OK > status)
    {
        if (eapSimTmp)
        {
            FREE(eapSimTmp);
            *eapSim = NULL;
        }
    }
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, "EAP_SIMinitSession: Error Initing Session, status = ", status);
    return status;

}


/*------------------------------------------------------------------*/

/*! Delete an EAP-SIM connection.
This function deletes an EAP-SIM connection.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_SIM__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_sim.h

\param eapSim   EAP-SIM session handle returned from EAP_SIMInitSession.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_SIMDeleteSession(eapSimCb *eapSim)
{
    MSTATUS status = OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "EAP_SIMDeleteSession: Delete Session, Handle = ", (sbyte4)((uintptr)eapSim));
    if (eapSim->permanentIdentity)
    {
        FREE(eapSim->permanentIdentity);
        eapSim->permanentIdentity  = NULL;
    }

    if (eapSim->psuedonym)
    {
        FREE(eapSim->psuedonym);
        eapSim->psuedonym = NULL;
    }

    if (eapSim->reauthId)
    {
        FREE(eapSim->reauthId);
        eapSim->reauthId = NULL;
    }

    if (eapSim->identity)
    {
        FREE(eapSim->identity);
        eapSim->identity  = NULL;
    }

    if (eapSim->versionList)
    {
        FREE(eapSim->versionList);
        eapSim->versionList  = NULL;
    }

    if (eapSim->versionListImpl)
    {
        FREE(eapSim->versionListImpl);
        eapSim->versionListImpl  = NULL;
    }

    if (eapSim->encr_data)
    {
        FREE(eapSim->encr_data);
        eapSim->encr_data  = NULL;
    }

    FREE(eapSim);

    return status;
}


/*------------------------------------------------------------------*/

/*! Set the EAP-SIM session's permanent identity.
This function (typically called by the peer) assigns the specified value to the
EAP-SIM session's permanent identity. (The IMSI&mdash;International Mobile
Subscriber Identity&mdash;is commonly used as the permanent identity.)

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_SIM__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_sim.h

\param eapSim   EAP-SIM session handle returned from EAP_SIMInitSession.
\param id       Pointer to desired permanent identity.
\param idLen    Number of bytes in permanent identity ($id$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\remark The }permanent} identity is different from the }final} identity, which
is used during identity phase negotiation (see EAP_SIMSetIdentity).

*/
extern MSTATUS
EAP_SIMSetPermIdentity(eapSimCb *eapSim, ubyte *id, ubyte2 idLen)
{
    MSTATUS status = OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "EAP_SIMSetPermIdentity: , Handle = ", (sbyte4)((uintptr)eapSim));

    if ((!id) || (!idLen))
    {
        status = ERR_EAP_SIM_INVALID_IDENTITY;
        goto exit;
    }

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, "  Perm Identity = ");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, id);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " " );

    if (eapSim->permanentIdentity)
    {
        FREE(eapSim->permanentIdentity);
    }

    eapSim->permanentIdentity = MALLOC(idLen);

    if (NULL == eapSim->permanentIdentity)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(eapSim->permanentIdentity,id,idLen);
    eapSim->permanentIdentityLen = idLen;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Set the EAP-SIM session's final identity.
This function (called by the authenticator or peer) assigns the specified
identity value to the specified EAP-SIM session's final identity (used after
identity negotiation is complete). The final identity is typically the IMSI
(International Mobile Subscriber Identity) or the reauthorization ID negotiated
between the peer and authenticator.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_SIM__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_sim.h

\param eapSim   EAP-SIM session handle returned from EAP_SIMInitSession.
\param id       Pointer to desired final identity.
\param idLen    Number of bytes in final identity ($id$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\remark The }final} identity is different from the }permanent} identity, which
is typically the IMSI (see EAP_SIMSetPermIdentity).

*/
extern MSTATUS
EAP_SIMSetIdentity(eapSimCb *eapSim, ubyte *id, ubyte2 idLen)
{
    MSTATUS status = OK;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, "EAP_SIMSetIdentity: , Handle = ", (sbyte4)((uintptr)eapSim));
    if ((!id) || (!idLen))
    {
        status = ERR_EAP_SIM_INVALID_IDENTITY;
        goto exit;
    }

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, " Identity = ");
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, id);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " " );

    if (eapSim->identity)
    {
        FREE(eapSim->identity);
    }

    eapSim->identity= MALLOC(idLen);
    if (NULL == eapSim->identity)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(eapSim->identity,id,idLen);
    eapSim->identityLen = idLen;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Add version(s) to an EAP-SIM session's supported versions list.
This function (called by the authenticator or peer) adds the specified
version(s) to the specified EAP-SIM session's list of supported versions. This
version information is required during the EAP-SIM Identity phase negotiation,
where the first version found to be common to the peer and authenticator is used
for communication.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_SIM__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_sim.h

\param eapSim           EAP-SIM session handle returned from EAP_SIMInitSession.
\param versionList      Pointer to array containing list of versions
that the node (calling authenticator or peer) is to support.
\param numVersion       Number of entries in the $versionList$ array.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_SIMSetImplementedVersion(eapSimCb *eapSim, ubyte2 *versionList, ubyte2 numVersion)
{
    MSTATUS status = OK;

    if (!(versionList))
    {
        status = ERR_EAP_SIM_INVALID_VERSION_LIST;
        goto exit;
    }

    if (eapSim->versionListImpl)
    {
        FREE(eapSim->versionListImpl);
    }

    if (0 == numVersion)
    {
        status = ERR_EAP_SIM_VERSION_LIST_NUM;
        goto exit;
    }

    eapSim->versionListImpl = MALLOC(sizeof(ubyte2) * numVersion);

    eapSim->numVersionListImpl = numVersion;

    if (NULL == eapSim->versionListImpl)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY((ubyte *)eapSim->versionListImpl,(ubyte *)versionList,sizeof(ubyte2)*numVersion);

    if (EAP_SESSION_TYPE_AUTHENTICATOR == eapSim->eapSimCfg.sessionType)
    {
        if (eapSim->versionList)
        {
            FREE(eapSim->versionList);
        }

        eapSim->versionList = MALLOC(sizeof(ubyte2) * numVersion);

        eapSim->numVersionList = numVersion;

        if (NULL == eapSim->versionList)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMCPY((ubyte *)eapSim->versionList,(ubyte *)versionList,sizeof(ubyte2)*numVersion);
    }

exit:
    if (OK > status)
    {
        if (eapSim->versionListImpl)
        {
            FREE(eapSim->versionListImpl);
            eapSim->versionListImpl = NULL;
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

/*! Get the EAP-SIM session ID returned by the peer.
This function (typically called by the authenticator) retrieves the identity
returned by the peer for the specified EAP-SIM session. That returned identity
can then be used by the authenticator's application-specific logic to decide
whether to process the identity, to get the tuple (the RAND, SRES and Kc), or to
ask for a different identity from the peer.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_SIM__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_sim.h

\param eapSim   EAP-SIM session handle returned from EAP_SIMInitSession.
\param identity On return, pointer to peer's identity.
\param len      On return, pointer to number of bytes in peer's ideneity ($identity$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_SIMGetIdentity(eapSimCb *eapSim, ubyte **identity, ubyte4 *len)
{
    *len = eapSim->identityLen;
    *identity = eapSim->identity;

    return OK;
}


/*------------------------------------------------------------------*/

/*! Get the authenticator's notification code.
This function  (typically called by the peer) retrieves the notification code
received from the authenticator for the specified EAP-SIM session.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_SIM__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_sim.h

\param eapSim       EAP-SIM session handle returned from EAP_SIMInitSession.
\param notifCode    On return, pointer to notification code value.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_SIMGetNotification(eapSimCb *eapSim, ubyte2 *notifCode)
{
    *notifCode = eapSim->notifCode;

    return OK;
}


/*------------------------------------------------------------------*/

/*! Get the client error code returned by the peer.
This function (typically called by the authenticator) retrieves the client error
code returned by the peer for the specified EAP-SIM session.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_SIM__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_sim.h

\param eapSim   EAP-SIM session handle returned from EAP_SIMInitSession.
\param clCode   On return, pointer to the %client error code value.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_SIMGetClientErrorCode(eapSimCb *eapSim, ubyte2 *clCode)
{
    *clCode = eapSim->clientErrCode;

    return OK;
}


/*------------------------------------------------------------------*/

/*! Get an EAP-SIM session's session status.
This function retrieves an EAP-SIM session's session status.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_SIM__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_sim.h

\param eap_sim  EAP-SIM session handle returned from EAP_SIMInitSession.
\param status   On return, pointer to the session's status: an $eapSimStatus$
enumeration (see eap_sim.h).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern  MSTATUS
EAP_SIMGetSessionStatus(void *eap_sim, eapSimStatus *status)
{
    eapSimCb *eapSim = (eapSimCb *)eap_sim;

    *status = eapSim->sessionStatus;

    return OK;
}


/*------------------------------------------------------------------*/

/*! Determine whether a challenge negotiation included a $RESULT_IND$ attribute.
This function, called by the authenticator or peer, determines whether the peer
or authenticator, respectively, sent the $RESULT_IND$ attribute during challenge
negotiation. If the result indication attribute is sent by either side,
$SUCCESS$/$FALURE$ is sent by the authenticator in a $Notification Request$.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_SIM__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_sim.h

\param eap_sim  EAP-SIM session handle returned from EAP_SIMInitSession.
\param rInd     On return, pointer to determination value: $1$ if the other side
sent a $RESULT_IND$ attribute; otherwise $0$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern  MSTATUS
EAP_SIMGetResultInd(void *eap_sim, ubyte *rInd)
{
    eapSimCb *eapSim = (eapSimCb *)eap_sim;

    *rInd = eapSim->recvResultInd;

    return OK;
}


/*------------------------------------------------------------------*/

/*! Get the version selected during negotiation.
This function (called by the peer) retrieves the version that was selected
during authenticator-peer version negotiation for the specified EAP-SIM session.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_SIM__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_sim.h

\param eap_sim  EAP-SIM session handle returned from EAP_SIMInitSession.
\param rVer     On return, pointer to selected version value.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern  MSTATUS
EAP_SIMGetSelectedVersion(void *eap_sim, ubyte2 *rVer)
{
    eapSimCb *eapSim = (eapSimCb *)eap_sim;

    *rVer = eapSim->selectedVersion;

    return OK;
}


/*------------------------------------------------------------------*/

/*! Determine whether an authenticator Notification's $S Bit$ is set.
This function (called by the peer) determines whether the Notification received
from the authenticator has the $S Bit$ set (which indicates a Success
Notification).

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_SIM__$

Additionally, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_sim.h

\param eap_sim  EAP-SIM session handle returned from EAP_SIMInitSession.
\param rCode    On return, pointer to determination value: $1$ if the $S Bit$ is set; otherwise $0$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern  MSTATUS
EAP_SIMGetSuccessNotifCode(void *eap_sim, ubyte *rCode)
{
    eapSimCb *eapSim = (eapSimCb *)eap_sim;
    *rCode = 0;

    if (eapSim->notifCode & EAP_SIM_NOTIF_S_BIT)
        *rCode = 1;

    return OK;
}


/*------------------------------------------------------------------*/
#endif /*defined(__ENABLE_DIGICERT_EAP_SIM__)  */
#endif /* (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))*/
