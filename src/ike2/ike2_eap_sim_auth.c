/**
 * @file  ike2_eap_sim_auth.c
 * @brief IKEv2 IKEv2 EAP-SIM Authenticator
 *
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     +   \c \__ENABLE_DIGICERT_EAP_AUTH__
 *     +   \c \__ENABLE_DIGICERT_EAP_SIM__
 *     +   \c \__DISABLE_DIGICERT_IKE_EAP__ must not be defined
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

#if defined(__ENABLE_DIGICERT_IKE_SERVER__)
#if defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_SIM__) && !defined(__DISABLE_DIGICERT_IKE_EAP__)

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../common/random.h"

#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_sim.h"

#include "../ipsec/ipsec.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ikesa.h"
#include "../ike2/ike2_eap.h"


/*------------------------------------------------------------------*/

extern ubyte4 g_ikeEapInstId; /* EAP instance */
extern ikeSettings m_ikeSettings;


/*------------------------------------------------------------------*/

static ubyte2 versionList[] = {1, 2};
static ubyte2 versionListLen = 2;


/*------------------------------------------------------------------*/

typedef struct appCtrlBlk_t
{
    eapSimCb           *eapSim;
    ubyte              sentErr;

    /* Result Indication Supported Flag  */
    ubyte              eapSimResultInd;

} appCtrlBlk;


/*------------------------------------------------------------------*/

static MSTATUS
EAP_SIM_AuthInitFunc(struct ike2eap *pxEap)
{
    MSTATUS status = OK;

    eapSimConfig eapSimCfg = { 0 };

    ubyte *poMsk = NULL;
    appCtrlBlk *cb = NULL;

    /* allocate */
    if ((NULL == (poMsk = (ubyte *) MALLOC(EAP_SIM_MSK_LEN))) || /* MSK */
        (NULL == (cb = (appCtrlBlk *) MALLOC(sizeof(appCtrlBlk)))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)cb, 0x00, sizeof(appCtrlBlk));

    cb->eapSimResultInd = 1; /* support Result Ind */

    /* initialize SIM/AKA session */
    eapSimCfg.send_result_ind = cb->eapSimResultInd;
    eapSimCfg.sessionType = EAP_SESSION_TYPE_AUTHENTICATOR;

    if (EAP_PROTO_AKA == pxEap->proto)
        eapSimCfg.aka = 1;

    if (OK > (status = EAP_SIMInitSession(cb, (void **)&cb->eapSim, eapSimCfg)))
        goto exit;

    if (OK > (status = EAP_SIMSetImplementedVersion(cb->eapSim,
                                        versionList, versionListLen)))
        goto exit;

    /* done */
    pxEap->dwMskLen = EAP_SIM_MSK_LEN; /* 64 */
    pxEap->poMsk = poMsk;
    pxEap->pCbData = cb;

    poMsk = NULL;
    cb = NULL;

exit:
    if (poMsk) FREE(poMsk);
    if (cb)
    {
        if (cb->eapSim) EAP_SIMDeleteSession(cb->eapSim);
        FREE(cb);
    }
    return status;
} /* EAP_SIM_AuthInitFunc */


/*------------------------------------------------------------------*/

static MSTATUS
EAP_SIM_AuthDelFunc(struct ike2eap *pxEap)
{
    MSTATUS status = OK;

    appCtrlBlk *cb;
    if (NULL != (cb = (appCtrlBlk *) pxEap->pCbData))
    {
        if (cb->eapSim) EAP_SIMDeleteSession(cb->eapSim);
        pxEap->pCbData = NULL;
        FREE(cb);
    }

    return status;
} /* EAP_SIM_AuthDelFunc */


/*------------------------------------------------------------------*/

static MSTATUS
authProcessIdentityResponse(struct ike2eap *pxEap,
                            ubyte *data, ubyte4 len,
                            eapMethodType *method_type,
                            ubyte **reqData, ubyte4 *reqLen)
{
    MSTATUS  status = OK;

    ubyte*   pos;
    ubyte4   id_len;
    ubyte*   identity;

    appCtrlBlk *cb = (appCtrlBlk *) pxEap->pCbData;

    /* set identity */
    pos = data + sizeof(eapHdr_t) + 1;
    id_len = len - sizeof(eapHdr_t) - 1;
    EAP_setIdentity(pxEap->pSession, g_ikeEapInstId, pos, id_len);
    EAP_getIdentity(pxEap->pSession, g_ikeEapInstId, &identity, &id_len);

    /* TBD : map identity to method */

    /* Send Start Req  Send ID Any*/
    if (OK > (status = EAP_SIMSetIdentity(cb->eapSim, identity, (ubyte2)id_len)))
        goto exit;

    if (EAP_PROTO_AKA == pxEap->proto)
    {
        *method_type = EAP_TYPE_AKA;
        status = EAP_AKASendIdentityReq(cb->eapSim, reqData, reqLen,
                                        EAP_SIM_AT_ANY_ID_REQ,
                                        ++((eapHdr_t *)data)->id);
    }
    else
    {
        *method_type = EAP_TYPE_SIM;
        status = EAP_SIMSendStartReq(cb->eapSim, reqData, reqLen,
                                     EAP_SIM_AT_ANY_ID_REQ,
                                     ++((eapHdr_t *)data)->id);
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
EAP_SIM_AuthReceivePktCallback(ubyte *appSessionHdl,
                               eapMethodType type,
                               eapCode code, ubyte id,
                               ubyte *data, ubyte4 len,
                               ubyte *opaque_data)
{
    MSTATUS status = OK;
    ubyte4 eapReqLen = 0;
    ubyte sendReq = 0;
    ubyte *reqData = NULL;
    eapMethodType methodType = 0;
    eapMethodState methodState = EAP_METHOD_STATE_INIT;
    eapMethodDecision decision = 0;
    eapCode sendCode = 0;
    ubyte freebuffer = 0;

    struct ike2eap *pxEap = (struct ike2eap *)appSessionHdl;
    appCtrlBlk *cb = (appCtrlBlk *) pxEap->pCbData;

    MOC_UNUSED(opaque_data);

    switch (code)
    {
        case EAP_CODE_RESPONSE :
            break;
        case EAP_CODE_REQUEST :
        case EAP_CODE_SUCCESS :
        case EAP_CODE_FAILURE :
        default:
        {
            status = ERR_EAP_INVALID_CODE;
            DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte *)"Invalid EAP Code", status);
            break;
        }
    }

    if (OK != status)
        goto exit;

    switch (type)
    {
        case EAP_TYPE_NONE :
        {
            /* set error code */
            status = ERR_EAP_INVALID_METHOD_TYPE;
            break;
        }

        case EAP_TYPE_IDENTITY :
        {
            status = authProcessIdentityResponse(pxEap, data, len,
                                                 &methodType,
                                                 &reqData, &eapReqLen);
            if (OK == status && eapReqLen != 0)
            {
                sendCode = EAP_CODE_REQUEST;
                methodState = EAP_METHOD_STATE_PROPOSED;
                decision = EAP_METHOD_DECISION_CONTINUE;
                sendReq = 1;
                freebuffer = 1;
            }
            break;
        }

        case EAP_TYPE_NOTIFICATION :
        {
            /* Log msg */
            methodType = EAP_TYPE_NOTIFICATION;
            break;
        }

        case EAP_TYPE_SIM :
        case EAP_TYPE_AKA :
        {
            eapSimStatus sessionState;

            if ((IKE_EAP_PROTO_T)type != pxEap->proto)
            {
                status = ERR_EAP_INVALID_METHOD_TYPE;
                break;
            }

            /* process response */
            if (EAP_TYPE_AKA == type)
                status = EAP_AKAProcessPkt(cb->eapSim, data, (ubyte2)len,
                                           &reqData, &eapReqLen, &sessionState);
            else
                status = EAP_SIMProcessPkt(cb->eapSim, data, (ubyte2)len,
                                           &reqData, &eapReqLen, &sessionState);

            if ((OK > status) &&
                (EAP_SIM_STATUS_RECV_CHALLENGE_RESP != sessionState))
            {
                goto fail; /* Send FAILURE */
            }

            switch (sessionState)
            {
                case EAP_SIM_STATUS_RECV_START_RESP :
                {
                    ubyte* ident; ubyte4 idLen;
                    ubyte* secret; ubyte4 secretLen;
                    ubyte Kc[24];  /*EAP_SIM_KC_LEN[8] x EAP_SIM_MAX_RAND[3]*/
                    ubyte Sres[12];/*EAP_SIM_SRES_LEN[4] x EAP_SIM_MAX_RAND[3]*/
                    ubyte rnd[48]; /*EAP_SIM_RAND_LEN[16] x EAP_SIM_MAX_RAND[3]*/
                    ubyte num_rand, i, *cur;

                    /* Get the Rand and Triplet (Kc Sres) based upon Identity
                       If the Identity is not acceptable can send
                       a Start Req again to get FAST or PERM INcrement the Id */
                    EAP_SIMGetIdentity(cb->eapSim, &ident, &idLen); /* always returns OK*/

                    /* Get the triplets from HLR */
                    if (NULL == m_ikeSettings.funcPtrLookupSecret)
                    {
                        status = ERR_IKE_CONFIG;
                        goto exit;
                    }
                    if (OK > (status = m_ikeSettings.funcPtrLookupSecret(
                                                 ident, idLen,
                                                 &secret, &secretLen,
                                                 pxEap->pxSa->serverInstance)))
                        goto fail;

                    num_rand = (ubyte)(secretLen / (EAP_SIM_RAND_LEN +
                                                    EAP_SIM_SRES_LEN +
                                                    EAP_SIM_KC_LEN));
                    if ((EAP_SIM_MAX_RAND != num_rand) &&
                        ((EAP_SIM_MAX_RAND-1) != num_rand)) /* must be 2 or 3 */
                    {
                        status = ERR_EAP_SIM_INVALID_NUM_RAND;
                    }
                    else
                    for (cur = secret, i=0; i < num_rand; i++)
                    {
                        DIGI_MEMCPY(rnd + (i * EAP_SIM_RAND_LEN), cur, EAP_SIM_RAND_LEN);
                        cur += EAP_SIM_RAND_LEN;
                        DIGI_MEMCPY(Sres + (i * EAP_SIM_SRES_LEN), cur, EAP_SIM_SRES_LEN);
                        cur += EAP_SIM_SRES_LEN;
                        DIGI_MEMCPY(Kc + (i * EAP_SIM_KC_LEN), cur, EAP_SIM_KC_LEN);
                        cur += EAP_SIM_KC_LEN;
                    }

                    if (NULL != m_ikeSettings.funcPtrReleaseSecret)
                        m_ikeSettings.funcPtrReleaseSecret(secret, secretLen,
                                                   pxEap->pxSa->serverInstance);

                    if (OK > status) goto fail;

                    status = EAP_SIMSendChallengeReq(cb->eapSim,
                                                     &reqData, &eapReqLen,
                                                     rnd, num_rand,
                                                     Kc, Sres,
                                                     NULL/*at_next_psuedo*/,0/* at_psuedo_len*/,
                                                     NULL /*at_next_reauthid*/,0/*at_reauthid_len*/,
                                                     ++id);
                    if (OK > status) goto fail; /* Send FAILURE */

                    decision = EAP_METHOD_DECISION_CONTINUE;
                    sendCode = EAP_CODE_REQUEST;
                    break;
                }

                case EAP_AKA_STATUS_RECV_IDENTITY_RESP:
                {
                    ubyte* ident; ubyte4 idLen;
                    ubyte* secret; ubyte4 secretLen;
                    ubyte* rnd; /*EAP_SIM_RAND_LEN[16]*/
                    ubyte* autn;/*EAP_AKA_AUTN_LEN(16]*/
                    ubyte* CK;  /*EAP_AKA_CK_LEN[16]*/
                    ubyte* IK;  /*EAP_AKA_IK_LEN[16]*/
                    ubyte* res; ubyte2 resLen; /* must be between 4 and 16 */
                    ubyte *cur;

                    /* Get the AUTN/RAND/IC/KC/RES from the HLR based upon Identity
                       If the Identity is not acceptable can send
                       an Identity Req again to get FAST or PERM INcrement the Id */
                    EAP_SIMGetIdentity(cb->eapSim, &ident, &idLen);

                    /* Get the quintuplet vector from HLR */
                    if (NULL == m_ikeSettings.funcPtrLookupSecret)
                    {
                        status = ERR_IKE_CONFIG;
                        goto exit;
                    }
                    if (OK > (status = m_ikeSettings.funcPtrLookupSecret(
                                                 ident, idLen,
                                                 &secret, &secretLen,
                                                 pxEap->pxSa->serverInstance)))
                        goto fail;

                    resLen = (ubyte2)(secretLen - (EAP_SIM_RAND_LEN +
                                                   EAP_AKA_AUTN_LEN +
                                                   EAP_AKA_CK_LEN +
                                                   EAP_AKA_IK_LEN));
                    if ((4 > resLen) || (16 < resLen)) /* must be 4-16 */
                    {
                        status = ERR_EAP_AKA_INVALID_RES;
                    }
                    else
                    {
                        cur = secret;
                        rnd  = cur; cur += EAP_SIM_RAND_LEN;
                        autn = cur; cur += EAP_AKA_AUTN_LEN;
                        CK   = cur; cur += EAP_AKA_CK_LEN;
                        IK   = cur; cur += EAP_AKA_IK_LEN;
                        res  = cur;
                    }

                    if (OK <= status)
                    status = EAP_AKASendChallengeReq(cb->eapSim,
                                                     &reqData, &eapReqLen,
                                                     rnd, autn, CK, IK,
                                                     res, resLen * 8, /* bits */
                                                     NULL, 0, /*pueso*/
                                                     NULL, 0, /*reauth*/
                                                     ++id);

                    if (NULL != m_ikeSettings.funcPtrReleaseSecret)
                        m_ikeSettings.funcPtrReleaseSecret(secret, secretLen,
                                                   pxEap->pxSa->serverInstance);

                    if (OK > status) goto fail; /* Send FAILURE */

                    decision = EAP_METHOD_DECISION_CONTINUE;
                    sendCode = EAP_CODE_REQUEST;
                    break;
                }

                case EAP_SIM_STATUS_RECV_CHALLENGE_RESP :
                {
                    /* If we support Result Ind  and the
                       client Supports it , send Notification */
                    ubyte rInd=0;
                    EAP_SIMGetResultInd(cb->eapSim , &rInd);
                    if (cb->eapSimResultInd && rInd)
                    {
                        if (OK > status)
                        {
                            status = EAP_SIMSendNotificationReq(cb->eapSim,
                                                    &reqData, &eapReqLen,
                                                    0/* at_counter*/,
                                                    EAP_SIM_NOTIF_P_BIT, ++id);
                            if (OK > status) goto fail; /* Send FAILURE */

                            decision = EAP_METHOD_DECISION_FAILURE;
                            cb->sentErr = 1;
                        }
                        else
                        {
                            status = EAP_SIMSendNotificationReq(cb->eapSim,
                                                    &reqData, &eapReqLen,
                                                    0/* at_counter*/,
                                                    EAP_SIM_NOTIF_S_BIT, ++id);
                            if (OK > status) goto fail; /* Send FAILURE */

                            decision = EAP_METHOD_DECISION_CONTINUE;
                        }
                        sendCode = EAP_CODE_REQUEST;
                    }
                    else
                    {
                        if (OK > status) goto fail; /* Send FAILURE */

                        /* else send SUCCESS */
                        sendCode = EAP_CODE_SUCCESS;
                    }
                    break;
                }

                case EAP_SIM_STATUS_RECV_NOTIFICATION_RESP :
                {
                    /* If we have sent an error notification Send Failure */
                    if (cb->sentErr)
                        sendCode = EAP_CODE_FAILURE;
                    else
                        sendCode = EAP_CODE_SUCCESS; /* else send SUCCESS */
                    break;
                }

                case EAP_SIM_STATUS_RECV_REAUTH_RESP :
                {
                    /* To code in this in the  App */
                    goto fail; /* ??? */
                    break;
                }

                case EAP_AKA_STATUS_RECV_SYNC_FAIL_RESP :
                {
                    /* We need to send the AUTS recevived from the peer
                       to the AuC / HLR to Sync the Seq #
                       and restart the Converstation  or send a CHallenge Req again*/
                    ubyte *auts;
                    if (OK == (status = EAP_AKAGetAuts(cb->eapSim, &auts)))
                    {
                    }
                }
                /* fall through */
                case EAP_AKA_STATUS_RECV_AUTH_REJECT_RESP :
                case EAP_SIM_STATUS_RECV_CLIENT_ERROR_CODE :

                default:
                    goto fail; /* ??? */
                    break;
            }

            if (EAP_CODE_SUCCESS == sendCode)
            {
                /* get MSK */
                ubyte *key; ubyte4 keyLen;
                if (OK > (status = EAP_SIMgetKey(cb->eapSim, EAP_SIM_MSK_KEY, &key, &keyLen)))
                    goto fail; /* Send FAILURE */

                DIGI_MEMCPY(pxEap->poMsk, key, keyLen);

                /* send SUCCESS */
                decision = EAP_METHOD_DECISION_SUCCESS;
                methodState = EAP_METHOD_STATE_END;
            }
            else if (EAP_CODE_FAILURE == sendCode)
            {
                /* send FAILURE */
                decision = EAP_METHOD_DECISION_FAILURE;
                methodState = EAP_METHOD_STATE_END;
            }
            else
            {
                methodType = type;
/*              decision = EAP_METHOD_DECISION_CONTINUE;*/
                methodState = EAP_METHOD_STATE_CONTINUE;
                freebuffer = 1;
            }
            sendReq = 1;
            break;
        }

        case EAP_TYPE_NAK :
        {
            /* check for additional methods */
            break;
        }

        default :
        {
            break;
        }
    }

    goto send;

fail:
    /* Send FAILURE */
    sendCode = EAP_CODE_FAILURE;
    decision = EAP_METHOD_DECISION_FAILURE;
    methodState = EAP_METHOD_STATE_END;
    sendReq = 1;

    status = OK;

send:
    if (sendReq)
    {
        status = EAP_ulTransmit(pxEap->pSession, g_ikeEapInstId,
                                methodType, sendCode,
                                decision, methodState,
                                reqData, eapReqLen);
    }

    if (freebuffer && NULL != reqData)
    {
        FREE(reqData);
    }

exit:
    return status;
} /* EAP_SIM_AuthReceivePktCallback */


/*------------------------------------------------------------------*/

static eapMethodDef_t methodDef =
{/*
        eapMethodType,
        ubyte method_name[EAP_MAX_METHOD_NAME],
        funcPtr_ulReceiveCallback,
        funcPtr_ulReceivePassthruCallback,
        funcPtr_ulReceiveIndication,
        funcPtr_ulMICVerify,
        funcPtr_ulGetMethodstate,
        funcPtr_ulGetDecision,
        funcPtr_llTransmitPacket
  */
        EAP_TYPE_NONE,
        "IKE_EAP_SIM_AUTH",
        EAP_SIM_AuthReceivePktCallback,
        NULL,
        IKE_eapReceiveIndication,
        IKE_eapVerifyMIC,
        IKE_eapGetMethodState,
        IKE_eapGetDecision,
        IKE_eapTransmitPktCallback
};

const IKE_eapSuiteInfo g_ikeEapSIMauthSuite =
{
    EAP_SIM_AuthInitFunc,
    EAP_SIM_AuthDelFunc,
    &methodDef,
    EAP_SESSION_TYPE_AUTHENTICATOR,
#ifdef __ENABLE_IKE_EAP_ONLY__
    TRUE
#endif
};


#endif /* defined(__ENABLE_DIGICERT_EAP_AUTH__) && defined(__ENABLE_DIGICERT_EAP_SIM__) && !defined(__DISABLE_DIGICERT_IKE_EAP__) */
#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */

