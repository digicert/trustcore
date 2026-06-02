/**
 * @file  eap.c
 * @brief EAP (Extensible Authentication Protocol) developer API
 *
 * @details    Core EAP API functions for authentication
 * @since      1.41
 * @version    1.41 and later
 *
 * @flags      Compilation flags required:
 *     To enabled any of this file's functions, at least one of the following flags
 *     must be defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_AUTH__
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__
 *     Whether the following flags are defined determines which additional header files
 *     are included:
 *     +   \c \__DEBUG_SSL_TIMER__
 *     +   \c \__ENABLE_ALL_DEBUGGING__
 *     Whether the following flags are defined determines which functions are enabled:
 *     +   \c \__ENABLE_ALL_DEBUGGING__
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

#include "../common/mtypes.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/mocana.h"
#include "../common/debug_console.h"
#include "../common/sizedbuffer.h"
#include "../common/mbitmap.h"
#include "../crypto/crypto.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/rsa.h"
#include "../crypto/des.h"
#include "../crypto/dh.h"
#include "../crypto/ca_mgmt.h"
#include "../common/redblack.h"
#include "../common/timer.h"
#include "../eap/eap.h"
#include "../eap/eap_auth.h"
#include "../eap/eap_session.h"
#include "../eap/eap_srp.h"

#if (defined(__DEBUG_SSL_TIMER__) || defined(__ENABLE_ALL_DEBUGGING__))
#include <stdio.h>
#endif


/*------------------------------------------------------------------*/

#define EAP_CONNECT_DISABLED        0
#define EAP_CONNECT_CLOSED          1
#define EAP_CONNECT_NEGOTIATE       2
#define EAP_CONNECT_OPEN            3


/*------------------------------------------------------------------*/

const ubyte nullIdentity [] = "NULL";

const ubyte * eapMethodStateString[] =
{
    (ubyte *)"EAP_METHOD_STATE_INIT",
    (ubyte *)"EAP_METHOD_STATE_CONT",
    (ubyte *)"EAP_METHOD_STATE_MAY_CONT",
    (ubyte *)"EAP_METHOD_STATE_DONE",
    (ubyte *)"EAP_METHOD_STATE_PROPOSED",
    (ubyte *)"EAP_METHOD_STATE_CONTINUE",
    (ubyte *)"EAP_METHOD_STATE_END"
};

const ubyte * eapMethodDecisionString[] =
{
    (ubyte *)"EAP_METHOD_DECISION_NONE",
    (ubyte *)"EAP_METHOD_DECISION_FAIL",
    (ubyte *)"EAP_METHOD_DECISION_COND_SUCC",
    (ubyte *)"EAP_METHOD_DECISION_UNCOND_SUCC",
    (ubyte *)"EAP_METHOD_DECISION_CONTINUE",
    (ubyte *)"EAP_METHOD_DECISION_SUCCESS",
    (ubyte *)"EAP_METHOD_DECISION_FAILURE"
};

/*------------------------------------------------------------------*/

#ifdef __ENABLE_ALL_DEBUGGING__
extern ubyte4 gStartTime;
#endif


/*------------------------------------------------------------------*/

/* Globals */
eapGlobal_t gEapGlobalState;


/*------------------------------------------------------------------*/

/* Prototypes */
static MSTATUS eap_sessionIdCompare(const void* cookie,
                                    const void *p1, const void *p2,
                                    sbyte4 *comparResult);

static MSTATUS eap_instanceIdCompare(const void* cookie,
                                     const void *p1, const void *p2,
                                     sbyte4 *comparResult);

static MSTATUS
eap_sessionDelete(eapSessionCb_t* eapSession);

#ifdef __ENABLE_DIGICERT_EAP_AUTH__
static MSTATUS
EAP_authSessionTimeout(void *session);
#endif


/*------------------------------------------------------------------*/

/*! Pass a packet from the upper (method) layer to the EAP stack.
This function is called by the authenticator or peer to pass a packet from the
upper (method) layer to the EAP stack. The EAP layer copies the packet sent by
the application, builds the EAP header using the $packet_type$ parameter's
information, and then passes the packet to the lower (physical) layer to be
transmitted to the peer or authenticator, respectively.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param appSessionHandle Cookie given by the application to identify the session.
\param instanceId       EAP instance ID returned from EAP_initInstance.
\param methodDef        Structure containing method information such as method type and callback functions.
\param cfgParam         Structure containing desired configuration parameters for this EAP session.
\param eapSessionHdl    On return, pointer to EAP session handle.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_sessionModify
\sa EAP_sessionDelete
\sa EAP_sessionEnable
\sa EAP_sessionDisable

*/
extern MSTATUS
EAP_sessionCreate(ubyte * appSessionHandle,
                  ubyte4 instanceId,
                  eapMethodDef_t methodDef,
                  eapSessionConfig_t cfgParam,
                  ubyte ** eapSessionHdl)
{
    eapSessionCb_t*     eapSession   = NULL;
    eapSessionCb_t*     tSession     = NULL;
    eapInstanceCb_t*    instance     = NULL;
    eapInstanceCb_t     tInstance;
    MSTATUS             status = OK;

    tInstance.instanceId = instanceId;

    /*
        Check That The Ul and LL Callback Fns are defined
    */
    if (((NULL == methodDef.funcPtr_ulReceiveCallback) ||
        (NULL == methodDef.funcPtr_ulReceivePassthruCallback)) &&
        (NULL == methodDef.funcPtr_llTransmitPacket))
    {
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_sessionCreate: UL/LL Fns Cannot be NULL");
        status = ERR_EAP_INVALID_CALLBACK_FN;
        goto exit;
    }

    if ((EAP_SESSION_TYPE_AUTHENTICATOR != cfgParam.sessionType) &&
        (EAP_SESSION_TYPE_PEER != cfgParam.sessionType)          &&
        (EAP_SESSION_TYPE_PASSTHROUGH != cfgParam.sessionType))
    {
        status = ERR_EAP_INVALID_SESSION_TYPE;
        goto exit;
    }

    if (OK > (status = RTOS_mutexWait(gEapGlobalState.instanceMutex)))
    {
        goto exit;
    }

    if (OK > (status = REDBLACK_find(gEapGlobalState.instanceTree, (const void *)&tInstance, (const void **) &instance)))
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_sessionCreate: Unable to find Instance ", instanceId);
        RTOS_mutexRelease(gEapGlobalState.instanceMutex);
        goto exit;
    }

    if (OK > (status = RTOS_mutexRelease(gEapGlobalState.instanceMutex)))
    {
        goto exit;
    }

    if (NULL == instance)
    {
        status = ERR_EAP_INSTANCE_ID_NOT_FOUND;
        goto exit;
    }

    eapSession = (eapSessionCb_t *)MALLOC (sizeof(eapSessionCb_t));
    if (NULL == eapSession)
    {
        instance->gStats.eap_no_of_failed_sessions++;
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)eapSession, 0, sizeof(eapSessionCb_t));
    /* Alloc Session Id */
    if (OK > (status = RTOS_mutexWait(instance->sessionMutex)))
    {
        FREE(eapSession);
        goto exit;
    }

    status = MBITMAP_findVacantIndex ((bitmapDescr *)instance->sessionIdbMap,
                                     &eapSession->sessionId);
    if (OK > status)
    {
        instance->gStats.eap_no_of_failed_sessions++;
        FREE (eapSession);
        RTOS_mutexRelease(instance->sessionMutex);
        goto exit;
    }

    /* Insert the session in the tree */
    status = REDBLACK_findOrInsert(instance->sessionTree, eapSession, (const void **)&tSession);

    if ((NULL != tSession) || (OK > status))
    {
        instance->gStats.eap_no_of_failed_sessions++;
        if (OK == status)
            status = ERR_RBTREE_INSERT_FAILED;
        MBITMAP_clearIndex ((bitmapDescr*)instance->sessionIdbMap,
                            eapSession->sessionId);
        FREE (eapSession);
        RTOS_mutexRelease(instance->sessionMutex);
        goto exit;
    }

    instance->gStats.eap_no_of_create_sessions++;

    DIGI_MEMCPY((ubyte *)&eapSession->methodDef,
               (const ubyte *)&methodDef, sizeof(eapMethodDef_t));
    DIGI_MEMCPY((ubyte *)&eapSession->eapSessionCfg ,
               (const ubyte *)&cfgParam, sizeof(eapSessionConfig_t));

    eapSession->appSessionHandle = appSessionHandle;
    eapSession->session_type     = cfgParam.sessionType;
    eapSession->eapInstance      = instance;
    *eapSessionHdl               = ((ubyte *)((uintptr)eapSession->sessionId));

    if (OK > (status = RTOS_mutexRelease(instance->sessionMutex)))
    {
        goto exit;
    }

    if (EAP_SESSION_TYPE_AUTHENTICATOR == cfgParam.sessionType ||
        EAP_SESSION_TYPE_PASSTHROUGH == cfgParam.sessionType)
    {
#if defined(__ENABLE_DIGICERT_EAP_AUTH__)
        if (cfgParam.eap_ul_timeout)
        {
            TIMER_queueTimer((void *)eapSession, eapSession->eapInstance->timerSession, cfgParam.eap_ul_timeout,0);
        }
        EAP_authProcessRestart (eapSession);
#else
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_sessionCreate: __ENABLE_DIGICERT_EAP_AUTH__ Not Defined and Session Type is Auth\n");
#endif
    }

    if (EAP_SESSION_TYPE_PEER == cfgParam.sessionType)
    {
#if defined(__ENABLE_DIGICERT_EAP_PEER__)
        if (cfgParam.eap_ul_timeout)
        {
            TIMER_queueTimer((void *)eapSession, eapSession->eapInstance->timerSession,cfgParam.eap_ul_timeout,0);
        }
        EAP_peerProcessRestart (eapSession);
#else
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_sessionCreate: __ENABLE_DIGICERT_EAP_PEER__ Not Defined and Session Type is PEER\n");
#endif
    }

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_sessionCreate: Create EAP Session ", eapSession->sessionId);
    DIGICERT_log((sbyte4)MOCANA_EAP, (sbyte4)LS_INFO, (sbyte *)"Created EAP Session.");

    instance->gStats.eap_no_of_active_sessions++;

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_sessionCreate: failed, status = ", (sbyte4)status);

    return status;
} /* EAP_sessionCreate */


/*------------------------------------------------------------------*/

/*! Enable an EAP session.
This function enables an existing EAP session, sets its current state to
$EAP_INITIALIZE$, and resets all remaining parameters. It cannot be called before
the corresponding port is enabled, and it must be called in order for the EAP
stack to process any packets.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID returned from EAP_initInstance.
\param methodDef        Structure containing method information such as method type and callback functions.
\param cfgParam         Structure containing desired configuration parameters for this EAP session.
\param modifiedFlag     Bitmask sum of all variables to modify:\n
\n
&bull; $EAP_MOD_METHOD_DEF$\n
&bull; $EAP_MOD_SESSION_TYPE$\n
&bull; $EAP_MOD_SESSION_MTU$\n
&bull; $EAP_MOD_SESSION_UL_TIMEOUT$\n
&bull; $EAP_MOD_SESSION_RETRANS_TIMEOUT$\n
&bull; $EAP_MOD_SESSION_MAX_RETRANS$\n

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_sessionCreate
\sa EAP_sessionDelete
\sa EAP_sessionEnable
\sa EAP_sessionDisable

*/
extern MSTATUS
EAP_sessionModify(ubyte * eapSessionHdl,
                  ubyte4 instanceId,
                  eapMethodDef_t methodDef,
                  eapSessionConfig_t cfgParam,
                  ubyte4 modifiedFlag)
{
    eapSessionCb_t* eapSession = NULL;
    MSTATUS         status     = OK;

    /* Lookup Session */
    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl),
                                  instanceId,&eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;
    /*
    Check MTU Size, Check Retransmit Time, and Times and restart valid timers
    if (restransmit time is not given then at least the Session Neg Time should
    be given to avoid dangling sessions
    */

    if (EAP_SESSION_TYPE_PEER == eapSession->session_type)
    {
        /* If this value has changed then only do this */
        if (modifiedFlag & EAP_MOD_SESSION_UL_TIMEOUT)
        {
            if (eapSession->eapSessionCfg.eap_ul_timeout)
            {
                TIMER_unTimer(eapSession,eapSession->eapInstance->timerSession);
            }
            eapSession->eapSessionCfg.eap_ul_timeout = cfgParam.eap_ul_timeout;
            if (cfgParam.eap_ul_timeout)
            {
                TIMER_queueTimer((void *)eapSession, eapSession->eapInstance->timerSession,
                                 eapSession->eapSessionCfg.eap_ul_timeout, 0);
            }
        }
        if (modifiedFlag & EAP_MOD_SESSION_MTU)
        {
            eapSession->eapSessionCfg.eap_mtu = cfgParam.eap_mtu;
        }
        if (modifiedFlag & EAP_MOD_METHOD_DEF)
        {
            if (EAP_TYPE_NONE == eapSession->eapSelectedMethod ||
                methodDef.method_type == eapSession->eapSelectedMethod)
            {
                DIGI_MEMCPY((ubyte *)&eapSession->methodDef,
                        (const ubyte *)&methodDef, sizeof(eapMethodDef_t));
            }
            else
            {
                DIGICERT_log((sbyte4)MOCANA_EAP, (sbyte4)LS_INFO,
                (sbyte *)"Cannot modify method type after method is selected.");
                status = ERR_EAP_SESSION_MODIFY_METHOD_TYPE;
                goto exit;
            }
        }
    }
    else if ((EAP_SESSION_TYPE_AUTHENTICATOR == eapSession->session_type) ||
             (EAP_SESSION_TYPE_PASSTHROUGH   == eapSession->session_type))
    {
        /* If this value has changed then only do this */
        if (modifiedFlag & EAP_MOD_SESSION_UL_TIMEOUT)
        {
            if (eapSession->eapSessionCfg.eap_ul_timeout)
            {
                TIMER_unTimer(eapSession, eapSession->eapInstance->timerSession);
            }
            eapSession->eapSessionCfg.eap_ul_timeout = cfgParam.eap_ul_timeout;
            if (cfgParam.eap_ul_timeout)
            {
                TIMER_queueTimer((void *)eapSession, eapSession->eapInstance->timerSession,
                                 eapSession->eapSessionCfg.eap_ul_timeout, 0);
            }
        }
        if (modifiedFlag & EAP_MOD_SESSION_RETRANS_TIMEOUT)
        {
            eapSession->eapSessionCfg.eap_retrans_timeout = cfgParam.eap_retrans_timeout;
        }
        if (modifiedFlag & EAP_MOD_SESSION_MAX_RETRANS)
        {
            if (eapSession->eapSessionCfg.eap_max_retrans &&
                !cfgParam.eap_max_retrans)
            {
                TIMER_unTimer(eapSession, eapSession->eapInstance->timerRetrans);
            }
            eapSession->eapSessionCfg.eap_max_retrans = cfgParam.eap_max_retrans;
        }
        if (modifiedFlag & EAP_MOD_SESSION_MTU)
        {
            eapSession->eapSessionCfg.eap_mtu = cfgParam.eap_mtu;
        }
        if (modifiedFlag & EAP_MOD_METHOD_DEF)
        {
            if (EAP_TYPE_NONE == eapSession->eapSelectedMethod ||
               methodDef.method_type == eapSession->eapSelectedMethod)
            {
                DIGI_MEMCPY((ubyte *)&eapSession->methodDef,
                        (const ubyte *)&methodDef, sizeof(eapMethodDef_t));
            }
            else
            {
                DIGICERT_log((sbyte4)MOCANA_EAP, (sbyte4)LS_INFO,
                (sbyte *)"Cannot modify method type after method is selected.");
                status = ERR_EAP_SESSION_MODIFY_METHOD_TYPE;
                goto exit;
            }
        }

        if (modifiedFlag & EAP_MOD_SESSION_TYPE)
        {
            if ((EAP_SESSION_TYPE_AUTHENTICATOR != cfgParam.sessionType) &&
               (EAP_SESSION_TYPE_PASSTHROUGH != cfgParam.sessionType))
            {
                status = ERR_EAP_INVALID_SESSION_TYPE;
                goto exit;
            }
            eapSession->session_type = cfgParam.sessionType;
        }
    }

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_sessionModify: Modified EAP Session ", eapSession->sessionId);
    DIGICERT_log((sbyte4)MOCANA_EAP, (sbyte4)LS_INFO, (sbyte *)"Modified EAP Session.");

    eapSession->eapInstance->gStats.eap_no_of_modify_sessions++;

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_sessionModify: Failed Status ", (sbyte4)status);

    return status;
} /* EAP_sessionModify */


/*------------------------------------------------------------------*/

/*! Delete an EAP session.
This function deletes an existing EAP session.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID returned from EAP_initInstance.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_sessionCreate
\sa EAP_sessionModify
\sa EAP_sessionEnable
\sa EAP_sessionDisable

*/
extern MSTATUS
EAP_sessionDelete(ubyte * eapSessionHdl,
                  ubyte4 instanceId)
{
    eapSessionCb_t* eapSession      = NULL;
    eapInstanceCb_t* instance      = NULL;
    MSTATUS         status          = OK;

    /* Lookup Session */
    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl),
                               instanceId,&eapSession);
    if ((OK > status) || (NULL == eapSession))
        goto exit;

    /* Remove from Tree */
    instance = eapSession->eapInstance;

    if (OK > (status = RTOS_mutexWait(instance->sessionMutex)))
    {
        goto exit;
    }
    status = eap_sessionDelete(eapSession);
    if (OK > (status = RTOS_mutexRelease(instance->sessionMutex)))
    {
        goto exit;
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_sessionDelete: Failed Status ", (sbyte4)status);

    return status;
} /* EAP_sessionDelete */


/*------------------------------------------------------------------*/

static MSTATUS
eap_sessionDelete(eapSessionCb_t* eapSession)
{
    MSTATUS         status          = OK;
    eapSessionCb_t* tEapSession     = NULL;

    status = REDBLACK_delete(eapSession->eapInstance->sessionTree, (void *)eapSession, (const void **) &tEapSession);

    if ((tEapSession != eapSession) || (OK > status))
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_sessionDelete: Unable to find EAP Session ", eapSession->sessionId);
        goto exit;

    }
    /* id Free */
    MBITMAP_clearIndex ((bitmapDescr*)eapSession->eapInstance->sessionIdbMap,
                            eapSession->sessionId);

    /* Unschedule Timers */
    if (eapSession->eapSessionCfg.eap_ul_timeout)
    {
        TIMER_unTimer(eapSession,eapSession->eapInstance->timerSession);
    }
    if (eapSession->eapSessionCfg.eap_max_retrans)
    {
        TIMER_unTimer(eapSession,eapSession->eapInstance->timerRetrans);
    }

    /* Free RESP Data */
    if (eapSession->eapRespData)
    {
        FREE (eapSession->eapRespData);
    }

    if (eapSession->eapIdentity)
    {
        FREE (eapSession->eapIdentity);
    }

    if (eapSession->eapReqData)
    {
        FREE (eapSession->eapReqData);
    }

    if (eapSession->eapKeyData)
    {
        FREE (eapSession->eapKeyData);
    }

#if defined(__ENABLE_DIGICERT_RADIUS_CLIENT__)
    if (eapSession->radiusMPPERecvKey)
        FREE(eapSession->radiusMPPERecvKey);

    if (eapSession->radiusMPPESendKey)
        FREE(eapSession->radiusMPPESendKey);

    if (eapSession->radiusAttrState)
        FREE(eapSession->radiusAttrState);
#endif /* __ENABLE_DIGICERT_RADIUS_CLIENT__*/

#ifdef __ENABLE_DIGICERT_EAP_SRP__
    if (EAP_SESSION_TYPE_AUTHENTICATOR == eapSession->session_type)
    {
        flushSRPstate(eapSession, EAPSRP_AUTH_STATE_NONE);
    }
    else if (EAP_SESSION_TYPE_PEER == eapSession->session_type)
    {
        flushSRPstate(eapSession, EAPSRP_PEER_STATE_NONE);
    }
#endif /*__ENABLE_DIGICERT_EAP_SRP__*/

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_sessionDelete: Deleted EAP Session ", eapSession->sessionId);
    DIGICERT_log((sbyte4)MOCANA_EAP, (sbyte4)LS_INFO, (sbyte *)"Deleted EAP Session.");

    eapSession->eapInstance->gStats.eap_no_of_active_sessions--;
    FREE(eapSession);

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_sessionDelete: Failed Status ", (sbyte4)status);

    return status;
} /* eap_sessionDelete */


/*------------------------------------------------------------------*/

/*! Restart an EAP session.
This function restarts an existing EAP session, setting its current state to
$EAP_INITIALIZE$ and resetting all remaining parameters.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID returned from EAP_initInstance.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_sessionCreate
\sa EAP_sessionModify
\sa EAP_sessionDelete
\sa EAP_sessionEnable
\sa EAP_sessionDisable

*/
extern MSTATUS
EAP_sessionRestart(ubyte * eapSessionHdl,
                   ubyte4 instanceId)
{
    eapSessionCb_t* eapSession  = NULL;
    MSTATUS         status      = OK;

    /* Lookup Session */
    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl),
                               instanceId,&eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    if (eapSession->eapRespData)
    {
        FREE (eapSession->eapRespData);
    }

    eapSession->eapRespData    = NULL;
    eapSession->eapRespDataLen = 0;

    /* Identity should be retained in case of re-auth?? */
    if (eapSession->eapIdentity)
    {
        FREE (eapSession->eapIdentity);
    }

    eapSession->eapIdentity   = NULL;
    eapSession->eapIdentityLen = 0;

    if (eapSession->eapReqData)
    {
        FREE (eapSession->eapReqData);
    }

    eapSession->eapReqData    = NULL;
    eapSession->eapReqDataLen = 0;

    if (eapSession->eapKeyData)
    {
        FREE (eapSession->eapKeyData);
    }
    eapSession->eapKeyData    = NULL;
    eapSession->eapKeyDataLen = 0;
    eapSession->eapKeyAvailable = FALSE;

    eapSession->eapInstance->gStats.eap_no_of_restart_sessions++;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_sessionRestart: Restart EAP Session ", eapSession->sessionId);
    DIGICERT_log((sbyte4)MOCANA_EAP, (sbyte4)LS_INFO, (sbyte *)"Restarted EAP Session.");

    if (eapSession->eapSuccess)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_sessionRestart: Ready For Reauth EAP Session ", eapSession->sessionId);
        DIGICERT_log((sbyte4)MOCANA_EAP, (sbyte4)LS_INFO, (sbyte *)"Reauth EAP Session.");

        /* Cannot Change Method Type */
        eapSession->eapMethodState = EAP_METHOD_STATE_INIT;
        eapSession->eapAllowNotification = TRUE;
        eapSession->eapRestart = TRUE;
        eapSession->eapSuccess = FALSE;
        eapSession->eapFail = FALSE;
        eapSession->eapKeyAvailable = FALSE;
        eapSession->eapSelectedMethod = EAP_TYPE_NONE;
        eapSession->eapRounds = 0;

        if (EAP_SESSION_TYPE_PEER == eapSession->session_type)
        {
#if defined(__ENABLE_DIGICERT_EAP_PEER__)
            /* Reschedule Timers */
            if (eapSession->eapSessionCfg.eap_ul_timeout)
            {
                TIMER_unTimer(eapSession,eapSession->eapInstance->timerSession);
                TIMER_queueTimer(eapSession,eapSession->eapInstance->timerSession,eapSession->eapSessionCfg.eap_ul_timeout,0);
            }
#endif
        }
    }
    else
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_sessionRestart: Full restart EAP Session ", eapSession->sessionId);
        DIGICERT_log((sbyte4)MOCANA_EAP, (sbyte4)LS_INFO, (sbyte *)"FULL Restarted EAP Session.");

        /* Go to INIT State */
        /* Isn't this check necessary here? */
        if (EAP_SESSION_TYPE_PEER == eapSession->session_type)
        {
#if defined(__ENABLE_DIGICERT_EAP_PEER__)
            /* Reschedule Timers */
            if (eapSession->eapSessionCfg.eap_ul_timeout)
            {
                TIMER_unTimer(eapSession,eapSession->eapInstance->timerSession);
                TIMER_queueTimer(eapSession,eapSession->eapInstance->timerSession,eapSession->eapSessionCfg.eap_ul_timeout,0);
            }
            status = EAP_peerProcessRestart(eapSession);
#endif
        }
        else if (EAP_SESSION_TYPE_AUTHENTICATOR == eapSession->session_type)
        {
#if defined(__ENABLE_DIGICERT_EAP_AUTH__)
            if (eapSession->eapSessionCfg.eap_ul_timeout)
            {
                TIMER_unTimer(eapSession, eapSession->eapInstance->timerSession);
                TIMER_queueTimer(eapSession, eapSession->eapInstance->timerSession,eapSession->eapSessionCfg.eap_ul_timeout,0);
            }
            status = EAP_authProcessRestart(eapSession);
#endif
        }
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_sessionRestart: Failed, status = ", (sbyte4)status);

    return status;
} /* EAP_sessionRestart */


/*------------------------------------------------------------------*/

/*! Enable an EAP session.
This function enables an existing EAP session, sets its current state to
$EAP_INITIALIZE$, and resets all remaining parameters. It cannot be called before
the corresponding port is enabled, and it must be called in order for the EAP
stack to process any packets.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID returned from EAP_initInstance.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_sessionCreate
\sa EAP_sessionModify
\sa EAP_sessionDisable

*/
extern MSTATUS
EAP_sessionEnable(ubyte * eapSessionHdl,
                  ubyte4 instanceId)
{
    eapSessionCb_t* eapSession  = NULL;
    byteBoolean     prev_state  = FALSE;
    MSTATUS         status      = OK;

    /* Lookup Session */
    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl),
                                  instanceId,&eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    prev_state = eapSession->eapPortEnabled;
    eapSession->eapPortEnabled = TRUE;
    if (FALSE == prev_state)
    {
        status = EAP_sessionRestart (eapSessionHdl, instanceId);
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Disable an EAP session.
This function disables an existing EAP session. When a port is disabled (for any
reason), the application should call this function for every active session on
the disabled port.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID returned from EAP_initInstance.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_sessionCreate
\sa EAP_sessionModify
\sa EAP_sessionEnable

*/
extern MSTATUS
EAP_sessionDisable(ubyte * eapSessionHdl,
                   ubyte4 instanceId)
{
    eapSessionCb_t* eapSession  = NULL;
    MSTATUS         status      = OK;

    /* Lookup Session */
    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl),
                                  instanceId, &eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    eapSession->eapPortEnabled = FALSE;

    if (EAP_SESSION_TYPE_PEER == eapSession->session_type)
    {
#if defined(__ENABLE_DIGICERT_EAP_PEER__)
        status = EAP_peerSessionDisable(eapSession);
#endif
    }
    else if (EAP_SESSION_TYPE_AUTHENTICATOR == eapSession->session_type)
    {
#if defined(__ENABLE_DIGICERT_EAP_AUTH__)
        status = EAP_authSessionDisable(eapSession);
#endif
    }

    /* Unschedule Timers */
    if (eapSession->eapSessionCfg.eap_ul_timeout)
    {
        TIMER_unTimer(eapSession,eapSession->eapInstance->timerSession);
    }
    if (eapSession->eapSessionCfg.eap_max_retrans)
    {
        TIMER_unTimer(eapSession,eapSession->eapInstance->timerRetrans);
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get current EAP authentication status.
This function retrieves the current EAP authentication status. The lower layer
uses this function if it requires an authenticated EAP session before
transmitting data but hasn't received the authentication status from the upper
layer.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID previously returned by EAP_initInstance.
\param authStatus       On return, pointer to authentication status (an
$eapAuthStatus$ enumerated value, defined in eap_proto.h).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_getAuthenticationStatus(ubyte * eapSessionHdl,
                            ubyte4 instanceId, eapAuthStatus *authStatus)
{
    eapSessionCb_t* eapSession  = NULL;
    MSTATUS         status      = OK;

    /* Lookup Session */
    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl),
                               instanceId, &eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    if (TRUE == eapSession->eapSuccess)
        *authStatus = EAP_AUTH_SUCCESS;
    else if (TRUE == eapSession->eapFail)
        *authStatus = EAP_AUTH_FAILURE;
    else
        *authStatus = EAP_AUTH_IN_PROGRESS;

exit:
    return status;
}


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_EAP_AUTH__)
/*! Start reauthorization and timer rescheduling.
This function checks the EAP session status, and if the status is $SUCCESS$,
calls EAP_sessionRestart to begin the reauthorization and timer rescheduling.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID previously returned by EAP_initInstance.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_ulStartReauth(ubyte * eapSessionHdl,
                  ubyte4 instanceId)
{
    eapSessionCb_t* eapSession  = NULL;
    MSTATUS         status      = OK;

    /* Lookup Session */
    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl), instanceId, &eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    if (FALSE == eapSession->eapSuccess)
    {
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_ulStartReauth: Not in Success State. Cannot start re-auth");
        DIGICERT_log((sbyte4)MOCANA_EAP, (sbyte4)LS_WARNING, (sbyte *)"Not in Success State. Cannot start re-auth");
        goto exit;
    }

    status = EAP_sessionRestart(eapSessionHdl, instanceId);

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

/*! Create and initialize an EAP instance and get is ID.
This function creates an EAP instance, initializes it, and returns its ID
through the $instanceId$ parameter. All subsequent function calls made for this
EAP instance use this returned ID.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param instanceId   On return, pointer to instance ID.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_initInstance(ubyte4 *instanceId)
{
    eapInstanceCb_t*    instance    = NULL;
    eapInstanceCb_t*    tInstance   = NULL;
    MSTATUS             status      = OK;
    ubyte               exitSetFlag = 0; /* Moved unroll to exit as coding practices state instead of in each error */

    /* Allocate an Instance  and Id*/
    instance = (eapInstanceCb_t *) MALLOC (sizeof(eapInstanceCb_t));

    if (NULL == instance)
    {
        gEapGlobalState.no_instance_fail++;
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte*)instance, 0, sizeof(eapInstanceCb_t));

    if (OK > (status = RTOS_mutexCreate(&instance->sessionMutex, EAP_SESSION_MUTEX, 1)))
    {
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"Semaphore initialization failed");
        goto exit;
    }

    if (OK > (status = RTOS_mutexWait(gEapGlobalState.instanceMutex)))  
        goto exit;    

    status = MBITMAP_findVacantIndex ((bitmapDescr*)gEapGlobalState.instanceIdbMap,
                                        &instance->instanceId);
    if (OK  > status)
    {
        exitSetFlag = 1;
        goto exit;
    }

    status = REDBLACK_findOrInsert(gEapGlobalState.instanceTree, (const void *)instance, (const void **) &tInstance);
    
    if ((NULL != tInstance) || (OK > status))
    {
        exitSetFlag = 2;
        if (OK == status)
            status = ERR_RBTREE_INSERT_FAILED;
        goto exit;
    }

    status = MBITMAP_createMap ((bitmapDescr**)&instance->sessionIdbMap, EAP_SESSION_ID_START, EAP_SESSION_ID_END );

    if (OK > status)
    {
        exitSetFlag = 3;
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_initInstance: Unable to Create Session MAP, status = ", status);
        goto exit;
    }

    /* Initialize tree */
    if (OK > (status = REDBLACK_allocTree (&instance->sessionTree, NULL, NULL, eap_sessionIdCompare, NULL, NULL)))
    {
        exitSetFlag = 3;
        goto exit;
    }

    status = TIMER_createTimer(EAP_timeoutCallback,&instance->timerSession);
    if (OK != status)
    {
        exitSetFlag = 3;
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_initInstance: TIMER_createTimer() failed, status = ", status);
        goto exit;
    }

    status = TIMER_createTimer(EAP_timeoutCallback,&instance->timerRetrans);
    if (OK != status)
    {
        exitSetFlag = 3;
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_initInstance: TIMER_createTimer() failed, status = ", status);
        goto exit;
    }
    gEapGlobalState.no_instance_create++;

    /* Initialize Semaphore */

    /* Initialize Timer Queue */
    *instanceId = instance->instanceId;

    if (OK > (status = RTOS_mutexRelease(gEapGlobalState.instanceMutex)))
    {
        exitSetFlag = 3;
        goto exit;
    }

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_initInstance: Create EAP Instance ", *instanceId);
    DIGICERT_log((sbyte4)MOCANA_EAP, (sbyte4)LS_INFO, (sbyte *)"Created EAP Instance");

exit:
    if (OK > status && NULL != instance)
    {
        gEapGlobalState.no_instance_fail++;
        if (NULL != instance->timerSession)
            TIMER_destroyTimer(instance->timerSession);
        if (NULL != instance->sessionTree)
            REDBLACK_freeTree(&instance->sessionTree, NULL, NULL, NULL);

        if (exitSetFlag > 1)          
            MBITMAP_clearIndex((bitmapDescr *)gEapGlobalState.instanceIdbMap,
                            instance->instanceId);

        if (NULL != tInstance)
        {
            if (exitSetFlag > 2)
                REDBLACK_delete(gEapGlobalState.instanceTree, (const void *)instance, (const void **)&tInstance);

            if (NULL != instance->sessionIdbMap)
                MBITMAP_releaseMap((bitmapDescr**)&instance->sessionIdbMap);
        }
        if (NULL != instance->sessionMutex)
        {
            status = RTOS_mutexFree(&instance->sessionMutex);
            if (exitSetFlag > 0)
                RTOS_mutexRelease(gEapGlobalState.instanceMutex);
        }

        FREE (instance);

        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_initInstance: Failed Status = ", (sbyte4)status);
    }

    return status;
} /* EAP_initInstance */


/*------------------------------------------------------------------*/

/*! Delete an EAP instance.
This function deletes an EAP instance.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param instanceId   EAP instance ID previously returned by EAP_initInstance.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_deleteInstance(ubyte4 instanceId)
{
    eapInstanceCb_t*    instance = NULL;
    eapSessionCb_t*     eapSession = NULL;
    eapInstanceCb_t     tInstance;
    MSTATUS             status = OK;
    redBlackListDescr*  rbList;

    tInstance.instanceId = instanceId;

    if (OK > (status = RTOS_mutexWait(gEapGlobalState.instanceMutex)))
    {
        goto exit;
    }

    if (OK > (status = REDBLACK_find(gEapGlobalState.instanceTree, (const void *)&tInstance, (const void **) &instance)))
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_deleteInstance: Unable to find Instance ", instanceId);
        RTOS_mutexRelease(gEapGlobalState.instanceMutex);
        goto exit;
    }

    if (NULL == instance)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_deleteInstance: Unable to find Instance ", instanceId);
        status = ERR_EAP_INSTANCE_ID_NOT_FOUND;
        RTOS_mutexRelease(gEapGlobalState.instanceMutex);
        goto exit;

    }

    if (OK > (status = REDBLACK_traverseListInit(instance->sessionTree, &rbList)))
    {
        RTOS_mutexRelease(gEapGlobalState.instanceMutex);
        goto exit;
    }

    while (OK == (status = REDBLACK_traverseListGetNext(rbList, (const void **)&eapSession)))
    {
        eap_sessionDelete(eapSession);
    }

    REDBLACK_traverseListFree(&rbList);

    if (instance->gStats.eap_no_of_active_sessions)
    {
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_deleteInstance: Unable to delete Instance ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, instanceId);
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)", number of active sessions = ", instance->gStats.eap_no_of_active_sessions);

        status = ERR_EAP_INSTANCE_HAS_SESSIONS;
        RTOS_mutexRelease(gEapGlobalState.instanceMutex);
        goto exit;
    }

    if (OK > (status = MBITMAP_clearIndex ((bitmapDescr*)gEapGlobalState.instanceIdbMap, instance->instanceId)))
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_deleteInstance: MBITMAP_clearIndex() failed, status = ", status);
    }

    /* Delete tree */
    REDBLACK_freeTree(&instance->sessionTree, NULL, NULL, NULL);

    REDBLACK_delete(gEapGlobalState.instanceTree, (const void *)instance, (const void **)&tInstance);


    status = MBITMAP_releaseMap((bitmapDescr**)&instance->sessionIdbMap);

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_deleteInstance: MBITMAP_releaseMap() failed, status = ", status);
    }

    status = TIMER_destroyTimer(instance->timerSession);
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_deleteInstance: TIMER_destroyTimer() failed, status = ", status);
    }

    status = TIMER_destroyTimer(instance->timerRetrans);
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_instanceDelete: TIMER_destroyTimer() failed, status = ", status);
    }
    status = RTOS_mutexFree(&instance->sessionMutex);

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_deleteInstance: RTOS_mutexFree() failed, status = ", status);
    }

    FREE(instance);

    gEapGlobalState.no_instance_delete++;

    if (OK > (status = RTOS_mutexRelease(gEapGlobalState.instanceMutex)))
    {
        goto exit;
    }

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_deleteInstance: Destroyed EAP Instance ", instanceId);
    DIGICERT_log((sbyte4)MOCANA_EAP, (sbyte4)LS_INFO, (sbyte *)"Destroyed EAP Instance");

exit:
    return status;
} /* EAP_deleteInstance */


/*------------------------------------------------------------------*/

/*! Initialize EAP structures, data, and stack.
This function initializes NanoEAP structures, data, and stack.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_init(void)
{
    MSTATUS status             = OK;

    if (gEapGlobalState.instanceMutex)
       goto exit;

    DIGI_MEMSET((ubyte *)&gEapGlobalState,0,sizeof(eapGlobal_t));

    /* Initialize Semaphore */
    if (OK > (status = RTOS_mutexCreate(&gEapGlobalState.instanceMutex, EAP_INSTANCE_MUTEX, 1)))
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_init: RTOS_mutexCreate() failed, status = ", status);
        goto exit;
    }

    status = MBITMAP_createMap ((bitmapDescr**)&gEapGlobalState.instanceIdbMap,
                                EAP_INSTANCE_ID_START, EAP_INSTANCE_ID_END);
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_init: MBITMAP_createMap() failed, status = ", status);
        goto exit;
    }

    /* Initialize tree */
    if (OK > (status = REDBLACK_allocTree(&gEapGlobalState.instanceTree , NULL, NULL, eap_instanceIdCompare, NULL, NULL)))
    {
        goto exit;
    }

    /* Initialize Timer Queue */
    status = TIMER_initTimer();
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_init: TIMER_initTimer() failed, status = ", status);
        goto exit;
    }

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_init: Initialized EAP Instance");
    DIGICERT_log((sbyte4)MOCANA_EAP, (sbyte4)LS_INFO, (sbyte *)"Initialized EAP ");

exit:
    if (OK > status)
    {
        if (gEapGlobalState.instanceMutex)
        {
            RTOS_mutexFree(&gEapGlobalState.instanceMutex);
            gEapGlobalState.instanceMutex = NULL;
        }
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_init: Failed Status ", (sbyte4)status);
    }

    return status;
} /* EAP_init */


/*------------------------------------------------------------------*/

/*! Clean up memory and mutexes and shut down the EAP stack.
This function performs memory and mutex cleanup, shuts down the EAP stack, and
deletes all core EAP sessions and EAP instances.

\since 2.45
\version 2.45 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_shutdown(void)
{
    MSTATUS status             = OK;
    eapInstanceCb_t*           instance;
    redBlackListDescr*  rbList;

    if (!gEapGlobalState.instanceMutex)
       goto exit;

    if (OK > (status = REDBLACK_traverseListInit(gEapGlobalState.instanceTree, &rbList)))
    {
        goto exit;
    }

    while (OK == (status = REDBLACK_traverseListGetNext(rbList, (const void **)&instance)))
    {
        EAP_deleteInstance(instance->instanceId);
    }

    REDBLACK_traverseListFree(&rbList);

    /* Delete Semaphore */
    if (OK > (status = RTOS_mutexFree(&gEapGlobalState.instanceMutex)))
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_shutdown: RTOS_mutexFree() failed, status = ", status);
        goto exit;
    }

    status = MBITMAP_releaseMap ((bitmapDescr**)&gEapGlobalState.instanceIdbMap);

    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_shutdown: MBITMAP_releaseMap() failed, status = ", status);
        goto exit;
    }

    /* Delete tree */
    REDBLACK_freeTree(&gEapGlobalState.instanceTree, NULL, NULL, NULL);

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_shutdown: Shutdown EAP Instance");
    DIGICERT_log((sbyte4)MOCANA_EAP, (sbyte4)LS_INFO, (sbyte *)"Shutdown EAP ");

    gEapGlobalState.instanceMutex = NULL;

    TIMER_deInitTimer();

exit:
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_shutdown: Failed Status ", (sbyte4)status);
    }

    DIGI_MEMSET((ubyte *)&gEapGlobalState,0,sizeof(eapGlobal_t));

    return status;
} /* EAP_shutdown */


/*------------------------------------------------------------------*/

static MSTATUS
eap_sessionIdCompare(const void *cookie,
                     const void *p1,
                     const void *p2,
                     sbyte4 *compareResults)
{
    eapSessionCb_t* a = (eapSessionCb_t *)p1;
    eapSessionCb_t* b = (eapSessionCb_t *)p2;

    if (a->sessionId < b->sessionId)
        *compareResults = -1;
    else if (a->sessionId > b->sessionId)
        *compareResults = 1;
    else
        *compareResults = 0;

    return OK;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_instanceIdCompare(const void *cookie,
                      const void *p1, const void *p2,
                      sbyte4 *compareResults)
{
    eapInstanceCb_t* a = (eapInstanceCb_t *)p1;
    eapInstanceCb_t* b = (eapInstanceCb_t *)p2;

    if (a->instanceId < b->instanceId)
        *compareResults = -1;
    else if (a->instanceId > b->instanceId)
        *compareResults = 1;
    else
        *compareResults = 0;

    return OK;
}


/*------------------------------------------------------------------*/

/*! Pass a packet from the upper (method) layer to the EAP stack.
This function is called by the authenticator or peer to pass a packet from the
upper (method) layer to the EAP stack. The EAP layer copies the packet sent by
the application, builds the EAP header using the $packet_type$ parameter's
information, and then passes the packet to the lower (physical) layer to be
transmitted to the peer or authenticator, respectively.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID returned from EAP_initInstance.
\param method_type      Any of the $eapMethodType$ enumerated values (see eap_proto.h).
\param code             Any of the $eapCode$ enumerated values (see eap_proto.h).
\param methodDecision   Any of the $eapMethodState$ enumerated values (refer
to eap_proto.h).
\param methodState     Any of the $eapMethodDecision$ enumerated values
(refer to eap_proto.h).
\param eap_data         Pointer to EAP payload.
\param eap_data_len     Number of bytes in $eap_data$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_ulTransmit(ubyte* eapSessionHdl,
               ubyte4 instanceId,
               eapMethodType method_type,
               eapCode code,
               eapMethodDecision methodDecision,
               eapMethodState methodState,
               ubyte* eap_data,
               ubyte4 eap_data_len)
{
    eapSessionCb_t *eapSession = NULL;
    MSTATUS status             = OK;

    /* Get the eapSession from the Handle */
    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl),
                                  instanceId,&eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    if (EAP_SESSION_TYPE_PEER == eapSession->session_type)
    {
#if defined(__ENABLE_DIGICERT_EAP_PEER__)
        status = EAP_peerProcessULTransmit(
                                    eapSession,
                                    method_type,
                                    code,
                                    methodDecision,
                                    methodState,
                                    eap_data,
                                    eap_data_len);
#endif
    }
    else if (EAP_SESSION_TYPE_AUTHENTICATOR == eapSession->session_type)
    {
#if defined(__ENABLE_DIGICERT_EAP_AUTH__)
        status = EAP_authProcessULTransmit(
                                    eapSession,
                                    method_type,
                                    code,
                                    methodDecision,
                                    methodState,
                                    eap_data,
                                    eap_data_len);
#endif
    }
    else if (EAP_SESSION_TYPE_PASSTHROUGH == eapSession->session_type)
    {
#if defined(__ENABLE_DIGICERT_EAP_AUTH__)
        status = EAP_passthruProcessULTransmit(
                                    eapSession,
                                    eap_data);
#endif
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Pass a received packet from the lower layer to the upper for processing.
This function is called by the lower layer to pass a received packet to the
upper EAP layer for processing. This function also looks up the session context
and passes it to the upper layer.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID returned from EAP_initInstance.
\param eap_pkt          Pointer to EAP packet
\param eap_pkt_len      Number of bytes in $eap_pkt$.
\param opaque_data      Pointer to opaque data&mdash;extra data that's passed
from the lower layer to the upper (method) layer through the EAP stack.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_ulTransmit
\sa EAP_llReceiveIndication

*/
extern MSTATUS
EAP_llReceivePacket(ubyte *eapSessionHdl,
                    ubyte4 instanceId,
                    ubyte * eap_pkt,
                    ubyte4 eap_pkt_len,
                    ubyte * opaque_data)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession;

    /* Get the eapSession from the Handle */
    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl),
                                  instanceId,&eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

#if defined(__ENABLE_ALL_DEBUGGING__)
    if ((eap_pkt) && (eap_pkt_len))
    {
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)" Received EAP packet <Upto 100 Bytes> ");
#ifndef __ENABLE_KEYVPN_LOG_SUPPRESSION__
        EAP_PrintBytes(eap_pkt, (eap_pkt_len < 100) ? eap_pkt_len : 100);
#endif
    }
#endif

    if (EAP_SESSION_TYPE_PEER == eapSession->session_type)
    {
#if defined(__ENABLE_DIGICERT_EAP_PEER__)
        status = EAP_peerProcessllReceivePacket(eapSession,
                                        eap_pkt,
                                        eap_pkt_len,
                                        opaque_data);
#endif
    }
    else if (EAP_SESSION_TYPE_AUTHENTICATOR == eapSession->session_type ||
             EAP_SESSION_TYPE_PASSTHROUGH == eapSession->session_type)
    {
#if defined(__ENABLE_DIGICERT_EAP_AUTH__)
        status = EAP_authProcessllReceivePacket(eapSession,
                                        eap_pkt,
                                        eap_pkt_len,
                                        opaque_data);
#endif
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Call expired timers' callbacks.
This function determines whether any timers have expired, and if so then calls
each expired expired timer's callback function. Your application should call
this function every 300 to 500 milliseconds.

\since 1.41
\version 2.45 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param instanceId       EAP instance ID returned from EAP_initInstance.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_checkTimers(ubyte4 instanceId)
{
    eapInstanceCb_t*    instance = NULL;
    eapInstanceCb_t     tInstance;
    MSTATUS status;

    tInstance.instanceId = instanceId;

    if (OK > (status = RTOS_mutexWait(gEapGlobalState.instanceMutex)))
    {
        goto exit;
    }

    if (OK > (status = REDBLACK_find(gEapGlobalState.instanceTree, (const void *)&tInstance, (const void **) &instance)))
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_checkTimers: Unable to find Instance ", instanceId);
        RTOS_mutexRelease(gEapGlobalState.instanceMutex);
        goto exit;
    }

    if (OK > (status = RTOS_mutexRelease(gEapGlobalState.instanceMutex)))
    {
        goto exit;
    }

    if (NULL == instance)
        goto exit;

    if (instance->timerSession)
        TIMER_checkTimer(instance->timerSession);
    if (instance->timerRetrans)
        TIMER_checkTimer(instance->timerRetrans);

exit:
    return 0;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_lookupSession(ubyte4 sessionId,
                  ubyte4 instanceId,
                  eapSessionCb_t **eapSession)
{
    eapInstanceCb_t*    instance = NULL;
    eapInstanceCb_t     tInstance;
    eapSessionCb_t      tSession, *sessionCb = NULL;
    MSTATUS             status = OK;

    *eapSession = NULL;

    tInstance.instanceId = instanceId;

    if (OK > (status = RTOS_mutexWait(gEapGlobalState.instanceMutex)))
    {
        goto exit;
    }

    if (OK > (status = REDBLACK_find(gEapGlobalState.instanceTree, &tInstance, (const void **) &instance)))
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"eap_lookupSession: Unable to find Instance ", instanceId);
        RTOS_mutexRelease(gEapGlobalState.instanceMutex);
        goto exit;
    }

    if (OK > (status = RTOS_mutexRelease(gEapGlobalState.instanceMutex)))
    {
        goto exit;
    }

    if (NULL == instance)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"eap_lookupSession: Unable to find Instance ", instanceId);
        status = ERR_EAP_INSTANCE_ID_NOT_FOUND;
        goto exit;

    }

    tSession.sessionId = sessionId;

    if (OK > (status = RTOS_mutexWait(instance->sessionMutex)))
    {
        goto exit;
    }

    if (OK > (status = REDBLACK_find(instance->sessionTree, (const void *)&tSession, (const void **) &sessionCb)))
    {
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_lookupSession: Unable to find Instance ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, instanceId);
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)" Session ", sessionId);
        RTOS_mutexRelease(gEapGlobalState.instanceMutex);
        goto exit;
    }

    if (OK > (status = RTOS_mutexRelease(instance->sessionMutex)))
    {
        goto exit;
    }

    if (NULL == sessionCb)
    {
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)"eap_lookupSession: Unable to find Instance ");
        DEBUG_INT(DEBUG_EAP_MESSAGE, instanceId);
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)" Session ", sessionId);
        status = ERR_EAP_INVALID_SESSION;
        goto exit;

    }

    *eapSession = sessionCb;

exit:
    return status;
} /* eap_lookupSession */


/*------------------------------------------------------------------*/

/*! Change EAP state machine's $EAP_SUCCESS$ or $EAP_FAILURE$ state.
This function changes the standard EAP state machine progression by applying
custom logic, which can be useful in cases such as when an EAP status response
is dropped, but the information is available through deductive reasoning (for
example, the authenticator progresses through the PPP state machine). In this
example, the peer lower layer can inform the EAP stack, enabling continued EAP
processing.

This function is called by the application to give alternate indications of
accept or reject. EAP will proceed to the $EAP_SUCCESS$ or $EAP_FAILURE$ state
according to the current state of the $decision$ variable.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID previously returned by EAP_initInstance.
\param altIndication    Alternate indication of success or failure&mdash;any of
the $eapAltIndication$ enumerated values:\n
\n
&bull; $EAP_ALT_ACCEPT$\n
&bull; $EAP_ALT_REJECT$

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_ulTransmit
\sa EAP_llReceivePacket

*/
extern MSTATUS
EAP_llReceiveIndication(ubyte *eapSessionHdl,
                        ubyte4 instanceId,
                        eapAltIndication altIndication)
{
    MSTATUS status = OK;
#if defined(__ENABLE_DIGICERT_EAP_PEER__)
    eapSessionCb_t *eapSession = NULL;

    /* Lookup Session */
    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl),
                                  instanceId,&eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    if (EAP_ALT_ACCEPT == altIndication)
    {
        if (eapSession->eapDecision != EAP_METHOD_DECISION_FAIL)
        {
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_llReceiveIndication: Received AltAccept, going to success state");
            /*SUCCESS */
            status = EAP_peerProcessAltEvent (eapSession,
                                               EAP_CODE_SUCCESS);
            goto exit;
        }
        if ((eapSession->eapMethodState != EAP_METHOD_STATE_CONT) &&
           (EAP_METHOD_DECISION_FAIL == eapSession->eapDecision))
        {
            /*FAIL */
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_llReceiveIndication: Received AltAccept, going to FAIL state");
            status = EAP_peerProcessAltEvent (eapSession,
                                               EAP_CODE_FAILURE);
            goto exit;
        }
    }
    else
    {
        /* FAIL */
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_llReceiveIndication: Received AltReject, going to FAIL state");

        status = EAP_peerProcessAltEvent(eapSession, EAP_CODE_FAILURE);
        goto exit;
    }

exit:
#endif
    return status;
}


/*------------------------------------------------------------------*/

/*! Set EAP session's authentication key.
This function sets the EAP session's authentication key to the specified value.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID previously returned by EAP_initInstance.
\param key              Pointer to desired key value.
\param keylen           Number of bytes in $key$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_getKey
*/
extern MSTATUS
EAP_setKey(ubyte * eapSessionHdl, ubyte4 instanceId,
           ubyte *key, ubyte4 keylen)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession = NULL;

    /* Lookup Session */
    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl),
                                  instanceId,&eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    if (EAP_MAX_KEY_SIZE < keylen)
    {
        status = ERR_EAP_INVALID_KEYLEN;
        goto exit;
    }

    if ((NULL == key) && keylen)
    {
        status = ERR_EAP_INVALID_KEY;
        goto exit;
    }

    if (eapSession->eapKeyData)
    {
        /* Free the previous Key */
        FREE(eapSession->eapKeyData);
        eapSession->eapKeyData = NULL;
        eapSession->eapKeyDataLen = 0;
        eapSession->eapKeyAvailable = FALSE;
    }

    if (keylen)
    {
        eapSession->eapKeyData = (ubyte *) MALLOC(keylen);

        if (NULL == eapSession->eapKeyData)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMCPY((ubyte *)eapSession->eapKeyData,
                (const ubyte *)key, keylen);

        eapSession->eapKeyDataLen = keylen;
        eapSession->eapKeyAvailable = TRUE;
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_setKey Failed Status ", (sbyte4)status);

    return status;
}


/*------------------------------------------------------------------*/

/*! Get EAP session's authentication key.
This function retrieves the EAP session's authentication key (or $NULL$ if
there's no key).

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID previously returned by EAP_initInstance.
\param key              On return, pointer to the authentication key.
\param keylen           On return, pointer to number of bytes in $key$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_setKey
*/
extern MSTATUS
EAP_getKey(ubyte * eapSessionHdl, ubyte4 instanceId,
           ubyte **key, ubyte *keylen)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession = NULL;

    /* Lookup Session */
    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl),
                                instanceId,&eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    if (eapSession->eapKeyData)
    {
        *key    = eapSession->eapKeyData;
        *keylen = (ubyte)eapSession->eapKeyDataLen;
    }
    else
    {
        status = ERR_EAP_KEY_NOTAVAILABLE;
        goto exit;
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_getKey Failed Status ", (sbyte4)status);

    return status;
}


/*------------------------------------------------------------------*/

/*! Get EAP session's status.
This function retrieves the EAP session's status.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap_session.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID previously returned by EAP_initInstance.
\param eapstatus        On return, pointer to EAP session status.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_getSessionStatus(ubyte * eapSessionHdl,
                     ubyte4 instanceId,
                     eapSessionStatus_t *eapstatus)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession = NULL;
    /* Lookup Session */
    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl),
                               instanceId,&eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    eapstatus->sessionId = eapSession->sessionId;
    eapstatus->eapDecision = eapSession->eapDecision;
    eapstatus->eapMethodState = eapSession->eapMethodState;
    eapstatus->eapSelectedMethod = eapSession->eapSelectedMethod;
    eapstatus->eapAllowNotification = eapSession->eapAllowNotification;
    eapstatus->eapCurrentId = eapSession->eapCurrentId;
    eapstatus->eapLastId = eapSession->eapLastId;
    eapstatus->eapSendCode = eapSession->eapSendCode;
    eapstatus->eapSuccess = eapSession->eapSuccess;
    eapstatus->eapFail = eapSession->eapFail;
    eapstatus->eapPortEnabled = eapSession->eapPortEnabled;
    eapstatus->eapRestart = eapSession->eapRestart;
    eapstatus->eapKeyAvailable = eapSession->eapKeyAvailable;
    eapstatus->eapIdentity   = eapSession->eapIdentity;
    eapstatus->eapIdentityLen = eapSession->eapIdentityLen;
    eapstatus->session_type = eapSession->session_type;
    eapstatus->eapSessionHdl = eapSession->eapSessionHdl;
    eapstatus->appSessionHandle = eapSession->appSessionHandle;
#if defined(__ENABLE_DIGICERT_EAP_PEER__)
    eapstatus->eapCurrentState = eapSession->eapCurrentState;
    eapstatus->eapPrevState = eapSession->eapPrevState;
#endif
#if defined(__ENABLE_DIGICERT_EAP_AUTH__)
    eapstatus->eapAuthCurrentState = eapSession->eapAuthCurrentState;
    eapstatus->eapAuthPrevState = eapSession->eapAuthPrevState;
    eapstatus->eapRetransCount = eapSession->eapRetransCount;
#endif

    DIGI_MEMCPY((ubyte *)&eapstatus->eapSessionCfg ,
               (ubyte *)&eapSession->eapSessionCfg,
               sizeof(eapSessionConfig_t));
    DIGI_MEMCPY((ubyte *)&eapstatus->eapSessionStats ,
               (ubyte *)&eapSession->eapSessionStats,
               sizeof(eapSessionStats_t));
    eapstatus->eapRounds = eapSession->eapRounds;

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_getSessionStatus Failed Status ", (sbyte4)status);

    return status;
}


/*------------------------------------------------------------------*/

/*! Get an EAP session's statistics.
This function retrieves statistics for the specified EAP session. The
statistics are accumulated values since they were last reset via a call to
EAP_resetSessionStats.

The following statistics are returned through the $eapstats$ parameter:
- Number of lower layer packets sent and received
- Number of packets the lower layer passed to the upper layer
- Number of packets the upper layer received from the lower layer
- Number of packets retransmitted and discarded
- Number of packets dropped because no callback was registered to process them
- Number of packets dropped because of an invalid packet

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID previously returned by EAP_initInstance.
\param eapstats         On return, pointer to session statistics (see $eapSessionStats_t$ in eap.h).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_getSessionStatus
\sa EAP_resetSessionStats
\sa EAP_getInstanceStats
\sa EAP_resetInstanceStats

*/
extern MSTATUS
EAP_getSessionStats(ubyte *eapSessionHdl,
                    ubyte4 instanceId,
                    eapSessionStats_t *eapstats)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession = NULL;
    /* Lookup Session */
    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl),
                               instanceId,&eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    DIGI_MEMCPY((ubyte *)eapstats ,
               (ubyte *)&eapSession->eapSessionStats,
               sizeof(eapSessionStats_t));

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_getSessionStats Failed Status ", (sbyte4)status);

    return status;
}


/*------------------------------------------------------------------*/

/*! Reset EAP session's statistics.
This function resets the specified EAP session's statistics to zero ($0$).

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID previously returned by EAP_initInstance.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_getSessionStatus
\sa EAP_resetSessionStats
\sa EAP_getInstanceStats
\sa EAP_resetInstanceStats

*/
extern MSTATUS
EAP_resetSessionStats(ubyte * eapSessionHdl,
                      ubyte4 instanceId)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession = NULL;
    /* Lookup Session */
    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl),
                               instanceId,&eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    DIGI_MEMSET((ubyte *)&eapSession->eapSessionStats,0,
               sizeof(eapSessionStats_t));

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_resetSessionStats Failed Status ", (sbyte4)status);

    return status;
}


/*------------------------------------------------------------------*/

/*! Get an EAP instance's statistics.
This function retrieves statistics for the specified EAP instance. The
statistics are accumulated values since they were last reset via a call to
EAP_resetInstanceStats.

The following statistics are returned through the $stats$ parameter:
- Total packets sent, received, and discarded
- Number of sessions created, modified, active, failed, and restarted
- (Authenticators only) Number of successful and number of failed peer authentications
- Number of times the authenticator/peer performed a retransmission
- Number of times the peer timed out
- Number of packets dropped due to invalid session, invalid packet

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param instanceId   EAP instance ID previously returned by EAP_initInstance.
\param stats        On return, pointer to global statistics (see $eapGlobalStats_t$ in eap.h).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_getSessionStatus
\sa EAP_getSessionStats
\sa EAP_resetSessionStats
\sa EAP_resetInstanceStats

*/
extern MSTATUS
EAP_getInstanceStats(ubyte4 instanceId,
                     eapGlobalStats_t *stats)
{
    eapInstanceCb_t   *instance = NULL;
    eapInstanceCb_t tInstance;
    MSTATUS status = OK;

    tInstance.instanceId = instanceId;

    if (OK > (status = RTOS_mutexWait(gEapGlobalState.instanceMutex)))
    {
        goto exit;
    }

    if (OK > (status = REDBLACK_find(gEapGlobalState.instanceTree, (const void *)&tInstance, (const void **) &instance)))
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_getInstanceStats: Unable to find Instance ", instanceId);
        RTOS_mutexRelease(gEapGlobalState.instanceMutex);
        goto exit;
    }

    if (OK > (status = RTOS_mutexRelease(gEapGlobalState.instanceMutex)))
    {
        goto exit;
    }

    if (NULL == instance)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_getInstanceStats: Unable to find Instance ", instanceId);
        status = ERR_EAP_INSTANCE_ID_NOT_FOUND;
        goto exit;
    }

    DIGI_MEMCPY((ubyte *)stats ,
               (ubyte *)&instance->gStats,
               sizeof(eapGlobalStats_t));

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_getInstanceStats Failed Status ", (sbyte4)status);

    return status;
}


/*------------------------------------------------------------------*/

/*! Reset EAP instance's global statistics.
This function resets the specified EAP instance's global statistics to zero ($0$).

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param instanceId   EAP instance ID previously returned by EAP_initInstance.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

\sa EAP_getSessionStats
\sa EAP_resetSessionStats
\sa EAP_getInstanceStats

*/
extern MSTATUS
EAP_resetInstanceStats(ubyte4 instanceId)
{
    eapInstanceCb_t   *instance = NULL;
    eapInstanceCb_t tInstance;
    MSTATUS status = OK;

    tInstance.instanceId = instanceId;

    if (OK > (status = RTOS_mutexWait(gEapGlobalState.instanceMutex)))
    {
        goto exit;
    }

    if (OK > (status = REDBLACK_find(gEapGlobalState.instanceTree, (const void *)&tInstance, (const void **) &instance)))
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_resetInstanceStats: Unable to find Instance ", instanceId);
        RTOS_mutexRelease(gEapGlobalState.instanceMutex);
        goto exit;
    }

    if (OK > (status = RTOS_mutexRelease(gEapGlobalState.instanceMutex)))
    {
        goto exit;
    }

    if (NULL ==  instance)
    {
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_resetInstanceStats: Unable to find Instance ", instanceId);
        status = ERR_EAP_INSTANCE_ID_NOT_FOUND;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)&instance->gStats, 0x00, sizeof(eapGlobalStats_t));

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_resetInstanceStats: Failed Status ", (sbyte4)status);

    return status;
} /* EAP_resetInstanceStats */


/*------------------------------------------------------------------*/

/*! Get the MTU (maximum transmission unit) value.
This function retrieves the MTU (maximum transmission unit) value that was set
at EAP session creation.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID returned from EAP_initInstance.
\param mtu              On return, pointer to MTU.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_getMtu(ubyte *eapSessionHdl,
           ubyte4 instanceId, ubyte4 *mtu)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession = NULL;

    /* Lookup Session */
    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl),
                               instanceId, &eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    *mtu = eapSession->eapSessionCfg.eap_mtu;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Set an EAP session's identity string.
This function sets an EAP session's identity string.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID returned from EAP_initInstance.
\param identity         Pointer to desired identity string value.
\param len              Pointer to number of bytes in $identity$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_setIdentity(ubyte *eapSessionHdl,
                ubyte4 instanceId, ubyte *identity, ubyte4 len)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession = NULL;

    /* Lookup Session */
    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl),
                               instanceId, &eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    /* free previous identity, if any */
    if (eapSession->eapIdentity)
        FREE(eapSession->eapIdentity);

    eapSession->eapIdentity = MALLOC(len + 1);
    if (NULL == eapSession->eapIdentity)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET(eapSession->eapIdentity, 0, len + 1);
    DIGI_MEMCPY(eapSession->eapIdentity, identity, len);
    eapSession->eapIdentityLen = len;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Get EAP session's identity string.
This function retrieves the EAP session's identity string.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID previously returned by EAP_initInstance.
\param identity         On return, pointer to the identity string.
\param len              On return, number of bytes in $identity$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_getIdentity(ubyte *eapSessionHdl, ubyte4 instanceId,
                ubyte **identity, ubyte4 *len)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession = NULL;

    /* Lookup Session */
    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl),
                               instanceId, &eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    *len = eapSession->eapIdentityLen;
    *identity = eapSession->eapIdentity;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/****f* src/eap/EAP_timeoutCallback
*
*  NAME
*   EAP_timeoutCallback  -- Callback function on timeout expiry
*  SYNOPSIS
*
*   #include "../eap/eap_session.h"
*
*   extern void
*   EAP_timeoutCallback (void * session,ubyte type)
*
*  FUNCTION
*  This callback function is registered from EAP_init and called when the
*  timer expires. It handles retransmission and other timeout related
*  activities like handling lost SUCCESS and FAILURE packets.
*
*  INPUTS
*    session : EAP Session Handle
*    type    : Type of timer
*
*
*  SEE ALSO
*   src/eap/EAP_init
******/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern void
EAP_timeoutCallback(void *session, ubyte *type)
{
    eapSessionCb_t* eapSession = (eapSessionCb_t *) session;

    DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_timeoutCallback: Timeout Called for Session ", eapSession->sessionId);

    /* It's a Retransmission Timeout for the Auth State */
    if (eapSession->eapInstance->timerRetrans == type)
    {
#if defined(__ENABLE_DIGICERT_EAP_AUTH__)
        if ((EAP_SESSION_TYPE_AUTHENTICATOR == eapSession->session_type) ||
            (EAP_SESSION_TYPE_PASSTHROUGH == eapSession->session_type))
        {
            EAP_authRetransmitTimeout(session);
        }
#endif
    }
    else if (eapSession->eapInstance->timerSession == type)
    {
#if defined(__ENABLE_DIGICERT_EAP_AUTH__)
        if ((EAP_SESSION_TYPE_AUTHENTICATOR == eapSession->session_type) ||
            (EAP_SESSION_TYPE_PASSTHROUGH == eapSession->session_type))
        {
            EAP_authSessionTimeout(session);
        }
#elif defined(__ENABLE_DIGICERT_EAP_PEER__)
        if (EAP_SESSION_TYPE_PEER == eapSession->session_type)
        {
            EAP_peerSessionTimeout(eapSession);
        }
#endif
    }

    return;
}


/*------------------------------------------------------------------*/

/*! Assign (place on the EAP stack) the EAP processing state machine ($methodState$) and decision ($decision$) values.
This function assigns the specified EAP processing state machine ($methodState$)
and decision ($decision$) values, placing them on the EAP stack. It is
particularly useful for two-phase methods: when the second stage method informs
the application of the result, the application calls this function to update the
EAP stack with the appropriate state machine values.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID returned from EAP_initInstance.
\param methodState      Value to assign to $methodState$.
\param methodDecision   Value to assign to $decision$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_setMethodStateDecision(ubyte *eapSessionHdl, ubyte4 instanceId,
                           ubyte methodState, ubyte methodDecision)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession = NULL;

    /* Lookup Session */
    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl),
                                instanceId, &eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    eapSession->eapMethodState = (ubyte) methodState;
    eapSession->eapDecision    = (ubyte) methodDecision;

exit:
    return status;
}


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_EAP_PEER__)
/*! Builds a NAK response to send to the authenticator.
This function builds a NAK response for your application to send from the peer
to the authenticator if the peer doesn't support the expanded method selected by
the authenticator. NAK responses return a list of supported expanded methods
through the $eapMethods$ parameter.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$

#Include %file:#&nbsp;&nbsp;eap.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID returned from EAP_initInstance.
\param expMethods       Array of Expanded methods supported.
\param expMethodCount   Number of Expanded methods supported.
\param eapResponse      On return, pointer to EAP response payload.
\param eapRespLen       On return, pointer to number of bytes in $eapResponse$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_buildExpandedNAK(ubyte *eapSessionHdl, ubyte4 instanceId,
                     eapExpandedMethod_t *expMethods, ubyte expMethodCount,
                     ubyte **eapResponse, ubyte4 *eapRespLen)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession = NULL;

    /* Lookup Session */
    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl),
                               instanceId, &eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    status = eap_buildExpandedNAK(eapSession,
                     expMethods, expMethodCount,
                     eapResponse, eapRespLen);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Builds an expanded payload response.
This function builds the expanded payload response for the peer, which is sent
in response to an expanded request received from the authenticator.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$

#Include %file:#&nbsp;&nbsp;eap.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID returned from EAP_initInstance.
\param expVendorId      Vendor ID (user-defined value).
\param expMethodId      ID of method being negotiated (user-defined value).
\param eapPayload       EAP response payload.
\param eapPayloadLen    EAP response payload length.
\param eapResponse      On return, pointer to expanded EAP response payload.
\param eapRespLen       On return, pointer to number of bytes in $eapResponse$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_buildExpandedResponse(ubyte *eapSessionHdl, ubyte4 instanceId,
                          ubyte4 expVendorId, ubyte4 expMethodId,
                          ubyte *eapPayload, ubyte4 eapPayloadLen,
                          ubyte **eapResponse, ubyte4 *eapRespLen)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession = NULL;

    /* Lookup Session */
    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl),
                               instanceId, &eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    status = eap_buildExpandedResponse(eapSession,
                          expVendorId, expMethodId,
                          eapPayload,  eapPayloadLen,
                          eapResponse, eapRespLen);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Builds a NAK response to send to the authenticator.
This function builds a NAK response for your application to send from the peer
to the authenticator if the peer doesn't support the method selected by
the authenticator. NAK responses return a list of supported methods through
the $nakMethods$ parameter.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$

#Include %file:#&nbsp;&nbsp;eap.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID returned from EAP_initInstance.
\param nakMethods       Array of methods supported.
\param nakMethodCount   Number of methods supported.
\param eapResponse      On return, pointer to EAP response payload.
\param eapRespLen       On return, pointer to number of bytes in $eapResponse$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_buildNAK(ubyte *eapSessionHdl, ubyte4 instanceId,
             ubyte* nakMethods, ubyte4 nakMethodCount,
             ubyte **eapResponse, ubyte4 *eapRespLen)
{
    eapSessionCb_t *eapSession = NULL;
    MSTATUS status = OK;

    /* Lookup Session */
    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl),
                               instanceId, &eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    status = eap_buildNAK(eapSession,
                          nakMethods, nakMethodCount,
                          eapResponse,eapRespLen);

exit:
    return status;
}
#endif /* defined(__ENABLE_DIGICERT_EAP_PEER__ */


/*------------------------------------------------------------------*/

/*! Set identifier and type to the last sent identifier and the EAP packet type.
This function sets the values of the identifier to the last sent identifier and
the type to the type of EAP packet on the stack. This function is used for
EAP-FAST when the application piggybacks the second stage packet to the previous
TLS packet (which in this case is the TLS Finished message).

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param eapSessionHdl    EAP session handle returned from EAP_sessionCreate.
\param instanceId       EAP instance ID returned from EAP_initInstance.
\param id               Identifier in EAP packet.
\param type             Any of the $eapMethodType$ enumerated values (see eap_proto.h).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_setId_Type(ubyte * eapSessionHdl, ubyte4 instanceId,
               ubyte id, ubyte type)
{
    eapSessionCb_t *eapSession = NULL;
    MSTATUS status;

    /* Lookup Session */
    status = eap_lookupSession((ubyte4)((uintptr)eapSessionHdl),
                               instanceId, &eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    eapSession->eapLastId = id;
    eapSession->sentType= type;

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_setId_Type Failed Status ", (sbyte4)status);

    return status;
}


/*------------------------------------------------------------------*/

/*! Builds an EAP request.
This function builds an EAP request using the provided identifier value. It is
used by EAP-FAST authenticators to piggyback an identity request to a TLS
Finished message received from a peer.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_EAP_PEER__$
- $__ENABLE_DIGICERT_EAP_AUTH__$

#Include %file:#&nbsp;&nbsp;eap.h

\param id       Value of identifier to be sent in EAP packet.
\param req      On return, pointer to generated EAP request packet.
\param reqLen   On return, pointer to number of bytes in $req$.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_generateIdReq(ubyte id,ubyte ** req, ubyte4 *reqLen)
{
    eapHdr_t * eapHdr;
    MSTATUS status = OK;

    *req = MALLOC(sizeof(eapHdr_t) + 1);
    if (NULL == *req)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    eapHdr = (eapHdr_t *) *req;

    eapHdr->id = id;
    eapHdr->code = EAP_CODE_REQUEST;
    /* Set the Length */
    DIGI_HTONS((ubyte *)*req + 2, sizeof(eapHdr_t) + 1);

    *(*req + sizeof(eapHdr_t))  = EAP_TYPE_IDENTITY;
    *reqLen = sizeof(eapHdr_t) + 1;

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_EAP_MESSAGE, (sbyte*)"EAP_generateIdReq Failed Status ", (sbyte4)status);

    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
EAP_getAppHdl(ubyte4  eapSessionHdl,
              ubyte4 instanceId,ubyte **appHdl)
{

    eapSessionCb_t* eapSession = NULL;
    MSTATUS         status     = OK;

    /* Lookup Session */
    status = eap_lookupSession((ubyte4)eapSessionHdl,
                               instanceId,&eapSession);

    if ((OK > status) || (NULL == eapSession))
        goto exit;

    *appHdl  = eapSession->appSessionHandle;

exit:
    return status;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_EAP_AUTH__
static MSTATUS
EAP_authSessionTimeout(void *session)
{
    MSTATUS status = OK;
    eapSessionCb_t *eapSession = (eapSessionCb_t *) session;

    if (NULL == eapSession)
    {
        status = ERR_EAP_INVALID_SESSION;
        goto exit;
    }

    /* Send Indication Up  Clean up the Req Buffer ?*/
    if (eapSession->eapReqData)
    {
        /* Free this buffer */
        FREE (eapSession->eapReqData);
        eapSession->eapReqData = NULL;
        eapSession->eapReqDataLen = 0;
    }

    eapSession->eapFail  = TRUE;
    eapSession->sentType = 0;

    status = eapSession->methodDef.funcPtr_ulReceiveIndication(
                                    eapSession->appSessionHandle,
                                    EAP_INDICATION_AUTH_TIMEOUT,
                                    NULL,0);

exit:
    return status;
} /* EAP_authSessionTimeout */
#endif


/*------------------------------------------------------------------*/

#if defined(__ENABLE_ALL_DEBUGGING__)
/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern void
EAP_PrintBytes(ubyte* buffer, sbyte4 len)
{
    sbyte4 i;

    for (i = 0; i < len; ++i)
    {
        DEBUG_HEXBYTE(DEBUG_EAP_MESSAGE, buffer[i]);
        DEBUG_PRINT(DEBUG_EAP_MESSAGE, (sbyte*)" ");

        if (i % 16 == 15)
        {
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");
        }
    }

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte*)"");
}
#endif

#endif /* defined(__ENABLE_DIGICERT_EAP_PEER__ || __AUTH__) */

