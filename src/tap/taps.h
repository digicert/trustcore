/**
 * @file taps.h
 *
 * @brief The Mocana Trust Anchor Platform (TAP) Server APIs
 * @details This file contains the Mocana Trust Anchor Platform (TAP) Server APIs
 * 
 * @flags
 * This file requires that the following flags be defined:
 *    + \c \__ENABLE_MOCANA_TAP__
 *
 * @flags
 * Whether the following flags are defined determines whether or not support is enabled for a particular security module:
 *    + \c \__ENABLE_MOCANA_TPM2__
 *
 * Copyright (c) Mocana Corp 2018. All Rights Reserved.
 * Proprietary and Confidential Material.
 * 
 */

#ifndef __TAPS_HEADER__
#define __TAPS_HEADER__

#ifdef __ENABLE_MOCANA_TAP__

#include "tap_smp.h"
#include "tap_common.h"

#ifdef __ENABLE_TAP_REMOTE__
#include "tap_remote.h"
#endif

#ifdef __ENABLE_MOCANA_TPM2__
#define SRK_CREDENTIAL_OFFSET   0
#endif

/* TODO - can this be moved to tap_conf_common.h*/
#define FILE_PATH_LEN   256

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************
   Definitions
****************************************************************/
#define MAX_COMMAND_SIZE        8192 

/** @private
 *  @internal
 */
typedef struct _TAPS_TRACKING_NODE
{
    TAP_HANDLE tokenHandle;
    TAP_HANDLE objectHandle;

    struct _TAPS_TRACKING_NODE *pNext;
} TAPS_TRACKING_NODE;

/** @private
 *  @internal
 */
typedef struct  _TAPS_CONNECTION
{
    RTOS_MUTEX mutex;
    TCP_SOCKET sockfd;
    RTOS_THREAD threadId;
    sbyte4 sslConnectId;

    TAP_Module *pTapModule;

    ubyte enableunsecurecomms;
    ubyte quitTime;
    ubyte state;
    ubyte localConnection;

    TAPS_TRACKING_NODE *pFirstTrackingNode;

    ubyte cmdBuffer[MAX_COMMAND_SIZE];
    struct _TAPS_CONNECTION *pNext;
} TAPS_CONNECTION;

/** @private
 *  @internal
 */
typedef struct
{
    RTOS_MUTEX mutex;

    TAPS_CONNECTION *pFirstActiveConnection;
} TAPS_CONNECTION_MGR;

/** @private
*  @internal
*/
typedef struct {
    byteBoolean exitAfterParse;
    ubyte4 serverPort;
#ifdef __ENABLE_TAP_REMOTE_UNIX_DOMAIN__
    char unixServerPath[FILE_PATH_LEN];
#endif
    byteBoolean isConfFileSpecified;
    char confFilePath[FILE_PATH_LEN];
    byteBoolean isConfDirSpecified;
    char confDirPath[FILE_PATH_LEN];
#ifdef __ENABLE_MOCANA_DATA_PROTECTION__
    byteBoolean isProtectLibSpecified;
    char protectLibPath[FILE_PATH_LEN];
#endif
} tapsExecutionOptions;

#if defined(__RTOS_WIN32__) && defined(__RUN_TAPS_SERVICE__)
/** @private
*  @internal
*/
typedef void(*tapsStopCallback) (MSTATUS tapsStatus);

/** @private
*  @internal
*/
typedef void(*tapsStartCallback) (MSTATUS tapsStatus);

/** @private
*  @internal
*/
typedef struct {
    tapsExecutionOptions    *pExecuteOpts;
    tapsStopCallback        pTapsStopCallback;
    tapsStartCallback       pTapsStartCallback;
} tapsServiceOpts;

/** @private
*  @internal
*/
void tapsMain(void *arg);
/** @private
*  @internal
*/
void TAPS_interruptToStop();
#endif


/***************************************************************
   Module Callback Definitions
****************************************************************/


/**
 * @ingroup taps_definitions
 * @details TAP callback for a module-specific dispatcher. All modules must implement this function.
 *   <p> The module must handle serialization/deserialization of module-specific structures within the TAP_CmdReqParams and TAP_CmdRspParams union members.
 *
 * @param [in]  pContext     The context associate with the device.
 * @param [in]  pCmd         The command, including both TAP and any module-specific data.
 * @param [out] pRsp         The response, including both TAP and any module-specific data.
 */
typedef MSTATUS (*tapDispatcherCallback)(void *pContext, TAP_CmdReq *pCmd, TAP_CmdRsp *pRsp);

/**
 * @ingroup taps_definitions
 * @details TAP callback for a module-specific callback handler.
 *   <p> .
 *
 * @param [in]  pContext     The context associate with the device.
 * @param [in]  pCmd         The command, including both TAP and any module-specific data.
 * @param [out] pRsp         The response, including both TAP and any module-specific data.
 */
 /* TODO: Get function signature from Atul */
typedef MSTATUS (*tapSmpCallbackHandler)(void *pContext, TAP_Buffer *pIn, TAP_Buffer *pOut);

/***************************************************************
   Function Prototypes 
****************************************************************/


/**
 * @ingroup taps_functions
 *
 * @brief Function to return a list of available devices.
 * @details Function to return a list of available devices. This includes any available emulators for testing purposes.
 *
 * @param [in,out] pProviderList   structure containing list of available providers.
 *
 * @return OK on success
 *
 */
 /* TODO: Should this be exposed in the .h file, or only in the .c file? */
MSTATUS TAPS_getProviderList(TAP_ProviderList *pProviderList);


#ifdef __cplusplus
}
#endif

#endif /* __ENABLE_MOCANA_TAP__ */

#endif /* __TAPS_HEADER__ */
