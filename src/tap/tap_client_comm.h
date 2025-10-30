/**
 * @file tap_client_comm.h
 *
 * @brief Common Trust Anchor Platform (TAP) Definitions and Types
 * @details This file contains definitions and functions that permit remote access of TAP functions across the network.
 *
 * @flags
 * This file requires that the following flags be defined:
 *    + \c \__ENABLE_MOCANA_TAP__
 *
 * Copyright (c) Mocana Corp 2018. All Rights Reserved.
 * Proprietary and Confidential Material.
 * 
 */


/*------------------------------------------------------------------*/

#ifndef __TAP_COMM_CLIENT_HEADER__
#define __TAP_COMM_CLIENT_HEADER__

/*! @cond */
#ifdef __ENABLE_MOCANA_TAP__
#ifdef __ENABLE_TAP_REMOTE__
/*! @endcond */

#include "tap_smp.h"
#include "tap_remote.h"
#include "tap_common.h"
#include "tap_conf_common.h"

MOC_EXTERN_DATA_DECL TAP_OPERATIONAL_INFO tapClientInfo;
MOC_EXTERN_DATA_DECL ubyte tapRemoteInitDone;

/***************************************************************
   Function Definitions
****************************************************************/

/**
 * @private
 * @internal
 *
 * @ingroup tap_functions
 *
 * @details Function used by all TAP client modules to setup connection to TAP server
 *
 * @param [in,out] pTapSession       TAP Session object to be initialized. It also contains the connection information to the TAP server.
 *
 * @return OK on success
 * @return
 *
 */
MOC_EXTERN MSTATUS TAP_OpenSession(TAP_SessionInfo *pSessionInfo);
MOC_EXTERN MSTATUS TAP_initRemoteSession();
MOC_EXTERN MSTATUS TAP_unInitRemoteSession();


/**
 * @private
 * @internal
 *
 * @ingroup tap_functions
 *
 * @details Function used by all TAP client modules to tear down connection to TAP server 
 *
 * @param [in,out] pTapSession       TAP Session information 
 *
 * @return OK on success
 * @return
 *
 */
MOC_EXTERN MSTATUS TAP_CloseSession(TAP_SessionInfo *pSessionInfo);


/**
 * @private
 * @internal
 *
 * @ingroup tap_functions
 *
 * @details Function used by all TAP client modules to send command to TAP server and receive response.
 *
 * @param [in]  pTapSession      Session information
 * @param [in]  pReqHdr          Command header.  All fields except the totalBytes must be filled out by the caller.
 * @param [in]  txBufferLen      Length of serialized command buffer
 * @param [in]  pTxBuffer        Serialized command buffer
 * @param [out] pRxBufferLen     Length of serialized response buffer
 * @param [out] ppRxBuffer       Serialized response buffer
 * @param [out] pRetCode         Pointer to command return code for commands that do not have a response buffer.
 *
 * @return OK on success
 * @return
 *
 * @memory  Memory is allocated for ppRxBuffer and must be freed by caller.
 */
MOC_EXTERN MSTATUS TAP_TransmitReceive(TAP_SessionInfo *pSessionInfo, 
                                   TAP_CmdReqHdr *pReqHdr,
                                   ubyte4 txBufferLen, ubyte *pTxBuffer,
                                   ubyte4 *pRxBufferLen, ubyte *pRxBuffer,
                                   MSTATUS *pRetCode
);


/*! @cond */
#endif  /* __ENABLE_MOCANA_TAP__ */
#endif  /* __ENABLE_TAP_REMOTE__ */
/*! @endcond */

#endif

