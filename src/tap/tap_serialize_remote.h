/**
 * @file tap_serialize_remote.h
 *
 * @brief Shadow structures for Common Trust Anchor Platform (TAP) declaration and Types
 * @details This file contains shadow structure definitions and functions common to all
 * Mocana Trust Anchor Platform (TAP) client and server modules.
 *
 * @flags
 * This file requires that the following flags be defined:
 *    + \c \__ENABLE_MOCANA_TAP__
 *
 * @flags
 * Whether the following flags are defined determines whether or not support is enabled for a particular HW security module:
 *    + \c \__ENABLE_MOCANA_TPM__
 *    + \c \__ENABLE_MOCANA_TPM2__
 *
 * Copyright (c) Mocana Corp 2018. All Rights Reserved.
 * Proprietary and Confidential Material.
 *
 */


/*------------------------------------------------------------------*/

#ifndef __TAP_SERIALIZE_REMOTE_HEADER__
#define __TAP_SERIALIZE_REMOTE_HEADER__

#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "tap_serialize.h"

#ifdef __cplusplus
extern "C" {
#endif

/*! @cond */

#ifdef __ENABLE_MOCANA_TAP__
#ifdef __ENABLE_TAP_REMOTE__

extern const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_CMD;

extern const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_CMD_DIRECTION;

extern const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_CMD_DEST;

extern const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_CMD_TYPE;

extern const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_GetProviderList_ReqParams;
extern const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_GetProviderList_RspParams;

extern const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_IsTapTypePresent_ReqParams;
extern const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_IsTapTypePresent_RspParams;

extern const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_InitContext_ReqParams;
extern const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_InitContext_RspParams;

extern const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_UninitContext_ReqParams;
extern const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_UninitContext_RspParams;

extern const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_CmdReqParams;
extern const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_CmdRspParams;

MOC_EXTERN_DATA_DECL const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_CmdReqHdr;
MOC_EXTERN_DATA_DECL const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_CmdRspHdr;

MOC_EXTERN_DATA_DECL const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_CmdReq;
MOC_EXTERN_DATA_DECL const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_CmdRsp;

extern const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_SERVER_CMD_PARAMS;

#endif /* __ENABLE_TAP_REMOTE__ */
#endif /* __ENABLE_MOCANA_TAP__ */

#ifdef __cplusplus
}
#endif

#endif /* __TAP_SERIALIZE_REMOTE_HEADER__ */
