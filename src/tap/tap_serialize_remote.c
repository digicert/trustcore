/**
 * @file tap_serialize_remote.c
 * @details This file contains shadow structure definitions and functions needed for
 *          Trust Anchor Platform (TAP) client-server communication.
 *
 * @flags
 *  To enable this file's functions, the following flags must be defined in
 * moptions.h:
 *  + \c \__ENABLE_DIGICERT_TAP__
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TAP__))
#ifdef __ENABLE_TAP_REMOTE__

#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#include "../common/vlong.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "tap_remote.h"
#include "tap_smp.h"
#include "tap_common.h"
#include "tap_serialize.h"
#include "tap_serialize_remote.h"
#include "tap_serialize_smp.h"


const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_CMD = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_CMD),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {0, &TAP_SHADOW_ubyte2},

};

const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_CMD_DIRECTION = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_CMD_DIRECTION),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {0, &TAP_SHADOW_ubyte},

};

const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_CMD_DEST = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_CMD_DEST),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {0, &TAP_SHADOW_ubyte},

};

const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_CMD_TYPE = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_CMD_TYPE),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {0, &TAP_SHADOW_ubyte},

};

const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_GetProviderList_RspParams = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_GetProviderList_RspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {TAP_OFFSETOF(TAP_GetProviderList_RspParams, providerList), &TAP_SHADOW_TAP_ProviderList},

};

const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_CmdRspParams = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(TAP_CmdRspParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_CMD_GET_PROVIDER_LIST, &TAP_REMOTE_SHADOW_TAP_GetProviderList_RspParams},

        }
};

const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_GetProviderList_ReqParams = {
        .handler = TAP_SERIALIZE_ListPointerTypeHandler,
        .structSize = sizeof(TAP_GetProviderList_ReqParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {TAP_OFFSETOF(TAP_GetProviderList_ReqParams, nullChar), &TAP_SHADOW_ubyte},
};

const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_CmdReqParams = {
        .handler = TAP_SERIALIZE_UnionTypeHandler,
        .structSize = sizeof(TAP_CmdReqParams),
        .numFields = 1,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,

        .pFieldList = {
                {TAP_CMD_GET_PROVIDER_LIST, &TAP_REMOTE_SHADOW_TAP_GetProviderList_ReqParams},
        }
};

const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_CmdReqHdr = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_CmdReqHdr),
        .numFields = 4,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_CmdReqHdr, cmdDest), &TAP_REMOTE_SHADOW_TAP_CMD_DEST},
                {TAP_OFFSETOF(TAP_CmdReqHdr, cmdType), &TAP_REMOTE_SHADOW_TAP_CMD_TYPE},
                {TAP_OFFSETOF(TAP_CmdReqHdr, providerType), &TAP_SHADOW_ubyte2},
                {TAP_OFFSETOF(TAP_CmdReqHdr, totalBytes), &TAP_SHADOW_ubyte4},
        },
};

const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_CmdRspHdr = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_CmdRspHdr),
        .numFields = 3,
        .unionSelectorOffset = 0,
        .unionSelectorSize = 0,
        .pFieldList = {
                {TAP_OFFSETOF(TAP_CmdRspHdr, cmdStatus), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(TAP_CmdRspHdr, cmdType), &TAP_REMOTE_SHADOW_TAP_CMD_TYPE},
                {TAP_OFFSETOF(TAP_CmdRspHdr, totalBytes), &TAP_SHADOW_ubyte4}
        },

};

const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_CmdReq = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_CmdReq),
        .numFields = 2,
        .unionSelectorOffset = TAP_OFFSETOF(TAP_CmdReq, cmdCode),
        .unionSelectorSize = SIZEOF(TAP_CmdReq, cmdCode),
        .pFieldList = {
                {TAP_OFFSETOF(TAP_CmdReq, cmdCode), &TAP_SHADOW_ubyte2},
                {TAP_OFFSETOF(TAP_CmdReq, reqParams), &TAP_REMOTE_SHADOW_TAP_CmdReqParams},
        },
};

const tap_shadow_struct TAP_REMOTE_SHADOW_TAP_CmdRsp = {
        .handler = TAP_SERIALIZE_StructTypeHandler,
        .structSize = sizeof(TAP_CmdRsp),
        .numFields = 3,
        .unionSelectorOffset = TAP_OFFSETOF(TAP_CmdRsp, cmdCode),
        .unionSelectorSize = SIZEOF(TAP_CmdRsp, cmdCode),
        .pFieldList = {
                {TAP_OFFSETOF(TAP_CmdRsp, cmdCode), &TAP_SHADOW_ubyte2},
                {TAP_OFFSETOF(TAP_CmdRsp, cmdStatus), &TAP_SHADOW_ubyte4},
                {TAP_OFFSETOF(TAP_CmdRsp, rspParams), &TAP_REMOTE_SHADOW_TAP_CmdRspParams}
        },

};

#endif /* __ENABLE_TAP_REMOTE__ */

#endif /* if defined(__ENABLE_DIGICERT_TAP__) */
