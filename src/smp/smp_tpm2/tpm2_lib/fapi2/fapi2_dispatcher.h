/**
 * @file fapi2_dispatcher.h
 * @brief This file in defines a generic dispatcher that
 * can be used to interact with FAPI2. The caller can use command
 * codes and pass structures corresponding to a given command code.
 * The main expected use of this is in the client server model of
 * NanoTAP.
 *
 * @flags
 *  To enable this file's functions, the following flags must be defined in
 * moptions.h:
 *
 *  + \c \__ENABLE_DIGICERT_TPM2__
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
#ifndef __FAPI2_DISPATCHER_H__
#define __FAPI2_DISPATCHER_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "fapi2.h"

TSS2_RC FAPI2_DISPATCHER_lookupCmdRspSize(
        FAPI2_CC cmdCode,
        ubyte4 *cmdSize,
        ubyte4 *rspSize
);

MOC_EXTERN TSS2_RC FAPI2_DISPATCHER_dispatch(
        FAPI2_CONTEXT *pCtx,
        FAPI2_CC commandCode,
        void *pIn,
        ubyte4 inSize,
        void *pOut,
        ubyte4 outSize
);
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __FAPI2_DISPATCHER_H__ */
