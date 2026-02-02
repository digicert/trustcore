/**
 * @file fapi2_nv.h
 * @brief This file contains functions to use the TPM2 NV RAM.
 *
 * @flags
 *  To enable this file's functions, the following flags must be defined in
 * moptions.h:
 *
 *  + \c \__ENABLE_DIGICERT_TPM2__
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
#ifndef __FAPI2_NV_H__
#define __FAPI2_NV_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "fapi2_context.h"

#define TPM2_RSA_NONCE_NV_INDEX     0x01c00003
#define TPM2_ECC_NONCE_NV_INDEX     0x01c0000b

/*
 * This API creates/defines an NV index in the TPM.
 * The NV index defined by this API creates an NV index that
 * can be authorized by the authValue provided here or with
 * the owner hierarchy authValue. The NV Index created does
 * not allow partial writes. It can also be locked from further
 * writes. The owner hierarchy authValue is expected to be set
 * appropriately in the FAPI2_CONTEXT to successfully execute
 * this API.
 */
MOC_EXTERN TSS2_RC FAPI2_NV_define(
        FAPI2_CONTEXT *pCtx,
        NVDefineIn *pIn
);

/*
 * This API writes to an already defined/created NV index.
 */
MOC_EXTERN TSS2_RC FAPI2_NV_writeOp(
        FAPI2_CONTEXT *pCtx,
        NVWriteOpIn *pIn
);

/*
 * This API reads an already defined/created NV index.
 */
MOC_EXTERN TSS2_RC FAPI2_NV_readOp(
        FAPI2_CONTEXT *pCtx,
        NVReadOpIn *pIn,
        NVReadOpOut *pOut
);

/*
 * This API reads the public portion of an already defined/created NV index.
 */
MOC_EXTERN TSS2_RC FAPI2_NV_readPublic(
        FAPI2_CONTEXT *pCtx,
        NVReadPubIn *pIn,
        NVReadPubOut *pOut
);

/*
 * This API undefines a previously defined NV index. The owner
 * hierarchy authValue must be set correctly in the FAPI2_CONTEXT
 * for this command to succeed.
 */

MOC_EXTERN TSS2_RC FAPI2_NV_undefine(
        FAPI2_CONTEXT *pCtx,
        NVUndefineIn *pIn
);

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
#endif /* __FAPI2_NV_H__ */
