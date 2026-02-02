/**
 * @file fapi2_integrity.h
 * @brief This file contains code and structures required for PCR operations.
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
#ifndef __FAPI2_INTEGRITY_H__
#define __FAPI2_INTEGRITY_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "fapi2_context.h"

/*
 * This API can be used to reset a PCR. 
 */
TSS2_RC FAPI2_INTEGRITY_pcrReset(
        FAPI2_CONTEXT *pCtx,
        IntegrityPcrResetIn *pIn);

/*
 * This API can be used to read values from PCR's. Upto 8 PCR's can be
 * read per call.
 */
MOC_EXTERN TSS2_RC FAPI2_INTEGRITY_pcrRead(
        FAPI2_CONTEXT *pCtx,
        IntegrityPcrReadIn *pIn,
        IntegrityPcrReadOut *pOut);

/*
 * This API can be used to extend digests into a PCR.
 */
MOC_EXTERN TSS2_RC FAPI2_INTEGRITY_pcrExtend(
        FAPI2_CONTEXT *pCtx,
        IntegrityPcrExtendIn *pIn
);
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
#endif /* __FAPI2_INTEGRITY_H__ */
