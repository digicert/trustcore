/**
 * @file fapi2_data_internal.h
 * @brief This file contains definitions internal to fapi data api's.
 * These must not be used by applications directly
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
#ifndef __FAPI2_DATA_INTERNAL_H__
#define __FAPI2_DATA_INTERNAL_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "fapi2_context.h"
#include "../sapi2/sapi2.h"

typedef struct {
    /*
     * Hierarchy to use for ticket creation. If this is TPM2_RH_NULL, a NULL ticket
     * will be produced. This value cannot be used if the ticket is intended to
     * provide validation for restricted signature.
     */
    TPMI_RH_HIERARCHY ticketHierarchy;

    /*
     * Hash algorithm to use to digest the data. This must be TPM2_ALG_SHA256,
     * TPM2_ALG_SHA384 or TPM2_ALG_SHA512. Note that one or all of these
     * algorithms may not be supported by the TPM hardware and an error will
     * be returned in such cases.
     */
    TPMI_ALG_HASH hashAlg;

    /*
     * Buffer length and pointer to buffer of the data to be digested.
     */
    ubyte4 bufferLen;
    ubyte *pBuffer;
} DataDigestInternalIn;

typedef struct {
    TPM2B_DIGEST digest;
    TPMT_TK_HASHCHECK validation;
} DataDigestInternalOut;

/*
 * Digests arbitrary length buffers using the TPM and specified hash algorithm. Returns
 * the digest and validation ticket indicating if the digested buffer began with the
 * value TPM2_GENERATED_VALUE. This is useful while performing signatures with restricted
 * signing keys.
 */
TSS2_RC FAPI2_DATA_digestInternal(
        FAPI2_CONTEXT *pCtx,
        DataDigestInternalIn *pIn,
        DataDigestInternalOut *pOut
);

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __FAPI2_DATA_INTERNAL_H__ */
