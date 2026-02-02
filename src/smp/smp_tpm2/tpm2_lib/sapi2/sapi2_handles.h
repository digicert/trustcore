/**
 * @file sapi2_handles.h
 * @brief This file contains SAPI2 HANDLES related functions for TPM2.
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

#ifndef __SAPI2_HANDLES_H__
#define __SAPI2_HANDLES_H__

#if (defined(__ENABLE_DIGICERT_TPM2__))

#include "../tpm2_types.h"

typedef enum {
    MOCTPM2_OBJ_METADATA_TYPE_INVALID = 0,
    MOCTPM2_OBJ_METADATA_TYPE_SESSION = 1,
    MOCTPM2_OBJ_METADATA_TYPE_PRIMARY = 2,
    MOCTPM2_OBJ_METADATA_TYPE_ORDINARY = 3,
    MOCTPM2_OBJ_METADATA_TYPE_END = 4,
} MOCTPM2_OBJ_METADATA_TYPE;

typedef struct {
    TPM2_HANDLE tpm2Handle;
    union {
        TPMT_PUBLIC objectPublicArea;
        TPMS_NV_PUBLIC nvPublicArea;
    } publicArea;
    TPM2B_NAME objectName;
    MOCTPM2_OBJ_METADATA_TYPE type;
    ubyte4 metaDataSize;
    void *pMetadata;
} MOCTPM2_OBJECT_HANDLE;

/* Functions */
TSS2_RC SAPI2_HANDLES_createObjectHandle(TPM2_HANDLE inTpm2Handle,
        TPMT_PUBLIC *pInPublicArea, MOCTPM2_OBJECT_HANDLE **ppOutObjectHandle);

TSS2_RC SAPI2_HANDLES_createNvHandle(TPM2_HANDLE inTpm2Handle,
        TPMS_NV_PUBLIC *pInPublicArea, MOCTPM2_OBJECT_HANDLE **ppOutObjectHandle);

MOC_EXTERN TSS2_RC SAPI2_HANDLES_destroyHandle(MOCTPM2_OBJECT_HANDLE **ppInObjectHandle,
        byteBoolean freeMetadata);

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __SAPI2_HANDLES_H__ */
