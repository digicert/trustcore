/**
 * @file sapi2_asym.h
 * @brief This file contains code required to execute TPM2 asymmetric primitive
 * commands.
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
#ifndef __SAPI2_ASYM_H__
#define __SAPI2_ASYM_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "sapi2_context.h"
#include "sapi2_handles.h"

typedef struct {
    TPMI_ECC_CURVE curveID;
} ECCParametersIn;

typedef struct {
    TPMS_ALGORITHM_DETAIL_ECC parameters;
} ECCParametersOut;

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pObjectHandle;
    TPM2B_PUBLIC_KEY_RSA *pMessage;
    TPMT_RSA_DECRYPT *pInScheme;
    TPM2B_DATA *pLabel;
} RSAEncryptIn;

typedef struct {
    TPM2B_PUBLIC_KEY_RSA outData;
} RSAEncryptOut;

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pObjectHandle;
    TPM2B_PUBLIC_KEY_RSA *pCipherText;
    TPMT_RSA_DECRYPT *pInScheme;
    TPM2B_DATA *pLabel;
    TPM2B_AUTH *pAuthObjectHandle;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} RSADecryptIn;

typedef struct {
    TPM2B_PUBLIC_KEY_RSA message;
} RSADecryptOut;

MOC_EXTERN TSS2_RC SAPI2_ASYM_ECCParameters(
        SAPI2_CONTEXT *pSapiContext,
        ECCParametersIn *pIn,
        ECCParametersOut *pOut
);

MOC_EXTERN TSS2_RC SAPI2_ASYM_RSAEncrypt(
        SAPI2_CONTEXT *pSapiContext,
        RSAEncryptIn *pIn,
        RSAEncryptOut *pOut
);

MOC_EXTERN TSS2_RC SAPI2_ASYM_RSADecrypt(
        SAPI2_CONTEXT *pSapiContext,
        RSADecryptIn *pIn,
        RSADecryptOut *pOut
);

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __SAPI2_ASYM_H__ */
