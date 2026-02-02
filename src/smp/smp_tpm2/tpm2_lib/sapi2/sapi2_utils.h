/**
 * @file sapi2_utils.h
 * @brief This file contains SAPI2 utility functions for TPM2.
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

#ifndef __SAPI2_UTILS_H__
#define __SAPI2_UTILS_H__


#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../../../../common/mtypes.h"
#include "../../../../common/mdefs.h"
#include "../../../../common/merrors.h"
#include "../../../../common/mrtos.h"
#include "../../../../common/mstdlib.h"
#include "../../../../common/debug_console.h"
#include "../../../../common/base64.h"
#include "../../../../common/random.h"
#include "../../../../common/vlong.h"
#include "../../../../crypto/crypto.h"
#include "../../../../crypto/pubcrypto.h"
#include "../tpm_common/tss2_error.h"
#include "../tpm2_types.h"
#include "sapi2_serialize.h"
#include "sapi2_handles.h"
#include "sapi2_context.h"

#define IS_TPM2_NV_HANDLE(handle)\
        (TPM2_HT_NV_INDEX == \
                ((handle & TPM2_HR_RANGE_MASK) >> TPM2_HR_SHIFT))

#define IS_TPM2_PCR_HANDLE(handle)\
        (TPM2_HT_PCR == \
                ((handle & TPM2_HR_RANGE_MASK) >> TPM2_HR_SHIFT))

#define IS_TPM2_HMAC_SESSION_HANDLE(handle)\
        (TPM2_HT_HMAC_SESSION == \
                ((handle & TPM2_HR_RANGE_MASK) >> TPM2_HR_SHIFT))

#define IS_TPM2_POLICY_SESSION_HANDLE(handle)\
        (TPM2_HT_POLICY_SESSION == \
                ((handle & TPM2_HR_RANGE_MASK) >> TPM2_HR_SHIFT))

#define IS_TPM2_SESSION_HANDLE(handle)\
        (IS_TPM2_HMAC_SESSION_HANDLE(handle) || \
                IS_TPM2_POLICY_SESSION_HANDLE(handle))

#define IS_TPM2_PERMANENT_HANDLE(handle)\
        (TPM2_HT_PERMANENT == \
                ((handle & TPM2_HR_RANGE_MASK) >> TPM2_HR_SHIFT))

#define IS_TPM2_PERSISTENT_HANDLE(handle)\
        (TPM2_HT_PERSISTENT == \
                ((handle & TPM2_HR_RANGE_MASK) >> TPM2_HR_SHIFT))

#define IS_TPM2_TRANSIENT_HANDLE(handle)\
        (TPM2_HT_TRANSIENT == \
                ((handle & TPM2_HR_RANGE_MASK) >> TPM2_HR_SHIFT))

#define IS_TPM2_OBJECT_HANDLE(handle)\
        (IS_TPM2_PCR_HANDLE(handle) || IS_TPM2_HMAC_SESSION_HANDLE(handle) ||\
                IS_TPM2_POLICY_SESSION_HANDLE(handle) ||\
                IS_TPM2_PERMANENT_HANDLE(handle) || \
                IS_TPM2_PERSISTENT_HANDLE(handle) ||\
                IS_TPM2_TRANSIENT_HANDLE(handle))

#define IS_VALID_TPM2_HANDLE(handle)\
        (IS_TPM2_OBJECT_HANDLE(handle) || IS_TPM2_NV_HANDLE(handle))

typedef struct {
    ubyte *pCmdStreamOut;
    ubyte4 cmdStreamOutSize;
    sapi2_cmd_desc *pCmdDesc;
} sapi2_utils_cmd_context;

typedef struct {
    ubyte *pRspStreamIn;
    ubyte4 rspStreamInSize;
    sapi2_rsp_desc *pRspDesc;
} sapi2_utils_rsp_context;

MOC_EXTERN TSS2_RC SAPI2_UTILS_getNvName(TPM2_HANDLE handle,
        TPMS_NV_PUBLIC *pPublic, TPM2B_NAME *pOutName);

MOC_EXTERN TSS2_RC SAPI2_UTILS_getObjectName(TPM2_HANDLE handle,
        TPMT_PUBLIC *pPublic, TPM2B_NAME *pOutName);

TSS2_RC SAPI2_UTILS_getCmdStream(
        sapi2_utils_cmd_context *pCmdCtx,
        ubyte4 *pCmdBufferSizeOut
);
TSS2_RC SAPI2_UTILS_getRspStructures(sapi2_utils_rsp_context *pRspCtx);

TSS2_RC SAPI2_UTILS_getHashAlg(
        TPM2_ALG_ID hashAlgId,
        const BulkHashAlgo **ppHashAlgOut
);

MSTATUS SAPI2_UTILS_getHashAlgFromAlgId(
        TPM2_ALG_ID hashAlgId,
        const BulkHashAlgo **ppHashAlgOut,
        ubyte *hashAlgOid
);

/*
 * KDFA as specified in the TPM library specification part 1.
 * All lenghts, including output key length must be in bytes. It will be
 * converted to bits internally.
 */
TSS2_RC SAPI2_UTILS_TPM2_KDFA(
        TPM2_ALG_ID hashAlgId,
        ubyte *pSecretKeyMaterial,
        ubyte4 pSecretKeyMaterialLen,
        const char *pLabel,
        ubyte *pContextU,
        ubyte4 contextULen,
        ubyte *pContextV,
        ubyte4 contextVLen,
        ubyte *pKeyOut,
        ubyte4 keyOutLen
);

TSS2_RC SAPI2_UTILS_TPM2_KDFE(
        TPM2_ALG_ID hashAlgId,
        ubyte *pZpointX,
        ubyte4 zPointXLen,
        const char *pLabel,
        ubyte *pPartyUInfo,
        ubyte4 partyUInfoLen,
        ubyte *pPartyVInfo,
        ubyte4 partyVInfoLen,
        ubyte *pKeyOut,
        ubyte4 keyOutLen
);

TSS2_RC SAPI2_UTILS_convertRSAKeyToTpm2Rsa(
        RSAKey *pRsaKey,
        TPM2B_PUBLIC_KEY_RSA *pRsaPublic,
        TPM2B_PRIVATE_KEY_RSA *pRsaPrivate
);

TSS2_RC SAPI2_UTILS_convertRSAPublicToTpm2RsaPublic(
        MOC_RSA(hwAccelDescr hwAccelCtx)
        RSAKey *pRsaKey,
        TPM2B_PUBLIC_KEY_RSA *pTpm2Rsa
);

TSS2_RC SAPI2_UTILS_convertTpm2RsaPublicToRSAKey(
        MOC_RSA(hwAccelDescr hwAccelCtx)
        TPM2B_PUBLIC_KEY_RSA *pRsa,
        RSAKey **ppKey,
        ubyte4 exponent
);

TSS2_RC SAPI2_UTILS_generateRsaSeed(
        MOC_RSA(hwAccelDescr hwAccelCtx)
        RSAKey* pRsaPublicKey,
        ubyte oaepHashOid,
        const ubyte *pLabel,
        ubyte4 labelLen,
        ubyte *pSeedOut,
        ubyte4 seedLen,
        TPM2B_ENCRYPTED_SECRET *pEncryptedSecretOut
);

#ifdef __ENABLE_DIGICERT_ECC__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
TSS2_RC SAPI2_UTILS_getECCurveFromTpm2EccCurveID(
        TPM2_ECC_CURVE curveID,
        ubyte4 *pEccCurveId
);
#else
TSS2_RC SAPI2_UTILS_getECCurveFromTpm2EccCurveID(
        TPM2_ECC_CURVE curveID,
        PEllipticCurvePtr *pECcurve
);
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
TSS2_RC SAPI2_UTILS_getTpm2EccCurveIDFromECCurve(
        ubyte4 eccCurveId,
        TPM2_ECC_CURVE *pCurveID
);
#else
TSS2_RC SAPI2_UTILS_getTpm2EccCurveIDFromECCurve(
        PEllipticCurvePtr pECcurve,
        TPM2_ECC_CURVE *pCurveID
);
#endif

TSS2_RC SAPI2_UTILS_convertEccKeyToTpm2Ecc(
        MOC_ECC(hwAccelDescr hwAccelCtx)
        ECCKey *pEccKey,
        TPMS_ECC_POINT *pEccPublicKey,
        TPM2B_ECC_PARAMETER *pEccPrivateKey
);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
TSS2_RC SAPI2_UTILS_convertTpm2EccPublicToEccKey(
        MOC_ECC(hwAccelDescr hwAccelCtx)
        TPMS_ECC_POINT *pTpm2EccPoint,
        ubyte4 eccCurveId,
        ECCKey **ppEccKey
);
#else
TSS2_RC SAPI2_UTILS_convertTpm2EccPublicToEccKey(
        TPMS_ECC_POINT *pTpm2EccPoint,
        PEllipticCurvePtr pECcurve,
        ECCKey **ppEccKey
);
#endif

TSS2_RC SAPI2_UTILS_convertEccPointToTpm2Point(
        MOC_ECC(hwAccelDescr hwAccelCtx)
        ECCKey *pEccKey,
        TPMS_ECC_POINT *pTpm2EccPoint
);

TSS2_RC SAPI2_UTILS_generateECCSeed(
        MOC_ECC(hwAccelDescr hwAccelCtx)
        ECCKey *pEccPublicKey,
        const ubyte *pLabel,
        ubyte4 labelLen,
        TPM2_ALG_ID kdfeHashAlg,
        ubyte *pSeedOut,
        ubyte4 seedLen,
        TPM2B_ENCRYPTED_SECRET *pEncryptedSecret
);
#endif
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __SAPI2_UTILS_H__ */
