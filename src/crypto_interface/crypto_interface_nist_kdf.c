/*
 * crypto_interface_nist_kdf.c
 *
 * Cryptographic Interface specification for NIST-KDF.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_NIST_KDF_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/nist_prf.h"
#include "../crypto/nist_kdf.h"
#include "../crypto_interface/crypto_interface_nist_kdf.h"
#include "../crypto_interface/crypto_interface_priv.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_NIST_KDF__

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_NIST_KDF__))
#define MOC_NIST_KDF_COUNTER(_status, _ctrSize, _prfCtx, _prfAlgo, _label, _labelSize, _ctx, _ctxSize, _keyMatEncSize, _le, _keyMat, _keyMatSize) \
_status = KDF_NIST_CounterMode(MOC_SYM(hwAccelCtx) _ctrSize, _prfCtx, _prfAlgo, _label, _labelSize, _ctx, _ctxSize, _keyMatEncSize, _le, _keyMat, _keyMatSize)
#else
#define MOC_NIST_KDF_COUNTER(_status, _ctrSize, _prfCtx, _prfAlgo, _label, _labelSize, _ctx, _ctxSize, _keyMatEncSize, _le, _keyMat, _keyMatSize) \
_status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_NIST_KDF__))
#define MOC_NIST_KDF_FEEDBACK(_status, _ctrSize, _prfCtx, _prfAlgo, _iv, _ivSize, _label, _labelSize, _ctx, _ctxSize, _keyMatEncSize, _le, _keyMat, _keyMatSize) \
_status = KDF_NIST_FeedbackMode(MOC_SYM(hwAccelCtx) _ctrSize, _prfCtx, _prfAlgo, _iv, _ivSize, _label, _labelSize, _ctx, _ctxSize, _keyMatEncSize, _le, _keyMat, _keyMatSize)
#else
#define MOC_NIST_KDF_FEEDBACK(_status, _ctrSize, _prfCtx, _prfAlgo, _iv, _ivSize, _label, _labelSize, _ctx, _ctxSize, _keyMatEncSize, _le, _keyMat, _keyMatSize) \
_status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_NIST_KDF__))
#define MOC_NIST_KDF_DP(_status, _ctrSize, _prfCtx, _prfAlgo, _label, _labelSize, _ctx, _ctxSize, _keyMatEncSize, _le, _keyMat, _keyMatSize) \
_status = KDF_NIST_DoublePipelineMode(MOC_SYM(hwAccelCtx) _ctrSize, _prfCtx, _prfAlgo, _label, _labelSize, _ctx, _ctxSize, _keyMatEncSize, _le, _keyMat, _keyMatSize)
#else
#define MOC_NIST_KDF_DP(_status, _ctrSize, _prfCtx, _prfAlgo, _label, _labelSize, _ctx, _ctxSize, _keyMatEncSize, _le, _keyMat, _keyMatSize) \
_status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_KDF_NIST_CounterMode( 
    MOC_SYM(hwAccelDescr hwAccelCtx)
    ubyte4 counterSize, void* prfContext,
    const PRF_NIST_108* prfAlgo,
    const ubyte* label, ubyte4 labelSize,
    const ubyte* context, ubyte4 contextSize,
    ubyte4 keyMaterialEncodingSize, ubyte4 littleEndian,
    ubyte* keyMaterial, ubyte4 keyMaterialSize)
{
    MSTATUS status;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
    ubyte4 index;
    
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_nist_kdf, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_NIST_KDF_COUNTER(status, counterSize, prfContext, prfAlgo, label, labelSize, context, contextSize, keyMaterialEncodingSize, littleEndian, keyMaterial, keyMaterialSize);
    }

exit:

    return status;     
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_KDF_NIST_FeedbackMode(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    ubyte4 counterSize, void* prfContext,
    const PRF_NIST_108* prfAlgo,
    const ubyte* iv, ubyte4 ivSize,
    const ubyte* label, ubyte4 labelSize,
    const ubyte* context, ubyte4 contextSize,
    ubyte4 keyMaterialEncodingSize, ubyte4 littleEndian,
    ubyte* keyMaterial, ubyte4 keyMaterialSize)
{
    MSTATUS status;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
    ubyte4 index;
    
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_nist_kdf, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_NIST_KDF_FEEDBACK(status, counterSize, prfContext, prfAlgo, iv, ivSize, label, labelSize, context, contextSize, keyMaterialEncodingSize, littleEndian, keyMaterial, keyMaterialSize);
    }

exit:

    return status;     
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_KDF_NIST_DoublePipelineMode(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    ubyte4 counterSize, void* prfContext,
    const PRF_NIST_108* prfAlgo,
    const ubyte* label, ubyte4 labelSize,
    const ubyte* context, ubyte4 contextSize,
    ubyte4 keyMaterialEncodingSize, ubyte4 littleEndian,
    ubyte* keyMaterial, ubyte4 keyMaterialSize)
{
    MSTATUS status;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
    ubyte4 index;
    
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_nist_kdf, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_NIST_KDF_DP(status, counterSize, prfContext, prfAlgo, label, labelSize, context, contextSize, keyMaterialEncodingSize, littleEndian, keyMaterial, keyMaterialSize);
    }

exit:

    return status;     
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_NIST_KDF__ */
