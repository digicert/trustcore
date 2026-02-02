/*
 * crypto_interface_ansix9_63_kdf.c
 *
 * Cryptographic Interface specification for ANSIX9_63-KDF.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_ANSIX9_63_KDF_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../crypto/crypto.h"
#include "../harness/harness.h"
#include "../crypto/ansix9_63_kdf.h"
#include "../crypto_interface/crypto_interface_priv.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_ANSIX9_63_KDF__

/*---------------------------------------------------------------------------*/

#if !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
#define MOC_ANSIX9_63_GENERATE(_status, _pBulkHashAlgo, _z, _zLength, _sharedInfo, _sharedInfoLen, _retLen, _ret) \
_status = ANSIX963KDF_generate(MOC_HASH(hwAccelCtx) _pBulkHashAlgo, _z, _zLength, _sharedInfo, _sharedInfoLen, _retLen, _ret)
#else
#define MOC_ANSIX9_63_GENERATE(_status, _pBulkHashAlgo, _z, _zLength, _sharedInfo, _sharedInfoLen, _retLen, _ret) \
_status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ANSIX963KDF_generate( 
    MOC_HASH(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo* pBulkHashAlgo,
    ubyte* z, ubyte4 zLength,
    const ubyte* sharedInfo, ubyte4 sharedInfoLen,
    ubyte4 retLen, ubyte ret[/*retLen*/])
{
    MSTATUS status;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
    ubyte4 index = 0;

    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_ansix9_63_kdf, &algoStatus, &index);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_ANSIX9_63_GENERATE(status, pBulkHashAlgo, z, zLength, sharedInfo, sharedInfoLen, retLen, ret);
    }

exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_ANSIX9_63_KDF__ */
