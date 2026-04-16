/*
 * crypto_interface_hmac_common.c
 *
 * Common methods to Crypto Interface for HMAC and HMAC-KDF.
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
#include "../crypto/mocsym.h"
#include "../common/initmocana.h"

#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto_interface/crypto_interface_hmac_common.h"
#include "../crypto_interface/crypto_interface_priv.h"

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_HMAC__) || defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_HMAC_KDF__)

/* We check the digest size and init method of the pBHAlgo to determine which hash method it represents */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacGetHashAlgoFlag (
    const BulkHashAlgo *pBHAlgo,
    ubyte *pHashAlgoFlag
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pBHAlgo)
        goto exit;

    status = ERR_INVALID_INPUT;
    switch(pBHAlgo->hashId)
    {
        case ht_md2:
        case ht_md4:
        case ht_md5:
        case ht_sha1:
        case ht_sha224:
        case ht_sha256:
        case ht_sha384:
        case ht_sha512:
        case ht_sha3_224:
        case ht_sha3_256:
        case ht_sha3_384:
        case ht_sha3_512:
        case ht_shake128:
        case ht_shake256:
            *pHashAlgoFlag = pBHAlgo->hashId;
            break;

        default:
            goto exit;
    }

    status = OK;

exit:

    return status;
}
#endif /* defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_HMAC__) || defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_HMAC_KDF__) */
