/*
 * mbedhmaccommon.c
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

#include "../../../crypto/mocsym.h"


#if defined(__ENABLE_DIGICERT_HMAC_MBED__) || defined(__ENABLE_DIGICERT_HMAC_KDF_MBED__)

#include "../../../crypto/mocsymalgs/mbed/mbedhmaccommon.h"

MOC_EXTERN MSTATUS ConvertMocDigestIdToMbedDigestId(
    ubyte mocDigestId,
    mbedtls_md_type_t *pRetMbedDigestId
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    
    if (NULL == pRetMbedDigestId)
        goto exit;
    
    switch (mocDigestId)
    {
        default:
            status = ERR_MBED_HMAC_UNSUPPORTED_DIGEST;
            goto exit;
            
        case ht_md2:
            *pRetMbedDigestId = MBEDTLS_MD_MD2;
            break;
            
        case ht_md4:
            *pRetMbedDigestId = MBEDTLS_MD_MD4;
            break;
            
        case ht_md5:
            *pRetMbedDigestId = MBEDTLS_MD_MD5;
            break;
            
        case ht_sha1:
            *pRetMbedDigestId = MBEDTLS_MD_SHA1;
            break;
            
        case ht_sha224:
            *pRetMbedDigestId = MBEDTLS_MD_SHA224;
            break;
            
        case ht_sha256:
            *pRetMbedDigestId = MBEDTLS_MD_SHA256;
            break;
            
        case ht_sha384:
            *pRetMbedDigestId = MBEDTLS_MD_SHA384;
            break;
            
        case ht_sha512:
            *pRetMbedDigestId = MBEDTLS_MD_SHA512;
            break;
    }
    
    status = OK;
    
exit:
    
    return status;
}
#endif /* defined(__ENABLE_DIGICERT_HMAC_MBED__) || defined(__ENABLE_DIGICERT_HMAC_KDF_MBED__) */
