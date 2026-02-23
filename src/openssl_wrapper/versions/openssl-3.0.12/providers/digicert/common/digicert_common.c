/*
 * digicert_common.c
 *
 * Defines common code needed by several cipher implementations.
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */
#include "../../../src/common/moptions.h"
#include "../../../src/common/mtypes.h"
#include "../../../src/common/mdefs.h"
#include "../../../src/common/merrors.h"
#include "../../../src/common/mstdlib.h"
#include "../../../src/common/vlong.h"
#include "../../../src/crypto/hw_accel.h"
#include "../../../src/crypto/ffc.h"
#include "../../../src/crypto/crypto.h"

#include "openssl/params.h"

#include "digicert_common.h"
#include "mocana_glue.h"

#include "openssl/obj_mac.h"
#include "openssl/evp.h"
#include "prov/names.h"

MOC_EXTERN MSTATUS digiprov_strdup(void **ppPtr, const char *pStr)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 len = 0;

    if (NULL == ppPtr || NULL == pStr)
        return status;

    len = DIGI_STRLEN((const sbyte *)pStr);

    status = DIGI_MALLOC(ppPtr, len + 1);
    if (OK != status)
        return status;
    
    status = DIGI_MEMCPY(*ppPtr, pStr, len);
    if (OK != status)
    {
        (void) DIGI_FREE(ppPtr);
        return status;
    }

    ((sbyte *)(*ppPtr))[len] = '\0';

    return status;
}

/* looks for pMdname as one of the possible names in pProvName */
static sbyte4 digiprov_compare_name(const char *pMdname, const char *pProvName)
{
    sbyte4 ret = 1;

    ubyte4 startPos = 0;
    ubyte4 endPos = 0;
    ubyte4 totalLen = 0;
    ubyte4 mdNameLen = 0;

    totalLen = DIGI_STRLEN((const sbyte *) pProvName);
    mdNameLen = DIGI_STRLEN((const sbyte *) pMdname);

    while (endPos <= totalLen)
    {
        if (endPos == totalLen || ':' == pProvName[endPos])
        {
            if (mdNameLen == endPos - startPos)
            {
                if (0 == DIGI_STRNICMP((const sbyte *) pMdname, (const sbyte *) pProvName + startPos, mdNameLen))
                {
                    ret = 0;
                    break;
                }
            }
            startPos = endPos+1;
        }
        
        endPos++;
    }

    return ret;
}

MOC_EXTERN MSTATUS digiprov_get_hashType(char *pMdname, FFCHashType *pHashType)
{
    if(NULL == pMdname)
        return ERR_NULL_POINTER;
    
    if (0 == digiprov_compare_name(pMdname, (const char *) PROV_NAMES_SHA1))
    {
        *pHashType = FFC_sha1;
    }
    else if (0 == digiprov_compare_name(pMdname, (const char *) PROV_NAMES_SHA2_224))
    {
        *pHashType = FFC_sha224;
    }
    else if (0 == digiprov_compare_name(pMdname, (const char *) PROV_NAMES_SHA2_256))
    {
        *pHashType = FFC_sha256;
    }
    else if (0 == digiprov_compare_name(pMdname, (const char *) PROV_NAMES_SHA2_384))
    {
        *pHashType = FFC_sha384;
    }
    else if (0 == digiprov_compare_name(pMdname, (const char *) PROV_NAMES_SHA2_512))
    {
        *pHashType = FFC_sha512;
    }
    else
    {
        return ERR_INVALID_INPUT;
    }

    return OK;
}

MOC_EXTERN MSTATUS digiprov_get_digest_data(const char *pMdname, BulkHashAlgo **ppBulkHashAlgo, 
                                            ubyte4 *pOutSize, ubyte4 *pBlockSize)
{
    MOC_EVP_MD_CTX mdCtx = {0};
    int nid = 0;

    if (NULL == ppBulkHashAlgo) /* We allow NULL on the other params */
        return ERR_NULL_POINTER;

    if (0 == digiprov_compare_name(pMdname, (const char *) PROV_NAMES_MD4))
    {
        nid = NID_md4;
    }
    else if (0 == digiprov_compare_name(pMdname, (const char *) PROV_NAMES_MD5))
    {
        nid = NID_md5;
    }
    else if (0 == digiprov_compare_name(pMdname, (const char *) PROV_NAMES_SHA1))
    {
        nid = NID_sha1;
    }
    else if (0 == digiprov_compare_name(pMdname, (const char *) PROV_NAMES_SHA2_224))
    {
        nid = NID_sha224;
    }
    else if (0 == digiprov_compare_name(pMdname, (const char *) PROV_NAMES_SHA2_256))
    {
        nid = NID_sha256;
    }
    else if (0 == digiprov_compare_name(pMdname, (const char *) PROV_NAMES_SHA2_384))
    {
        nid = NID_sha384;
    }
    else if (0 == digiprov_compare_name(pMdname, (const char *) PROV_NAMES_SHA2_512))
    {
        nid = NID_sha512;
    }
    else if (0 == digiprov_compare_name(pMdname, (const char *) PROV_NAMES_SHA3_224))
    {
        nid = NID_sha3_224;
    }
    else if (0 == digiprov_compare_name(pMdname, (const char *) PROV_NAMES_SHA3_256))
    {
        nid = NID_sha3_256;
    }
    else if (0 == digiprov_compare_name(pMdname, (const char *) PROV_NAMES_SHA3_384))
    {
        nid = NID_sha3_384;
    }
    else if (0 == digiprov_compare_name(pMdname, (const char *) PROV_NAMES_SHA3_512))
    {
        nid = NID_sha3_512;
    }
    else
    {
        return ERR_INVALID_INPUT;
    }

#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
    if (1 == EVP_default_properties_is_fips_enabled(NULL))
    {
        switch (nid)
        {
            case NID_md4:
                return ERR_INVALID_INPUT;
        }
    }
#endif

    DIGI_EVP_setDigestAlgo(&mdCtx, nid);

    if (NULL == mdCtx.pDigestAlgo || NULL == mdCtx.pDigestAlgo->pHashAlgo)
    {
        return ERR_INVALID_INPUT;
    }

    *ppBulkHashAlgo = (BulkHashAlgo *) mdCtx.pDigestAlgo->pHashAlgo;

    if (NULL != pOutSize)
        *pOutSize = mdCtx.pDigestAlgo->digestResultSize;
    
    if (NULL != pBlockSize)
        *pBlockSize = mdCtx.pDigestAlgo->pHashAlgo->blockSize;

    return OK;
}

/* based on OpenSSL's version. We have our own so we can use our own memory allocation */
static int get_string_internal(const OSSL_PARAM *p, void **val,
                               size_t *max_len, size_t *used_len,
                               unsigned int type)
{
    MSTATUS status = OK;
    size_t sz, alloc_sz;

    if ((val == NULL && used_len == NULL) || p == NULL || p->data_type != type)
        return 0;

    sz = p->data_size;
    /*
     * If the input size is 0, or the input string needs NUL byte
     * termination, allocate an extra byte.
     */
    alloc_sz = sz + (type == OSSL_PARAM_UTF8_STRING || sz == 0);

    if (used_len != NULL)
        *used_len = sz;

    if (p->data == NULL)
        return 0;

    if (val == NULL)
        return 1;

    if (*val == NULL) 
    {
        char *q = NULL;

        status = DIGI_MALLOC((void **) &q, alloc_sz);
        if (OK != status)
            return 0;

        *val = q; q = NULL;
        *max_len = alloc_sz;
    }

    if (*max_len < sz)
        return 0;
    (void) DIGI_MEMCPY((ubyte *) *val, p->data, sz);
    return 1;
}

MOC_EXTERN int digiprov_get_utf8_string(const OSSL_PARAM *p, char **val, size_t max_len)
{
    int ret = get_string_internal(p, (void **)val, &max_len, NULL, OSSL_PARAM_UTF8_STRING);

    /*
     * We try to ensure that the copied string is terminated with a
     * NUL byte.  That should be easy, just place a NUL byte at
     * |((char*)*val)[p->data_size]|.
     * Unfortunately, we have seen cases where |p->data_size| doesn't
     * correctly reflect the length of the string, and just happens
     * to be out of bounds according to |max_len|, so in that case, we
     * make the extra step of trying to find the true length of the
     * string that |p->data| points at, and use that as an index to
     * place the NUL byte in |*val|.
     */
    size_t data_length = p->data_size;

    if (ret == 0)
        return 0;
    if (data_length >= max_len)
        data_length = OPENSSL_strnlen(p->data, data_length);
    if (data_length >= max_len)
        return 0;            /* No space for a terminating NUL byte */
    (*val)[data_length] = '\0';

    return ret;
}

MOC_EXTERN int digiprov_get_octet_string(const OSSL_PARAM *p, void **val, size_t max_len, size_t *used_len)
{
    return get_string_internal(p, val, &max_len, used_len, OSSL_PARAM_OCTET_STRING);
}

