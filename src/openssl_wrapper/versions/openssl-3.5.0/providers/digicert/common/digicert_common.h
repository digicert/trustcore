/*
 * digicert_common.h
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
#ifndef DIGICERT_COMMON_H
#define DIGICERT_COMMON_H

#ifdef  __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS digiprov_strdup(void **ppPtr, const char *pStr);
MOC_EXTERN MSTATUS digiprov_get_hashType(char *pMdname, FFCHashType *pHashType);
MOC_EXTERN MSTATUS digiprov_get_digest_data(const char *pMdname, BulkHashAlgo **ppBulkHashAlgo, 
                                            ubyte4 *pOutSize, ubyte4 *pBlockSize);
MOC_EXTERN int digiprov_get_utf8_string(const OSSL_PARAM *p, char **val, size_t max_len);
MOC_EXTERN int digiprov_get_octet_string(const OSSL_PARAM *p, void **val, size_t max_len, size_t *used_len);

#ifdef  __cplusplus
}
#endif
#endif /* DIGICERT_COMMON_H */
