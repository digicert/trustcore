/**
 * @file sapi2_hash.h
 * @brief This file contains SAPI HASH related functions for TPM2.
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
#ifndef __SAPI2_HASH_H
#define __SAPI2_HASH_H

#if (defined(__ENABLE_DIGICERT_TPM2__))
/**
 * @private
 * @internal
 *
 */
typedef struct
{
    ubyte *pBuf;
    ubyte4 bufLen;
} HASH_ELEMENT;


MOC_EXTERN MSTATUS
SAPI2_HASH_computeHASH(TPM2_ALG_ID algId, HASH_ELEMENT *pHashElement, ubyte4 maxHashElements, 
        ubyte *pHashOutput, ubyte4 hashLen);

MSTATUS
SAPI2_HASH_computeCmdPHash(MOCTPM2_SESSION *pSession, TPM2_CC commandCode,
        TPM2B_NAME **ppNames, ubyte4 numNames, HASH_ELEMENT *pParms, ubyte4 maxParms,
        TPM2B_DIGEST *pResult);

MSTATUS
SAPI2_HASH_computeRspPHash(MOCTPM2_SESSION *pSession, TPM2_CC commandCode,
        TPM2_CC responseCode, HASH_ELEMENT *pParms, ubyte4 maxParms,
        TPM2B_DIGEST *pResult);

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __SAPI2_HASH_H */
