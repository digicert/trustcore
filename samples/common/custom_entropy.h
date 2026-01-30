/*
 * custom_entropy.h
 *
 * APIs for custom entropy injection.
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#ifndef __CUSTOM_ENTROPY_HEADER__
#define __CUSTOM_ENTROPY_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MOC_CUSTOM_ENTROPY_LEN
#define MOC_CUSTOM_ENTROPY_LEN 48
#endif

MOC_EXTERN MSTATUS DIGICERT_CUSTOM_getEntropy(
    ubyte *pBuffer,
    ubyte4 bufferLen
    );

#endif /* ifndef __CUSTOM_ENTROPY_HEADER__ */