/*
 * mbedrandom.h
 *
 * Operator for Software version of ECC MocAsym Key.
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

#include <stddef.h>

#ifndef __DIGICERT_MBED_RANDOM_H__
#define __DIGICERT_MBED_RANDOM_H__

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN int MocMbedRngFun(
    void *pRandInfo,
    unsigned char *pBuffer,
    size_t byteCount
    );

#ifdef __cplusplus
}
#endif

#endif /* __DIGICERT_MBED_RANDOM_H__ */