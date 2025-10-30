/*
 * utf8.h
 *
 * Code for handling UTF-8 values
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

#ifndef __UTF8_HEADER__
#define __UTF8_HEADER__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mdefs.h"

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS UTF8_validateEncoding(
    ubyte *pData,
    ubyte4 dataLen,
    byteBoolean *pIsValid);

#ifdef __cplusplus
}
#endif

#endif /* __UTF8_HEADER__ */