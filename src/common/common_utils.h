/*
 * common_utils.c
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

#ifndef __COMMON_UTILS_HEADER__
#define __COMMON_UTILS_HEADER__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS COMMON_UTILS_unescapeNewLine(
    ubyte *pData,
    ubyte4 *pDataLen);

MOC_EXTERN MSTATUS COMMON_UTILS_addPathComponent(
    sbyte *pPath,
    sbyte *pComponent,
    sbyte **ppNewPath);

MOC_EXTERN MSTATUS COMMON_UTILS_addPathComponentWithLength(
    sbyte *pPath,
    sbyte *pComponent,
    ubyte4 componentLen,
    sbyte **ppNewPath);

MOC_EXTERN MSTATUS COMMON_UTILS_addPathExtension(
    sbyte *pPath,
    sbyte *pExtension,
    sbyte **ppNewPath);

MOC_EXTERN MSTATUS COMMON_UTILS_splitPath(
    sbyte *path,
    sbyte **ppDirName,
    sbyte **ppFileName);

MOC_EXTERN MSTATUS COMMON_UTILS_evaluatePlaceholder(
    sbyte *pPlaceholder,
    sbyte *pReplacement,
    sbyte **ppPath);

#ifdef __cplusplus
}
#endif

#endif /* __COMMON_UTILS_HEADER__ */