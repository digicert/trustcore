/*
 * common_utils.h
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
