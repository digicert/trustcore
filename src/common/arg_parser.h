/*
 * arg_parser.h
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

#ifndef __ARG_PARSER_HEADER__
#define __ARG_PARSER_HEADER__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS ARG_PARSER_getStringValueRef(
    char **ppArgv,
    int argc,
    int *pIdx,
    sbyte **ppStr);

MOC_EXTERN MSTATUS ARG_PARSER_getStringValue(
    char **ppArgv,
    int argc,
    int *pIdx,
    sbyte **ppStr);

#ifdef __cplusplus
}
#endif

#endif /* __ARG_PARSER_HEADER__ */
