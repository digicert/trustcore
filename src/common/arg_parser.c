/*
 * arg_parser.c
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

#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_ARG_PARSER__)

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/arg_parser.h"

extern MSTATUS ARG_PARSER_getStringValueRef(
    char **ppArgv,
    int argc,
    int *pIdx,
    sbyte **ppStr)
{
    MSTATUS status;
    int curArg;

    if (NULL == ppArgv || NULL == pIdx || NULL == ppStr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    curArg = *pIdx;
    curArg++;
    if (curArg >= argc)
    {
        status = ERR_ARG_PARSER_MISSING_VALUE;
        goto exit;
    }

    *ppStr = ppArgv[curArg];
    *pIdx = curArg;
    status = OK;

exit:

    return status;
}

extern MSTATUS ARG_PARSER_getStringValue(
    char **ppArgv,
    int argc,
    int *pIdx,
    sbyte **ppStr)
{
    MSTATUS status;
    sbyte *pRef = NULL;
    sbyte *pVal = NULL;
    sbyte4 len;
    int localIdx;
    int *pLocalIdx = NULL;

    if (NULL != pIdx)
    {
        localIdx = *pIdx;
        pLocalIdx = &localIdx;
    }

    status = ARG_PARSER_getStringValueRef(ppArgv, argc, pLocalIdx, &pRef);
    if (OK != status)
    {
        goto exit;
    }

    len = DIGI_STRLEN(pRef);
    status = DIGI_MALLOC_MEMCPY((void **) &pVal, len + 1, pRef, len);
    if (OK != status)
    {
        goto exit;
    }
    pVal[len] = '\0';

    *ppStr = pVal;
    *pIdx = localIdx;

exit:

    return status;
}

#endif /* __ENABLE_DIGICERT_ARG_PARSER__ */
