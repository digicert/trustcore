
/**
 * @file smp.h
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
 *
 */

/**
 * @file smp.h 
 *
 * @brief This file contains types and structures for NanoSMP modules.
 * @details This file contains types and structures for NanoSMP modules.
 * 
 * @flags
 * This file requires that the following flags be defined:
 *    + \c \__ENABLE_DIGICERT_SMP__
 *
 * 
 */

#ifndef __SMP_HEADER__
#define __SMP_HEADER__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/mstdlib.h"

#if defined(__ENABLE_DIGICERT_SMP__)
#include "../tap/tap_smp.h"


#define SMP_CREATE_NAME_HELPER(a,b,c,d) a##b##c##d
#define SMP_CREATE_API_NAME(a, b, c, d) SMP_CREATE_NAME_HELPER(a,b,c,d)

#ifdef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__

#define SMP_API(smpName, apiName, ...)\
        SMP_CREATE_API_NAME(SMP_, smpName, _,apiName)(__VA_ARGS__)

#define CALL_SMP_API(smpName, apiName, ...)\
        status = SMP_CREATE_API_NAME(SMP_, smpName, _,apiName)(__VA_ARGS__)

#define CALL_SMP_API_NO_RET(smpName, apiName, ...)\
        SMP_CREATE_API_NAME(SMP_, smpName, _,apiName)(__VA_ARGS__)
#else
#define SMP_API(smpName, apiName, ...)\
        SMP_CREATE_API_NAME(SMP_, smpName, _,apiName)(\
                __VA_ARGS__,\
                TAP_ErrorAttributes *pErrorRules, TAP_ErrorAttributes **ppErrAttrReturned)

#define CALL_SMP_API(smpName, apiName, ...)\
        status = SMP_CREATE_API_NAME(SMP_, smpName, _,apiName)(__VA_ARGS__, pErrorRules, ppErrAttrReturned)

#define CALL_SMP_API_NO_RET(smpName, apiName, ...)\
        SMP_CREATE_API_NAME(SMP_, smpName, _,apiName)(__VA_ARGS__, pErrorRules, ppErrAttrReturned)

#endif /* __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__ */

#endif /* __ENABLE_DIGICERT_SMP__ */
#endif /* __SMP_HEADER__ */
