
/*
 * @file smp.h
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
