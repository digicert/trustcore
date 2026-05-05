/*
 * build_info.c
 *
 * Capture build information
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

#if defined(__ENABLE_DIGICERT_BUILD_INFO__)

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/debug_console.h"
#include "../common/build_info.h"

/*----------------------------------------------------------------------------*/

/* Define "unknown" macro */
#define BUILD_INFO_UNKNOWN      "(unknown)"

/* Define copyright macros */
#ifndef BUILD_INFO_YEAR_VAL
#error "Year must be defined"
#endif
#define BUILD_INFO_COPYRIGHT_STR    "Copyright (c) " BUILD_INFO_YEAR_VAL " Digicert Inc\n"

/* Define platform macros */
#define BUILD_INFO_PLATFORM     "Platform: "
#ifndef BUILD_INFO_PLATFORM_VAL
#define BUILD_INFO_PLATFORM_VAL BUILD_INFO_UNKNOWN
#endif
#define BUILD_INFO_PLATFORM_STR "  " BUILD_INFO_PLATFORM BUILD_INFO_PLATFORM_VAL "\n"

/* Define version macros */
#define BUILD_INFO_VERSION      "Version: "
#ifndef BUILD_INFO_VERSION_VAL
#define BUILD_INFO_VERSION_VAL BUILD_INFO_UNKNOWN
#endif
#define BUILD_INFO_VERSION_STR "  " BUILD_INFO_VERSION BUILD_INFO_VERSION_VAL "\n"

/* Define build macros */
#define BUILD_INFO_BUILD        "Build: "
#ifndef BUILD_INFO_TYPE_VAL
#define BUILD_INFO_TYPE_VAL BUILD_INFO_UNKNOWN
#endif
#define BUILD_INFO_BUILD_STR "  " BUILD_INFO_BUILD BUILD_INFO_TYPE_VAL " (" BUILD_INFO_BUILD_VAL ")" "\n"

/* Define date macros */
#define BUILD_INFO_DATE         "Date: "
#ifndef BUILD_INFO_DATE_VAL
#define BUILD_INFO_DATE_VAL BUILD_INFO_UNKNOWN
#endif
#define BUILD_INFO_DATE_STR "  " BUILD_INFO_DATE BUILD_INFO_DATE_VAL "\n"

/* Construct final macro contaning all information */
#define BUILD_INFO_STR \
    BUILD_INFO_COPYRIGHT_STR \
    BUILD_INFO_PLATFORM_STR \
    BUILD_INFO_VERSION_STR \
    BUILD_INFO_BUILD_STR \
    BUILD_INFO_DATE_STR



/*----------------------------------------------------------------------------*/

extern void BUILD_INFO_print(void)
{
    DB_PRINT(BUILD_INFO_STR);
}

/*----------------------------------------------------------------------------*/

#endif /* __ENABLE_DIGICERT_BUILD_INFO__ */
