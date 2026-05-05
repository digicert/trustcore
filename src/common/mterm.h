/**
 * @file   mterm.h
 * @brief  Mocana Terminal Abstraction Layer
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

/*------------------------------------------------------------------*/

#ifndef __MTERM_HEADER__
#define __MTERM_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#include "mtypes.h"

/*------------------------------------------------------------------*/

#if defined(__RTOS_WIN32__)

#define TERM_promptPassword     WIN32_promptPassword

#elif defined(__RTOS_LINUX__)

#define TERM_promptPassword     LINUX_promptPassword

#endif

/*------------------------------------------------------------------*/

/**
 * @brief Read a password from the user with optional character masking.
 *
 * @param pPassword    Buffer to store the password
 * @param passwdLength Maximum length of password buffer
 * @param mask         ASCII character to display as mask (0 for no output)
 *
 * @return Number of characters read, or -1 on error
 */
MOC_EXTERN sbyte4 TERM_promptPassword(
    sbyte *pPassword,
    ubyte4 passwdLength,
    int mask);

/*------------------------------------------------------------------*/

#ifdef __cplusplus
}
#endif

#endif /* __MTERM_HEADER__ */
