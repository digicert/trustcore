/*
 * smp_nanoroot_parseConfig.h
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
@file       smp_nanoroot_parseConfig.h
@ingroup    nanosmp_tree
@brief      NanoROOT specific header file
@details    This header file contains  parsing
            helper function declarations required by NanoROOT API.
*/

#ifndef __SMP_NANOROOT_PARSECONFIG_HEADER__
#define __SMP_NANOROOT_PARSECONFIG_HEADER__

#if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_SMP_NANOROOT__))

#define PATH_MAX 4096
/* Allowlist of permitted characters for path and arguments */
#define NANOROOT_ALLOWED_PATH_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_.-"
#define NANOROOT_ALLOWED_ARG_CHARS  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_.-=:"

/* Dangerous shell metacharacters to reject */
#define NANOROOT_BLOCKED_CHARS ";|&$`><\n\r\\!#(){}[]'\""

/**
 * @brief Validate input string against allowlist and blocklist
 * @param pInput    Input string to validate
 * @param pAllowed  String of allowed characters (NULL = use blocklist only)
 * @return OK if valid, error code otherwise
 */
MSTATUS NanoROOT_validateInput(const sbyte *pInput, const sbyte *pAllowed);

/**
 * @brief Validate that path is within allowed directories and is executable
 * @param pPath  Path to validate
 * @return OK if valid, error code otherwise
 */
MSTATUS NanoROOT_validatePath(const sbyte *pPath);

MSTATUS NanoROOT_parseCredFile(ubyte *pAttributeFile);

#endif /* __ENABLE_DIGICERT_SMP__ && __ENABLE_DIGICERT_SMP_NANOROOT__ */

#endif /* __SMP_NANOROOT_PARSECONFIG_HEADER__ */
