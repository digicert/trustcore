/*
 * smp_nanoroot_parseConfig.h
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
@file       smp_nanoroot_parseConfig.h
@ingroup    nanosmp_tree
@brief      NanoROOT specific header file
@details    This header file contains  parsing
            helper function declarations required by NanoROOT API.
*/

#ifndef __SMP_NANOROOT_PARSECONFIG_HEADER__
#define __SMP_NANOROOT_PARSECONFIG_HEADER__

#if (defined (__ENABLE_MOCANA_SMP__) && defined (__ENABLE_MOCANA_SMP_NANOROOT__))

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

#endif /* __ENABLE_MOCANA_SMP__ && __ENABLE_MOCANA_SMP_NANOROOT__ */

#endif /* __SMP_NANOROOT_PARSECONFIG_HEADER__ */
