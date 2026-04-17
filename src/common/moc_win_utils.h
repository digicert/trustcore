/*
 * moc_win_utils.h
 *
 * Utility methods used for windows platform
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

#ifndef __MOCWINUTILS_HEADER__
#define __MOCWINUTILS_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __RTOS_WIN32__

MOC_EXTERN MSTATUS
UTILS_getWinConfigDir(ubyte **ppConfigDirPath,
                      const ubyte *pConfigDirName);

MOC_EXTERN MSTATUS
UTILS_getWinConfigFilePath(ubyte **ppConfigFilePath,
                           const ubyte *pConfigFileRelativePath);

#endif /* __RTOS_WIN32__ */

#ifdef __cplusplus
}
#endif

#endif /*__MOCWINUTILS_HEADER__*/

