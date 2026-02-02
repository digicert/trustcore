/*
 * moc_win_utils.h
 *
 * Utility methods used for windows platform
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
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

