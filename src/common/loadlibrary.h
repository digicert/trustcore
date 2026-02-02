/*
 * loadlibrary.h
 *
 * Function prototypes to perform runtime dynamic library linking.
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

#ifndef __M_LOAD_LIBRARY_HEADER__
#define __M_LOAD_LIBRARY_HEADER__

MOC_EXTERN MSTATUS DIGICERT_loadDynamicLibrary(const char *pFilename, void **ppHandle);
MOC_EXTERN MSTATUS DIGICERT_loadDynamicLibraryEx(const char *pFilename, void **ppHandle);
MOC_EXTERN MSTATUS DIGICERT_unloadDynamicLibrary(void *pHandle);
MOC_EXTERN MSTATUS DIGICERT_getSymbolFromLibrary(const char *pSymbol, void *pLibHandle, void **ppSymbolAddr);

#endif /* __M_LOAD_LIBRARY_HEADER__ */