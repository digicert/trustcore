/*
 * memory_debug.h
 *
 * Mocana Memory Leak Detection Code
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

#ifndef __MEMORY_DEBUG_HEADER__
#define __MEMORY_DEBUG_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_DIGICERT_DEBUG_MEMORY__
#define DEBUG_RELABEL_MEMORY(PTR)       dbg_relabel_memory(PTR,(ubyte *)__FILE__,__LINE__)
#define DEBUG_CHECK_MEMORY(PTR)         dbg_check_memory  (PTR,(ubyte *)__FILE__,__LINE__)
#else
#define DEBUG_RELABEL_MEMORY(PTR)
#define DEBUG_CHECK_MEMORY(PTR)
#endif


/*------------------------------------------------------------------*/

MOC_EXTERN void dbg_relabel_memory(void *pBlockToRelabel, ubyte *pFile, ubyte4 lineNum);
MOC_EXTERN void dbg_check_memory  (void *pBlockToCheck, ubyte *pFile, ubyte4 lineNum);

MOC_EXTERN ubyte4 MEMORY_DEBUG_resetHighWaterMark(void);

MOC_EXTERN void MEMORY_DEBUG_enableMutex(void);
MOC_EXTERN void MEMORY_DEBUG_disableMutex(void);


#ifdef __cplusplus
}
#endif

#endif /* __MEMORY_DEBUG_HEADER__ */

