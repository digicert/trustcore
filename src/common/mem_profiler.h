/*
 * mem_profiler.h
 *
 * Memory Profiler Header.
 * Records and outputs data on the allocation history of the program.
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#ifndef __MEMORY_PROFILER_HEADER__
#define __MEMORY_PROFILER_HEADER__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS MEM_PROFILER_init(void);
MOC_EXTERN MSTATUS MEM_PROFILER_addState(ubyte4 stateId);
MOC_EXTERN MSTATUS MEM_PROFILER_addVar(ubyte *pVarName, uintptr address);
MOC_EXTERN MSTATUS MEM_PROFILER_addRecord(byteBoolean isAlloc, uintptr address, ubyte4 length, ubyte *pFunc, sbyte4 line);
MOC_EXTERN MSTATUS MEM_PROFILER_addToMap(uintptr location, uintptr address, ubyte4 length);
MOC_EXTERN MSTATUS MEM_PROFILER_deleteFromMap(uintptr location);
MOC_EXTERN MSTATUS MEM_PROFILER_iterateMap(void);
MOC_EXTERN MSTATUS MEM_PROFILER_done(void);

#ifdef __cplusplus
}
#endif
    
#endif /* __MEMORY_PROFILER_HEADER__ */
