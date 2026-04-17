/*
 * mem_profiler.h
 *
 * Memory Profiler Header.
 * Records and outputs data on the allocation history of the program.
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
