/*
 * dynarray.h
 *
 * Dynarray
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

#ifndef __DYNARRAY_H__
#define __DYNARRAY_H__

typedef struct DynArray
{
    sbyte4  numUsed;
    sbyte4  numAllocated;
    sbyte4  elementSize;
    void*   array;
} DynArray;

MOC_EXTERN MSTATUS DYNARR_Init( sbyte4 elementSize, DynArray* pArr);
MOC_EXTERN MSTATUS DYNARR_InitEx( sbyte4 elementSize, ubyte4 initialSize, DynArray* pArr);
MOC_EXTERN MSTATUS DYNARR_Uninit( DynArray* pArr);
MOC_EXTERN MSTATUS DYNARR_GetElementSize( const DynArray* pArr, sbyte4* pElementSize);
MOC_EXTERN MSTATUS DYNARR_GetElementCount( const DynArray* pArr, sbyte4* pElementCount);
MOC_EXTERN MSTATUS DYNARR_Append( DynArray* pArr, const void* pElement);
MOC_EXTERN MSTATUS DYNARR_AppendEx( DynArray* pArr, const void* pElement, ubyte4 incrementSize);
MOC_EXTERN MSTATUS DYNARR_AppendMultiple( DynArray* pArr, const void* pElements, ubyte4 numElems, ubyte4 incrementSize);
MOC_EXTERN MSTATUS DYNARR_Get( const DynArray* pArr, sbyte4 index, void* ppElement);
MOC_EXTERN MSTATUS DYNARR_GetArray( const DynArray* pArr, const void** pArray);
MOC_EXTERN MSTATUS DYNARR_DetachArray( DynArray* pArr, void** pArray);

#endif /* __DYNARRAY_H__ */
