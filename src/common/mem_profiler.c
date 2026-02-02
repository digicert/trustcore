/*
 * mem_part_profiler.c
 *
 * Memory Profiler Source Code.
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

#include "../common/mem_profiler.h"

#ifdef __ENABLE_DIGICERT_MEM_PROFILE__

#include "../common/mfmgmt.h"
#include "../common/mrtos.h"
#include "../common/mem_part.h"

#ifdef __ENABLE_DIGICERT_MEM_PROFILE_MAP__
#include "../common/hash_map_simple.h"
#endif

#ifndef MOC_MEM_PROFILER_OUT_FILE
#define MOC_MEM_PROFILER_OUT_FILE "allocation_history.txt"
#endif

#if __LONG_MAX__ == __INT_MAX__
#define PTR_FORMAT "%08x"
#else
#define PTR_FORMAT "%llx"
#endif

#ifdef __ENABLE_DIGICERT_MEM_PROFILE_VAR_TABLE__
#define EXTRA_ZERO ":0"
#define DOUBLE_COLON "::"
#else
#define EXTRA_ZERO ""
#define DOUBLE_COLON ""
#endif

static FileDescriptor gpOutFile = NULL;

#ifdef __ENABLE_DIGICERT_MEM_PROFILE_MAP__

#ifndef MOC_MEM_PROFILE_MEM_SIZE
#define MOC_MEM_PROFILE_MEM_SIZE (5000000)
#endif

#ifndef MOC_MEM_PROFILE_HASH_MAP_SIZE
#define MOC_MEM_PROFILE_HASH_MAP_SIZE 2048
#endif

typedef struct _PtrLengthPair
{
    uintptr value;
    ubyte4 length;

} PtrLengthPair;

static ubyte gpMemBuffer[MOC_MEM_PROFILE_MEM_SIZE] = {0};
static HashMap *gpHashMap = NULL;

static ubyte4 hashMethodMedium(void *pKey)
{
    uintptr key = (uintptr) pKey;

#if __LONG_MAX__ == __INT_MAX__
    return ( (key ^ (key >> 10) ^ (key >> 20) ^ (key >> 30)) & (uintptr) 0x03ff );
#else
    return ( (key ^ (key >> 10) ^ (key >> 20) ^ (key >> 30) ^ (key >> 40) ^ (key >> 50) ^ (key >> 60)) & (uintptr) 0x03ff );
#endif
}

#endif /* __ENABLE_DIGICERT_MEM_PROFILE_MAP__ */

#if defined(__RTOS_ZEPHYR__) && defined(__ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__)
#include <zephyr/fs/fs.h>
struct fs_file_t gpZephyrOutFile;
#endif

MOC_EXTERN MSTATUS MEM_PROFILER_init(void)
{
    if (NULL == gpOutFile)
    {
#ifdef __ENABLE_DIGICERT_MEM_PROFILE_MAP__
        MSTATUS status = createHashMapStaticMem(&gpHashMap, MOC_MEM_PROFILE_HASH_MAP_SIZE, hashMethodMedium, gpMemBuffer, MOC_MEM_PROFILE_MEM_SIZE);
        if (OK != status)
            return status;
#endif

#if defined(__RTOS_ZEPHYR__) && defined(__ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__)
        MSTATUS status;
        status = FMGMT_fopenEx(MOC_MEM_PROFILER_OUT_FILE, "w", (FileDescriptor) &gpZephyrOutFile);
        if (OK != status)
            return status;

        gpOutFile = (FileDescriptor) &gpZephyrOutFile;
#else
        return FMGMT_fopen(MOC_MEM_PROFILER_OUT_FILE, "w", &gpOutFile);
#endif
    }
    return OK; /* already initialized */
}

MOC_EXTERN MSTATUS MEM_PROFILER_addState(ubyte4 stateId)
{
    int retVal = 0;
    
    if (NULL == gpOutFile)
        return ERR_NULL_POINTER;
    
    retVal = FMGMT_fprintf (gpOutFile, "2:" PTR_FORMAT EXTRA_ZERO DOUBLE_COLON "\n", stateId);
    if (retVal < 0)
        return ERR_FILE_WRITE_FAILED;
    
    return OK;
}

#ifdef __ENABLE_DIGICERT_MEM_PROFILE_VAR_TABLE__
MOC_EXTERN MSTATUS MEM_PROFILER_addVar(ubyte *pVarName, uintptr address)
{
    int retVal = 0;
    
    if (NULL == gpOutFile)
        return ERR_NULL_POINTER;
    
    retVal = FMGMT_fprintf (gpOutFile, "3:" PTR_FORMAT ":0:%s\n", address, (const char *) pVarName);
    if (retVal < 0)
        return ERR_FILE_WRITE_FAILED;
    
    return OK;
}
#endif

MOC_EXTERN MSTATUS MEM_PROFILER_addRecord(byteBoolean isAlloc, uintptr address, ubyte4 length, ubyte *pFunc, sbyte4 line)
{
    int retVal = 0;
    
    if (NULL == gpOutFile)
        return ERR_NULL_POINTER;
    
    if (isAlloc)
    {
#ifdef __ENABLE_DIGICERT_MEM_PROFILE_LEAK_CHECK__
        retVal = FMGMT_fprintf (gpOutFile, "1:" PTR_FORMAT ":%08x:%s:%d" DOUBLE_COLON "\n", (ubyte4) address, length, (const char *) pFunc, (int) line);
#else
        retVal = FMGMT_fprintf (gpOutFile, "1:" PTR_FORMAT ":%08x" DOUBLE_COLON "\n", (ubyte4) address, length);
#endif
    }
    else /* is a free */
    {
        retVal = FMGMT_fprintf (gpOutFile, "0:" PTR_FORMAT EXTRA_ZERO DOUBLE_COLON "\n", (ubyte4) address);
    }
    
    if (retVal < 0)
        return ERR_FILE_WRITE_FAILED;
    
    FMGMT_fflush(gpOutFile);
    return OK;
}

#ifdef __ENABLE_DIGICERT_MEM_PROFILE_MAP__ 
MOC_EXTERN MSTATUS MEM_PROFILER_addToMap(uintptr location, uintptr address, ubyte4 length)
{
    MSTATUS status = ERR_NULL_POINTER;
    void *pNewPair = NULL;

    if (0 == location)
        goto exit;

    status = allocateMemBlock(gpHashMap, sizeof(PtrLengthPair), &pNewPair);
    if (OK != status)
        goto exit;
    
    ((PtrLengthPair *) pNewPair)->value = address;
    ((PtrLengthPair *) pNewPair)->length = length;

    status = addKey(gpHashMap, (void *) location, pNewPair);
    if (OK != status)
        goto exit;

    pNewPair = NULL;

exit:

    if (NULL != pNewPair)
    {
        (void) freeMemBlock(gpHashMap, &pNewPair);
    }

    return status;
}

MOC_EXTERN MSTATUS MEM_PROFILER_deleteFromMap(uintptr location)
{
    MSTATUS status = ERR_NULL_POINTER;
    void *pRetPair = NULL;

    status = deleteKey(gpHashMap, (void * ) location, &pRetPair);
    if (OK != status)
        goto exit;

    if (NULL != pRetPair)
    {
        status = freeMemBlock(gpHashMap, &pRetPair);
    }

exit:

    return status;
}

MOC_EXTERN MSTATUS MEM_PROFILER_iterateMap(void)
{
    MSTATUS status = OK;
    void *pKey = NULL;
    PtrLengthPair *pValue = NULL;
    ubyte4 index = 0;

    while (OK == status)
    {
        status = iterateHashMap(gpHashMap, &index, &pKey, (void **) &pValue);

        (void) pKey;
        (void) pValue->value;
        (void) pValue->length;
    }

    return OK;
}

#endif /* __ENABLE_DIGICERT_MEM_PROFILE_MAP__ */


MOC_EXTERN MSTATUS MEM_PROFILER_done(void)
{
    MSTATUS status = OK;

#ifdef __ENABLE_DIGICERT_MEM_PROFILE_MAP__
    if (NULL != gpHashMap)
    {
        status = deleteHashMap(&gpHashMap);
    }
#endif

    if (NULL != gpOutFile)
    {
#if defined(__RTOS_ZEPHYR__) && defined(__ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__)
        MSTATUS fstatus = FMGMT_fcloseEx(&gpOutFile);
#else
        MSTATUS fstatus = FMGMT_fclose(&gpOutFile);
#endif
        if (OK == status)
            status = fstatus;

        gpOutFile = NULL;
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_MEM_PROFILE__ */
