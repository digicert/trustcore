/**
 * @file   mem_part.h
 * @brief  Overlays a memory partition over a given memory region
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

#ifndef __MEMORY_PARTITION_HEADER__
#define __MEMORY_PARTITION_HEADER__

#ifdef __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__

#ifndef MOC_PARTITION_SMALL_PARTS_PER_128
#define MOC_PARTITION_SMALL_PARTS_PER_128 24
#endif

#ifndef MOC_PARTITION_MEDIUM_PARTS_PER_128
#define MOC_PARTITION_MEDIUM_PARTS_PER_128 40
#endif

#ifndef MOC_PARTITION_LARGE_PARTS_PER_128
#define MOC_PARTITION_LARGE_PARTS_PER_128 64
#endif

#if 128 != (MOC_PARTITION_SMALL_PARTS_PER_128 + MOC_PARTITION_MEDIUM_PARTS_PER_128 + MOC_PARTITION_LARGE_PARTS_PER_128)
#error MEMORY PARTITION PARTS_PER_128 MUST ADD TO 128
#endif

/* Allocation requests for fewer bytes than the threshold will default to the small partition */
#ifndef MOC_PARTITION_SMALL_THRESHOLD
#define MOC_PARTITION_SMALL_THRESHOLD 128
#endif

/* Allocation requests for fewer bytes than the threshold will default to the medium partition */
#ifndef MOC_PARTITION_MEDIUM_THRESHOLD
#define MOC_PARTITION_MEDIUM_THRESHOLD 1024
#endif

#ifndef MOC_MIN_PARTITION_SIZE
#define MOC_MIN_PARTITION_SIZE      (256)
#endif

#else

#ifndef MOC_MIN_PARTITION_SIZE
#define MOC_MIN_PARTITION_SIZE      (1024)
#endif

#endif /* __ENABLE_DIGICERT_MEM_PART_MULTI_POOLS__ */

typedef struct memBlock_s
{
    struct memBlock_s*  pNextMemBlock;
    ubyte4              memBlockSize;

} memBlock;

typedef struct
{
    ubyte4              totalMemBlockLength;
    ubyte4              magicNumOffset;

} memBlockHeader;

typedef struct memPartDescr
{
    intBoolean          isMemPartDamaged;

    intBoolean          isMemMutexEnabled;
    RTOS_MUTEX          memMutex;

    ubyte4              memPartitionSize;
    ubyte*              pMemBaseAddress;
    ubyte*              pMemStartAddress;
    ubyte*              pMemEndAddress;

    ubyte8               pPhysicalAddress;    /* optional, allows mapping user-virtual address space to physical address space */
    ubyte8               pKernelAddress;      /* optional, allows mapping user-virtual address space to kernel-virtual address space */

    memBlock            memBlockHead;

} memPartDescr;


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MEM_PART_init(void);
MOC_EXTERN MSTATUS MEM_PART_uninit(void);

MOC_EXTERN MSTATUS MEM_PART_createPartition(memPartDescr **ppRetMemPartition, ubyte *pMemPartBase, usize memPartSize);
MOC_EXTERN MSTATUS MEM_PART_freePartition(memPartDescr **ppFreeMemPartition);

MOC_EXTERN MSTATUS MEM_PART_enableMutexGuard(memPartDescr *pMemPartition);
MOC_EXTERN MSTATUS MEM_PART_assignOtherAddresses(memPartDescr *pMemPartition, ubyte8 pPhysicalAddress, ubyte8 pKernelAddress);
MOC_EXTERN MSTATUS MEM_PART_mapToPhysicalAddress(memPartDescr *pMemPartition, ubyte *pPartitionAddress, ubyte8 *ppRetPhysicalAddress);
MOC_EXTERN MSTATUS MEM_PART_mapToKernelAddress(memPartDescr *pMemPartition, ubyte *pPartitionAddress, ubyte8 *ppRetKernelAddress);

MOC_EXTERN MSTATUS MEM_PART_alloc(memPartDescr *pMemPartition, ubyte4 numBytesToAlloc, void **ppRetNewMemBlock);
MOC_EXTERN MSTATUS MEM_PART_free(memPartDescr *pMemPartition, void **ppFreeMemBlock);

MOC_EXTERN MSTATUS MEM_PART_getBlockLen(void *pPtr, ubyte4 *pRetBlockLen);

/* This function stores the given partition in a location where the DIGI_MALLOC
 * routine will find it. That is, it gives DIGI_MALLOC control of pPartition.
 * If one is already loaded, the function will return an error.
 * Note that this does not build a partition, it only places an existing one at
 * some location where DIGI_MALLOC will control it. You will build the partition,
 * call this Load function to place it into the location.
 * Best practices ar that you build the partition, call Load, then NULL out your
 * variable.
 */
MOC_EXTERN MSTATUS DIGI_LoadPartition (memPartDescr *pPartition);
/* This function retrieves the partition from the location. It will no longer be
 * at that location, DIGI_MALLOC will no longer control it.
 * Note that this function will not free the partition, only return it.
 * This is the opposite of Load, it simply returns control of the partition back
 * to you. The DIGI_MALLOC will no longer have access to the partition.
 * Pass in the address of a memPartDescr pointer, the function will deposit at
 * that address the partition that had been loaded. You will now have control
 * over it.
 * Generally you will build a partition and Load it. When the program is done,
 * you Unload to recover control of the partition, and then clean it up (which
 * will likely involve some sort of destructor).
 */
MOC_EXTERN MSTATUS DIGI_UnloadPartition (memPartDescr **pPartition);

/* This function unloads and frees the global memory partition. Note this 
 * function IS NOT a direct equivalent of calling DIGI_UnloadPartition then 
 * MEM_PART_freePartition. This function will destroy the partition mutex that
 * has been allocated within the parition itself, then unload it from the global
 * memory descriptor */
MOC_EXTERN MSTATUS DIGI_UnloadAndFreeGlobalPartition(void);

#ifdef __ENABLE_DIGICERT_MEM_PART_DEBUG__
MOC_EXTERN MSTATUS MEM_PART_printMemoryPartitions(memPartDescr *pMemPartition, char *pOutFileName);
#endif

/*----------------------------------------------------------------------------*/

#if defined(__DISABLE_DIGICERT_MEM_PART_MUTEX__)

/**
 * @def      MOC_MEM_PART_INIT_CHECK_THREAD_SUPPORT(_status, _pSetupInfo)  
 * @details  This macro will determine if multi thread support is enabled for
 *           memory partition management. If the disable mutex flag is set and
 *           the setup info does not specify single threaded mode when trying to
 *           initialize a static memory partition then that is an error. 
 *
 * @param _status      The MSTATUS value for return from the calling function.
 * @param _pSetupInfo  Pointer to a InitMocanaSetupInfo struct.
 *
 * @par Flags
 * To enable this macro, the following flags \b must be defined
 *   + \c \__ENABLE_DIGICERT_MEM_PART__
 *   + \c \__DISABLE_DIGICERT_MEM_PART_MUTEX__
 */
#define MOC_MEM_PART_INIT_CHECK_THREAD_SUPPORT(_status, _pSetupInfo)           \
    _status = OK;                                                              \
    if ( !(MOC_INIT_FLAG_SINGLE_THREAD & _pSetupInfo->flags) )                 \
      _status = ERR_MEM_PART_NO_THREAD_SUPPORT;

/* Expand to nothing */
#define MOC_MEM_PART_INIT_THREAD_SUPPORT(_status, _pPartition)
    

#else

/* Expand to simply set status OK */
#define MOC_MEM_PART_INIT_CHECK_THREAD_SUPPORT(_status, _pSetupInfo)           \
    _status = OK;  

/**
 * @def      MOC_MEM_PART_INIT_THREAD_SUPPORT(_status, _pPartition) 
 * @details  This macro will report an error if the mutex disable flag is set,
 *           otherwise it will initialize the mutex for the memory partition.
 *
 * @param _status      The MSTATUS value for return from the calling function.
 * @param _pPartition  Pointer to a memory part descriptor
 *
 * @par Flags
 * To enable this macro, the following flags \b must be defined
 *   + \c \__ENABLE_DIGICERT_MEM_PART__
 * To enable this macro, the following flags must \b not be defined
 *   + \c \__DISABLE_DIGICERT_MEM_PART_MUTEX__
 */
#define MOC_MEM_PART_INIT_THREAD_SUPPORT(_status, _pPartition)                 \
    _status = MEM_PART_enableMutexGuard(_pPartition);


#endif /* if defined(__DISABLE_DIGICERT_MEM_PART_MUTEX__) */

/*----------------------------------------------------------------------------*/

/* These macros expand to call init and uninit if enabled, otherwise they expand
 * to do nothing.
 */
#if defined(__ENABLE_DIGICERT_MEM_PART__)

/**
 * @def      MOC_MEM_PART_DECL(_pPartition, _staticMemLoadFlag)
 * @details  This macro will declare variables to be used in initializing
 *           a static memory partition if requested.
 *
 * @param _pPartition         A memPartDescr identifier.
 * @param _staticMemLoadFlag  An identifier for the load flag, which is used
 *                            to identify and attempt recovery from failed
 *                            initialization calls.
 *
 * @par Flags
 * To enable this macro, the following flag \b must be defined
 *   + \c \__ENABLE_DIGICERT_MEM_PART__
 */
#define MOC_MEM_PART_DECL(_pPartition, _staticMemLoadFlag)                     \
    memPartDescr *_pPartition = NULL;                                          \
    ubyte4 _staticMemLoadFlag = 0;

/**
 * @def      MOC_MEM_PART_SET_DONE_FLAG(_staticMemLoadFlag)
 * @details  This macro will set the flag state to 0 .
 *
 * @param _staticMemLoadFlag  An identifier for the load flag, which is used
 *                            to identify and attempt recovery from failed
 *                            initialization calls.
 *
 * @par Flags
 * To enable this macro, the following flag \b must be defined
 *   + \c \__ENABLE_DIGICERT_MEM_PART__
 */
#define MOC_MEM_PART_SET_DONE_FLAG(_staticMemLoadFlag) \
    _staticMemLoadFlag = 0;

/**
 * @def      MOC_MEM_PART_INIT(_status)
 * @details  This macro will initialize the memory partition management. If the
 *           setup information specifies, it will also initialize a static
 *           memory partition
 *
 * @param _status      The MSTATUS value for return from the calling function.
 * @param _pSetupInfo  Pointer to a InitMocanaSetupInfo struct.
 * @param _pPartition  Pointer to allocated buffer to use as a memory partition.
 * @param _flag        Flag which indicates if the rest of the initialization
 *                     code has executed successfully.
 *
 * @par Flags
 * To enable this macro, the following flag \b must be defined
 *   + \c \__ENABLE_DIGICERT_MEM_PART__
 */
#define MOC_MEM_PART_INIT(_status, _pSetupInfo, _pPartition, _flag)            \
    if (NULL != _pSetupInfo && NULL != _pSetupInfo->pStaticMem)                \
    {                                                                          \
      _flag = 0;                                                               \
      _pPartition = NULL;                                                      \
      MOC_MEM_PART_INIT_CHECK_THREAD_SUPPORT(_status, _pSetupInfo)             \
      if (OK != _status)                                                       \
        goto exit;                                                             \
      _status = MEM_PART_createPartition(&(_pPartition),                       \
      _pSetupInfo->pStaticMem,              \
      _pSetupInfo->staticMemSize);          \
      if (OK != _status)                                                       \
        goto exit;                                                             \
      _status = DIGI_LoadPartition(_pPartition);                                \
      if (OK != _status)                                                       \
        goto exit;                                                             \
      MOC_MEM_PART_INIT_THREAD_SUPPORT(_status, _pPartition)                   \
      if (OK != _status)                                                       \
        goto exit;                                                             \
      _pPartition = NULL;                                                      \
      _flag = 1;                                                               \
      _status = MEM_PART_init();                                               \
      if (OK != _status)                                                       \
        goto exit;                                                             \
    }                                                                          \
    else                                                                       \
    {                                                                          \
      _status = MEM_PART_init();                                               \
      if (OK != _status)                                                       \
        goto exit;                                                             \
    }

/**
 * @def      MOC_MEM_PART_INIT_CLEANUP(_pSetupInfo, _pPartition, _flag)
 * @details  This macro will cleanup any allocated memory in the event a
 *           failure occurs before completing the full initialization sequence.
 *
 * @param _pSetupInfo  Pointer to a InitMocanaSetupInfo struct.
 * @param _pPartition  Pointer to allocated buffer to use as a memory partition.
 * @param _flag        Flag which indicates if the rest of the initialization
 *                     code has executed successfully.
 *
 * @par Flags
 * To enable this macro, the following flag \b must be defined
 *   + \c \__ENABLE_DIGICERT_MEM_PART__
 *
 * @note     The return status is ignored for both of these function calls
 *           because if we are executing this code we are already doing cleanup
 *           after an error, there is nothing we can do if these error out as
 *           well so why check. It also preserves the original error code for
 *           the caller.
 */
#define MOC_MEM_PART_INIT_CLEANUP(_pSetupInfo, _pPartition, _flag)             \
    if (NULL != _pSetupInfo && NULL != _pSetupInfo->pStaticMem)                \
    {                                                                          \
      if (0 != _flag)                                                          \
        DIGI_UnloadAndFreeGlobalPartition();                                    \
    }

/**
 * @def      MOC_MEM_PART_UNINIT(_status, _dStatus)
 * @details  This macro will uninitialize the memory partition management.
 *
 * @note     Portions of ths macro code uninitialize pieces associated with a
 *           static memory initialization (all lines using pPartition).  The
 *           result for these calls is not checked because if a static memory
 *           initialization was \b not used then they will certainly return
 *           failure, however this is expected behavior and should not be
 *           propogated back to the caller.  There is still an existing problem
 *           here though, if static memory initialization \b was used then the
 *           calls to DIGI_UnloadPartition and MEM_PART_freePartition are not
 *           checked for return values, masking any possible errors on that
 *           segment of the uninitialization code.
 *
 * @param _status   The \ref MSTATUS value for return from the calling function.
 * @param _dStatus  The temporary placeholder status used to check return values.
 *
 * @par Flags
 * To enable this macro, the following flag \b must be defined
 *   + \c \__ENABLE_DIGICERT_MEM_PART__
 */
#define MOC_MEM_PART_UNINIT(_status, _dStatus)                                 \
    _dStatus = MEM_PART_uninit ();                                             \
    if (OK == _status)                                                         \
      _status = _dStatus;                                                       \
    _dStatus = DIGI_UnloadAndFreeGlobalPartition();                             \
    if (OK == _status)                                                         \
      _status = _dStatus;                                                      \


#else /* defined (__ENABLE_DIGICERT_MEM_PART__) */

#define MOC_MEM_PART_DECL(_pPartition, _staticMemLoadFlag)
#define MOC_MEM_PART_SET_DONE_FLAG(_staticMemLoadFlag)
#define MOC_MEM_PART_INIT(_status, _pSetupInfo, _pPartition, _flag)            \
    _status = ERR_MEM_PART;                                                    \
    if (NULL != _pSetupInfo && NULL != _pSetupInfo->pStaticMem)                \
      goto exit;
#define MOC_MEM_PART_INIT_CLEANUP(_pSetupInfo, _pPartition, _flag)
#define MOC_MEM_PART_UNINIT(_status, _dStatus)

#endif /* defined (__ENABLE_DIGICERT_MEM_PART__) */
#endif /* __MEMORY_PARTITION_HEADER__ */
