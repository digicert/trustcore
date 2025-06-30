/*
 * hash_table.h
 *
 * Hash Table Factory Header
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

#ifndef __HASH_TABLE_HEADER__
#define __HASH_TABLE_HEADER__

#define SET_NEXT_ELEM( p, n)    { if (p!=n) p->pNextElement = n; }

#ifdef __cplusplus
extern "C" {
#endif

/*------------------------------------------------------------------*/

typedef struct hashTablePtrElement
{
    void*                           pAppData;       /* reference by pointer */
    ubyte4                          hashValue;

    struct hashTablePtrElement*     pNextElement;

} hashTablePtrElement;



typedef MSTATUS ((*funcPtrAllocHashPtrElement)(void *, hashTablePtrElement **));
typedef MSTATUS ((*funcPtrFreeHashPtrElement)(void *, hashTablePtrElement *));

typedef struct hashTableOfPtrs
{
    ubyte4                          hashTableSizeMask;
    void*                           pHashCookie;

    /* allows for pre-allocated elements */
    funcPtrAllocHashPtrElement      pFuncAllocElement;
    funcPtrFreeHashPtrElement       pFuncFreeElement;

    hashTablePtrElement*            pHashTableArray[1];

#ifdef __ENABLE_MOCANA_DPDK_CONNECTOR__
    void*                           pExternalHash;
#endif

} hashTableOfPtrs;


/*------------------------------------------------------------------*/

typedef struct hashTableIndexElement
{
    ubyte4                          appDataIndex;   /* note: on 64-bit processors, 'ubyte4' is smaller than a 'void*' */
    ubyte4                          hashValue;

    struct hashTableIndexElement*   pNextElement;

} hashTableIndexElement;

typedef MSTATUS ((*funcPtrAllocElement)(void *, hashTableIndexElement **));
typedef MSTATUS ((*funcPtrFreeElement)(void *, hashTableIndexElement **));
typedef MSTATUS ((*funcPtrExtraMatchTest)(void *, void *, intBoolean *));

typedef struct hashTableIndices
{
    ubyte4                  hashTableSizeMask;
    void*                   pHashCookie;

    /* allows for pre-allocated elements */
    funcPtrAllocElement     pFuncAllocElement;
    funcPtrFreeElement      pFuncFreeElement;

    hashTableIndexElement*  pHashTableArray[1]; /* note: array size should be non-zero to avoid compiler error */

} hashTableIndices;


/*------------------------------------------------------------------*/

/** 
 * @brief    Creates a hash table of index values.
 * @details  Creates a hash table of index values. This is a table of (key, index) pairs where index is a 32-bit
 *           value. Memory is allocated for the hash table so be sure to call \c HASH_TABLE_removeIndiceTable
 *           to delete the hash table and free all allocated memory.
 *
 * @param ppRetHashTable    Location that will receive a pointer to the newly allocated hash table.
 * @param hashTableSizeMask 32-bit mask that will be applied to a hash value to create the array index
 *                          for where the element will be located in the hash table array. This mask
 *                          must have its leftmost bits 0 and right most bits all 1 and the hash table array
 *                          is neccessarily a power of 2 in size based on the number of bits set in this mask.
 *                          For example a mask of 0x7f will ensuere a 128 element table array is created.
 * @param pHashCookie       (Optional). Data in an arbitrary structure that may be needed or used by
 *                          the user specified element allocation and free methods.
 * @param pFuncAllocElement Function pointer to a method that will allocate a new \c hashTableIndexElement. This user specified 
 *                          method must be of the \c funcPtrAllocElement form and may take in an optional cookie. 
 * @param pFuncFreeElement  Function pointer to a method that will free a \c hashTableIndexElement. This user specified 
 *                          method must be of the \c funcPtrFreeElement form and may take in an optional cookie. 
 *   
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS HASH_TABLE_createIndiceTable(hashTableIndices **ppRetHashTable, ubyte4 hashTableSizeMask, void *pHashCookie, funcPtrAllocElement pFuncAllocElement, funcPtrFreeElement pFuncFreeElement);

/** 
 * @brief    Clears all the elements of the hash table and optionally applies a user specified method to each index found in the table.
 * @details  Clears all the elements of the hash table and optionally applies a user specified method to each index found in the table.
 *           This method does not free the actual hash table itself.
 *
 * @param pClearHashTable    Pointer to the hash table to be cleared.
 * @param pClearCtx          (Optional) Data that may be needed by the user specified method applied to each index found in the table.
 * @param funcPtrClearIndex  (Optional) Function pointer that if provided, will be applied to each index found in the table. 
 *   
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS HASH_TABLE_clearIndiceTable(hashTableIndices *pClearHashTable, void *pClearCtx, MSTATUS(*funcPtrClearIndex)(void * /* pClearCtx */, ubyte4 /* appDataIndex */));

/** 
 * @brief    Deletes and frees memory associated with a hash table of indices.
 * @details  Deletes and frees memory associated with a hash table of indices. This will internally clear all elements of the table
 *           too (ie there is no need to call \c HASH_TABLE_clearIndiceTable first unless you need to apply a function pointer to each index).
 *
 * @param pFreeHashTable    Pointer to the hash table to be freed.
 * @param ppRetHashCookie   (Optional) If provided then the contents will be set to point
 *                          to the original cookie provided upon the creation of the hash table.
 *   
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS HASH_TABLE_removeIndiceTable(hashTableIndices *pFreeHashTable, void **ppRetHashCookie);

/** 
 * @brief    Adds a new (key, index) pair to the hash table.
 * @details  Adds a new (key, index) pair to the hash table. The key must have already been hashed to a 32-bit hash value.
 *
 * @param pHashTable        Pointer to the hash table to be potentially modified.
 * @param hashValue         The 32-bit hash value of the key.
 * @param appDataIndex      The application data index to be added to the table.
 *   
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS HASH_TABLE_addIndex(hashTableIndices *pHashTable, ubyte4 hashValue, ubyte4 appDataIndex);

/** 
 * @brief    Deletes a (key, index) pair from the hash table.
 * @details  Deletes a (key, index) pair from the hash table. The key must have already been hashed to a 32-bit hash value.
 *
 * @param pHashTable         Pointer to the hash table to be potentially modified.
 * @param hashValue          The 32-bit hash value of the key.
 * @param testDataIndex      The index that should be associated with that key.
 * @param pRetFoundHashValue Contents will be set to \c TRUE if the (key, index) pair was found and deleted.
 *                           If the (key, index) pair was not found the contents will be set to \c FALSE.
 *   
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS HASH_TABLE_deleteIndex(hashTableIndices *pHashTable, ubyte4 hashValue, ubyte4 testDataIndex, intBoolean *pRetFoundHashValue);

/** 
 * @brief    Finds a (key, index) pair from the hash table.
 * @details  Finds a (key, index) pair from the hash table. The key must have already been hashed to a 32-bit hash value.
 *
 * @param pHashTable         Pointer to the hash table to be looked in.
 * @param hashValue          The 32-bit hash value of the key.
 * @param testDataIndex      The index that should be associated with that key.
 * @param pRetFoundHashValue Contents will be set to \c TRUE if the (key, index) pair was found.
 *                           If the (key, index) pair was not found the contents will be set to \c FALSE.
 *   
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS HASH_TABLE_findIndex(hashTableIndices *pHashTable, ubyte4 hashValue, ubyte4 testDataIndex, intBoolean *pRetFoundHashValue);

/*-----------------------------------------------------------------------------------------------------------------------------------------*/

/** 
 * @brief    Creates a hash table of pointer values.
 * @details  Creates a hash table of pointer values. This is a table of (key, pointer) pairs where pointer is 
 *           an arbitrary type (ie a \c void *) that can point to any application structure. 
 *           Memory is allocated for the hash table so be sure to call \c HASH_TABLE_removePtrsTable
 *           to delete the hash table and free all allocated memory.
 *
 * @param ppRetHashTable    Location that will receive a pointer to the newly allocated hash table.
 * @param hashTableSizeMask 32-bit mask that will be applied to a hash value to create the array index
 *                          for where the element will be located in the hash table array. This mask
 *                          must have its leftmost bits 0 and right most bits all 1 and the hash table array
 *                          is neccessarily a power of 2 in size based on the number of bits set in this mask.
 *                          For example a mask of 0x7f will ensure a 128 element table array is created.
 * @param pHashCookie       (Optional). Data in an arbitrary structure that may be needed or used by
 *                          the user specified element allocation and free methods.
 * @param pFuncPtrAllocHashPtrElement Function pointer to a method that will allocate a new \c hashTablePtrElement. This user specified 
 *                                    method must be of the \c funcPtrAllocHashPtrElement form and may take in an optional cookie. 
 * @param pFuncPtrFreeHashPtrElement  Function pointer to a method that will free a \c hashTablePtrElement. This user specified 
 *                                    method must be of the \c funcPtrFreeHashPtrElement form and may take in an optional cookie. 
 *   
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS HASH_TABLE_createPtrsTable(hashTableOfPtrs **ppRetHashTable, ubyte4 hashTableSizeMask, void *pHashCookie,
                                              funcPtrAllocHashPtrElement pFuncPtrAllocHashPtrElement, funcPtrFreeHashPtrElement pFuncPtrFreeHashPtrElement);
/** 
 * @brief    Deletes and frees memory associated with a hash table of pointers.
 * @details  Deletes and frees memory associated with a hash table of pointers. 
 *           This will internally free all elements of the table too before freeing the table itself.
 *
 * @param pFreeHashTable    Pointer to the hash table to be freed.
 * @param ppRetHashCookie   (Optional) If provided then the contents will be set to point
 *                          to the original cookie provided upon the creation of the hash table.
 *   
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS HASH_TABLE_removePtrsTable(hashTableOfPtrs *pFreeHashTable, void **ppRetHashCookie);

/** 
 * @brief    Adds a new (key, pointer) pair to the hash table.
 * @details  Adds a new (key, pointer) pair to the hash table. The key must have already been hashed to a 32-bit hash value.
 *
 * @param pHashTable        Pointer to the hash table to be potentially modified.
 * @param hashValue         The 32-bit hash value of the key.
 * @param pAppData          The application data pointer to be added to the table.
 *   
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS HASH_TABLE_addPtr(hashTableOfPtrs *pHashTable, ubyte4 hashValue, void *pAppData);

/** 
 * @brief    Deletes a (key, pointer) pair from the hash table.
 * @details  Deletes a (key, pointer) pair from the hash table. The key must have already been hashed to a 32-bit hash value.
 *           Optionally, the data pointed to by the pointer can be tested for equality to data that is input, via a user specified
 *           function pointer callback. In that case the (key, pointer) pair is only deleted if a match is found.
 *
 * @param pHashTable             Pointer to the hash table to be potentially modified.
 * @param hashValue              The 32-bit hash value of the key.
 * @param pTestData              (Optional) Pointer to data that will be tested for equality with the data pointed to by
 *                               the pointer found in the (key, pointer) pair. This parameter is required if the callback
 *                               method \c pFuncPtrExtraMatchTest is non-NULL.
 * @param pFuncPtrExtraMatchTest (Optional) Function pointer to a method that will test whether the the data pointed to by 
 *                               \c pTestData is the same as the data pointed to in the found (key, pointer) pair. This pair
 *                               is only deleted if this method determines that a match was found.
 * @param ppRetAppDataToDelete   Contents will be set to the pointer in the the (key, pointer) pair to be deleted if it is found.
 *                               This is required irregardless of whether \c pFuncPtrExtraMatchTest is specified.
 * @param pRetFoundHashValue     Contents will be set to \c TRUE if the (key, pointer) pair was found and deleted.
 *                               If the (key, pointer) pair was not found the contents will be set to \c FALSE.
 *   
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS HASH_TABLE_deletePtr(hashTableOfPtrs *pHashTable, ubyte4 hashValue, void *pTestData, funcPtrExtraMatchTest pFuncPtrExtraMatchTest, void **ppRetAppDataToDelete, intBoolean *pRetFoundHashValue);

/** 
 * @brief    Finds a (key, pointer) pair in the hash table.
 * @details  Finds a (key, pointer) pair in the hash table. The key must have already been hashed to a 32-bit hash value.
 *           Optionally, the data pointed to by the pointer can be tested for equality to data that is input, via a user specified
 *           function pointer callback. In that case the method indicates a found pair only if the callback specifies a true match.
 *
 * @param pHashTable             Pointer to the hash table to be looked in.
 * @param hashValue              The 32-bit hash value of the key.
 * @param pTestData              (Optional) Pointer to data that will be tested for equality with the data pointed to by
 *                               the pointer found in the (key, pointer) pair. This parameter is required if the callback
 *                               method \c pFuncPtrExtraMatchTest is non-NULL.
 * @param pFuncPtrExtraMatchTest (Optional) Function pointer to a method that will test whether the the data pointed to by 
 *                               \c pTestData is the same as the data pointed to in the found (key, pointer) pair.
 * @param ppRetAppData           Contents will be set to the pointer in the the (key, pointer) pair if it is found.
 *                               This is required irregardless of whether \c pFuncPtrExtraMatchTest is specified.
 * @param pRetFoundHashValue     Contents will be set to \c TRUE if the (key, pointer) pair was found and if the optionally
 *                               specified \c pFuncPtrExtraMatchTest found a match. Otherwise the contents will be set to \c FALSE.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS HASH_TABLE_findPtr(hashTableOfPtrs *pHashTable, ubyte4 hashValue, void *pTestData, funcPtrExtraMatchTest pFuncPtrExtraMatchTest, void **ppRetAppData, intBoolean *pRetFoundHashValue);

/** 
 * @brief    Traverses all the elements of the hash table and applies a user specified method to each pointer found in the table.
 * @details  Traverses all the elements of the hash table and applies a user specified method to each pointer found in the table.
 *
 * @param pHashTable            Pointer to the hash table to be traversed.
 * @param funcPtrTraverseTable  Function pointer that will be applied to every pointer found in the table.
 *   
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS HASH_TABLE_traversePtrTable(hashTableOfPtrs *pHashTable, MSTATUS(*funcPtrTraverseTable)(void * /* pAppData */));

/** 
 * @brief    Iterates through elements of the hash table.
 * @details  Iterates through elements of the hash table with a beginning index and bucket cookie. 
 *           Each call to this method will return the application pointer value from the next found (key, pointer) pair
 *           and update the currently specified index and/or bucket cookie to that one. This method will return NULL
 *           once it has gotten to the final element in the table. 
 *
 * @param pHashTable     Pointer to the hash table to be traversed.
 * @param ppBucketCookie The location of the pointer to the previous bucket, ie the (key, pointer) element that
 *                       was last visited. This pointer will then be updated to the current bucket. To begin
 *                       your iteration this pointer, ie the contents of \c pBucketCookie, should be \c NULL.
 *                       
 * @param pIndex         The contents are the last visited index in the hash table array. This will be updated
 *                       to the current visited index (which may be the same for indices with multiple buckets).       
 *                       To begin your iteration the contents should be 0.
 *   
 * @return     The application pointer, ie the pointer from the next found (key, pointer) pair, is returned.
 *             If NULL is returned then we are at the end of the hash table, ie there is no next found element.
 */
MOC_EXTERN void * HASH_TABLE_iteratePtrTable(hashTableOfPtrs *pHashTable, void **ppBucketCookie, ubyte4 *pIndex);

/** 
 * @brief    Traverses all the elements of the hash table and applies a user specified method to each pointer found in the table.
 * @details  Traverses all the elements of the hash table and applies a user specified method to each pointer found in the table. This
 *           method also allows for a optional cookie data to be passed into your user specified method.
 *
 * @param pHashTable              Pointer to the hash table to be traversed.
 * @param pCookie                 Pointer to optional cookie data that may be required by your \c funcPtrTraverseTableExt method.
 * @param funcPtrTraverseTableExt Function pointer that will be applied to every pointer found in the table.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS HASH_TABLE_traversePtrTableExt(hashTableOfPtrs *pHashTable, void *pCookie,
                   MSTATUS(*funcPtrTraverseTableExt)(void *pAppData, void *pCookie ));

#ifdef __cplusplus
}
#endif

#endif /* __HASH_TABLE_HEADER__ */

