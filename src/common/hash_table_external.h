/*
 * hash_table_external.h
 *
 * Hash Table Connector for external hash table implementations
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

#ifndef __HASH_TABLE_EXTERNAL_HEADER__
#define __HASH_TABLE_EXTERNAL_HEADER__

#include "../common/hash_table.h"

#ifdef __cplusplus
extern "C" {
#endif

/** 
 * @brief    Creates an external hash table of pointer values.
 * @details  Creates an external hash table of pointer values. This is a table of (key, pointer) pairs where pointer is 
 *           an arbitrary type (ie a \c void *) that can point to any application structure. 
 *           Memory is allocated for the hash table so be sure to call \c HASH_TABLE_EXT_removePtrsTable
 *           to delete the hash table and free all allocated memory.
 *
 * @param ppRetHashTable    Location that will receive a pointer to the newly allocated hash table.
 * @param hashTableSizeMask 32-bit mask that will be applied to a hash value to create the array index
 *                          for where the element will be located in the hash table array. This mask
 *                          must have its leftmost bits 0 and right most bits all 1 and the hash table array
 *                          is neccessarily a power of 2 in size based on the number of bits set in this mask.
 *                          For example a mask of 0x7f will ensuere a 128 element table array is created.
 * @param pHashCookie       (Optional). Data in an arbitrary structure that may be used to identify the hash table.
 * @param keyLen            The length of hash table keys in bytes. Keys may be of an arbitary structure but
 *                          must have a fixed length.
 * @param initValue         The initial hash value that may be required by the external hashing method. 
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS HASH_TABLE_EXT_createPtrsTable(hashTableOfPtrs **ppRetHashTable, ubyte4 hashTableSizeMask, void *pHashCookie,
                                                  ubyte4 keyLen, ubyte4 initValue);

/** 
 * @brief    Deletes and frees memory associated with an external hash table of pointers.
 * @details  Deletes and frees memory associated with an external hash table of pointers. 
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
MOC_EXTERN MSTATUS HASH_TABLE_EXT_removePtrsTable(hashTableOfPtrs *pFreeHashTable, void **ppRetHashCookie);

/** 
 * @brief    Adds a new (key, pointer) pair to an external hash table.
 * @details  Adds a new (key, pointer) pair to an external hash table.
 *
 * @param pHashTable   Pointer to the hash table to be potentially modified.
 * @param pKey         Pointer to the key as an arbitrary structure. It's size (ie length in bytes)
 *                     must be the key length specified upon table creation.
 * @param pAppData     The application data pointer to be added to the table.
 *   
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS HASH_TABLE_EXT_addPtr(hashTableOfPtrs *pHashTable, void *pKey, void *pAppData);

/** 
 * @brief    Deletes a (key, pointer) pair from the external hash table.
 * @details  Deletes a (key, pointer) pair from the external hash table.
 *           Optionally, the data pointed to by the pointer can be tested for equality to data that is input, via a user specified
 *           function pointer callback. In that case the (key, pointer) pair is only deleted if a match is found.
 *
 * @param pHashTable             Pointer to the hash table to be potentially modified.
 * @param pKey                   Pointer to the key as an arbitrary structure. It's size (ie length in bytes)
 *                               must be the key length specified upon table creation.
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
MOC_EXTERN MSTATUS HASH_TABLE_EXT_deletePtr(hashTableOfPtrs *pHashTable, void *pKey, void *pTestData, funcPtrExtraMatchTest pFuncPtrExtraMatchTest, void **ppRetAppDataToDelete, intBoolean *pRetFoundHashValue);

/** 
 * @brief    Finds a (key, pointer) pair in an external hash table.
 * @details  Finds a (key, pointer) pair in an external hash table.
 *           Optionally, the data pointed to by the pointer can be tested for equality to data that is input, via a user specified
 *           function pointer callback. In that case the method indicates a found pair only if the callback specifies a true match.
 *
 * @param pHashTable             Pointer to the hash table to be looked in.
 * @param pKey                   Pointer to the key as an arbitrary structure. It's size (ie length in bytes)
 *                               must be the key length specified upon table creation.
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
MOC_EXTERN MSTATUS HASH_TABLE_EXT_findPtr(hashTableOfPtrs *pHashTable, void *pKey, void *pTestData, funcPtrExtraMatchTest pFuncPtrExtraMatchTest, void **ppRetAppData, intBoolean *pRetFoundHashValue);

/** 
 * @brief    Traverses all the elements of the external hash table and applies a user specified method to each pointer found in the table.
 * @details  Traverses all the elements of the external hash table and applies a user specified method to each pointer found in the table.
 *
 * @param pHashTable            Pointer to the hash table to be traversed.
 * @param funcPtrTraverseTable  Function pointer that will be applied to every pointer found in the table.
 *   
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS HASH_TABLE_EXT_traversePtrTable(hashTableOfPtrs *pHashTable, MSTATUS(*funcPtrTraverseTable)(void * /* pAppData */));

/** 
 * @brief    Iterates through elements of the external hash table.
 * @details  Iterates through elements of the external hash table with a beginning index. 
 *           Each call to this method will return the application pointer value from the next found (key, pointer) pair
 *           and update the currently specified key and index to that one. This method will return NULL
 *           once it has gotten to the final element in the table. 
 *
 * @param pHashTable     Pointer to the hash table to be traversed.
 * @param ppKeyCookie    The contents are the last visited key in the external hash table. This will be updated
 *                       to the current visited key. To begin your iteration the contents should be NULL.
 * @param pIndex         The contents are the last visited index in the external hash table. This will be updated
 *                       to the current visited index. To begin your iteration the contents should be 0.
 *   
 * @return     The application pointer, ie the pointer from the next found (key, pointer) pair, is returned.
 *             If NULL is returned then we are at the end of the hash table, ie there is no next found element.
 */
MOC_EXTERN void * HASH_TABLE_EXT_iteratePtrTable(hashTableOfPtrs *pHashTable, void **ppKeyCookie, ubyte4 *pIndex);

/** 
 * @brief    Traverses all the elements of the external hash table and applies a user specified method to each pointer found in the table.
 * @details  Traverses all the elements of the external hash table and applies a user specified method to each pointer found in the table. This
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
MOC_EXTERN MSTATUS HASH_TABLE_EXT_traversePtrTableExt(hashTableOfPtrs *pHashTable, void *pCookie,
                   MSTATUS(*funcPtrTraverseTableExt)(void *pAppData, void *pCookie ));

#ifdef __cplusplus
}
#endif

#endif /* __HASH_TABLE_EXTERNAL_HEADER__ */
