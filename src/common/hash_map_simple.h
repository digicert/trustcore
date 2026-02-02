/*
 * hash_map_simple.h
 *
 * Simple Hash Map
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

#ifndef __HASH_MAP_SIMPLE_HEADER__
#define __HASH_MAP_SIMPLE_HEADER__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mem_part.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct HashMapElement
{
    void *pKey;
    void *pValue;
    
    struct HashMapElement *pNextElement;
    
} HashMapElement;

typedef ubyte4 (*HashMethod)(void *pKey);

typedef struct HashMap
{
    ubyte4 size;
    HashMethod hashMethod;
    HashMapElement *pElements;
    /* For alternate memory pool for hash map allocations */
    memPartDescr *pMemPart;

} HashMap;

/** 
 * @brief    Creates a simple hash map of (key, value) pairs.
 * @details  Creates a simple hash map of (key, value) pairs. Both keys and values may consist of
 *           arbitrary structures and the hash map will store pointers to those structures.
 *           Memory is allocated for the hash table so be sure to call \c deleteHashMap
 *           to delete the hash table and free all allocated memory.
 *
 * @param ppNewHashMap      Location that will receive a pointer to the newly allocated hash map.
 * @param size              The size of the internal hash table array. This is not required to be
 *                          a power of 2 but for performance that is recommended.
 * @param hashMethod        A function pointer for a user specified callback method that will perform
 *                          the hashing step of converting a key to a 32-bit value. The hash values
 *                          returned must be from [0, ... , size - 1] for the \c size specified above.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS createHashMap(HashMap **ppNewHashMap, ubyte4 size, HashMethod hashMethod);


/** 
 * @brief    Creates a simple hash map of (key, value) pairs using memory from a static buffer.
 * @details  Creates a simple hash map of (key, value) pairs using memory from a static buffer. 
 *           Both keys and values may consist of
 *           arbitrary structures and the hash map will store pointers to those structures.
 *           Memory is allocated for the hash table so be sure to call \c deleteHashMap
 *           to delete the hash table and free all allocated memory.
 *
 * @param ppNewHashMap      Location that will receive a pointer to the newly allocated hash map.
 * @param size              The size of the internal hash table array. This is not required to be
 *                          a power of 2 but for performance that is recommended.
 * @param hashMethod        A function pointer for a user specified callback method that will perform
 *                          the hashing step of converting a key to a 32-bit value. The hash values
 *                          returned must be from [0, ... , size - 1] for the \c size specified above.
 * @param pMemBuffer        Static buffer of memory used for the hash table allocations.
 * @param bufferLen         The length of \c pMemBuffer in bytes. Must be large enough for the
 *                          anticipated hash table size.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS createHashMapStaticMem(HashMap **ppNewHashMap, ubyte4 size, HashMethod hashMethod, ubyte *pMemBuffer, ubyte4 bufferLen);


/** 
 * @brief    Adds a (key, value) pair to a simple hash map.
 * @details  Adds a (key, value) pair to a simple hash map.
 *
 * @param pHashMap    Pointer to the hash map to be potentially modified.
 * @param pKey        Pointer to the key to be added.
 * @param pValue      Pointer to the value associated with that key.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS addKey(HashMap *pHashMap, void *pKey, void *pValue);

/** 
 * @brief    Gets a (key, value) pair from a simple hash map.
 * @details  Gets a (key, value) pair from a simple hash map.
 *
 * @param pHashMap    Pointer to the hash map to be searched.
 * @param pKey        Pointer to the key to be found.
 * @param ppRetValue  Contents will be set to the pointer to the value
 *                    associated with that key if it is found. If it is not
 *                    found the contents will be set to \c NULL. 
 *
 * @return     \c OK (0) if successful and the key is found in the hash map.
 *             \c ERR_HASH_MAP_KEY_NOT_FOUND (-13723) is returned if the
 *             key is not in the hash map.
 */
MOC_EXTERN MSTATUS getKey(HashMap *pHashMap, void *pKey, void **ppRetValue);

/** 
 * @brief    Deletes a (key, value) pair from a simple hash map.
 * @details  Deletes a (key, value) pair from a simple hash map.
 *
 * @param pHashMap    Pointer to the hash map to be searched.
 * @param pKey        Pointer to the key to be deleted.
 * @param ppRetValue  Contents will be set to the pointer to the value
 *                    associated with that key if it is found and deleted. If it is not
 *                    found the contents will be set to \c NULL. 
 *
 * @return     \c OK (0) if successful and the key is found in the hash map.
 *             \c ERR_HASH_MAP_KEY_NOT_FOUND (-13723) is returned if the
 *             key is not in the hash map.
 */
MOC_EXTERN MSTATUS deleteKey(HashMap *pHashMap, void *pKey, void **ppRetValue);

/** 
 * @brief    Deletes a simple hash map and frees all allocated memory.
 * @details  Deletes a simple hash map and frees all allocated memory including that for all
 *           elements within the hash map.
 *
 * @param ppHashMap   Location of the pointer to the hash map to be deleted.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS deleteHashMap(HashMap **ppHashMap);

/** 
 * @brief    Iterates through a hashmap retrieving each key value pair.
 * @details  Iterates through a hashmap retrieving each key value pair.
 *
 * @param pHashMap   Pointer the hashmap
 * @param pLastIndex Contents should be set to the last index visited. This should be 0 to begin iteration.
 * @param ppLastKey  Contents should be set to the last key visited. This should be NULL to begin iteration.
 *                   After the call the contents will be set to the next key.
 * @param ppLastValue After the call the contents will be set to the next value.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS iterateHashMap(HashMap *pHashMap, ubyte4 *pLastIndex, void **ppLastKey, void **ppLastValue);

/** 
 * @brief    Prints out all the key value pairs in a hash map.
 * @details  Prints out all the key value pairs in a hash map.
 *
 * @param pHashMap   Pointer to the input hash map
 *
 */
MOC_EXTERN void printHashMap(HashMap *pHashMap);

/** 
 * @brief    Allocates memory for potential hash map keys or values.
 * @details  Allocates memory for potential hash map keys or values. If the
 *           hash map uses a static buffer it will allocate from there. Be
 *           sure to clean up this memory by calling \c freeMemBlock.
 *
 * @param pHashMap   Pointer to the hash map
 * @param size       The number of bytes to allocate
 * @param ppNewPtr   Location that will receive a pointer to the newly allocated data
 *
 */
MOC_EXTERN MSTATUS allocateMemBlock(HashMap *pHashMap, ubyte4 size, void **ppNewPtr);

/** 
 * @brief    Frees memory allocated for hash map keys or values.
 * @details  Frees memory allocated for hash map keys or values.
 *
 * @param pHashMap   Pointer to the hash map
 * @param ppPtr      Location of the pointer that will be freed
 *
 */
MOC_EXTERN MSTATUS freeMemBlock(HashMap *pHashMap, void **ppPtr);


#ifdef __cplusplus
}
#endif

#endif /* __HASH_MAP_SIMPLE_HEADER__ */

