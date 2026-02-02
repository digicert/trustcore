/*
 * certobj.h
 *
 * Declarations and definitions for cert and request objects.
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../../crypto/certops.h"

#ifndef __CERT_OBJECT_HEADER__
#define __CERT_OBJECT_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#define MOC_CERT_OBJ_TYPE_CERT      1
#define MOC_CERT_OBJ_TYPE_REQUEST   2

/* If someonbe needs to allocate memory in addition to the memory allocated
 * during creation, and that memory must belong to the object, store it in this
 * struct.
 * The object will keep this link list of memory alive until the object is freed.
 * The flag is whatever the caller passed in, but the good programmer will limit
 * the possible values of the flag to the #defines that begin MOC_CERT_OBJ_MEM_.
 */
typedef struct MObjectMemory
{
  ubyte4                 flag;
  void                  *pBuffer;
  ubyte4                 bufferSize;
  struct MObjectMemory  *pNext;
} MObjectMemory;

/* The pExtArray is the OfElement for the Extensions in a Request. The extIndex
 * is the index inside the Attributes of the Extensions.
 * If this holds a cert, the fields are ignored. If this is a request and there
 * are no Extensions (no ExtensionRequest Attribute), then ignore extIndex. If
 * you are performing an operation on attributes, and you need to know which
 * attribute to skip, look at pExtArray and extIndex. If pExtArray is NULL, build
 * it by calling MDecodeExtensionRequest. If, after that call th pExtArray is
 * NULL, then you know there are no extensions.
 */
typedef struct
{
  ubyte4          type;
  ubyte          *pDer;
  ubyte4          derLen;
  MAsn1Element   *pArray;
  MAsn1Element   *pExtArray;
  ubyte4          extIndex;
  MObjectMemory  *pObjMem;
} MCertOrRequestObject;

/* Coordinate these values with parsereq.c and PKCS10_parseCertRequest.
 */
#define MOC_REQUEST_ARRAY_INDEX_TBS        1
#define MOC_REQUEST_ARRAY_INDEX_NAME       3
#define MOC_REQUEST_ARRAY_INDEX_KEY        8
#define MOC_REQUEST_ARRAY_INDEX_KEY_OID    10
#define MOC_REQUEST_ARRAY_INDEX_ATTR       13
#define MOC_REQUEST_ARRAY_INDEX_EXT        13
#define MOC_REQUEST_ARRAY_INDEX_SIG_ALGID  17
#define MOC_REQUEST_ARRAY_INDEX_SIG        18

#define MOC_CERT_ARRAY_INDEX_SUBJNAME           13
#define MOC_CERT_ARRAY_INDEX_ISSNAME            5
#define MOC_CERT_ARRAY_INDEX_EXT                25
#define MOC_CERT_ARRAY_INDEX_KEY                18
#define MOC_CERT_ARRAY_INDEX_KEY_OID            20

#define MOC_CERT_ARRAY_INDEX_TBS                1
#define MOC_CERT_ARRAY_INDEX_SIGNATURE          31
#define MOC_CERT_ARRAY_INDEX_SIG_ALG_ID_SIGNED  4
#define MOC_CERT_ARRAY_INDEX_SIG_ALG_ID         30
#define MOC_CERT_ARRAY_INDEX_NOT_BEFORE         11
#define MOC_CERT_ARRAY_INDEX_NOT_AFTER          12
#define MOC_CERT_ARRAY_INDEX_SERIAL_NUM         3
#define MOC_CERT_ARRAY_INDEX_ISSUER_UNIQUE      23
#define MOC_CERT_ARRAY_INDEX_SUBJ_UNIQUE        24

/* Create the object.
 * <p>This allocates space for the object, then sets the fields. The type is once
 * of the MOC_CERT_OBJ_ flags.
 * <p>The caller passes in the address of the Element array. The function will
 * expect to find an array at that address. If so, it will copy a reference to
 * the pointer, then deposit a NULL at the given address. This is how the object
 * will take control of the array.
 * <p>The caller also passes in the address where the function will find the DER
 * encoding that is the cert or request. This is the data that is used to build
 * the Element array. The Element array points to locations inside the encoding,
 * so if the Element array is to remain alive over function calls, so must the
 * actual encoding. The function will copy the address of the actual data, then
 * set *ppDer to NULL, which is how it takes ownership.
 */
MSTATUS MCreateCertObj (
  ubyte4 type,
  ubyte **ppDer,
  ubyte4 derLen,
  MAsn1Element **ppArray,
  MCertOrRequestObject **ppNewObj,
  struct vlong **ppVlongQueue
  );

/* Free any memory allocated for the cert object.
 */
MSTATUS MFreeCertObj (
  MCertOrRequestObject **ppObj,
  struct vlong **ppVlongQueue
  );

/* Load the given memory into the object.
 * The CertOrRequestObj contains a link list of structs containing memory. This
 * function will build a new struct (MObjectMemory), set the fields, place it at
 * the front of the link list, and set *ppBuffer to NULL (to indicate that the
 * caller no longer possesses the memory.
 * The data will be stored with the flag you pass in. There are several flags
 * defined: MOC_CERT_OBJ_MEM_.
 * Later on, you can call the MGetMemory function to get that data again.
 * You can set flag to 0, but that really means the entry has no flag. Later on,
 * a search for flag of 0 will yield nothing.
 * You should add only one entry per flag value, but this function will not check
 * for duplications.
 */
MSTATUS MLoadMemoryIntoCertObject (
  MCertOrRequestObject *pObj,
  ubyte4 flag,
  void **ppBuffer,
  ubyte4 bufferSize
  );

#define MOC_CERT_OBJ_MEM_ISSUER_SERIAL      1
#define MOC_CERT_OBJ_MEM_AUTH_KEY_ID        2
#define MOC_CERT_OBJ_MEM_SUBJ_KEY_ID        3
#define MOC_CERT_OBJ_MEM_BASIC_CONSTRAINTS  4
#define MOC_CERT_OBJ_MEM_KEY_USAGE          5
#define MOC_CERT_OBJ_MEM_TEMPLATE_NAME      6

/** Get the memory buffer associated with the given flag out of the cert object.
 * If there is no buffer associated with that flag, return ERR_NOT_FOUND.
 * The memory returned still belongs to the object, do not free or alter it.
 * Note that a flag of 0 is meaningless. If you pass in 0 for flag, the function
 * will return no entry, even if some entry has the flag 0. An entry with flag 0
 * means the entry has no flag. A search for an entry with flag 0 means search
 * for the entry with flag 0, but no entry has flag 0, because each entry has a
 * non-zero flag or no flag.
 * This function will return the first entry it finds with the flag. If there are
 * more entries with that flag, they will be ignored.
 */
MSTATUS MGetMemoryInfoCertObject (
  MCertOrRequestObject *pObj,
  ubyte4 flag,
  void **ppBuffer,
  ubyte4 *pBufferLen
  );

/* Either get the count of the number of Elements in an OF, or get the Element
 * for a particular index.
 * <p>The caller passes in an OfElement. This is the MAsn1Element that is the OF
 * (not the contents of the OF, but the OF itself).
 * <p>If pCount is not NULL, get the count. If it is NULL, get the Element at
 * index. If there is no Element at the index, set *ppElement to NULL and return
 * ERR_INDEX_OOB.
 * <p>If pCount is not NULL, the index and pElement args are ignored.
 */
MSTATUS MGetCountOrEntryByIndex (
  MAsn1Element *pOfElement,
  ubyte4 *pCount,
  ubyte4 index,
  MAsn1Element **ppElement
  );

/* Code common to most (if not all) NameTypes, and some attributes. To decode,
 * just check the OID and point to the V of the TLV of the encoded value.
 */
MSTATUS MGetSimpleValue (
  MGetAttributeData *pGetData,
  ubyte *pOid,
  ubyte4 oidLen
  );

#define MOC_WHICH_LIST_REQ_NAME        1
#define MOC_WHICH_LIST_REQ_ATTR        2
#define MOC_WHICH_LIST_REQ_EXT         3
#define MOC_WHICH_LIST_CERT_SUBJNAME   4
#define MOC_WHICH_LIST_CERT_ISSNAME    5
#define MOC_WHICH_LIST_CERT_EXT        6

/* Decode the ExtensionRequest Attribute inside a request.
 * <p>The function will search pObj->pArray for the attribute. If it finds it, it
 * will decode the value and store the resulting Element array at pObj->pExtArray.
 * <p>If the function finds no Attributes, or if there are Attributes but none is
 * ExtensionRequest, then the function will leave pObj->pExtArray NULL and return
 * OK. So after calling this function, check pExtArray to see if there is
 * anything there.
 */
MSTATUS MDecodeExtensionRequest (
  MCertOrRequestObject *pObj
  );

#ifdef __cplusplus
}
#endif

#endif /* __CERT_OBJECT_HEADER__ */
