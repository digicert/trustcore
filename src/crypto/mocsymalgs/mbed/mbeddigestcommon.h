/*
 * mbeddigestcommon.h
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

#include "../../../crypto/mocsym.h"

#include <stddef.h>

#ifndef __DIGICERT_MBED_SYM_DIGEST_COMMON_H__
#define __DIGICERT_MBED_SYM_DIGEST_COMMON_H__

#ifdef __cplusplus
extern "C" {
#endif

/* This section will contain function pointers which are relevant to the MbedTLS
 * library. The MbedTLS API for digest algorithms is the same for the SHA and
 * MD family of algorithms. These function pointers are used so an operator
 * implementing a particular digest algorithm can simply pass in the relevant
 * function pointer into the Mbed digest common functions. Note that this is
 * dependent on the function signatures of MbedTLS. All the digest functions
 * have the same function signature for their initialization, start, update,
 * final, clone, and free so general purpose MbedTLS digest functions have been
 * made that take in those function signatures and simply call the function.
 */

/* This function pointer is used to initialize a MbedTLS digest context. This
 * function pointer will be an MbedTLS function that will set the context to the
 * initial state. Usually the MbedTLS digest initialization functions will
 * memset the context to 0's.
 */
typedef void (*MbedDigestInitFunc) (
  void *pCtx
  );

/* This function pointer will be used to set the MbedTLS context state to the
 * "start" state. This function pointer is similar to the init function pointer
 * but this function pointer will actually set the starting values inside the
 * context.
 */
typedef int (*MbedDigestStartFunc) (
  void *pCtx
  );

/* This function pointer is for updating the context with input.
 */
typedef int (*MbedDigestUpdateFunc) (
  void *pCtx,
  const unsigned char *pInput,
  size_t inputLen
  );

/* This function pointer is used to get the digest out of the context.
 */
typedef int (*MbedDigestFinalFunc) (
  void *pCtx,
  unsigned char *pOutput
  );

/* This function pointer will be used to clone a context. The values in the
 * source context are copied into the destination. The destination context must
 * be allocated beforehand.
 */
typedef void (*MbedDigestCloneFunc) (
  void *pDstCtx,
  void *pSrcCtx
  );

/* This function pointer will "free" the context. This simply means that the
 * context will be memset to 0. It does not actually free the memory. This is
 * because a MbedTLS digest context will either be dynamically allocated or on
 * the stack. Since the free function does not know how the context has been
 * allocated, it will clear all the data. The Mbed operators will dynamically
 * allocate all the memory for the contexts.
 */
typedef void (*MbedDigestFreeFunc) (
  void *pCtx
  );

/* This function is used to allocate an underlying MbedTLS context as the local
 * data for the MocSymCtx. The caller will pass in the MocSymCtx to populate
 * along with information to store in the MocSymCtx. The caller must provide the
 * size of the underlying MbedTLS digest context and the function will take care
 * of allocating it and setting it as the local data for the MocSymCtx.
 */
MOC_EXTERN MSTATUS MbedDigestCreate(
  MocSymCtx pMocSymCtx,
  MSymOperator symOp,
  void *pAssociatedInfo,
  ubyte4 ctxSize,
  ubyte4 localType
  );

/* This function is used to initialize the context and start the context. If
 * a caller calls CRYPTO_digestInit, then the context will be initialized which
 * tpyically means it will be memset to 0. After that the context will be
 * started.
 */
MOC_EXTERN MSTATUS MbedDigestInit(
  MocSymCtx pMocSymCtx,
  MbedDigestInitFunc pDigestInit,
  MbedDigestStartFunc pDigestStart
  );

/* This function is used to update the context with data
 */
MOC_EXTERN MSTATUS MbedDigestUpdate(
  MocSymCtx pMocSymCtx,
  MSymOperatorData *pDataToDigest,
  MbedDigestUpdateFunc pDigestUpdate
  );

/* This function will digest data with update if data was passed in. After the
 * data is processed, the data will be retrieved using the final function
 * pointer. The data will be copied into the output buffer. If the ouptut buffer
 * is not big enough then ERR_BUFFER_TOO_SMALL will be returned and the data
 * that is passed in will not be operated on. The required length of the buffer
 * will also be set.
 */
MOC_EXTERN MSTATUS MbedDigestFinal(
  MocSymCtx pMocSymCtx,
  MSymOperatorData *pDataToDigest,
  MSymOperatorBuffer *pDigest,
  MbedDigestUpdateFunc pDigestUpdate,
  MbedDigestFinalFunc pDigestFinal,
  ubyte4 digestLen
  );

/* This function will copy the local data of the MocSymCtx if it exists. If it
 * doesn't exist then OK will be returned and nothing will be copied into the
 * operator.
 */
MOC_EXTERN MSTATUS MbedDigestClone(
  MocSymCtx pMocSymCtx,
  MocSymCtx pNewCtx,
  MbedDigestCloneFunc pDigestClone
  );

/* This function will call the free function pointer and then actually free the
 * memory itself. The free function pointer is called just to memset data to 0.
 */
MOC_EXTERN MSTATUS MbedDigestFree(
  MocSymCtx pMocSymCtx,
  MbedDigestFreeFunc pDigestFree
  );

#ifdef __cplusplus
}
#endif

#endif /* __DIGICERT_MBED_SYM_DIGEST_COMMON_H__ */

