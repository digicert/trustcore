/*
 * commonasym.h
 *
 * Declarations and definitions that are common to many or even all asymmetric
 * mocasym keys.
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

#include "../../../crypto/mocasym.h"

#ifndef __COMMON_ASYM_HEADER__
#define __COMMON_ASYM_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/* This is the "base class" for many mocasym keys. This is the struct that is
 * common to many keys, the data that goes into the mocAsymKey->pKeyData.
 * It contains the algId (the latest used) and a digest object.
 * If you want to "subclass" this struct, create a new struct with this struct as
 * the first field (the struct itself, not a pointer) so that a pointer to the
 * pKeyData can be dereferenced as this or your full data struct.
 */
typedef struct
{
  ubyte         *pAlgId;
  ubyte4         algIdLen;
  MocSymCtx      pDigestCtx;
} MAsymCommonKeyData;

/* Return the algorithm identifier in the pMocAsymKey.
 * <p>This function assumes that the pKeyData inside the pMocAsymKey can be
 * dereferenced as a pointer to MAsymCommonKeyData.
 */
MOC_EXTERN MSTATUS CommonReturnAlgId (
  MocAsymKey pMocAsymKey,
  MKeyOperatorBuffer *pOutputInfo
  );

/* Load the given algId and/or the digest ctx into the pKeyData.
 * <p>This function will dereference the pKeyData in pMocAsymKey as a pointer to
 * MAsymCommonKeyData. It will then look at pNewAlgId and pNewDigestCtx. If an
 * item is not NULL, the function will free the old value and copy in the new
 * value.
 * <p>This function simply copies the data given, it does not verify it is a
 * valid.
 * <p>The function will go to the address given by ppNewDigestCtx. If there is an
 * object there, it will free the old, copy the new, and set *ppNewDigestCtx to
 * NULL, taking over ownership of the object.
 * <p>Note that if the input is NULL, the function will not free the previous
 * element.
 */
MOC_EXTERN MSTATUS LoadCommonKeyData (
  MocAsymKey pMocAsymKey,
  ubyte *pNewAlgId,
  ubyte4 newAlgIdLen,
  MocSymCtx *ppNewDigestCtx
  );

/* This function will derefenerence the pKeyData in pMocAsymKey as a pointer to
 * MAsymCommonKeyData. It will then free any information therein.
 * <p>Note that it will only free the contents, it does notfree the struct itself.
 */
MOC_EXTERN MSTATUS FreeCommonKeyData (
  MocAsymKey pMocAsymKey
  );

#ifdef __cplusplus
}
#endif

#endif /* __COMMON_ASYM_HEADER__ */
