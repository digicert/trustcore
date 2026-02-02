/*
 * mbedpoly1305.h
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

#include "mbedtls/poly1305.h"

#ifndef __MBEDPOLY1305_HEADER__
#define __MBEDPOLY1305_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#define MOC_POLY1305_KEY_LEN 32
#define MOC_POLY1305_MAC_LEN 16

typedef struct
{
  mbedtls_poly1305_context *pPolyCtx;
  ubyte pKey[MOC_POLY1305_KEY_LEN];
  ubyte4 keyLen;
} MbedPolyInfo;


MOC_EXTERN MSTATUS MPoly1305MbedCreate (
  MocSymCtx pSymCtx
  );

MOC_EXTERN MSTATUS MPoly1305MbedLoadKey (
  MocSymCtx pSymCtx,
  MSymOperatorData *pKeyData
  );

MOC_EXTERN MSTATUS MPoly1305MbedInit (
  MocSymCtx pSymCtx
  );

MOC_EXTERN MSTATUS MPoly1305MbedUpdate (
  MocSymCtx pSymCtx,
  MSymOperatorData *pInput
  );

MOC_EXTERN MSTATUS MPoly1305MbedFinal (
  MocSymCtx pSymCtx,
  MSymOperatorData *pInput,
  MSymOperatorBuffer *pOutput
  );

MOC_EXTERN MSTATUS MPoly1305MbedFreeData (
  MbedPolyInfo **ppCtx
  );

MOC_EXTERN MSTATUS MPoly1305MbedFree (
  MocSymCtx pSymCtx
  );

MOC_EXTERN MSTATUS MPoly1305MbedClone(
  MocSymCtx pCtx,
  MocSymCtx pCopyCtx
  );


#ifdef __cplusplus
}
#endif

#endif /* __MBEDPOLY1305_HEADER__ */
