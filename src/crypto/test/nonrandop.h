/*
 * nonrandop.h
 *
 * deterministic rng data generation for test vectors.
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
#include "../../crypto/mocsym.h"

#ifndef nonrandop_h
#define nonrandop_h

#ifdef __cplusplus
extern "C" {
#endif

/* This is the operator used by test cases. This operator allows the user to
 * specify specific outputs instead of random outputs. The non random output
 * allows for easier testing. This operator should never be used for any
 * other reason then testing.
 *
 * Use CRYPTO_createMocSymRandom, where the associated info is another random
 * context such as the global random context, to create this operator.
 *
 * Use CRYPTO_freeMocSymRandom to free the randomContext.
 *
 * Use CRYPTO_seedRandomContext to populate this function with the designated
 * bytes.
 *
 * Use RANDOM_numberGenerator to generate bytes. If the operator has bytes
 * loaded in from CRYPTO_seedRandomContext then it will use those, otherwise
 * it will use the randomContext that was passed in during initialization. Also,
 * if the static bytes have already been used (RANDOM_numberGenerator has been
 * called), then the second call to generate bytes (another call to
 * RANDOM_numberGenerator) will use the randomContext that was passed in during
 * initialization.
 */
MOC_EXTERN MSTATUS NonRandomOperator(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  );

#ifdef __cplusplus
}
#endif

#endif /* nonrandop_h */
