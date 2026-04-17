/*
 * nonrandop.h
 *
 * deterministic rng data generation for test vectors.
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
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
