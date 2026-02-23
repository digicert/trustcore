/*
 * openssl_shim.c
 *
 * OpenSSL SSL interface for DIGICERT
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */
#include "../common/moptions.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"

#include "../common/merrors.h"
#include "../common/sizedbuffer.h"

#include "ossl_types.h"
#include "openssl_shim.h"

int
OSSL_bindMethods(nssl_methods_t *pMeth)
{
     sbyte4	status;
     status = SSL_bindShimMethods(pMeth);
     if (OK > status)
	  return -1;
     return 1;
}

int
OSSL_SB_Allocate(OSSL_SizedBuffer *pSB, int size)
{
     if (NULL == (pSB->data  = OSSL_MALLOC(size))) {
	  return -1;
     }
     pSB->length	= size;
     return 0;
}

int
OSSL_SB_Free(OSSL_SizedBuffer *pSB)
{
     if (pSB->data != NULL) {
	  OSSL_FREE(pSB->data);
	  pSB->data	= NULL;
	  pSB->length	= 0;
	  return 1;
     }
     return 0;
}

extern void OSSL_RSAParamsFree(OSSL_RSAParams *p)
{
     if (NULL == p)
	  return;
     if (p->pN) OSSL_FREE(p->pN);
     if (p->pE) OSSL_FREE(p->pE);
     if (p->pP) OSSL_FREE(p->pP);
     if (p->pQ) OSSL_FREE(p->pQ);
}

extern void OSSL_DSAParamsFree(OSSL_DSAParams *p)
{
     if (NULL == p)
	  return;
     if (p->pP) OSSL_FREE(p->pP);
     if (p->pQ) OSSL_FREE(p->pQ);
     if (p->pG) OSSL_FREE(p->pG);
     if (p->pX) OSSL_FREE(p->pX);
     if (p->pY) OSSL_FREE(p->pY);
}
#if (defined (__ENABLE_DIGICERT_ECC__))
extern void OSSL_ECCParamsFree(OSSL_ECCParams *p)
{
     if (NULL == p)
	  return;
     if (p->pPub) OSSL_FREE(p->pPub);
     if (p->pPriv) OSSL_FREE(p->pPriv);
}
#endif
