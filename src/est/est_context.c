/**
 * @file  est_context.c
 * @brief EST context management functions.
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert's Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_EST_CLIENT__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/mrtos.h"
#include "../asn1/parseasn1.h"
#include "../asn1/derencoder.h"
#include "../crypto/crypto.h"
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/pkcs_common.h"
#include "../crypto/pkcs10.h"
#include "../crypto/pkcs7.h"
#include "../est/est_context.h"

/*------------------------------------------------------------------*/

EST_nameStr mEstContentTypeMediaTypes[] =
{
    { (ubyte*)"application/x-pki-message", 25 },
    { (ubyte*)"application/csrattrs", 20 },
    { (ubyte*)"application/pkcs7-mime", 22 }
};

EST_nameStr mEstContentTypePkcs7Parameter[] = {
    { (ubyte*)"certs-only", 10 },
    { (ubyte*)"multipart-mixed", 15 },
    { (ubyte*)"CMC-response", 12 }
};

/*------------------------------------------------------------------*/

static estSettings mEstSettings;

/*------------------------------------------------------------------*/

MOC_EXTERN estSettings*
EST_estSettings(void)
{
    return &mEstSettings;
}

/*------------------------------------------------------------------*/

#endif /* #if defined(__ENABLE_DIGICERT_EST_CLIENT__) */
