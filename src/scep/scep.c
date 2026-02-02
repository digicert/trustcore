/**
 * @file  scep.c
 * @brief SCEP -- Simple Certificate Enrollment Protocol
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert's Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.
 *
 */
#include "../common/moptions.h"

#ifdef __ENABLE_DIGICERT_SCEP_CLIENT__

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
#include "../scep/scep.h"

/*------------------------------------------------------------------*/

SCEP_operationsInfo mScepOperations[] =
{
    {{ (ubyte*)"PKIOperation", 12}, TRUE }, /* PKCSReq */
    {{ (ubyte*)"PKIOperation", 12}, TRUE }, /* GetCertInitial */
    {{ (ubyte*)"PKIOperation", 12}, TRUE }, /* GetCert */
    {{ (ubyte*)"PKIOperation", 12}, TRUE }, /* GetCRL */
    {{ (ubyte*)"RevokeCert",     10}, TRUE },
    {{ (ubyte*)"PublishCRL",     10}, TRUE },
    {{ (ubyte*)"ApproveCertEnroll",     17}, TRUE },
    {{ (ubyte*)"RegisterEndEntity",     17}, TRUE },
    {{ (ubyte*)"GetCACert",     9}, TRUE  },
    {{ (ubyte*)"GetNextCACert",    13}, TRUE },
    {{ (ubyte*)"GetCACertChain",    14}, TRUE },
    {{ (ubyte*)"GetCACaps",     9}, TRUE }
};

SCEP_nameStr mScepResponseTypes[] =
{
    { (ubyte*)"application/x-pki-message", 25 },
    { (ubyte*)"application/x-x509-ca-cert", 26 },
    { (ubyte*)"application/x-x509-ca-ra-cert", 29 },
    { (ubyte*)"application/x-x509-ca-ra-cert-chain", 35 },
    { (ubyte*)"application/xml", 15 }
};

/*------------------------------------------------------------------*/

static scepSettings mScepSettings;

/*------------------------------------------------------------------*/

extern scepSettings*
SCEP_scepSettings(void)
{
    return &mScepSettings;
}

/*------------------------------------------------------------------*/

#endif /* __ENABLE_DIGICERT_SCEP_CLIENT__ */
