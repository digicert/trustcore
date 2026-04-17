/**
 * @file  scep.c
 * @brief SCEP -- Simple Certificate Enrollment Protocol
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
