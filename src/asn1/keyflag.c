/*
 * keyflag.c
 *
 * Functions that convert algId and OID to akt_ flag.
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
 */

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mocana.h"
#include "../common/mrtos.h"
#include "../common/mem_part.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../crypto/hw_accel.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../crypto/crypto.h"
#include "../crypto/ca_mgmt.h"

extern MSTATUS ASN1_getKeyFlagFromOid (
  ubyte *pKeyOid,
  ubyte4 oidLen,
  ubyte4 *pKeyAlg
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  ubyte pRsaOid[MOP_RSA_P1_ENC_OID_LEN] = {
    MOP_RSA_P1_ENC_OID
  };
  ubyte pDsaOid[MOP_DSA_OID_LEN] = {
    MOP_DSA_OID
  };
  ubyte pEccOid[MOP_ECC_KEY_OID_LEN] = {
    MOP_ECC_KEY_OID
  };

  status = ERR_NULL_POINTER;
  if ( (NULL == pKeyOid) || (NULL == pKeyAlg) )
    goto exit;

  *pKeyAlg = akt_undefined;
  status = ASN1_compareOID (
    pRsaOid, MOP_RSA_P1_ENC_OID_LEN, pKeyOid, oidLen, NULL, &cmpResult);
  if (OK != status)
    goto exit;

  *pKeyAlg = akt_rsa;
  if (0 == cmpResult)
    goto exit;

  *pKeyAlg = akt_undefined;
  status = ASN1_compareOID (
    pDsaOid, MOP_DSA_OID_LEN, pKeyOid, oidLen, NULL, &cmpResult);
  if (OK != status)
    goto exit;

  *pKeyAlg = akt_dsa;
  if (0 == cmpResult)
    goto exit;

  *pKeyAlg = akt_undefined;
  status = ASN1_compareOID (
    pEccOid, MOP_ECC_KEY_OID_LEN, pKeyOid, oidLen, NULL, &cmpResult);
  if (OK != status)
    goto exit;

  if (0 == cmpResult)
    *pKeyAlg = akt_ecc;

exit:

  return (status);
}
