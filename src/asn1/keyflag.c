/*
 * keyflag.c
 *
 * Functions that convert algId and OID to akt_ flag.
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
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
