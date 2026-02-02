/*
 * algflag.c
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

#if (!defined(__DISABLE_DIGICERT_ASN1_GET_FLAG_FROM_ALG_ID_OID__))

extern MSTATUS ASN1_getPublicKeyAlgFlagFromOid (
  ubyte *pAlgOid,
  ubyte4 oidLen,
  ubyte4 *pAlg
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  ubyte4 index, lastByte;
  ubyte4 *pAddr;
#define MOP_ALG_FLAG_ARRAY_COUNT 6
#define MOP_ALG_FLAG_DONT_SKIP_INDEX 4
  /* skip last byte
   */
  ubyte pRsaEOid[MOP_RSA_P1_ENC_OID_LEN] = {
    MOP_RSA_P1_ENC_OID
  };
  /* skip last byte
   */
  ubyte pRsaSOid[MOP_RSA_SHA1_P1_OID_LEN] = {
    MOP_RSA_SHA1_P1_OID
  };
  /* skip last byte
   */
  ubyte pDsa1Oid[MOP_DSA_SHA1_ALG_ID_LEN] = {
    MOP_DSA_SHA1_ALG_ID
  };
  /* skip last byte
   */
  ubyte pDsa2Oid[MOP_DSA_SHA224_ALG_ID_LEN] = {
    MOP_DSA_SHA224_ALG_ID
  };
  /* don't skip last byte
   */
  ubyte pEcc1Oid[MOP_ECDSA_SHA1_ALG_ID_LEN] = {
    MOP_ECDSA_SHA1_ALG_ID
  };
  /* skip last byte
   */
  ubyte pEcc2Oid[MOP_ECDSA_SHA224_ALG_ID_LEN] = {
    MOP_ECDSA_SHA224_ALG_ID
  };
  ubyte4 pFlagArray[MOP_ALG_FLAG_ARRAY_COUNT] = {
    akt_rsa, akt_rsa, akt_dsa, akt_dsa, akt_ecc, akt_ecc
  };
  ubyte *ppOidArray[MOP_ALG_FLAG_ARRAY_COUNT] = {
    pRsaEOid, pRsaSOid, pDsa1Oid, pDsa2Oid, pEcc1Oid, pEcc2Oid
  };
  ubyte4 pLenArray[MOP_ALG_FLAG_ARRAY_COUNT] = {
    MOP_RSA_P1_ENC_OID_LEN, MOP_RSA_SHA1_P1_OID_LEN,
    MOP_DSA_SHA1_ALG_ID_LEN, MOP_DSA_SHA224_ALG_ID_LEN,
    MOP_ECDSA_SHA1_ALG_ID_LEN, MOP_ECDSA_SHA224_ALG_ID_LEN
  };

  status = ERR_NULL_POINTER;
  if ( (NULL == pAlgOid) || (NULL == pAlg) )
    goto exit;

  *pAlg = akt_undefined;
  for (index = 0; index < MOP_ALG_FLAG_ARRAY_COUNT; ++index)
  {
    pAddr = NULL;
    if (MOP_ALG_FLAG_DONT_SKIP_INDEX != index)
      pAddr = &lastByte;

    status = ASN1_compareOID (
      ppOidArray[index], pLenArray[index], pAlgOid, oidLen, pAddr, &cmpResult);
    if (OK != status)
      goto exit;

    if (0 != cmpResult)
      continue;

    *pAlg = pFlagArray[index];
    break;
  }

exit:

  return (status);
}

#endif /* (!defined(__DISABLE_DIGICERT_ASN1_GET_FLAG_FROM_ALG_ID_OID__)) */
