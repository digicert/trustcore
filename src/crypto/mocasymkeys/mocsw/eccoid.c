/*
 * eccoid.c
 *
 * Functions dealing with ECC OIDs.
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

#include "../../../common/moptions.h"
#include "../../../crypto/mocasym.h"
#include "../../../crypto/mocasymkeys/mocsw/commonasym.h"
#include "../../../crypto/mocasymkeys/mocsw/commonecc.h"

#include "../../../asn1/parseasn1.h"

#if (defined(__ENABLE_DIGICERT_SERIALIZE__))

/* p192 and p256 have the same oid except for the final byte */
static const ubyte gpCurveP192Oid[MOP_ECC_CURVE_P192_OID_LEN] =
{
  MOP_ECC_CURVE_P192_OID
};

/* p224, p384, p521 have the same oid except for the final byte */
static const ubyte gpCurveP224Oid[MOP_ECC_CURVE_P224_OID_LEN] =
{
  MOP_ECC_CURVE_P224_OID
};

#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
/* Ed25519, Ed448, X25519, X448 have the same oid except for the final byte */
static const ubyte gpCurveEdOid[MOP_ECC_CURVE_EDDH_25519_OID_LEN] =
{
    MOP_ECC_CURVE_EDDH_25519_OID
};
#endif

MOC_EXTERN MSTATUS GetCurveOid (
  ubyte4 curveId,
  ubyte *pOidBuf,
  ubyte4 bufferSize,
  ubyte4 *pOidLen
)
{
  MSTATUS status = ERR_NULL_POINTER;

  /* no curve's oid ends in 0x00, so we can use lastByte as a flag */
  ubyte lastByte = 0x00;

  if (NULL == pOidBuf || NULL == pOidLen)
    goto exit;

  status = ERR_BUFFER_TOO_SMALL;
  switch (curveId)
  {
#if (defined(__ENABLE_DIGICERT_ECC__))
    case cid_EC_P192:

      lastByte = MOP_ECC_CURVE_P192_BYTE;
      /* fall through */

    case cid_EC_P256:

      if (!lastByte)
        lastByte = MOP_ECC_CURVE_P256_BYTE;

      if (bufferSize < MOP_ECC_CURVE_P192_OID_LEN)
        goto exit;

      status = DIGI_MEMCPY(pOidBuf, gpCurveP192Oid, MOP_ECC_CURVE_P192_OID_LEN - 1);
      if (OK != status)
        goto exit;

      pOidBuf[MOP_ECC_CURVE_P192_OID_LEN - 1] = lastByte;
      *pOidLen = MOP_ECC_CURVE_P192_OID_LEN;

      break;

    case cid_EC_P224:

      lastByte = MOP_ECC_CURVE_P224_BYTE;
      /* fall through */

    case cid_EC_P384:

      if (!lastByte)
        lastByte = MOP_ECC_CURVE_P384_BYTE;
      /* fall through */

    case cid_EC_P521:

      if (!lastByte)
        lastByte = MOP_ECC_CURVE_P521_BYTE;

      if (bufferSize < MOP_ECC_CURVE_P224_OID_LEN)
        goto exit;

      status = DIGI_MEMCPY(pOidBuf, gpCurveP224Oid, MOP_ECC_CURVE_P224_OID_LEN - 1);
      if (OK != status)
        goto exit;

      pOidBuf[MOP_ECC_CURVE_P224_OID_LEN - 1] = lastByte;
      *pOidLen = MOP_ECC_CURVE_P224_OID_LEN;

      break;

      /* Check Edward's curves in reverse of usual order */
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
    case cid_EC_Ed448:

      lastByte = MOP_ECC_CURVE_EDDSA_448_BYTE;
      /* fall through */
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
    case cid_EC_Ed25519:

      if (!lastByte)
        lastByte = MOP_ECC_CURVE_EDDSA_25519_BYTE;
      
      /* fall through */
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
    case cid_EC_X448:

      if (!lastByte)
        lastByte = MOP_ECC_CURVE_EDDH_448_BYTE;
      
       /* fall through */
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
    case cid_EC_X25519:

      if (bufferSize < MOP_ECC_CURVE_EDDH_25519_OID_LEN)
        goto exit;
          
      status = DIGI_MEMCPY(pOidBuf, gpCurveEdOid, MOP_ECC_CURVE_EDDH_25519_OID_LEN);
      if (OK != status)
        goto exit;
      
      if (lastByte)
        pOidBuf[MOP_ECC_CURVE_EDDH_25519_OID_LEN - 1] = lastByte;
      
      *pOidLen = MOP_ECC_CURVE_EDDH_25519_OID_LEN;
      break;
#endif
#endif /* __ENABLE_DIGICERT_ECC__ */

    default:

      status = ERR_INVALID_INPUT;
      break;
  }

exit:

  return status;
}


MSTATUS GetCurveId (
  ubyte *pOid,
  ubyte4 oidLen,
  ubyte4 *pCurveId
)
{
  MSTATUS status = ERR_NULL_POINTER;
  sbyte4 compare = 0;

  if (NULL == pOid || NULL == pCurveId)
    goto exit;

  /* There are 3 possible oid Lengths over the 9 supported curves */
  *pCurveId = 0;
  status = ERR_EC_UNSUPPORTED_CURVE;
  if ( (MOP_ECC_CURVE_P192_OID_LEN - 2) != oidLen &&
       (MOP_ECC_CURVE_P224_OID_LEN - 2) != oidLen &&
       (MOP_ECC_CURVE_EDDH_25519_OID_LEN - 2) != oidLen )
    goto exit;

#ifdef __ENABLE_DIGICERT_ECC__

  if ((MOP_ECC_CURVE_P192_OID_LEN - 2) == oidLen)  /* check for p192 or p256 */
  {
    /* either curve has the same oid for all the bytes except the final byte.
     ok to ignore return code of DIGI_MEMCMP
     */
    DIGI_MEMCMP(pOid, gpCurveP192Oid + 2, oidLen - 1, &compare);
    if (compare)
      goto exit;

    if (MOP_ECC_CURVE_P256_BYTE == pOid[oidLen - 1])
    {
      *pCurveId = cid_EC_P256;
      status = OK;
    }
    else if (MOP_ECC_CURVE_P192_BYTE == pOid[oidLen - 1])
    {
      *pCurveId = cid_EC_P192;
      status = OK;
    }
  }
  else if((MOP_ECC_CURVE_P224_OID_LEN - 2) == oidLen)
  {
    /*
     The other 3 curves have the same oid for all the bytes except the final byte.
     ok to ignore return code of DIGI_MEMCMP
     */
    DIGI_MEMCMP(pOid, gpCurveP224Oid + 2, oidLen - 1, &compare);
    if (compare)
      goto exit;

    if (MOP_ECC_CURVE_P224_BYTE == pOid[oidLen - 1])
    {
      *pCurveId = cid_EC_P224;
      status = OK;
    }
    else if (MOP_ECC_CURVE_P384_BYTE == pOid[oidLen - 1])
    {
      *pCurveId = cid_EC_P384;
      status = OK;
    }
    else if (MOP_ECC_CURVE_P521_BYTE == pOid[oidLen - 1])
    {
      *pCurveId = cid_EC_P521;
      status = OK;
    }
  }
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
  else if ((MOP_ECC_CURVE_EDDH_25519_OID_LEN - 2) == oidLen)
  {
    DIGI_MEMCMP(pOid, gpCurveEdOid + 2, oidLen - 1, &compare);
    if (compare)
      goto exit;

#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
    if (gpCurveEdOid[MOP_ECC_CURVE_EDDH_25519_OID_LEN - 1] == pOid[oidLen - 1])
    {
      *pCurveId = cid_EC_X25519;
      status = OK;
      goto exit;
    }
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
    if (MOP_ECC_CURVE_EDDH_448_BYTE == pOid[oidLen - 1])
    {
      *pCurveId = cid_EC_X448;
      status = OK;
      goto exit;
    }
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
    if (MOP_ECC_CURVE_EDDSA_25519_BYTE == pOid[oidLen - 1])
    {
      *pCurveId = cid_EC_Ed25519;
      status = OK;
      goto exit;
    }
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
    if (MOP_ECC_CURVE_EDDSA_448_BYTE == pOid[oidLen - 1])
    {
      *pCurveId = cid_EC_Ed448;
      status = OK;
    }
#endif
  }
#endif /* __ENABLE_DIGICERT_ECC_ED_COMMON__ */
#endif /* __ENABLE_DIGICERT_ECC__ */
    
exit:

  return status;
}
#endif /* (defined(__ENABLE_DIGICERT_SERIALIZE__)) */
