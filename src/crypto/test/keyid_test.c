/*
 * keyid_test.c
 *
 * Tests for the TAP-independent key ID operator.
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

#include "../../crypto/mocasymkeys/mocsw/id.h"
#if defined(__ENABLE_DIGICERT_TAP__)
#include "../../crypto/mocasymkeys/tap/idtap.h"
#endif
#include "../../../unit_tests/unittest.h"

int keyid_test_all(void)
{
#if defined(__ENABLE_DIGICERT_ASYM_KEY__) && defined(__ENABLE_DIGICERT_SERIALIZE__)
  int ret = 0;
  MSTATUS status;
  ubyte id[] = {0xaa, 0xbb, 0xcc};
  ubyte oid[] = {MOP_TAP_KEY_ID_ALG_ID};
  ubyte otherOid[] = {MOP_SECURE_STORAGE_KEY_ALG_ID};
  ubyte der[] = {
    0x30, 0x27, 0x02, 0x01, 0x00, MOP_TAP_KEY_ID_ALG_ID,
    0x04, 0x13, 0x30, 0x11, 0x02, 0x01, 0x00,
    0x02, 0x01, 0x12, 0x02, 0x01, 0x34, 0x02, 0x01, 0x56,
    0x04, 0x03, 0xaa, 0xbb, 0xcc
  };
  ubyte oversizedProviderDer[] = {
    0x30, 0x2b, 0x02, 0x01, 0x00, MOP_TAP_KEY_ID_ALG_ID,
    0x04, 0x17, 0x30, 0x15, 0x02, 0x01, 0x00,
    0x02, 0x05, 0x00, 0x00, 0x03, 0xe7, 0x00,
    0x02, 0x01, 0x34, 0x02, 0x01, 0x56,
    0x04, 0x03, 0xaa, 0xbb, 0xcc
  };
  ubyte negativeProviderDer[] = {
    0x30, 0x27, 0x02, 0x01, 0x00, MOP_TAP_KEY_ID_ALG_ID,
    0x04, 0x13, 0x30, 0x11, 0x02, 0x01, 0x00,
    0x02, 0x01, 0xff, 0x02, 0x01, 0x34, 0x02, 0x01, 0x56,
    0x04, 0x03, 0xaa, 0xbb, 0xcc
  };
  ubyte oversizedModuleDer[] = {
    0x30, 0x2b, 0x02, 0x01, 0x00, MOP_TAP_KEY_ID_ALG_ID,
    0x04, 0x17, 0x30, 0x15, 0x02, 0x01, 0x00,
    0x02, 0x01, 0x12, 0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x01, 0x56, 0x04, 0x03, 0xaa, 0xbb, 0xcc
  };
  ubyte negativeModuleDer[] = {
    0x30, 0x27, 0x02, 0x01, 0x00, MOP_TAP_KEY_ID_ALG_ID,
    0x04, 0x13, 0x30, 0x11, 0x02, 0x01, 0x00,
    0x02, 0x01, 0x12, 0x02, 0x01, 0xff, 0x02, 0x01, 0x56,
    0x04, 0x03, 0xaa, 0xbb, 0xcc
  };
  ubyte noncanonicalModuleDer[] = {
    0x30, 0x28, 0x02, 0x01, 0x00, MOP_TAP_KEY_ID_ALG_ID,
    0x04, 0x14, 0x30, 0x12, 0x02, 0x01, 0x00,
    0x02, 0x01, 0x12, 0x02, 0x02, 0x00, 0x34, 0x02, 0x01, 0x56,
    0x04, 0x03, 0xaa, 0xbb, 0xcc
  };
  ubyte oversizedTokenDer[] = {
    0x30, 0x2b, 0x02, 0x01, 0x00, MOP_TAP_KEY_ID_ALG_ID,
    0x04, 0x17, 0x30, 0x15, 0x02, 0x01, 0x00,
    0x02, 0x01, 0x12, 0x02, 0x01, 0x34,
    0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x03, 0xaa, 0xbb, 0xcc
  };
  ubyte negativeTokenDer[] = {
    0x30, 0x27, 0x02, 0x01, 0x00, MOP_TAP_KEY_ID_ALG_ID,
    0x04, 0x13, 0x30, 0x11, 0x02, 0x01, 0x00,
    0x02, 0x01, 0x12, 0x02, 0x01, 0x34, 0x02, 0x01, 0xff,
    0x04, 0x03, 0xaa, 0xbb, 0xcc
  };
  ubyte noncanonicalTokenDer[] = {
    0x30, 0x28, 0x02, 0x01, 0x00, MOP_TAP_KEY_ID_ALG_ID,
    0x04, 0x14, 0x30, 0x12, 0x02, 0x01, 0x00,
    0x02, 0x01, 0x12, 0x02, 0x01, 0x34, 0x02, 0x02, 0x00, 0x56,
    0x04, 0x03, 0xaa, 0xbb, 0xcc
  };
  ubyte *pEncoded = NULL, *pId = NULL;
  ubyte4 encodedLen = 0, idLen = 0, token = 0, provider = 0, module = 0;
  sbyte4 cmp = 0;
  ubyte4 localType = 0;
  MKeyOperatorData input = {0};
  MKeyObjectInfo info = {0};
  MKeyObjectInfo decoded = {0};
  MKeyOperatorDataReturn output = {0};

  ret += UNITTEST_INT(0, KeyOperatorId(NULL, NULL, MOC_ASYM_OP_GET_LOCAL_TYPE,
                        NULL, &localType, NULL), OK);
  ret += UNITTEST_INT(0, localType, MOC_LOCAL_TYPE_ID);
  ret += UNITTEST_INT(0, KeyOperatorId(NULL, NULL, MOC_ASYM_OP_GET_LOCAL_TYPE,
                        NULL, NULL, NULL), ERR_NULL_POINTER);
  ret += UNITTEST_INT(0, KeyOperatorId(NULL, NULL, MOC_ASYM_OP_SERIALIZE,
                        NULL, NULL, NULL), ERR_NULL_POINTER);
  ret += UNITTEST_INT(0, KeyOperatorId(NULL, NULL, MOC_ASYM_OP_DESERIALIZE,
                        NULL, NULL, NULL), ERR_NULL_POINTER);
  ret += UNITTEST_INT(0, KeyOperatorId(NULL, NULL, MOC_ASYM_OP_GET_PARAMS,
                        NULL, &info, NULL), ERR_NULL_POINTER);

  input.pData = der;
  input.length = sizeof(der);
  ret += UNITTEST_INT(0, KeyOperatorId(NULL, NULL, MOC_ASYM_OP_GET_PARAMS,
                        &input, &info, NULL), OK);
  ret += UNITTEST_INT(0, info.provider, 0x12);
  ret += UNITTEST_INT(0, info.moduleId, 0x34);
#if defined(__ENABLE_DIGICERT_TAP__)
  ret += UNITTEST_INT(0, IdTapGetTapInfo(&input, &info, FALSE), OK);
  ret += UNITTEST_INT(0, info.provider, 0x12);
  ret += UNITTEST_INT(0, info.moduleId, 0x34);
#endif

  status = IdParseAsn1(der, sizeof(der), oid, sizeof(oid), &pId, &idLen,
                       &token, &provider, &module);
  ret += UNITTEST_INT(0, status, OK);
  if (OK != status)
    goto exit;
  ret += UNITTEST_INT(0, idLen, sizeof(id));
  if (idLen == sizeof(id))
  {
    ret += UNITTEST_INT(0, DIGI_MEMCMP(pId, id, idLen, &cmp), OK);
    ret += UNITTEST_INT(0, cmp, 0);
  }
  ret += UNITTEST_INT(0, token, 0x56);
  ret += UNITTEST_INT(0, provider, 0x12);
  ret += UNITTEST_INT(0, module, 0x34);
  output.ppData = &pEncoded;
  output.pLength = &encodedLen;
  input.pData = id;
  input.length = sizeof(id);
  info.provider = 0x12;
  info.moduleId = 0x34;
  info.tokenId = 0x56;
  input.pAdditionalOpInfo = &info;
  status = KeyOperatorId(NULL, NULL, MOC_ASYM_OP_SERIALIZE, &input, &output, NULL);
  ret += UNITTEST_INT(0, status, OK);
  if (OK != status)
    goto exit;
  ret += UNITTEST_INT(0, encodedLen, sizeof(der));
  if (encodedLen == sizeof(der))
  {
    ret += UNITTEST_INT(0, DIGI_MEMCMP(pEncoded, der, encodedLen, &cmp), OK);
    ret += UNITTEST_INT(0, cmp, 0);
  }
  DIGI_FREE((void **) &pId);
  input.pData = pEncoded;
  input.length = encodedLen;
  status = KeyOperatorId(NULL, NULL, MOC_ASYM_OP_DESERIALIZE, &input, &decoded, NULL);
  ret += UNITTEST_INT(0, status, OK);
  if (OK != status)
    goto exit;
  pId = decoded.pId;
  idLen = decoded.idLen;
  ret += UNITTEST_INT(0, decoded.provider, 0x12);
  ret += UNITTEST_INT(0, idLen, sizeof(id));
  if (idLen == sizeof(id))
  {
    ret += UNITTEST_INT(0, DIGI_MEMCMP(pId, id, idLen, &cmp), OK);
    ret += UNITTEST_INT(0, cmp, 0);
  }
  DIGI_FREE((void **) &pEncoded);
  ret += UNITTEST_INT(0, IdParseAsn1(der, sizeof(der), otherOid, sizeof(otherOid),
                        NULL, NULL, NULL, NULL, NULL), ERR_INVALID_INPUT);
  ret += UNITTEST_TRUE(0, OK != IdParseAsn1(der, sizeof(der) - 1, oid, sizeof(oid),
                        NULL, NULL, NULL, NULL, NULL));
  ret += UNITTEST_INT(0, IdParseAsn1(der, sizeof(der), oid, sizeof(oid),
                        &pId, NULL, NULL, NULL, NULL), ERR_NULL_POINTER);
  ret += UNITTEST_TRUE(0, OK != IdParseAsn1(oversizedProviderDer,
                        sizeof(oversizedProviderDer), oid, sizeof(oid),
                        NULL, NULL, NULL, &provider, NULL));
  ret += UNITTEST_TRUE(0, OK != IdParseAsn1(negativeProviderDer,
                        sizeof(negativeProviderDer), oid, sizeof(oid),
                        NULL, NULL, NULL, &provider, NULL));
  ret += UNITTEST_TRUE(0, OK != IdParseAsn1(oversizedModuleDer,
                        sizeof(oversizedModuleDer), oid, sizeof(oid),
                        NULL, NULL, NULL, NULL, &module));
  ret += UNITTEST_TRUE(0, OK != IdParseAsn1(negativeModuleDer,
                        sizeof(negativeModuleDer), oid, sizeof(oid),
                        NULL, NULL, NULL, NULL, &module));
  ret += UNITTEST_TRUE(0, OK != IdParseAsn1(noncanonicalModuleDer,
                        sizeof(noncanonicalModuleDer), oid, sizeof(oid),
                        NULL, NULL, NULL, NULL, &module));
  ret += UNITTEST_TRUE(0, OK != IdParseAsn1(oversizedTokenDer,
                        sizeof(oversizedTokenDer), oid, sizeof(oid),
                        NULL, NULL, &token, NULL, NULL));
  ret += UNITTEST_TRUE(0, OK != IdParseAsn1(negativeTokenDer,
                        sizeof(negativeTokenDer), oid, sizeof(oid),
                        NULL, NULL, &token, NULL, NULL));
  ret += UNITTEST_TRUE(0, OK != IdParseAsn1(noncanonicalTokenDer,
                        sizeof(noncanonicalTokenDer), oid, sizeof(oid),
                        NULL, NULL, &token, NULL, NULL));

  status = IdCreateAsn1(0x12, 0x34, 0x56, oid, sizeof(oid), id, sizeof(id),
                        &pEncoded, &encodedLen);
  ret += UNITTEST_INT(0, status, OK);
  if (OK != status)
    goto exit;
  ret += UNITTEST_INT(0, encodedLen, sizeof(der));
  if (encodedLen == sizeof(der))
  {
    ret += UNITTEST_INT(0, DIGI_MEMCMP(pEncoded, der, encodedLen, &cmp), OK);
    ret += UNITTEST_INT(0, cmp, 0);
  }

  DIGI_FREE((void **) &pId);
  DIGI_FREE((void **) &pEncoded);
  status = IdCreateAsn1(0x12, 0x34, 0x56, otherOid, sizeof(otherOid),
                        id, sizeof(id), &pEncoded, &encodedLen);
  ret += UNITTEST_INT(0, status, OK);
  if (OK != status)
    goto exit;
  status = IdParseAsn1(pEncoded, encodedLen, otherOid, sizeof(otherOid),
                       &pId, &idLen, &token, &provider, &module);
  ret += UNITTEST_INT(0, status, OK);
  if (OK != status)
    goto exit;
  ret += UNITTEST_INT(0, provider, 0x12);
  ret += UNITTEST_INT(0, module, 0x34);
  ret += UNITTEST_INT(0, token, 0x56);
  ret += UNITTEST_INT(0, idLen, sizeof(id));
  if (idLen == sizeof(id))
  {
    ret += UNITTEST_INT(0, DIGI_MEMCMP(pId, id, sizeof(id), &cmp), OK);
    ret += UNITTEST_INT(0, cmp, 0);
  }
#if defined(__ENABLE_DIGICERT_TAP__)
  input.pData = pEncoded;
  input.length = encodedLen;
  ret += UNITTEST_INT(0, IdTapGetTapInfo(&input, &info, TRUE), OK);
  ret += UNITTEST_INT(0, info.provider, 0x12);
  ret += UNITTEST_INT(0, info.moduleId, 0x34);
#endif

exit:
  if (NULL != pId)
    DIGI_FREE((void **) &pId);
  if (NULL != pEncoded)
    DIGI_FREE((void **) &pEncoded);
  return ret;
#else
  return 0;
#endif
}
