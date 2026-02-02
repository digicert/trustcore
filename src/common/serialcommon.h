/*
 * serialize.h
 *
 * Declarations and definitions for Asymmetric key serialization.
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

#include "../crypto/mocasym.h"

#ifndef __DIGICERT_SERIALIZE_HEADER__
#define __DIGICERT_SERIALIZE_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#define MOC_PUB_PEM_HEADER "-----BEGIN PUBLIC KEY-----"
#define MOC_PUB_PEM_HEADER_LEN  26
#define MOC_PUB_PEM_FOOTER "-----END PUBLIC KEY-----"
#define MOC_PUB_PEM_FOOTER_LEN  24
#define MOC_PRI_PEM_HEADER "-----BEGIN PRIVATE KEY-----"
#define MOC_PRI_PEM_HEADER_LEN  27
#define MOC_PRI_PEM_FOOTER "-----END PRIVATE KEY-----"
#define MOC_PRI_PEM_FOOTER_LEN  25

/* Structure to maintain common serialization info between the common functions */
typedef struct
{
  ubyte **ppSerializedKey;
  ubyte4 *pSerializedKeyLen;
  ubyte4 derLen;
  ubyte4 headerLen;
  ubyte4 footerLen;
  serializedKeyFormat formatToUse;
  ubyte *pDerEncoding;
  ubyte *pHeader;
  ubyte *pFooter;
  ubyte pPubHeader[MOC_PUB_PEM_HEADER_LEN];
  ubyte pPubFooter[MOC_PUB_PEM_FOOTER_LEN];
  ubyte pPriHeader[MOC_PRI_PEM_HEADER_LEN];
  ubyte pPriFooter[MOC_PRI_PEM_FOOTER_LEN];
  MKeyOperatorDataReturn dataToReturn;
} MSerializeInfo;

/* Perform initialization code common among serialization functions.
 * 
 * @param pInfo  Pointer to a caller allocated MSerializeInfo structure.
 * @param format Serialization format requested.
 */
MOC_EXTERN MSTATUS SerializeCommonInit (
  MSerializeInfo *pInfo,
  serializedKeyFormat format
  );

/* Perform serialization processing common among serialization functions. 
 * Primarily wraps a DER encoding into a PEM encoding.
 * 
 * @param pInfo Pointer to a caller allocated MSerializeInfo structure 
 */
MOC_EXTERN MSTATUS SerializeCommon (
  MSerializeInfo *pInfo
  );

#ifdef __cplusplus
}
#endif

#endif /* __DIGICERT_SERIALIZE_HEADER__ */
