/*
 * malgo_id.h
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#ifndef __MALGO_ID_HEADER__
#define __MALGO_ID_HEADER__

#include "../asn1/derencoder.h"

#ifdef __cplusplus
extern "C" {
#endif

/*----------------------------------------------------------------------------*/

/* Forward declaration
typedef struct MAlgoId MAlgoId;
 */

/* Set of function pointers used to handle algorithm identifiers
 *
 * AlgIdDeserializeParams - Used to deserialize an algorithm identifiers
 *   parameters into a Mocana structure. Required to implement.
 * AlgIdSerializeParams - Used to serialize a Mocana structure into an ASN.1
 *   encoding. Optional to implement.
 * AlgIdFreeParams - Used to free the parameters. Optional to implement.
 * AlgIdCopyParams - Used to create a deep copy of the parameters. Optional to
 *   implement.
 */
typedef MSTATUS (*AlgIdDeserializeParams)(
    ASN1_ITEMPTR pParams, CStream cs, void **ppParams);
typedef MSTATUS (*AlgIdSerializeParams)(DER_ITEMPTR pItem, void *pParams);
typedef MSTATUS (*AlgIdFreeParams)(void **ppParams);
typedef MSTATUS (*AlgIdCopyParams)(void *pParams, void **ppParams);

/* Set of flags which correspond to an OID defined oiddefs.c
 */
typedef enum
{
    ALG_ID_RSA_ENC_OID       = 0, /* rsaEncryption_OID */
    ALG_ID_DSA_OID           = 1, /* dsa_OID */
    ALG_ID_EC_PUBLIC_KEY_OID = 2, /* ecPublicKey_OID */
    ALG_ID_ECED_25519_OID    = 3, /* eddsa25519 */
    ALG_ID_ECED_448_OID      = 4, /* eddsa448 */
    ALG_ID_RSA_SSA_PSS_OID   = 5, /* rsaSsaPss_OID */
    ALG_ID_SUPPORTED_OID_COUNT = 6 /* Must be the last enumeration */
} MAlgoOid;

/* Structure to hold algorithm ID information.
 */
typedef struct MAlgoId
{
    MAlgoOid oidFlag;
    void *pParams;
} MAlgoId;

/* API to deserialize an algorithm ID.
 *
 * This API expects an OID flag and an algorithm identifier. The caller is
 * expected to parse the algorithm identifier and pass in the appropriate
 * OID flag. On return this function will provide the MAlgoId structure which
 * will contain the parsed algorithm identifier information.
 */
MOC_EXTERN MSTATUS ALG_ID_deserialize(
    MAlgoOid oidFlag,
    ASN1_ITEMPTR pAlgId,
    CStream cs,
    MAlgoId **ppRetAlgoId
    );

MOC_EXTERN MSTATUS ALG_ID_deserializeBuffer(
    MAlgoOid oidFlag,
    ubyte *pAlgId,
    ubyte4 algIdLen,
    MAlgoId **ppRetAlgoId
    );

/* API to serialize an algorithm ID.
 *
 * This API expects a constructed MAlgoId structure and returns an ASN.1
 * encoded algorithm identifier.
 */
MOC_EXTERN MSTATUS ALG_ID_serializeAlloc(
    MAlgoId *pAlgoId,
    ubyte **ppRetAlgId,
    ubyte4 *pRetAlgIdLen
    );

/* API to free a MAlgoId structure.
 */
MOC_EXTERN MSTATUS ALG_ID_free(
    MAlgoId **ppAlgoId
    );

/* API to copy the MAlgoId structure.
 */
MOC_EXTERN MSTATUS ALG_ID_copy(
    MAlgoId *pAlgoId,
    MAlgoId **ppRetAlgoId
    );

/*-- ecPublicKey_OID structure -----------------------------------------------*/

typedef struct
{
    ubyte4 curveId;
} EcPublicKeyAlgIdParams;

/*-- rsaSsaPss_OID structure -------------------------------------------------*/

typedef struct
{
    ubyte digestId;
    ubyte mgfAlgo;
    ubyte mgfDigestId;
    ubyte4 saltLen;
    ubyte trailerField;
} RsaSsaPssAlgIdParams;

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS ALG_ID_createRsaPssParams(
    ubyte digestId,
    ubyte mgfAlgo,
    ubyte mgfDigestId,
    ubyte4 saltLen,
    ubyte trailerField,
    MAlgoId **ppRetAlgoId
    );

#ifdef __cplusplus
}
#endif

#endif /* __MALGO_ID_HEADER__ */
