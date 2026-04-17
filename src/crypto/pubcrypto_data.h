/*
 * pubcrypto_data.h
 *
 * General Public Crypto Definitions & Types Header
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

/*------------------------------------------------------------------*/

#ifndef __PUBCRYPTO_DATA_HEADER__
#define __PUBCRYPTO_DATA_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS CRYPTO_getRSAHashAlgoOID( ubyte rsaAlgoId, ubyte rsaAlgoOID[/* 1 + MAX_SIG_OID_LEN */]);
MOC_EXTERN MSTATUS CRYPTO_getDSAHashAlgoOID( ubyte rsaAlgoId, ubyte dsaAlgoOID[/* 1 + MAX_SIG_OID_LEN */]);
MOC_EXTERN MSTATUS CRYPTO_getECDSAHashAlgoOID( ubyte rsaAlgoId, ubyte ecdsaAlgoOID[/* 1 + MAX_SIG_OID_LEN */]);
MOC_EXTERN MSTATUS CRYPTO_getHashAlgoOID( ubyte rsaAlgoId, const ubyte** pHashAlgoOID);

#ifdef __ENABLE_DIGICERT_ECC__
MOC_EXTERN MSTATUS CRYPTO_getEDDSAAlgoOID( struct ECCKey *pECCKey, ubyte eddsaAlgoOID[/* 1 + MAX_SIG_OID_LEN */]);
MOC_EXTERN MSTATUS CRYPTO_getECCurveOID( const struct ECCKey* pKey, const ubyte* *pCurveOID);
#endif

MOC_EXTERN MSTATUS CRYPTO_getCompositeAlgs(ubyte oidByte, ubyte4 *pClAlg, ubyte4 *pQsAlg);
MOC_EXTERN MSTATUS CRYPTO_getHybridAlgoOID(ubyte4 clAlgId, ubyte4 qsAlgId, ubyte oid[/* MAX_PQC_OID_LEN */]);
MOC_EXTERN MSTATUS CRYPTO_getQsAlgoOID(ubyte4 qsAlgId, ubyte oid[/* MAX_PQC_OID_LEN */]);
MOC_EXTERN MSTATUS CRYPTO_getAlgoOIDAlloc(ubyte4 clAlgId, ubyte4 qsAlgId, ubyte **ppOid, ubyte4 *pOidLen);

MOC_EXTERN MSTATUS CRYPTO_getQsAlgoFromOID(ubyte *pOid, ubyte4 oidLen, ubyte4 *pQsAlgIdEx);
MOC_EXTERN MSTATUS CRYPTO_getHybridCurveAlgoFromOID(ubyte *pOid, ubyte4 oidLen, ubyte4 *pClAlgId, ubyte4 *pQsAlgId);

#ifdef __cplusplus
}
#endif

#endif /* __PUBCRYPTO_DATA_HEADER__ */
