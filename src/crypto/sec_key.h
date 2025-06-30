/*
 * sec_key.h
 *
 * SEC key reading/writing routines
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

#ifndef __SEC_KEY_HEADER__
#define __SEC_KEY_HEADER__


/*------------------------------------------------------------------*/

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ENABLE_MOCANA_ECC__)

#if !defined(__DISABLE_MOCANA_CERTIFICATE_PARSING__)

/* create a ECC key based on the SEC1 DER encoding */
MOC_EXTERN MSTATUS SEC_getKey(MOC_ECC(hwAccelDescr hwAccelCtx) const ubyte* sec1DER, ubyte4 sec1DERLen, AsymmetricKey* pECCKey);
/* used when the curve is already known (PKCS8) */
MOC_EXTERN MSTATUS SEC_getPrivateKey(MOC_ECC(hwAccelDescr hwAccelCtx) ASN1_ITEMPTR pSeq, CStream cs, ubyte curveId,
                                     AsymmetricKey* pECCKey);

#endif /* !defined(__DISABLE_MOCANA_CERTIFICATE_PARSING__) */

#if defined( __ENABLE_MOCANA_DER_CONVERSION__) || defined(__ENABLE_MOCANA_PEM_CONVERSION__)

enum
{
    E_SEC_omitCurveOID = 0x00000001,
};

MOC_EXTERN MSTATUS SEC_setKey(MOC_ASYM(hwAccelDescr hwAccelCtx) const AsymmetricKey* pKey, ubyte **ppRetKeyDER, ubyte4 *pRetKeyDERLength);
MOC_EXTERN MSTATUS SEC_setKeyEx(MOC_ASYM(hwAccelDescr hwAccelCtx) const AsymmetricKey* pKey, ubyte4 options,
                                ubyte **ppRetKeyDER, ubyte4 *pRetKeyDERLength);

#endif /* defined( __ENABLE_MOCANA_DER_CONVERSION__) || defined(__ENABLE_MOCANA_PEM_CONVERSION__) */

#endif /* defined(__ENABLE_MOCANA_ECC__) */


#ifdef __cplusplus
}
#endif

#endif  /* __SEC_KEY_HEADER__ */
