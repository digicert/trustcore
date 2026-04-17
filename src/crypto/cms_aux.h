/*
 * cms_aux.h
 *
 * CMS auxiliary routines
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

#ifndef __CMS_AUX_HEADER__
#define __CMS_AUX_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS CMS_AUX_getReceiptRequest( ASN1_ITEMPTR pSignerInfo, CStream cs,
                                              ASN1_ITEMPTR* ppReceiptRequest);

/* these functions return an array of pointer to char - the array must be FREE'd by
the caller, the pointer to char should not be touched */

/* CMS_AUX_getReceiptRequestFrom : num is -1 for all, 0 for not on mailing list and > 0 for
a list */
MOC_EXTERN MSTATUS CMS_AUX_getReceiptRequestFrom( ASN1_ITEMPTR pReceiptRequest, CStream cs,
                                                    const ubyte*** from, sbyte4* num);
MOC_EXTERN MSTATUS CMS_AUX_getReceiptRequestTo( ASN1_ITEMPTR pReceiptRequest, CStream cs,
                                                    const ubyte*** to, sbyte4* num);

MOC_EXTERN MSTATUS CMS_AUX_getAttribute( ASN1_ITEMPTR pSignerInfo, CStream cs,
                                              const ubyte* attributeTypeOID,
                                              intBoolean signedAttr,
                                              ASN1_ITEMPTR *pAttribute);

MOC_EXTERN MSTATUS CMS_AUX_getAttributeValue( ASN1_ITEMPTR pSignerInfo, CStream cs,
                                              const ubyte* attributeTypeOID,
                                              intBoolean signedAttr,
                                              ubyte** ppAttributeValue,
                                              ubyte4* pAttributeValueLen);

#define CMS_AUX_ASN1TimeToTimeDate CERT_GetCertTime

/* redeclaration to make sure it matches the original one in parsecert.h */
MOC_EXTERN MSTATUS CMS_AUX_ASN1TimeToTimeDate( ASN1_ITEMPTR pTime, CStream s, TimeDate* pGMTTime);

MOC_EXTERN MSTATUS CMS_AUX_getAlgoName( const ubyte* algoOID, const char** ppAlgoName);

#ifdef __cplusplus
}
#endif

#endif  /*#ifndef __CMS_AUX_HEADER__ */
