/*
 * pkcs_common.h
 *
 * Routines shared by PKCS implementations
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

#ifndef __PKCS_COMMON_HEADER__
#define __PKCS_COMMON_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

typedef enum encryptedContentType {
    NORMAL=0, SCEP=1
} encryptedContentType;

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS PKCS_BulkDecrypt(MOC_SYM(hwAccelDescr hwAccelCtx)
                                ASN1_ITEM* pEncryptedContent,
                                CStream s,
                                BulkCtx bulkCtx,
                                const BulkEncryptionAlgo* pBulkAlgo,
                                ubyte* iv,
                                ubyte** decryptedInfo,
                                sbyte4* decryptedInfoLen);

MOC_EXTERN MSTATUS PKCS_BulkDecryptEx(MOC_SYM(hwAccelDescr hwAccelCtx)
                                encryptedContentType type,
                                ASN1_ITEM* pEncryptedContent,
                                CStream s,
                                BulkCtx bulkCtx,
                                const BulkEncryptionAlgo* pBulkAlgo,
                                ubyte* iv,
                                ubyte** decryptedInfo,
                                sbyte4* decryptedInfoLen);

#if defined(__ENABLE_DIGICERT_PKCS5__) || defined(__ENABLE_DIGICERT_PKCS12__)
MOC_EXTERN MSTATUS PKCS_DecryptPKCS8Key( MOC_SYM(hwAccelDescr hwAccelCtx)
                            ASN1_ITEMPTR pEncryptedKeyInfo,
                            CStream s, const ubyte* uniPassword,
                            sbyte4 uniPassLen, ubyte** privateKeyInfo,
                            sbyte4* privateKeyInfoLen);
#endif


MOC_EXTERN MSTATUS PKCS_GetCBCParams( ASN1_ITEM* pAlgoOID, CStream s,
                                     ubyte blockSize, ubyte iv[16]);

#ifdef __ENABLE_ARC2_CIPHERS__
MOC_EXTERN MSTATUS PKCS_GetRC2CBCParams( ASN1_ITEM* pAlgoOID,
                               CStream s,
                               sbyte4* pEffectiveKeyBits,
                               ubyte iv[8]); /*RC2_BLOCK_SIZE*/

#endif

#ifdef __cplusplus
}
#endif

#endif  /*#ifndef __PKCS_COMMON_HEADER__ */

