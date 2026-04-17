/*
 * pkcs11_rsa.h
 *
 * Mocana PKCS11 RSA header
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

#ifndef __PKCS11__RSA_HEADER__
#define __PKCS11__RSA_HEADER__


/*------------------------------------------------------------------*/
/* Need RSA's PKCS11 C headers (cryptoki.h, pkcs11.h, pkcs11f.h, pkcs11t.h)
 * http://www.rsa.com/rsalabs/node.asp?id=2133
 *
 */
extern MSTATUS
 RSAINT_decrypt(CK_SESSION_HANDLE hSession,
                CK_MECHANISM_PTR pMechanism,
                CK_OBJECT_HANDLE pKey,
                CK_BYTE_PTR pEngcryptedData,
                CK_ULONG ulEncryptedDataLen,
                CK_BYTE_PTR pData,
                CK_ULONG_PTR pulDataLen);

#endif /* __PKCS11__RSA_HEADER__ */
