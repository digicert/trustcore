/*
 * pkcs11_rsa.h
 *
 * Mocana PKCS11 RSA header
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
