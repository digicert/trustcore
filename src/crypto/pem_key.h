/*
 * pem_key.h
 *
 * Decrypt encrypted private PEM key.
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

#ifndef __PEM_KEY_HEADER__
#define __PEM_KEY_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS PEM_getPrivateKey(ubyte* pKeyFile, ubyte4 fileSize, ubyte* pPassword, ubyte4 passwordLen, ubyte** ppDecodeFile, ubyte4 *pDecodedLength);

#ifdef __cplusplus
}
#endif

#endif
