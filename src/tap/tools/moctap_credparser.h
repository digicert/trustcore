/*
 * moctap_credparser.h
 *
 * SMP Credentials parser 
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

#ifndef __MOCTAP_CREDPARSER_H__
#define __MOCTAP_CREDPARSER_H__

MOC_EXTERN MSTATUS
MocTap_GetCredentialData( sbyte* scriptContent, sbyte4 scriptLen, 
      TAP_EntityCredentialList **pUsageCredentials);

MOC_EXTERN MSTATUS
MocTap_EncodeAuthData(
    ubyte *pData, ubyte **ppAuth);

MOC_EXTERN MSTATUS
MocTap_DecodeAuthData(
    ubyte *pData, ubyte4 dataLen, ubyte **ppAuth, ubyte4 *pAuthLen,
    intBoolean nullTerminate);

#endif /* __MOCTAP_CREDPARSER_H__ */
