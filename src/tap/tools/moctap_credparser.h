/*
 * moctap_credparser.h
 *
 * SMP Credentials parser 
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
