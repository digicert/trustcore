/**
 * @file  eap_avp.h
 * @brief EAP AVP handling API
 *
 * @details    AVP interface definitions
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

#ifndef __EAP_AVP_HEADER__
#define __EAP_AVP_HEADER__

#ifdef __cplusplus
extern "C" {
#endif
#define AVP_CODE_FIELD_SIZE                  4
#define AVP_FLAGS_FIELD_SIZE                 1
#define AVP_LENGTH_FIELD_SIZE                3
#define AVP_VENDOR_ID_FIELD_SIZE             4
#define AVP_MIN_LEN                          8
#define AVP_FLAGS_OFFSET                    (AVP_CODE_FIELD_SIZE)
#define AVP_LENGTH_OFFSET                   (AVP_CODE_FIELD_SIZE + AVP_FLAGS_FIELD_SIZE)
#define AVP_VENDOR_ID_OFFSET                (AVP_CODE_FIELD_SIZE + AVP_FLAGS_FIELD_SIZE + AVP_LENGTH_FIELD_SIZE)
#define AVP_WITH_VENDOR_ID_DATA_OFFSET      (AVP_CODE_FIELD_SIZE + AVP_FLAGS_FIELD_SIZE + AVP_LENGTH_FIELD_SIZE + AVP_VENDOR_ID_FIELD_SIZE)
#define AVP_DATA_OFFSET                     (AVP_CODE_FIELD_SIZE + AVP_FLAGS_FIELD_SIZE + AVP_LENGTH_FIELD_SIZE)
#define AVP_CODE_PLUS_FLAGS_PLUS_LEN_SIZE   (AVP_CODE_FIELD_SIZE + AVP_FLAGS_FIELD_SIZE + AVP_LENGTH_FIELD_SIZE)

#define AVP_VENDOR_ID_FLAG                  0x80
#define AVP_MANDATORY_FLAG                  0x40


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS AVP_getAttributeByType(ubyte *pPkt, ubyte4 pktLen, ubyte4 type, ubyte *pFlags, ubyte4 *pVendorId, ubyte **ppValue, ubyte4 *pLength);
MOC_EXTERN MSTATUS AVP_getAttributeByIndex(ubyte *pPkt, ubyte4 pktLen, ubyte index, ubyte4 *pType, ubyte *pFlags, ubyte4 *pVendorId, ubyte **ppValue, ubyte4 *pLength);
MOC_EXTERN sbyte4  AVP_appendAttribute(ubyte *pBuf, ubyte4 type, ubyte flags, ubyte4 vendorId, ubyte *pData, ubyte4 dataLength, ubyte4 *length);

#ifdef __cplusplus
}
#endif
#endif  /* __EAP_AVP_HEADER__ */

