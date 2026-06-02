/**
 * @file  ikekey.h
 * @brief IPsec SA key management.
 *
 * @details    IKE IPsec SA installation and key management definitions.
 * @since      1.41
 * @version    6.5.1 and later
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
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
/* internal use only */

#ifndef __IKEKEY_HEADER__
#define __IKEKEY_HEADER__

#if defined(__ENABLE_DIGICERT_IKE_SERVER__)

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

#define IKE_KEY_TYPE_RESERVED   (0)
#define IKE_KEY_TYPE_ACQUIRE    (1)
#define IKE_KEY_TYPE_SUSPEND    (2)
#define IKE_KEY_TYPE_DELETED    (3)
#define IKE_KEY_TYPE_CONNECTED  (4)
#define IKE_KEY_TYPE_ABORTED    (5)
#define IKE_KEY_TYPE_SAINIT     (6)
#define IKE_KEY_TYPE_MAX        (6)

#define IKE_KEY_TYPE_MASK       0x00ff
#define IKE_KEY_MOD_INITC       0x8000
#define IKE_KEY_MOD_SAINIT      0x4000
#define IKE_KEY_MOD_REDIRECTED  0x2000
#define IKE_KEY_MOD_PRIVATE     0x1000 /* for TYPE_DELETED */
#define IKE_KEY_MOD_OUTBOUND    0x0800 /* for TYPE_DELETED */
#define IKE_KEY_MOD_GDOI        0x0400 /* for GDOI (client) TYPE_ACQUIRE */


/*------------------------------------------------------------------*/

struct spd;
struct sadb;

MOC_EXTERN MSTATUS IKE_keyAcquire(MOC_IP_ADDRESS dwDestAddr,
                              MOC_IP_ADDRESS dwSrcAddr,
                              ubyte oUlp,
                              ubyte2 wDestPort, ubyte2 wSrcPort,
                              struct spd *pxSp
                              MOC_INTF(ifid)
                              MOC_COOKIE(cookie));

MOC_EXTERN MSTATUS IKE_keyAcqExp(struct sadb *pxSa, ubyte2 type);

MOC_EXTERN MSTATUS IKE_keyInform(MOC_IP_ADDRESS dwDestAddr,
                             MOC_IP_ADDRESS dwSrcAddr,
#ifdef __ENABLE_IPSEC_NAT_T__
                             ubyte2 wUdpEncPort,
#endif
                             ubyte4 dwSpi, ubyte oProtocol,
                             ubyte4 dwIkeSaId, sbyte4 ikeSaIndex,
                             ubyte2 type
                             MOC_COOKIE(cookie));

MOC_EXTERN MSTATUS IKE_keyInfoEx(struct sadb *pxSa,
#ifdef __ENABLE_IPSEC_NAT_T__
                                 ubyte2 wUdpEncPort,
#endif
                                 ubyte4 dwSpi, ubyte2 type);


#ifdef __cplusplus
}
#endif

#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

#endif /* __IKEKEY_HEADER__ */

