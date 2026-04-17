/*
 * harness_intfPkcs11.h
 *
 * Mocana Acceleration Harness Interface to PKCS11
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

#ifndef __HARNESS_INTF_PKCS11_HEADER__
#define __HARNESS_INTF_PKCS11_HEADER__

/*------------------------------------------------------------------*/

extern MSTATUS
HARNESS_PKCS11_openChannel(enum moduleNames moduleId, void **ppRetChannelContext);


/*------------------------------------------------------------------*/

extern MSTATUS
HARNESS_PKCS11_closeChannel(enum moduleNames moduleId, void **ppFreeChannelContext);


/*------------------------------------------------------------------*/

extern MSTATUS
HARNESS_PKCS11_init(void);


/*------------------------------------------------------------------*/

extern MSTATUS
HARNESS_PKCS11_uninit(void);

#endif /* __HARNESS_INTF_PKCS11_HEADER__ */
