/*
 * harness_intfPkcs11.h
 *
 * Mocana Acceleration Harness Interface to PKCS11
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
