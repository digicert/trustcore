/*
 * freescale_sync_8248.h
 *
 * Freescale 8248 Hardware Acceleration Synchronous Adapter
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
#ifndef __FREESCALE_SYNC_8248_HEADER__
#define __FREESCALE_SYNC_8248_HEADER__


/*------------------------------------------------------------------*/

#ifndef FSL_SEC_SYNC_TIMEOUT_MS
#define FSL_SEC_SYNC_TIMEOUT_MS     1000
#endif


/*------------------------------------------------------------------*/

MOC_EXTERN ubyte*       SEC_getSECBaseAddress(void);
MOC_EXTERN ubyte*       SEC_getIMMR(void);

MOC_EXTERN ubyte4       FSL8248_SetSEC_IMR_1(ubyte4 val);


#if defined(__ENABLE_MW_ASM__)
MOC_EXTERN void         FSL8248_SetEEInterrupt(intBoolean enable);
MOC_EXTERN asm ubyte4   SEC_getMSR(void);
MOC_EXTERN asm void     SEC_setMSR(ubyte4 val);
#endif /* defined(__ENABLE_MW_ASM__) */

#endif /* __FREESCALE_SYNC_8248_HEADER__ */

