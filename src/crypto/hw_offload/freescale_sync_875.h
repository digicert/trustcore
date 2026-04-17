/*
 * freescale_sync_875.h
 *
 * Freescale 875 Hardware Acceleration Synchronous Adapter
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
#ifndef __FREESCALE_SYNC_875_HEADER__
#define __FREESCALE_SYNC_875_HEADER__

/*------------------------------------------------------------------*/

#ifndef FSL_SEC_SYNC_TIMEOUT_MS
/* a crypto operation should never timeout, this is a safe guard */
#define FSL_SEC_SYNC_TIMEOUT_MS     1000
#endif


/*------------------------------------------------------------------*/

/* MOC_EXTERN void FSL875_SIU_SECCoprocessorEnable(intBoolean enable); */

MOC_EXTERN ubyte4 FSL875_ChIndexToISRDoneMask(int index, ubyte4 *pMask);
MOC_EXTERN ubyte4 FSL875_ChIndexToISRErrorMask(sbyte4 index, ubyte4 *pMask);

MOC_EXTERN ubyte*       SEC_getSECBaseAddress(void);


MOC_EXTERN void         FSL875_SetSECInterrupt(intBoolean enable);
MOC_EXTERN ubyte4       FSL875_SetSEC_IMR_1(ubyte4 val);


#if defined(__ENABLE_MW_ASM__)
MOC_EXTERN void         FSL875_SetEEInterrupt(intBoolean enable);
MOC_EXTERN asm ubyte4   SEC_getIMMR(void);
MOC_EXTERN asm ubyte4   SEC_getMSR(void);
MOC_EXTERN asm void     SEC_setMSR(ubyte4 val);
#endif /* defined(__ENABLE_MW_ASM__) */


#endif /* __FREESCALE_SYNC_875_HEADER__ */

