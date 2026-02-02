/*
 * truerand.h
 *
 * Implementation of AT&T Bell Labs 'truerand' Algorithm Header
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#ifndef __TRUERAND_HEADER__
#define __TRUERAND_HEADER__

/* invoked from timer interrupt handler */
MOC_EXTERN intBoolean TRUERAND_irqHandler(void);

/* entropy collector API */
MOC_EXTERN MSTATUS TRUERAND_entropyCollector(ubyte *pRetEntopy, ubyte4 numBitsRequired, void(*setTrueRandIrqHandler)(void));

#endif

