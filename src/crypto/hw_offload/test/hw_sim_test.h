/*
 * hw_sim_test.h
 *
 * HW ACCEL simulated initialization and opening
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

#ifndef __HW_SIM_TEST_H__
#define __HW_SIM_TEST_H__

#ifdef __cplusplus
extern "C" {
#endif

extern int HW_SIM_testHwCtx(void *pHwAccelCtx, char *pCaller);
    
extern int HW_SIM_init(void);

extern int HW_SIM_uninit (void);

extern int HW_SIM_open (enum moduleNames moduleId, void **ppHwAccelCookie);

extern int HW_SIM_close (enum moduleNames moduleId, void **ppHwAccelCookie);

#ifdef __cplusplus
}
#endif

#endif /* __HW_SIM_TEST_H__ */
