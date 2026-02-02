/*
 * linux_memdrv.h
 *
 * Linux Memory Driver Interface
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

#ifndef __LINUX_MEM_DRV_HEADER__
#define __LINUX_MEM_DRV_HEADER__


/*------------------------------------------------------------------*/

#define MEM_DRIVER_NAME             "moc_memdrv"


/*------------------------------------------------------------------*/

typedef struct
{
    unsigned long long  pKernelAddress;
    unsigned long long  pPhysicalAddress;
    unsigned long long  memAllocSize;

} memDrvBlockDescr;

typedef enum memDrvIoctlMethods_s
{
    MEMDRV_ALLOC_MEM_BLOCK = 0x5678

} memDrvIoctlMethods;

#endif /* __LINUX_MEM_DRV_HEADER__ */

