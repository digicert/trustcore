/*
 * linux_memdrv.h
 *
 * Linux Memory Driver Interface
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

