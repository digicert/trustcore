/*
 * qnx_memdrv.h
 *
 * QNX Memory Driver Interface
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
 */

#ifndef __QNX_MEM_DRV_HEADER__
#define __QNX_MEM_DRV_HEADER__


/*------------------------------------------------------------------*/

#define MEM_DRIVER_NAME             "moc_memdrv"


/*------------------------------------------------------------------*/

typedef struct
{
    void*           memAddr;
    void*           pKernelAddress;
    void*           pPhysicalAddress;
    unsigned long   memAllocSize;
    unsigned long   memId;

} memDrvBlockDescr;

#define QNXHARNESS_CMD_CODE 0x1234

#define    MEMDRV_ALLOC_MEM_BLOCK    __DIOTF(_DCMD_MISC, QNXHARNESS_CMD_CODE + 0, memDrvBlockDescr)
#define    HARNESS_QNXOPEN_CHANNEL   __DIOT(_DCMD_MISC,  QNXHARNESS_CMD_CODE + 1, int)
#define    HARNESS_QNXCLOSE_CHANNEL  __DIOT(_DCMD_MISC,  QNXHARNESS_CMD_CODE + 2, int)
#define    HARNESS_QNXDO_CRYPTO      __DIOT(_DCMD_MISC,  QNXHARNESS_CMD_CODE + 3, int)
#define    HARNESS_QNXMEM_CLOSE      __DIOT(_DCMD_MISC,  QNXHARNESS_CMD_CODE + 4, int)

int QNX_mapSharedMemory(char * deviceName, long memId, unsigned **addr, long size, int *mapfd);
int QNX_openSharedMemory(char * deviceName, long memId, unsigned **addr, long size, int *mapfd);
int QNX_closeSharedMemory(char * deviceName, long memId);


#endif /* __QNX_MEM_DRV_HEADER__ */

