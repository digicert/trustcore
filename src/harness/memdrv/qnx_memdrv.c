/*
 * qnx_memdrv.c
 *
 * QNX Memory Driver
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

#include "../../common/moptions.h"
#if defined(__RTOS_QNX__)

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <sys/mman.h>

/* Max length: device name prefix + decimal memId + newline + NUL */
#define QNX_MEMDRV_NAME_MAX 128

int
QNX_mapSharedMemory(char * deviceName, long memId, unsigned **addr, long size, int *mapfd)
{
    int fd;
    sbyte    deviceFullName[QNX_MEMDRV_NAME_MAX];

    snprintf(deviceFullName, sizeof(deviceFullName), "%s%ld\n", deviceName, memId);
    printf("Opening Memory %s\n",deviceFullName);
    fd = shm_open( deviceFullName, O_RDWR, 0777 );
    if( fd == -1 ) {
        fprintf( stderr, "Open failed:%s\n", strerror( errno ) );
        return -1;
    }

    *addr = mmap( 0, size,  PROT_NOCACHE | PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 );
    if( *addr == MAP_FAILED ) {
        fprintf( stderr, "mmap failed: %s\n", strerror( errno ) );
        return -1;
    }

    *mapfd = fd;

    printf( "Map addr is 0x%08x\n", (unsigned int)*addr );

    return 0;
}

int
QNX_openSharedMemory(char * deviceName, long memId, unsigned **addr, long size, int *mapfd)
{
    int fd;
    sbyte    deviceFullName[QNX_MEMDRV_NAME_MAX];

    snprintf(deviceFullName, sizeof(deviceFullName), "%s%ld\n", deviceName, memId);
    printf("Opening Memory %s\n",deviceFullName);

    fd = shm_open( deviceFullName,  O_RDWR | O_CREAT, 0777 );
    if( fd == -1 ) {
        fprintf( stderr, "Open failed:%s\n", strerror( errno ) );
        return -1;
    }

    if ( shm_ctl(fd,  SHMCTL_ANON | SHMCTL_PHYS , NULL, size ) == -1) {
        fprintf( stderr, "shm_ctl: %s\n", strerror( errno ) );
        return -1;
    }

    if( ftruncate( fd, size ) == -1 ) {
        fprintf( stderr, "ftruncate: %s\n", strerror( errno ) );
        return -1;
    }

    *addr = mmap( 0, size, PROT_NOCACHE | PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 );
    if( *addr == MAP_FAILED ) {
        fprintf( stderr, "mmap failed: %s\n", strerror( errno ) );
        return -1;
    }

    memset(*addr, 0, size);

    *mapfd = fd;

    printf( "Map addr is 0x%08x\n", (unsigned int)*addr );

    return 0;
}

int
QNX_closeSharedMemory(char * deviceName, long memId)
{
    sbyte    deviceFullName[QNX_MEMDRV_NAME_MAX];

    snprintf(deviceFullName, sizeof(deviceFullName), "%s%ld\n", deviceName, memId);
    printf("Closing Memory %s\n",deviceFullName);

    shm_unlink( deviceFullName);

    return 0;
}

#endif /*__RTOS_QNX__*/
