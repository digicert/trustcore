/*
 * missiu_com.c
 *
 * Common communication functions for Mocana IPsec Stack In Userspace
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert's Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.
 *
 */

#ifdef __ENABLE_DIGICERT_MISSIU__

#include <sys/ioctl.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <linux/if.h>
#include <errno.h>
#include <sys/un.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "missiu.h"

/* return a socket connected to missiu.  If iface is not null, connect to the
 * instance of missiu running on that iface.
 */
extern int MISSIU_findMissiu(const char *iface)
{
    int ret, fd = -1;
    DIR *dp;
    struct dirent *ep;
    char scanned_iface[IFNAMSIZ + 1];
    const char *iface_ptr = iface;
    char cmd_name[IFNAMSIZ + sizeof(CMDFIFO_FMT) + sizeof(RUN_DIR)];
    struct sockaddr_un cmd_addr;

    if (NULL == iface_ptr)
    {
        /* scan RUN_DIR for suitable instance of missiu */
        dp = opendir(RUN_DIR);
        if (NULL == dp)
        {
            perror ("Couldn't open missiu running directory");
            goto fail;
        }

        while((ep = readdir(dp)))
        {
            ret = sscanf(ep->d_name, CMDFIFO_FMT, scanned_iface);
            if (1 == ret)
            {

                if (NULL != iface_ptr)
                {
                    fprintf(stderr, "multiple instances of missiu running.  " \
                            "Please specify interface\n");
                    goto fail;
                }
                iface_ptr = scanned_iface;
            }
        }
        closedir(dp);
    }

    /* open the command fifo and connect */
    fd = socket(PF_LOCAL, SOCK_SEQPACKET, 0);
    if(fd == -1)
    {
        perror("failed to create control socket");
        goto fail;
    }

    sprintf(cmd_name, RUN_DIR CMDFIFO_FMT, iface_ptr);
    cmd_addr.sun_family = AF_LOCAL;
    strncpy(cmd_addr.sun_path, cmd_name, sizeof(cmd_addr.sun_path));
    ret = connect(fd, (struct sockaddr *)&cmd_addr, SUN_LEN(&cmd_addr));
    if (ret == -1)
    {
        fprintf(stderr, "failed to connect to daemon.  missiu not running?\n");
        fd = -1;
        goto fail;
    }

    return fd;

fail:
    if (fd != -1)
        close(fd);
    return -1;
}

/* send command to missiu running on iface.  shmem is the name of the shared
 * memory for passing results/args back/forth
 */
extern sbyte4
MISSIU_sendIoCtl(char *iface, struct missiu_tlv *cmdbuf)
{
    sbyte4 ret = 0;
    int fd = -1, result;

    /* find the missiu process of interest */
    fd = MISSIU_findMissiu(iface);
    if (fd == -1)
        return -1;

    /* send ioctl to missiu */
    ret = sendto(fd, cmdbuf, cmdbuf->len, 0, NULL, 0);
    if (ret !=  cmdbuf->len)
    {
        if (ret == -1)
            perror("failed to send command to missiu daemon");
        else
            fprintf(stderr, "failed to send entire command to missiu\n");
        ret = -1;
        goto done;
    }

    /* receive response from missiu */
    /* TODO: this should timeout instead of blocking forever */
    ret = recv(fd, &result, sizeof(result), 0);
    if (-1 == ret)
    {
        fprintf(stderr, "failed to recv response from missiu\n");
        ret = -1;
        goto done;
    }
    if (sizeof(result) != ret)
    {
        fprintf(stderr, "unexpected response length from missiu: %d\n", ret);
        ret = -1;
        goto done;
    }
    ret = result;

done:
    if (fd != -1)
        close(fd);
    return ret;
}

extern void
MISSIU_destroySharedMem(struct missiu_shmem *shmem, void **mem)
{
    if (MAP_FAILED != *mem)
        munmap(*mem, shmem->size);

    if (0 != shmem->name[0])
        shm_unlink(shmem->name);

    shmem->name[0] = 0;
    *mem = MAP_FAILED;
}

extern sbyte4
MISSIU_createSharedMem(struct missiu_shmem *shmem, void **mem)
{
    sbyte4 ret = 0;
    int fd = -1;
    *mem = MAP_FAILED;
    shmem->name[0] = 0;

    /* create a name for our shared memory area */
    strcpy(&shmem->name[0], SHMEM_TEMPLATE);
    mktemp(&shmem->name[0]);
    if (0 == shmem->name[0])
    {
        fprintf(stderr, "Failed to create shared memory area\n");
        goto fail;
    }

    /* now create the shared memory area and mmap it */
    fd = shm_open(shmem->name, O_RDWR|O_CREAT|O_TRUNC, S_IRWXU);
    if (-1 == fd)
    {
        perror("Failed to open shared memory area");
        goto fail;
    }
    ret = ftruncate(fd, shmem->size);
    if (-1 == ret)
    {
        perror("Failed to set size of shared memory area");
        goto fail;
    }
    *mem = mmap(NULL, shmem->size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (MAP_FAILED == *mem)
    {
        perror("Failed to map shared memory area");
        goto fail;
    }
    close(fd);

    return 0;

fail:

    MISSIU_destroySharedMem(shmem, mem);

    if (-1 != fd)
        close(fd);

    return -1;
}

/* prepare a TLV command buffer of type "cmd" with a value member of "size"
 * bytes.  Caller must call free on cmdbuf after he's done.
 */
extern sbyte4
MISSIU_prepareTLV(ubyte4 cmd, ubyte4 size, struct missiu_tlv **cmdbuf)
{
    int len;

    /* allocate a command buffer */
    len = sizeof(struct missiu_tlv) + size;
    *cmdbuf = (struct missiu_tlv *)malloc(len);
    if (!*cmdbuf)
    {
        fprintf(stderr, "failed to allocate command buffer\n");
        return -1;
    }
    (*cmdbuf)->type = cmd;
    (*cmdbuf)->len = len;
    return 0;
}

/* send a simple ioctl with a 4-byte value and return the 4-byte status to the
 * instance of missiu running on iface.  This function is not suitable for
 * ioctls that return a data struct in the shared memory.
 */
extern sbyte4
MISSIU_ioctlSimple(char *iface, ubyte4 cmd, ubyte4 value)
{
    sbyte4 status = 0;
    struct missiu_tlv *cmdbuf = NULL;
    char *mem;
    struct missiu_shmem *shmem;

    /* create a TLV cmdbuf with an shmem */
    status = MISSIU_prepareTLV(cmd, sizeof(struct missiu_shmem), &cmdbuf);
    if (status != 0)
        goto done;

    /* allocate shared mem of suitable size and initialize it */
    shmem = (struct missiu_shmem *)&cmdbuf->value[0];
    shmem->size = sizeof(value);
    status = MISSIU_createSharedMem(shmem, (void **)&mem);
    if (0 != status)
        goto done;
    *(ubyte4 *)mem = value;

    /* send it off to the missiu daemon */
    status = MISSIU_sendIoCtl(iface, cmdbuf);

done:
    MISSIU_destroySharedMem(shmem, (void **)&mem);

    if (NULL != cmdbuf)
        free(cmdbuf);

    return status;
}

/* send a simple ioctl with a 4-byte value.  Return the 4-byte status and set
 * the *value to the return value of the ioctl.
 */
extern sbyte4
MISSIU_ioctlSimpleGet(char *iface, ubyte4 cmd, ubyte4 *value)
{
    sbyte4 status = 0;
    struct missiu_tlv *cmdbuf = NULL;
    char *mem;
    struct missiu_shmem *shmem;

    /* create a TLV cmdbuf with an shmem */
    status = MISSIU_prepareTLV(cmd, sizeof(struct missiu_shmem), &cmdbuf);
    if (status != 0)
        goto done;

    /* allocate shared mem of suitable size and initialize it */
    shmem = (struct missiu_shmem *)&cmdbuf->value[0];
    shmem->size = sizeof(value);
    status = MISSIU_createSharedMem(shmem, (void **)&mem);
    if (0 != status)
        goto done;
    *(ubyte4 *)mem = *value;

    /* send it off to the missiu daemon */
    status = MISSIU_sendIoCtl(iface, cmdbuf);

    *value = *(ubyte4 *)mem;

done:
    MISSIU_destroySharedMem(shmem, (void **)&mem);

    if (NULL != cmdbuf)
        free(cmdbuf);

    return status;
}

#endif /* __ENABLE_DIGICERT_MISSIU__ */
