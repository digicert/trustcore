/*
 * Copyright (c) 2019 Jan Van Winkel <jan.van_winkel@dxplore.eu>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
#define LOG_LEVEL CONFIG_LOG_DEFAULT_LEVEL
LOG_MODULE_REGISTER(app, LOG_LEVEL_DBG);

#ifndef __RTOS_ZEPHYR__
#define __RTOS_ZEPHYR__
#define __ZEPHYR_FMGMT__
#define __RTOS_LINUX__
#define __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
#endif

#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/shell/shell.h>
#include <zephyr/net/socket.h>
#include <zephyr/dfu/flash_img.h>
#include <zephyr/dfu/mcuboot.h>

/* LITTLEFS */
#include <zephyr/fs/littlefs.h>
#include <zephyr/storage/flash_map.h>

/* DigiCert includes */
#include "common/moptions.h"
#include "common/mdefs.h"
#include "common/mtypes.h"
#include "common/merrors.h"
#include "common/mstdlib.h"
#include "common/mrtos.h"
#include "common/mtcp.h"
#include "common/mtcp_async.h"
#include "common/mfmgmt.h"
#include "common/common_utils.h"
#include "trustedge/utils/trustedge_utils.h"
#include "trustedge/trustedge_main.h"
#include "trustedge/agent/trustedge_agent_updatepolicy.h"

#if !defined(__ENABLE_DIGICERT_NATIVE_SIM__)
#include "dns.h"
#endif

#define STORAGE_PARTITION	fs_partition
#define STORAGE_PARTITION_ID	FIXED_PARTITION_ID(STORAGE_PARTITION)

FS_LITTLEFS_DECLARE_DEFAULT_CONFIG(lfs_data);
static struct fs_mount_t littlefs_mnt = {
    .type = FS_LITTLEFS,
    .fs_data = &lfs_data,
    .storage_dev = (void *)STORAGE_PARTITION_ID,
};

void get_partition_size(const char *mount_point)
{
    struct fs_statvfs stat;

    int ret = fs_statvfs(mount_point, &stat);
    if (ret != 0) {
        LOG_ERR("Failed to get file system stats: %d", ret);
        return;
    }

    /* Total size = block size * total number of blocks */
    uint64_t total_size = stat.f_bsize * stat.f_blocks;
    /* Available size = block size * available blocks */
    uint64_t available_size = stat.f_bsize * stat.f_bfree;

    LOG_INF("Total partition size: %llu bytes", total_size);
    LOG_INF("Available size: %llu bytes", available_size);
}

static char *mntpt_prepare(char *mntpt)
{
    char *cpy_mntpt;

    cpy_mntpt = k_malloc(strlen(mntpt) + 1);
    if (cpy_mntpt) {
        strcpy(cpy_mntpt, mntpt);
    }
    return cpy_mntpt;
}

static int cmd_mount_littlefs(char *mnt_pt) {
    if (littlefs_mnt.mnt_point != NULL) {
        return -EBUSY;
    }

    char *mntpt = mntpt_prepare(mnt_pt);

    if (!mntpt) {
        return -ENOEXEC; /* ?!? */
    }

    littlefs_mnt.mnt_point = mntpt;

    int rc = fs_mount(&littlefs_mnt);

    if (rc != 0) {
        k_free((void *)littlefs_mnt.mnt_point);
        littlefs_mnt.mnt_point = NULL;
        return -ENOEXEC;
    }

    return rc;
}

void setup_fs(char *mnt_pnt) {
    sbyte4 ret;

    ret = cmd_mount_littlefs(mnt_pnt);
    if (ret != 0)
    {
        goto exit;
    }

    get_partition_size(mnt_pnt);
exit:
    return;
}

/* shell command */
K_SEM_DEFINE(startTrustedge, 0, 1);
atomic_t cmdType = ATOMIC_INIT(0); // 0 == normal flow, 1 == reboot

static int cmd_trustedge_update(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(sh);
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
    atomic_set(&cmdType, 0);
    k_sem_give(&startTrustedge);
    return 0;
}

static int cmd_trustedge_reboot(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(sh);
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
    atomic_set(&cmdType, 1);
    k_sem_give(&startTrustedge);
    return 0;
}

static int cmd_trustedge_confirm(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(sh);
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
    atomic_set(&cmdType, 2);
    k_sem_give(&startTrustedge);
    return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_demo,
	SHELL_CMD(update, NULL, "run OTA sample.", cmd_trustedge_update),
	SHELL_CMD(reboot, NULL, "reboot device.", cmd_trustedge_reboot),
	SHELL_CMD(confirm, NULL, "confirm current image.", cmd_trustedge_confirm),
	SHELL_SUBCMD_SET_END /* Array terminated. */
);
SHELL_CMD_REGISTER(trustedge, &sub_demo, "Demo commands", NULL);
/* end shell command */

#define TRUSTEDGE_TCP_SERVER_PORT   8080
#define BUFFER_SIZE                 1024
/*********************** */
#define DOWNLOAD_FILE "payload.zip"
#define OUTPUT_DIR "tmp1"
/*********************************** */

static MSTATUS TRUSTEDGE_tcpDownloadBin(TCP_SOCKET serverSocket, ubyte2 port, sbyte *pFilename)
{
    MSTATUS status = ERR_GENERAL;
    sbyte pPayload[BUFFER_SIZE] = {0};
    sbyte pIpAddr[40] = {0};
    ubyte4 nRet = 0;
    sbyte4 bytesWritten = 0;
    sbyte4 numBytesSent = 0;
    k_timeout_t timeout = K_MSEC(2000);
    FileDescriptor pCtx = NULL;
    int totalBytes = 0;

    status = TRUSTEDGE_utilsGetHostByName("provision.digicert.com", pIpAddr);
    if (OK != status)
    {
        LOG_ERR("failed to get ip address of provision.digicert.com, status=%d\n", status);
        goto exit;
    }

    do
    {
        k_sleep(timeout);
        status = TCP_CONNECT(&serverSocket, pIpAddr, port);
    } while (OK != status);

    if (0 == DIGI_STRCMP(pFilename, "bin"))
    {
        status = FMGMT_fopen(DOWNLOAD_FILE, "wb", &pCtx);
        if (OK != status)
        {
            goto exit;
        }
    }

    status = TCP_WRITE(serverSocket, pFilename, DIGI_STRLEN(pFilename), &numBytesSent);
    if (OK != status)
    {
        goto exit;
    }

    do {

        status = TCP_READ_AVL_EX(serverSocket, pPayload, BUFFER_SIZE, &nRet, TCP_NO_TIMEOUT);
        if (ERR_TCP_READ_TIMEOUT == status)
        {
            status = OK;
            break;
        }

        if (nRet > 0)
        {
            status = FMGMT_fwrite(pPayload, 1, nRet, pCtx, &bytesWritten);
            totalBytes += bytesWritten;
            if (OK != status)
            {
                break;
            }
        }
    } while (nRet > 0);

    FMGMT_fclose(&pCtx);
    LOG_INF("firmware downloaded successfully\n");
    status = OK;

exit:

    return status;
}

void TRUSETDGE_downloadBin(void *pArg)
{
    MSTATUS status;
    TCP_SOCKET serverSocket = -1;
    sbyte *pFileRequest = (sbyte *)pArg;

    status = TRUSTEDGE_tcpDownloadBin(serverSocket, TRUSTEDGE_TCP_SERVER_PORT, pFileRequest);
    if (OK != status)
    {
        goto exit;
    }

exit:
    (void) TCP_CLOSE_SOCKET(serverSocket);
}

/* This needs to be provided by application */
static uint8_t gPartitionId = FIXED_PARTITION_ID(slot1_partition);

static MSTATUS TRUSTEDGE_SAMPLE_deviceFirmwareUpdateHandler(
    TrustEdgeArtifactAction *pAction,
    sbyte *pFile
)
{
    MSTATUS status;
    struct flash_area *fa;
    FileDescriptor pFileCtx = NULL;
    int rc = -1;
    off_t offset = 0;
    uint8_t buf[32];
    struct flash_img_context *ctx = NULL;
    sbyte *pInFilePath = NULL;

    if (NULL == pFile)
    {
        goto exit;
    }
    LOG_INF("pFile = %s\n", pFile);

    if (NULL == pAction)
    {
        goto exit;
    }

    if (NULL == pAction->pActionPath)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "%s", "no file path found\n");
        goto exit;
    }

    if (TE_ACTION_INSTALL == pAction->type)
    {

        status = COMMON_UTILS_addPathComponent(
            (sbyte *) pFile, (sbyte *) pAction->pActionPath, &pInFilePath);
        if (OK != status)
        {
            goto exit;
        }

        if (FALSE == FMGMT_pathExists(pInFilePath, NULL))
        {
            status = ERR_TRUSTEDGE_AGENT_ACTION_FAILED;
            goto exit;
        }
    }

    if (FALSE == FMGMT_pathExists(pInFilePath, NULL))
    {
        LOG_ERR("file %s does not exist\n", pInFilePath);
        goto exit;
    }

    ctx = k_malloc(sizeof(struct flash_img_context));
    if (ctx == NULL) {
        goto exit;
    }

    /* partition must be erased before we write to it */
    rc = flash_area_open(gPartitionId, (const struct flash_area **) &fa);
    if(rc != 0) {
        LOG_ERR("flash_area_open:%d\n", rc);
        goto exit;
    }

    rc = flash_area_erase(fa, 0, fa->fa_size);
    if(rc != 0) {
        LOG_ERR("flash_area_erase:%d\n", rc);
        goto exit;
    }

    flash_area_close(fa);
    /* erase complete */

    rc = flash_img_init_id(ctx, gPartitionId);
    if (rc != 0) {
        LOG_ERR("flash_img_init_id:%d\n", rc);
        goto exit;
    }

    status = FMGMT_fopen(pInFilePath, "r", &pFileCtx);
    if (OK != status) {
        LOG_ERR("FMGMT_fopen:%d\n", status);
        rc = -1;
        goto exit;
    }

    status = FMGMT_fread(buf, 1, sizeof(buf), pFileCtx, &rc);
    if (OK != status) {
        LOG_ERR("pre FMGMT_fread:%d\n", status);
        rc = -1;
        goto exit;
    }

    while (rc > 0) {
        if (rc < 32) {
            for (int i = rc; i < sizeof(buf); i++) {
                buf[i] = 0xFF;
            }
            rc = 32;
        }

        rc = flash_img_buffered_write(ctx, buf, rc, false);
        if(rc) {
            LOG_ERR("flash_img_buffered_write:false:%d\n", rc);
            LOG_ERR("bytes written: %ld\n", offset);
            goto exit;
        }
        offset += rc;

        status = FMGMT_fread(buf, 1, sizeof(buf), pFileCtx, &rc);
        if (OK != status) {
            LOG_ERR("post FMGMT_fread:%d\n", status);
            rc = -1;
            goto exit;
        }
    }

    rc = flash_img_buffered_write(ctx, buf, 0, true);
    if (rc) {
        LOG_ERR("flash_img_buffered_write:true:%d\n", rc);
        goto exit;
    }

    struct mcuboot_img_header header;
    if(boot_read_bank_header(gPartitionId, &header, sizeof(header)))
    {
        LOG_ERR("Failed to read bank header\n");
        rc = -1;
        goto exit;
    }

#if 1
    LOG_INF("image header\n");
    LOG_INF("size:       %d\n", header.h.v1.image_size);
    LOG_INF("version:    %d.%d.%d.%d\n", header.h.v1.sem_ver.major,
        header.h.v1.sem_ver.minor, header.h.v1.sem_ver.revision,
        header.h.v1.sem_ver.build_num);
    LOG_INF("mcuversion: %d\n", header.mcuboot_version);
#endif

    /* TODO: enable image check and make sure image signature is good to go */

    rc = boot_request_upgrade(BOOT_UPGRADE_TEST);
    if (rc) {
        LOG_ERR("failed to request upgrade: %d\n", rc);
        goto exit;
    }

    LOG_INF("firmware update requested successfully\n");

exit:
    DIGI_FREE((void **) &pInFilePath);
    k_free(ctx);
    return rc;
}

static int validateImage(void *pArgs)
{
    MOC_UNUSED(pArgs);

    /* add checks here */
    return boot_write_img_confirmed();
}

static int get_file_size(sbyte *pFile)
{
    int ret = 0;
    sbyte4 filSize;
    struct fs_file_t fs_file;
    fs_file_t_init(&fs_file);


    ret = fs_open(&fs_file, pFile, (fs_mode_t)FS_O_READ);
    if (ret < 0)
    {
        return -1;
    }

    ret = fs_seek(&fs_file, 0, MSEEK_END);
    if (ret < 0)
    {
        return -1;
    }

    filSize = (sbyte4)fs_tell(&fs_file);
    (void) fs_close(&fs_file);

    return filSize;
}

int main()
{
    MSTATUS status;
    char *mount_point = "/lfs1";
    RTOS_THREAD clientTid = RTOS_THREAD_INVALID;
    LOG_INF("image: %s\n", MY_IMAGE_NAME);
    TrustEdgeArtifactAction action = {0};
    action.type = TE_ACTION_INSTALL;
    action.handler.type = TE_ACTION_HANDLER_SCRIPT;
    action.handler.subtype = TE_ACTION_HANDLER_SUBTYPE_NODEJS;
    action.pActionPath = "./payload/trustedge.signed.bin";

    setup_fs(mount_point);

    status = FMGMT_setMountPoint(mount_point);
    if (OK != status)
        goto exit;

    (void) FMGMT_mkdir("log", 0775);

#if !defined(__ENABLE_DIGICERT_NATIVE_SIM__)
    dnsLookupTableInit();
    TRUSTEDGE_registerDNSLookupCallback(startDnsLookup);
#endif

    while(1)
    {
        k_sem_take(&startTrustedge, K_FOREVER);
        switch(atomic_get(&cmdType))
        {
            case 0:
                (void) FMGMT_remove(DOWNLOAD_FILE, TRUE);

                status = RTOS_createThread(TRUSETDGE_downloadBin, (void *)"bin", TRUSTEDGE_MAIN, &clientTid);
                if (OK != status)
                {
                    goto exit;
                }

                pthread_join((uintptr) clientTid, NULL);

                (void) FMGMT_remove(OUTPUT_DIR, TRUE);
                (void) FMGMT_mkdir(OUTPUT_DIR, 0775);

                status = TRUSTEDGE_utilsExtractInlineZip(DOWNLOAD_FILE, 0, 0, OUTPUT_DIR);
                if (OK != status)
                {
                    LOG_ERR("TRUSTEDGE_utilsExtractInlineZip error=%d\n", status);
                    goto exit;
                }

                LOG_INF("%s has size %d\n", action.pActionPath, get_file_size(action.pActionPath));

                if (TRUSTEDGE_SAMPLE_deviceFirmwareUpdateHandler(&action, OUTPUT_DIR)) {
                    LOG_ERR("DFU failed\n");
                    goto exit;
                }
                break;
                ;;
            case 1:
                sys_reboot(SYS_REBOOT_COLD);
                break;
                ;;
            case 2:
                if (validateImage(NULL))
                {
                    LOG_ERR("Failed to validate image.\n");
                    goto exit;
                }
                LOG_INF("confirmed\n");
                break;
                ;;
            default:
                break;
        }
    }

exit:
    return 0;
}
