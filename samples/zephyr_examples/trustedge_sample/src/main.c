/*
 * Copyright (c) 2019 Jan Van Winkel <jan.van_winkel@dxplore.eu>
 *
 * SPDX-License-Identifier: Apache-2.0
 */


#ifndef __RTOS_ZEPHYR__
#define __RTOS_ZEPHYR__
#define __ZEPHYR_FMGMT__
#define __RTOS_LINUX__
#define __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
#endif

#include <zephyr/logging/log.h>
#include <string.h>
#include <pthread.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/shell/shell.h>
#include <zephyr/net/socket.h>
#ifdef __ENABLE_DIGICERT_BOOTLOADER_SUPPORT__
#include <zephyr/dfu/flash_img.h>
#include <zephyr/dfu/mcuboot.h>
#endif

#if defined(CONFIG_LOG_BACKEND_FS)
#include <zephyr/logging/log_ctrl.h>
#endif

/* LITTLEFS */
#include <zephyr/fs/littlefs.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/kernel.h>
#include <zephyr/multi_heap/shared_multi_heap.h>

/* DigiCert includes */
#include "common/moptions.h"
#include "common/mdefs.h"
#include "common/mtypes.h"
#include "common/merrors.h"
#if defined(__ENABLE_DIGICERT_MEM_PROFILE__) || defined(__ENABLE_DIGICERT_STACK_PROFILE__)
#include "common/mtcp.h"
#endif
/* #include "common/mrtos.h" */
#include "common/mfmgmt.h"
#include "trustedge/trustedge_main.h"

#if !defined(__ENABLE_DIGICERT_NATIVE_SIM__)
#include "dns.h"
#endif

#if defined(__ENABLE_DIGICERT_CUSTOM_MALLOC__)
#define CUSTOM_HEAP_SIZE (146 * 1024)
static uint8_t heap_buffer[CUSTOM_HEAP_SIZE] __aligned(4);
#endif

#ifdef __ENABLE_DIGICERT_ESP32S3__
#define STORAGE_PARTITION	storage_partition
#else
#define STORAGE_PARTITION	fs_partition
#endif
#define STORAGE_PARTITION_ID	FIXED_PARTITION_ID(STORAGE_PARTITION)

FS_LITTLEFS_DECLARE_DEFAULT_CONFIG(lfs_data);
static struct fs_mount_t littlefs_mnt = {
    .type = FS_LITTLEFS,
    .fs_data = &lfs_data,
    .storage_dev = (void *)STORAGE_PARTITION_ID,
};

static char *mount_point = "/lfs1";

void get_partition_size(const char *mount_point)
{
    struct fs_statvfs stat;

    int ret = fs_statvfs(mount_point, &stat);
    if (ret != 0) {
        printk("Failed to get file system stats: %d\n", ret);
        return;
    }

    /* Total size = block size * total number of blocks */
    uint64_t total_size = stat.f_bsize * stat.f_blocks;
    /* Available size = block size * available blocks */
    uint64_t available_size = stat.f_bsize * stat.f_bfree;

    printk("Total partition size: %llu bytes\n", total_size);
    printk("Available size: %llu bytes\n", available_size);
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

static int cmd_mount_littlefs(char *mnt_pt)
{
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

void setup_fs(char *mnt_pnt)
{
    int ret;

    ret = cmd_mount_littlefs(mnt_pnt);
    if (ret != 0)
    {
        goto exit;
    }

    get_partition_size(mnt_pnt);
exit:
    return;
}

void TRUSTEDGE_launchWrapper(void *pArgs)
{
    enum TrustedgeMode mode = (enum TrustedgeMode)(uintptr_t)pArgs;
    int status = TRUSTEDGE_launch(mode);
    if (0 != status)
    {
        printk("TRUSTEDGE_launch failed: %d\n", status);
    }
}

#ifdef __ENABLE_DIGICERT_STACK_PROFILE__
typedef struct stack_info {
    k_tid_t thread_id; /* used to identify the thread */
    size_t used;
    size_t size;
    size_t max_used; /* the high water mark we are looking for */
} stack_info;

#define MAX_STACKS 20

typedef struct stacks_info {
    struct stack_info stack_array[MAX_STACKS];
    int count;
} stacks_info;

static struct stacks_info g_stacks_data = { 0 };
static struct k_mutex     g_stackmon_mu;

atomic_t stackLoop = ATOMIC_INIT(1);

int find_thread(k_tid_t thread_id, struct stacks_info *pStacks)
{
    int i;
    for (i = 0; i < pStacks->count; i++)
    {
        if (pStacks->stack_array[i].thread_id == thread_id)
        {
            return i;
        }
    }
    return -1;
}

static void update_one(const struct k_thread *t, void *user)
{
#if defined(CONFIG_INIT_STACKS) && defined(CONFIG_THREAD_STACK_INFO)
    size_t unused;
    struct stacks_info *pStacks = (struct stacks_info *) user;
    int thread_index = find_thread((k_tid_t)t, pStacks);

    if (thread_index < 0)
    {
        if (pStacks->count >= MAX_STACKS)
        {
            printk("maximum number of tracked stacks reached\n");
            return;
        }
        /* if we have not seen thread before, save it to end of array */
        thread_index = pStacks->count;
        pStacks->stack_array[thread_index].size = t->stack_info.size;
        pStacks->stack_array[thread_index].thread_id = (k_tid_t)t;
        pStacks->stack_array[thread_index].max_used = 0;
        pStacks->count++;
    }

    if (k_thread_stack_space_get((k_tid_t)t, &unused) == 0)
    {
        pStacks->stack_array[thread_index].used = t->stack_info.size - unused;
        if (pStacks->stack_array[thread_index].used >
            pStacks->stack_array[thread_index].max_used)
        {
            pStacks->stack_array[thread_index].max_used =
                pStacks->stack_array[thread_index].used;
        }
    }
#else
    ARG_UNUSED(t);
    ARG_UNUSED(user);
#endif
}

int stackmon_update(struct stacks_info *pStacks)
{
    k_mutex_lock(&g_stackmon_mu, K_FOREVER);
    k_thread_foreach(update_one, (void *) pStacks);
    k_mutex_unlock(&g_stackmon_mu);
    return 0;
}

void print_stacks_info(struct stacks_info *pStacks)
{
    int i;
    k_mutex_lock(&g_stackmon_mu, K_FOREVER);
    printk("\nThread stack usage:\n");
    printk("  %-20s %18s %8s\n", "Thread Name / ID", "High Water Mark", "Size");
    printk("  ------------------------------------------------------------\n");

    for (int i = 0; i < pStacks->count; i++) {
        const char *name = k_thread_name_get((k_tid_t)pStacks->stack_array[i].thread_id);
        if (!name || !name[0]) {
            // Use pointer as fallback name
            printk("  %-20p %10zu bytes     %8zu\n",
                pStacks->stack_array[i].thread_id,
                pStacks->stack_array[i].max_used,
                pStacks->stack_array[i].size);
        } else {
            printk("  %-20s %10zu bytes     %8zu\n",
                name,
                pStacks->stack_array[i].max_used,
                pStacks->stack_array[i].size);
        }
    }

    printk("  ------------------------------------------------------------\n");
#if 0

    printk("\nThread stack usage:\n");
    printk("  Thread Name      High Water Mark   Size\n");
    printk("------------------------------------------------\n");
    for (i = 0; i < pStacks->count; i++)
    {
        const char *name = k_thread_name_get((k_tid_t)pStacks->stack_array[i].thread_id);
        if (!name || !name[0])
        {
            printk("  %p  %5zu   %5zu\n",
                pStacks->stack_array[i].thread_id,
                pStacks->stack_array[i].max_used,
                pStacks->stack_array[i].size);
        }
        else
        {
            printk("  %s  %5zu   %5zu\n",
                name,
                pStacks->stack_array[i].max_used,
                pStacks->stack_array[i].size);
        }
    }
    printk("------------------------------------------------\n");
#endif
    k_mutex_unlock(&g_stackmon_mu);
}

static void stack_tracking_thread(void *a, void *b, void *c)
{
    ARG_UNUSED(a);
    ARG_UNUSED(b);
    ARG_UNUSED(c);

    memset(&g_stacks_data, 0, sizeof(g_stacks_data));
    k_mutex_init(&g_stackmon_mu);

    printk("\nstack tracking starting\n");

    while (atomic_get(&stackLoop))
    {
        stackmon_update(&g_stacks_data);
        k_sleep(K_SECONDS(2));
    }

    printk("stack tracking stopping\n");
}

#define MONITOR_STACK_SIZE  1024
#define MONITOR_PRIORITY    1

K_THREAD_DEFINE(stack_monitor, MONITOR_STACK_SIZE, stack_tracking_thread,
    NULL, NULL, NULL, MONITOR_PRIORITY, 0, 0);
#endif /* __ENABLE_DIGICERT_STACK_PROFILE__ */

char* concat_with_slash(const char* str1, const char* str2)
{
    if (!str1 || !str2) return NULL;

    size_t len1 = strlen(str1);
    size_t len2 = strlen(str2);
    size_t total_len = len1 + 1 + len2 + 1;  // slash + null terminator

    // Use k_malloc instead of malloc
    char* result = k_malloc(total_len);
    if (!result) return NULL;

    strcpy(result, str1);
    result[len1] = '/';
    strcpy(result + len1 + 1, str2);

    return result;
}

/* This needs to be provided by application */
#ifdef __ENABLE_DIGICERT_BOOTLOADER_SUPPORT__
static uint8_t gPartitionId = FIXED_PARTITION_ID(slot1_partition);

static int confirmImage(void *pArgs)
{
    MOC_UNUSED(pArgs);

    /* add checks here */
    return boot_write_img_confirmed();
}

static int TRUSTEDGE_SAMPLE_actionHandler(
    TrustEdgeArtifactAction *pAction,
    char *pFile
)
{
    int status = -1;
    struct flash_area *fa;
    int rc = -1;
    off_t offset = 0;
    uint8_t buf[32];
    struct flash_img_context *ctx = NULL;
    char *pInFilePath = NULL;
    char *pBasePath = NULL; /* this will be mount plus pFile path */ 
    struct stat st;
    struct fs_file_t file;

    fs_file_t_init(&file);

    printk("starting firmware update\n");
    if (NULL == pFile)
    {
        goto exit;
    }

    if (NULL == pAction)
    {
        goto exit;
    }

    if (NULL == pAction->pActionPath)
    {
        goto exit;
    }

    if (TE_ACTION_INSTALL == pAction->type)
    {

        /* prefix mount point to file path to get full path */
        pBasePath = concat_with_slash(mount_point, pFile);
        if (NULL == pBasePath)
        {
            goto exit;
        }

        pInFilePath = concat_with_slash(pBasePath, pAction->pActionPath);
        k_free(pBasePath); 
        if (NULL == pInFilePath)
        {
            goto exit;
        }
    }
    else
    {
        printk("not supported action type %d\n", pAction->type);
        goto exit;
    }

    if (0 != stat(pInFilePath, &st))
    {
        printk("stat failed for %s\n", pInFilePath);
        goto exit;
    }

    ctx = k_malloc(sizeof(struct flash_img_context));
    if (ctx == NULL)
    {
        goto exit;
    }

    /* partition must be erased before we write to it */
    rc = flash_area_open(gPartitionId, (const struct flash_area **) &fa);
    if(rc != 0)
    {
        printk("flash_area_open:%d\n", rc);
        goto exit;
    }

    rc = flash_area_erase(fa, 0, fa->fa_size);
    if(rc != 0)
    {
        printk("flash_area_erase:%d\n", rc);
        goto exit;
    }

    flash_area_close(fa);
    /* erase complete */

    rc = flash_img_init_id(ctx, gPartitionId);
    if (rc != 0)
    {
        printk("flash_img_init_id:%d\n", rc);
        goto exit;
    }

    rc = fs_open(&file, pInFilePath, FS_O_READ);
    if (rc != 0)
    {
        printk("fs_open failed: %d\n", rc);
        goto exit;
    }

    rc = fs_read(&file, buf, sizeof(buf));
    if (rc < 0)
    {
        printk("fs_read failed: %d\n", rc);
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
            printk("flash_img_buffered_write:false:%d\n", rc);
            printk("bytes written: %ld\n", offset);
            goto exit;
        }
        offset += rc;

        rc = fs_read(&file, buf, sizeof(buf));
        if (rc < 0) {
            printk("fs_read failed: %d\n", rc);
            goto exit;
        }
    }

    rc = flash_img_buffered_write(ctx, buf, 0, true);
    if (rc) {
        printk("flash_img_buffered_write:true:%d\n", rc);
        goto exit;
    }

    struct mcuboot_img_header header;
    if(boot_read_bank_header(gPartitionId, &header, sizeof(header)))
    {
        printk("Failed to read bank header\n");
        goto exit;
    }

#if 1
    printk("image header\n");
    printk("size:       %d\n", header.h.v1.image_size);
    printk("version:    %d.%d.%d.%d\n", header.h.v1.sem_ver.major,
        header.h.v1.sem_ver.minor, header.h.v1.sem_ver.revision,
        header.h.v1.sem_ver.build_num);
    printk("mcuversion: %d\n", header.mcuboot_version);
#endif

    /* TODO: enable image check and make sure image signature is good to go */

    rc = boot_request_upgrade(BOOT_UPGRADE_TEST);
    if (rc)
    {
        printk("failed to request upgrade: %d\n", rc);
        goto exit;
    }

    printk("firmware update requested successfully\n");
    status = 0;

exit:
    k_free(pInFilePath);
    k_free(ctx);

    fs_close(&file);
    return status;
}
#else

char *zephyr_strdup(const char *s)
{
    size_t len = strlen(s) + 1;
    char *copy = k_malloc(len);
    if (copy) {
        memcpy(copy, s, len);
    }
    return copy;
}


void split_path(const char *full_path, char **dir_path, char **file_name)
{
    struct stat st;
    if (!full_path) {
        *dir_path = NULL;
        *file_name = NULL;
        return;
    }

    /* if the path provided is to a directory, then we know there is no file name */
    if (stat(full_path, &st) == 0 && S_ISDIR(st.st_mode))
    {
        /* It's a directory */
        *dir_path = zephyr_strdup(full_path);
        *file_name = NULL;
        return;
    }

    const char *last_slash = strrchr(full_path, '/');

    if (!last_slash) {
        /* No slash found: assume current directory */
        *dir_path = zephyr_strdup(".");
        *file_name = zephyr_strdup(full_path);
    } else {
        size_t dir_len = last_slash - full_path;
        *dir_path = (char *)k_malloc(dir_len + 1);
        strncpy(*dir_path, full_path, dir_len);
        (*dir_path)[dir_len] = '\0';

        *file_name = zephyr_strdup(last_slash + 1);
    }
}


int copy_file(const char *src_path, const char *dst_path)
{
    char buffer[512];
    size_t bytes;
    FILE *src = fopen(src_path, "rb");

    if (!src) {
        perror("Failed to open source file");
        return -1;
    }

    FILE *dst = fopen(dst_path, "wb");
    if (!dst) {
        perror("Failed to open destination file");
        fclose(src);
        return -1;
    }

    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        fwrite(buffer, 1, bytes, dst);
    }

    fclose(src);
    fclose(dst);
    return 0;
}


static int TRUSTEDGE_SAMPLE_actionHandler(
    struct TrustEdgeArtifactAction *pAction,
    char *pFile
)
{
    int status = -1;
    char *pInFilePath = NULL;
    char *pDestDir = NULL;
    char *pDestFileName = NULL;
    char *pDestFileDir = NULL;
    char *pDestFilePath = NULL;
    char *pBasePath = NULL; /* this will be mount plus pFile path */ 
    char *pDestBasePath = NULL;

    struct stat st;

    if (NULL == pAction || NULL == pFile)
    {
        goto exit;
    }
    printk("pFile = %s\n", pFile);

    if (NULL == pAction->pActionPath)
    {
        printk("no file path found\n");
        goto exit;
    }

    /* TODO: server does not support creating update packages of type "text",
             when added to surver we want to add the check. */
    if (pAction->handler.type    != TE_ACTION_HANDLER_SCRIPT)
    /* if (pAction->handler.type    != TE_ACTION_HANDLER_SCRIPT ||
        pAction->handler.subtype != TE_ACTION_HANDLER_SUBTYPE_TEXT) */
    {
        printk("unsupported handler type/subytype\n");
        goto exit;
    }

    if (TE_ACTION_INSTALL == pAction->type)
    {

        if (NULL == pAction->pActionArgument)
        {
            printk("no file destination found\n");
            goto exit;
        }

        /* prefix mount point to file path to get full path */
        pBasePath = concat_with_slash(mount_point, pFile);
        if (NULL == pBasePath)
        {
            goto exit;
        }

        pInFilePath = concat_with_slash(pBasePath, pAction->pActionPath);
        if (NULL == pInFilePath)
        {
            goto exit;
        }

        if (0 != stat(pInFilePath, &st))
        {
            printk("file not found: %s\n", pInFilePath);
            goto exit;
        }

        /* pInFilePath is the absolute path to the file we want to copy to system */
        pDestBasePath = concat_with_slash(mount_point, pAction->pActionArgument);
        if (NULL == pDestBasePath)
        {
            goto exit;
        }

        split_path(pDestBasePath, &pDestDir, &pDestFileName);
        if (NULL == pDestDir)
        {
            goto exit;
        }

        /* pDestFileName is either NULL, "", or the file name we want for destination file */

        if (0 != stat(pDestDir, &st))
        {
            printk("directory not found: %s\n", pDestDir);
            goto exit;
        }

        if (NULL == pDestFileName || 0 == strlen(pDestFileName))
        {
            /* get name of in file to use as destination file name since no file
             * name was specified */
            k_free(pDestFileName);
            split_path(pInFilePath, &pDestFileDir, &pDestFileName);
            if (NULL == pDestFileDir || NULL == pDestFileName)
            {
                goto exit;
            }

            k_free(pDestFileDir); /* not used */

            pDestFilePath = concat_with_slash(pDestDir, pDestFileName);
            if (NULL == pDestFilePath)
            {
                status = -1;
                goto exit;
            }
        }
        else {

            pDestFilePath = concat_with_slash(mount_point, pAction->pActionArgument);
            if (NULL == pDestFilePath)
            {
                goto exit;
            }
        }

        status = copy_file(pInFilePath, pDestFilePath);
        if (0 != status)
        {
            goto exit;
        }

        printk("File %s has been copied to %s\n", pInFilePath, pDestFilePath);
    }
    else if (TE_ACTION_ROLLBACK == pAction->type)
    {
        printk("we are deleting %s file\n", pAction->pActionArgument);
        pDestBasePath = concat_with_slash(mount_point, pAction->pActionArgument);
        if (NULL == pDestBasePath)
        {
            goto exit;
        }

        if (0 != stat(pDestBasePath, &st))
        {
            printk("file not found: %s\n", pDestBasePath);
            goto exit;
        }

        status = FMGMT_remove(pDestBasePath, FALSE);
        if (0 != status)
        {
            printk("Failed to delete file\n");
            goto exit;
        }

        printk("Successfully removed %s\n", pDestBasePath);
    }
    else
    {
        status = ERR_TRUSTEDGE_AGENT;
        goto exit;
    }

exit:
    k_free(pDestFilePath);
    k_free(pInFilePath);
    k_free(pDestDir);
    k_free(pDestFileName);
    k_free(pDestBasePath);

    return status;
}
#endif

/* shell command */
K_SEM_DEFINE(startTrustedge, 0, 1);
atomic_t cmdType = ATOMIC_INIT(0); // 0 == normal flow, 1 == reboot

static int cmd_trustedge_start(const struct shell *sh, size_t argc, char **argv)
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

static int cmd_trustedge_reset(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(sh);
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
    atomic_set(&cmdType, 2);
    k_sem_give(&startTrustedge);
    return 0;
}

static int cmd_trustedge_confirm(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(sh);
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
    atomic_set(&cmdType, 3);
    k_sem_give(&startTrustedge);
    return 0;
}

static int cmd_trustedge_uninit(const struct shell *sh, size_t argc, char **argv)
{
    ARG_UNUSED(sh);
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);
#ifdef __ENABLE_DIGICERT_STACK_PROFILE__
    atomic_set(&stackLoop, 0);
#endif
    atomic_set(&cmdType, 4);
    k_sem_give(&startTrustedge);
    return 0;
}

static int cmd_trustedge_state(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(sh);
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
    switch(TRUSTEDGE_getState()) {
        case UNKNOWN:
            printk("TrustEdge status: UNKNOWN\n");
            break;
        case CONNECTED:
            printk("TrustEdge state: CONNECTED\n");
            break;
        case PROCESSING_POLICY:
            printk("TrustEdge state: PROCESSING_POLICY\n");
            break;
        case DISCONNECTED:
            printk("TrustEdge state: DISCONNECTED\n");
            break;
    };
    return 0;
}

static int cmd_trustedge_status(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(sh);
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
    switch(TRUSTEDGE_getStatus()) {
        case PREINSTALL:
            printk("TrustEdge status: PREINSTALL\n");
            break;
        case INSTALLED:
            printk("TrustEdge status: INSTALLED\n");
            break;
        case PROVISIONED:
            printk("TrustEdge status: PROVISIONED\n");
            break;
    };
    return 0;
}

#if defined(__ENABLE_DIGICERT_MEM_PROFILE__) || defined(__ENABLE_DIGICERT_STACK_PROFILE__)
#define BUFFER_SIZE 4096
static ubyte pBuffer[BUFFER_SIZE] = {0};
static int cmd_trustedge_send_file(const struct shell *sh, size_t argc, char **argv)
{
    char pIpAddr[16] = {0};
    unsigned int ret = 0;
    ubyte2 port = 0;
    int status = ERR_GENERAL;
    char *pFile = NULL;
    FileDescriptor pFileCtx = NULL;
    unsigned int bytesRead = 0;
    TCP_SOCKET serverSocket;

    if (argc < 2) {
        shell_error(sh, "Usage: trustedge send <file> <destination> <port>");
        return -EINVAL;
    }

    pFile = argv[1];
    memcpy(pIpAddr, argv[2], strlen(argv[2]));
    printk("connecting to IP Addr: %s\n", (char *) pIpAddr);

    port = (ubyte2) atoi(argv[3]);

    status = TCP_CONNECT(&serverSocket, pIpAddr, port);
    if (0 != status) {
        printk("TCP_CONNECT:error: %d\n", status);
        goto exit;
    }

    printk("Connected to server\n");

    status = FMGMT_fopen(pFile, "r", &pFileCtx);
    if (0 != status) {
        printk("FMGMT_fopen:error: %d\n", status);
        goto exit;
    }

    do {
        status = FMGMT_fread(pBuffer, 1, BUFFER_SIZE, pFileCtx, &bytesRead);
        if (0 != status) {
            printk("FMGMT_fread:error: %d\n", status);
            goto exit;
        }

        if (bytesRead == 0 || status != 0) {
            break;
        }

        TCP_WRITE(serverSocket, pBuffer, bytesRead, &ret);
    } while (ret > 0);

    FMGMT_fclose(&pFileCtx);
    printk("File sent successfully\n");
exit:

    (void) TCP_CLOSE_SOCKET(serverSocket);
    return 0;
}
#endif

SHELL_STATIC_SUBCMD_SET_CREATE(sub_demo,
	SHELL_CMD(start, NULL, "Run TrustEdge.", cmd_trustedge_start),
	SHELL_CMD(state, NULL, "Show TrustEdge state.", cmd_trustedge_state),
	SHELL_CMD(status, NULL, "Show TrustEdge status.", cmd_trustedge_status),
	SHELL_CMD(reboot, NULL, "reboot device.", cmd_trustedge_reboot),
	SHELL_CMD(reset, NULL, "reset file system.", cmd_trustedge_reset),
	SHELL_CMD(confirm, NULL, "confirm image.", cmd_trustedge_confirm),
	SHELL_CMD(uninit, NULL, "Uninitialize TrustEdge.", cmd_trustedge_uninit),
#if defined(__ENABLE_DIGICERT_MEM_PROFILE__) || defined(__ENABLE_DIGICERT_STACK_PROFILE__)
	SHELL_CMD(send, NULL, "Send log file to a server.", cmd_trustedge_send_file),
#endif
	SHELL_SUBCMD_SET_END /* Array terminated. */
);
SHELL_CMD_REGISTER(trustedge, &sub_demo, "Demo commands", NULL);

int runTrustedge(void)
{
    int status = -1;
    /* RTOS_THREAD trustedgeTid = RTOS_THREAD_INVALID; */
    enum TrustedgeStatus trustedgeStatus;

    trustedgeStatus = TRUSTEDGE_getStatus();
    if (PREINSTALL == trustedgeStatus)
    {
        printk("%s\n", "status: PREINSTALL");
    }
    else if(INSTALLED == trustedgeStatus)
    {
        printk("%s\n", "status: INSTALLED");
    }
    else if(PROVISIONED == trustedgeStatus)
    {
        printk("%s\n", "status: PROVISIONED");
    }

#if !defined(__ENABLE_DIGICERT_NATIVE_SIM__)
    TRUSTEDGE_registerDNSLookupCallback(startDnsLookup);
#endif
    TRUSTEDGE_registerUpdateActionHandlerCallback(TRUSTEDGE_SAMPLE_actionHandler);

    TRUSTEDGE_launchWrapper((void *)(uintptr_t)LAUNCH_AND_EXIT);
    status = 0;

    return status;
}
/* end shell command */

#ifdef CONFIG_THREAD_MONITOR
static void count_thread_cb(const struct k_thread *thread, void *user_data)
{
    int *count = (int *)user_data;
    (*count)++;

    printk("Thread: %p, name: %s\n", thread, k_thread_name_get((struct k_thread *)thread));
}

void print_thread_count(void) {
    int count = 0;
    k_thread_foreach(count_thread_cb, &count);
    printk("Active threads: %d\n", count);
}
#endif

int main()
{
    int status;

#if CONFIG_THREAD_MONITOR
    print_thread_count();
#endif

    setup_fs(mount_point);

#if defined(__ENABLE_DIGICERT_CUSTOM_MALLOC__)
    printk("initializing custom heap\n");
    status = DIGICERT_initCustomHeap(heap_buffer, CUSTOM_HEAP_SIZE);
    if (0 != status)
        goto exit;
#endif

    status = TRUSTEDGE_setMountPoint(mount_point);
    if (0 != status)
        goto exit;

    printk("image name: %s\n", IMAGE_NAME);
#ifdef __ENABLE_DIGICERT_BOOTLOADER_SUPPORT__
    printk("bootloader: enabled\n");
#else
    printk("bootloader: disabled\n");
#endif

#if defined(CONFIG_LOG_BACKEND_FS) && !defined(CONFIG_LOG_BACKEND_FS_AUTOSTART)
    k_msleep(2000);
#endif

#if defined(CONFIG_LOG_BACKEND_FS) && !defined(CONFIG_LOG_BACKEND_FS_AUTOSTART)
    if (0 == status)
    {
        const struct log_backend *fs_backend = log_backend_get_by_name("log_backend_fs");
        if (fs_backend) {
            log_backend_enable(fs_backend, fs_backend->cb->ctx, LOG_LEVEL_DBG);
            printk("Filesystem logging enabled\n");
        }
    }
    else
    {
        printk("Could not create log directory, keeping UART only\n");
    }
#endif

#if !defined(__ENABLE_DIGICERT_NATIVE_SIM__)
    dnsLookupTableInit();
#endif

    /* call digicert init */
    status = TRUSTEDGE_init();
    if (0 != status)
        goto nocleanup;

    while(1)
    {
        k_sem_take(&startTrustedge, K_FOREVER);
        switch(atomic_get(&cmdType)) {
            case 0:
                status = runTrustedge();
                if (0 != status)
                {
                    printk("runTrustedge failed: %d\n", status);
                }
                printk("trustedge finished running: %d\n", status);
#ifdef __ENABLE_DIGICERT_STACK_PROFILE__
                print_stacks_info(&g_stacks_data);
#endif
                break;
            case 1:
#ifdef __ENABLE_DIGICERT_BOOTLOADER_SUPPORT__
                printk("reboot device\n");
                sys_reboot(SYS_REBOOT_COLD);
#endif
                break;
            case 2:
                (void) FMGMT_remove("etc/digicert/trustedge.json", TRUE);
                (void) FMGMT_remove("etc/digicert", TRUE);
                (void) FMGMT_remove("etc/", TRUE);
                (void) FMGMT_remove("allocation_history.txt", TRUE);
                (void) FMGMT_remove("stackmon.txt", TRUE);
                (void) FMGMT_remove("filesystem.zip", TRUE);
                (void) FMGMT_remove("bootstrap.zip", TRUE);
                (void) FMGMT_remove("tmp", TRUE);
                (void) FMGMT_mkdir("tmp", 0775);

                (void) FMGMT_remove("log", TRUE);
                (void) FMGMT_mkdir("log", 0775);
                printk("reset done.\n");
                break;
            case 3:
#ifdef __ENABLE_DIGICERT_BOOTLOADER_SUPPORT__
                confirmImage(NULL);
                printk("confirm image\n");
#else
                printk("confirm image not supported\n");
#endif
                break;
            case 4:
                printk("\nstop monitoring\n");
                TRUSTEDGE_deinit();
                break;
            default:
                break;
        }
    }

exit:
    TRUSTEDGE_deinit();
nocleanup:
    return 0;
}
