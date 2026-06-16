/*
 * Copyright (c) 2019 Jan Van Winkel <jan.van_winkel@dxplore.eu>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
#define LOG_LEVEL CONFIG_LOG_DEFAULT_LEVEL
LOG_MODULE_REGISTER(app, LOG_LEVEL_DBG);

#include <zephyr/fs/fs.h>
#include <zephyr/fs/littlefs.h>
#include <zephyr/storage/flash_map.h>

#define STORAGE_PARTITION	fs_partition
#define STORAGE_PARTITION_ID	FIXED_PARTITION_ID(STORAGE_PARTITION)

FS_LITTLEFS_DECLARE_DEFAULT_CONFIG(lfs_data);
static struct fs_mount_t littlefs_mnt = {
    .type = FS_LITTLEFS,
    .fs_data = &lfs_data,
    .storage_dev = (void *)STORAGE_PARTITION_ID,
};

static void get_partition_size(const char *mount_point)
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

static void setup_fs(char *mnt_pnt) {
    int ret;

    ret = cmd_mount_littlefs(mnt_pnt);
    if (ret != 0)
    {
        printk("cmd_mount_littlefs:error: %d\n", ret);
        goto exit;
    }

    get_partition_size(mnt_pnt);
exit:
    return;
}

int main(void)
{
	char *mount_point = "/lfs1";

	setup_fs(mount_point);
	return 0;
}
