#include <zephyr/logging/log.h>
#define LOG_LEVEL CONFIG_LOG_DEFAULT_LEVEL
LOG_MODULE_REGISTER(app, LOG_LEVEL_DBG);

#ifndef __RTOS_ZEPHYR__
#define __RTOS_LINUX__
#define __RTOS_ZEPHYR__
#endif

#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include <zephyr/kernel.h>
#include <zephyr/linker/sections.h>
#include <zephyr/net/conn_mgr_connectivity.h>
#include <zephyr/net/sntp.h>
#include <zephyr/net/socket.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/shell/shell.h>

#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_context.h>
#include <zephyr/net/net_mgmt.h>
#include <arpa/inet.h>

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
#include "common/mocana.h"

#include <zephyr/fs/fs.h>
#include <zephyr/fs/littlefs.h>
#include <zephyr/logging/log.h>
#include <zephyr/storage/flash_map.h>

/* filesystem information */

#define MAX_PATH_LEN 255
#define MOC_MAX_BYTES_TO_COPY	4096
#define MAX_PATH_LENGTH			64

#include <zephyr/fs/littlefs.h>
#include <zephyr/storage/flash_map.h>

#ifdef __ENABLE_DIGICERT_ESP32S3__
#include <zephyr/shell/shell.h>
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

static sbyte *TRUSTEDGE_Zephyr_mntptPrepare(sbyte *pMntPt)
{
    sbyte *pCpyMntpt;

    pCpyMntpt = k_malloc(strlen(pMntPt) + 1);
    if (pCpyMntpt) {
        strcpy(pCpyMntpt, pMntPt);
    }
    return pCpyMntpt;
}

static MSTATUS TRUSTEDGE_Zephyr_mountLittlefs(sbyte *pMntPt, sbyte4 *pRet)
{
    MSTATUS status = ERR_GENERAL;
    sbyte *pDirMntPt = NULL;
    sbyte4 rc;

    if (littlefs_mnt.mnt_point != NULL) {
        *pRet = -EBUSY;
        goto exit;
    }

    pDirMntPt = TRUSTEDGE_Zephyr_mntptPrepare(pMntPt);
    if (pDirMntPt == NULL) {
        *pRet = -ENOEXEC; /* ?!? */
        goto exit;
    }

    littlefs_mnt.mnt_point = pDirMntPt;

    rc = fs_mount(&littlefs_mnt);
    if (rc != 0) {
        status = ERR_MEM_FREE_PTR;
        *pRet = -ENOEXEC;
        goto exit;
    }

    status = OK;

exit:
    if (status == ERR_MEM_FREE_PTR)
    {
        k_free((void *)littlefs_mnt.mnt_point);
        littlefs_mnt.mnt_point = NULL;
    }

    return status;
}

static MSTATUS TRUSTEDGE_Zephyr_reOpenFile(sbyte *pFile, FileDescriptor *ppCtx)
{
    MSTATUS status = ERR_GENERAL;
    status = FMGMT_fclose(ppCtx);
    if (OK != status)
    {
        LOG_INF("FMGMT_fclose:error: %d\n", status);
        goto exit;
    }

    status = FMGMT_fopen(pFile, "a", ppCtx);
    if (OK != status)
    {
        LOG_INF("FMGMT_fopen:error: %d\n", status);
        goto exit;
    }

    status = OK;

exit:
    return status;
}


static MSTATUS TRUSTEDGE_Zephyr_fileTests(sbyte *pPath, sbyte *pFile, sbyte *pNewFile)
{
    MSTATUS status = ERR_GENERAL;
    FileDescriptor pCtx = NULL;
    sbyte4 bytesWritten = 0;
    sbyte4 bytesRead = 0;
    sbyte buffer[512];
    sbyte4 bufferLen = 512;
    sbyte c;
    sbyte *pInStr = NULL;
    sbyte4 totalLen = 0;

    if (TRUE == FMGMT_pathExists(pFile, NULL))
    {
        status = FMGMT_remove(pFile, FALSE);
    }

    LOG_INF("Creating file %s at path %s\n", pFile, pPath);
    status = FMGMT_fopen(pFile, "w", &pCtx);
    if (OK != status)
    {
        LOG_INF("FMGMT_fopen:error: %d\n", status);
        goto exit;
    }

    LOG_INF("File created successfully\n");
    LOG_INF("---------------------------------------------------\n");
    LOG_INF("Writing text to file %s\n", pFile);
    status = FMGMT_fprintf(pCtx, "%d: %s\n", 42, "forty two");
    if (OK != status)
    {
        LOG_INF("FMGMT_fprintf:error: %d\n", status);
        goto exit;
    }

    bytesWritten = FMGMT_fputs("second line is here\n", pCtx);
    if (bytesWritten <= 0)
    {
        LOG_INF("FMGMT_fputs:error: %d\n", status);
        goto exit;
    }

    LOG_INF("bytesWritten: %d\n", bytesWritten);
    LOG_INF("Text written to file successfuly\n");
    LOG_INF("---------------------------------------------------\n");
    LOG_INF("Closing file %s\n", pFile);

    status = FMGMT_fclose(&pCtx);
    if (OK != status)
    {
        LOG_INF("FMGMT_fclose:error: %d\n", status);
        goto exit;
    }

    LOG_INF("File closed successfully\n");
    LOG_INF("---------------------------------------------------\n");
    LOG_INF("Opening file again %s in read mode\n", pFile);

    status = FMGMT_fopen(pFile, "r", &pCtx);
    if (OK != status)
    {
        LOG_INF("FMGMT_fopen:error: %d\n", status);
        goto exit;
    }

    LOG_INF("File opened successfully\n");
    LOG_INF("---------------------------------------------------\n");
    LOG_INF("Reading and writing file\n");
    pInStr = FMGMT_fgets(buffer, bufferLen, pCtx);
    if (NULL == pInStr)
    {
        status = ERR_NULL_POINTER;
        LOG_INF("FMGMT_fgets:error: %d\n", status);
        goto exit;
    }

    LOG_INF("First string: %s", pInStr);

    c = FMGMT_fgetc(pCtx);
    LOG_INF("First char : %c\n", c);

    status = TRUSTEDGE_Zephyr_reOpenFile(pFile, &pCtx);
    if (OK != status)
    {
        LOG_INF("TRUSTEDGE_Zephyr_reOpenFile:error: %d\n", status);
        goto exit;
    }

    status = FMGMT_fwrite ("this is the third line\n", 1, 23, pCtx, &bytesWritten);
    if (OK != status)
    {
        LOG_INF("FMGMT_fwrite:error: %d\n", status);
        goto exit;
    }

    status = TRUSTEDGE_Zephyr_reOpenFile(pFile, &pCtx);
    if (OK != status)
    {
        LOG_INF("TRUSTEDGE_Zephyr_reOpenFile:error: %d\n", status);
        goto exit;
    }

    LOG_INF("before seek: MSEEK_END = %d\n", MSEEK_END);
    status = FMGMT_fseek(pCtx, 0, 2);
    if (OK != status)
    {
        LOG_INF("FMGMT_fseek:error: %d\n", status);
        goto exit;
    }

    status = FMGMT_ftell(pCtx, &totalLen);
    if (OK != status)
    {
        LOG_INF("FMGMT_ftell:error: %d\n", status);
        goto exit;
    }

    LOG_INF("Total length of file: %d\n", totalLen);

    status = TRUSTEDGE_Zephyr_reOpenFile(pFile, &pCtx);
    if (OK != status)
    {
        LOG_INF("TRUSTEDGE_Zephyr_reOpenFile:error: %d\n", status);
        goto exit;
    }

    status = FMGMT_fread (buffer, 1, totalLen, pCtx, &bytesRead);
    if (OK != status)
    {
        LOG_INF("FMGMT_fread:error: %d\n", status);
        goto exit;
    }

    LOG_INF("File contents: %s\n", buffer);

    LOG_INF("File read and written successfully\n");
    LOG_INF("---------------------------------------------------\n");
    LOG_INF("Renaming file %s to %s\n", pFile, pNewFile);

    status = FMGMT_rename(pFile, pNewFile);
    if (OK != status)
    {
        LOG_INF("FMGMT_rename:error: %d\n", status);
        goto exit;
    }

    LOG_INF("File renamed successfully\n");
    LOG_INF("---------------------------------------------------\n");

    status = OK;
exit:
    if (NULL != pCtx)
    {
        status = FMGMT_fflush(pCtx);
        if (OK != status)
        {
            LOG_INF("FMGMT_fflush:error: %d\n", status);
        }

        status = FMGMT_fclose(&pCtx);
        if (OK != status)
        {
            LOG_INF("FMGMT_fopen:error: %d\n", status);
        }
    }

    return status;
}

static MSTATUS TRUSTEDGE_Zephyr_directoryTests(sbyte *pPath)
{
    MSTATUS status = ERR_GENERAL;
    DirectoryDescriptor pDirDesc = NULL;
    DirectoryEntry dirEnt = {0};

    LOG_INF("Enumerating files in dir %s\n", pPath);
    status = FMGMT_getFirstFile(pPath, &pDirDesc, &dirEnt);
    if (OK != status)
    {
        LOG_INF("FMGMT_getFirstFile:error: %d\n", status);
        goto exit;
    }

    do {
        if (FTFile == dirEnt.type)
        {
            LOG_INF("file found, ");
        }
        else if (FTDirectory == dirEnt.type)
        {
            LOG_INF("directory found, \n");
        }
        else if (FTNone == dirEnt.type)
        {
            LOG_INF("directory empty\n");
            goto exit;
        }

        LOG_INF("name: %s\n", dirEnt.pName);

        /* Need to clear dirEnt.pName before calling FMGMT_getNextFile */
        if (NULL != dirEnt.pName)
        {
            DIGI_FREE((void **) &dirEnt.pName);
        }
        status = FMGMT_getNextFile(pDirDesc, &dirEnt);
        if (OK != status)
        {
            LOG_INF("FMGMT_getNextFile:error: %d\n", status);
            goto exit;
        }
    } while (FTNone != dirEnt.type);

    LOG_INF("Enumerating files completed successfully\n");
    LOG_INF("---------------------------------------------------\n");

    status = OK;

exit:
    if (NULL != pDirDesc)
    {
        status = FMGMT_closeDir(&pDirDesc);
        if (OK != status)
        {
            LOG_INF("FMGMT_closeDir:error: %d\n", status);
        }
    }

    return status;
}

static MSTATUS TRUSTEDGE_Zephyr_commonUtilsMocanaWrapperTests(sbyte *pFile, sbyte *pNewFile)
{
    MSTATUS status = ERR_GENERAL;
    ubyte *pBuffer = NULL;
    ubyte4 bufferLen = 0;
    ubyte *pData = "test data";
    ubyte *pNewData = "\nsome more important data";
    sbyte4 len = 0;
    sbyte pFileNameBuffer[MAX_PATH_LENGTH] = {0};
    intBoolean fileExists = FALSE;

    LOG_INF("Reading file %s\n", pFile);
    status = DIGICERT_readFile(pFile, &pBuffer, &bufferLen);
    if (OK != status)
    {
        LOG_INF("DIGICERT_readFile:error: %d\n", status);
        goto exit;
    }

    LOG_INF("\nFile Data: %s\n", pBuffer);

    LOG_INF("File read successfully\n");
    LOG_INF("---------------------------------------------------\n");
    LOG_INF("Deleting file %s\n", pFile);

    status = DIGICERT_deleteFile(pFile);
    if (OK != status)
    {
        LOG_INF("DIGICERT_deleteFile:error: %d\n", status);
        goto exit;
    }

    LOG_INF("File deleted successfully\n");
    LOG_INF("---------------------------------------------------\n");
    LOG_INF("Creating new file %s\n", pFile);

    status = DIGICERT_writeFile(pFile, pData, DIGI_STRLEN(pData));
        if (OK != status)
    {
        LOG_INF("DIGICERT_writeFile:error: %d\n", status);
        goto exit;
    }

    LOG_INF("File created successfully with data: %s\n", pData);
    LOG_INF("---------------------------------------------------\n");
    LOG_INF("Copying file %s to %s\n", pFile, pNewFile);

    status = DIGICERT_copyFile(pFile, pNewFile);
    if (OK != status)
    {
        LOG_INF("DIGICERT_copyFile:error: %d\n", status);
        goto exit;
    }

    LOG_INF("File copied successfully\n");
    LOG_INF("---------------------------------------------------\n");
    LOG_INF("Check if file %s exists\n", pNewFile);

    len = DIGI_STRLEN (pNewFile) - 4;
    status = DIGI_MEMCPY (pFileNameBuffer, pNewFile, len);
    if (OK != status)
    {
        LOG_INF("DIGI_MEMCPY:error: %d\n", status);
        goto exit;
    }

    pFileNameBuffer[len] = '\0';

    status = DIGICERT_checkFile(pFileNameBuffer, ".txt", &fileExists);
    if (OK != status)
    {
        LOG_INF("DIGICERT_checkFile:error: %d\n", status);
        goto exit;
    }

    if (FALSE == fileExists)
    {
        status = ERR_FILE_NOT_EXIST;
        goto exit;
    }

    LOG_INF("File searched successfully\n");
    LOG_INF("---------------------------------------------------\n");
    LOG_INF("Appending data to file %s\n", pFile);

    status = DIGICERT_appendFile(pFile, pNewData, DIGI_STRLEN(pNewData));
    if (OK != status)
    {
        LOG_INF("DIGICERT_appendFile:error: %d\n", status);
        goto exit;
    }

    LOG_INF("Appended data successfully\n");

    DIGI_FREE ((void **) &pBuffer);
    status = DIGICERT_readFile(pFile, &pBuffer, &bufferLen);
    if (OK != status)
    {
        LOG_INF("DIGICERT_readFile:error: %d\n", status);
        goto exit;
    }

    LOG_INF("\nFile Data: %s\n", pBuffer);
    LOG_INF("---------------------------------------------------\n");
    LOG_INF("Appending data to new file %s\n", pFile);
    LOG_INF("Deleting old file %s\n", pFile);

    status = DIGICERT_deleteFile(pFile);
    if (OK != status)
    {
        LOG_INF("DIGICERT_deleteFile:error: %d\n", status);
        goto exit;
    }

    LOG_INF("Old file deleted successfully\n");

    status = DIGICERT_appendFile(pFile, pNewData, DIGI_STRLEN(pNewData));
    if (OK != status)
    {
        LOG_INF("DIGICERT_appendFile:error: %d\n", status);
        goto exit;
    }

    LOG_INF("Created file and appended data successfully\n");

    if (NULL != pBuffer)
    {
        status = DIGICERT_freeReadFile(&pBuffer);
        if (OK != status)
        {
            LOG_INF("DIGICERT_freeReadFile:error: %d\n", status);
            goto exit;
        }
    }

    status = DIGICERT_readFile(pFile, &pBuffer, &bufferLen);
    if (OK != status)
    {
        LOG_INF("DIGICERT_readFile:error: %d\n", status);
        goto exit;
    }

    LOG_INF("\nFile Data: %s\n", pBuffer);

    status = OK;
exit:

    if (NULL != pBuffer)
    {
        status = DIGICERT_freeReadFile(&pBuffer);
        if (OK != status)
        {
            LOG_INF("DIGICERT_freeReadFile:error: %d\n", status);
        }
    }
    return status;
}
/* end of file functions */

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

    LOG_INF("Total partition size: %llu bytes\n", total_size);
    LOG_INF("Available size: %llu bytes\n", available_size);
}

#define ZEPHYR_PORT             7290
#define BUFFER_SIZE             1024

typedef enum _ThreadType {
    SERVER,
    CLIENT
} ThreadType;

typedef struct _ThreadArgs {
     ThreadType threadType;
} ThreadArgs;

static MSTATUS TRUSTEDGE_Zephyr_tcpServer(TCP_SOCKET listenSocket, TCP_SOCKET clientSocket)
{
    MSTATUS status = ERR_GENERAL;
    sbyte pPayload[BUFFER_SIZE] = {0};
    intBoolean needToDie = FALSE;
    ubyte4 received = 0;
    ubyte4 nRet = 0;

#if defined(__DIGICERT_SAMPLE_NATIVE_SIM__)
    status = TCP_LISTEN_SOCKET_LOCAL(&listenSocket, ZEPHYR_PORT);
    if (OK != status)
    {
        LOG_INF("TCP_LISTEN_SOCKET_LOCAL:error: %d\n", status);
        goto exit;
    }

    LOG_INF("Server listening on [localhost:%d]\n", ZEPHYR_PORT);
    LOG_INF("Run command \"nc 127.0.0.1 %d\" to connect to server\n", ZEPHYR_PORT);
#else
    status = TCP_LISTEN_SOCKET(&listenSocket, ZEPHYR_PORT);
    if (OK != status)
    {
        LOG_INF("TCP_LISTEN_SOCKET:error: %d\n", status);
        goto exit;
    }

    LOG_INF("Server listening on port %d\n", ZEPHYR_PORT);
#endif

    status = TCP_ACCEPT_SOCKET(&clientSocket, listenSocket, &needToDie);
    if (OK != status)
    {
        LOG_INF("TCP_ACCEPT_SOCKET:error: %d\n", status);
        goto exit;
    }

    LOG_INF("\nClient connection accepted\n");
    LOG_INF("Waiting for data from client...\n");

    status = TCP_READ_AVL(clientSocket, pPayload, BUFFER_SIZE, &received, TCP_NO_TIMEOUT);
    if (OK != status)
    {
        LOG_INF("TCP_READ_AVL:error: %d\n", status);
        goto exit;
    }

    pPayload[received] = '\0';
    LOG_INF("Message received from client: %s\n", pPayload);

    LOG_INF("Waiting for data from client...\n");

    status = TCP_READ_AVL_EX(clientSocket, pPayload, BUFFER_SIZE, &nRet, TCP_NO_TIMEOUT);
    if (ERR_TCP_READ_TIMEOUT == status)
    {
        status = OK;
    }

    pPayload[nRet] = '\0';

    if (OK != status)
    {
        LOG_INF("TCP_READ_AVL_EX:error: %d\n", status);
        goto exit;
    }

    LOG_INF("Message received from client: %s\n", pPayload);
    status = OK;

exit:
    return status;
}

static MSTATUS TRUSTEDGE_Zephyr_tcpClient(TCP_SOCKET serverSocket, ubyte2 port)
{
    MSTATUS status = ERR_GENERAL;
    sbyte pIpAddr[40] = {0};
    ubyte4 nRet = 0;
    sbyte *pMsg = "Hello Server!\n";
    k_timeout_t timeout = K_MSEC(5000);

#if defined(CONFIG_NET_CONFIG_PEER_IPV4_ADDR)
    memcpy(pIpAddr, CONFIG_NET_CONFIG_PEER_IPV4_ADDR, strlen(CONFIG_NET_CONFIG_PEER_IPV4_ADDR));
#else
    status = TCP_GETHOSTBYNAME("localhost", pIpAddr);
    if (OK != status)
    {
        LOG_INF("TCP_GETHOSTBYNAME:error: %d\n", status);
        goto exit;
    }
#endif /* CONFIG_NET_CONFIG_PEER_IPV4_ADDR */

    LOG_INF("connecting to IP Addr: %s\n", pIpAddr);
#if defined(__DIGICERT_SAMPLE_NATIVE_SIM__)
    LOG_INF("Run command \"nc -lp %d\" to create a server\n", port);
#endif

    do
    {
        status = TCP_CONNECT(&serverSocket, pIpAddr, port);
        k_sleep(timeout);
    } while (OK != status);

    TCP_WRITE(serverSocket, pMsg, DIGI_STRLEN((sbyte *)pMsg), &nRet);

    LOG_INF("Msg sent to server successfully\n");

    status = OK;

#if !defined(CONFIG_NET_CONFIG_PEER_IPV4_ADDR)
exit:
#endif
    return status;
}

static void *TRUSTEDGE_threadStart(void *pArg)
{
    MSTATUS status = ERR_GENERAL;
    TCP_SOCKET listenSocket = -1;
    TCP_SOCKET clientSocket = -1;
    TCP_SOCKET serverSocket = -1;
    ThreadArgs *pStruct = (ThreadArgs *)pArg;

    switch(pStruct->threadType)
    {
        case SERVER:
            LOG_INF("\nRunning in server mode\n");
            LOG_INF("***************************\n");
            status = TRUSTEDGE_Zephyr_tcpServer(listenSocket, clientSocket);
            if (OK != status)
            {
                LOG_INF("TRUSTEDGE_Zephyr_tcpServer:error: %d\n", status);
                goto exit;
            }

            LOG_INF("exit_status from server thread: %d\n", status);
            break;

        case CLIENT:
            LOG_INF("\nRunning in client mode\n");
            LOG_INF("***************************\n");
            status = TRUSTEDGE_Zephyr_tcpClient(serverSocket, ZEPHYR_PORT + 1);
            if (OK != status)
            {
                LOG_INF("TRUSTEDGE_Zephyr_tcpClient:error: %d\n", status);
                goto exit;
            }

            LOG_INF("exit_status from client thread: %d\n", status);
            break;

        default:
            LOG_INF("Neither a client nor a server\n");
    };

    status = OK;

exit:
    (void) TCP_CLOSE_SOCKET(listenSocket);
    (void) TCP_CLOSE_SOCKET(clientSocket);
    (void) TCP_CLOSE_SOCKET(serverSocket);
    return NULL;
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

static int cmd_trustedge_compare(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(sh);
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
    atomic_set(&cmdType, 2);
    k_sem_give(&startTrustedge);
    return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_demo,
	SHELL_CMD(update, NULL, "run test sample.", cmd_trustedge_update),
	SHELL_CMD(reboot, NULL, "reboot device.", cmd_trustedge_reboot),
	SHELL_CMD(comp, NULL, "compare binaries.", cmd_trustedge_compare),
	SHELL_SUBCMD_SET_END /* Array terminated. */
);
SHELL_CMD_REGISTER(trustedge, &sub_demo, "Demo commands", NULL);
/* end shell command */

#define TEST_PAYLOAD_FILE "test_payload.zip"
static sbyte *g_DownloadFile = TEST_PAYLOAD_FILE;
static sbyte *g_DownloadFile1 = "/lfs1/test_payload.zip";
#define TRUSTEDGE_TCP_SERVER_PORT   8080
#define BUFFER_SIZE                 1024

static MSTATUS TRUSTEDGE_tcpDownloadBin(TCP_SOCKET serverSocket, ubyte2 port, sbyte *pFilename)
{
    MSTATUS status = ERR_GENERAL;
    sbyte pPayload[BUFFER_SIZE] = {0};
    //sbyte pIpAddr[40] = {0};
    sbyte *pIpAddr = "172.18.209.115";
    ubyte4 nRet = 0;
    sbyte4 bytesWritten = 0;
    sbyte4 numBytesSent = 0;
    k_timeout_t timeout = K_MSEC(2000);
    FileDescriptor pCtx = NULL;
    int totalBytes = 0;
    intBoolean freeFile = FALSE;

#if 0
    status = TRUSTEDGE_utilsGetHostByName("provision.digicert.com", pIpAddr);
    if (OK != status)
    {
        LOG_ERR("failed to get ip address of provision.digicert.com, status=%d\n", status);
        goto exit;
    }
#endif

    do
    {
        k_sleep(timeout);
        status = TCP_CONNECT(&serverSocket, pIpAddr, port);
    } while (OK != status);

    if (0 == DIGI_STRCMP(pFilename, "bin"))
    {
        LOG_INF("opening.. %s\n", g_DownloadFile);
        status = FMGMT_fopen(g_DownloadFile, "wb", &pCtx);
        if (OK != status)
        {
            goto exit;
        }
        freeFile = TRUE;
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

    LOG_INF("firmware downloaded successfully\n");
    status = OK;

exit:
    if (freeFile == TRUE)
    {
        FMGMT_fclose(&pCtx);
    }

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

/* tests */
static MSTATUS fileSystemTests(void)
{
    MSTATUS status = ERR_GENERAL;
    sbyte *pDir = "/lfs1";
    sbyte *pSubDir = "newdir";
    sbyte *pFile = "newfile.txt";
    sbyte pFDPath[MAX_PATH_LENGTH] = {'/'};
    sbyte pNewFDPath[MAX_PATH_LENGTH] = {0};
    sbyte4 ret;
    sbyte cwd[MAX_PATH_LENGTH];
    sbyte *pNewFile = "digifile.txt";
    sbyte *pCopyFile = "mocfile.txt";
#if defined(__DIGICERT_SAMPLE_NATIVE_SIM__)
    const sbyte *pVarName = "ZEPH_TEST_ENV";
    sbyte *pRetrievedValue = NULL;
#endif

    LOG_INF("TEST1: Mounting dir: %s\n", pDir);
    status = TRUSTEDGE_Zephyr_mountLittlefs(pDir, &ret);
    if (status != OK)
    {
        LOG_INF("TRUSTEDGE_Zephyr_mountLittlefs:error: %d\n", ret);
        goto exit;
    }

    status = FMGMT_setMountPoint(pDir);
    if (OK != status)
    {
        LOG_INF("FMGMT_setMountPoint:error: %d\n", status);
        goto exit;
    }

    LOG_INF("TEST1: Directory mounted successfully\n");
    LOG_INF("\n***************************************************\n");
    LOG_INF("TEST2: Creating new dir %s and changing into new dir...\n", pSubDir);

    if (TRUE == FMGMT_pathExists(pSubDir, NULL))
    {
        status = FMGMT_remove(pSubDir, TRUE);
    }

    status = FMGMT_mkdir(pSubDir, 0);
    if (OK != status)
    {
        LOG_INF("FMGMT_mkdir:error: %d\n", status);
        goto exit;
    }

    status = DIGI_MEMCPY(pFDPath + 1, pSubDir, DIGI_STRLEN(pSubDir));
    if (OK != status)
    {
        LOG_INF("DIGI_MEMCPY:error: %d\n", status);
        goto exit;
    }

    status = FMGMT_changeCWD(pFDPath);
    if (OK != status)
    {
        LOG_INF("FMGMT_changeCWD:error: %d\n", status);
        goto exit;
    }

    status = FMGMT_getCWD(cwd, MAX_PATH_LENGTH);
    if (OK != status)
    {
        LOG_INF("FMGMT_getCWD:error: %d\n", status);
        goto exit;
    }

    LOG_INF("TEST2: CWD: %s\n", cwd);
    LOG_INF("\n***************************************************\n");
    LOG_INF("TEST3: Testing file operations\n");

    status = TRUSTEDGE_Zephyr_fileTests(pSubDir, pFile, pNewFile);
    if (OK != status)
    {
        LOG_INF("TRUSTEDGE_Zephyr_fileTests:error: %d\n", status);
        goto exit;
    }

    LOG_INF("TEST3: File operations completed successfully\n");
    LOG_INF("\n***************************************************\n");
    LOG_INF("TEST4: Testing dir operations\n");

    status = FMGMT_changeCWD("/");
    if (OK != status)
    {
        LOG_INF("FMGMT_changeCWD:error: %d\n", status);
        goto exit;
    }

    status = TRUSTEDGE_Zephyr_directoryTests(pSubDir);
    if (OK != status)
    {
        LOG_INF("TRUSTEDGE_Zephyr_directoryTests:error: %d\n", status);
        goto exit;
    }

    LOG_INF("TEST4: Dir operations completed successfully\n");
    LOG_INF("\n***************************************************\n");
    LOG_INF("TEST5: Testing common utils apis\n");

    status = DIGI_MEMCPY(pFDPath, pSubDir, DIGI_STRLEN(pSubDir));
    if (OK != status)
    {
        LOG_INF("DIGI_MEMCPY:error: %d\n", status);
        goto exit;
    }

    pFDPath[DIGI_STRLEN(pSubDir)] = '/';
    status = DIGI_MEMCPY(pFDPath + DIGI_STRLEN(pSubDir) + 1, pNewFile, DIGI_STRLEN(pNewFile));
    if (OK != status)
    {
        LOG_INF("DIGI_MEMCPY:error: %d\n", status);
        goto exit;
    }

    pFDPath[DIGI_STRLEN(pSubDir) + 1 + DIGI_STRLEN(pNewFile)] = '\0';

    status = DIGI_MEMCPY(pNewFDPath, pSubDir, DIGI_STRLEN(pSubDir));
    if (OK != status)
    {
        LOG_INF("DIGI_MEMCPY:error: %d\n", status);
        goto exit;
    }

    pNewFDPath[DIGI_STRLEN(pSubDir)] = '/';
    status = DIGI_MEMCPY(pNewFDPath + DIGI_STRLEN(pSubDir) + 1, pCopyFile, DIGI_STRLEN(pCopyFile));
    if (OK != status)
    {
        LOG_INF("DIGI_MEMCPY:error: %d\n", status);
        goto exit;
    }

    pNewFDPath[DIGI_STRLEN(pSubDir) + 1 + DIGI_STRLEN(pCopyFile)] = '\0';

    status = TRUSTEDGE_Zephyr_commonUtilsMocanaWrapperTests(pFDPath, pNewFDPath);
    if (OK != status)
    {
        LOG_INF("TRUSTEDGE_Zephyr_commonUtilsMocanaWrapperTests:error: %d\n", status);
        goto exit;
    }

#if defined(__DIGICERT_SAMPLE_NATIVE_SIM__)
    setenv("ZEPH_TEST_ENV", "digicert", 1/*overwrite*/);

    LOG_INF("TEST5: Common utils apis tested successfully\n");
    LOG_INF("\n***************************************************\n");
    LOG_INF("TEST6: Testing environment variable api\n");
    status = FMGMT_getEnvironmentVariableValueAlloc (pVarName, &pRetrievedValue);
    if (OK != status)
    {
        LOG_INF("FMGMT_getEnvironmentVariableValueAlloc:error: %d\n", status);
        LOG_INF("Run this command to test this API: \"export ZEPH_TEST_ENV=digicert\"\n");
        goto exit;
    }

    LOG_INF("%s = %s\n", pVarName, pRetrievedValue);
    LOG_INF("TEST6: Environment variable api test successful\n");
    LOG_INF("\n***************************************************\n");
#endif

    status = OK;

exit:
    get_partition_size(pDir);
    return status;
}

static MSTATUS tcpTests(void)
{
    MSTATUS status = ERR_GENERAL;
    ThreadArgs serverArgs = {0};
    ThreadArgs clientArgs = {0};
    RTOS_THREAD serverTid = RTOS_THREAD_INVALID;
    RTOS_THREAD clientTid = RTOS_THREAD_INVALID;

    serverArgs.threadType = SERVER;
    status = RTOS_createThread((void (*)(void *)) TRUSTEDGE_threadStart, (void *)&serverArgs, TRUSTEDGE_MAIN, &serverTid);
    if (OK != status)
    {
        LOG_INF("RTOS_createThread:error: %d\n", status);
        goto exit;
    }

    clientArgs.threadType = CLIENT;
    status = RTOS_createThread((void (*)(void *)) TRUSTEDGE_threadStart, (void *)&clientArgs, TRUSTEDGE_MAIN, &clientTid);
    if (OK != status)
    {
        LOG_INF("RTOS_createThread:error: %d\n", status);
        goto exit;
    }

    status = OK;

exit:
    pthread_join((uintptr) serverTid, NULL);
    pthread_join((uintptr) clientTid, NULL);
    return status;
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

static int compare_files(sbyte *pFile1, sbyte *pFile2)
{
    int ret = 0;
    sbyte4 bytesRead1 = 0;
    sbyte4 bytesRead2 = 0;
    ubyte buffer1[BUFFER_SIZE] = {0};
    ubyte buffer2[BUFFER_SIZE] = {0};

    struct fs_file_t fs_file1;
    struct fs_file_t fs_file2;

    fs_file_t_init(&fs_file1);
    fs_file_t_init(&fs_file2);

    ret = fs_open(&fs_file1, pFile1, (fs_mode_t)FS_O_READ);
    if (ret != 0)
    {
        LOG_ERR("failed to open %s\n", pFile1);
        return -1;
    }

    ret = fs_open(&fs_file2, pFile2, (fs_mode_t)FS_O_READ);
    if (ret != 0)
    {
        LOG_ERR("failed to open %s\n", pFile2);
        return -1;
    }

    do {
        bytesRead1 = fs_read(&fs_file1, buffer1, 30);
        if (bytesRead1 < 0)
        {
            LOG_ERR("failed to read from %s\n", pFile1);
            ret = -1;
            break;
        }

        bytesRead2 = fs_read(&fs_file2, buffer2, 30);
        if (bytesRead2 < 0)
        {
            LOG_ERR("failed to read from %s\n", pFile2);
            ret = -1;
            break;
        }

        if (bytesRead1 != bytesRead2 || memcmp(buffer1, buffer2, bytesRead1) != 0)
        {
            ret = 1; // files are not equal
            LOG_ERR("failed\n");
            LOG_ERR("bytesRead1: %d\n", bytesRead1);
            LOG_ERR("bytesRead2: %d\n", bytesRead2);
            for (int i = 0;i < 30; i++)
            {
                LOG_ERR("%02x:", buffer1[i]);
            }
            LOG_ERR("\n");
            for (int i = 0;i < 30; i++)
            {
                LOG_ERR("%02x:", buffer2[i]);
            }
            LOG_ERR("\n");
            break;
        }
    } while (bytesRead1 > 0 && bytesRead2 > 0);

    (void) fs_close(&fs_file1);
    (void) fs_close(&fs_file2);
    return ret; // 0 == files are equal, 1 == files are not equal
}

int main()
{
    MSTATUS status = ERR_GENERAL;
    sbyte *pDir = "/lfs1";
    sbyte4 ret;
    sbyte *pFil = NULL;
    sbyte4 filSize;
    RTOS_THREAD clientTid = RTOS_THREAD_INVALID;
    sbyte *pFPath = NULL;


    status = TRUSTEDGE_Zephyr_mountLittlefs(pDir, &ret);
    if (status != OK)
    {
        printk("TRUSTEDGE_Zephyr_mountLittlefs:error: %d\n", ret);
        goto exit;
    }

    status = FMGMT_setMountPoint(pDir);
    if (OK != status)
    {
        printk("FMGMT_setMountPoint:error: %d\n", status);
        goto exit;
    }

    (void) FMGMT_mkdir("log", 0775);

    while(1)
    {
        k_sem_take(&startTrustedge, K_FOREVER);
        switch(atomic_get(&cmdType))
        {
            case 0:
                LOG_INF("downloading binary..\n");
                (void) FMGMT_remove(g_DownloadFile, TRUE);
                status = RTOS_createThread(TRUSETDGE_downloadBin, (void *)"bin", TRUSTEDGE_MAIN, &clientTid);
                if (OK != status)
                {
                    goto exit;
                }

                pthread_join((uintptr) clientTid, NULL);

                filSize = get_file_size(g_DownloadFile1);
                LOG_INF("%s has size %d\n", g_DownloadFile, filSize);

                (void) FMGMT_remove("ex", TRUE);
                FMGMT_mkdir("ex", 7775);

                status = TRUSTEDGE_utilsExtractInlineZip(g_DownloadFile, 0, 0, "ex");
                if (OK != status)
                {
                    printk("TRUSTEDGE_utilsExtractInlineZip:error: %d\n", status);
                    goto exit;
                }

                pFPath = "/lfs1/ex/payload/trustedge.signed.bin";
                filSize = get_file_size(pFPath);
                LOG_INF("%s has size %d\n", pFPath, filSize);

                break;
                ;;
            case 1:
                sys_reboot(SYS_REBOOT_COLD);
                break;
                ;;
            case 2:
                //g_DownloadFile = "test_payload1.zip";
                #if 0
                LOG_INF("downloading %s binary..\n", g_DownloadFile);
                (void) FMGMT_remove(g_DownloadFile, TRUE);
                status = RTOS_createThread(TRUSETDGE_downloadBin, (void *)"bin", TRUSTEDGE_MAIN, &clientTid);
                if (OK != status)
                {
                    goto exit;
                }

                pthread_join((uintptr) clientTid, NULL);
                #endif

                filSize = get_file_size(g_DownloadFile1);
                LOG_INF("%s has size %d\n", g_DownloadFile1, filSize);

                /* we download */
                //ret = compare_files("/lfs1/tmp/artifact/payload.zip", "/lfs1/test_payload1.zip");
                //LOG_INF("compare ZIP files: %d\n", ret);

                (void) FMGMT_remove("ex4", TRUE);
                FMGMT_mkdir("ex4", 7775);

                status = TRUSTEDGE_utilsExtractInlineZip(g_DownloadFile, 0, 0, "ex4");
                LOG_INF("111.status = %d\n", status);

                sbyte *pOtherFile = "/lfs1/ex4/payload/trustedge.signed.bin";
                filSize = get_file_size(pOtherFile);
                LOG_INF("%s has size %d\n", pOtherFile, filSize);

                LOG_INF("extract original information\n");

                #if 0
                (void) FMGMT_remove("ex5", TRUE);
                FMGMT_mkdir("ex5", 7775);

                status = TRUSTEDGE_utilsExtractInlineZip("tmp/artifact/payload.zip", 0, 0, "ex5");
                LOG_INF("status=%d\n", status);

                sbyte *pOrigFIle = "/lfs1/ex5/payload/trustedge.signed.bin";

                filSize = get_file_size(pOrigFIle);
                LOG_INF("%s has size %d\n", pOrigFIle, filSize);

                ret = compare_files(pOtherFile, pOrigFIle);
                LOG_INF("file compared: %d\n", ret);
#endif
                break;
                ;;
            case 3:
                sbyte *pPayloadZip = NULL;

                status = FMGMT_remove("/etc", TRUE);
                if (OK != status)
                {
                    LOG_ERR("exiting unzip; %d\n", status);
                    goto exit;
                }

                status = TRUSTEDGE_install("filesystem.zip");
                if (OK != status)
                {
                    LOG_ERR("exiting fs install: %d\n", status);
                    goto exit;
                }

                status = TRUSTEDGE_extractBootStrap("bootstrap.zip");
                if (OK != status)
                {
                    LOG_ERR("bootstrap extraction failed with status=%d\n", status);
                    goto exit;
                }

                status = TRUSTEDGE_getFirstFileWithExtension("/tmp/artifact", ".zip", &pPayloadZip);
                LOG_INF("TRUSTEDGE_getFirstFileWithExtension = %d\n", status);
                if (OK == status)
                {
                    LOG_INF("payload zip: %s", pPayloadZip);
                }

                break;
                ;;
            default:
                break;
        }
    }

    //status = fileSystemTests();
    //printk("file system tests: %d\n", status);

    //status = tcpTests();
    //printk("network tests: %d\n", status);
exit:
    return (OK == status)? 0 : -1;
}
