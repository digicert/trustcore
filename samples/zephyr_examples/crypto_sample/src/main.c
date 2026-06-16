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

#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_context.h>
#include <zephyr/net/net_mgmt.h>
#include <arpa/inet.h>

/* DigiCert includes */
#include "common/initmocana.h"
#include "crypto/mocasym.h"
#include "crypto/rsa.h"

#include "common/mstdlib.h"
#include "unittest.h"
#include "unittest_utils.h"

#include "crypto_interface/crypto_interface_priv.h"
#include "crypto/test/nonrandop.h"
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


static MocCtx gpMocCtx = NULL;

static int gCurrentVector = 0;
static int gCurrentVectorVerify = 0;

typedef enum VectorType
{
    encDec,
    signVerify

} VectorType;

typedef struct TestVector
{
    char *pModulus;
    char *pP;
    char *pQ;
    char *pPublicExponent;
    char *pDigestOrPlain;
    char *pSigOrCipher;
    char *pNonce;
    VectorType type;

} TestVector;

typedef struct TestVectorVerify
{
    char *pModulus;
    char *pPublicExponent;
    char *pDigest;
    char *pSignature;
    sbyte4 verifyStatus;

} TestVectorVerify;

typedef struct TestVectorVerifyData
{
    /* Assume e=0x10001 */
    char *pModulus;
    char *pMessage;
    ubyte hashId;
    char *pSignature;
    byteBoolean isValid;

} TestVectorVerifyData;

#define MOC_RSA_MAX_MOD_BYTE_LEN 384
#include "rsa_data_inc.h"

/* Global variables so the "fake RNG" callback method will have access as what to return */
static ubyte gpNonce[MOC_RSA_MAX_MOD_BYTE_LEN] = {0};
static ubyte4 gNonceLen = 0;
static ubyte4 gNoncePos = 0;
/* filesystem information */

#define MAX_PATH_LEN 255

#ifdef __ENABLE_DIGICERT_ESP32S3__
#define STORAGE_PARTITION	storage_partition
#else
#define STORAGE_PARTITION	fs_partition
#endif
#define STORAGE_PARTITION_ID	FIXED_PARTITION_ID(STORAGE_PARTITION)
#define MOC_MAX_BYTES_TO_COPY	4096
#define MAX_PATH_LENGTH			64

#include <zephyr/fs/littlefs.h>
#include <zephyr/storage/flash_map.h>

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
        printk("FMGMT_fclose:error: %d\n", status);
        goto exit;
    }

    status = FMGMT_fopen(pFile, "a", ppCtx);
    if (OK != status)
    {
        printk("FMGMT_fopen:error: %d\n", status);
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

    printk("Creating file %s at path %s\n", pFile, pPath);
    status = FMGMT_fopen(pFile, "w", &pCtx);
    if (OK != status)
    {
        printk("FMGMT_fopen:error: %d\n", status);
        goto exit;
    }

    printk("File created successfully\n");
    printk("---------------------------------------------------\n");
    printk("Writing text to file %s\n", pFile);
    status = FMGMT_fprintf(pCtx, "%d: %s\n", 42, "forty two");
    if (OK != status)
    {
        printk("FMGMT_fprintf:error: %d\n", status);
        goto exit;
    }

    bytesWritten = FMGMT_fputs("second line is here\n", pCtx);
    if (bytesWritten <= 0)
    {
        printk("FMGMT_fputs:error: %d\n", status);
        goto exit;
    }

    printk("bytesWritten: %d\n", bytesWritten);
    printk("Text written to file successfuly\n");
    printk("---------------------------------------------------\n");
    printk("Closing file %s\n", pFile);

    status = FMGMT_fclose(&pCtx);
    if (OK != status)
    {
        printk("FMGMT_fclose:error: %d\n", status);
        goto exit;
    }

    printk("File closed successfully\n");
    printk("---------------------------------------------------\n");
    printk("Opening file again %s in read mode\n", pFile);

    status = FMGMT_fopen(pFile, "r", &pCtx);
    if (OK != status)
    {
        printk("FMGMT_fopen:error: %d\n", status);
        goto exit;
    }

    printk("File opened successfully\n");
    printk("---------------------------------------------------\n");
    printk("Reading and writing file\n");
    pInStr = FMGMT_fgets(buffer, bufferLen, pCtx);
    if (NULL == pInStr)
    {
        status = ERR_NULL_POINTER;
        printk("FMGMT_fgets:error: %d\n", status);
        goto exit;
    }

    printk("First string: %s", pInStr);

    c = FMGMT_fgetc(pCtx);
    printk("First char : %c\n", c);

    status = TRUSTEDGE_Zephyr_reOpenFile(pFile, &pCtx);
    if (OK != status)
    {
        printk("TRUSTEDGE_Zephyr_reOpenFile:error: %d\n", status);
        goto exit;
    }

    status = FMGMT_fwrite ("this is the third line\n", 1, 23, pCtx, &bytesWritten);
    if (OK != status)
    {
        printk("FMGMT_fwrite:error: %d\n", status);
        goto exit;
    }

    status = TRUSTEDGE_Zephyr_reOpenFile(pFile, &pCtx);
    if (OK != status)
    {
        printk("TRUSTEDGE_Zephyr_reOpenFile:error: %d\n", status);
        goto exit;
    }

    printk("before seek: MSEEK_END = %d\n", MSEEK_END);
    status = FMGMT_fseek(pCtx, 0, 2);
    if (OK != status)
    {
        printk("FMGMT_fseek:error: %d\n", status);
        goto exit;
    }

    status = FMGMT_ftell(pCtx, &totalLen);
    if (OK != status)
    {
        printk("FMGMT_ftell:error: %d\n", status);
        goto exit;
    }

    printk("Total length of file: %d\n", totalLen);

    status = TRUSTEDGE_Zephyr_reOpenFile(pFile, &pCtx);
    if (OK != status)
    {
        printk("TRUSTEDGE_Zephyr_reOpenFile:error: %d\n", status);
        goto exit;
    }

    status = FMGMT_fread (buffer, 1, totalLen, pCtx, &bytesRead);
    if (OK != status)
    {
        printk("FMGMT_fread:error: %d\n", status);
        goto exit;
    }

    printk("File contents: %s\n", buffer);

    printk("File read and written successfully\n");
    printk("---------------------------------------------------\n");
    printk("Renaming file %s to %s\n", pFile, pNewFile);

    status = FMGMT_rename(pFile, pNewFile);
    if (OK != status)
    {
        printk("FMGMT_rename:error: %d\n", status);
        goto exit;
    }

    printk("File renamed successfully\n");
    printk("---------------------------------------------------\n");

    status = OK;
exit:
    if (NULL != pCtx)
    {
        status = FMGMT_fflush(pCtx);
        if (OK != status)
        {
            printk("FMGMT_fflush:error: %d\n", status);
        }

        status = FMGMT_fclose(&pCtx);
        if (OK != status)
        {
            printk("FMGMT_fopen:error: %d\n", status);
        }
    }

    return status;
}

static MSTATUS TRUSTEDGE_Zephyr_directoryTests(sbyte *pPath)
{
    MSTATUS status = ERR_GENERAL;
    DirectoryDescriptor pDirDesc = NULL;
    DirectoryEntry dirEnt = {0};

    printk("Enumerating files in dir %s\n", pPath);
    status = FMGMT_getFirstFile(pPath, &pDirDesc, &dirEnt);
    if (OK != status)
    {
        printk("FMGMT_getFirstFile:error: %d\n", status);
        goto exit;
    }

    do {
        if (FTFile == dirEnt.type)
        {
            printk("file found, ");
        }
        else if (FTDirectory == dirEnt.type)
        {
            printk("directory found, \n");
        }
        else if (FTNone == dirEnt.type)
        {
            printk("directory empty\n");
            goto exit;
        }

        printk("name: %s\n", dirEnt.pName);

        /* Need to clear dirEnt.pName before calling FMGMT_getNextFile */
        if (NULL != dirEnt.pName)
        {
            DIGI_FREE((void **) &dirEnt.pName);
        }
        status = FMGMT_getNextFile(pDirDesc, &dirEnt);
        if (OK != status)
        {
            printk("FMGMT_getNextFile:error: %d\n", status);
            goto exit;
        }
    } while (FTNone != dirEnt.type);

    printk("Enumerating files completed successfully\n");
    printk("---------------------------------------------------\n");

    status = OK;

exit:
    if (NULL != pDirDesc)
    {
        status = FMGMT_closeDir(&pDirDesc);
        if (OK != status)
        {
            printk("FMGMT_closeDir:error: %d\n", status);
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

    printk("Reading file %s\n", pFile);
    status = DIGICERT_readFile(pFile, &pBuffer, &bufferLen);
    if (OK != status)
    {
        printk("DIGICERT_readFile:error: %d\n", status);
        goto exit;
    }

    printk("\nFile Data: %s\n", pBuffer);

    printk("File read successfully\n");
    printk("---------------------------------------------------\n");
    printk("Deleting file %s\n", pFile);

    status = DIGICERT_deleteFile(pFile);
    if (OK != status)
    {
        printk("DIGICERT_deleteFile:error: %d\n", status);
        goto exit;
    }

    printk("File deleted successfully\n");
    printk("---------------------------------------------------\n");
    printk("Creating new file %s\n", pFile);

    status = DIGICERT_writeFile(pFile, pData, DIGI_STRLEN(pData));
        if (OK != status)
    {
        printk("DIGICERT_writeFile:error: %d\n", status);
        goto exit;
    }

    printk("File created successfully with data: %s\n", pData);
    printk("---------------------------------------------------\n");
    printk("Copying file %s to %s\n", pFile, pNewFile);

    status = DIGICERT_copyFile(pFile, pNewFile);
    if (OK != status)
    {
        printk("DIGICERT_copyFile:error: %d\n", status);
        goto exit;
    }

    printk("File copied successfully\n");
    printk("---------------------------------------------------\n");
    printk("Check if file %s exists\n", pNewFile);

    len = DIGI_STRLEN (pNewFile) - 4;
    status = DIGI_MEMCPY (pFileNameBuffer, pNewFile, len);
    if (OK != status)
    {
        printk("DIGI_MEMCPY:error: %d\n", status);
        goto exit;
    }

    pFileNameBuffer[len] = '\0';

    status = DIGICERT_checkFile(pFileNameBuffer, ".txt", &fileExists);
    if (OK != status)
    {
        printk("DIGICERT_checkFile:error: %d\n", status);
        goto exit;
    }

    if (FALSE == fileExists)
    {
        status = ERR_FILE_NOT_EXIST;
        goto exit;
    }

    printk("File searched successfully\n");
    printk("---------------------------------------------------\n");
    printk("Appending data to file %s\n", pFile);

    status = DIGICERT_appendFile(pFile, pNewData, DIGI_STRLEN(pNewData));
    if (OK != status)
    {
        printk("DIGICERT_appendFile:error: %d\n", status);
        goto exit;
    }

    printk("Appended data successfully\n");

    DIGI_FREE ((void **) &pBuffer);
    status = DIGICERT_readFile(pFile, &pBuffer, &bufferLen);
    if (OK != status)
    {
        printk("DIGICERT_readFile:error: %d\n", status);
        goto exit;
    }

    printk("\nFile Data: %s\n", pBuffer);
    printk("---------------------------------------------------\n");
    printk("Appending data to new file %s\n", pFile);
    printk("Deleting old file %s\n", pFile);

    status = DIGICERT_deleteFile(pFile);
    if (OK != status)
    {
        printk("DIGICERT_deleteFile:error: %d\n", status);
        goto exit;
    }

    printk("Old file deleted successfully\n");

    status = DIGICERT_appendFile(pFile, pNewData, DIGI_STRLEN(pNewData));
    if (OK != status)
    {
        printk("DIGICERT_appendFile:error: %d\n", status);
        goto exit;
    }

    printk("Created file and appended data successfully\n");

    if (NULL != pBuffer)
    {
        status = DIGICERT_freeReadFile(&pBuffer);
        if (OK != status)
        {
            printk("DIGICERT_freeReadFile:error: %d\n", status);
            goto exit;
        }
    }

    status = DIGICERT_readFile(pFile, &pBuffer, &bufferLen);
    if (OK != status)
    {
        printk("DIGICERT_readFile:error: %d\n", status);
        goto exit;
    }

    printk("\nFile Data: %s\n", pBuffer);

    status = OK;
exit:

    if (NULL != pBuffer)
    {
        status = DIGICERT_freeReadFile(&pBuffer);
        if (OK != status)
        {
            printk("DIGICERT_freeReadFile:error: %d\n", status);
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

    printk("Total partition size: %llu bytes\n", total_size);
    printk("Available size: %llu bytes\n", available_size);
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
        printk("TCP_LISTEN_SOCKET_LOCAL:error: %d\n", status);
        goto exit;
    }

    printk("Server listening on [localhost:%d]\n", ZEPHYR_PORT);
    printk("Run command \"nc 127.0.0.1 %d\" to connect to server\n", ZEPHYR_PORT);
#else
    status = TCP_LISTEN_SOCKET(&listenSocket, ZEPHYR_PORT);
    if (OK != status)
    {
        printk("TCP_LISTEN_SOCKET:error: %d\n", status);
        goto exit;
    }

    printk("Server listening on port %d\n", ZEPHYR_PORT);
#endif

    status = TCP_ACCEPT_SOCKET(&clientSocket, listenSocket, &needToDie);
    if (OK != status)
    {
        printk("TCP_ACCEPT_SOCKET:error: %d\n", status);
        goto exit;
    }

    printk("\nClient connection accepted\n");
    printk("Waiting for data from client...\n");

    status = TCP_READ_AVL(clientSocket, pPayload, BUFFER_SIZE, &received, TCP_NO_TIMEOUT);
    if (OK != status)
    {
        printk("TCP_READ_AVL:error: %d\n", status);
        goto exit;
    }

    pPayload[received] = '\0';
    printk("Message received from client: %s\n", pPayload);

    printk("Waiting for data from client...\n");

    status = TCP_READ_AVL_EX(clientSocket, pPayload, BUFFER_SIZE, &nRet, TCP_NO_TIMEOUT);
    if (ERR_TCP_READ_TIMEOUT == status)
    {
        status = OK;
    }

    pPayload[nRet] = '\0';

    if (OK != status)
    {
        printk("TCP_READ_AVL_EX:error: %d\n", status);
        goto exit;
    }

    printk("Message received from client: %s\n", pPayload);
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
        printk("TCP_GETHOSTBYNAME:error: %d\n", status);
        goto exit;
    }
#endif /* CONFIG_NET_CONFIG_PEER_IPV4_ADDR */

    printk("connecting to IP Addr: %s\n", pIpAddr);
#if defined(__DIGICERT_SAMPLE_NATIVE_SIM__)
    printk("Run command \"nc -lp %d\" to create a server\n", port);
#endif

    do
    {
        status = TCP_CONNECT(&serverSocket, pIpAddr, port);
        k_sleep(timeout);
    } while (OK != status);

    TCP_WRITE(serverSocket, pMsg, DIGI_STRLEN((sbyte *)pMsg), &nRet);

    printk("Msg sent to server successfully\n");

    status = OK;

exit:
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
            printk("\nRunning in server mode\n");
            printk("***************************\n");
            status = TRUSTEDGE_Zephyr_tcpServer(listenSocket, clientSocket);
            if (OK != status)
            {
                printk("TRUSTEDGE_Zephyr_tcpServer:error: %d\n", status);
                goto exit;
            }

            printk("exit_status from server thread: %d\n", status);
            break;

        case CLIENT:
            printk("\nRunning in client mode\n");
            printk("***************************\n");
            status = TRUSTEDGE_Zephyr_tcpClient(serverSocket, ZEPHYR_PORT + 1);
            if (OK != status)
            {
                printk("TRUSTEDGE_Zephyr_tcpClient:error: %d\n", status);
                goto exit;
            }

            printk("exit_status from client thread: %d\n", status);
            break;

        default:
            printk("Neither a client nor a server\n");
    };

    status = OK;

exit:
    (void) TCP_CLOSE_SOCKET(listenSocket);
    (void) TCP_CLOSE_SOCKET(clientSocket);
    (void) TCP_CLOSE_SOCKET(serverSocket);
    return NULL;
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
    const sbyte *pVarName = "ZEPH_TEST_ENV";
    sbyte *pRetrievedValue = NULL;

    printk("TEST1: Mounting dir: %s\n", pDir);
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

    printk("TEST1: Directory mounted successfully\n");
    printk("\n***************************************************\n");
    printk("TEST2: Creating new dir %s and changing into new dir...\n", pSubDir);

    if (TRUE == FMGMT_pathExists(pSubDir, NULL))
    {
        status = FMGMT_remove(pSubDir, TRUE);
    }

    status = FMGMT_mkdir(pSubDir, 0);
    if (OK != status)
    {
        printk("FMGMT_mkdir:error: %d\n", status);
        goto exit;
    }

    status = DIGI_MEMCPY(pFDPath + 1, pSubDir, DIGI_STRLEN(pSubDir));
    if (OK != status)
    {
        printk("DIGI_MEMCPY:error: %d\n", status);
        goto exit;
    }

    status = FMGMT_changeCWD(pFDPath);
    if (OK != status)
    {
        printk("FMGMT_changeCWD:error: %d\n", status);
        goto exit;
    }

    status = FMGMT_getCWD(cwd, MAX_PATH_LENGTH);
    if (OK != status)
    {
        printk("FMGMT_getCWD:error: %d\n", status);
        goto exit;
    }

    printk("TEST2: CWD: %s\n", cwd);
    printk("\n***************************************************\n");
    printk("TEST3: Testing file operations\n");

    status = TRUSTEDGE_Zephyr_fileTests(pSubDir, pFile, pNewFile);
    if (OK != status)
    {
        printk("TRUSTEDGE_Zephyr_fileTests:error: %d\n", status);
        goto exit;
    }

    printk("TEST3: File operations completed successfully\n");
    printk("\n***************************************************\n");
    printk("TEST4: Testing dir operations\n");

    status = FMGMT_changeCWD("/");
    if (OK != status)
    {
        printk("FMGMT_changeCWD:error: %d\n", status);
        goto exit;
    }

    status = TRUSTEDGE_Zephyr_directoryTests(pSubDir);
    if (OK != status)
    {
        printk("TRUSTEDGE_Zephyr_directoryTests:error: %d\n", status);
        goto exit;
    }

    printk("TEST4: Dir operations completed successfully\n");
    printk("\n***************************************************\n");
    printk("TEST5: Testing common utils apis\n");

    status = DIGI_MEMCPY(pFDPath, pSubDir, DIGI_STRLEN(pSubDir));
    if (OK != status)
    {
        printk("DIGI_MEMCPY:error: %d\n", status);
        goto exit;
    }

    pFDPath[DIGI_STRLEN(pSubDir)] = '/';
    status = DIGI_MEMCPY(pFDPath + DIGI_STRLEN(pSubDir) + 1, pNewFile, DIGI_STRLEN(pNewFile));
    if (OK != status)
    {
        printk("DIGI_MEMCPY:error: %d\n", status);
        goto exit;
    }

    pFDPath[DIGI_STRLEN(pSubDir) + 1 + DIGI_STRLEN(pNewFile)] = '\0';

    status = DIGI_MEMCPY(pNewFDPath, pSubDir, DIGI_STRLEN(pSubDir));
    if (OK != status)
    {
        printk("DIGI_MEMCPY:error: %d\n", status);
        goto exit;
    }

    pNewFDPath[DIGI_STRLEN(pSubDir)] = '/';
    status = DIGI_MEMCPY(pNewFDPath + DIGI_STRLEN(pSubDir) + 1, pCopyFile, DIGI_STRLEN(pCopyFile));
    if (OK != status)
    {
        printk("DIGI_MEMCPY:error: %d\n", status);
        goto exit;
    }

    pNewFDPath[DIGI_STRLEN(pSubDir) + 1 + DIGI_STRLEN(pCopyFile)] = '\0';

    status = TRUSTEDGE_Zephyr_commonUtilsMocanaWrapperTests(pFDPath, pNewFDPath);
    if (OK != status)
    {
        printk("TRUSTEDGE_Zephyr_commonUtilsMocanaWrapperTests:error: %d\n", status);
        goto exit;
    }

#if defined(__DIGICERT_SAMPLE_NATIVE_SIM__)
    setenv("ZEPH_TEST_ENV", "digicert", 1/*overwrite*/);

    printk("TEST5: Common utils apis tested successfully\n");
    printk("\n***************************************************\n");
    printk("TEST6: Testing environment variable api\n");
    status = FMGMT_getEnvironmentVariableValueAlloc (pVarName, &pRetrievedValue);
    if (OK != status)
    {
        printk("FMGMT_getEnvironmentVariableValueAlloc:error: %d\n", status);
        printk("Run this command to test this API: \"export ZEPH_TEST_ENV=digicert\"\n");
        goto exit;
    }

    printk("%s = %s\n", pVarName, pRetrievedValue);
    printk("TEST6: Environment variable api test successful\n");
    printk("\n***************************************************\n");
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
        printk("RTOS_createThread:error: %d\n", status);
        goto exit;
    }

    clientArgs.threadType = CLIENT;
    status = RTOS_createThread((void (*)(void *)) TRUSTEDGE_threadStart, (void *)&clientArgs, TRUSTEDGE_MAIN, &clientTid);
    if (OK != status)
    {
        printk("RTOS_createThread:error: %d\n", status);
        goto exit;
    }

    status = OK;

exit:
    pthread_join((uintptr) serverTid, NULL);
    pthread_join((uintptr) clientTid, NULL);
    return status;
}

/*
 A fake random number generator callBack method. It just write to the buffer
 the value of the global variable gpNonce. gpNonce is big enough for all curves,
 but we need to take into account the Endianness of the platforms pf_unit type.
 */
static sbyte4 rngCallback(void *rngFunArg, ubyte4 length, ubyte *pBuffer)
{
    MSTATUS status = OK;

    (void) rngFunArg;

    if ((gNoncePos + length) > gNonceLen) /* uh oh, error */
    {
        return -1;
    }

    status = DIGI_MEMCPY(pBuffer, gpNonce + gNoncePos, length);
    UNITTEST_STATUS(gCurrentVector, status);
    gNoncePos += length;

    return (sbyte4) status;
}

/* This method includes tests of init and delete method error cases too */
static int testErrorCases()
{
    int retVal = 0;
    MSTATUS status = OK;
    intBoolean isValid;

    RSAKey *pPrivKey = NULL;
    RSAKey *pPubKey = NULL;

    /* space to test too large a modulus */
#ifdef __ENABLE_DIGICERT_64_BIT__
    ubyte pModulus[512*8+1] =
#else
    ubyte pModulus[512*4+1] =
#endif
    {
        0xb0,0x30,0xe1,0x64,0x9b,0xe0,0x5f,0x85,0xdf,0xc2,0x5d,0xbf,0x3d,0xc7,0x1f,0xc7,
        0x87,0x85,0xa7,0x31,0x50,0x50,0x10,0x3d,0x47,0x05,0xe5,0x3a,0x9e,0xe5,0xdb,0x78,
        0x25,0xe5,0x31,0x65,0x70,0x73,0x0c,0xf8,0xcb,0xc9,0xf7,0xb8,0x49,0xfa,0x26,0x1c,
        0xc6,0x5c,0x8e,0xba,0x30,0x0e,0x77,0xcd,0x08,0xc5,0x26,0xed,0x94,0xb1,0x86,0xa5,
        0xbf,0x46,0xc5,0x10,0xf3,0x44,0xaf,0xc5,0xfc,0x5b,0xf3,0x82,0x06,0xbd,0x45,0xdc,
        0xe6,0x47,0xd5,0x51,0xe3,0x0d,0x8b,0xae,0x86,0xd7,0xd1,0xcc,0x4c,0xcd,0x4c,0x0c,
        0xa6,0xdf,0x54,0xc9,0xeb,0x7a,0x42,0xf5,0xe4,0x1c,0x1c,0xf4,0x5a,0xd7,0x17,0xcd,
        0xe8,0x5a,0xbc,0x99,0x2d,0xf7,0x56,0x34,0xdb,0x62,0xc1,0x36,0xbe,0xd8,0xd1,0x2b
    };

    ubyte4 modulusLen = 128;

    ubyte pP[64] =
    {
        0xdf,0xa5,0x76,0xd0,0x5c,0x2f,0x46,0x8b,0x04,0x30,0xa8,0x46,0x7e,0xcd,0x0b,0x4d,
        0xb4,0x92,0xac,0xb0,0x33,0x07,0x42,0x65,0xef,0x29,0xc1,0x44,0x3e,0xcc,0xa3,0xcc,
        0xc6,0x9d,0xd4,0x30,0xfa,0xc0,0xf3,0x5b,0x8b,0x98,0xde,0x0c,0xd0,0x8a,0xae,0x4f,
        0xd9,0xfe,0xfc,0xfe,0xb3,0x3e,0x64,0x1c,0xbb,0xa3,0xa5,0x44,0x93,0xc2,0x99,0x3d
    };
    ubyte pQ[64] =
    {
        0xc9,0xad,0xf2,0xff,0x9c,0x4f,0xe9,0x8d,0x24,0xa1,0x72,0xcf,0x33,0x18,0x83,0x94,
        0x29,0x8f,0xb0,0x22,0xc0,0x58,0x27,0x70,0x89,0xc9,0x40,0x5e,0x5b,0x74,0x85,0x14,
        0x13,0x40,0xe3,0xdd,0x89,0x9f,0xa9,0xca,0x2e,0x8f,0x61,0x1f,0xce,0x56,0x26,0x81,
        0x10,0x59,0x6c,0x9a,0x7f,0x2b,0xcb,0x11,0x20,0xef,0xd7,0x19,0x63,0xce,0x2a,0x87
    };

    /* space to test too large a pubKey */
    ubyte pPub[9] = {0x01, 0x00, 0x01};
    ubyte4 pubLen = 3;

    ubyte pDigest[118] = {0}; /* big renough to test too big */
    ubyte4 digestLen = 32;
    ubyte pSig[128] = {0};
    sbyte4 sigSize = 128;

    ubyte pVerify[128] = {0};
    ubyte4 verifySize = 0;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    randomContext *pRndCtx = NULL;
#endif

    /******* RSA_createKey *******/

    status = RSA_createKey(NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* properly create keys for further tests */
    status = RSA_createKey(&pPrivKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = RSA_createKey(&pPubKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
    {
        /* Get a deterministc RNG */
        status = getDeterministicRngCtx(&pRndCtx);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;

        /* Set up the RNG to produce the nonce that was copied to gpNonce */
        status = CRYPTO_seedRandomContext(pRndCtx, NULL, gpNonce, gNonceLen);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;

        /* mbed will check that the modulus is not even lol! */
        pModulus[sizeof(pModulus) - 1] = 0x01;
    }
#endif

    /******* RSA_setPublicKeyData *******/

    status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) NULL, pPub, pubLen, pModulus, modulusLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) pPubKey, NULL, pubLen, pModulus, modulusLen, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) pPubKey, pPub, pubLen, NULL, modulusLen, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* bad exponent */
    status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) pPubKey, pPub, 0, pModulus, modulusLen, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BAD_EXPONENT);

    status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) pPubKey, pPub + 1, 1, pModulus, modulusLen, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BAD_EXPONENT);

    /* mbed allows an exponent of 1 */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED != pPubKey->enabled)
#endif
    {
        status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) pPubKey, pPub, 1, pModulus, modulusLen, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BAD_EXPONENT);
    }

    /******* RSA_setPublicKeyParameters *******/

    status = RSA_setPublicKeyParameters(MOC_RSA(gpHwAccelCtx) NULL, 65537, pModulus, modulusLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_setPublicKeyParameters(MOC_RSA(gpHwAccelCtx) pPubKey, 65537, NULL, modulusLen, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_setPublicKeyParameters(MOC_RSA(gpHwAccelCtx) pPubKey, 0, pModulus, modulusLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BAD_EXPONENT);

    /* mbed allows an exponent of 1 */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED != pPubKey->enabled)
#endif
    {
        status = RSA_setPublicKeyParameters(MOC_RSA(gpHwAccelCtx) pPubKey, 1, pModulus, modulusLen, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BAD_EXPONENT);
    }

    /* properly set the public key params for further tests */
    status = RSA_setPublicKeyParameters(MOC_RSA(gpHwAccelCtx) pPubKey, 65537, pModulus, modulusLen, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /******* RSA_setAllKeyData ********/

    /* Null params */
    status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) NULL, pPub, pubLen, pModulus, modulusLen, pP, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) pPrivKey, NULL, pubLen, pModulus, modulusLen, pP, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* mbed will get the modulus from p and q */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED != pPrivKey->enabled)
#endif
    {
        status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) pPrivKey, pPub, pubLen, NULL, modulusLen, pP, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);
    }

    status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) pPrivKey, pPub, pubLen, pModulus, modulusLen, NULL, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) pPrivKey, pPub, pubLen, pModulus, modulusLen, pP, sizeof(pP),
                               NULL, sizeof(pQ), NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* bad public exponent */
    status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) pPrivKey, pPub, 0, pModulus, modulusLen, pP, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BAD_EXPONENT);

    /* mbed allows an exponent of 1 */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED != pPrivKey->enabled)
#endif
    {
        status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) pPrivKey, pPub, 1, pModulus, modulusLen, pP, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BAD_EXPONENT);
    }

    /******* RSA_setAllKeyParameters *******/

    /* Null params */
    status = RSA_setAllKeyParameters(MOC_RSA(gpHwAccelCtx) NULL, 65537, pModulus, modulusLen, pP, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* mbed will get the modulus from p and q */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED != pPrivKey->enabled)
#endif
    {
        status = RSA_setAllKeyParameters(MOC_RSA(gpHwAccelCtx) pPrivKey, 65537, NULL, modulusLen, pP, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);
    }

    status = RSA_setAllKeyParameters(MOC_RSA(gpHwAccelCtx) pPrivKey, 65537, pModulus, modulusLen, NULL, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_setAllKeyParameters(MOC_RSA(gpHwAccelCtx) pPrivKey, 65537, pModulus, modulusLen, pP, sizeof(pP),
                               NULL, sizeof(pQ), NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* bad public exponent */
    status = RSA_setAllKeyParameters(MOC_RSA(gpHwAccelCtx) pPrivKey, 0, pModulus, modulusLen, pP, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BAD_EXPONENT);

    status = RSA_setAllKeyParameters(MOC_RSA(gpHwAccelCtx) pPrivKey, 1, pModulus, modulusLen, pP, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BAD_EXPONENT);

    /* properly set the params for further tests */
    status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) pPrivKey, pPub, pubLen, pModulus, modulusLen, pP, sizeof(pP),
                               pQ, sizeof(pQ), NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /******* RSA_getCipherTextLength *******/

    status = RSA_getCipherTextLength(MOC_RSA(gpHwAccelCtx) NULL, &sigSize);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_getCipherTextLength(MOC_RSA(gpHwAccelCtx) pPrivKey, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /******* RSA_encrypt *******/

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) NULL, pDigest, digestLen, pVerify, RANDOM_rngFun, pRndCtx, NULL);
    else
#endif
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) NULL, pDigest, digestLen, pVerify, rngCallback, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pPubKey, NULL, digestLen, pVerify, RANDOM_rngFun, pRndCtx, NULL);
    else
#endif
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pPubKey, NULL, digestLen, pVerify, rngCallback, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* For operators NULL output buffer will set the length to what's needed (so not a true error case) */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
    {
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, NULL, RANDOM_rngFun, pRndCtx, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BUFFER_TOO_SMALL);

        /* but for RSA there is no output length param to be set and checked */
    }
    else
#endif
    {
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, NULL, rngCallback, NULL, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);
    }

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
    {
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, pVerify, NULL, pRndCtx, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    }
    else
#endif
    {
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, pVerify, NULL, NULL, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);
    }

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
    {
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, pVerify, RANDOM_rngFun, NULL, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    }
#endif

    /* invalid plainLen */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
    {
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, 118, pVerify, RANDOM_rngFun, pRndCtx, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    }
    else
#endif
    {
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, 118, pVerify, rngCallback, NULL, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_INVALID_KEY);
    }

    /* invalid rng */
    gNoncePos = gNonceLen;
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
    {   /* mbed is supposed to use the RANDOM_rngFun and pRndCtx */
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, pVerify, rngCallback, NULL, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    }
    else
#endif
    {
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, pVerify, rngCallback, NULL, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_RNG_FAILURE);
    }

    /******* RSA_decrypt *******/

    status = RSA_decrypt(MOC_RSA(gpHwAccelCtx) NULL, pVerify, pDigest, (ubyte4*) &sigSize, NULL, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_decrypt(MOC_RSA(gpHwAccelCtx) pPrivKey, NULL, pDigest, (ubyte4*) &sigSize, NULL, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* For operators NULL output buffer will set the length to what's needed (so not a true error case) */
    status = RSA_decrypt(MOC_RSA(gpHwAccelCtx) pPrivKey, pVerify, NULL, (ubyte4*) &sigSize, NULL, NULL, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivKey->enabled)
    {
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BUFFER_TOO_SMALL);

        /* we set the plainSize (ie sigSize) to the modulusLen even though it might be less */
        retVal += UNITTEST_INT(__MOC_LINE__, sigSize, modulusLen);
    }
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_decrypt(MOC_RSA(gpHwAccelCtx) pPrivKey, pVerify, pDigest, NULL, NULL, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* use a public key */
    status = RSA_decrypt(MOC_RSA(gpHwAccelCtx) pPubKey, pVerify, pDigest, (ubyte4*) &sigSize, NULL, NULL, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_KEY_NOT_READY);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_INVALID_KEY);

    /* ciphertext of 0 */
    status = DIGI_MEMSET(pVerify, 0x00, sizeof(pVerify));
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = RSA_decrypt(MOC_RSA(gpHwAccelCtx) pPrivKey, pVerify, pDigest, (ubyte4*) &sigSize, NULL, NULL, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_OUT_OF_RANGE);

    /******* RSA_signMessage *******/

    status = RSA_signMessage(MOC_RSA(gpHwAccelCtx) NULL, pDigest, digestLen, pSig, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_signMessage(MOC_RSA(gpHwAccelCtx) pPrivKey, NULL, digestLen, pSig, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_signMessage(MOC_RSA(gpHwAccelCtx) pPrivKey, pDigest, digestLen, NULL, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BUFFER_TOO_SMALL);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* digest too large, mbed does not distinguish this error case */
    status = RSA_signMessage(MOC_RSA(gpHwAccelCtx) pPrivKey, pDigest, 118, pSig, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPrivKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_BAD_SIGNATURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_INVALID_KEY);

    /* sign with a public key */
    status = RSA_signMessage(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, pSig, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_KEY_NOT_READY);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_INVALID_KEY);

    /******* RSA_verifySignature *******/

    status = RSA_verifySignature(MOC_RSA(gpHwAccelCtx) NULL, pSig, pVerify, &verifySize, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_verifySignature(MOC_RSA(gpHwAccelCtx) pPubKey, NULL, pVerify, &verifySize, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_verifySignature(MOC_RSA(gpHwAccelCtx) pPubKey, pSig, NULL, &verifySize, NULL);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_BUFFER_TOO_SMALL);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_verifySignature(MOC_RSA(gpHwAccelCtx) pPubKey, pSig, pVerify, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* properly set a public key too large for our verify */
    status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) pPubKey, pPub, 9, pModulus, modulusLen, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* mbed is fine with the public key, just we don't get a valid decryption */
    status = RSA_verifySignature(MOC_RSA(gpHwAccelCtx) pPubKey, pSig, pVerify, &verifySize, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_DECRYPTION);

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED != pPubKey->enabled)
#endif
    {
        /* properly set a modulus too large for our verify */
#ifdef __ENABLE_DIGICERT_64_BIT__
        pModulus[512*8] = 0x01;
        status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) pPubKey, pPub, pubLen, pModulus, 512*8+1, NULL);
#else
        pModulus[512*4] = 0x01;
        status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) pPubKey, pPub, pubLen, pModulus, 512*4+1, NULL);
#endif
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        status = RSA_verifySignature(MOC_RSA(gpHwAccelCtx) pPubKey, pSig, pVerify, &verifySize, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_INVALID_MODULUS);
    }
    /* ERR_RSA_DECRYPTION is tested in the test vectors */

    /****** RSA_verifyDigest *******/

    status = RSA_verifyDigest(MOC_RSA(gpHwAccelCtx) NULL, pDigest, digestLen, pSig, sigSize, &isValid, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_verifyDigest(MOC_RSA(gpHwAccelCtx) pPubKey, NULL, digestLen, pSig, sigSize, &isValid, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    status = RSA_verifyDigest(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, pSig, sigSize, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED != pPubKey->enabled)
#endif
    {
        status = RSA_verifyDigest(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, pSig, sigSize, &isValid, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_BAD_SIGNATURE);

        status = RSA_verifyDigest(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, pSig, 127, &isValid, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_BAD_SIGNATURE);

        status = RSA_verifyDigest(MOC_RSA(gpHwAccelCtx) pPubKey, pDigest, digestLen, pSig, 129, &isValid, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_RSA_BAD_SIGNATURE);
    }

    /****** RSA_freeKey *******/

    status = RSA_freeKey(NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

    /* properly free pPrivKey */
    status = RSA_freeKey(&pPrivKey, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* free an already freed key */
    status = RSA_freeKey(&pPrivKey, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, (int) status, (int) ERR_NULL_POINTER);

exit:

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (NULL != pRndCtx && NULL != pPubKey && CRYPTO_INTERFACE_ALGO_ENABLED == pPubKey->enabled)
    {
        status = CRYPTO_freeMocSymRandom(&pRndCtx);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
#endif

    if (NULL != pPrivKey)
    {
        status = RSA_freeKey(&pPrivKey, NULL);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    if (NULL != pPubKey)
    {
        status = RSA_freeKey(&pPubKey, NULL);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}

static int testEncDec(ubyte *pModulus, ubyte4 modulusLen, ubyte *pP, ubyte4 pLen,
                      ubyte *pQ, ubyte4 qLen, ubyte *pPub, ubyte4 pubLen,
                      ubyte *pPlain, ubyte4 plainLen, ubyte *pCipher, ubyte4 cipherLen)
{
    MSTATUS status;
    int retVal = 0;
    sbyte4 compare;

    RSAKey *pKey = NULL;
    ubyte pGenCipher[MOC_RSA_MAX_MOD_BYTE_LEN] = {0};
    ubyte pRecoveredPlain[MOC_RSA_MAX_MOD_BYTE_LEN] = {0};
    sbyte4 cipherSize;
    ubyte4 plainSize;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    randomContext *pRndCtx = NULL;
#endif

    status = RSA_createKey(&pKey);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        /* Get a deterministc RNG */
        status = getDeterministicRngCtx(&pRndCtx);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;

        /* Set up the RNG to produce the nonce that was copied to gpNonce */
        status = CRYPTO_seedRandomContext(pRndCtx, NULL, gpNonce, gNonceLen);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;
    }
#endif

    /* set values of key for the known vector test */
    status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) pKey, pPub, pubLen, pModulus,
                               modulusLen, pP, pLen, pQ,
                               qLen, NULL);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    status = RSA_getCipherTextLength(MOC_RSA(gpHwAccelCtx) pKey, &cipherSize);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(gCurrentVector, cipherSize, cipherLen);

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pKey, pPlain, plainLen, pGenCipher, RANDOM_rngFun, pRndCtx, NULL);
    else
#endif
        status = RSA_encrypt(MOC_RSA(gpHwAccelCtx) pKey, pPlain, plainLen, pGenCipher, rngCallback, NULL, NULL);

    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pGenCipher, pCipher, cipherLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(gCurrentVector, compare, 0);

    status = RSA_decrypt(MOC_RSA(gpHwAccelCtx) pKey, pCipher, pRecoveredPlain, &plainSize, NULL, NULL, NULL);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(gCurrentVector, plainSize, plainLen);

    status = DIGI_MEMCMP(pRecoveredPlain, pPlain, plainLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(gCurrentVector, compare, 0);

exit:

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__)
    if (NULL != pRndCtx && pKey != NULL && CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        status = CRYPTO_freeMocSymRandom(&pRndCtx);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
#endif

    if (NULL != pKey)
    {
        status = RSA_freeKey(&pKey, NULL);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }

    return retVal;
}

static int testSignVerify(ubyte *pModulus, ubyte4 modulusLen, ubyte *pP, ubyte4 pLen,
                          ubyte *pQ, ubyte4 qLen, ubyte *pPub, ubyte4 pubLen,
                          ubyte *pDigest, ubyte4 digestLen, ubyte *pSig, ubyte4 sigLen)
{
    MSTATUS status;
    int retVal = 0;
    sbyte4 compare;
    intBoolean isValid = FALSE;

    RSAKey *pKey = NULL;
    ubyte pGeneratedSig[MOC_RSA_MAX_MOD_BYTE_LEN] = {0};
    ubyte pGeneratedVerify[MOC_RSA_MAX_MOD_BYTE_LEN] = {0};
    sbyte4 sigSize;
    ubyte4 verifySize;

    status = RSA_createKey(&pKey);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    /* set values of key for the known vector test */
    status = RSA_setAllKeyData(MOC_RSA(gpHwAccelCtx) pKey, pPub, pubLen, pModulus,
                               modulusLen, pP, pLen, pQ,
                               qLen, NULL);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    status = RSA_getCipherTextLength(MOC_RSA(gpHwAccelCtx) pKey, &sigSize);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(gCurrentVector, sigSize, sigLen);

    status = RSA_signMessage(MOC_RSA(gpHwAccelCtx) pKey, pDigest, digestLen, pGeneratedSig, NULL);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pGeneratedSig, pSig, sigLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(gCurrentVector, compare, 0);

    /* verify first with the boolean setting API */
    status = RSA_verifyDigest(MOC_RSA(gpHwAccelCtx) pKey, pDigest, digestLen, pSig, sigLen, &isValid, NULL);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(gCurrentVector, isValid, TRUE);

    /* verify again for the raw API */
    status = RSA_verifySignature(MOC_RSA(gpHwAccelCtx) pKey, pSig, pGeneratedVerify, &verifySize, NULL);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(gCurrentVector, verifySize, digestLen);

    status = DIGI_MEMCMP(pGeneratedVerify, pDigest, digestLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(gCurrentVector, compare, 0);

exit:

    if (NULL != pKey)
    {
        status = RSA_freeKey(&pKey, NULL);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }

    return retVal;
}

static int testVerify(ubyte *pModulus, ubyte4 modulusLen, ubyte *pPub, ubyte4 pubLen,
                      ubyte *pDigest, ubyte4 digestLen, ubyte *pSig, ubyte4 sigLen, sbyte4 expectedStatus)
{
    MSTATUS status = OK, fstatus = OK;
    int retVal = 0;
    sbyte4 compare;
    intBoolean isValid = FALSE;

    RSAKey *pKey = NULL;
    ubyte pGeneratedVerify[MOC_RSA_MAX_MOD_BYTE_LEN] = {0};
    ubyte4 verifySize;

    status = RSA_createKey(&pKey);
    retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
    if (OK != status)
        goto exit;

    /* set values of key for the known vector test */
    status = RSA_setPublicKeyData(MOC_RSA(gpHwAccelCtx) pKey, pPub, pubLen, pModulus, modulusLen, NULL);
    if (ERR_RSA_UNSUPPORTED_KEY_LENGTH == expectedStatus)
        retVal += UNITTEST_INT(gCurrentVectorVerify, status, expectedStatus);
    else
        retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
    if (OK != status)
        goto exit;

    /* verify first with the boolean setting API */
    fstatus = RSA_verifyDigest(MOC_RSA(gpHwAccelCtx) pKey, pDigest, digestLen, pSig, sigLen, &isValid, NULL);

    /* verify again for the raw API */
    status = RSA_verifySignature(MOC_RSA(gpHwAccelCtx) pKey, pSig, pGeneratedVerify, &verifySize, NULL);

    if (expectedStatus)
    {
        /* first API just check that we didn't get something valid */
        if (OK == fstatus && isValid)
        {
            /* force error */
           retVal += UNITTEST_INT(gCurrentVectorVerify, 0, -1);
        }

        /* For second API we may have status = ERR_RSA_DECRYPTION
            or status OK with a non-matching digest (for expectedStatus -1).
        */
        if (-1 == expectedStatus)  /* something should be wrong with the digest */
        {
            if (verifySize != digestLen)
            {
                goto exit; /* no test failure */
            }
            else
            {
                status = DIGI_MEMCMP(pGeneratedVerify, pDigest, digestLen, &compare);
                retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
                if (OK != status)
                    goto exit;

                if (!compare)
                {
                /* force error */
                    retVal += UNITTEST_INT(gCurrentVectorVerify, 0, -1);
                }
            }
        }
        else  /* we should have status == expectedStatus */
        {
            retVal += UNITTEST_INT(gCurrentVectorVerify, (int) status, (int) expectedStatus);
        }
    }
    else  /* is a valid sig */
    {
        /* check first API */
        retVal += UNITTEST_STATUS(gCurrentVectorVerify, fstatus);
        if (OK != status)
            goto exit;

        retVal += UNITTEST_INT(gCurrentVectorVerify, isValid, TRUE);

        /* check second API */
        retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
        if (OK != status)
            goto exit;

        retVal += UNITTEST_INT(gCurrentVectorVerify, verifySize, digestLen);

        status = DIGI_MEMCMP(pGeneratedVerify, pDigest, digestLen, &compare);
        retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
        if (OK != status)
            goto exit;

        retVal += UNITTEST_INT(gCurrentVectorVerify, compare, 0);
    }

exit:

    if (NULL != pKey)
    {
        status = RSA_freeKey(&pKey, NULL);
        retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
    }

    return retVal;
}


static int knownAnswerTestVerify(TestVectorVerify *pTestVector)
{
    MSTATUS status;
    int retVal = 0;

    ubyte *pModulus = NULL;
    ubyte4 modulusLen = 0;

    ubyte *pPublicExponent = NULL;
    ubyte4 publicExponentLen = 0;

    ubyte *pDigest = NULL;
    ubyte4 digestLen = 0;

    ubyte *pSignature = NULL;
    ubyte4 sigLen = 0;

    if (NULL != pTestVector->pModulus)
        modulusLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pModulus, &pModulus);

    if (NULL != pTestVector->pPublicExponent)
        publicExponentLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPublicExponent, &pPublicExponent);

    if (NULL != pTestVector->pDigest)
        digestLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pDigest, &pDigest);

    if (NULL != pTestVector->pSignature)
        sigLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pSignature, &pSignature);

    retVal += testVerify(pModulus, modulusLen, pPublicExponent, publicExponentLen,
                         pDigest, digestLen, pSignature, sigLen, pTestVector->verifyStatus);
exit:

    if (NULL != pModulus)
    {
        status = DIGI_FREE((void **) &pModulus);
        retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
    }
    if (NULL != pPublicExponent)
    {
        status = DIGI_FREE((void **) &pPublicExponent);
        retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
    }
    if (NULL != pDigest)
    {
        status = DIGI_FREE((void **) &pDigest);
        retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
    }
    if (NULL != pSignature)
    {
        status = DIGI_FREE((void **) &pSignature);
        retVal += UNITTEST_STATUS(gCurrentVectorVerify, status);
    }

    return retVal;
}


static int knownAnswerTest(TestVector *pTestVector)
{
    MSTATUS status;
    int retVal = 0;
    int i;

    ubyte *pModulus = NULL;
    ubyte4 modulusLen = 0;

    ubyte *pP = NULL;
    ubyte4 pLen = 0;

    ubyte *pQ = NULL;
    ubyte4 qLen = 0;

    ubyte *pPublicExponent = NULL;
    ubyte4 publicExponentLen = 0;

    ubyte *pDigestOrPlain = NULL;
    ubyte4 digestOrPlainLen = 0;

    ubyte *pSigOrCipher = NULL;
    ubyte4 sigOrCipherLen = 0;

    ubyte *pNonce = NULL;

    if (NULL != pTestVector->pModulus)
        modulusLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pModulus, &pModulus);

    if (NULL != pTestVector->pP)
        pLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pP, &pP);

    if (NULL != pTestVector->pQ)
        qLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pQ, &pQ);

    if (NULL != pTestVector->pPublicExponent)
        publicExponentLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPublicExponent, &pPublicExponent);

    if (NULL != pTestVector->pDigestOrPlain)
        digestOrPlainLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pDigestOrPlain, &pDigestOrPlain);

    if (NULL != pTestVector->pSigOrCipher)
        sigOrCipherLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pSigOrCipher, &pSigOrCipher);

    /* copy nonce to the global variable for use in the rngCallback method */
    if (NULL != pTestVector->pNonce)
    {
        gNonceLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pNonce, &pNonce);
        status = DIGI_MEMCPY(gpNonce, pNonce, gNonceLen);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;

        gNoncePos = 0;
    }

    if (signVerify == pTestVector->type)
        retVal += testSignVerify(pModulus, modulusLen, pP, pLen, pQ, qLen, pPublicExponent, publicExponentLen,
                                 pDigestOrPlain, digestOrPlainLen, pSigOrCipher, sigOrCipherLen);
    else
        retVal += testEncDec(pModulus, modulusLen, pP, pLen, pQ, qLen, pPublicExponent, publicExponentLen,
                             pDigestOrPlain, digestOrPlainLen, pSigOrCipher, sigOrCipherLen);
exit:

    if (NULL != pModulus)
    {
        status = DIGI_FREE((void **) &pModulus);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pP)
    {
        status = DIGI_FREE((void **) &pP);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pQ)
    {
        status = DIGI_FREE((void **) &pQ);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pPublicExponent)
    {
        status = DIGI_FREE((void **) &pPublicExponent);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pDigestOrPlain)
    {
        status = DIGI_FREE((void **) &pDigestOrPlain);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pSigOrCipher)
    {
        status = DIGI_FREE((void **) &pSigOrCipher);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pNonce)
    {
        status = DIGI_FREE((void **) &pNonce);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }

    return retVal;
}


int main()
{
    MSTATUS status = ERR_GENERAL;
    int retVal = 0;
    int i;

    //status = fileSystemTests();
    //printk("file system tests: %d\n", status);

    //status = tcpTests();
    //printk("network tests: %d\n", status);
    InitMocanaSetupInfo setupInfo = {0};
    /**********************************************************
     *************** DO NOT USE MOC_NO_AUTOSEED ***************
     ***************** in any production code. ****************
     **********************************************************/
    setupInfo.flags = MOC_NO_AUTOSEED;

    RTOS_sleepCheckStatusMS(5000);
    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    gCurrentVector = 0;
    for (i = 0; i < sizeof(gTestVector)/sizeof(gTestVector[0]); ++i)
    {
        retVal += knownAnswerTest(gTestVector+i);
        gCurrentVector++;
    }

    gCurrentVectorVerify = 0;
    for (i = 0; i < sizeof(gTestVectorVerify)/sizeof(gTestVectorVerify[0]); ++i)
    {
        retVal += knownAnswerTestVerify(gTestVectorVerify+i);
        gCurrentVectorVerify++;
    }

    retVal += testErrorCases();

exit:
    status = DIGICERT_free(&gpMocCtx);
    retVal += UNITTEST_INT(__MOC_LINE__, status, OK);

    LOG_INF("retVal=%d\n", retVal);
    return retVal;
}
