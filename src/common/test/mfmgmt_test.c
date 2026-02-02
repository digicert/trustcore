/*
 * mfmgmt_test.c
 *
 * unit test for File Management APIs
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

#include <stdio.h>
#if defined(__RTOS_OSX__)
#include <stdlib.h>
#endif

#include "../../common/moptions.h"

#include "../../common/mdefs.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/mfmgmt.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/mocana.h"

#include "../../../unit_tests/unittest.h"

#define TEST_FILE_DATA      "this is a string\n"
#define TEST_FILE_DATA_LEN  17
#define TEST_DIRECTORY      "fmgmt_test_dir"
#define TEST_DIRECTORY_LEN  14
#define TEST_SUBDIR         "sub_dir"
#define TEST_SUBDIR_LEN     7
#define TEST_SUBDIR_RENAME  "sub_dir_rename"
#define TEST_SUBDIR_RENAME_LEN 14
#define TEST_DELETE_DIR     "delete_me"
#define TEST_DELETE_DIR_LEN 9
#define TEST_FILE1          "testfile1.txt"
#define TEST_FILE1_LEN      13
#define TEST_FILE2          "testfile2.txt"
#define TEST_FILE2_LEN      13
#define TEST_FILE3          "testfile3.txt"
#define TEST_FILE3_LEN      13
#define TEST_FILE4          "testfile4.txt"
#define TEST_FILE4_LEN      13
#define TEST_FILE5          "testfile5.txt"
#define TEST_FILE5_LEN      13
#define TEST_FILE6          "testfile6.txt"
#define TEST_FILE6_LEN      13
#define TEST_FILE7          "testfile7.txt"
#define TEST_FILE7_LEN      13

static sbyte *pTestDirPath       = NULL; /* root */
static sbyte *pTestSubDirPath    = NULL; /* subdirectory */
static sbyte *pTestSubDirRenamePath = NULL; /* subdirectory renamed */
static sbyte *pTestDeleteDirPath = NULL; /* subdirectory */
static sbyte *pTestFile1Path     = NULL; /* in root */
static sbyte *pTestFile2Path     = NULL; /* in root */
static sbyte *pTestFile3Path     = NULL; /* in root */
static sbyte *pTestFile4Path     = NULL; /* in subdirectory */
static sbyte *pTestFile5Path     = NULL; /* used for negative tests */
static sbyte *pTestFile6Path     = NULL; /* used for negative tests */
static sbyte *pTestFile7Path     = NULL; /* used common/utils.c tests */

static MSTATUS testFile1 (const sbyte *pFilePath)
{
    MSTATUS status = ERR_NULL_POINTER;
    FileDescriptor pFile1 = NULL, pFile2 = NULL;
    ubyte4 bytesWritten, bytesRead;
    ubyte pBufferIn[TEST_FILE_DATA_LEN];
    ubyte pBufferOut[TEST_FILE_DATA_LEN] = TEST_FILE_DATA;

    if (NULL == pFilePath)
        goto exit;

    /* open file and write test data */
    status = FMGMT_fopen (pFilePath, "w", &pFile1);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = FMGMT_fwrite (TEST_FILE_DATA, 1, TEST_FILE_DATA_LEN, pFile1, &bytesWritten);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (TEST_FILE_DATA_LEN != bytesWritten)
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* close write context */
    status = FMGMT_fclose (&pFile1);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* read file after it exists */
    status = FMGMT_fopen (pFilePath, "r", &pFile2);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = FMGMT_fread (pBufferIn, 1, TEST_FILE_DATA_LEN, pFile2, &bytesRead);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (TEST_FILE_DATA_LEN != bytesRead)
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    for (int i = 0; i < TEST_FILE_DATA_LEN; i++)
    {
        if (pBufferIn[i] != pBufferOut[i])
        {
            status = ERR_GENERAL;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    /* close read context */
    status = FMGMT_fclose (&pFile2);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
    
exit:
    if (OK != status)
    {
        FMGMT_fclose (&pFile1);
        FMGMT_fclose (&pFile2);
    }

    return status;
}

static MSTATUS testFileDescriptorSetCurEnd(
    FileDescriptor pFile, sbyte *pExpected)
{
    MSTATUS status;
    sbyte4 expectedLen = DIGI_STRLEN(pExpected);
    ubyte4 totalLen = expectedLen + 1;
    ubyte fileData;
    ubyte4 bytesRead;
    sbyte4 i;

    /* Reset file descriptor to end */
    status = FMGMT_fseek(pFile, 0, MSEEK_END);
    if (OK != status)
        goto exit;

    /* Get size of file */
    status = FMGMT_ftell(pFile, &totalLen);
    if (OK != status)
        goto exit;

    if (totalLen != expectedLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    for (i = 0; i < totalLen; i++)
    {
        status = FMGMT_fseek(pFile, i, MSEEK_SET);
        if (OK != status)
            goto exit;

        status = FMGMT_fread(&fileData, 1, 1, pFile, &bytesRead);
        if (OK != status)
            goto exit;

        if (fileData != pExpected[i])
        {
            status = ERR_GENERAL;
            goto exit;
        }
    }

    status = FMGMT_fseek(pFile, 0, MSEEK_SET);
    if (OK != status)
        goto exit;


    for (i = 0; i < totalLen; i++)
    {
        status = FMGMT_fread(&fileData, 1, 1, pFile, &bytesRead);
        if (OK != status)
            goto exit;

        status = FMGMT_fseek(pFile, -1, MSEEK_CUR);
        if (OK != status)
            goto exit;

        if (fileData != pExpected[i])
        {
            status = ERR_GENERAL;
            goto exit;
        }

        status = FMGMT_fseek(pFile, 1, MSEEK_CUR);
        if (OK != status)
            goto exit;
    }

    for (i = 0; i < totalLen; i++)
    {
        status = FMGMT_fseek(pFile, -1 * (i + 1), MSEEK_END);
        if (OK != status)
            goto exit;

        status = FMGMT_fread(&fileData, 1, 1, pFile, &bytesRead);
        if (OK != status)
            goto exit;

        if (fileData != pExpected[totalLen - i - 1])
        {
            status = ERR_GENERAL;
            goto exit;
        }
    }

exit:

    return status;
}

extern MSTATUS testFile2 (const sbyte *pFilePath)
{
    MSTATUS status = ERR_NULL_POINTER;
    FileDescriptor pFile1, pFile2;
    sbyte *pFormat = "%s%d\n";
#ifdef __RTOS_WIN32__
    sbyte *pExpected = "1234567890\n\n";
#else
    sbyte *pExpected = "1234567890\n";
#endif
    sbyte pBufferIn[11];
    sbyte pBufferOffset[7];
    ubyte4 bytesRead;

    /* open file and write test data */
    status = FMGMT_fopen (pFilePath, "w", &pFile1);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = FMGMT_fprintf (pFile1, pFormat, "12345678", 90);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = FMGMT_fclose (&pFile1);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = FMGMT_fopen (pFilePath, "r", &pFile2);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = FMGMT_fread (pBufferIn, 1, 11, pFile2, &bytesRead);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (11 != bytesRead)
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    for (int i = 0;i < 11; i++)
    {
        if (pExpected[i] != pBufferIn[i])
        {
            status = ERR_GENERAL;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    status = FMGMT_fseek (pFile2, 4, MSEEK_SET);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = FMGMT_fread (pBufferOffset, 1, 7, pFile2, &bytesRead);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    for (int i = 0;i < 7; i++)
    {
        if (pExpected[i + 4] != pBufferOffset[i])
        {
            status = ERR_GENERAL;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    status = testFileDescriptorSetCurEnd(pFile2, pExpected);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = FMGMT_fclose (&pFile2);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:
    return status;
}

static MSTATUS createFilePath (const sbyte *pDirectoryPath, const sbyte *pFileName, sbyte **ppFullPath)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte *pTestFile = NULL;
    ubyte4 testFileLength;
    ubyte4 directoryPathLength;
    ubyte4 fileNameLength;

    if ((NULL == pDirectoryPath) || (NULL == pFileName) || (NULL == ppFullPath))
        goto exit;

    directoryPathLength = DIGI_STRLEN (pDirectoryPath);
    fileNameLength = DIGI_STRLEN (pFileName);

    /* file */
    testFileLength = directoryPathLength + fileNameLength + 1 + 1;
    status = DIGI_MALLOC ((void **) &pTestFile, testFileLength);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY ((void *) pTestFile, pDirectoryPath, directoryPathLength);
    if (OK != status)
        goto exit;

    pTestFile[directoryPathLength] = '/';

    status = DIGI_MEMCPY ((void *) (pTestFile + directoryPathLength + 1), pFileName, fileNameLength);
    if (OK != status)
        goto exit;

    pTestFile[testFileLength - 1] = '\0';

    *ppFullPath = pTestFile;

exit:
    return status;
}


static MSTATUS generateDataPaths (const sbyte *pDirectoryPath)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 directoryPathLength;
    sbyte *pTestDirectoryPath = NULL;
    ubyte4 testDirectoryPathLength = 0;
    ubyte4 testSubDirPathLength;
    ubyte4 testDeleteDirPathLength;

    printf("----------------------------------- GENERATE -----------------------------------\n");

    /* directory path */
#ifndef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    directoryPathLength = DIGI_STRLEN ((const sbyte*) pDirectoryPath);
    testDirectoryPathLength = directoryPathLength + TEST_DIRECTORY_LEN + 1;
#else
    testDirectoryPathLength = TEST_DIRECTORY_LEN + 1;
#endif

    status = DIGI_MALLOC ((void **) &pTestDirectoryPath, testDirectoryPathLength);
    if (OK != status)
        goto exit;

#ifndef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    status = DIGI_MEMCPY (pTestDirectoryPath, pDirectoryPath, directoryPathLength);
    if (OK != status)
        goto exit;
#endif

#ifndef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    status = DIGI_MEMCPY (pTestDirectoryPath + directoryPathLength, TEST_DIRECTORY, TEST_DIRECTORY_LEN);
#else
    status = DIGI_MEMCPY (pTestDirectoryPath, TEST_DIRECTORY, TEST_DIRECTORY_LEN);
#endif
    if (OK != status)
        goto exit;

    pTestDirectoryPath[testDirectoryPathLength - 1] = '\0';

    createFilePath (pTestDirectoryPath, TEST_FILE1, &pTestFile1Path);
    createFilePath (pTestDirectoryPath, TEST_FILE2, &pTestFile2Path);
    createFilePath (pTestDirectoryPath, TEST_FILE3, &pTestFile3Path);
    createFilePath (pTestDirectoryPath, TEST_FILE5, &pTestFile5Path);
    createFilePath (pTestDirectoryPath, TEST_FILE7, &pTestFile7Path);

    testSubDirPathLength = testDirectoryPathLength + DIGI_STRLEN (TEST_SUBDIR) + 1;
    status = DIGI_MALLOC ((void **) &pTestSubDirPath, testSubDirPathLength);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY (pTestSubDirPath, pTestDirectoryPath, testDirectoryPathLength);
    if (OK != status)
        goto exit;

    pTestSubDirPath[testDirectoryPathLength - 1] = '/';
    

    status = DIGI_MEMCPY (pTestSubDirPath + testDirectoryPathLength, TEST_SUBDIR, TEST_SUBDIR_LEN);
    if (OK != status)
        goto exit;

    pTestSubDirPath[testSubDirPathLength - 1] = '\0';

    createFilePath (pTestSubDirPath, TEST_FILE4, &pTestFile4Path);

    testSubDirPathLength = testDirectoryPathLength + DIGI_STRLEN (TEST_SUBDIR_RENAME) + 1;
    status = DIGI_MALLOC ((void **) &pTestSubDirRenamePath, testSubDirPathLength);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY (pTestSubDirRenamePath, pTestDirectoryPath, testDirectoryPathLength);
    if (OK != status)
        goto exit;

    pTestSubDirRenamePath[testDirectoryPathLength - 1] = '/';
    

    status = DIGI_MEMCPY (pTestSubDirRenamePath + testDirectoryPathLength, TEST_SUBDIR_RENAME, TEST_SUBDIR_RENAME_LEN);
    if (OK != status)
        goto exit;

    pTestSubDirRenamePath[testSubDirPathLength - 1] = '\0';

    testDeleteDirPathLength = testDirectoryPathLength + TEST_DELETE_DIR_LEN + 1;
    status = DIGI_MALLOC ((void **) &pTestDeleteDirPath, testDeleteDirPathLength);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY (pTestDeleteDirPath, pTestDirectoryPath, testDirectoryPathLength);
    if (OK != status)
        goto exit;

    pTestDeleteDirPath[testDirectoryPathLength - 1] = '/';

    status = DIGI_MEMCPY (pTestDeleteDirPath + testDirectoryPathLength, TEST_DELETE_DIR, TEST_DELETE_DIR_LEN); 
    if (OK != status)
        goto exit;

    pTestDeleteDirPath[testDeleteDirPathLength - 1] = '\0';
    createFilePath (pTestDeleteDirPath, TEST_FILE6, &pTestFile6Path);
    printf ("test path: %s\n", pTestDirectoryPath);
    printf ("test path: %s\n", pTestFile1Path);
    printf ("test path: %s\n", pTestFile2Path);
    printf ("test path: %s\n", pTestFile3Path);
    printf ("test path: %s\n", pTestSubDirPath);
    printf ("test path: %s\n", pTestSubDirRenamePath);
    printf ("test path: %s\n", pTestFile4Path);
    printf ("test path: %s\n", pTestDeleteDirPath);
    printf ("test path: %s\n", pTestFile5Path);
    printf ("test path: %s\n", pTestDeleteDirPath);
    printf ("test path: %s\n", pTestFile6Path);

    printf("--------------------------------------------------------------------------------\n");
    /* assign pointers */
    pTestDirPath = pTestDirectoryPath;
exit:
    return status;
}

static void clearData ()
{
    if (NULL != pTestFile4Path)
        FMGMT_remove (pTestFile4Path, FALSE);

    if (NULL != pTestSubDirPath)
        FMGMT_remove (pTestSubDirPath, FALSE);

    if (NULL != pTestSubDirRenamePath)
        FMGMT_remove (pTestSubDirRenamePath, FALSE);

#ifndef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    if (NULL != pTestFile3Path)
        FMGMT_remove (pTestFile3Path, FALSE);

    if (NULL != pTestFile2Path)
        FMGMT_remove (pTestFile2Path, FALSE);

    if (NULL != pTestFile1Path)
        FMGMT_remove (pTestFile1Path, FALSE);
#endif

    if (NULL != pTestDirPath)
        FMGMT_remove (pTestDirPath, FALSE);
}

static MSTATUS createRootDirectory ()
{
    MSTATUS status;
    sbyte4 processPathLength;
    sbyte *pTestDirectoryPath = NULL;
    ubyte4 testDirectoryPathLength;
    ubyte pTestFileName[1024] = { 0 };
    FileDescriptorInfo fileInfo = { 0 };
    intBoolean exists;

    fileInfo.type = FTNone;

    /* clearData calls FMGMT_remove in on data paths, this shouldn't exist */
    exists = FMGMT_pathExists (pTestDirPath, &fileInfo);
    if (TRUE == exists)
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        return 1;
    }

    /* expected value if file doesn't exist */
    if (FTNone != fileInfo.type)
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        return 1;
    }
    
    /* create root directory */
    status = FMGMT_mkdir (pTestDirPath, 0777);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* expected to be present */
    exists = FMGMT_pathExists (pTestDirPath, &fileInfo);
    if (FALSE == exists)
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    printf("file size:          %d\n", fileInfo.fileSize);
    printf("last access time:   %d\n", fileInfo.accessTime);
    printf("date created:       %d\n", fileInfo.createTime);
    printf("last modification:  %d\n", fileInfo.modifyTime);
    printf("group ID:           %d\n", fileInfo.gid);
    printf("user ID:            %d\n", fileInfo.uid);
    printf("permissions:        %d\n", fileInfo.mode);
    printf("is writable:        %s\n", (TRUE == fileInfo.isWrite) ? "true": "false");
    printf("is readable:        %s\n", (TRUE == fileInfo.isRead)  ? "true": "false");

    if (FTDirectory != fileInfo.type)
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:

    return status;
}

/* rename test file #1 to test file #3 */
#ifndef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
static MSTATUS changeCwdAndRename (const sbyte *pCurrentDirectory, ubyte4 currentDirectoryLength)
{
    MSTATUS status;
    FileDescriptor pFile = NULL;
    sbyte pCurrWorkingDir[1024];
    ubyte4 currWorkingDirLen = 1024;
    ubyte4 outputLength;
    sbyte pBufferIn[TEST_FILE_DATA_LEN];
    ubyte4 bufferInLength = TEST_FILE_DATA_LEN;
    sbyte *pExpected = TEST_FILE_DATA;
    ubyte4 bytesRead;

    /* correct directory retrieved with FMGMT_getCWD */
    status = FMGMT_changeCWD ((const sbyte *) pTestDirPath);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = FMGMT_fopen (TEST_FILE1, "r", &pFile);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* clear buffer for new read */
    status = DIGI_MEMSET (pBufferIn, 0x00, TEST_FILE_DATA_LEN);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = FMGMT_fread (pBufferIn, 1, TEST_FILE_DATA_LEN, pFile, &bytesRead);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = FMGMT_fclose (&pFile);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    for (int i = 0; i < TEST_FILE_DATA_LEN; i++)
    {
        if (pExpected[i] != pBufferIn[i])
        {
            status = ERR_GENERAL;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    /* successfully changed directories */
    /* rename file */
    status = FMGMT_rename (TEST_FILE1, TEST_FILE3);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* open new file and make sure it has same expected content */
    status = FMGMT_fopen (TEST_FILE3, "r", &pFile);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = FMGMT_fread (pBufferIn, 1, TEST_FILE_DATA_LEN, pFile, &bytesRead);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = FMGMT_fclose (&pFile);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    for (int i = 0; i < TEST_FILE_DATA_LEN; i++)
    {
        if (pExpected[i] != pBufferIn[i])
        {
            status = ERR_GENERAL;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    /* renamed file contains same content as original */
    status = FMGMT_changeCWD (pCurrentDirectory);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    DIGI_MEMSET (pCurrWorkingDir, 0x00, currWorkingDirLen);

    status = FMGMT_getCWD (pCurrWorkingDir, currWorkingDirLen);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    for (int i = 0;i < currentDirectoryLength - 1; i++)
    {
        if (pCurrentDirectory[i] != pCurrWorkingDir[i])
        {
            status = ERR_GENERAL;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__ */

static MSTATUS testDirectoryPath (const sbyte *pDirectoryPath, const sbyte *pFilePath)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte *pDirPathAlloc = NULL;
    ubyte4 dirPathAllocLen;
    ubyte pDirPath[1024];
    ubyte4 dirPathLen = 1024;
    ubyte4 calculatedLength;
    ubyte4 expectedDirPathLen = DIGI_STRLEN (pDirectoryPath);
    ubyte pFileName[64];
    ubyte4 fileNameLength = 64;

    status = FMGMT_getDirectoryPath (pFilePath,  pDirPath, dirPathLen);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    calculatedLength = DIGI_STRLEN ((const sbyte *) pDirPath);

    if (expectedDirPathLen != calculatedLength)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    for (int i = 0;i < expectedDirPathLen ; i++)
    {
        if (pDirPath[i] != pDirectoryPath[i])
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    status = FMGMT_getDirectoryPathAlloc (pFilePath, &pDirPathAlloc);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    dirPathAllocLen = DIGI_STRLEN ((const sbyte *) pDirPathAlloc);

    if (expectedDirPathLen != dirPathAllocLen)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    for (int i = 0;i < expectedDirPathLen ; i++)
    {
        if (pDirPathAlloc[i] != pDirectoryPath[i])
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

exit:
    DIGI_FREE((void **) &pDirPathAlloc);
    return status;
}

#define TEST_ENV_VAR_NAME "ABCD_NOGO"
#define TEST_ENV_VAR_VALUE "test_value_here"

static MSTATUS testEnvVariableAPI ()
{
    MSTATUS status;
    const sbyte *pVariableName = TEST_ENV_VAR_NAME;
    const sbyte *pVariableValue = TEST_ENV_VAR_VALUE;
#ifdef __RTOS_WIN32__
    const sbyte *pEnvVar = TEST_ENV_VAR_NAME "=" TEST_ENV_VAR_VALUE;
    const sbyte *pUnsetEnv = TEST_ENV_VAR_NAME "=";
#endif
    sbyte *pRetrievedValue;
    ubyte4 retrievedValueLen;

    sbyte pValueBuffer[512];
    ubyte4 valueBufferLen = 512;

#if defined(__RTOS_WIN32__)
    if (0 != _putenv((const char *) pEnvVar))
#else
    if (0 != setenv (pVariableName, pVariableValue, 1))
#endif
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = FMGMT_getEnvironmentVariableValue (pVariableName, pValueBuffer, valueBufferLen);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    for (int i = 0;i < DIGI_STRLEN (pVariableValue) ; i++)
    {
        if (pValueBuffer[i] != pVariableValue[i])
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    status = FMGMT_getEnvironmentVariableValueAlloc (pVariableName, &pRetrievedValue);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    retrievedValueLen = DIGI_STRLEN (pRetrievedValue);
    for (int i = 0;i < DIGI_STRLEN (pVariableValue) ; i++)
    {
        if (pRetrievedValue[i] != pVariableValue[i])
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

#if defined(__RTOS_WIN32__)
    _putenv((const char *) pUnsetEnv);
#else
    unsetenv (pVariableName);
#endif
exit:
    DIGI_FREE((void **) &pRetrievedValue);
    return status;
}

static MSTATUS testDirectoryAPI (const sbyte *pTestDirectory)
{
    MSTATUS status = ERR_NULL_POINTER;
    DirectoryDescriptor pDir = NULL;
    DirectoryEntry dirEnt;
    intBoolean hasNext = TRUE;
    sbyte4 cmpRes = -1;

    status = FMGMT_getFirstFile (pTestDirectory, &pDir, &dirEnt);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    do
    {
        if (TEST_FILE1_LEN == dirEnt.nameLength)
        {
            DIGI_MEMCMP (dirEnt.pName, TEST_FILE1, TEST_FILE1_LEN, &cmpRes);
            if (0 == cmpRes)
            {
                if (FTFile != dirEnt.type)
                {
                    status = ERR_CMP;
                    UNITTEST_STATUS(__MOC_LINE__, status);
                    goto exit;
                }
            }
        }

        if (2 == dirEnt.nameLength)
        {
            DIGI_MEMCMP (dirEnt.pName, "..", 2, &cmpRes);
            if (0 == cmpRes)
            {
                if (FTDirectory != dirEnt.type)
                {
                    status = ERR_CMP;
                    UNITTEST_STATUS(__MOC_LINE__, status);
                    goto exit;
                }
            }
        }

        status = FMGMT_getNextFile (pDir,  &dirEnt);
        if (OK != status)
            goto exit;

    } while (FTNone != dirEnt.type);

    status = FMGMT_closeDir (&pDir);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:
    return status;
}

static MSTATUS testFullPaths (const sbyte *pDirectoryPath)
{
    MSTATUS status;
    sbyte *pAbsPath = NULL;
    ubyte4 absPathLen;
    sbyte pAbsPathBuffer[1024];
    ubyte4 absPathBufferLen = 1024;
    sbyte pTempDir[1024];
    sbyte *pTemp = pTempDir;
    int i;

    status = FMGMT_getFullPath (".", pAbsPathBuffer, absPathBufferLen);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    for (i = 0;i < (DIGI_STRLEN (pDirectoryPath) - 1) ; i++)
    {
        if (pDirectoryPath[i] != pAbsPathBuffer[i])
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    status = FMGMT_getFullPathAlloc (".", &pAbsPath);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    absPathLen = DIGI_STRLEN (pAbsPath);
    
    if (absPathLen != (DIGI_STRLEN (pDirectoryPath) - 1))
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    for (i = 0;i < absPathLen ; i++)
    {
        if (pDirectoryPath[i] != pAbsPath[i])
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    if (TRUE == FMGMT_pathExists("temp", NULL))
    {
        status = ERR_DIR_EXISTS;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    DIGI_MEMCPY(pTemp, pDirectoryPath, DIGI_STRLEN(pDirectoryPath));
    pTemp += DIGI_STRLEN(pDirectoryPath);
    DIGI_MEMCPY(pTemp, "temp", DIGI_STRLEN("temp"));
    pTemp += DIGI_STRLEN("temp");
    *pTemp = '\0';
    pTemp++;

    DIGI_MEMSET(pAbsPathBuffer, 0xAB, absPathBufferLen);
    status = FMGMT_getFullPath ("temp", pAbsPathBuffer, absPathBufferLen);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    ubyte4 tLen = DIGI_STRLEN(pTempDir);
    ubyte4 aLen = DIGI_STRLEN(pAbsPathBuffer);

    if (tLen != aLen)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    for (i = 0; i < DIGI_STRLEN(pTempDir); i++)
    {
        if (pTempDir[i] != pAbsPathBuffer[i])
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    DIGI_FREE((void **) &pAbsPath);
    status = FMGMT_getFullPathAlloc ("temp", &pAbsPath);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (DIGI_STRLEN(pTempDir) != DIGI_STRLEN(pAbsPath))
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    for (i = 0; i < DIGI_STRLEN(pTempDir); i++)
    {
        if (pTempDir[i] != pAbsPath[i])
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

exit:
    DIGI_FREE((void **) &pAbsPath);
    return status;
}

static MSTATUS testRecursiveDelete ()
{
    MSTATUS status;
    FileDescriptor pFile;

    /* check all files necessary are present: */
    if (FALSE == FMGMT_pathExists (pTestFile1Path, NULL))
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (FALSE == FMGMT_pathExists (pTestFile2Path, NULL))
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (FALSE == FMGMT_pathExists (pTestFile3Path, NULL))
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (FALSE == FMGMT_pathExists (pTestFile4Path, NULL))
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = FMGMT_remove (pTestDirPath, TRUE);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* check all files necessary are present: */
    if (TRUE == FMGMT_pathExists (pTestFile1Path, NULL))
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (TRUE == FMGMT_pathExists (pTestFile2Path, NULL))
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (TRUE == FMGMT_pathExists (pTestFile3Path, NULL))
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (TRUE == FMGMT_pathExists (pTestFile4Path, NULL))
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (TRUE == FMGMT_pathExists (pTestSubDirPath, NULL))
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (TRUE == FMGMT_pathExists (pTestDirPath, NULL))
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:
    return status;
}

static ubyte4 negativeTests (const sbyte *pPath)
{
    MSTATUS status = OK;
    ubyte4 errorCount = 0;
    FileDescriptorInfo fileInfo;
    sbyte *pTemp = NULL;
    ubyte pBuffer[1024];
    ubyte4 bufferLen = 1024;

    if (TRUE == FMGMT_pathExists (NULL, &fileInfo))
    {
        errorCount += 1;
    }

    status = FMGMT_getCWD (NULL, 0);
    if (ERR_NULL_POINTER != status)
        errorCount += 1;

    status = FMGMT_changeCWD (NULL);
    if (ERR_NULL_POINTER != status)
        errorCount += 1;

    status = FMGMT_remove (NULL, TRUE);
    if (ERR_NULL_POINTER != status)
        errorCount += 1;

    status = FMGMT_remove (NULL, FALSE);
    if (ERR_NULL_POINTER != status)
        errorCount += 1;

    status = FMGMT_getFirstFile (NULL, NULL, NULL);
    if (ERR_NULL_POINTER != status)
        errorCount += 1;

    status = FMGMT_getNextFile (NULL, NULL);
    if (ERR_NULL_POINTER != status)
        errorCount += 1;

    status = FMGMT_closeDir (NULL);
    if (ERR_NULL_POINTER != status)
        errorCount += 1;

    status = FMGMT_fopen (NULL, NULL, NULL);
    if (ERR_NULL_POINTER != status)
        errorCount += 1;

    status = FMGMT_fclose (NULL);
    if (ERR_NULL_POINTER != status)
        errorCount += 1;

    status = FMGMT_fread (NULL, 0, 0, NULL, NULL);
    if (ERR_NULL_POINTER != status)
        errorCount += 1;

    status = FMGMT_fseek (NULL, 0, 0);
    if (ERR_NULL_POINTER != status)
        errorCount += 1;

    status = FMGMT_fflush (NULL);
    if (ERR_NULL_POINTER != status)
        errorCount += 1;

    status = FMGMT_fprintf (NULL, NULL);
    if (ERR_NULL_POINTER != status)
        errorCount += 1;

    status = FMGMT_ftell (NULL, NULL);
    if (ERR_NULL_POINTER != status)
        errorCount += 1;

    if (NULL != FMGMT_fgets (NULL, 0, NULL))
        errorCount += 1;

    if (MOC_EOF != FMGMT_fgetc (NULL))
        errorCount += 1;

    status = FMGMT_fputs (NULL, NULL);
    if (-1 != status)
        errorCount += 1;

    status = FMGMT_getDirectoryPath (NULL, NULL, 0);
    if (ERR_NULL_POINTER != status)
        errorCount += 1;

    status = FMGMT_getDirectoryPathAlloc (NULL, NULL);
    if (ERR_NULL_POINTER != status)
        errorCount += 1;

    status = FMGMT_getFullPath (NULL, NULL, 0);
    if (ERR_NULL_POINTER != status)
        errorCount += 1;

    status = FMGMT_getFullPathAlloc (NULL, NULL);
    if (ERR_NULL_POINTER != status)
        errorCount += 1;

    status = FMGMT_getEnvironmentVariableValue (NULL, NULL, 0);
    if (ERR_NULL_POINTER != status)
        errorCount += 1;

    status = FMGMT_getProcessPath (NULL, 0, NULL);
    if (ERR_NULL_POINTER != status)
        errorCount += 1;

    status = FMGMT_getProcessPath (pBuffer, 1, NULL);
    if (ERR_NULL_POINTER != status)
        errorCount += 1;

    status = FMGMT_getProcessPathAlloc (NULL);
    if (ERR_NULL_POINTER != status)
        errorCount += 1;

#ifndef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    status = FMGMT_getDirectoryPathAlloc ("aaaaaaaaaaaa", &pTemp);
    if (OK == status)
        errorCount += 1;
#endif

    status = FMGMT_getFullPath ("", pBuffer, bufferLen);
    if (OK == status)
        errorCount += 1;

    status = FMGMT_getFullPath (".", pBuffer, 2);
    if (ERR_BUFFER_OVERFLOW != status)
        errorCount += 1;

    if (NULL != pTemp)
        DIGI_FREE ((void **) &pTemp);
    return errorCount;
}

static MSTATUS negativeRename (sbyte *pOldName, sbyte *pNewName, sbyte *pDirPath)
{
    MSTATUS status;
    FileDescriptorInfo fileInfo;
    sbyte temp;
    sbyte4 oldNameLength;
    sbyte4 i;
    sbyte *pTempName = NULL;

    oldNameLength = DIGI_STRLEN (pOldName);

    DIGI_MALLOC ((void **) &pTempName, oldNameLength + 1);
    DIGI_MEMCPY (pTempName, pOldName, oldNameLength);

    pTempName[oldNameLength] = '\0';

    if (OK == FMGMT_rename (NULL, pNewName))
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (OK == FMGMT_rename (NULL, NULL))
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (OK == FMGMT_rename (pOldName, NULL))
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* check directory exists */
    if (FALSE == FMGMT_pathExists (pDirPath, &fileInfo))
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (FTDirectory != fileInfo.type)
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (FALSE == FMGMT_pathExists (pOldName, &fileInfo))
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* if new name is a directory and the directory is not empty,
     * error should be ERR_DIR_EXISTS */
    status = FMGMT_rename (pOldName, pDirPath);
    if (OK == status)
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    i = 0;
    /* change a character in pOldName */
    while (i < oldNameLength)
    {
        if ((('a' <= pTempName[i]) && ('z' >= pTempName[i])) ||
            (('A' <= pTempName[i]) && ('Z' >= pTempName[i])))
        {
            temp = pTempName[i];
            if ('X' != pTempName[i])
            {
                pTempName[i] = 'X';
            }
            else if ('Z' != pTempName[i])
            {
                pTempName[i] = 'Z';
            }

            break;
        }
        i++;
    }

    status = FMGMT_rename (pTempName, pNewName);
    if (ERR_DIR_INVALID_PATH != status)
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
    status = OK;

exit:
    if (NULL != pTempName)
        DIGI_FREE ((void **) &pTempName);

    return status;
}

static MSTATUS negativeMkdir (sbyte *pExistingDirectory)
{
    MSTATUS status;
    sbyte temp;
    sbyte4 i;
    sbyte4 dirLength;
    sbyte *pTempDir = NULL;

    dirLength = DIGI_STRLEN (pExistingDirectory);

    DIGI_MALLOC ((void **)  &pTempDir, dirLength + 1);
    DIGI_MEMCPY (pTempDir, pExistingDirectory, dirLength);
    pTempDir[dirLength] = '\0';
    status = FMGMT_mkdir (pTempDir, 0777);
    if (ERR_DIR_EXISTS != status)
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    i = 0;
    /* change a character in pTempDir */
    while (i < dirLength)
    {
        if ((('a' <= pTempDir[i]) && ('z' >= pTempDir[i])) ||
            (('A' <= pTempDir[i]) && ('Z' >= pTempDir[i])))
        {
            temp = pTempDir[i];
            if ('X' != pTempDir[i])
            {
                pTempDir[i] = 'X';
            }
            else if ('Z' != pTempDir[i])
            {
                pTempDir[i] = 'Z';
            }

            break;
        }
        i++;
    }

    status = FMGMT_mkdir (pTempDir, 0777);
    if (ERR_DIR_INVALID_PATH != status)
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = OK;

exit:
    if (NULL != pTempDir)
        DIGI_FREE ((void **) &pTempDir);

    return status;
}

static MSTATUS negativeRemove (sbyte *pFilePath, sbyte *pDirPath)
{
    MSTATUS status;
    FileDescriptor pFile = NULL;

    status = FMGMT_mkdir (pDirPath, 0777);
    if (OK != status)
        goto exit;

    if (FALSE == FMGMT_pathExists (pDirPath, NULL))
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
    status = testFile1 (pFilePath);
    if (OK != status)
    {
        goto exit;
    }

    status = FMGMT_remove (pDirPath, FALSE);
    if (OK == status)
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
    status = OK;

exit:
    return status;
}

static MSTATUS negativeGetCWD ()
{
    MSTATUS status;
    ubyte pPath[1024] = { 0 };
    ubyte4 pathLen = 1024;

    status = FMGMT_getCWD (pPath, 2);
    if (ERR_BUFFER_OVERFLOW != status)
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = OK;
exit:
    return status;
}

static MSTATUS negativeChangeCWD (sbyte *pNewDir, sbyte4 newDirLen, sbyte *pFilePath)
{
    MSTATUS status;
    sbyte temp;
    sbyte *pTempDir = NULL;
    sbyte4 tempDirLen;
    sbyte4 i = 0;

    DIGI_MALLOC ((void **) &pTempDir, newDirLen + 1);
    DIGI_MEMCPY (pTempDir, pNewDir, newDirLen);
    pTempDir[newDirLen] = '\0';

    while (i < newDirLen)
    {
        if ((('a' <= pTempDir[i]) && ('z' >= pTempDir[i])) ||
            (('A' <= pTempDir[i]) && ('Z' >= pTempDir[i])))
        {
            temp = pTempDir[i];
            if ('X' != pTempDir[i])
            {
                pTempDir[i] = 'X';
            }
            else if ('Z' != pTempDir[i])
            {
                pTempDir[i] = 'Z';
            }

            break;
        }
        i++;
    }

    status = FMGMT_changeCWD (pTempDir);
    if (ERR_DIR_INVALID_PATH != status)
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }


    status = FMGMT_changeCWD (pFilePath);
    if (OK == status)
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = OK;

exit:
    if (NULL != pTempDir)
        DIGI_FREE ((void **) &pTempDir);
    return status;
}

static MSTATUS negativeDirTest (const sbyte *pDirPath, const sbyte *pFilePath)
{
    MSTATUS status;
    DirectoryDescriptor pDir = NULL;
    DirectoryEntry pDirEntry;
    sbyte temp;
    sbyte4 i = 0;
    sbyte4 filePathLen, dirPathLen;
    sbyte *pTempDir = NULL;


    filePathLen = DIGI_STRLEN (pFilePath);
    dirPathLen = DIGI_STRLEN (pDirPath);

    DIGI_MALLOC ((void **) &pTempDir, dirPathLen + 1);
    DIGI_MEMCPY (pTempDir, pDirPath, dirPathLen);
    pTempDir[dirPathLen] = '\0';


    while (i < dirPathLen)
    {
        if ((('a' <= pTempDir[i]) && ('z' >= pTempDir[i])) ||
            (('A' <= pTempDir[i]) && ('Z' >= pTempDir[i])))
        {
            temp = pTempDir[i];
            if ('X' != pTempDir[i])
            {
                pTempDir[i] = 'X';
            }
            else if ('Z' != pTempDir[i])
            {
                pTempDir[i] = 'Z';
            }

            break;
        }
        i++;
    }

    status = FMGMT_getFirstFile (pTempDir, &pDir, &pDirEntry);
    if (ERR_DIR_INVALID_PATH != status)
    {
        status = ERR_GENERAL;
        goto exit;
    }

    status = FMGMT_getFirstFile (pFilePath, &pDir, &pDirEntry);
    if (ERR_DIR_NOT_DIRECTORY != status)
    {
        status = ERR_GENERAL;
        goto exit;
    }

    status = OK;

exit:
    if (NULL != pTempDir)
        DIGI_FREE ((void **) &pTempDir);

    return status;
}

static MSTATUS negativeFileStreaming (const sbyte *pFilePath, const sbyte *pDirPath)
{
    MSTATUS status;
    sbyte *pTmpPath = NULL;
    sbyte4 i = 0;
    sbyte temp;
    sbyte4 fileNameLen;
    FileDescriptor pFile;

    fileNameLen = DIGI_STRLEN (pFilePath);

    DIGI_MALLOC ((void **) &pTmpPath, fileNameLen + 1);
    DIGI_MEMCPY (pTmpPath, pFilePath, fileNameLen);
    pTmpPath[fileNameLen] = '\0';

    while (i < fileNameLen)
    {
        if ((('a' <= pTmpPath[i]) && ('z' >= pTmpPath[i])) ||
            (('A' <= pTmpPath[i]) && ('Z' >= pTmpPath[i])))
        {
            temp = pTmpPath[i];
            if ('X' != pTmpPath[i])
            {
                pTmpPath[i] = 'X';
            }
            else if ('Z' != pTmpPath[i])
            {
                pTmpPath[i] = 'Z';
            }

            break;
        }
        i++;
    }

    status = FMGMT_fopen (pTmpPath, "r", &pFile);
    if (OK == status)
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* cannot open directory with write permissions */
    status = FMGMT_fopen (pDirPath, "w", &pFile);
    if (OK == status)
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

#ifndef __RTOS_WIN32__
    status = FMGMT_fopen (pDirPath, "x", &pFile);
    if (OK == status)
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
#endif

    status = OK;

exit:
    DIGI_FREE((void **) &pTmpPath);
    return status;
}

MSTATUS removeProcessName(sbyte *pPath)
{
    MSTATUS status = OK;
    sbyte4 i, len;

    len = DIGI_STRLEN(pPath);
    for (i = len - 1; i >= 0; i--)
    {
#ifdef __RTOS_WIN32__
            if (pPath[i] == '\\')
#else
            if (pPath[i] == '/')
#endif
                break;
    }

    if (i < 0)
    {
        status = ERR_PATH_IS_INVALID;
        goto exit;
    }
    pPath[i + 1] = '\0';
exit:
    return status;
}

static MSTATUS testGetProcessPath(sbyte *pProcessPath)
{
    MSTATUS status;
    sbyte pPath[1024];
    sbyte4 pathLen;
    sbyte4 processPathLen = DIGI_STRLEN(pProcessPath);
    ubyte4 bytesRead;

    /* Test to make sure error is thrown if buffer is too small. Not enough
     * space for NULL terminator so implementation should fail. */
    pathLen = processPathLen;
    status = FMGMT_getProcessPath(pPath, pathLen, &bytesRead);
    if (OK == status)
    {
        status = ERR_GENERAL;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* Exact length should succeed. */
    pathLen = processPathLen + 1;
    status = FMGMT_getProcessPath(pPath, pathLen, &bytesRead);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (bytesRead != processPathLen)
    {
        status = ERR_BAD_LENGTH;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:

    return status;
}

static int testDoubleDotOp (sbyte *pSrc)
{
    MSTATUS status;
    ubyte pBuff[1024];
    ubyte4 buffLen = 1024;
    printf("buffer in = %s\n", pSrc);
    status = FMGMT_getFullPath (pSrc, pBuff, buffLen);
    if (OK == status)
    {
        printf("abspath = %s\n", pBuff);
        return 0;
    }
    return 1;
}

static int testAllDoubleDotOp ()
{
    sbyte4 errorCount = 0;
    ubyte *pSrc = "../"TEST_DIRECTORY"/da_log3.txt";
    errorCount += testDoubleDotOp (pSrc);

    return errorCount;
}

static int testCommonUtils ()
{
    MSTATUS status;
    ubyte *pBuffer = NULL;
    ubyte4 bufferLen = 0;
    ubyte4 errorCount = 0;
    sbyte4 cmpRes = -1;
    ubyte *pFileCopy = NULL;
    ubyte4 fileCopyLen = 0;
    intBoolean fileExists = FALSE;

    status = DIGICERT_writeFile (pTestFile7Path, TEST_FILE_DATA, TEST_FILE_DATA_LEN);
    if (OK != status)
        goto exit;

    status = DIGICERT_readFile (pTestFile7Path, &pBuffer, &bufferLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP (TEST_FILE_DATA, pBuffer, bufferLen, &cmpRes);
    if (OK != status)
        goto exit;

    /* content should be the same */
    if (0 != cmpRes)
        goto exit;

    status = DIGICERT_deleteFile (pTestFile7Path);
    if (OK != status)
        goto exit;

    /* we shouldn't find file after DIGICERT_deleteFile */
    if (TRUE == FMGMT_pathExists (pTestFile7Path, NULL))
        goto exit;

    status = DIGICERT_copyFile (pTestFile1Path, pTestFile7Path);
    if (OK != status)
        goto exit;

    DIGI_FREE ((void **) &pBuffer);
    status = DIGICERT_readFile (pTestFile7Path, &pBuffer, &bufferLen);
    if (OK != status)
        goto exit;

    cmpRes = -1;
    status = DIGI_MEMCMP (TEST_FILE_DATA, pBuffer, bufferLen, &cmpRes);
    if (OK != status)
        goto exit;

    /* content should be the same */
    if (0 != cmpRes)
    {
        status = ERR_GENERAL;
        goto exit;
    }

    status = DIGICERT_deleteFile (pTestFile7Path);
    if (OK != status)
        goto exit;

    /* we shouldn't find file after DIGICERT_deleteFile */
    if (TRUE == FMGMT_pathExists (pTestFile7Path, NULL))
        goto exit;

    /* test appending */
    status = DIGICERT_writeFile (pTestFile7Path, TEST_FILE_DATA, 5);
    if (OK != status)
        goto exit;

    status = DIGICERT_appendFile (pTestFile7Path, TEST_FILE_DATA + 5, TEST_FILE_DATA_LEN - 5);
    if (OK != status)
        goto exit;

    DIGI_FREE ((void **) &pBuffer);
    status = DIGICERT_readFile (pTestFile7Path, &pBuffer, &bufferLen);
    if (OK != status)
        goto exit;

    cmpRes = -1;
    status = DIGI_MEMCMP (TEST_FILE_DATA, pBuffer, bufferLen, &cmpRes);
    if (OK != status)
        goto exit;

    /* content should be the same */
    if (0 != cmpRes)
    {
        status = ERR_GENERAL;
        goto exit;
    }

    fileCopyLen = DIGI_STRLEN (pTestFile7Path) - 4;
    status = DIGI_MALLOC((void **) &pFileCopy, fileCopyLen + 1);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY (pFileCopy, pTestFile7Path, fileCopyLen);
    if (OK != status)
        goto exit;

    pFileCopy[fileCopyLen] = '\0';
    status = DIGICERT_checkFile (pFileCopy, ".txt", &fileExists);
    if (OK != status)
        goto exit;

    if (FALSE == fileExists)
    {
        status = ERR_GENERAL;
        goto exit;
    }

    status = DIGICERT_deleteFile (pTestFile7Path);
    if (OK != status)
        goto exit;

exit:
    DIGI_FREE ((void **) &pBuffer);
    DIGI_FREE ((void **) &pFileCopy);
    return status;
}

int mfmgmt_test()
{
    MSTATUS status;
    ubyte4 errorCount = 0;
    sbyte *pProcessPath = NULL;
    sbyte pProcessBuffer[1024];
    ubyte4 processBufferLen = 1024;
    ubyte4 bytesRead;
    sbyte pCWD[1024] = { 0 };

    status = FMGMT_getCWD(pCWD, sizeof(pCWD));
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    ubyte pDirBuff[1024];
    sbyte *pDirFullPath = NULL;
    ubyte4 dirFullPathLen = 0;
    /* For testing purposes let's use getcwd to get a
     * starting directory for FMGMT_setMountPoint() */
    getcwd (pDirBuff, 1024);

    status = FMGMT_setMountPoint ("/home");
    if (OK != status)
    {
        printf("Error thrown here\n");
        errorCount += 1;
        goto exit;
    }

    status = FMGMT_changeCWD (pDirBuff + DIGI_STRLEN("/home"));
#endif

    /* get test directory */
    status = FMGMT_getProcessPathAlloc (&pProcessPath);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
        goto exit;
    }

    status = FMGMT_getProcessPath (pProcessBuffer, processBufferLen, &bytesRead);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
        goto exit;
    }

    for (int i = 0;i < DIGI_STRLEN (pProcessPath) ; i++)
    {
        if (pProcessPath[i] != pProcessBuffer[i])
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            errorCount += 1;
            goto exit;
        }
    }

    printf("process: %s\n", pProcessPath);

    status = testGetProcessPath(pProcessPath);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
        goto exit;
    }

    status = removeProcessName(pProcessPath);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
        goto exit;
    }

    printf("process directory: %s\n", pProcessPath);

    status = generateDataPaths (pProcessPath);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
        goto exit;
    }

    clearData ();

    /* create root directory */
    status = createRootDirectory ();
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
        goto exit;
    }

    /* create testfile1.txt */
    status = testFile1 (pTestFile1Path);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
        goto exit;
    }

    /* test common/utils.c functions that use FMGMT */
    status = testCommonUtils ();
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
        goto exit;
    }

    /* create testfile2.txt */
    status = testFile2 (pTestFile2Path);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
        goto exit;
    }

#ifndef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    /* renames testfile1.txt to testfile3.txt */
    status = changeCwdAndRename (pProcessPath, DIGI_STRLEN ((const sbyte *) pProcessPath));
    if (OK != status)
    {
        errorCount += 1;
        goto exit;
    }

    /* delete testfile3.txt */
    status = FMGMT_remove (pTestFile3Path, FALSE);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
        goto exit;
    }
#endif

    /* verify file is does not exist */
    if (TRUE == FMGMT_pathExists (pTestFile3Path, NULL))
    {
        status = ERR_GENERAL; 
        errorCount += 1;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* create testfile1.txt again */
    status = testFile1 (pTestFile1Path);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
        goto exit;
    }

#ifndef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    status = testDirectoryPath (pTestDirPath, pTestFile1Path);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
    }
#else
    status = FMGMT_getFullPathAlloc (pTestDirPath, &pDirFullPath);
    if (OK != status)
        goto exit;

    status = testDirectoryPath (pDirFullPath, pTestFile1Path);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
    }
#endif

    status = testEnvVariableAPI ();
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
    }

    status = testDirectoryAPI (pTestDirPath);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
    }

#ifndef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    status = testFullPaths (pProcessPath);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
    }
#endif

    /* create subdirectory */
    status = FMGMT_mkdir (pTestSubDirPath, 0777);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
        goto exit;
    }

    /* rename - test with empty directory */
    status = FMGMT_rename(pTestSubDirPath, pTestSubDirRenamePath);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
        goto exit;
    }

    if (TRUE == FMGMT_pathExists(pTestSubDirPath, NULL))
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (FALSE == FMGMT_pathExists(pTestSubDirRenamePath, NULL))
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = FMGMT_rename(pTestSubDirRenamePath, pTestSubDirPath);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* create testfile3.txt */
    status = testFile1 (pTestFile3Path);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* create testfile4.txt, this file goes in sub directory */
    status = testFile1 (pTestFile4Path);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    errorCount += testAllDoubleDotOp ();

    /* rename - test with non empty directory */
    status = FMGMT_rename(pTestSubDirPath, pTestSubDirRenamePath);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (TRUE == FMGMT_pathExists(pTestSubDirPath, NULL))
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if (FALSE == FMGMT_pathExists(pTestSubDirRenamePath, NULL))
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    status = FMGMT_rename(pTestSubDirRenamePath, pTestSubDirPath);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* 
     * testfile1.txt
     * testfile2.txt
     * testfile3.txt
     * sub_dir/testfile4.txt */

    errorCount += negativeTests (pProcessPath);

    status = negativeRename (pTestFile1Path, pTestFile5Path, pTestSubDirPath);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
    }

    status = negativeMkdir (pTestSubDirPath);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
    }

    status = negativeRemove (pTestFile6Path, pTestDeleteDirPath);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
    }

    status = negativeGetCWD ();
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
    }

    status = negativeChangeCWD (pTestDirPath, DIGI_STRLEN (pTestDirPath), pTestFile1Path);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
    }

    status = negativeDirTest (pTestDirPath, pTestFile1Path);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
    }

    status = negativeFileStreaming (pTestFile1Path, pTestDirPath);
    if (OK != status)
    {
        UNITTEST_STATUS(__MOC_LINE__, status);
        errorCount += 1;
    }


    status = testRecursiveDelete ();

exit:
    DIGI_FREE((void **) &pTestDirPath);
    DIGI_FREE((void **) &pTestSubDirPath);
    DIGI_FREE((void **) &pTestSubDirRenamePath);
    DIGI_FREE((void **) &pTestDeleteDirPath);
#ifndef __ENABLE_DIGICERT_FMGMT_FORCE_ABSOLUTE_PATH__
    DIGI_FREE((void **) &pTestFile1Path);
    DIGI_FREE((void **) &pTestFile2Path);
    DIGI_FREE((void **) &pTestFile3Path);
    DIGI_FREE((void **) &pTestFile5Path);
#endif
    DIGI_FREE((void **) &pTestFile4Path);
    DIGI_FREE((void **) &pTestFile6Path);

    printf("errorCount = %d\n", errorCount);
    if (NULL != pProcessPath)
        DIGI_FREE((void **) &pProcessPath);

    FMGMT_changeCWD(pCWD);

    if ((OK != status) || (0 < errorCount))
        return errorCount;
    return 0;
}
