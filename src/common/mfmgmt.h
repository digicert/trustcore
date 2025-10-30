/**
 * @file   mfgmt.h
 * @brief  Mocana File Manamgement Abstraction Layer
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */


/*------------------------------------------------------------------*/

#ifndef __MFMGMT_HEADER__
#define __MFMGMT_HEADER__

#include "mtypes.h"
#include "merrors.h"

#if defined(__RTOS_FREERTOS__) && !defined(__FREERTOS_SIMULATOR__) && !defined(__RTOS_FREERTOS_ESP32__)
#include "ff.h"
#ifndef file_size
#define file_size  f_size
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef void* DirectoryDescriptor;
typedef void* FileDescriptor;

/* Enumeration for file types */
enum fileDescriptorTypes {
    FTUnknown   = 0,
    FTDirectory = 1,
    FTFile      = 2,
    FTBlockFile = 3,
    FTCharFile  = 4,
    FTFifo      = 5,
    FTSymLink   = 6,
    FTSocket    = 7,
    FTNone      = 8
};

/* Structure used to hold information about a file.
 */
typedef struct FileDescriptorInfo {
    enum fileDescriptorTypes type;
    sbyte4 fileSize;    /* signed integer */

#ifdef __ENABLE_MOCANA_64_BIT__
    sbyte8 accessTime;  /* long */
    sbyte8 createTime;  /* long */
    sbyte8 modifyTime;  /* long */
#else
    sbyte4 accessTime;  /* long */
    sbyte4 createTime;  /* long */
    sbyte4 modifyTime;  /* long */
#endif
    sbyte4 gid;         /* integer */
    sbyte4 uid;         /* integer */
    sbyte4 mode;        /* integer */
    byteBoolean isWrite;
    byteBoolean isRead;

} FileDescriptorInfo;

/* This structure contains information about a directory entry. The
 * fileDescriptorTypes variables provides information about what type of file
 * this is. The pName and nameLength variables is the location on the file
 * system of the current entry relative to the open directory.
 */
typedef struct DirectoryEntry
{
    enum fileDescriptorTypes type;
    void *pCtx;
    ubyte *pName;
    ubyte4 nameLength;
} DirectoryEntry;


#define MOC_EOF     -1

#if defined(__ZEPHYR_FMGMT__)
#define FMGMT_mkdir                             ZEPHYR_mkdir
#define FMGMT_remove                            ZEPHYR_remove
#define FMGMT_rename                            ZEPHYR_rename
#define FMGMT_pathExists                        ZEPHYR_pathExists

#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
#define FMGMT_fopenEx                           ZEPHYR_fopenEx
#define FMGMT_fcloseEx                          ZEPHYR_fcloseEx
#endif
#define FMGMT_fopen                             ZEPHYR_fopen
#define FMGMT_fclose                            ZEPHYR_fclose
#define FMGMT_fread                             ZEPHYR_fread
#define FMGMT_fwrite                            ZEPHYR_fwrite
#define FMGMT_fseek                             ZEPHYR_fseek
#define FMGMT_fflush                            ZEPHYR_fflush
#define FMGMT_fprintf                           ZEPHYR_fprintf
#define FMGMT_ftell                             ZEPHYR_ftell
#define FMGMT_fgets                             ZEPHYR_fgets
#define FMGMT_fgetc                             ZEPHYR_fgetc
#define FMGMT_fputs                             ZEPHYR_fputs

#define FMGMT_getFirstFile                      ZEPHYR_getFirstFile
#define FMGMT_closeDir                          ZEPHYR_closeDir
#define FMGMT_getNextFile                       ZEPHYR_getNextFile

#define FMGMT_getFullPath                       ZEPHYR_getFullPath
#define FMGMT_getFullPathAlloc                  ZEPHYR_getFullPathAlloc
#define FMGMT_getFullPathAllocAux               ZEPHYR_getFullPathAllocAux

#define FMGMT_getDirectoryPath                  ZEPHYR_getDirectoryPath
#define FMGMT_getDirectoryPathAlloc             ZEPHYR_getDirectoryPathAlloc
#define FMGMT_changeCWD                         ZEPHYR_changeCWD
#define FMGMT_getCWD                            ZEPHYR_getCWD

#define FMGMT_getEnvironmentVariableValue       ZEPHYR_getEnvironmentVariableValue
#define FMGMT_getEnvironmentVariableValueAlloc  ZEPHYR_getEnvironmentVariableValueAlloc

#define FMGMT_setMountPoint                     TP_setMountPoint
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
#define FMGMT_needFullPath                      ZEPHYR_needFullPath
#endif
#elif defined(__LINUX_FMGMT__)
#define FMGMT_mkdir                             LINUX_mkdir
#define FMGMT_remove                            LINUX_remove
#define FMGMT_rename                            LINUX_rename
#define FMGMT_pathExists                        LINUX_pathExists

#define FMGMT_fopen                             LINUX_fopen
#define FMGMT_fclose                            LINUX_fclose
#define FMGMT_fread                             LINUX_fread
#define FMGMT_fwrite                            LINUX_fwrite
#define FMGMT_fseek                             LINUX_fseek
#define FMGMT_fflush                            LINUX_fflush
#define FMGMT_fprintf                           LINUX_fprintf
#define FMGMT_ftell                             LINUX_ftell
#define FMGMT_fgets                             LINUX_fgets
#define FMGMT_fgetc                             LINUX_fgetc
#define FMGMT_fputs                             LINUX_fputs

#define FMGMT_getFirstFile                      LINUX_getFirstFile
#define FMGMT_closeDir                          LINUX_closeDir
#define FMGMT_getNextFile                       LINUX_getNextFile

#define FMGMT_getFullPath                       LINUX_getFullPath
#define FMGMT_getFullPathAlloc                  LINUX_getFullPathAlloc
#define FMGMT_getFullPathAllocAux               LINUX_getFullPathAllocAux

#define FMGMT_getDirectoryPath                  LINUX_getDirectoryPath
#define FMGMT_getDirectoryPathAlloc             LINUX_getDirectoryPathAlloc
#define FMGMT_changeCWD                         LINUX_changeCWD
#define FMGMT_getCWD                            LINUX_getCWD

#define FMGMT_getEnvironmentVariableValue       LINUX_getEnvironmentVariableValue
#define FMGMT_getEnvironmentVariableValueAlloc  LINUX_getEnvironmentVariableValueAlloc

#define FMGMT_getProcessPath                    LINUX_getProcessPath
#define FMGMT_getProcessPathAlloc               LINUX_getProcessPathAlloc

#define FMGMT_setMountPoint                     TP_setMountPoint
#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
#define FMGMT_needFullPath                      LINUX_needFullPath
#endif

/* Execute Process API needed */
#elif defined(__OSX_FMGMT__)
#define FMGMT_mkdir                             OSX_mkdir
#define FMGMT_remove                            OSX_remove
#define FMGMT_rename                            OSX_rename
#define FMGMT_pathExists                        OSX_pathExists

#define FMGMT_fopen                             OSX_fopen
#define FMGMT_fclose                            OSX_fclose
#define FMGMT_fread                             OSX_fread
#define FMGMT_fwrite                            OSX_fwrite
#define FMGMT_fseek                             OSX_fseek
#define FMGMT_fflush                            OSX_fflush
#define FMGMT_fprintf                           OSX_fprintf
#define FMGMT_ftell                             OSX_ftell
#define FMGMT_fgets                             OSX_fgets
#define FMGMT_fgetc                             OSX_fgetc
#define FMGMT_fputs                             OSX_fputs

#define FMGMT_getFirstFile                      OSX_getFirstFile
#define FMGMT_closeDir                          OSX_closeDir
#define FMGMT_getNextFile                       OSX_getNextFile

#define FMGMT_getFullPath                       OSX_getFullPath
#define FMGMT_getFullPathAlloc                  OSX_getFullPathAlloc

#define FMGMT_getDirectoryPath                  OSX_getDirectoryPath
#define FMGMT_getDirectoryPathAlloc             OSX_getDirectoryPathAlloc
#define FMGMT_changeCWD                         OSX_changeCWD
#define FMGMT_getCWD                            OSX_getCWD

#define FMGMT_getEnvironmentVariableValue       OSX_getEnvironmentVariableValue
#define FMGMT_getEnvironmentVariableValueAlloc  OSX_getEnvironmentVariableValueAlloc
#define FMGMT_getProcessPath                    OSX_getProcessPath
#define FMGMT_getProcessPathAlloc               OSX_getProcessPathAlloc

#elif defined(__VXWORKS_FMGMT__)
#define FMGMT_stat                              VXWORKS_stat
#define FMGMT_pathExists                        VXWORKS_pathExists
#define FMGMT_mkdir                             VXWORKS_mkdir
#define FMGMT_readlink                          VXWORKS_readlink
#define FMGMT_remove                            VXWORKS_remove
#define FMGMT_rename                            VXWORKS_rename

#define FMGMT_fopen                             VXWORKS_fopen
#define FMGMT_fclose                            VXWORKS_fclose
#define FMGMT_fread                             VXWORKS_fread
#define FMGMT_fwrite                            VXWORKS_fwrite
#define FMGMT_fseek                             VXWORKS_fseek
#define FMGMT_ftell                             VXWORKS_ftell
#define FMGMT_fflush                            VXWORKS_fflush
#define FMGMT_fprintf                           VXWORKS_fprintf
#define FMGMT_fgets                             VXWORKS_fgets

#define FMGMT_opendir                           VXWORKS_opendir
#define FMGMT_closeDir                          VXWORKS_closeDir
#define FMGMT_getFirstFile                      VXWORKS_getFirstFile
#define FMGMT_getNextFile                       VXWORKS_getNextFile
#define FMGMT_isFile                            VXWORKS_isFile
#define FMGMT_isDirectory                       VXWORKS_isDirectory

#define FMGMT_getFullPath                       VXWORKS_getFullPath
#define FMGMT_getFullPathAlloc                  VXWORKS_getFullPathAlloc
#define FMGMT_getDirectoryPath                  VXWORKS_getDirectoryPath
#define FMGMT_getDirectoryPathAlloc             VXWORKS_getDirectoryPathAlloc
#define FMGMT_getCWD                            VXWORKS_getCWD
#define FMGMT_changeCWD                         VXWORKS_changeCWD
#define FMGMT_changePwd                         VXWORKS_changePwd

#define FMGMT_getEnvironmentVariableValue       VXWORKS_getEnvironmentVariableValue
#define FMGMT_getEnvironmentVariableValueAlloc  VXWORKS_getEnvironmentVariableValueAlloc
#define FMGMT_getProcessPath                    VXWORKS_getProcessPath
#define FMGMT_getProcessPathAlloc               VXWORKS_getProcessPathAlloc

#elif defined(__QNX_FMGMT__)
#define FMGMT_stat                              QNX_stat
#define FMGMT_pathExists                        QNX_pathExists
#define FMGMT_mkdir                             QNX_mkdir
#define FMGMT_readlink                          QNX_readlink
#define FMGMT_remove                            QNX_remove
#define FMGMT_rename                            QNX_rename

#define FMGMT_fopen                             QNX_fopen
#define FMGMT_fclose                            QNX_fclose
#define FMGMT_fread                             QNX_fread
#define FMGMT_fwrite                            QNX_fwrite
#define FMGMT_fseek                             QNX_fseek
#define FMGMT_ftell                             QNX_ftell
#define FMGMT_fflush                            QNX_fflush
#define FMGMT_fprintf                           QNX_fprintf
#define FMGMT_fgets                             QNX_fgets

#define FMGMT_opendir                           QNX_opendir
#define FMGMT_closeDir                          QNX_closeDir
#define FMGMT_getFirstFile                      QNX_getFirstFile
#define FMGMT_getNextFile                       QNX_getNextFile
#define FMGMT_isFile                            QNX_isFile
#define FMGMT_isDirectory                       QNX_isDirectory

#define FMGMT_getFullPath                       QNX_getFullPath
#define FMGMT_getFullPathAlloc                  QNX_getFullPathAlloc
#define FMGMT_getDirectoryPath                  QNX_getDirectoryPath
#define FMGMT_getDirectoryPathAlloc             QNX_getDirectoryPathAlloc
#define FMGMT_getCWD                            QNX_getCWD
#define FMGMT_changeCWD                         QNX_changeCWD
#define FMGMT_changePwd                         QNX_changePwd

#define FMGMT_getEnvironmentVariableValue       QNX_getEnvironmentVariableValue
#define FMGMT_getEnvironmentVariableValueAlloc  QNX_getEnvironmentVariableValueAlloc
#define FMGMT_getProcessPath                    QNX_getProcessPath
#define FMGMT_getProcessPathAlloc               QNX_getProcessPathAlloc

#elif defined(__FREERTOS_FMGMT__)

#define FMGMT_rename                            FREERTOS_rename
#define FMGMT_fflush                            FREERTOS_fflush
#define FMGMT_ftell                             FREERTOS_ftell
#define FMGMT_fgets                             FREERTOS_fgets
#define FMGMT_fputs                             FREERTOS_fputs
#define FMGMT_pathExists                        FREERTOS_pathExists
#define FMGMT_mkdir                             FREERTOS_mkdir
#define FMGMT_remove                            FREERTOS_remove

#define FMGMT_fopen                             FREERTOS_fopen
#define FMGMT_fclose                            FREERTOS_fclose
#define FMGMT_fread                             FREERTOS_fread
#define FMGMT_fwrite                            FREERTOS_fwrite
#define FMGMT_fseek                             FREERTOS_fseek
#define FMGMT_fprintf                           FREERTOS_fprintf


#define FMGMT_closeDir                          FREERTOS_closeDir
#define FMGMT_getFirstFile                      FREERTOS_getFirstFile
#define FMGMT_getNextFile                       FREERTOS_getNextFile
#define FMGMT_changeCWD                         FREERTOS_changeCWD
#define FMGMT_getCWD                            FREERTOS_getCWD

#define FMGMT_getFullPath                       FREERTOS_getFullPath
#define FMGMT_getFullPathAlloc                  FREERTOS_getFullPathAlloc
#define FMGMT_getDirectoryPath                  FREERTOS_getDirectoryPath
#define FMGMT_getDirectoryPathAlloc             FREERTOS_getDirectoryPathAlloc

#define FMGMT_getEnvironmentVariableValue       FREERTOS_getEnvironmentVariableValue
#define FMGMT_getEnvironmentVariableValueAlloc  FREERTOS_getEnvironmentVariableValueAlloc
#define FMGMT_getProcessPath                    FREERTOS_getProcessPath
#define FMGMT_getProcessPathAlloc               FREERTOS_getProcessPathAlloc

#elif defined(__WIN32_FMGMT__)

#define FMGMT_stat                              WIN32_stat
#define FMGMT_pathExists                        WIN32_pathExists
#define FMGMT_mkdir                             WIN32_mkdir
#define FMGMT_readlink                          WIN32_readlink
#define FMGMT_remove                            WIN32_remove

#define FMGMT_fopen                             WIN32_fopen
#define FMGMT_fclose                            WIN32_fclose
#define FMGMT_fread                             WIN32_fread
#define FMGMT_fwrite                            WIN32_fwrite
#define FMGMT_fseek                             WIN32_fseek

#define FMGMT_openDir                           WIN32_opendir
#define FMGMT_closeDir                          WIN32_closedir
#define FMGMT_getFirstFile                      WIN32_getFirstFile
#define FMGMT_getNextFile                       WIN32_getNextFile
#define FMGMT_getDirectoryEntryName             WIN32_getDirectoryEntryName
#define FMGMT_getFullPath                       WIN32_getFullPath
#define FMGMT_isFile                            WIN32_isFile
#define FMGMT_isDirectory                       WIN32_isDirectory

#define FMGMT_getFullPathAlloc                  WIN32_getFullPathAlloc
#define FMGMT_getDirectoryPath                  WIN32_getDirectoryPath
#define FMGMT_getDirectoryPathAlloc             WIN32_getDirectoryPathAlloc
#define FMGMT_changeCWD                         WIN32_changeCWD
#define FMGMT_getCWD                            WIN32_getCWD
#define FMGMT_rename                            WIN32_rename
#define FMGMT_fflush                            WIN32_fflush
#define FMGMT_fprintf                           WIN32_fprintf
#define FMGMT_ftell                             WIN32_ftell
#define FMGMT_fgets                             WIN32_fgets
#define FMGMT_fgetc                             WIN32_fgetc
#define FMGMT_fputs                             WIN32_fputs

#define FMGMT_getEnvironmentVariableValue       WIN32_getEnvironmentVariableValue
#define FMGMT_getEnvironmentVariableValueAlloc  WIN32_getEnvironmentVariableValueAlloc
#define FMGMT_getProcessPath                    WIN32_getProcessPath
#define FMGMT_getProcessPathAlloc               WIN32_getProcessPathAlloc
#elif defined(__AZURE_FMGMT__)
#define FMGMT_pathExists                        AZURERTOS_pathExists
#define FMGMT_remove                            AZURERTOS_remove
#define FMGMT_rename                            AZURERTOS_rename
#define FMGMT_changeCWD                         AZURERTOS_changeCWD
#define FMGMT_getCWD                            AZURERTOS_getCWD
#define FMGMT_mkdir                             AZURERTOS_mkdir
#define FMGMT_getFirstFile                      AZURERTOS_getFirstFile
#define FMGMT_getFullPath                       AZURERTOS_getFullPath
#define FMGMT_getNextFile                       AZURERTOS_getNextFile
#define FMGMT_closeDir                          AZURERTOS_closeDir
#define FMGMT_fclose                            AZURERTOS_fclose
#define FMGMT_fopen                             AZURERTOS_fopen
#define FMGMT_fprintf                           AZURERTOS_fprintf
#define FMGMT_fread                             AZURERTOS_fread
#define FMGMT_fseek                             AZURERTOS_fseek
#define FMGMT_fwrite                            AZURERTOS_fwrite
#define FMGMT_fflush                            AZURERTOS_fflush
#define FMGMT_fgets                             AZURERTOS_fgets
#define FMGMT_getEnvironmentVariableValueAlloc  AZURERTOS_getEnvironmentVariableValueAlloc
#define FMGMT_getDirectoryPathAlloc             AZURERTOS_getDirectoryPathAlloc
#define FMGMT_ftell                             AZURERTOS_ftell
#else
#error UNSUPPORTED PLATFORM
#endif

/**
 * This function checks if the specified path exists or not. Optionally, the
 * caller can pass in a pointer to a \c FileDescriptorInfo structure. This
 * structure is populated with information about the path if the path exists.
 *
 * @param pPath     Path to check.
 * @param pType     Optional pointer, if provided and the path exists then this
 *                  pointer is populated with information about the path.
 *
 * @return         \c TRUE if the path exists, otherwise \c FALSE.
 */
MOC_EXTERN intBoolean FMGMT_pathExists (const sbyte *pPath, FileDescriptorInfo *pType);
/**
 * This function renames a file/directory with the old name to the new name.
 * Both arguments must either be a file path or directory path.
 *
 * @param pOldName  Name of existing file/directory to rename.
 * @param pNewName  New name of the file/directory.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_rename (const sbyte *pOldName, sbyte *pNewName);
/**
 * This function creates a directory with the specified mode. The mode specifies
 * the permission bits (and potentially other attributes) that the directory is
 * constructed with. The underlying OS implementation may or may not use the
 * mode specified when creating the directory.
 *
 * @param pDirectoryName    Path to the new directory to create.
 * @param mode              Attributes used to create the directory with (may
 *                          not be used depending on underlying OS).
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_mkdir (const sbyte *pDirectoryName, ubyte4 mode);
/**
 * This function gets the current working directory.
 *
 * @param pCwd      Buffer used to store the current working directory. Must be
 *                  large enough to store the directory.
 * @param cwdLength Length of the buffer used to store the current working
 *                  directory.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_getCWD (sbyte *pCwd, ubyte4 cwdLength);
/**
 * This function changes the current working directory.
 *
 * @param pNewCwd   The directory to change to.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_changeCWD (const sbyte *pNewCwd);
/**
 * This function deletes a file or empty directory specified by the path. If the
 * resursive parameter is set to \c TRUE then this function will also delete
 * non-empty directories.
 *
 * @param pFilePath The path to a file/directory to delete.
 * @param recursive Deletes directory even if it is non-empty when specified as
 *                  \c TRUE.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_remove (const sbyte *pFilePath, intBoolean recursive);
/**
 * This function gets the next directory entry from an open directory and
 * populates \c DirectoryEntry with it. Note that calls to methods which read
 * the next entry in a directory (such as FMGMT_getNextFile) overrides all the
 * data in the specified \c DirectoryEntry structure.
 *
 * @param pDirCtx   Directory context to retrieve the next entry from.
 * @param pFileCtx  Pointer populated with information about the next directory
 *                  entry.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_getNextFile (DirectoryDescriptor pDirCtx, DirectoryEntry *pFileCtx);
/**
 * This function opens the directory specified by pDirPath. A context is
 * allocated for the directory and the context is returned to the caller through
 * the \c DirectoryDescriptor structure. The caller must free the directory
 * context using FMGMT_closeDir. If the directory path does not exist an error
 * is thrown. The first entry in the directory is populated through the
 * \c DirectoryEntry structure. Calls to methods which read the next entry in a
 * directory (such as FMGMT_getNextFile) override the data in the given
 * \c DirectoryEntry structure.
 *
 *
 * @param pDirPath      The path to the directory to open.
 * @param ppNewDirCtx   Pointer to the location that will store the new
 *                      directory context.
 * @param pFirstFile    Pointer populated with information about the first
 *                      directory entry.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_getFirstFile (const sbyte *pDirPath, DirectoryDescriptor *ppNewDirCtx, DirectoryEntry *pFirstFile);
/**
 * This function frees any memory allocated during the creation of a directory
 * context.
 *
 * @param ppDirCtx  Directory context to free.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_closeDir (DirectoryDescriptor *ppDirCtx);

#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
/**
 * This function opens a file desciptor to the specified file.
 *
 * @param pFileName     Directory context to free.
 * @param pMode         Mode to open file in.
 * @param pFileCtx      Pointer to  file descriptor to initialize.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_fopenEx(const sbyte *pFileName, const sbyte *pMode, FileDescriptor pFileCtx);

/**
 * This function closes a file desciptor.
 *
 * @param pFileCtx The file descriptor to close.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_fcloseEx(FileDescriptor pFileCtx);
#endif

/**
 * This function opens a file desciptor to the specified file.
 *
 * @param pFileName     Directory context to free.
 * @param pMode         Mode to open file in.
 * @param ppNewFileCtx  Pointer to the location that will store the new file
 *                      descriptor.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_fopen (const sbyte *pFileName, const sbyte *pMode, FileDescriptor *ppNewFileCtx);
/**
 * This function closes a file desciptor.
 *
 * @param ppFileCtx The file descriptor to close.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_fclose (FileDescriptor *ppFileCtx);
/**
 * This function reads from the file stream stored in pFileCtx.
 * The caller supplies the number of items to read and the size of each item, in bytes.
 * The total number of bytes read from the file stream as returned in pBytesRead. The number
 * of bytes read may be less then the number of bytes requested in the case where
 * end-of-file is reached.
 *
 * @param pBuffer       Buffer populated with data from file.
 * @param itemSize      Number of bytes per item.
 * @param numOfItems    Number of items to read.
 * @param pFileCtx      File descriptor context.
 * @param pBytesRead    Pointer location used to store the number of bytes read.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_fread (ubyte *pBuffer, ubyte4 itemSize, ubyte4 numOfItems, FileDescriptor pFileCtx, ubyte4 *pBytesRead);
/**
 * This function writes to the file stream stored in pFileCtx.
 * The caller specified the size of each item, in bytes, and the number of items.
 * The number of bytes written to file stream are returned in pBytesWrote.
 *
 * @param pBuffer       Buffer containing data to write to the file descriptor.
 * @param itemSize      Number of bytes to write per item.
 * @param numOfItems    Number of items to write.
 * @param pFileCtx      File descriptor context.
 * @param pBytesWrote   Pointer location used to store the number of bytes
 *                      written.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_fwrite (const ubyte *pBuffer, ubyte4 itemSize, ubyte4 numOfItems, FileDescriptor pFileCtx, ubyte4 *pBytesWrote);
/**
 * This function sets the position in the file stream stored in the file descriptor.
 * The new position is calculated by adding offset to the position specified by m_whence.
 * The possible positions specified by m_whence are the following:
 *   MSEEK_SET - specifies the beginning of the file stream
 *   MSEEK_CUR - specifies the current index of the file stream
 *   MSEEK_END - specifies the end of the file stream
 *
 * @param pFileCtx      File descriptor context.
 * @param offset        Number of bytes to be offset.
 * @param m_whence      Enumeration that specifying where to start offset from.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */

#ifdef __ENABLE_MOCANA_64_BIT__
MOC_EXTERN MSTATUS FMGMT_fseek (FileDescriptor pFileCtx, sbyte8 offset, ubyte4 m_whence);
#else
MOC_EXTERN MSTATUS FMGMT_fseek (FileDescriptor pFileCtx, sbyte4 offset, ubyte4 m_whence);
#endif

/**
 * Forces a write of all the buffered data in the file stream stored in
 * pFileCtx.
 *
 * @param pFileCtx      File descriptor context.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_fflush (FileDescriptor pFileCtx);
/**
 * This function writes output to the file stream stored in pFileCtx, using the
 * format specified by the caller.
 *
 * @param pFileCtx      File descriptor context.
 * @param pFormat       Format of the data to write out.
 * @param ...           Variable number of arguments used to populate the
 *                      specified format.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_fprintf (FileDescriptor pFileCtx, const sbyte *pFormat, ...);
/**
 * This function retrieves the current position of the file stream stored in
 * pFileCtx. The position is stored in bytes at the location pointed to by
 * pOffset.
 *
 * @param pFileCtx      File descriptor context.
 * @param pOffset       Pointer populated with the offset into the file stream
 *                      in bytes.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_ftell (FileDescriptor pFileCtx, ubyte4 *pOffset);
/**
 * This function reads up to stringLen - 1 bytes from the file stream stored in
 * pFileCtx. The data is stored into the pString buffer and a NULL termination
 * character is stored after the last character read. Use MOC_STRLEN to retrieve
 * the number of bytes written to pString.
 *
 * @param pFileCtx      File descriptor context.
 * @param pString       Buffer where data is written out to. NULL terminated.
 * @param stringLen     Length of the buffer.
 *
 * @return          Returns pString buffer on succes, otherwise NULL
 */
MOC_EXTERN sbyte*  FMGMT_fgets (sbyte *pString, ubyte4 stringLen, FileDescriptor pFileCtx);
/**
 * This function reads the next character from the file stream stored in
 * pFileCtx.
 *
 * @param pFileCtx      File descriptor context.
 *
 * @return          Returns the next character in the file stream as a sbyte4,
 *                  otherwise MOC_EOF is on end of file or if an error occured
 */
MOC_EXTERN sbyte4  FMGMT_fgetc (FileDescriptor pFileCtx);
/**
 * This function writes a NULL terminated string to the file stream in pFileCtx.
 * The string is written out to the file stream without the NULL terminating
 * character.
 *
 * @param pString       NULL terminated string to write to file descriptor.
 * @param pFileCtx      File descriptor context.
 *
 * @return          Returns non-negative value on success.
 */
MOC_EXTERN sbyte4  FMGMT_fputs (sbyte *pString, FileDescriptor pFileCtx);
/**
 * This function takes in a path to a file as pFilePath and strips the file name
 * and separator from the file path, leaving the directory path. The directory
 * path is stored in pDirectoryPath. Use MOC_STRLEN to get the length of the
 * directory path.
 *
 * @param pFilePath             Path to file.
 * @param pDirectoryPath        Buffer where directory path is stored.
 * @param directoryPathLength   Length of the pDirectoryPath buffer.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_getDirectoryPath (const sbyte *pFilePath, sbyte *pDirectoryPath, ubyte4 directoryPathLength);
/**
 * This function takes in a path to a file as pFilePath and strips the file name
 * and separator from the file path, leaving the directory path. The directory
 * path is stored as a NULL terminated string at the location specified by
 * ppDirectoryPath. Use MOC_STRLEN to get the length of the directory path. The
 * directory path buffer is allocated and must be freed using MOC_FREE.
 *
 * @param pFilePath             Path to file.
 * @param ppDirectoryPath       Pointer address where NULL terminated directory
 *                              path is stored.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_getDirectoryPathAlloc (const sbyte *pFilePath, sbyte **ppDirectoryPath);
/**
 * This function takes in a relative path to a file/directory and returns the
 * absolute path to the same file/directory. The absolute path is stored as a
 * NULL terminated string to pAbsolutePath. Use MOC_STRLEN to get the length of
 * the value.
 *
 * @param pRelativePath         Relative path to file/directory.
 * @param pAbsolutePath         Buffer where absolute path will be stored.
 * @param absolutePathLength    Lenght of pAbsolutePath buffer.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_getFullPath (const sbyte *pRelativePath, sbyte *pAbsolutePath, ubyte4 absolutePathLength);
/**
 * This function takes in a relative path to a file/directory and returns the
 * absolute path to the same file/directory. The absolute path is stored as a
 * NULL terminated string at the location specified by ppAbsolutePath. Use
 * MOC_STRLEN to get the length of the value. The buffer is allocated
 * and must be freed using MOC_FREE.
 *
 * @param pRelativePath         Relative path to file/directory.
 * @param ppAbsolutePath        Pointer address where NULL terminated absolute
 *                              path is stored.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_getFullPathAlloc (const sbyte *pRelativePath, sbyte **ppAbsolutePath);
/**
 * This function retrieves the value of the environment variable specified
 * through pVariableName. The environment variable value is stored as a NULL
 * terminated string to pValueBuffer. Use MOC_STRLEN on pValueBuffer to retrieve
 * the length of the value. If the environment variable is not set, an error is
 * returned.
 *
 * @param pVariableName     Name of the environment variable to get.
 * @param pValueBuffer      Buffer where value of environment variable is
 *                          stored.
 * @param valueBufferLength Length of pValueBuffer in bytes.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_getEnvironmentVariableValue (const sbyte *pVariableName, sbyte *pValueBuffer, ubyte4 valueBufferLength);
/**
 * This function retrieves the value of the environment variable specified
 * through pVariableName. The environment variable value is stored as a NULL
 * terminated string at the location specified by ppValueBuffer on success. Use
 * MOC_STRLEN to get the length of the value. If the environment variable is not
 * set, an error is returned.
 *
 * @param pVariableName     Name of the environment variable to get.
 * @param ppValueBuffer     Pointer address where NULL terminated environment
 *                          variable value is stored.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_getEnvironmentVariableValueAlloc (const sbyte *pVariableName, sbyte **ppValueBuffer);
/**
 * This function retrieves the full path of the current process being executed,
 * including the process name and stores it in pProcessPath. The number of bytes
 * written to the buffer is stored in pBytesRead.
 *
 * @param pProcessPath      Buffer where process path is stored.
 * @param processPathLen    Length of pProcessPath buffer in bytes.
 * @param pBytesRead        Pointer address where number of bytes written is
 *                          stored.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_getProcessPath (sbyte *pProcessPath, ubyte4 processPathLen, ubyte4 *pBytesRead);
/**                                                                          * This function retrieves the full path of the current process being executed,
 * including the process name and stores it to the location specified by
 * ppProcessPath. The buffer is allocated and must be freed using
 * MOC_FREE. Use MOC_STRLEN to retrieve the length of the path.
 *
 * @param ppProcessPath     Pointer address where NULL terminated process
 *                          path is stored.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_getProcessPathAlloc (sbyte **ppProcessPath);

/**
 * This function sets the mount point using mount path and starting
 * directory path.
 *
 * @param pNewMountPath     NULL terminating string with path to mount point.
 * @param pNewDirectoryPath NULL terminating string with path to current working
 *                          directory from mount point.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN signed int FMGMT_setMountPoint (unsigned char *pNewMountPath);

#ifdef __ENABLE_MOCANA_FMGMT_FORCE_ABSOLUTE_PATH__
/**
 * This function frees memory used by mount point.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS FMGMT_freeMountPoint ();

MOC_EXTERN MSTATUS FMGMT_getFullPathAllocAux (const sbyte *pRelativePath, sbyte **ppAbsolutePath, intBoolean prefixMount);
MOC_EXTERN intBoolean FMGMT_needFullPath ();
#endif


#ifdef __cplusplus
}
#endif

#endif /* __MFMGMT_HEADER__ */
