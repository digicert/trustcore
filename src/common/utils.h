/*
 * utils.h
 *
 * Utility header for storing and retrieving keys
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

#ifndef __UTILS_HEADER__
#define __UTILS_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS UTILS_mkdir(const char* directory);
MOC_EXTERN MSTATUS UTILS_readFile(const char* pFilename, ubyte **ppRetBuffer, ubyte4 *pRetBufLength);
MOC_EXTERN MSTATUS UTILS_readFileRaw(const ubyte* pFileObj, ubyte **ppRetBuffer, ubyte4 *pRetBufLength);
MOC_EXTERN MSTATUS UTILS_freeReadFile(ubyte **ppRetBuffer);
MOC_EXTERN MSTATUS UTILS_writeFile(const char* pFilename, const ubyte *pBuffer, ubyte4 bufLength);
MOC_EXTERN MSTATUS UTILS_appendFile(const char* pFilename, const ubyte *pBuffer, ubyte4 bufLength);
MOC_EXTERN MSTATUS UTILS_copyFile(const char* pSrcFilename, const char* pDestFilename, ubyte4 bufLength);
MOC_EXTERN MSTATUS UTILS_deleteFile(const char *pFilename);
MOC_EXTERN MSTATUS UTILS_checkFile(const char *pFilename, const char *pExt, intBoolean *pFileExist);

typedef struct UTILS_FILE_STREAM_CTX
{
    void *pFileStream;
    ubyte4 fileSize;
    ubyte4 bytesRead;
    
} UTILS_FILE_STREAM_CTX;


MOC_EXTERN MSTATUS UTILS_initReadFile(UTILS_FILE_STREAM_CTX *pCtx, const char *pFilename);
MOC_EXTERN MSTATUS UTILS_updateReadFile(UTILS_FILE_STREAM_CTX *pCtx, ubyte *pBuffer, ubyte4 bufferLen, ubyte4 *pBytesRead, byteBoolean *pDone);
    
MOC_EXTERN MSTATUS UTILS_initWriteFile(UTILS_FILE_STREAM_CTX *pCtx, const char *pFilename);
MOC_EXTERN MSTATUS UTILS_updateWriteFile(UTILS_FILE_STREAM_CTX *pCtx, ubyte *pBuffer, ubyte4 bufferLen);

MOC_EXTERN MSTATUS UTILS_closeFile(UTILS_FILE_STREAM_CTX *pCtx);

#ifdef __cplusplus
}
#endif

#endif /* __UTILS_HEADER__ */

