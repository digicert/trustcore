/*
 * mime_parser.h
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
/**
 @file       mime_parser.h
 @brief      APIs for MIME parsing

 @filedoc    mime_parser.h
*/

#ifndef __MIME_PARSER_HEADER__
#define __MIME_PARSER_HEADER__

#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mfmgmt.h"

#ifdef __cplusplus
extern "C" {
#endif

/*----------------------------------------------------------------------------*/

#define MIME_CONTENT_TYPE_PKCS8_STR         "application/pkcs8"
#define MIME_CONTENT_TYPE_PKCS7_MIME_STR    "application/pkcs7-mime"

/*----------------------------------------------------------------------------*/

typedef enum
{
    MIME_CONTENT_TYPE_NONE = 0,
    MIME_CONTENT_TYPE_JSON,
    MIME_CONTENT_TYPE_PKCS7_MIME,
    MIME_CONTENT_TYPE_OCTET_STREAM,
    MIME_CONTENT_TYPE_PKCS8,
    MIME_CONTENT_TYPE_CMC
} MimeContentType;

/*----------------------------------------------------------------------------*/

typedef enum
{
    MIME_CONTENT_TRANSFER_ENCODING_NONE = 0,
    MIME_CONTENT_TRANSFER_ENCODING_7BIT,
    MIME_CONTENT_TRANSFER_ENCODING_8BIT,
    MIME_CONTENT_TRANSFER_ENCODING_BINARY,
    MIME_CONTENT_TRANSFER_ENCODING_BASE64
} MimeContentTransferEncoding;

/*----------------------------------------------------------------------------*/

typedef struct MimePart
{
    MimeContentType contentType;
    MimeContentTransferEncoding contentTransferEncoding;
    ubyte *pData;
    ubyte4 dataLen;
    FileDescriptor pFile;
    ubyte4 fileOffset;
    ubyte *pId;
    ubyte *pDescription;
    ubyte *pDisposition;
    struct MimePart *pNext;
} MimePart;

/*----------------------------------------------------------------------------*/

typedef struct MimePayload {
    FileDescriptor pFile;
    ubyte *pPayLoad;
    ubyte4 payloadLen;
    ubyte4 payloadOffset;
} MimePayload;

/*----------------------------------------------------------------------------*/

typedef void MimePartProcessArg;

/*----------------------------------------------------------------------------*/

typedef MSTATUS (*funcPtrMimePartProcess)(MimePart *, MimePartProcessArg *);

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MIME_process(
    MimePayload *pInput,
    funcPtrMimePartProcess func,
    MimePartProcessArg *pArgs);

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MIME_processBody(
    MimePayload *pInput,
    sbyte *pBoundary,
    funcPtrMimePartProcess func,
    MimePartProcessArg *pArgs);

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MIME_getBoundaryFromLine(
    ubyte *pContentType,
    ubyte4 contentTypeLen,
    sbyte **ppBoundary);

/*----------------------------------------------------------------------------*/

#ifdef __cplusplus
}
#endif

#endif /* __MIME_PARSER_HEADER__ */