/*
 * ssh_str.h
 *
 * SSH String Methods Header
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

#ifndef __SSH_STR_HEADER__
#define __SSH_STR_HEADER__

/*------------------------------------------------------------------*/

#define DEFINE_SSH_LEN(Z)       (sizeof(ubyte4)+sizeof(Z)-1)
#define DEFINE_SSH_STR(Z)       { ((sizeof(Z) - 1) >> 24), ((sizeof(Z)-1)>>16), \
                                  ((sizeof(Z) - 1) >>  8),  (sizeof(Z)-1), Z}

#define DEFINE_SSH_STRING(Z)    { sizeof(ubyte4)+sizeof(Z)-1,  DEFINE_SSH_STR(Z)}

/*------------------------------------------------------------------*/

typedef struct sshStringBuffer
{
    ubyte4  stringLen;
    ubyte*  pString;

} sshStringBuffer;

/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_STR_makeStringBuffer(sshStringBuffer **ppRetString, ubyte4 strLen);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_STR_freeStringBuffer(sshStringBuffer **ppRetString);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_STR_copyFromString(ubyte *pBuffer, ubyte4 *bufIndex, sshStringBuffer *pAppendToBuffer, intBoolean copyToBuffer);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_STR_copyStringToPayload(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *bufIndex, sshStringBuffer *pAppendToBuffer);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_STR_copyStringToPayload2(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *bufIndex, ubyte *pAppendToBuffer, ubyte4 appendLen);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_STR_copyStringToPayload3(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *bufIndex, sshStringBuffer *pAppendToBuffer);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_STR_copyStringFromPayload(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *pBufIndex, sshStringBuffer **ppRetString);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_STR_copyStringFromPayload2(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *pBufIndex, sshStringBuffer **ppRetString);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_STR_copyStringFromPayload3(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *pBufIndex, ubyte **ppRetString);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_STR_getOption(sshStringBuffer *pString, ubyte4 *pStringNextIndex, ubyte **ppRetOption, ubyte4 *pRetOptionLength);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_STR_findOption(sshStringBuffer *pSourceString, ubyte *pOption, ubyte4 optionLen, intBoolean *pInString, ubyte4 *pWordIndex);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_STR_locateOption(sshStringBuffer *pClientString, sshStringBuffer *pServerString, ubyte4 *pWordIndex);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_STR_locateOption1(sshStringBuffer *pClientString, sshStringBuffer *pServerString, ubyte4 *pWordIndex);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_STR_copyBytesAsStringToPayload(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *bufIndex, ubyte *pAppendToBuffer, ubyte4 appendLen);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_STR_walkStringInPayload(const ubyte *pBuffer, ubyte4 bufSize, ubyte4 *pBufIndex);

#endif /* __SSH_STR_HEADER__ */
