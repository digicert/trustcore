/*
 * ssh_str.h
 *
 * SSH String Methods Header
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
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
