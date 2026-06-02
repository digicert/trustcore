/**
 * @file  pfkey_ipsec.h
 * @brief PF_KEY Kernel Interface - IPSec Integration Header
 *
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


#ifndef __PFKEY_IPSEC_H__
#define __PFKEY_IPSEC_H__


/*------------------------------------------------------------------*/

#define PFKEY_DIVROUNDUP(x, y)      ((x + y - 1)/y)
#define PFKEY_ALIGN                 8

#define SOCKET_ERROR                -1

#define PFKEY_MAX_SUPPORTED_ALGO    10

#define PFKEY_ALGTYPE_AUTH            1
#define PFKEY_ALGTYPE_ENCRYPT       2

#define KERNEL_MALLOC(len)           kmalloc(len, GFP_KERNEL)
#define KERNEL_FREE(pMsg)            kfree(pMsg)


/*------------------------------------------------------------------*/

typedef struct pfKeyError_t
{
    ubyte4          errnum;
    ubyte           pfkeyCmd;

} pfKeyError;

typedef struct pfKeyResponse_t
{
    ubyte           pfkeyCmd;
    void*           pData;

} pfKeyResponse;

typedef struct pfKeyCallback_t
{
    void    (*pfkey_funcPtrError)   (pfKeyError *pfKeyErr);
    MSTATUS (*pfkey_funcPtrSend)    (ubyte *pBuffer, ubyte4 bufLen);
    void    (*pfkey_funcPtrResponse)(pfKeyResponse *pResp);

} pfKeyCallback;

typedef struct pfKeyCb_t
{
    ubyte4          sockfd;
    ubyte4          seqNo;
    pid_t           pid;
    pfKeyCallback   fnCallBack;

} pfKeyCb;

typedef struct pfKeyGetSpiResponse_t
{
    ubyte4          dwSpi;
    MOC_IP_ADDRESS  dwSrc;
    MOC_IP_ADDRESS  dwDst;

} pfKeyGetSpiResponse;

#define pfKeyDeleteResponse pfKeyGetSpiResponse

typedef struct pfKeySuppAlgo_t
{
    ubyte           algType;
    ubyte           algId;
    ubyte           ivLen;
    ubyte2          algMinBits;
    ubyte2          algMaxBytes;

} pfKeySuppAlgo;

typedef struct pfKeyRegisterResponse_t
{
    ubyte4          numSupported;
    pfKeySuppAlgo   algoInfo[PFKEY_MAX_SUPPORTED_ALGO];

} pfKeyRegisterResponse;

typedef struct pfKeyProposal_t
{
    ubyte           authAlgo;
    ubyte           encrAlgo;
    ubyte2          authAlgMinBytes;
    ubyte2          authAlgMaxBytes;
    ubyte2          encrAlgMinBytes;
    ubyte2          encrAlgMaxBytes;
    ubyte4          softAllocs;
    ubyte4          hardAllocs;
    ubyte8          softBytes;
    ubyte8          hardBytes;
    ubyte8          softAddtime;
    ubyte8          hardAddtime;
    ubyte8          softUsetime;
    ubyte8          hardUsetime;

} pfKeyProposal;

typedef struct pfKeyIpsecCb_t
{
    ubyte4          seqNo;
    ubyte           acquireSentFlag;
    ubyte           proto[2];

}pfKeyIpsecCb;


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS PFKEY_IPSEC_init(ubyte **pPfkeyCb);

MOC_EXTERN MSTATUS PFKEY_acquire(pfKeyIpsecCb *pPfkey, ubyte4 pid, SPD pxSp, ubyte numProp, pfKeyProposal *pProp, ubyte **ppMsg, ubyte2 *pLen);
MOC_EXTERN MSTATUS PFKEY_expire(ubyte4 seq, ubyte4 pid, SADB ppxSa, ubyte **ppMsg, ubyte2 *pLen);

MOC_EXTERN MSTATUS PFKEY_IPSEC_parse(pfKeyIpsecCb *pPfkey, ubyte *pMsg, ubyte4 msgLen, ubyte **pReply, ubyte2 *pReplyLen);

MOC_EXTERN MSTATUS pfkey_buildAssocExtension(ubyte4 dwSpi, ubyte authAlgo, ubyte encrAlgo, ubyte aeadTag, struct sadb_sa *pSa, ubyte state, ubyte flag);
MOC_EXTERN MSTATUS pfkey_parseAddressExtension(struct sadb_address *pExt, MOC_IP_ADDRESS_S *pAddr, ubyte *pProto, ubyte2 *pPort);
MOC_EXTERN MSTATUS pfkey_buildKeyExtension(struct sadb_key *pKey, ubyte2 extType, ubyte *keyData, ubyte2 keyDataLen);
/*
MOC_EXTERN MSTATUS pfkey_buildBase(ubyte4 seqNo, ubyte4 pid, ubyte proto, ubyte msgType, ubyte errno, ubyte2 msgLen, struct sadb_msg *pBase);
*/
MOC_EXTERN MSTATUS pfkey_buildAddressExtension(ubyte2 extType, MOC_IP_ADDRESS addr, struct sadb_address *pAddr);


#endif /* __PFKEY_IPSEC_H__ */

