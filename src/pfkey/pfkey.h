/**
 * @file  pfkey.h
 * @brief PF_KEY Kernel Interface - Header
 *
 * @details    NanoSec PF_KEY developer API header.
 * @since      3.2
 * @version    4.0 and later
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

/*------------------------------------------------------------------*/

#ifndef __PFKEY_HEADER__
#define __PFKEY_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#define PFKEY_DIVROUNDUP(x, y)      (((x) + (y) - 1) / (y))
#define PFKEY_ALIGN                 8

#ifndef SOCKET_ERROR
#define SOCKET_ERROR                -1
#endif

#define PFKEY_ALGTYPE_AUTH          1
#define PFKEY_ALGTYPE_ENCRYPT       2

#define PFKEY_MAX_SUPPORTED_ALGO    10

#ifndef PFKEY_COMB_MAX
#define PFKEY_COMB_MAX              32
#endif


/*------------------------------------------------------------------*/


/**
@brief      Details of errors passed through callback functions (see
            pfKeyCallback_t and pfkey_callback_functions).

@details    This structure is used to provide details about errors that are
            passed through PF_KEY callback functions (see pfKeyCallback_t and
            pfkey_callback_functions).

@since 3.2
@version 3.2 and later

@todo_version (and \@since; omitted from earlier doxygen comments)

@flags
No flag definitions are required to use this structure.

@inc_file pfkey.h
*/
typedef struct pfKeyError_t
{
    /**
    @brief      Error number.
    @details    Error number.
    @todo_techpubs (identify file containing the relevant enums/constants)
    */
    ubyte4  errnum;
    /**
    @brief      PF_KEY message type; corresponds to SADB_* message types in
                  pfkeyv2_common.h.
    @details    PF_KEY message type; corresponds to SADB_* message types in
                  pfkeyv2_common.h (for example, SADB_REGISTER).
    */
    ubyte   pfkeyCmd;
    /**
    @brief      Sequence number.
    @details    Sequence number.
    @todo_eng_review (is the sequence number unique per transmit? per send?)
    */
    ubyte4  pfkeySeq;
} pfKeyError;

/**
@brief      Details of a response passed through the
            pfKeyCallback::pfkey_funcPtrResponse callback functions.

@details    This structure is used to provide details of a response that is
            passed through the pfKeyCallback::pfkey_funcPtrResponse callback
            function.

@since 3.2
@version 3.2 and later

@todo_version (and \@since; omitted from earlier doxygen comments)

@flags
No flag definitions are required to use this structure.

@inc_file pfkey.h
*/
typedef struct pfKeyResponse_t
{
    /**
    @brief      PF_KEY message type; corresponds to SADB_* message types in
                  pfkeyv2_common.h.
    @details    PF_KEY message type; corresponds to SADB_* message types in
                  pfkeyv2_common.h (for example, SADB_REGISTER).
    */
    ubyte   pfkeyCmd;
    /**
    @brief      Sequence number.
    @details    Sequence number.
    @todo_eng_review (is the sequence number unique per transmit? per send?)
    */
    ubyte4  pfkeySeq;
    /**
    @brief      Negative number error code definition from merrors.h.
    @details    Negative number error code definition from merrors.h. To
                retrieve a string containing an English text error identifier
                corresponding to the function's returned error status, use the
                \c DISPLAY_ERROR macro.
    */
    sbyte4  pfkeyStatus;
    /**
    @brief      Pointer to response payload.
    @details    Pointer to response payload.
    */
    void*   pData;
} pfKeyResponse;

/**
@brief      Details of a request passed through the
            pfKeyCallback::pfkey_funcPtrRequest callback functions.

@details    This structure is used to provide details of a request that is
            passed through the pfKeyCallback::pfkey_funcPtrRequest callback
            function.

@since 3.2
@version 3.2 and later

@todo_version (and \@since; omitted from earlier doxygen comments)

@flags
No flag definitions are required to use this structure.

@inc_file pfkey.h
*/
typedef struct pfKeyRequest_t
{
    /**
    @brief      PF_KEY message type; corresponds to SADB_* message types in
                  pfkeyv2_common.h.
    @details    PF_KEY message type; corresponds to SADB_* message types in
                  pfkeyv2_common.h (for example, SADB_REGISTER).
    */
    ubyte   pfkeyCmd;
    /**
    @brief      Sequence number.
    @details    Sequence number.
    @todo_eng_review (is the sequence number unique per transmit? per send?)
    */
    ubyte4  pfkeySeq;
    /**
    @brief      Pointer to request payload.
    @details    Pointer to request payload.
    */
    void*   pData;
} pfKeyRequest;

/**
@brief      Callback function pointers for PF_KEY.

@details    This structure is used for PF_KEY processing. Each callback function
            should be customized for your application and then registered by
            assigning it to the appropriate structure function pointer(s).

@since 3.2
@version 4.0 and later

@flags
No flag definitions are required to use this structure.

@inc_file pfkey.h
*/
typedef struct pfKeyCallback_t
{
/**
@brief      Handle NanoSec IPsec errors.

@details    This callback function handles errors received from NanoSec IPsec.

@ingroup    pfkey_callback_functions

@since 3.2
@version 3.2 and later

@flags
No flag definitions are required to enable this callback.

@inc_file   pfkey_ipsec.h
@todo_techpubs (confirm which header file is needed to include this declaration;
                likely it's pfkey.h, but older doc said pfkey_ipsec.h)

@param pfKeyErr     A structure of type (pfKeyError *) is filled in with the
                    error details and returned to the callback function.

@callbackdoc    pfkey.h
*/
    void (*pfkey_funcPtrError)(pfKeyError *pfKeyErr);

/**
@brief      Send (transmit) a PF_KEY message.

@details    This callback function sends (transmits) a PF_KEY message.

@ingroup    pfkey_callback_functions

@since 3.2
@version 3.2 and later

@flags
No flag definitions are required to enable this callback.

@inc_file   pfkey_ipsec.h

@todo_techpubs (confirm which header file is needed to include this declaration;
                likely it's pfkey.h, but older doc said pfkey_ipsec.h)

@param pBuffer     Buffer containing the message to send.
@param bufLen      Length of buffer (\p pBuffer).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc    pfkey.h
*/
    MSTATUS (*pfkey_funcPtrSend)(ubyte *pBuffer, ubyte4 bufLen);

/**
@brief      Pass a response message from NanoSec IPsec to an application.

@details    This callback passes a response message from NanoSec IPsec to an
            application.

@ingroup    pfkey_callback_functions

@since 3.2
@version 3.2 and later

@flags
No flag definitions are required to enable this callback.

@inc_file   pfkey_ipsec.h

@todo_techpubs (confirm which header file is needed to include this declaration;
                likely it's pfkey.h, but older doc said pfkey_ipsec.h)

@param  pResp   Pointer to structure containing PF_KEY command type and the
                  data buffer (which must be typecast per command type).

@callbackdoc    pfkey.h
*/
    void (*pfkey_funcPtrResponse)(pfKeyResponse *pResp);

/**
@brief      Pass a request message from NanoSec IPsec to an application.

@details    This callback passes a request message from NanoSec IPsec to an
            application.

@ingroup    pfkey_callback_functions

@since 4.0
@version 4.0 and later

@flags
No flag definitions are required to enable this callback.

@inc_file   pfkey_ipsec.h

@todo_techpubs (confirm which header file is needed to include this declaration;
                likely it's pfkey.h, but older doc said pfkey_ipsec.h)

@param  pRequest    Pointer to structure containing PF_KEY request
                      details.

@callbackdoc    pfkey.h
*/
    void (*pfkey_funcPtrRequest)(pfKeyRequest *pRequest);

} pfKeyCallback;

/**
@cond
*/
typedef struct pfKeyCb_t
{
    ubyte4 seqNo;
    ubyte4 pid;
    pfKeyCallback fnCallBack;
} pfKeyCb;

typedef struct pfKeyGetSpiResponse_t
{
    ubyte4 dwSpi;
    MOC_IP_ADDRESS_S dwSrc;
    MOC_IP_ADDRESS_S dwDst;
} pfKeyGetSpiResponse;

#define pfKeyDeleteResponse pfKeyGetSpiResponse

typedef struct pfKeySuppAlgo_t
{
    ubyte algType;
    ubyte algId;
    ubyte ivLen;
    ubyte2 algMinBits;
    ubyte2 algMaxBytes;
} pfKeySuppAlgo;

typedef struct pfKeyRegisterResponse_t
{
    ubyte4 numSupported;
    pfKeySuppAlgo algoInfo[PFKEY_MAX_SUPPORTED_ALGO];
} pfKeyRegisterResponse;
/**
@endcond
*/


/*------------------------------------------------------------------*/

struct ipsecKeyEx;
struct ipsecKey;

MOC_EXTERN MSTATUS PFKEY_init(pfKeyCb **ppPfkeyCb, ubyte4 pid, pfKeyCallback *pFnCallback);
MOC_EXTERN MSTATUS PFKEY_parse(pfKeyCb *pPfkeyCb, ubyte *pMsg, ubyte2 msgLen);

MOC_EXTERN MSTATUS PFKEY_register   (pfKeyCb *pPfkey, ubyte proto, ubyte **ppmsg, ubyte4 *pLen);
MOC_EXTERN MSTATUS PFKEY_add        (pfKeyCb *pPfkey, struct ipsecKeyEx *pKeyEx, ubyte **ppMsg, ubyte4 *pLen);
MOC_EXTERN MSTATUS PFKEY_delete     (pfKeyCb *pPfkey, struct ipsecKey *pKey, ubyte **ppMsg, ubyte4 *pLen);
MOC_EXTERN MSTATUS PFKEY_update     (pfKeyCb *pPfkey, struct ipsecKeyEx *pKeyEx, ubyte **ppMsg, ubyte4 *pLen);
MOC_EXTERN MSTATUS PFKEY_getSPI     (pfKeyCb *pPfkey, struct ipsecKey *pKey, ubyte **ppMsg, ubyte4 *pLen);
MOC_EXTERN MSTATUS PFKEY_get        (pfKeyCb *pPfkey, ubyte4 dwSpi, ubyte proto,
                                 MOC_IP_ADDRESS dwSrcAddr, MOC_IP_ADDRESS dwDstAddr,
                                 ubyte **ppMsg, ubyte4 *pLen);
MOC_EXTERN MSTATUS PFKEY_spdDump    (pfKeyCb *pPfkey, ubyte proto, ubyte **ppMsg, ubyte4 *pLen);
MOC_EXTERN MSTATUS PFKEY_flush      (pfKeyCb *pPfkey, ubyte proto, ubyte **ppMsg, ubyte4 *pLen);
MOC_EXTERN MSTATUS PFKEY_dump       (pfKeyCb *pPfkey, ubyte proto, ubyte **ppMsg, ubyte4 *pLen);

MOC_EXTERN MSTATUS PFKEY_acquire    (pfKeyCb *pPfkey, ubyte proto, ubyte errorNo, ubyte **ppMsg, ubyte4 *pLen);


#ifdef __cplusplus
}
#endif

#endif /* __PFKEY_HEADER__ */

