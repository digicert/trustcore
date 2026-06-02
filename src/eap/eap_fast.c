/**
 * @file  eap_fast.c
 * @brief EAP-FAST method implementation
 *
 * @details    EAP Flexible Authentication via Secure Tunneling
 * @since      1.41
 * @version    1.41 and later
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, at least one flag in each of the following flag pairs must be defined in moptions.h:
 *     +   Enable EAP peer/authenticator (\c \__ENABLE_DIGICERT_EAP_PEER__, \c \__ENABLE_DIGICERT_EAP_AUTH__)
 *     +   Enable an EAP FAST method (\c \__ENABLE_DIGICERT_EAP_FAST__, \c \__ENABLE_DIGICERT_EAP_PEAPV2__)
 *     Whether the following flags are defined determines which functions are enabled:
 *     +   \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__
 *     +   \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
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


/* Add to your makefile */
#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#if ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) && (defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)))

#if (defined(__ENABLE_DIGICERT_EAP_FAST__) || defined(__ENABLE_DIGICERT_EAP_PEAPV2__))

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/vlong.h"
#include "../common/debug_console.h"
#include "../common/sizedbuffer.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../common/random.h"
#include "../crypto/crypto.h"
#include "../crypto/hmac.h"
#include "../crypto/cert_store.h"
#include "../ssl/ssl.h"
#include "../eap/eap.h"
#include "../eap/eap_proto.h"
#include "../eap/eap_md5.h"
#include "../eap/eap_tls.h"
#include "../eap/eap_fast.h"
#include "../eap/eap_fast_pvt.h"


/*------------------------------------------------------------------*/

#define MAX_EAP_PACKET                       (2048)
#define EAP_FAST_INNER_METHOD_COMPOUND_KEY       (28) /* length of "Inner Methods Compound Keys\0" including null*/
/* SSL Record Header type */
#define SSL_CHANGE_CIPHER_SPEC              (20)
#define SSL_ALERT                           (21)
#define SSL_HANDSHAKE                       (22)
#define SSL_APPLICATION_DATA                (23)


/*------------------------------------------------------------------*/

static MSTATUS
eap_fastCalculateCryptoMac(eapFASTCB *eapFastCb, ubyte *cmk,
                           ubyte *p_cryptoTLV, sbyte4 cryptoTLV_len,
                           ubyte *cmac)
{
    ubyte*          preMasterSecret = NULL;
    ubyte4          preMasterSecretLen = 0;
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_EAP, &hwAccelCtx)))
        goto nocleanup;

    status = HMAC_SHA1(MOC_HASH(hwAccelCtx) cmk, 20, p_cryptoTLV,
                       cryptoTLV_len, NULL, 0, cmac);
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_EAP, &hwAccelCtx);
nocleanup:
    return status;
}


/*------------------------------------------------------------------*/

/*! Build an EAP-FAST packet from the specified encrypted second stage payload.
This function builds an EAP-FAST packet from the specified encrypted second
stage payload, prepending the header and performing any required fragmentation,
and returning the resultant packet through the $eapResponse$ parameter. Typically
your application passes the resulting packet to EAP for transmission from
authenticator to peer or from peer to authenticator.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one flag in each of the following flag pairs must be defined in moptions.h:
- Enable EAP peer/authenticator ($__ENABLE_DIGICERT_EAP_PEER__$, $__ENABLE_DIGICERT_EAP_AUTH__$)
- Enable asynchronous SSL client/server ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$, $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)
- Enable an EAP FAST method ($__ENABLE_DIGICERT_EAP_FAST__$, $__ENABLE_DIGICERT_EAP_PEAPV2__$)

#Include %file:#&nbsp;&nbsp;eap_fast.h

\param eapFASTCb    EAP-FAST session handle returned from EAP_FASTinitSession.
\param pkt          Pointer to payload to include in the EAP-FAST packet.
\param pktLen       Number of bytes in the payload data ($pkt$).
\param eapResponse  On return, pointer to resultant EAP-FAST response packet.
\param eapRespLen   On return, number of bytes in EAP-FAST response payload ($eapResponse$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_FASTFormSendPacket(void *eapFASTCb,ubyte *pkt, ubyte4 pktLen,
                       ubyte **eapResponse, ubyte4 *eapRespLen)
{

    eapFASTCB*  eapFastCb = (eapFASTCB *)eapFASTCb;
    ubyte4      length;
    ubyte*      resp = NULL;
    MSTATUS     status = OK;

    /*Create the Eap-Fast Header with S, L or M flags */
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_FASTFormSendPacket: Session. 0x");
    DEBUG_HEXINT(DEBUG_EAP_MESSAGE, (sbyte4)((uintptr)eapFASTCb));
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");

    *eapResponse = NULL;
    *eapRespLen =  0;

    if (MAX_EAP_TLS_MTU >= pktLen+1)
    {
        *eapRespLen = pktLen + 1;
        resp = MALLOC(*eapRespLen);

        if (NULL == resp)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        *resp = eapFastCb->eapFASTparam.version;
        DIGI_MEMCPY((ubyte *)(resp + 1),(ubyte *)pkt,pktLen);
        eapFastCb->data_send_remaining = 0;
    }
    else
    {
        /* Will need fragmentation */
        *eapRespLen = MAX_EAP_TLS_MTU + 5;
        resp = (ubyte *) MALLOC(*eapRespLen);
        if (NULL == resp)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        *resp = EAP_FAST_LENGTH_INCLUDED_FLAG | EAP_FAST_MORE_FRAGMENTS_FLAG;
        *resp |= eapFastCb->eapFASTparam.version;
        length = EAP_HTONL(*eapRespLen);
        DIGI_MEMCPY(resp + 1,(ubyte *)&length,4);
        eapFastCb->data_send_remaining = pktLen - MAX_EAP_TLS_MTU;
        eapFastCb->frag_flag = EAP_FAST_FRAG_FLAG_SEND;

        DIGI_MEMCPY(resp + 5,(ubyte *)pkt + 5, MAX_EAP_TLS_MTU);

        /*Cache the packet for Future */
        eapFastCb->data_send = pkt;
        eapFastCb->data_send_cur = pkt + MAX_EAP_TLS_MTU;
    }

    *eapResponse = resp;

exit:

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_fastBuildIntermediateResultTlv(ubyte2 intResult, ubyte *buf, ubyte4 *length)
{
    ubyte *ptr = buf;

    *ptr++ = 0x80;
    *ptr++ = EAP_FAST_INTERMEDIATE_RESULT_TLV;
    *ptr++ = 0;
    *ptr++ = 2;
    *ptr++ = intResult >> 8;
    *ptr++ = intResult;
    *length = 6;

    return OK;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_fastBuildCryptoBindingTlv(eapFASTCB *eapFastCb, ubyte subType,
                              ubyte *nonce, ubyte *cmk,
                              ubyte *buf, ubyte4 *length)
{
    ubyte    *ptr = buf;
    ubyte    cmac[EAP_FAST_CRYPTO_BINDING_CMAC_LEN];
    MSTATUS  status;

    DIGI_MEMSET(buf, 0, EAP_FAST_CRYPTO_BINDING_TLV_LEN+4);
    *ptr++ = 0x80;
    *ptr++ = EAP_FAST_CRYPTO_BINDING_TLV;
    *ptr++ = 0;
    *ptr++ = EAP_FAST_CRYPTO_BINDING_TLV_LEN;
    *ptr++ = 0;       /* Reserved */
    *ptr++ = 1;       /* Crypto Binding TLV version */
    *ptr++ = eapFastCb->eapFASTparam.version;       /* Received version */
    *ptr++ = subType;

    DIGI_MEMCPY(ptr, nonce, EAP_FAST_CRYPTO_BINDING_NONCE_LEN);
    ptr += EAP_FAST_CRYPTO_BINDING_NONCE_LEN;

    /* Calculate cmac */
    if (EAP_TYPE_FAST == eapFastCb->eapFASTparam.methodType)
    {
        status = eap_fastCalculateCryptoMac(eapFastCb, cmk, buf,
                               EAP_FAST_CRYPTO_BINDING_TLV_LEN +4, cmac);
        DIGI_MEMCPY(ptr, cmac, EAP_FAST_CRYPTO_BINDING_CMAC_LEN);
        *length = EAP_FAST_CRYPTO_BINDING_TLV_LEN + 4;
    }
    else  /* PEAPV2 */
    {
        status = eap_fastCalculateCryptoMac(eapFastCb, cmk, buf,
                               EAP_PEAPV2_CRYPTO_BINDING_TLV_LEN +4, cmac);
        DIGI_MEMCPY(ptr, cmac, EAP_PEAPV2_CRYPTO_BINDING_CMAC_LEN);
        *length = EAP_PEAPV2_CRYPTO_BINDING_TLV_LEN + 4;
    }

    return OK;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_fastBuildErrorTlv(ubyte4 errCode, ubyte *buf, ubyte4 *length)
{
    ubyte     *ptr = buf;
    ubyte4    error_code;

    *ptr++ = 0x80;
    *ptr++ = EAP_FAST_ERROR_TLV;
    *ptr++ = 0;
    *ptr++ = EAP_FAST_ERROR_TLV_LEN;
    error_code = EAP_HTONL(errCode);
    DIGI_MEMCPY(ptr, (ubyte *)&error_code, 4);

    *length = EAP_FAST_ERROR_TLV_LEN + 4;

    return OK;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_fastBuildResultTlv(ubyte2 status, ubyte *buf, ubyte4 *length)
{
    ubyte     *ptr = buf;
    ubyte2    stat;

    *ptr++ = 0x80;
    *ptr++ = EAP_FAST_RESULT_TLV;
    *ptr++ = 0;
    *ptr++ = EAP_FAST_RESULT_TLV_LEN;
    stat = EAP_HTONS(status);
    DIGI_MEMCPY(ptr, (ubyte *)&stat, 2);

    *length = EAP_FAST_RESULT_TLV_LEN + 4;

    return OK;
}

/*------------------------------------------------------------------*/
static MSTATUS
eap_fastBuildPACAckTlv(ubyte2 status, ubyte *buf, ubyte4 *length)
{
    ubyte     *ptr = buf;
    ubyte2    stat;

    *ptr++ = 0x80;
    *ptr++ = EAP_FAST_PAC_TLV;
    *ptr++ = 0;
    *ptr++ = EAP_FAST_PAC_ACK_LENGTH + 4;
    *ptr++ = 0;
    *ptr++ = EAP_FAST_PAC_ACK;
    *ptr++ = 0;
    *ptr++ = EAP_FAST_PAC_ACK_LENGTH;
    stat = EAP_HTONS(status);
    DIGI_MEMCPY(ptr, (ubyte *)&stat, 2);

    *length = EAP_FAST_PAC_ACK_LENGTH + 8;

    return OK;
}
/*------------------------------------------------------------------*/

static MSTATUS
eap_fastBuildPACTlv(EAP_FAST_pac_t *pac, ubyte *buf, ubyte4 *length)
{
    ubyte     *ptr = buf;
    ubyte2    stat;
    ubyte4    stat4;
    ubyte*    pacTlvLen;
    ubyte*    pacInfoTlvLen;


    *ptr++ = 0x80;
    *ptr++ = EAP_FAST_PAC_TLV;
    pacTlvLen = ptr;/* Place Holder for updateing later on */
    *ptr++ = 0;
    *ptr++ = 0;

    *ptr++ = 0;
    *ptr++ = EAP_FAST_PAC_KEY;
    *ptr++ = 0;
    *ptr = EAP_FAST_PAC_KEY_LENGTH;
    DIGI_MEMCPY(ptr, (ubyte *)pac->pacKey, EAP_FAST_PAC_KEY_LENGTH );
    ptr+= EAP_FAST_PAC_KEY_LENGTH;

    if (pac->pacOpaque)
    {
        *ptr++ = 0;
        *ptr++ = EAP_FAST_PAC_OPAQUE;
        stat = EAP_HTONS(pac->pacOpaqueLen);
        DIGI_MEMCPY(ptr, (ubyte *)&stat, 2);
        ptr+= 2;
        DIGI_MEMCPY(ptr, (ubyte *)pac->pacOpaque,pac->pacOpaqueLen );
        ptr+= pac->pacOpaqueLen;
    }

    *ptr++ = 0;
    *ptr++ = EAP_FAST_PAC_INFO;
    pacInfoTlvLen = ptr;
    *ptr++ = 0;
    *ptr++ = 0;

    if (pac->pacLifetime)
    {
        *ptr++ = 0;
        *ptr++ = EAP_FAST_PAC_LIFETIME;
        *ptr++ = 0;
        *ptr++ = 2;

        stat4 = EAP_HTONL(pac->pacLifetime);
        DIGI_MEMCPY(ptr, (ubyte *)&stat4, 4);
        ptr+= 4;
    }

    if (pac->a_id)
    {
        *ptr++ = 0;
        *ptr++ = EAP_FAST_PAC_A_ID;
        stat = EAP_HTONS(pac->a_idLen);
        DIGI_MEMCPY(ptr, (ubyte *)&stat, 2);
        ptr+= 2;
        DIGI_MEMCPY(ptr, (ubyte *)pac->a_id,pac->a_idLen );
        ptr+= pac->a_idLen;
    }
    if (pac->i_id)
    {
        *ptr++ = 0;
        *ptr++ = EAP_FAST_PAC_I_ID;
        stat = EAP_HTONS(pac->i_idLen);
        DIGI_MEMCPY(ptr, (ubyte *)&stat, 2);
        ptr+= 2;
        DIGI_MEMCPY(ptr, (ubyte *)pac->i_id,pac->i_idLen );
        ptr+= pac->i_idLen;
    }
    if (pac->a_idInfo)
    {
        *ptr++ = 0;
        *ptr++ = EAP_FAST_PAC_A_ID_INFO;
        stat = EAP_HTONS(pac->a_idInfoLen);
        DIGI_MEMCPY(ptr, (ubyte *)&stat, 2);
        ptr+= 2;
        DIGI_MEMCPY(ptr, (ubyte *)pac->a_idInfo,pac->a_idInfoLen );
        ptr+= pac->a_idInfoLen;
    }

    if (!pac->pacType)
        pac->pacType = EAP_FAST_PAC_TYPE_TUNNEL;

    *ptr++ = 0;
    *ptr++ = EAP_FAST_PAC_TYPE;
    *ptr++ = 0;
    *ptr++ = 2;
    stat = EAP_HTONS(pac->pacType);
    DIGI_MEMCPY(ptr, (ubyte *)&stat,2);
    ptr+= 2;

    /* Update PAC INFO Len */
    stat = ptr - pacInfoTlvLen;
    stat = EAP_HTONS(stat);
    DIGI_MEMCPY(pacInfoTlvLen, (ubyte *)&stat,2);
    /* Update PAC TLV Len */
    stat = ptr - pacTlvLen;
    stat = EAP_HTONS(stat);
    DIGI_MEMCPY(pacTlvLen, (ubyte *)&stat,2);

    *length = ptr - buf;

    return OK;
}

/*------------------------------------------------------------------*/

extern MSTATUS
EAP_FASTGetPAC(ubyte *eapFastSessionHdl, EAP_FAST_pac_t **pac)
{
    MSTATUS    status = OK;
    eapFASTCB  *eapCb = (eapFASTCB *)eapFastSessionHdl;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, " Session : 0x");
    DEBUG_HEXINT(DEBUG_EAP_MESSAGE, (sbyte4)((uintptr)eapCb));
    if (eapCb->pac)
        *pac = eapCb->pac;
    else
    {
        status = ERR_EAP_FAST_PAC_NOT_AVAILABLE;
        *pac = NULL;
    }

    return status ;
}

/*------------------------------------------------------------------*/

/*! Transmits $Result$ and PAC Provisioning TLVs to the peer.
This function (called by the authenticator) transmits the result and the
and PAC Provisioning TLVs (type-length-values) to the peer using the specified
Key / A-ID and Other parameters specified by the User/.

This function enables the authenticator to provision PAC on the Peer

\since 5.0
\version 5.0 and later

! Flags
To enable this function, at least one flag in each of the following flag pairs must be defined in moptions.h:
- Enable EAP peer/authenticator ($__ENABLE_DIGICERT_EAP_PEER__$, $__ENABLE_DIGICERT_EAP_AUTH__$)
- Enable asynchronous SSL client/server ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$, $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)
- Enable an EAP FAST method ($__ENABLE_DIGICERT_EAP_FAST__$, $__ENABLE_DIGICERT_EAP_PEAPV2__$)

#Include %file:#&nbsp;&nbsp;eap_fast.h

\param eapFastSessionHdl    Application session handle (cookie given by the application to identify the session).
\param pac                  PAC Structure with the Relevant information.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_FASTauthSendPAC_ResultTlv(ubyte *eapFastSessionHdl, EAP_FAST_pac_t *pac)
{
    ubyte      *response;
    ubyte      *cur;
    ubyte4     length;
    ubyte4     responseLen;
    MSTATUS    status = OK;
    eapFASTCB  *eapCb = (eapFASTCB *)eapFastSessionHdl;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, " Session : 0x");
    DEBUG_HEXINT(DEBUG_EAP_MESSAGE, (sbyte4)((uintptr)eapCb));
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " EAP_FASTauthSendPAC_ResultTLV: SUCCESS ");

    if ((!pac) ||
       (!pac->pacOpaque) ||
       (!pac->a_id))
    {
        status = ERR_EAP_FAST_INVALID_PAC_INFO;
        goto exit;

    }

#if defined(__ENABLE_ALL_DEBUGGING__)
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Sending OPAQUE  ");
        EAP_PrintBytes( pac->pacOpaque,pac->pacOpaqueLen);
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");
#endif

    if (( 255 < pac->pacOpaqueLen) ||
       ( 255 <  pac->a_idInfoLen)  ||
       ( 255 <  pac->i_idLen)  ||
       ( 255 <  pac->a_idLen))
    {
        status = ERR_EAP_FAST_INVALID_PAC_INFO_LEN;
        goto exit;

    }

    response =  MALLOC(MAX_EAP_PACKET);
    if (NULL == response)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    cur = response;
    length = 0;
    responseLen = 0;

    /* Build Result TLV */
    status = eap_fastBuildResultTlv(EAP_FAST_RESULT_TLV_SUCCESS,
                                                cur, &length);
    cur += length;
    responseLen += length;

    status = eap_fastBuildPACTlv(pac, cur, &length);
    cur += length;
    responseLen += length;
    eapCb->pac_sent = 1;

    status = eapCb->eapFASTparam.ulTransmit(eapCb->appSessionCB, response,
                                   (ubyte2)responseLen, FALSE);

exit:
    return status;

}


/*------------------------------------------------------------------*/

/*! Transmits $Result$ and crypto binding TLVs to the peer.
This function (called by the authenticator) transmits the intermediate result
and crypto binding TLVs (type-length-values) to the peer using the specified
compound key and nonce.

This function enables the authenticator to negotiate additional methods. Once
the $Result$ TLV is sent (by a call to EAP_FASTauthSendMethodResult), the
authenticator ceases negotiating additional methods.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one flag in each of the following flag pairs must be defined in moptions.h:
- Enable EAP peer/authenticator ($__ENABLE_DIGICERT_EAP_PEER__$, $__ENABLE_DIGICERT_EAP_AUTH__$)
- Enable asynchronous SSL client/server ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$, $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)
- Enable an EAP FAST method ($__ENABLE_DIGICERT_EAP_FAST__$, $__ENABLE_DIGICERT_EAP_PEAPV2__$)

#Include %file:#&nbsp;&nbsp;eap_fast.h

\param eapFastSessionHdl    Application session handle (cookie given by the application to identify the session).
\param cmk                  Compound key (derived by using the FAST TLS algorithms provided by the TLS layer).
\param nonce                32-byte random number to incorporate into the %crypto
binding TLV and to use for calculating the %crypto MAC (message authentication
code).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_FASTauthSendCryptoBindingTlv(ubyte *eapFastSessionHdl, ubyte *cmk,ubyte *nonce)
{
    ubyte      *response;
    ubyte      *cur;
    ubyte4     length;
    ubyte4     responseLen;
    ubyte      *cmac;
    MSTATUS    status = OK;
    eapFASTCB  *eapCb = (eapFASTCB *)eapFastSessionHdl;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, " Session : 0x");
    DEBUG_HEXINT(DEBUG_EAP_MESSAGE, (sbyte4)((uintptr)eapCb));
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " EAP_FASTauthSendCryptoBindingTLV: SUCCESS ");

#if defined(__ENABLE_ALL_DEBUGGING__)
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Sending NONCE  ");
        EAP_PrintBytes( nonce,EAP_FAST_CRYPTO_BINDING_NONCE_LEN);
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "AUTH CMK  ");
        EAP_PrintBytes( cmk,20);
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");
#endif

    response =  MALLOC(MAX_EAP_PACKET);
    if (NULL == response)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    cur = response;
    length = 0;
    responseLen = 0;

    /* Build Intermediate Result TLV */
    eapCb->intermediate_result = EAP_FAST_INTERMEDIATE_SUCCESS;
    status = eap_fastBuildIntermediateResultTlv(eapCb->intermediate_result,
                                                cur, &length);
    cur += length;
    responseLen += length;

    DIGI_MEMCPY(eapCb->nonce, nonce,EAP_FAST_CRYPTO_BINDING_NONCE_LEN);

    status = eap_fastBuildCryptoBindingTlv(eapCb,
                                               EAP_FAST_BINDING_REQUEST,
                                               eapCb->nonce, cmk,
                                               cur, &length);
    cur += length;
    responseLen += length;

    status = eapCb->eapFASTparam.ulTransmit(eapCb->appSessionCB, response,
                                   (ubyte2)responseLen, FALSE);

exit:
    return status;

}


/*------------------------------------------------------------------*/

/*! Buld a $Method Result$ packet.
This function builds a $Method Result$ packet to pass the specified intermediate
method %crypto binding, compound key (if any) and result TLVs to the peer's upper
layer.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one flag in each of the following flag pairs must be defined in moptions.h:
- Enable EAP peer/authenticator ($__ENABLE_DIGICERT_EAP_PEER__$, $__ENABLE_DIGICERT_EAP_AUTH__$)
- Enable asynchronous SSL client/server ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$, $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)
- Enable an EAP FAST method ($__ENABLE_DIGICERT_EAP_FAST__$, $__ENABLE_DIGICERT_EAP_PEAPV2__$)

#Include %file:#&nbsp;&nbsp;eap_fast.h

\param appSessionHdl        Application session handle (cookie given by the application to identify the session).
\param sendCryptoBinding    $1$ to specify that the crypto-binding TLV be sent; any other value to specify that it not be sent.
\param compoundKey          Pointer to compound intermediate method key (derived
by using the FAST TLS algorithms provided by the TLS layer; may be NULL).
\param result               Result to transmit: $EAP_FAST_RESULT_TLV_SUCCESS$ or
$EAP_FAST_RESULT_TLV_FAILURE$.
\param nonce                Pointer to 32-byte random number to incorporate into
the %crypto binding TLV and to use for calculating the %crypto MAC (message
authentication code).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_FASTauthSendMethodResult(ubyte *eapFastSessionHdl, ubyte sendCryptoBinding,
                             ubyte *compoundKey, ubyte2 result,ubyte * nonce)
{
    ubyte        *response;
    ubyte        *cur;
    ubyte4       length;
    ubyte4       responseLen;
    ubyte        *cmac;
    MSTATUS      status = OK;
    eapFASTCB    *eapCb = (eapFASTCB *)eapFastSessionHdl;

    response =  MALLOC(MAX_EAP_PACKET);
    if (NULL == response)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    cur = response;
    length = 0;
    responseLen = 0;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, " Session : 0x");
    DEBUG_HEXINT(DEBUG_EAP_MESSAGE, (sbyte4)((uintptr)eapCb));
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, " EAP_FASTauthSendMethodResult: Result  ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, result);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");

    if (TRUE == sendCryptoBinding)
    {
        /* Build Crypto-binding TLV */
        /* Server nonce */
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Sending Crypto Binding TLV ");
#if defined(__ENABLE_ALL_DEBUGGING__)
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Sending NONCE  ");
        EAP_PrintBytes( nonce,EAP_FAST_CRYPTO_BINDING_NONCE_LEN);
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "AUTH CMK  ");
        EAP_PrintBytes( compoundKey,20);
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");
#endif
        DIGI_MEMCPY(eapCb->nonce, nonce,EAP_FAST_CRYPTO_BINDING_NONCE_LEN);

        status = eap_fastBuildCryptoBindingTlv(eapCb,
                                               EAP_FAST_BINDING_REQUEST,
                                               eapCb->nonce, compoundKey,
                                               cur, &length);
        cur += length;
        responseLen += length;
        /* Build Intermediate Result TLV */
        if (EAP_FAST_RESULT_TLV_SUCCESS == result)
        {
            eapCb->intermediate_result = EAP_FAST_INTERMEDIATE_SUCCESS;
        }
        else
        {
            eapCb->intermediate_result = EAP_FAST_INTERMEDIATE_FAILURE;
        }

        status = eap_fastBuildIntermediateResultTlv(eapCb->intermediate_result, cur, &length);
        cur += length;
        responseLen += length;
    }

    /* Build Result TLV */
    status = eap_fastBuildResultTlv(result, cur, &length);
    cur += length;
    responseLen += length;

    /* send */
    status = eapCb->eapFASTparam.ulTransmit(eapCb->appSessionCB, response,
                                   (ubyte2)responseLen, FALSE);

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
EAP_FASTauthGetCryptoBindingStatus(ubyte *eapFastSessionHdl,
                                    ubyte *bindingStatus)
{
    eapFASTCB    *eapCb = (eapFASTCB *)eapFastSessionHdl;
    *bindingStatus = eapCb->crypto_binding_verified;
    return OK;
}

/*------------------------------------------------------------------*/

static MSTATUS
eap_fastBuildEapPayloadTlv(ubyte *eapPkt, ubyte2 eapPktLen,
                           ubyte *tlv, ubyte2 tlvLen,
                           ubyte *buf, ubyte4 *length)
{
    ubyte     *ptr = buf;
    ubyte2    len;

    *ptr++ = 0x80;
    *ptr++ = EAP_FAST_EAP_PAYLOAD_TLV;
    len = eapPktLen + tlvLen;
    len = EAP_HTONS(len);
    DIGI_MEMCPY(ptr, (ubyte *)&len, 2);
    ptr += 2;
    DIGI_MEMCPY(ptr, eapPkt, eapPktLen);
    ptr += eapPktLen;
    if (tlv && tlvLen != 0)
    {
        DIGI_MEMCPY(ptr, tlv, tlvLen);
    }
    *length = eapPktLen + tlvLen + 4;
    return OK;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_fastgetTLVbyType(eapFASTCB *eapCb, ubyte *pPkt, ubyte4 pktLen, ubyte2 type,
                     ubyte2 *pTlvLen, ubyte **pData, ubyte *isMandatory)
{
    ubyte2 tlvType;
    ubyte  *ptr = pPkt;
    ubyte2 tlv_len = 0;
    ubyte2 len;

    *isMandatory = FALSE;

    while (ptr)
    {
        DIGI_MEMCPY((ubyte *)&tlvType, ptr, 2);
        tlvType = EAP_NTOHS(tlvType) & 0x3fff;
        DIGI_MEMCPY((ubyte *)&len, (ptr + 2), 2);
        len = EAP_NTOHS(len);
        if (tlvType == type)
        {
            if (*ptr & 0x80)
                *isMandatory = TRUE;
            *pTlvLen = len;
            *pData = ptr + 4;
            break;
        }
        tlv_len += len + 4;
        if (tlv_len < pktLen)
            ptr += len + 4;
        else
            break;
    }

    return OK;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_fastIncNonce(eapFASTCB *eapCb)
{
    sbyte4 pos = EAP_FAST_CRYPTO_BINDING_NONCE_LEN - 1;

    while (pos >= 0)
    {
        eapCb->nonce[pos]++;
        if (eapCb->nonce[pos] != 0)
            break;
        pos--;
    }

    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_peapv2ProcessCryptoBindingTLV(eapFASTCB *eapCb, ubyte *pPkt, ubyte2 pktLen,
                                ubyte *resp, ubyte4 *pRespLen)
{
    ubyte     *nonce;
    ubyte     cmac[EAP_FAST_CRYPTO_BINDING_CMAC_LEN];
    ubyte     recvd_cmac[EAP_FAST_CRYPTO_BINDING_CMAC_LEN];
    ubyte     cmk[20];
    ubyte2    tlvLen;
    ubyte4    resp_tlv_len;
    ubyte     *pTlv;
    ubyte     *ptr;
    sbyte4    cmp;
    ubyte     isMandatory;
    MSTATUS   status = OK;

    status = eap_fastgetTLVbyType(eapCb, pPkt, pktLen,
                                  EAP_FAST_CRYPTO_BINDING_TLV,
                                  &tlvLen, &pTlv, &isMandatory);
    ptr = pTlv + 1;
    /* verify version */
    if (*ptr != 1 || *(ptr + 1) != eapCb->eapFASTparam.version)
    {
        status = eap_fastBuildErrorTlv(
                              EAP_FAST_UNEXPECTED_TLVS_EXCHANGED_ERROR,
                              resp, pRespLen);
        status = ERR_EAP_FAST_UNEXPECTED_TLVS_ERROR;
        goto exit;
    }
    if (((EAP_SESSION_TYPE_PEER == eapCb->eapFASTparam.sessionType) &&
         (*(ptr + 2) != EAP_FAST_BINDING_REQUEST)) ||
        ((EAP_SESSION_TYPE_AUTHENTICATOR == eapCb->eapFASTparam.sessionType) &&
         (*(ptr + 2) != EAP_FAST_BINDING_RESPONSE)))
    {
        status = eap_fastBuildErrorTlv(
                              EAP_FAST_UNEXPECTED_TLVS_EXCHANGED_ERROR,
                              resp, pRespLen);
        resp_tlv_len = *pRespLen;
        status = eap_fastBuildResultTlv(EAP_FAST_RESULT_TLV_FAILURE,
                                        (resp + resp_tlv_len), pRespLen);
        *pRespLen += resp_tlv_len;
        status = ERR_EAP_FAST_UNEXPECTED_TLVS_ERROR;
        goto exit;
    }
    ptr += 2;
    if (EAP_FAST_INTERMEDIATE_FAILURE == eapCb->intermediate_result)
    {
        /* build Intermediate failure result */
        status = eap_fastBuildIntermediateResultTlv(
                 EAP_FAST_INTERMEDIATE_FAILURE, resp, pRespLen);
        goto exit;
    }
    /* verify compound MAC only 16 Bytes */
    DIGI_MEMCPY(recvd_cmac, (pTlv + 36), EAP_PEAPV2_CRYPTO_BINDING_CMAC_LEN);
    DIGI_MEMSET((pTlv + 36), 0, EAP_PEAPV2_CRYPTO_BINDING_CMAC_LEN);

    if (EAP_SESSION_TYPE_PEER == eapCb->eapFASTparam.sessionType)
    {
        if (EAP_FAST_INTERMEDIATE_SUCCESS == eapCb->intermediate_result)
        {
            /* Get Server nonce */
            DIGI_MEMCPY(eapCb->nonce, (pTlv + 4),
                       EAP_FAST_CRYPTO_BINDING_NONCE_LEN);

            /* Create Client NONCE */
            if (OK > (status = RANDOM_numberGenerator(g_pRandomContext,
                            eapCb->c_nonce, EAP_FAST_CRYPTO_BINDING_NONCE_LEN)))
            {
                goto exit;
            }

            status = eapCb->eapFASTparam.ulGetPeapV2CompoundKey((ubyte *)eapCb->appSessionCB, cmk,eapCb->nonce,eapCb->c_nonce);

            if (OK > status)
                goto exit;

            status = eap_fastCalculateCryptoMac(eapCb, cmk, (pTlv - 4),
                                   EAP_PEAPV2_CRYPTO_BINDING_TLV_LEN +4, cmac);
            if (OK > status)
                goto exit;

            DIGI_MEMCMP(cmac, recvd_cmac, EAP_PEAPV2_CRYPTO_BINDING_CMAC_LEN, &cmp);

            if (cmp != 0)
            {
                status = eap_fastBuildErrorTlv(
                                      EAP_FAST_UNEXPECTED_TLVS_EXCHANGED_ERROR,
                                      resp, pRespLen);
                status = ERR_EAP_FAST_UNEXPECTED_TLVS_ERROR;
                goto exit;
            }

            /* Call BuildCryptoBindingTLV */
            status = eap_fastBuildCryptoBindingTlv(eapCb,
                                               EAP_FAST_BINDING_RESPONSE,
                                               eapCb->c_nonce, cmk,
                                               resp, pRespLen);
            resp_tlv_len = *pRespLen;
            status = eap_fastBuildIntermediateResultTlv(
                     EAP_FAST_INTERMEDIATE_SUCCESS, (resp + resp_tlv_len), pRespLen);
            *pRespLen += resp_tlv_len;
        }
    }
    else if (EAP_SESSION_TYPE_AUTHENTICATOR == eapCb->eapFASTparam.sessionType)
    {

        DIGI_MEMCPY(eapCb->c_nonce, (pTlv + 4), EAP_FAST_CRYPTO_BINDING_NONCE_LEN);
        status = eapCb->eapFASTparam.ulGetPeapV2CompoundKey((ubyte *)eapCb->appSessionCB, cmk,eapCb->nonce,eapCb->c_nonce);

        if (OK > status)
            goto exit;

        status = eap_fastCalculateCryptoMac(eapCb, cmk, (pTlv - 4),
                               EAP_PEAPV2_CRYPTO_BINDING_TLV_LEN +4, cmac);
        if (OK > status)
            goto exit;

        DIGI_MEMCMP(cmac, recvd_cmac, EAP_PEAPV2_CRYPTO_BINDING_CMAC_LEN, &cmp);

        if (cmp != 0)
        {
            status = eap_fastBuildErrorTlv(
                                  EAP_FAST_UNEXPECTED_TLVS_EXCHANGED_ERROR,
                                  resp, pRespLen);
            status = ERR_EAP_FAST_UNEXPECTED_TLVS_ERROR;
            goto exit;
        }

    }

    eapCb->crypto_binding_verified = TRUE;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
eap_fastProcessCryptoBindingTLV(eapFASTCB *eapCb, ubyte *pPkt, ubyte2 pktLen,
                                ubyte *resp, ubyte4 *pRespLen)
{
    ubyte     *nonce;
    ubyte     cmac[EAP_FAST_CRYPTO_BINDING_CMAC_LEN];
    ubyte     recvd_cmac[EAP_FAST_CRYPTO_BINDING_CMAC_LEN];
    ubyte     cmk[20];
    ubyte2    tlvLen;
    ubyte4    resp_tlv_len;
    ubyte     *pTlv;
    ubyte     *ptr;
    sbyte4    cmp;
    ubyte     isMandatory;
    MSTATUS   status = OK;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, " eap_fastProcessCryptoBindingTLV: ");

    status = eap_fastgetTLVbyType(eapCb, pPkt, pktLen,
                                  EAP_FAST_CRYPTO_BINDING_TLV,
                                  &tlvLen, &pTlv, &isMandatory);
    ptr = pTlv + 1;
    /* verify version */
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, " Version : ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte)*ptr);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, " :  Version  ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte)*(ptr+1));
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, " :  Subtype  ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte)*(ptr+2));
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");

    if (*ptr != 1 || *(ptr + 1) != eapCb->eapFASTparam.version)
    {
        status = eap_fastBuildErrorTlv(
                              EAP_FAST_UNEXPECTED_TLVS_EXCHANGED_ERROR,
                              resp, pRespLen);
        status = ERR_EAP_FAST_UNEXPECTED_TLVS_ERROR;
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " Invalid Version ");
        goto exit;
    }
    if (((EAP_SESSION_TYPE_PEER == eapCb->eapFASTparam.sessionType) &&
         (*(ptr + 2) != EAP_FAST_BINDING_REQUEST)) ||
        ((EAP_SESSION_TYPE_AUTHENTICATOR == eapCb->eapFASTparam.sessionType) &&
         (*(ptr + 2) != EAP_FAST_BINDING_RESPONSE)))
    {
        status = eap_fastBuildErrorTlv(
                              EAP_FAST_UNEXPECTED_TLVS_EXCHANGED_ERROR,
                              resp, pRespLen);
        resp_tlv_len = *pRespLen;
        status = eap_fastBuildResultTlv(EAP_FAST_RESULT_TLV_FAILURE,
                                        (resp + resp_tlv_len), pRespLen);
        *pRespLen += resp_tlv_len;
        status = ERR_EAP_FAST_UNEXPECTED_TLVS_ERROR;
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " Invalid Binding Req/Resp ");
        goto exit;
    }
    ptr += 2;
    if (EAP_FAST_INTERMEDIATE_FAILURE == eapCb->intermediate_result)
    {
        /* build Intermediate failure result */
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " Sending EAP_FAST_INTERMEDIATE_FAILURE");
        status = eap_fastBuildIntermediateResultTlv(
                 EAP_FAST_INTERMEDIATE_FAILURE, resp, pRespLen);
        goto exit;
    }
    /* verify compound MAC */
    DIGI_MEMCPY(recvd_cmac, (pTlv + 36), EAP_FAST_CRYPTO_BINDING_CMAC_LEN);
    DIGI_MEMSET((pTlv + 36), 0, EAP_FAST_CRYPTO_BINDING_CMAC_LEN);

#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "RECVD CRYPTO BINDING CMAC  ");
    EAP_PrintBytes( recvd_cmac, EAP_FAST_CRYPTO_BINDING_CMAC_LEN);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");
#endif

    status = eapCb->eapFASTparam.ulGetFastCompoundKey((ubyte *)eapCb->appSessionCB, cmk);

    if (OK > status)
        goto exit;

#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "COMPOUND MAC ");
    EAP_PrintBytes( cmk, 20);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");
#endif

    status = eap_fastCalculateCryptoMac(eapCb, cmk, (pTlv - 4),
                           EAP_FAST_CRYPTO_BINDING_TLV_LEN +4, cmac);
    if (OK > status)
        goto exit;

#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "CALCULATED CRYPTO BINDING CMAC  ");
    EAP_PrintBytes( cmac, EAP_FAST_CRYPTO_BINDING_CMAC_LEN);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");
#endif

    DIGI_MEMCMP(cmac, recvd_cmac, EAP_FAST_CRYPTO_BINDING_CMAC_LEN, &cmp);

    if (cmp != 0)
    {
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid CRYPTO BINDING CMAC Sending Error TLV  ");
        status = eap_fastBuildErrorTlv(
                              EAP_FAST_UNEXPECTED_TLVS_EXCHANGED_ERROR,
                              resp, pRespLen);
        status = ERR_EAP_FAST_UNEXPECTED_TLVS_ERROR;
        goto exit;
    }
    if (EAP_SESSION_TYPE_PEER == eapCb->eapFASTparam.sessionType)
    {
        if (!(eapCb->tlv_flag & EAP_FAST_INTERMEDIATE_RESULT_TLV_FLAG))
            eapCb->intermediate_result = EAP_FAST_INTERMEDIATE_SUCCESS ;
        if (EAP_FAST_INTERMEDIATE_SUCCESS == eapCb->intermediate_result)
        {
            /* Increment nonce */
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Sending Crypto Binding Response Success  ");
            DIGI_MEMCPY(eapCb->nonce, (pTlv + 4),
                       EAP_FAST_CRYPTO_BINDING_NONCE_LEN);
            eap_fastIncNonce(eapCb);

#if defined(__ENABLE_ALL_DEBUGGING__)
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Incremented NONCE  ");
            EAP_PrintBytes( eapCb->nonce,EAP_FAST_CRYPTO_BINDING_NONCE_LEN);
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");
#endif
            /* Call BuildCryptoBindingTLV */
            status = eap_fastBuildCryptoBindingTlv(eapCb,
                                               EAP_FAST_BINDING_RESPONSE,
                                               eapCb->nonce, cmk,
                                               resp, pRespLen);
            if ((eapCb->tlv_flag & EAP_FAST_INTERMEDIATE_RESULT_TLV_FLAG))
            {
                resp_tlv_len = *pRespLen;
                status = eap_fastBuildIntermediateResultTlv(
                         EAP_FAST_INTERMEDIATE_SUCCESS, (resp + resp_tlv_len), pRespLen);
                *pRespLen += resp_tlv_len;
            }
        }
    }
    else if (EAP_SESSION_TYPE_AUTHENTICATOR == eapCb->eapFASTparam.sessionType)
    {
        /* verify incremented nonce */
        eap_fastIncNonce(eapCb);
        DIGI_MEMCMP(eapCb->nonce, (pTlv + 4), EAP_FAST_CRYPTO_BINDING_NONCE_LEN,
                   &cmp);
#if defined(__ENABLE_ALL_DEBUGGING__)
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Incremented NONCE  ");
        EAP_PrintBytes( eapCb->nonce,EAP_FAST_CRYPTO_BINDING_NONCE_LEN);
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Received NONCE  ");
        EAP_PrintBytes( (ubyte *)pTlv + 4,EAP_FAST_CRYPTO_BINDING_NONCE_LEN);
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");
#endif
        if (cmp != 0)
        {
            /* Send error TLV & Result TLV of Failure */
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Invalid Nonce Sending Error TLV  ");
            status = eap_fastBuildErrorTlv(
                              EAP_FAST_UNEXPECTED_TLVS_EXCHANGED_ERROR,
                              resp, pRespLen);
            resp_tlv_len = *pRespLen;
            status = eap_fastBuildResultTlv(EAP_FAST_RESULT_TLV_FAILURE,
                                        (resp + resp_tlv_len), pRespLen);
            *pRespLen += resp_tlv_len;
            status = ERR_EAP_FAST_UNEXPECTED_TLVS_ERROR;
            eapCb->crypto_binding_verified = FALSE;
            goto exit;
        }
    }

    eapCb->crypto_binding_verified = TRUE;

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_fastProcessIntermediateResultTLV(eapFASTCB *eapCb, ubyte *pPkt,
                                     ubyte2 pktLen,
                                     ubyte *resp, ubyte4 *pRespLen)
{
    MSTATUS status = OK;
    ubyte   *pTlv = NULL;
    ubyte2  intResult;
    ubyte2  tlvLen;
    ubyte   isMandatory;

    status = eap_fastgetTLVbyType(eapCb, pPkt, pktLen,
                                  EAP_FAST_INTERMEDIATE_RESULT_TLV,
                                  &tlvLen, &pTlv, &isMandatory);


    intResult =  *pTlv << 8 | *(pTlv +1);

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, " eap_fastProcessIntermediateResultTLV:Result ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4) intResult );
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");
    if (eapCb->intermediate_result != intResult)
        eapCb->intermediate_result = intResult;
    *pRespLen = 0;
    return OK;
}

/*------------------------------------------------------------------*/

static MSTATUS
eap_fastProcessPACTLV(eapFASTCB *eapCb, ubyte *pPkt, ubyte2 pktLen,
                         ubyte *resp, ubyte4 *pRespLen)
{
    ubyte2     tlvLen;
    ubyte2     PACtlvLen;
    ubyte2     PACInfotlvLen;
    ubyte      *pTlv;
    ubyte      *pPACTlv;
    ubyte      *pPACInfoTlv;
    ubyte      isMandatory;
    MSTATUS    status;
    ubyte2     result;
    ubyte4     err_code;
    ubyte4     cur_resp_len;
    EAP_FAST_pac_t *pac = NULL;

    status = eap_fastgetTLVbyType(eapCb, pPkt, pktLen, EAP_FAST_PAC_TLV,
                     &PACtlvLen, &pPACTlv, &isMandatory);
    if (!pPACTlv)
    {
        status = ERR_EAP_FAST_UNEXPECTED_TLVS_ERROR;
        goto exit;
    }

    if (EAP_SESSION_TYPE_PEER == eapCb->eapFASTparam.sessionType)
    {
        if (NULL == (pac = MALLOC(sizeof(EAP_FAST_pac_t))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;

        }
        DIGI_MEMSET((ubyte *)pac, 0, sizeof(*pac));

        status = eap_fastgetTLVbyType(eapCb, pPACTlv, PACtlvLen,
                     EAP_FAST_PAC_KEY, &tlvLen, &pTlv, &isMandatory);
        if (!pTlv)
        {
            status = ERR_EAP_FAST_UNEXPECTED_TLVS_ERROR;
            goto exit;
        }

        if (EAP_FAST_PAC_KEY_LENGTH != tlvLen)
        {
             status = ERR_EAP_FAST_INVALID_TLV_LENGTH;
             goto exit;
        }
        DIGI_MEMCPY(pac->pacKey, pTlv, EAP_FAST_PAC_KEY_LENGTH);
#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " PAC KEY ");
    EAP_PrintBytes( pac->pacKey, EAP_FAST_PAC_KEY_LENGTH );
#endif

        status = eap_fastgetTLVbyType(eapCb, pPACTlv, PACtlvLen,
                     EAP_FAST_PAC_OPAQUE, &tlvLen, &pTlv, &isMandatory);
        if (!pTlv)
        {
            status = ERR_EAP_FAST_UNEXPECTED_TLVS_ERROR;
            goto exit;
        }
        if (NULL == (pac->pacOpaque = MALLOC(tlvLen)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;

        }

        DIGI_MEMCPY(pac->pacOpaque, pTlv, tlvLen);
        pac->pacOpaqueLen =  tlvLen;

#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " PAC OPAQUE ");
    EAP_PrintBytes( pac->pacOpaque, pac->pacOpaqueLen );
#endif

        status = eap_fastgetTLVbyType(eapCb, pPACTlv, PACtlvLen,
                     EAP_FAST_PAC_INFO, &PACInfotlvLen, &pPACInfoTlv, &isMandatory);
        if (!pPACInfoTlv)
        {
            status = ERR_EAP_FAST_UNEXPECTED_TLVS_ERROR;
            goto exit;
        }
        status = eap_fastgetTLVbyType(eapCb, pPACInfoTlv, PACInfotlvLen,
                     EAP_FAST_PAC_A_ID, &tlvLen, &pTlv, &isMandatory);
        if (!pTlv)
        {
            status = ERR_EAP_FAST_UNEXPECTED_TLVS_ERROR;
            goto exit;
        }
        if (NULL == (pac->a_id = MALLOC(tlvLen)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;

        }
        DIGI_MEMCPY(pac->a_id, pTlv, tlvLen);
        pac->a_idLen =  tlvLen;
        status = eap_fastgetTLVbyType(eapCb, pPACInfoTlv, PACInfotlvLen,
                     EAP_FAST_PAC_A_ID_INFO, &tlvLen, &pTlv, &isMandatory);
        if (!pTlv)
        {
            status = ERR_EAP_FAST_UNEXPECTED_TLVS_ERROR;
            goto exit;
        }
        if (NULL == (pac->a_idInfo = MALLOC(tlvLen)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;

        }
        DIGI_MEMCPY(pac->a_idInfo, pTlv, tlvLen);
        pac->a_idInfoLen =  tlvLen;
        eapCb->pac = pac;
    }
    else
    {
        /*Should Not be getting this TLV */
        if (!eapCb->pac_sent)
        {
            /* The Peer has to Send a PAC_TYPE TLV Requesting
               the PAC Type */
            status = eap_fastgetTLVbyType(eapCb, pPACTlv, PACtlvLen,
                     EAP_FAST_PAC_TYPE, &tlvLen, &pTlv, &isMandatory);
            if (!pTlv)
            {
                status = ERR_EAP_FAST_UNEXPECTED_TLVS_ERROR;
                goto exit;
            }

            DIGI_MEMCPY((ubyte *)&result, pTlv, 2);
            result = EAP_NTOHS(result);
            eapCb->pac_type_request = result;
            goto exit;

        }
        status = eap_fastgetTLVbyType(eapCb, pPACTlv, PACtlvLen,
                     EAP_FAST_PAC_ACK, &tlvLen, &pTlv, &isMandatory);
        if (!pTlv)
        {
            status = ERR_EAP_FAST_UNEXPECTED_TLVS_ERROR;
            goto exit;
        }
        DIGI_MEMCPY((ubyte *)&result, pTlv, 2);
        result = EAP_NTOHS(result);
        eapCb->pac_ack_result = result;

    }


exit:

    if (OK > status)
    {
        if (pac)
        {
            if (pac->pacOpaque)
               FREE(pac->pacOpaque);
            if (pac->a_id)
               FREE(pac->a_id);
            if (pac->a_idInfo)
               FREE(pac->a_idInfo);
            FREE(pac);

        }
    }
    return status;

}

/*------------------------------------------------------------------*/

static MSTATUS
eap_fastProcessResultTLV(eapFASTCB *eapCb, ubyte *pPkt, ubyte2 pktLen,
                         ubyte *resp, ubyte4 *pRespLen)
{
    ubyte2     tlvLen;
    ubyte      *pTlv;
    ubyte      isMandatory;
    MSTATUS    status;
    ubyte2     result;
    ubyte4     err_code = 0;
    ubyte4     cur_resp_len;

    if (eapCb->tlv_flag & EAP_FAST_PAC_TLV_FLAG)
    {

        eap_fastProcessPACTLV(eapCb, pPkt, pktLen,
                              resp, pRespLen);

    }

    status = eap_fastgetTLVbyType(eapCb, pPkt, pktLen, EAP_FAST_RESULT_TLV,
                     &tlvLen, &pTlv, &isMandatory);
    if (!pTlv)
    {
        status = ERR_EAP_FAST_UNEXPECTED_TLVS_ERROR;
        goto exit;
    }

    DIGI_MEMCPY((ubyte *)&result, pTlv, 2);
    result = EAP_NTOHS(result);

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, "eap_fastProcessResultTLV: Received Result Code ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)result);

    if (EAP_FAST_RESULT_TLV_FAILURE == result)
    {
        pTlv = NULL;
        tlvLen = 0;
        status = eap_fastgetTLVbyType(eapCb, pPkt, pktLen, EAP_FAST_ERROR_TLV,
                     &tlvLen, &pTlv, &isMandatory);
        if (pTlv && tlvLen != 0)
        {
            DIGI_MEMCPY((ubyte *)&err_code, pTlv, 4);
            err_code = EAP_NTOHL(err_code);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, "  Error Code ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)err_code);
        }
        if (EAP_SESSION_TYPE_PEER == eapCb->eapFASTparam.sessionType)
        {
            /* Send Result TLV with Failure */
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, "  Sending RESULT TLV FAILURE ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)err_code);
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");
            status = eap_fastBuildResultTlv(EAP_FAST_RESULT_TLV_FAILURE,
                                            resp, pRespLen);
        }
        status = eapCb->eapFASTparam.ulAuthResultTransmit(eapCb->appSessionCB,
                                                 eapCb->crypto_binding_verified,
                                                 EAP_AUTH_FAILURE);
        /* Delete inner EAP session here */
        status = EAP_sessionDelete(eapCb->eapSessionHdl,
                                       eapCb->eapFASTparam.instanceId);
        eapCb->eapSessionHdl = NULL;
        if (eapCb->method_count > 0)
            eapCb->method_count--;

    }
    else if (EAP_FAST_RESULT_TLV_SUCCESS == result)
    {
        if (EAP_SESSION_TYPE_PEER == eapCb->eapFASTparam.sessionType)
        {
            if (0 == eapCb->method_count)
            {
                /* No methods have been executed in phase 2, so no intermediate
                   result is expected */
                /* Send Result TLV with Success */
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, "  Sending RESULT TLV SUCCESS ");
                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");
                status = eap_fastBuildResultTlv(EAP_FAST_RESULT_TLV_SUCCESS,
                                        resp, pRespLen);
            }
            else
            {
                if (TRUE == eapCb->crypto_binding_verified &&
                    EAP_FAST_INTERMEDIATE_SUCCESS == eapCb->intermediate_result)
                {
                    /* Send Result TLV with Success */
                    DEBUG_PRINT(DEBUG_EAP_MESSAGE, "  Recv Intermediate Success Sending RESULT TLV SUCCESS ");
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");
                    status = eap_fastBuildResultTlv(EAP_FAST_RESULT_TLV_SUCCESS,
                                        resp, pRespLen);
                    if (eapCb->tlv_flag & EAP_FAST_PAC_TLV_FLAG)
                    {
                        status = eap_fastBuildPACAckTlv(EAP_FAST_PAC_ACK_RESULT_SUCCESS, resp + *pRespLen , &cur_resp_len);
                        *pRespLen += cur_resp_len;
                    }

                    status = eapCb->eapFASTparam.ulAuthResultTransmit(
                                                     eapCb->appSessionCB,
                                                 eapCb->crypto_binding_verified,
                                                     EAP_AUTH_SUCCESS);
                }
                else
                {
                    /* send Error TLV with code */
                    DEBUG_PRINT(DEBUG_EAP_MESSAGE, "  Sending RESULT TLV FAILUREWITH UNEXPECTED_TLVS_EXCHANGE_ERROR ");
                    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");
                    status = eap_fastBuildErrorTlv(
                              EAP_FAST_UNEXPECTED_TLVS_EXCHANGED_ERROR,
                              resp, pRespLen);
                    /* send Result TLV with Failure */
                    cur_resp_len = *pRespLen;
                    status = eap_fastBuildResultTlv(
                                        EAP_FAST_RESULT_TLV_FAILURE,
                                        (resp + cur_resp_len), pRespLen);
                    *pRespLen += cur_resp_len;
                }
            }
            /* Delete inner EAP session here */
            status = EAP_sessionDelete(eapCb->eapSessionHdl,
                                       eapCb->eapFASTparam.instanceId);
            eapCb->eapSessionHdl = NULL;
            if (eapCb->method_count > 0)
                eapCb->method_count--;

        }
        else if (EAP_SESSION_TYPE_AUTHENTICATOR ==
                                             eapCb->eapFASTparam.sessionType)
        {
            if ((0 == eapCb->method_count  &&
                EAP_FAST_RESULT_TLV_SUCCESS == result) ||
               (0 < eapCb->method_count &&
                TRUE == eapCb->crypto_binding_verified &&
                EAP_FAST_INTERMEDIATE_SUCCESS == eapCb->intermediate_result))
            {
                /* Auth received Success from peer, so tear down TLS tunnel and
                   send EAP-Success */
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, "  Intermediate Success Sending AUTH RESULT TLV SUCCESS ");
                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");
                status = eapCb->eapFASTparam.ulAuthResultTransmit(
                                                 eapCb->appSessionCB,
                                                 eapCb->crypto_binding_verified,
                                                 EAP_AUTH_SUCCESS);
                status = eapCb->eapFASTparam.ulTLSclose(eapCb->appSessionCB);
            }
            else
            {
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, "  Failure Sending AUTH RESULT TLV FAILURE ");
                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");
                status = eapCb->eapFASTparam.ulTLSclose(eapCb->appSessionCB);
                if (OK > status)
                    goto exit;
                status = eapCb->eapFASTparam.ulAuthResultTransmit(
                                                 eapCb->appSessionCB,
                                                 eapCb->crypto_binding_verified,
                                                 EAP_AUTH_FAILURE);
                if (OK > status)
                    goto exit;
            }
            status = EAP_sessionDelete(eapCb->eapAuthSessionHdl,
                                       eapCb->eapFASTparam.instanceId);
            eapCb->eapAuthSessionHdl = NULL;

            if (OK > status)
                goto exit;

            if (eapCb->method_count > 0)
                eapCb->method_count--;

        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_fastProcessNakTLV(eapFASTCB *eapCb, ubyte *pTLV, ubyte2 len,
                      ubyte *resp, ubyte4 *pRespLen)
{
    /* what action should be taken here?? */
    return OK;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_fastProcessErrorTLV(eapFASTCB *eapCb, ubyte *pPkt, ubyte2 len,
                        ubyte *resp, ubyte4 *pRespLen)
{
    ubyte2     tlvLen;
    ubyte*     pTlv;
    ubyte      isMandatory;
    ubyte4     err_code;
    MSTATUS    status;

    /* extract error code. If fatal, send failure Result TLV */
    status = eap_fastgetTLVbyType(eapCb, pPkt, len, EAP_FAST_ERROR_TLV,
                     &tlvLen, &pTlv, &isMandatory);

    if (!pTlv || OK > status)
        goto exit;

    DIGI_MEMCPY((ubyte *)&err_code, pTlv, 4);
    err_code = EAP_NTOHL(err_code);
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, "eap_fastProcessErrorTLV: Received Err Code ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)err_code);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_fastProcessVendorTLV(eapFASTCB *eapCb, ubyte *pPkt, ubyte2 len,
                        ubyte *resp, ubyte4 *pRespLen)
{
    ubyte2     tlvLen;
    ubyte      *pTlv;
    ubyte      isMandatory;
    MSTATUS    status;
    ubyte4     vendor_id;
    ubyte      *pVendorTlv;

    /* extract Vendor specific TLV */
    status = eap_fastgetTLVbyType(eapCb, pPkt, len, EAP_FAST_VENDOR_TLV,
                     &tlvLen, &pTlv, &isMandatory);
    if (!pTlv || OK > status)
        goto exit;

    DIGI_MEMCPY((ubyte *)&vendor_id, pTlv, 4);
    vendor_id = EAP_NTOHL(vendor_id);
    pVendorTlv = pTlv + 4;
    /* Do any vendor specific TLV processing here */

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
eap_fastProcessEAPPeerRequest(eapFASTCB *eapCb, ubyte *pkt, ubyte4 pktLen)
{
   /* Pass the packet up  to the Peer  Second Stage*/
    MSTATUS status =OK;
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, "eap_fastProcessEapPeerRequest Length ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)pktLen);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");

    status = EAP_llReceivePacket(eapCb->eapSessionHdl,
                                 eapCb->eapFASTparam.instanceId,
                                 pkt, pktLen, NULL);


    return status;

}


/*------------------------------------------------------------------*/

static MSTATUS
eap_fastProcessEAPAuthRequest(eapFASTCB *eapCb, ubyte *pkt, ubyte4 pktLen)
{
   /* Pass the packet up  to the Auth Second Stage*/
    MSTATUS status = OK;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, "eap_fastProcessEapAuthRequest ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)pktLen);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");
    status = EAP_llReceivePacket(eapCb->eapAuthSessionHdl,
                                 eapCb->eapFASTparam.instanceId,
                                 pkt, pktLen, NULL);


    return status;

}


/*------------------------------------------------------------------*/

static MSTATUS
eap_fastProcessEapPayloadTLV(eapFASTCB *eapCb, ubyte *pPkt, ubyte2 len,
                        ubyte *resp, ubyte4 *pRespLen)
{
    ubyte2     eapPktlen;
    ubyte      isMandatory;
    MSTATUS    status;
    ubyte      *eapPkt;

    /* extract EAP pkt */
    status = eap_fastgetTLVbyType(eapCb, pPkt, len, EAP_FAST_EAP_PAYLOAD_TLV,
                     &eapPktlen, &eapPkt, &isMandatory);
    if (OK > status || !eapPkt)
        goto exit;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, "eap_fastProcessEapPayloadTLV --> ");

    if (EAP_SESSION_TYPE_PEER == eapCb->eapFASTparam.sessionType)
    {
#ifdef __ENABLE_DIGICERT_EAP_PEER__
        if (EAP_FAST_EAP_INIT == eapCb->eapStatus)
        {
            /* Open a new session */
            status = EAP_FASTPeerInit((ubyte *)eapCb);
            if (OK > status)
                goto exit;

            eapCb->eapStatus = EAP_FAST_EAP_IDENTITY;
        }
        status = eap_fastProcessEAPPeerRequest(eapCb, eapPkt, eapPktlen);
        if (OK > status)
            goto exit;
#endif
    }
    else if (EAP_SESSION_TYPE_AUTHENTICATOR == eapCb->eapFASTparam.sessionType)
    {
        status = eap_fastProcessEAPAuthRequest(eapCb, eapPkt, eapPktlen);
        if (OK > status)
            goto exit;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Process a decrypted EAP packet's TLVs.
This function parses a decrypted EAP packet for TLVs and processes each
according to its type.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one flag in each of the following flag pairs must be defined in moptions.h:
- Enable EAP peer/authenticator ($__ENABLE_DIGICERT_EAP_PEER__$, $__ENABLE_DIGICERT_EAP_AUTH__$)
- Enable asynchronous SSL client/server ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$, $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)
- Enable an EAP FAST method ($__ENABLE_DIGICERT_EAP_FAST__$, $__ENABLE_DIGICERT_EAP_PEAPV2__$)

#Include %file:#&nbsp;&nbsp;eap_fast.h

\param fastHdl  EAP-FAST session handle returned from EAP_FASTinitSession.
\param pPkt     Pointer to input packet.
\param pktLen   Number of bytes in input packet ($pPkt$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_FASTProcessTLV(ubyte * fastHdl, ubyte *pPkt, ubyte4 pktLen)
{
    ubyte2    type;
    ubyte     isMandatory = FALSE;
    ubyte     *ptr = pPkt;
    ubyte2    tlv_len = 0;
    ubyte     *response = NULL;
    ubyte     *cur;
    ubyte4    length;
    ubyte4    responseLen = 0;
    ubyte2    len;
    eapFASTCB *eapCb = (eapFASTCB *)fastHdl;
    MSTATUS   status = OK;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, " Session : 0x");
    DEBUG_HEXINT(DEBUG_EAP_MESSAGE, (sbyte4)((uintptr)eapCb));
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, " EAP_FASTProcessTLV: ");

    eapCb->tlv_flag = 0;
    while (ptr)
    {
        if (*ptr & 0x80)
            isMandatory = TRUE;

        DIGI_MEMCPY((ubyte *)&type, ptr, 2);
        type = EAP_NTOHS(type) & 0x3fff;
        DIGI_MEMCPY((ubyte *)&len, (ptr + 2), 2);
        len = EAP_NTOHS(len);

        switch (type)
        {
            case EAP_FAST_RESULT_TLV:
            {
                eapCb->tlv_flag |= EAP_FAST_RESULT_TLV_FLAG;
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, " EAP_FAST_RESULT_TLV : ");
                break;
            }

            case EAP_FAST_NAK_TLV:
            {
                eapCb->tlv_flag |= EAP_FAST_NAK_TLV_FLAG;
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, " EAP_FAST_NAK_TLV : ");
                break;
            }

            case EAP_FAST_ERROR_TLV:
            {
                eapCb->tlv_flag |= EAP_FAST_ERROR_TLV_FLAG;
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, " EAP_FAST_ERROR_TLV : ");
                break;
            }

            case EAP_FAST_EAP_PAYLOAD_TLV:
            {
                eapCb->tlv_flag |= EAP_FAST_EAP_PAYLOAD_TLV_FLAG;
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, " EAP_FAST_EAP_PAYLOAD_TLV : ");
                break;
            }

            case EAP_FAST_INTERMEDIATE_RESULT_TLV:
            {
                eapCb->tlv_flag |= EAP_FAST_INTERMEDIATE_RESULT_TLV_FLAG;
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, " EAP_FAST_INTERMEDIATE_RESULT_TLV : ");
                break;
            }

            case EAP_FAST_CRYPTO_BINDING_TLV:
            {
                eapCb->tlv_flag |= EAP_FAST_CRYPTO_BINDING_TLV_FLAG;
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, " EAP_FAST_CRYPTO_BINDING_TLV : ");
                break;
            }
            case EAP_FAST_REQUEST_ACTION_TLV:
            {
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, " EAP_FAST_REQUEST_ACTION_TLV : ");
                break;
            }
            case EAP_FAST_VENDOR_TLV:
            {
                eapCb->tlv_flag |= EAP_FAST_VENDOR_TLV_FLAG;
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, " EAP_FAST_VENDOR_TLV : ");
                break;
            }

            case EAP_FAST_PAC_TLV:
            {
                eapCb->tlv_flag |= EAP_FAST_PAC_TLV_FLAG;
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, " EAP_FAST_PAC_TLV : ");
                break;
            }

            default:
            {
                status = ERR_EAP_FAST_INVALID_TLV_TYPE;
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, " INVALID : ");
                DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)type);
                goto exit;
            }
        }
        tlv_len += len + 4;
        if (tlv_len < pktLen)
            ptr += len + 4;
        else
            break;
    }
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");

    response =  MALLOC(MAX_EAP_PACKET);
    if (NULL == response)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    cur = response;
    length = 0;
    responseLen = 0;

    if (eapCb->tlv_flag & EAP_FAST_ERROR_TLV_FLAG)
    {
        length = 0;
        status = eap_fastProcessErrorTLV(eapCb, pPkt, pktLen, cur, &length);
        if (OK > status)
            goto exit;
        cur += length;
        responseLen += length;
    }
    if (eapCb->tlv_flag & EAP_FAST_VENDOR_TLV_FLAG)
    {
        length = 0;
        status = eap_fastProcessVendorTLV(eapCb, pPkt, pktLen, cur, &length);
        if (OK > status)
            goto exit;
        cur += length;
        responseLen += length;
    }
    if (eapCb->tlv_flag & EAP_FAST_INTERMEDIATE_RESULT_TLV_FLAG)
    {
        length = 0;
        status = eap_fastProcessIntermediateResultTLV(eapCb, pPkt, pktLen,
                                                      cur, &length);
        if (OK > status)
            goto exit;
        cur += length;
        responseLen += length;
    }
    if (eapCb->tlv_flag & EAP_FAST_CRYPTO_BINDING_TLV_FLAG)
    {
        length = 0;
        if (EAP_TYPE_FAST == eapCb->eapFASTparam.methodType)
            status = eap_fastProcessCryptoBindingTLV(eapCb, pPkt, pktLen,
                                                     cur, &length);
        else  /* Peap V2 */
            status = eap_peapv2ProcessCryptoBindingTLV(eapCb, pPkt, pktLen,
                                                     cur, &length);
        if (OK > status)
            goto exit;
        cur += length;
        responseLen += length;
    }
    if (eapCb->tlv_flag & EAP_FAST_RESULT_TLV_FLAG)
    {
        length = 0;
        status = eap_fastProcessResultTLV(eapCb, pPkt, pktLen,
                                                      cur, &length);
        if (OK > status)
            goto exit;
        cur += length;
        responseLen += length;
    }
    if (eapCb->tlv_flag & EAP_FAST_EAP_PAYLOAD_TLV_FLAG)
    {
        length = 0;
        status = eap_fastProcessEapPayloadTLV(eapCb, pPkt, pktLen, cur, &length);
        if (OK > status)
            goto exit;
        cur += length;
        responseLen += length;
    }
    if (response && responseLen > 0)
    {
        status = eapCb->eapFASTparam.ulTransmit(eapCb->appSessionCB, response,
                                   (ubyte2)responseLen, FALSE);
        if (OK > status)
            goto exit;
    }

exit:
    if (response && (0 == responseLen))
    {
        FREE(response);
    }
    return status;
}

/*------------------------------------------------------------------*/

static  MSTATUS
eap_fastSendPendingBytes(eapFASTCB *eapFastCb,
                        ubyte **eapRespData, ubyte4 *eapRespLen)
{
    MSTATUS   status = OK;
    ubyte     *eapResponse = NULL;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, "eap_fastSendPendingBytes: ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4) eapFastCb->data_send_remaining);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");

    if (MAX_EAP_TLS_MTU >= eapFastCb->data_send_remaining)
    {
        *eapRespLen = eapFastCb->data_send_remaining + 1;
        eapResponse = (ubyte *) MALLOC(*eapRespLen);

        if (NULL == eapResponse)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        *eapResponse = eapFastCb->eapFASTparam.version;
        eapFastCb->data_send_remaining = 0;
        eapFastCb->frag_flag = 0;
        FREE(eapFastCb->data_send);
        eapFastCb->data_send = NULL;
        eapFastCb->data_send_cur = NULL;
    }
    else
    {
       /* Will need fragmentation */
        *eapRespLen = MAX_EAP_TLS_MTU + 1;
        eapResponse = (ubyte *) MALLOC(*eapRespLen);
        if (NULL == eapResponse)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        *eapResponse = EAP_FAST_MORE_FRAGMENTS_FLAG |
                       eapFastCb->eapFASTparam.version;
        eapFastCb->data_send_remaining -= MAX_EAP_TLS_MTU;
    }

    status = DIGI_MEMCPY((eapResponse + 1), eapFastCb->data_send_cur,
                        (*eapRespLen - 1));
    if (eapFastCb->data_send_remaining)
    {
        eapFastCb->data_send_cur += (*eapRespLen - 1);
    }

    *eapRespData = eapResponse;

exit:
    if (OK > status)
    {
        if (eapResponse)
            FREE(eapResponse);
    }
    return status;
}


/*------------------------------------------------------------------*/

/* Take care of Incoming Fragmentation */

/*! Process a packet's TLVs, managing fragmentation, and send the packet on for second stage negotiation.
This function processes a packet's TLVs, performs any required reassembly, and
passes the packet to the EAP-FAST lower layer for second stage (method)
negotiation.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one flag in each of the following flag pairs must be defined in moptions.h:
- Enable EAP peer/authenticator ($__ENABLE_DIGICERT_EAP_PEER__$, $__ENABLE_DIGICERT_EAP_AUTH__$)
- Enable asynchronous SSL client/server ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$, $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)
- Enable an EAP FAST method ($__ENABLE_DIGICERT_EAP_FAST__$, $__ENABLE_DIGICERT_EAP_PEAPV2__$)

#Include %file:#&nbsp;&nbsp;eap_fast.h

\param eapFASTCb    EAP-FAST session handle returned from EAP_FASTinitSession.
\param pkt          Pointer to input packet (received from lower layer).
\param pktLen       Number of bytes in input packet ($pkt$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_FASTreceiveLLPacket(void * eapFASTCb, ubyte *pkt, ubyte4 pktLen)
{
    eapFASTCB  *fastCB = (eapFASTCB *)eapFASTCb;
    MSTATUS    status = ERR_NULL_POINTER;
    ubyte      *eapRespData;
    ubyte4     eapRespLen;
    ubyte      *eapClearRespData = NULL;
    ubyte4     eapClearRespLen = 0;
    ubyte      *eapRemData = NULL;
    ubyte4     eapRemLen = 0;
    ubyte      *ptr;
    ubyte      flags;
    ubyte2     type;
    ubyte2     len;
    intBoolean isTlsPkt = FALSE;
    ubyte      tlsType = 0;

    if (!pkt)
        goto exit;
    /* We can recv the following msgs */
    /* EAP-FAST start message with S flag set */
    /* Frag message with L & M flag - for 1st fragment */
    /* Frag message with M flag */
    /* Last Frag Message with  No Flag */
    /* Regular message with no L or M flag */
    /* Frag ACK Message Len ==1   */
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_FASTreceiveLLPacket: Session. 0x");
    DEBUG_HEXINT(DEBUG_EAP_MESSAGE, (sbyte4)((uintptr)fastCB));
#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " Payload Upto 100 Bytes ");
#ifndef __ENABLE_KEYVPN_LOG_SUPPRESSION__
    EAP_PrintBytes( pkt, (pktLen < 100 ) ? pktLen : 100 );
#endif
#endif
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");

    flags = *(pkt + 1);
    if (0 == fastCB->frag_flag)
    {
        if ((flags & EAP_FAST_LENGTH_INCLUDED_FLAG) &&
                 (flags & EAP_FAST_MORE_FRAGMENTS_FLAG))
        {
            /* This is the first fragment */
            DIGI_MEMCPY((ubyte *) &fastCB->data_recv_total_len, (pkt + 2), 4);
            fastCB->data_recv_total_len = EAP_NTOHL(fastCB->data_recv_total_len);
            fastCB->data_recv = MALLOC(fastCB->data_recv_total_len);
            if (NULL == fastCB->data_recv)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            DIGI_MEMCPY(fastCB->data_recv, (pkt + 6), (pktLen - 6));
            fastCB->data_recv_len = pktLen - 6;
            fastCB->frag_flag =  EAP_FAST_FRAG_FLAG_RECV;
            /* Send ACK */
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, "Received First Fragment Total Lenght ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)fastCB->data_recv_total_len);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, "  Fragment Lenght ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)fastCB->data_recv_len);
            DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " Sending Ack ");

            status = fastCB->eapFASTparam.ulTransmit(fastCB->appSessionCB,NULL,0,TRUE);
            goto exit;
        }
    }
    else /* fastCB->frag_flag != 0  */
    {
        if (1 == pktLen) /*its an ACK.. Send Pending Bytes */
        {
            if (EAP_FAST_FRAG_FLAG_SEND == fastCB->frag_flag)
            {
                DEBUG_PRINT(DEBUG_EAP_MESSAGE, "Received Ack Sending Pending Bytes ");
                status = eap_fastSendPendingBytes(fastCB,
                                                  &eapRespData, &eapRespLen);
                if (OK > status)
                    goto exit;
                status = fastCB->eapFASTparam.ulTransmit(fastCB->appSessionCB,
                                                eapRespData,eapRespLen,TRUE);
                DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)eapRespLen);
                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");
                goto exit;
            }
            else
            {
                /* getting an ACK when we've already sent all the data.? */
                 status = ERR_EAP_TLS_NO_DATA_TO_SEND;
                 goto exit;
            }
        }
        if (EAP_FAST_FRAG_FLAG_RECV == fastCB->frag_flag)
        {
            ubyte *tlsData = pkt + 2;
            ubyte2 tlsDataLen = pktLen - 2;
            if (flags & EAP_FAST_LENGTH_INCLUDED_FLAG)
            {
               tlsData +=4;
               tlsDataLen-=4;
            }

            DIGI_MEMCPY((fastCB->data_recv + fastCB->data_recv_len),
                   (tlsData), (tlsDataLen));

            fastCB->data_recv_len += tlsDataLen;
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, "Received Fragment Lenght ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)tlsDataLen);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, "  Lenght Received So Far ");
            DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4)fastCB->data_recv_len);
            DEBUG_PRINT(DEBUG_EAP_MESSAGE, " Sending Ack ");
            if (flags & EAP_FAST_MORE_FRAGMENTS_FLAG)
            {
                /* Send ACK */
                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " More Fragments to Arrive ");
                status = fastCB->eapFASTparam.ulTransmit(fastCB->appSessionCB, NULL,
                                                0, TRUE);
                goto exit;
            }
            else /* Its the Last Pkt */
            {
                /* Last fragment */
                DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " Fragments Completed ");
                fastCB->frag_flag = 0;
            }
        }
    }

    /* Check If the Fully Formed Packet is a TLS Packet */

    if (fastCB->data_recv && fastCB->data_recv_total_len)
    {
        tlsType = *fastCB->data_recv;
        if (tlsType != SSL_APPLICATION_DATA)
            isTlsPkt = TRUE;

        status = EAP_TLSRecvData((ubyte *)fastCB, fastCB->eapFASTparam.tls_con,
                                 fastCB->data_recv,
                                 fastCB->data_recv_total_len,
                                 &eapClearRespData, &eapClearRespLen,
                                 &eapRemData, &eapRemLen);

        FREE(fastCB->data_recv);
        fastCB->data_recv = NULL;
        fastCB->data_recv_total_len = 0;
        fastCB->data_recv_len = 0;
        if (OK > status)
            goto exit;
    }
    else
    {
        if ((pkt) && (pktLen))
        {
            if (!(*(pkt+1) & EAP_TLS_LENGTH_FLAG))
            {
                tlsType = *(pkt+2);

                if (tlsType != SSL_APPLICATION_DATA)
                    isTlsPkt = TRUE;

                /* Data Starts an Offset 2 (PEAPByte,Flag Byte */
                status = EAP_TLSRecvData((ubyte *)fastCB,
                                     fastCB->eapFASTparam.tls_con,
                                     pkt+2,pktLen-2,
                                     &eapClearRespData, &eapClearRespLen,
                                     &eapRemData, &eapRemLen);
            }
            else
            {
                /* Data Starts an Offset 6 (PEAPByte,Flag Byte,Length 4 Bytes */
                tlsType = *(pkt+6);

                if (tlsType != SSL_APPLICATION_DATA)
                    isTlsPkt = TRUE;

                status = EAP_TLSRecvData((ubyte *)fastCB,
                                     fastCB->eapFASTparam.tls_con,
                                     pkt+6,pktLen -6,
                                     &eapClearRespData, &eapClearRespLen,
                                     &eapRemData, &eapRemLen);
            }
            if (OK > status)
                goto exit;

        }
    }

#if defined(__ENABLE_ALL_DEBUGGING__)
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "Decrypted Payload Upto 100 Bytes ");
#ifndef __ENABLE_KEYVPN_LOG_SUPPRESSION__
    EAP_PrintBytes( eapClearRespData, (eapClearRespLen < 100 ) ? eapClearRespLen : 100 );
#endif
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "  ");
#endif

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, "TLS Type is ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte)tlsType);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");

    if (!(isTlsPkt))
    {
        status = EAP_FASTProcessTLV((ubyte *)fastCB, eapClearRespData,eapClearRespLen);
    }
    else
    {

        if (SSL_ALERT == tlsType)
        {
            /* Just Send an Ack */
            status = fastCB->eapFASTparam.ulTransmit(fastCB->appSessionCB,NULL,0,TRUE);
            status = fastCB->eapFASTparam.ulAuthResultTransmit(fastCB->appSessionCB,
                                                     fastCB->crypto_binding_verified,
                                                     EAP_AUTH_FAILURE);
        /* Delete inner EAP session here */
            goto exit;
        }

        status = fastCB->eapFASTparam.ulTransmit(fastCB->appSessionCB,NULL,0,TRUE);
        goto exit;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Delete a second stage EAP-FAST session.
This function deletes a second stage EAP-FAST session.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one flag in each of the following flag pairs must be defined in moptions.h:
- Enable EAP peer/authenticator ($__ENABLE_DIGICERT_EAP_PEER__$, $__ENABLE_DIGICERT_EAP_AUTH__$)
- Enable asynchronous SSL client/server ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$, $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)
- Enable an EAP FAST method ($__ENABLE_DIGICERT_EAP_FAST__$, $__ENABLE_DIGICERT_EAP_PEAPV2__$)

#Include %file:#&nbsp;&nbsp;eap_fast.h

\param eapFASTSession   EAP-FAST session handle returned from EAP_FASTinitSession.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_FASTdeleteSession(ubyte *eapFASTSession)
{
    eapFASTCB *eapCb = (eapFASTCB *)eapFASTSession;
    MSTATUS   status = OK;

    if (NULL == eapCb)
        goto exit;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_FASTdeleteSession: Session. 0x");
    DEBUG_HEXINT(DEBUG_EAP_MESSAGE, (sbyte4)((uintptr)eapCb));
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");

    if(EAP_SESSION_TYPE_AUTHENTICATOR == eapCb->eapFASTparam.sessionType)
    {
        if (eapCb->eapAuthSessionHdl)
            status = EAP_sessionDelete(eapCb->eapAuthSessionHdl,
                                       eapCb->eapFASTparam.instanceId);
    }

    if(EAP_SESSION_TYPE_PEER == eapCb->eapFASTparam.sessionType)
    {
        if (eapCb->eapSessionHdl)
            status = EAP_sessionDelete(eapCb->eapSessionHdl,
                                       eapCb->eapFASTparam.instanceId);
    }

    if (eapCb->pac)
    {
        if (eapCb->pac->pacOpaque)
            FREE(eapCb->pac->pacOpaque);
        if (eapCb->pac->a_id)
            FREE(eapCb->pac->a_id);
        if (eapCb->pac->i_id)
            FREE(eapCb->pac->i_id);
        if (eapCb->pac->a_idInfo)
            FREE(eapCb->pac->a_idInfo);
        FREE(eapCb->pac);
    }
    if (eapCb)
        FREE(eapCb);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Create and initialize an EAP-FAST session.
This function creates and initializes an EAP-FAST session based on the specified
parameters, returning the resultant session handle through the $eapFastSession$
parameter.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one flag in each of the following flag pairs must be defined in moptions.h:
- Enable EAP peer/authenticator ($__ENABLE_DIGICERT_EAP_PEER__$, $__ENABLE_DIGICERT_EAP_AUTH__$)
- Enable asynchronous SSL client/server ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$, $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)
- Enable an EAP FAST method ($__ENABLE_DIGICERT_EAP_FAST__$, $__ENABLE_DIGICERT_EAP_PEAPV2__$)

#Include %file:#&nbsp;&nbsp;eap_fast.h

\param appSessionCB     Application session handle (cookie given by the application to identify the session).
\param eapFASTSession   On return, pointer to EAP-FAST session handle.
\param eapFASTparams    Pointer to desired EAP-FAST session parameters.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_FASTinitSession(ubyte *appSessionCB, ubyte **eapFASTSession,
                    EAP_FAST_params *eapFASTparams)
{

    eapFASTCB  *sessionCB = NULL;
    MSTATUS    status = OK;

    if ((NULL == eapFASTparams) || (NULL == eapFASTparams->ulTransmit))
    {
        status = ERR_EAP_FAST_MISSING_PARAMS;
        goto exit;
    }

    if ((EAP_SESSION_TYPE_PEER != eapFASTparams->sessionType) &&
        (EAP_SESSION_TYPE_AUTHENTICATOR != eapFASTparams->sessionType))
    {
        status = ERR_EAP_FAST_MISSING_PARAMS;
        goto exit;
    }

    if ((EAP_TYPE_FAST != eapFASTparams->methodType) &&
        (EAP_TYPE_PEAP != eapFASTparams->methodType))
    {
        status = ERR_EAP_FAST_MISSING_PARAMS;
        goto exit;
    }

    sessionCB = MALLOC(sizeof(eapFASTCB));

    if (NULL == sessionCB)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)sessionCB,0,sizeof(eapFASTCB));

    DIGI_MEMCPY((ubyte *)&sessionCB->eapFASTparam,(ubyte *)eapFASTparams,
               sizeof(EAP_FAST_params));

    /* We do the full eap  initialization code here */
    /* We should open the auth session here */
    sessionCB->appSessionCB = appSessionCB;
    *eapFASTSession = (void *)sessionCB;

#if defined(__ENABLE_DIGICERT_EAP_AUTH__)
    if (EAP_SESSION_TYPE_AUTHENTICATOR == eapFASTparams->sessionType)
    {
        status = EAP_FASTAuthInit((ubyte *)sessionCB);
        sessionCB->eapStatus = EAP_FAST_EAP_IDENTITY;
    }
#endif

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, "EAP_FASTInitSession: Session. 0x");
    DEBUG_HEXINT(DEBUG_EAP_MESSAGE, (sbyte4)((uintptr)sessionCB));
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");
exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Build an EAP payload TLV from an input second stage EAP packet and then pass the packet to the first stage.
This function builds an EAP payload TLV from the input second stage EAP packet
and then passes the packet to the first stage using the registered upper layer
callback. This packet can later be encrypted by the TLS session and passed to
the EAP lower layer.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one flag in each of the following flag pairs must be defined in moptions.h:
- Enable EAP peer/authenticator ($__ENABLE_DIGICERT_EAP_PEER__$, $__ENABLE_DIGICERT_EAP_AUTH__$)
- Enable asynchronous SSL client/server ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$, $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)
- Enable an EAP FAST method ($__ENABLE_DIGICERT_EAP_FAST__$, $__ENABLE_DIGICERT_EAP_PEAPV2__$)

#Include %file:#&nbsp;&nbsp;eap_fast.h

\param eapFastCb    EAP-FAST session handle returned from EAP_FASTinitSession.
\param eapPkt       Pointer to input EAP packet.
\param eapPktLen    Number of bytes in input EAP packet ($eapPkt$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_FASTEncapEAPPkt(ubyte *eapFastCb, ubyte *eapPkt, ubyte4 eapPktLen)
{
    ubyte     *response = NULL;
    ubyte     *cur;
    ubyte     flags = 0;
    ubyte4    responseLen = 0;
    ubyte4    length = 0;
    MSTATUS   status;
    eapFASTCB *eapCb = (eapFASTCB *)eapFastCb;

    response = MALLOC(eapPktLen + 4);

    if (NULL == response)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    cur = response;

    status = eap_fastBuildEapPayloadTlv(eapPkt, eapPktLen,
                                        NULL, 0,
                                        cur, &length);
    if (OK > status)
        goto exit;

    responseLen += length;
    cur         += length;

    DEBUG_PRINT(DEBUG_EAP_MESSAGE, " Session : 0x");
    DEBUG_HEXINT(DEBUG_EAP_MESSAGE, (sbyte4)((uintptr)eapCb));
    DEBUG_PRINT(DEBUG_EAP_MESSAGE, " EAP_FASTEncapEAPPkt Length ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4) responseLen);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");

    /*Send the Response */
    status = eapCb->eapFASTparam.ulTransmit(eapCb->appSessionCB,
                                        response, responseLen, FALSE);
exit:
    return status;

}


/*------------------------------------------------------------------*/

/*! Encapsulate an EAP packet into an EAP payload TLV packet.
This function encapsulates an  EAP packet into an EAP payload TLV,
returning the resultant packet through the $response$ parameter.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one flag in each of the following flag pairs must be defined in moptions.h:
- Enable EAP peer/authenticator ($__ENABLE_DIGICERT_EAP_PEER__$, $__ENABLE_DIGICERT_EAP_AUTH__$)
- Enable asynchronous SSL client/server ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$, $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)
- Enable an EAP FAST method ($__ENABLE_DIGICERT_EAP_FAST__$, $__ENABLE_DIGICERT_EAP_PEAPV2__$)

#Include %file:#&nbsp;&nbsp;eap_fast.h

\param eapPkt       Pointer to input EAP packet.
\param eapPktLen    Number of bytes in input EAP packet ($eapPkt$).
\param response     On return, pointer to response packet.
\param responseLen  On return, pointer to number of bytes in response packet ($response$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_FASTgetTLVEncapEAPPkt(ubyte *eapPkt, ubyte4 eapPktLen,ubyte **response,ubyte4 *responseLen)
{
    ubyte  *cur;
    ubyte   flags = 0;
    ubyte4  length = 0;
    MSTATUS status;

    *response = MALLOC(eapPktLen + 4);

    if (NULL == *response)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    cur = *response;

    status = eap_fastBuildEapPayloadTlv(eapPkt, eapPktLen,
                                        NULL, 0,
                                        cur, &length);
    if (OK > status)
        goto exit;

    *responseLen += length;
    cur          += length;

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "EAP_FASTgetTLVEncapEAPPkt Length ");
    DEBUG_INT(DEBUG_EAP_MESSAGE, (sbyte4) *responseLen);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) " ");

exit:
    return status;

}


/*------------------------------------------------------------------*/

/*! Extract the authority ID (if any) from an EAP-FAST packet.
This function extracts the authority ID (if any) from an EAP-FAST packet,
returning it through the $authId$ parameter.

\since 1.41
\version 1.41 and later

! Flags
To enable this function, at least one flag in each of the following flag pairs must be defined in moptions.h:
- Enable EAP peer/authenticator ($__ENABLE_DIGICERT_EAP_PEER__$, $__ENABLE_DIGICERT_EAP_AUTH__$)
- Enable asynchronous SSL client/server ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$, $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)
- Enable an EAP FAST method ($__ENABLE_DIGICERT_EAP_FAST__$, $__ENABLE_DIGICERT_EAP_PEAPV2__$)

#Include %file:#&nbsp;&nbsp;eap_fast.h

\param pkt          Pointer to EAP-FAST packet.
\param pktLen       Number of bytes in EAP-FAST packet ($pkt$).
\param authId       On return, pointer to authority ID.
\param authIdLen    On return, pointer to number of bytes in authority ID ($authId$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_FASTgetAuthId(ubyte *pkt, ubyte4 pktLen, ubyte **authId, ubyte2 *authIdLen)
{
    ubyte     *ptr;
    ubyte2    type;
    ubyte2    len;
    MSTATUS   status = OK;

    if (2 > pktLen)
    {
        status = ERR_EAP_TLS_INVALID_LEN;
        goto exit;
    }

    if (pktLen > 2)
    {
        ptr = pkt + 2;
        /* This is the first pkt, so data is Authority ID */
        type = *ptr++;
        type = (type << 8) + *ptr++;

        if (type != EAP_FAST_AUTH_ID_TYPE)
        {
            status = ERR_EAP_FAST_AUTH_ID_ERROR;
            goto exit;
        }
        len = *ptr++;
        len = (len << 8) + *ptr++;

        *authId = MALLOC(len);
        if (NULL == *authId)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        status = DIGI_MEMCPY(*authId, ptr, len);
        *authIdLen = len;
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "EAP_FASTgetAuthId: AuthId.");
#if defined(__ENABLE_ALL_DEBUGGING__)
        EAP_PrintBytes( *authId, *authIdLen);
        DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "  ");
#endif
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Build an $Authority ID Requeest$ packet.
This function (called by an EAP-TLS authenticator) builds an $Authority ID
Request$ packet that includes the specified $flags$ values. The resultant data will
ultimately be sent to the peer to provide hints about the authenticator's
identity during a $TLS Start$ message transmission.

\since 1.41
\version 1.41
\deprecated For applications using version 2.02 and later, you should not use
this function. Instead, call the EAP_TLSSetAuthId function.

! Flags
To enable this function, at least one flag in each of the following flag pairs must be defined in moptions.h:
- Enable EAP peer/authenticator ($__ENABLE_DIGICERT_EAP_PEER__$, $__ENABLE_DIGICERT_EAP_AUTH__$)
- Enable asynchronous SSL client/server ($__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__$, $__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__$)
- Enable an EAP FAST method ($__ENABLE_DIGICERT_EAP_FAST__$, $__ENABLE_DIGICERT_EAP_PEAPV2__$)

#Include %file:#&nbsp;&nbsp;eap_fast.h

\param flags        Sum of bitmasks indicating the $TLS Start$ bit status and
the TLS version.
\param authId       Pointer to authority ID (often set by calling
EAP_TLSSetAuthId before calling EAP_TLSstartRequest).
\param authIdLen    Number of bytes in authority ID ($authId$).
\param eapReqData   On return, pointer to resultant EAP-FAST/TLS request payload.
\param eapReqLen    On return, pointer to number of bytes in EAP request payload ($eapReqData$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
EAP_FASTbuildAuthId(ubyte flags, ubyte *authId, ubyte2 authIdLen,
                    ubyte **eapReqData, ubyte4 *eapReqLen)
{
    ubyte      *eapRequest = NULL;
    ubyte      *ptr = NULL;
    MSTATUS    status = OK;
    ubyte2     type;
    ubyte2     len;

    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "EAP_FASTbuildAuthId: AuthId.");
#if defined(__ENABLE_ALL_DEBUGGING__)
    EAP_PrintBytes( authId, authIdLen);
    DEBUG_PRINTNL(DEBUG_EAP_MESSAGE, (sbyte *) "  ");
#endif


    *eapReqLen = 5 + authIdLen;
    eapRequest = (ubyte *) MALLOC(*eapReqLen);

    if(NULL == eapRequest)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    ptr = eapRequest;
    *ptr++ = flags;
    type = EAP_HTONS(EAP_FAST_AUTH_ID_TYPE);
    DIGI_MEMCPY(ptr, (ubyte *)&type, 2);
    ptr += 2;
    len = EAP_HTONS(authIdLen);
    DIGI_MEMCPY(ptr, (ubyte *)&len, 2);
    ptr += 2;
    DIGI_MEMCPY(ptr, authId, authIdLen);
    *eapReqData = eapRequest;
exit:
    return status;
}


/*------------------------------------------------------------------*/

#endif /*(defined(__ENABLE_DIGICERT_EAP_FAST__)) */
#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */
