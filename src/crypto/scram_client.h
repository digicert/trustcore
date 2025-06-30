/*
 * scram_client.h
 * 
 * Definitions for client SCRAM implementation
 * 
 */

#ifndef __SCRAM_CLIENT_HEADER__
#define __SCRAM_CLIENT_HEADER__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SCRAM_SHA256_METHOD_STRING "SCRAM-SHA-256"
#define SCRAM_SHA512_METHOD_STRING "SCRAM-SHA-512"

typedef struct
{
    ubyte *pClientFirst;
    ubyte4 clientFirstLen;
    ubyte *pAuthMsg;
    ubyte4 authMsgLen;
    ubyte *pSalt;
    ubyte4 saltLen;
    ubyte hashType;
    ubyte4 hashLen;
    ubyte4 iterCount;
} ScramCtx;

/**
 * @details Create a new SCRAM context.
 *
 * @param ppNewCtx The pointer which will receive the pointer to the newly allocated SCRAM context.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS SCRAM_newCtx(ScramCtx **ppNewCtx);

/**
 * @details Free a SCRAM context.
 *
 * @param ppScramCtx The double pointer to a SCRAM context previously created with SCRAM_newCtx().
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS SCRAM_freeCtx(ScramCtx **ppScramCtx);

/* Do NOT free ppClientFirst, it is owned by the pCtx and will be freed upon a call to SCRAM_freeCtx() */

/**
 * @details Build the client first data.
 *
 * @param pCtx             Scram context to use.
 * @param pUsername        Username to use when building the client first data.
 * @param pNonce           Nonce used to create client first data. Optional, if
 *                         one is not provided a nonce is generated internally.
 * @param nonceLen         If pNonce is not NULL, then this must be the size of
 *                         pNonce in bytes. Otherwise this size will be used to
 *                         generate the nonce.
 * @param ppClientFirst    Will be set to a pointer pointing to the client first data,
 *                         which is owned and managed by the SCRAM context. DO NOT FREE
 *                         THIS POINTER, it will be freed upon a call to SCRAM_freeCtx()
 * @param pClientFirstLen  Pointer to the ubyte4 which will be set to the length of the 
 *                         client first message in bytes.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS SCRAM_buildClientFirstData(
    ScramCtx *pCtx,
    char *pUsername,
    ubyte *pNonce,
    ubyte4 nonceLen,
    ubyte **ppClientFirst,
    ubyte4 *pClientFirstLen);

/**
 * @details Build the client final data.
 *
 * @param pCtx             Scram context to use.
 * @param pServerFirst     The server first data.
 * @param serverFirstLen   The length in bytes of the server first data.
 * @param pPassword        The password associated with the username passed into
 *                         SCRAM_buildClientFirstData()
 * @param passwordLen      The length in bytes of the password.
 * @param hashType         The hash type to use for the operation, one of {ht_sha256, ht_sha512}
 * @param ppClientFinal    Will be set to a pointer pointing to the newly allocated client 
 *                         final data, which the caller is responsible for freeing. 
 * @param pClientFinalLen  Pointer to the ubyte4 which will be set to the length of the 
 *                         client final message in bytes.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS SCRAM_buildClientFinal(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    ScramCtx *pCtx,
    ubyte *pServerFirst,
    ubyte4 serverFirstLen,
    ubyte *pPassword,
    ubyte4 passwordLen,
    ubyte hashType,
    ubyte **ppClientFinal,
    ubyte4 *pClientFinalLen);

/**
 * @details Verify the server final data.
 *
 * @param pCtx             Scram context to use.
 * @param pPassword        The password associated with the username passed into
 *                         SCRAM_buildClientFirstData()
 * @param passwordLen      The length in bytes of the password.
 * @param pServerFinal     The server final data.
 * @param serverFinalLen   The length in bytes of the server final data.
 * @param pVerify          Will be set to TRUE if the signature verified, FALSE otherwise.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS SCRAM_verifyServerSignature(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    ScramCtx *pCtx,
    ubyte *pPassword,
    ubyte4 passwordLen,
    ubyte *pServerFinal,
    ubyte4 serverFinalLen,
    byteBoolean *pVerify);

#ifdef __cplusplus
}
#endif

#endif /* __SCRAM_CLIENT_HEADER__ */