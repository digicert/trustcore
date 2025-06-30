/*
 * capsym.h
 *
 * Cryptographic Abstraction Platform (CAP) Symmetric algorithm declarations.
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

/**
@file       capsym.h
@brief      Cryptographic Abstraction Platform (CAP) Symmetric algorithm declarations.
@details    Add details here.

@filedoc    capsym.h
*/

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mocana.h"
#include "../common/mrtos.h"
#include "../common/mem_part.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../cap/capdecl.h"

/* Use the definitions and declarations in this include file to build a symmetric
 * algorithm implementation.
 * This will work for symmetric encryption algorithms (AES, etc.) along with
 * digest and mac algorithms (SHA-256, HMAC with SHA-1, etc.), and random number
 * generators.
 * To build an implementation, you will write an Operator function that can
 * perform the subset of operations you want it to perform. It will have its own
 * local info, whatever you decide it needs to do its work.
 * To use a MocSymCtx, you will create the ctx by calling CRYPTO_createMocSymCtx,
 * then pass the created ctx to functions that perform the operations, such as
 * CRYPTO_generateKey, CRYPTO_encryptUpdate, or CRYPTO_macFinal.
 */

#ifndef __CAP_SYM_HEADER__
#define __CAP_SYM_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __RTOS_WIN32__

#ifdef WIN_EXPORT_NANOCAP
#define MOC_EXTERN_CAPSYM_H __declspec(dllexport)
#else
#define MOC_EXTERN_CAPSYM_H __declspec(dllimport) extern
#endif /* WIN_EXPORT_NANOCAP */

#ifdef WIN_STATIC
#undef MOC_EXTERN_CAPSYM_H
#define MOC_EXTERN_CAPSYM_H extern
#endif /* WIN_STATIC */

#else

#define MOC_EXTERN_CAPSYM_H extern

#endif /* __RTOS_WIN32__ */

/* We want all opCodes to be different. For example, we don't want the opCode for
 * Sign to coincidentally be the same as VerifyExtension. So for each class of
 * opCodes, assign a base number. For each class of opCodes, you now have 4 bits
 * to work with. You might simply choose to use numbers 1 through 11, or you
 * might specify some further bit system. For example, under the CERT opCode
 * system, you might have 0x1000 as the base number for request attributes, and
 * 0x2000 for extensions, and 0x3000 for name elements.
 * All other classes will include mocsym.h.
 */

/* All opCodes for Sym operations are based off this number.
 */
#define MOC_SYM_OP_CODE         0x10000
/* All opCodes for Asym operations are based off this number.
 */
#define MOC_ASYM_OP_CODE        0x20000
/* All opCodes for Cert operations are based off this number.
 */
#define MOC_CERT_OP_CODE        0x30000
/* All opCodes for Storage operations are based off this number.
 */
#define MOC_STORE_OP_CODE       0x40000

/** This is the signature of the operator function in a MocSymCtx.
 * <p>When Mocana code needs to perform some symmetric operation using a
 * MocSymCtx, it will call on the Operator function loaded.
 * <p>The Mocana code will pass to the Operator the object that is being worked
 * on along with the MocCtx. It is possible that one or both of them will be
 * NULL. Sometimes the caller just does not have access to them.
 * <p>The Mocana code will pass to the Operator function a flag indicating what
 * it wants the the operator to do. This is the opCode arg. The flag will be one
 * of the MOC_SYM_OP_CODE_ values defined.
 * <p>The Mocana code will also pass to the Operator inputInfo and outputInfo.
 * There will be different infos for each OP_CODE. Check the documentation for
 * what associated info to expect for each OP_CODE. Some info might be NULL, it
 * could be a data struct with a field where the Operator is to deposit allocated
 * memory (e.g. the DER encoding of an algorithm ID). It could be something else.
 * The infos will likely be data structs, the addresses cast to void *. The
 * operator dereferences the pointers to the specific structs based on the opCode
 * arg.
 * <p>The implementation of the Operator function will likely begin with a switch
 * statement. It will switch on the opCode. For each operation the implementation
 * supports, it will call a specific subroutine that knows how to dereference the
 * associated info and perform the specific operation.
 * <p>Mocana will pass to the Operator function the MocSymCtx. Any data the ctx
 * needs in order to perform its operations (such as hardware handle, init vector,
 * etc.) is at the mocSymCtx->pLocalData field, but the Operator will have the
 * entire context at its disposal.
 *
 * @param pMocSymCtx The object that contains the data needed to perform.
 * @param pMocCtx The MocCtx built during the call to MOCANA_initialize,
 * containing the lists of Operators the function will use to find one that can
 * do the work.
 * @param opCode What operation the caller is requesting the ctx perform.
 * @param pInputInfo Any input info (such as data to encrypt or digest) on which
 * the operator is to perform.
 * @param pOutputInfo Any buffers or addresses where the operator is to place
 * results.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
typedef MSTATUS (*MSymOperator) (
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  ubyte4 opCode,
  void *pInputInfo,
  void *pOutputInfo
  );

/* These are the operations a MocSymCtx will be asked to perform. Not every
 * ctx will be able to perform all operations. For example, a ctx built to
 * perform AES on a hardware device will be able to perform MOC_SYM_OP_GENERATE_KEY, but
 * won't be able to perform MOC_SYM_OP_DIGEST_INIT.
 * <p>It is possible a particular ctx won't be able to perform an operation you
 * might think it should. For example, a ctx built to perform AES in hardware
 * might not be able to return an AlgID, it is possible the developers built it
 * to be as small as possible so doesn't implement everything. Similarly, a
 * hardware implementation might not be able to load an AES key, it can only
 * operate on its own keys which are represented as tokens, not key data.
 * <p>For each value, the documentation describes the format of the pInputInfo
 * and pOutputInfo (see the documentation for MSymOperator).
 */

/** This is the opCode indicating the Operator should create itself. An existing
 * MocSymCtx struct is passed in, install the Operatore, build the localData and
 * set the localType.
 * <pre>
 * <code>
 * pInputInfo is void *, the pOperatorInfo passed during the call to
 *                       CRYPTO_createMocSymCtx.
 * pOutputInfo is NULL,  there is nothing to output, the create builds
 *                       the ctx.
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_CREATE                 (MOC_SYM_OP_CODE+1)

/** An Operator will be called to "build itself" using the AlgId or OID. If the
 * AlgId or OID is for the algorithm the Opearator performs, it will build
 * itself, if not, it will return the error ERR_CRYPTO_NOT_EXPECTED_ALGID.
 * <p>Note that the caller might pass in an algorithm ID or just an OID. An
 * AlgId is defined as
 * <pre>
 * <code>
 *   SEQUENCE {
 *     algorithm  OBJECT IDENTIFIER,
 *     ANY defined by algorithm }
 * </code>
 * </pre>
 * <p>An OID is simply the byte array 06 len -object ID-
 * <pre>
 * <code>
 * pInputInfo is a pointer to MSymOperatorDataAndInfo containing the AlgId or
 *                       OID along with associated info (info the Operator
 *                       needs).
 * pOutputInfo is NULL,  there is nothing to output, the create builds
 *                       the ctx.
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_CREATE_FROM_ALG_ID     (MOC_SYM_OP_CODE+2)

/** Free the local info, set the localType and SymOperator to 0/NULL.
 * <pre>
 * <code>
 * pInputInfo is NULL
 * pOutputInfo is NULL
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_FREE                   (MOC_SYM_OP_CODE+3)

/** Just return the localType.
 * <p>If an existing object exists, someone can simply look at the
 * object->localType to see it. But what if someone wnats to find out before
 * building what the localType will be?
 * <p>Call the Operator with this op just to get the localType.
 * <pre>
 * <code>
 * pInputInfo is NULL
 * pOutputInfo is a pointer to a ubyte4
 * </code>
 * </pre>
 * <p>The Operator will go to the address and deposit the localType.
 */
#define MOC_SYM_OP_GET_LOCAL_TYPE         (MOC_SYM_OP_CODE+4)

/** Use this opCode to indicate the Ctx should return the algId of the the object
 * as it is currently set.
 * <pre>
 * <code>
 * pInputInfo is NULL
 * pOutputInfo is a pointer to an MSymOperatorBuffer. The Operator is to fill
 * the pBuffer with the AlgId and set *pOutputLen to the length.
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_GET_ALG_ID             (MOC_SYM_OP_CODE+5)

/** Use this op code to perform the initial seeding of a random operator. Note
 * this is not used to reseed, it is only used to perform the one time initial
 * seeding process. Use MOC_SYM_OP_RESEED_RANDOM for reseeding.
 * <pre>
 * <code>
 * pInputInfo is a pointer to a MRandomSeedInfo containing the seed info.
 * pOutputInfo is NULL
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_SEED_RANDOM            (MOC_SYM_OP_CODE+6)

/** <pre>
 * <code>
 * pInputInfo is NULL
 * pOutputInfo is a pointer to an MSymOperatorBuffer. The Operator is to fill
 * the pBuffer with bufferSize random bytes and set *pOutputLen to the length.
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_GENERATE_RANDOM        (MOC_SYM_OP_CODE+7)

/** Generate a new symmetric key.
 * <pre>
 * <code>
 * pInputInfo is a pointer to an MSymKeyGenInfo struct containing a
 * rngFun, its argument, and the key size in bits.
 * pOutputInfo is a pointer to an MSymOperatorBuffer struct.
 * </code>
 * </pre>
 * <p>Place the resulting key data into the output info. This might be the raw
 * key data, it might be a hardware handle.
 */
#define MOC_SYM_OP_GENERATE_KEY           (MOC_SYM_OP_CODE+8)

/** Encode the key following this ASN.1 definition:
 * <pre>
 * <code>
 *    SymmetricKeyInfo ::= SEQUENCE {
 *      algorithm     OBJECT IDENTIFIER,
 *      deviceType    INTEGER,
 *      keyData       OCTET STRING }
 * </code>
 * </pre>
 * <p>See CRYPTO_encodeSymKey. There is also a helper routine:
 * CRYPTO_buildSymKeyEncoding.
 * <pre>
 * <code>
 * pInputInfo is NULL.
 * pOutputInfo is a pointer to an MSymOperatorBuffer struct.
 * </code>
 * </pre>
 * <p>To load encoded key data, call loadEncodedSymKey (MOC_SYM_OP_DECODE_KEY).
 */
#define MOC_SYM_OP_ENCODE_KEY             (MOC_SYM_OP_CODE+9)

/** Load key data. This might be raw, symmetric key data, or it could be a
 * hardware handle.
 * <p>The key data to load is the data returned during the call to GenerateKey
 * (MOC_SYM_OP_GENERATE_KEY). Do not use this opCode with encoded key data.
 * <pre>
 * <code>
 * pInputInfo is a pointer to MSymOperatorData containing the key data.
 * pOutputInfo is NULL
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_LOAD_KEY               (MOC_SYM_OP_CODE+10)

/** Decode the key following this ASN.1 definition:
 * <pre>
 * <code>
 *    SymmetricKeyInfo ::= SEQUENCE {
 *      algorithm     OBJECT IDENTIFIER,
 *      deviceType    INTEGER,
 *      keyData       OCTET STRING }
 * </code>
 * </pre>
 * <p>This loads the key data, but it must be the encoded key.
 * <p>See CRYPTO_loadEncodedSymKey. There is also a helper routine:
 * CRYPTO_parseSymKeyEncoding.
 * <pre>
 * <code>
 * pInputInfo is a pointer to a MSymOperatorData containing the encoded key.
 * pOutputInfo is NULL. The "output" is the actual key object that is loaded.
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_DECODE_KEY             (MOC_SYM_OP_CODE+11)

/** Return the block size, in bytes.
 * <p>For AES, this is 16, for a SHA-256 this is 64.
 * <pre>
 * <code>
 * pInputInfo is NULL
 * pOutputInfo is a pointer to a ubyte4
 * </code>
 * </pre>
 * <p>The Operator will go to the address and deposit the block size.
 */
#define MOC_SYM_OP_BLOCK_SIZE             (MOC_SYM_OP_CODE+12)

/** Initialize the Ctx for a new digest.
 * <pre>
 * <code>
 * pInputInfo is NULL
 * pOutputInfo is NULL
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_DIGEST_INIT            (MOC_SYM_OP_CODE+13)

/** <pre>
 * <code>
 * pInputInfo is a pointer to MSymOperatorData containing the data to digest.
 * pOutputInfo is NULL
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_DIGEST_UPDATE          (MOC_SYM_OP_CODE+14)

/** Finalize the digest process, computing the message digest. There might be
 * more data to digest, there might be no more.
 * <pre>
 * <code>
 * pInputInfo is a pointer to MSymOperatorData containing the data to digest.
 * pOutputInfo is a pointer to an MSymOperatorBuffer. The Operator is to fill
 * the pBuffer with the message digest and set *pOutputLen to the length.
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_DIGEST_FINAL            (MOC_SYM_OP_CODE+15)

/** Return the digest size.
 * <pre>
 * <code>
 * pInputInfo is NULL
 * pOutputInfo is a pointer to a ubyte4
 * </code>
 * </pre>
 * <p>The Operator will go to the address and deposit the digest size.
 */
#define MOC_SYM_OP_DIGEST_SIZE            (MOC_SYM_OP_CODE+16)

/** Initialize for the MAC operation. This is called after generating or loading
 * a key.
 * <pre>
 * <code>
 * pInputInfo is NULL
 * pOutputInfo is NULL
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_MAC_INIT               (MOC_SYM_OP_CODE+17)

/** <pre>
 * <code>
 * pInputInfo is a pointer to MSymOperatorData containing the data to mac.
 * pOutputInfo is NULL
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_MAC_UPDATE             (MOC_SYM_OP_CODE+18)

/** Finalize the MAC process, computing the checksum. There might be more data to
 * mac, there might be no more.
 * <pre>
 * <code>
 * pInputInfo is a pointer to MSymOperatorData containing the data to mac.
 * pOutputInfo is a pointer to an MSymOperatorBuffer. The Operator is to fill
 * the pBuffer with the Mac and set *pOutputLen to the length.
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_MAC_FINAL              (MOC_SYM_OP_CODE+19)

/** After you generate or load a key, call Init to start the process.
 * <pre>
 * <code>
 * pInputInfo is NULL
 * pOutputInfo is NULL
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_ENCRYPT_INIT           (MOC_SYM_OP_CODE+20)

/** After you generate or load a key, call Init to start the process.
 * <pre>
 * <code>
 * pInputInfo is NULL
 * pOutputInfo is NULL
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_DECRYPT_INIT           (MOC_SYM_OP_CODE+21)

/** Encrypt as much of the data as you can. This might be the first data, it
 * might be picking up where a previous call left off.
 * <pre>
 * <code>
 * pInputInfo is a pointer to MSymOperatorData containing the data to encrypt.
 * pOutputInfo is a pointer to MSymOperatorBuffer containing the buffer into
 * which the output will be placed.
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_ENCRYPT_UPDATE         (MOC_SYM_OP_CODE+22)

/** Decrypt as much of the data as you can. This might be the first data, it
 * might be picking up where a previous call left off.
 * <pre>
 * <code>
 * pInputInfo is a pointer to MSymOperatorData containing the data to encrypt.
 * pOutputInfo is a pointer to MSymOperatorBuffer containing the buffer into
 * which the output will be placed.
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_DECRYPT_UPDATE         (MOC_SYM_OP_CODE+23)

/** Finish encrypting, applying padding if necessary, computing a checksum if
 * part of the algorithm, verify the total input length.
 * <pre>
 * <code>
 * pInputInfo is a pointer to MSymOperatorData containing any data to encrypt
 * (there might be none).
 * pOutputInfo is a pointer to MSymOperatorBuffer containing the buffer into
 * which the output will be placed.
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_ENCRYPT_FINAL          (MOC_SYM_OP_CODE+24)

/** Finish decrypting, stripping padding if necessary, verifying a checksum if
 * part of the algorithm, verify the total input length.
 * <pre>
 * <code>
 * pInputInfo is a pointer to MSymOperatorData containing any data to encrypt
 * (there might be none).
 * pOutputInfo is a pointer to MSymOperatorBuffer containing the buffer into
 * which the output will be placed.
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_DECRYPT_FINAL          (MOC_SYM_OP_CODE+25)

/** Update an operators associated data.
 * <pre>
 * <code>
 * pInputInfo is a pointer to an implementation dependent operator data structure.
 * pOutputInfo is NULL.
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_UPDATE_OP_DATA         (MOC_SYM_OP_CODE+26)

/** Determine what type of seed operation a random object supports.
 * Possible return values are MOC_SYM_RAND_SEED_TYPE_NONE,
 * MOC_SYM_RAND_SEED_TYPE_DIRECT, MOC_SYM_RAND_SEED_TYPE_CALLBACK,
 * or MOC_SYM_RAND_SEED_TYPE_INTERNAL.
 * <pre>
 * <code>
 * pInputInfo is NULL.
 * pOutputInfo is a pointer to an ubyte4 indicating the type of seed supported.
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_RAND_GET_SEED_TYPE     (MOC_SYM_OP_CODE+27)

/** Derive a symmetric key.
 * <pre>
 * <code>
 * pInputInfo is a pointer to optional associated data.
 * pOutputInfo is a pointer to MSymOperatorBuffer containing the buffer into
 * which the output will be placed.
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_DERIVE_KEY             (MOC_SYM_OP_CODE+28)

/** Use an underlying block cipher to encrypt a single block of data. This op
 * code was designed specifically for AES key wrapping, it is for encrypting a
 * single block of data using raw ECB mode regardless of the operator mode. The
 * AES key wrapping algorithm requires a raw ECB computation, so to use an
 * operator with a different AES mode (CBC, CTR, etc) for key wrapping this op
 * code must be implemented to encrypt one block using raw AES-ECB.
 * <pre>
 * <code>
 * pInputInfo is a pointer to one block of data to be encrypted.
 * pOutputInfo is a pointer to the location that will recieve the encrypted
 *             block.
 * </code>
 * </pre>
 *
 * Note this op code takes no length arguments, the input and output will be
 * exactly one block. It is the callers responsibility to ensure that the input
 * and output buffers are large enough.
 */
#define MOC_SYM_OP_ENCRYPT_BLOCK          (MOC_SYM_OP_CODE+29)

/** Use an underlying block cipher to decrypt a single block of data. This op
 * code was designed specifically for AES key wrapping, it is for decrypting a
 * single block of data using raw ECB mode regardless of the operator mode. The
 * AES key wrapping algorithm requires a raw ECB computation, so to use an
 * operator with a different AES mode (CBC, CTR, etc) for key wrapping this op
 * code must be implemented to decrypt one block using raw AES-ECB.
 * <pre>
 * <code>
 * pInputInfo  is a pointer to one block of data to be decrypted.
 * pOutputInfo is a pointer to the location that will recieve the decrypted
 *             block.
 * </code>
 * </pre>
 *
 * Note this op code takes no length arguments, the input and output will be
 * exactly one block. It is the callers responsibility to ensure that the input
 * and output buffers are large enough.
 */
#define MOC_SYM_OP_DECRYPT_BLOCK          (MOC_SYM_OP_CODE+30)

/** Retrieve the size of the key contained in a MocSymCtx object.
 * <pre>
 * <code>
 * pInputInfo is NULL.
 * pOutputInfo is pointer to a ubyte4.
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_GET_KEY_SIZE           (MOC_SYM_OP_CODE+31)

/** This operation will clone the object and create an exact copy of it. It will
 * perform a deep copy on the underlying data.
 * <pre>
 * <code>
 * pInputInfo is NULL.
 * pOutputInfo is pointer to the MocSymCtx that the data will be copied over too
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_CLONE                  (MOC_SYM_OP_CODE+32)

/** Use this op code to reseed a random operator. Note this is not used to
 * perform the initial seeding, use MOC_SYM_OP_SEED_RANDOM instead.
 * <pre>
 * <code>
 * pInputInfo is a pointer to a MRandomReseedInfo containing the reseed info.
 * pOutputInfo is NULL
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_RESEED_RANDOM            (MOC_SYM_OP_CODE+33)

/** Use this op code get operator defined data.
 *
 * <pre>
 * <code>
 * pInputInfo is NULL.
 * pOutputInfo is Pointer to an object that is defined by the operator
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_GET_OP_DATA            (MOC_SYM_OP_CODE+34)

/** Initialize the Ctx for a new digest with custom initial constants.
 * <pre>
 * <code>
 * pInputInfo is a pointer to the structure containing the initial constants.
 * pOutputInfo is NULL
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_DIGEST_INIT_CUSTOM     (MOC_SYM_OP_CODE+35)

/** Use this op code to perform a raw transform on a block of data
 * with variable initial conditions. For example this may be a sha
 * transform with different initial constants.
 *
 * <pre>
 * <code>
 * pInputInfo is a pointer to MSymOperatorData containing the data to transform.
 * pOutputInfo is a pointer to MSymOperatorBuffer containing the buffer into
 * which the output will be placed.
 * </code>
 * </pre>
 */
#define MOC_SYM_OP_DO_RAW_TRANSFORM       (MOC_SYM_OP_CODE+36)

/** Generate a new symmetric key.
 * <pre>
 * <code>
 * pInputInfo is a pointer to an MSymKeyGenInfoEx struct containing a
 * rngFun, its argument, and the key size in bits.
 * pOutputInfo is a pointer to an MSymOperatorBuffer struct.
 * </code>
 * </pre>
 * <p>Place the resulting key data into the output info. This might be the raw
 * key data, it might be a hardware handle.
 */
#define MOC_SYM_OP_GENERATE_KEY_EX           (MOC_SYM_OP_CODE+37)

typedef ubyte4 symOperation;

/**
 * These are the possible state values for a moc sym context
 */
#define CTX_STATE_CREATE   1
#define CTX_STATE_INIT     2
#define CTX_STATE_UPDATE   3
#define CTX_STATE_FINAL    4

/* A MocSymContext is a struct that holds an implementation of some algorithm.
 * This includes an Operator function and any info the Operator needs in
 * performing its operations. This will likely be a hardware handle, an init
 * vector, key data, and so on.
 * <p>The localType contains information about the object. Look at the
 * MOC_LOCAL_TYPE_ values defined below. They let anyone operating on the object
 * to know something about it, such as algorithm, hardware/software, and so on.
 * <p>If you build your own Operator, look at what bits are defined that describe
 * your code.
 * <p>You must supply the Operator function. See the documentation for
 * MSymOperator for information on this function pointer.
 * <p>The Mocana API will keep track ot the state field.
 */
typedef struct MocSymContext
{
  ubyte4         localType;
  MSymOperator   SymOperator;
  void          *pLocalData;
  ubyte          state;
} MocSymContext;

/* These are the definitions of the values that can be used to build a localType
 * in a MocSymContext or MocAsymmetricKey.
 *
 * The localType allows someone to learn a little about the object. For example,
 * if someone has an object, and it is supposed to be SHA-256, check out the
 * algorithm bits. Is the algorithm SHA-256? Maybe it's a software
 * implementation, maybe it's hardware. For a particular query it doesn't matter,
 * all someone wants to know is if the object is SHA-256. Or maybe the caller
 * just wants to know that the object performs message digest operations, it
 * doesn't matter which algorithm.
 *
 * When building an Operator (MSymOperator or MKeyOperator), build a localType
 * based on the algorithm and implementation. Each bit or set of bits is used to
 * describe an aspect of the implementation.
 *
 * Note that this value might not describe everything about the object. But this
 * field is not designed to completely describe the object, but describe some of
 * the most important characteristics.
 *
 * Note also that this is not a bit field. Each set of bits has a particular
 * purpose. There should be a mask for a set of bits, which allow you to isolate
 * those bits that are concerned with some aspect of the object, then compare the
 * result to a set of possible values (e.g. a switch statement). There are some
 * bit sets that consist of only one bit, so it is equivalent to a bit field, but
 * in general, a set of bits describe a particular aspect and among that set are
 * possible values that are not bit fields.
 *
 *  0x80000000  unused
 *  0x40000000  unused
 *  0x20000000  unused
 *
 *  If this bit is set, then Mocana wrote the Operator. If you are not working
 *  for Mocana and you write an Operator, create the localType without setting
 *  this bit.
 *
 *  0x10000000  MOCANA
 *
 *  These bits are used to specify whether the object is a symmetric (MocSymCtx),
 *  asymmetric (MocAsymKey), a software implmentation or hardware or HSM.
 *  A flag of HW generally means hardware accelerator. The key data is the same as
 *  with a software implementation.
 *  A flag of HSM means the key is a token, not the raw data.
 *  The symmetric and asymmetric flags are defined here so that we can keep track
 *  of them in one place, so that we don't accidentally reuse bits.
 *  Both a MocAsymKey and MocSymCtx have a ubyte4 as the first element, so it is
 *  possible to look at an object and determine if it is Asym or Sym.
 *  Note that an Operator will be two values: sym and sw, or asym and hw, or so
 *  on.
 *
 *  0x0f800000  SYM, ASYM, SW, HW, HSM
 *
 *  0x00400000  unused
 *
 *  We reserve these bits in case we want to specify the name of the hardware
 *  vendor. This is not the name of the device, but rather the hardware vendor.
 *  For example, Acme might make an accelerator chip, but that chip is on version
 *  8 or there are multiple "sizes", or maybe Acme makes one accelerator that
 *  performs AES only, and another that performs AES and RSA. It doesn't matter,
 *  there is only one value for Acme. This is 5 bits, so there is room for 31
 *  vendors. We currently don't use the 00400000 bit, so if we end up needing
 *  more than 31 vendors, we can use that bit to increase to 63.
 *
 *  0x003e0000  HW vendors
 *
 *  Do not use the bit 0x0001000 for symmetric loclTypes, it is reserved for the
 *  MocAsymKey.
 *
 *  0x00010000  asym
 *
 *  For Asymmetric keys, we reserve this bit to indicate public/private status.
 *  If the bit is set then it is a private key, else it is a public key.
 *
 *  0x00008000  public/private status
 *  0x00004000  unused
 *
 *  This set of bits is used to describe "compound" algorithms. These are
 *  algorithms that are used in conjunction with other algorithms. The other
 *  algorithms can be digests, padding schemes, or almost wnything else. For
 *  example, RSA will work with a padding scheme when encrypting and a digest
 *  when signing. AES works with a feedback mode.
 *
 *  0x00003f00  compound algs
 *
 *  This set of bits is used to describe "atomic" algorithms, those that are
 *  standalone, such as digests.
 *
 *  0x000000ff  algs
 */
#define MOC_LOCAL_TYPE_MOCANA           0x10000000
#define MOC_LOCAL_TYPE_QS               0x40000000
#define MOC_LOCAL_TYPE_SYM              0x08000000
#define MOC_LOCAL_TYPE_ASYM             0x04000000
#define MOC_LOCAL_TYPE_SW               0x02000000
#define MOC_LOCAL_TYPE_HSM              0x01000000
#define MOC_LOCAL_TYPE_HW               0x00800000
#define MOC_LOCAL_TYPE_PRI              0x00008000

/* Which hardware? vendor name or hardware class.
 * Each vendor will have a number, this is not a bit field.
 */
#define MOC_LOCAL_TYPE_HW_MASK          0x003e0000
#define MOC_LOCAL_TYPE_TAP              0x00020000
#define MOC_LOCAL_TYPE_INTEL_NI         0x00040000

#define MOC_LOCAL_TYPE_ALG_MASK         0x000000ff
#define MOC_LOCAL_TYPE_ECB              0x00000001
#define MOC_LOCAL_TYPE_CBC              0x00000002
#define MOC_LOCAL_TYPE_CFB              0x00000003
#define MOC_LOCAL_TYPE_OFB              0x00000004
#define MOC_LOCAL_TYPE_CTR              0x00000005
#define MOC_LOCAL_TYPE_GCM              0x00000006
#define MOC_LOCAL_TYPE_ANSI_X9_63       0x00000007
#define MOC_LOCAL_TYPE_NIST_KDF         0x00000008
#define MOC_LOCAL_TYPE_CMAC             0x00000009
#define MOC_LOCAL_TYPE_XTS              0x0000000A
#define MOC_LOCAL_TYPE_CCM              0x0000000B
#define MOC_LOCAL_TYPE_EAX              0x0000000C
#define MOC_LOCAL_TYPE_POLY1305         0x0000000D
#define MOC_LOCAL_TYPE_HMAC_KDF         0x0000000E
#define MOC_LOCAL_TYPE_AES_XCBC         0x0000000F
#define MOC_LOCAL_TYPE_CFB1             0x00000010
#define MOC_LOCAL_TYPE_KEYWRAP          0x00000011

/* All digest algorithms must have the 0x10 bit set, and no other algorithm is
 * allowed to have this bit set.
 */
#define MOC_LOCAL_TYPE_DIGEST           0x00000070
#define MOC_LOCAL_TYPE_MD5              0x00000070
#define MOC_LOCAL_TYPE_SHA1             0x00000071
#define MOC_LOCAL_TYPE_SHA224           0x00000072
#define MOC_LOCAL_TYPE_SHA256           0x00000073
#define MOC_LOCAL_TYPE_SHA384           0x00000074
#define MOC_LOCAL_TYPE_SHA512           0x00000075
#define MOC_LOCAL_TYPE_MD2              0x00000076
#define MOC_LOCAL_TYPE_MD4              0x00000077
#define MOC_LOCAL_TYPE_BLAKE_2B         0x00000078
#define MOC_LOCAL_TYPE_BLAKE_2S         0x00000079
#define MOC_LOCAL_TYPE_SHA3             0x0000007a

/* RSA signing modes */
#define MOC_LOCAL_TYPE_P1_PAD           0x00000061
#define MOC_LOCAL_TYPE_OAEP             0x00000062
#define MOC_LOCAL_TYPE_PSS              0x00000063

/* ECC curves */
#define MOC_LOCAL_TYPE_P192             0x00000051
#define MOC_LOCAL_TYPE_P224             0x00000052
#define MOC_LOCAL_TYPE_P256             0x00000053
#define MOC_LOCAL_TYPE_P384             0x00000054
#define MOC_LOCAL_TYPE_P521             0x00000055
#define MOC_LOCAL_TYPE_X25519           0x00000056
#define MOC_LOCAL_TYPE_X448             0x00000057
#define MOC_LOCAL_TYPE_ED25519          0x00000058
#define MOC_LOCAL_TYPE_ED448            0x00000059

#define MOC_LOCAL_TYPE_RANDOM           0x00000080
#define MOC_LOCAL_TYPE_CTR_DRBG         0x00000081
#define MOC_LOCAL_TYPE_FIPS186          0x00000082
#define MOC_LOCAL_TYPE_DRBG_HASH        0x00000083

#define MOC_LOCAL_TYPE_PQC_MLKEM        0x00000091
#define MOC_LOCAL_TYPE_PQC_MLDSA        0x00000098
#define MOC_LOCAL_TYPE_PQC_FNDSA        0x00000099
#define MOC_LOCAL_TYPE_PQC_SLHDSA       0x0000009d

/* COM stands for combination, meaning it is an algorithm that is actually a
 * combination of algorithms, sucha as AES with feedback, or HMAC with digest.
 */
#define MOC_LOCAL_TYPE_COM_MASK         0x00003f00
#define MOC_LOCAL_TYPE_AES              0x00000100
#define MOC_LOCAL_TYPE_ARC2             0x00000200
#define MOC_LOCAL_TYPE_HMAC             0x00000300
#define MOC_LOCAL_TYPE_ARC4             0x00000400
#define MOC_LOCAL_TYPE_RC5              0x00000500
#define MOC_LOCAL_TYPE_AES_MAC          0x00000600
#define MOC_LOCAL_TYPE_KDF              0x00000700
#define MOC_LOCAL_TYPE_PKCS5_PBE        0x00000800
#define MOC_LOCAL_TYPE_TDES             0x00000900
#define MOC_LOCAL_TYPE_DES              0x00000A00
#define MOC_LOCAL_TYPE_CHACHA20         0x00000B00
#define MOC_LOCAL_TYPE_BLOWFISH         0x00000C00

/* RSA is a combination algorithm because encryption is always combined with a
 * padding scheme and signatures are combined with a digest.
 */
#define MOC_LOCAL_TYPE_RSA              0x00001100
#define MOC_LOCAL_TYPE_DSA              0x00001200
/* DH is a combination algorithm because how the shared secret is used is another
 * algorithm. For example, two parties generate the same shared secret, and use a
 * key derivation function on that shared secret, not the actual bytes
 * themselves, to build the symmetric key.
 */
#define MOC_LOCAL_TYPE_DH               0x00001300
/* An ECC key can perform ECDH or ECDSA, or even an EC Encryption (such as El
 * Gamal).
 */
#define MOC_LOCAL_TYPE_ECC              0x00001400
#define MOC_LOCAL_TYPE_QS_KEM           0x00001500
#define MOC_LOCAL_TYPE_QS_SIG           0x00001600

/* Flag for each digest algorithm */
#define MOC_DIGEST_ALG_MD2     ( MOC_LOCAL_TYPE_MD2 )
#define MOC_DIGEST_ALG_MD4     ( MOC_LOCAL_TYPE_MD4 )
#define MOC_DIGEST_ALG_MD5     ( MOC_LOCAL_TYPE_MD5 )
#define MOC_DIGEST_ALG_SHA1    ( MOC_LOCAL_TYPE_SHA1 )
#define MOC_DIGEST_ALG_SHA224  ( MOC_LOCAL_TYPE_SHA224 )
#define MOC_DIGEST_ALG_SHA256  ( MOC_LOCAL_TYPE_SHA256 )
#define MOC_DIGEST_ALG_SHA384  ( MOC_LOCAL_TYPE_SHA384 )
#define MOC_DIGEST_ALG_SHA512  ( MOC_LOCAL_TYPE_SHA512 )
#define MOC_DIGEST_ALG_SHA3    ( MOC_LOCAL_TYPE_SHA3 )

/* Flag for each symmetric algorithm */
#define MOC_SYM_ALG_AES \
    ( MOC_LOCAL_TYPE_AES )
#define MOC_SYM_ALG_AES_ECB \
    ( MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_ECB )
#define MOC_SYM_ALG_AES_CBC \
    ( MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_CBC )
#define MOC_SYM_ALG_AES_CFB \
    ( MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_CFB )
#define MOC_SYM_ALG_AES_CFB1 \
    ( MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_CFB1 )
#define MOC_SYM_ALG_AES_OFB \
    ( MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_OFB )
#define MOC_SYM_ALG_AES_CTR \
    ( MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_CTR )
#define MOC_SYM_ALG_AES_GCM \
    ( MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_GCM )
#define MOC_SYM_ALG_AES_XTS \
    ( MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_XTS )
#define MOC_SYM_ALG_AES_EAX \
    ( MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_EAX )
#define MOC_SYM_ALG_AES_CCM \
    ( MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_CCM )
#define MOC_SYM_ALG_DES \
    ( MOC_LOCAL_TYPE_DES )
#define MOC_SYM_ALG_DES_ECB \
    ( MOC_LOCAL_TYPE_DES | MOC_LOCAL_TYPE_ECB )
#define MOC_SYM_ALG_DES_CBC \
    ( MOC_LOCAL_TYPE_DES | MOC_LOCAL_TYPE_CBC )
#define MOC_SYM_ALG_TDES \
    ( MOC_LOCAL_TYPE_TDES )
#define MOC_SYM_ALG_TDES_ECB \
    ( MOC_LOCAL_TYPE_TDES | MOC_LOCAL_TYPE_ECB )
#define MOC_SYM_ALG_TDES_CBC \
    ( MOC_LOCAL_TYPE_TDES | MOC_LOCAL_TYPE_CBC )
#define MOC_SYM_ALG_ARC2_CBC \
    ( MOC_LOCAL_TYPE_ARC2 | MOC_LOCAL_TYPE_CBC )
#define MOC_SYM_ALG_ARC4 \
    ( MOC_LOCAL_TYPE_ARC4 )
#define MOC_SYM_ALG_RC5 \
    ( MOC_LOCAL_TYPE_RC5 )
#define MOC_SYM_ALG_RC5_ECB \
    ( MOC_LOCAL_TYPE_RC5 | MOC_LOCAL_TYPE_ECB )
#define MOC_SYM_ALG_RC5_CBC \
    ( MOC_LOCAL_TYPE_RC5 | MOC_LOCAL_TYPE_CBC )
#define MOC_SYM_ALG_HMAC \
    ( MOC_LOCAL_TYPE_HMAC )
#define MOC_SYM_ALG_AES_CMAC \
    ( MOC_LOCAL_TYPE_AES_MAC | MOC_LOCAL_TYPE_CMAC)
#define MOC_SYM_ALG_AES_XCBC \
    ( MOC_LOCAL_TYPE_AES_MAC | MOC_LOCAL_TYPE_AES_XCBC)
#define MOC_SYM_ALG_NIST_KDF \
    ( MOC_LOCAL_TYPE_KDF | MOC_LOCAL_TYPE_NIST_KDF)
#define MOC_SYM_ALG_HMAC_KDF \
    ( MOC_LOCAL_TYPE_KDF | MOC_LOCAL_TYPE_HMAC_KDF)
#define MOC_SYM_ALG_ANSI_X9_63_KDF \
    ( MOC_LOCAL_TYPE_KDF | MOC_LOCAL_TYPE_ANSI_X9_63)
#define MOC_SYM_ALG_POLY1305 \
    ( MOC_LOCAL_TYPE_POLY1305 )
#define MOC_SYM_ALG_CHACHA20 \
    ( MOC_LOCAL_TYPE_CHACHA20 )
#define MOC_SYM_ALG_CHACHAPOLY \
    ( MOC_LOCAL_TYPE_CHACHA20 | MOC_LOCAL_TYPE_POLY1305)
#define MOC_SYM_ALG_BLOWFISH_CBC \
    ( MOC_LOCAL_TYPE_BLOWFISH | MOC_LOCAL_TYPE_CBC)
#define MOC_SYM_ALG_AES_KW \
    ( MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_KEYWRAP)

#define MOC_SYM_ALG_BLAKE_2B ( MOC_LOCAL_TYPE_BLAKE_2B )
#define MOC_SYM_ALG_BLAKE_2S ( MOC_LOCAL_TYPE_BLAKE_2S )

#define MOC_SYM_ALG_PKCS5_PBE \
    ( MOC_LOCAL_TYPE_PKCS5_PBE )
    
/* Flag for each random algorithm */
#define MOC_RAND_ALG_CTR_DRBG_AES \
    ( MOC_LOCAL_TYPE_AES | MOC_LOCAL_TYPE_CTR_DRBG)

#define MOC_RAND_ALG_NIST_DRBG_HASH \
    (MOC_LOCAL_TYPE_DRBG_HASH)

#define MOC_RAND_ALG_FIPS186 \
    (MOC_LOCAL_TYPE_FIPS186)

/* Global list defining the symmetric algorithms that CAP supports */
#define MOC_NUM_SUPPORTED_SYM_ALGOS 46
MOC_EXTERN_CAPSYM_H const ubyte4 pSupportedSymAlgos[MOC_NUM_SUPPORTED_SYM_ALGOS];

/** This struct contains a byte array and its length. This is for when the Mocana
 * code has to pass data to the Operator function.
 */
typedef struct
{
  ubyte    *pData;
  ubyte4    length;
} MSymOperatorData;

/** This struct contains an output buffer. It will contain a pointer to the
 * buffer, its size, and the address where the length can be deposited.
 * <p>If the pBuffer is NULL or bufferSize is 0, then *pOutputLen will be set to
 * the required size. If pBuffer is not NULL and bufferSize is not 0, but
 * bufferSize is too small, then *pOutputLen will be set to the required size.
 * <p>If pBuffer is not NULL and bufferSize is big enough, then *pOutputLen will
 * be set to the number of bytes placed into pBuffer.
 */
typedef struct
{
  ubyte    *pBuffer;
  ubyte4    bufferSize;
  ubyte4   *pOutputLen;
} MSymOperatorBuffer;

/** This data struct is used to pass an Operator or array of Operators along with
 * associated info in one unit.
 * <p>Most likely the info will be NULL or a hardware handle.
 */
typedef struct
{
  MSymOperator   SymOperator;
  void          *pOperatorInfo;
} MSymOperatorAndInfo;

/* This is the struct used to pass in info about how to generate random numbers */
typedef struct
{
  RNGFun RngFun;
  void *pRngFunArg;
} MRandomGenInfo;

/** This is the struct used to pass in info about key generation.
 */
typedef struct
{
  MRandomGenInfo  *pRandInfo;
  ubyte4          keySizeBits;
} MSymKeyGenInfo;

typedef struct
{
  ubyte4 keySizeBits;
  void *pOperatorInfo;
} MSymKeyGenInfoEx;

typedef struct
{
  MocSymCtx *ppNewSymCtx;
} MSymKeyGenResult;

/** This is for when we have to pass an algorithm identifier and the list of
 * operators.
 * <p>When an Operator is called, the algId is passed in to see if it recognizes
 * it. The list is also passed in in case the Operator needs a supporting ctx.
 * <p>The currentIndex is the index of the Operator currently being queried, so
 * it knows not to look at that index for a supporting ctx.
 */
typedef struct
{
  ubyte                *pAlgId;
  ubyte4                algIdLen;
  MSymOperatorAndInfo  *pOperatorList;
  ubyte4                listCount;
  ubyte4                currentIndex;
} MSymOperatorAlgIdAndOpList;

/*------------------------------------------------------------*/

/** This function will allocate memory for a MocSymCtx struct (all fields init to
 * NULL/0), and then call the SymOperator function itself so it can build and set
 * the local data (localType), and set the Operator field.
 * <p>Call CRYPTO_freeMocSymCtx to free any memory. Note that freeMocSymCtx
 * will call on the KeyOperator to free any local data as well as freeing the
 * MocSymCtx struct.
 * <p>The caller passes in any associated info the Operator might need. If it
 * needs something, the Operator will likely need a further data such as an IV,
 * or a hardware handle, or a "helper" function (e.g. CBC or GCM for an AES Ctx,
 * or a digest Operator for an HMAC Ctx). However, it is also possible an
 * Operator needs nothing (pass in NULL), because the Operator itself will manage
 * any handles or supporting functions. Check the documentation for each Operator
 * to find out what, if any, info you need to pass in.
 * <p>The caller passes in the address of a MocSymCtx. The function will go to
 * that address and deposit the newly created context.
 * <p>For example.
 * <pre>
 * <code>
 *   MSTATUS status;
 *   MocSymCtx pNewCtx = NULL;
 *
 *   status = CRYPTO_createMocSymCtx (
 *     SomeHwOperator, NULL, pMocCtx, &pNewCtx);
 *   if (OK != status)
 *     goto exit;
 *
 *      . . .
 *
 * exit:
 *
 *   CRYPTO_freeMocSymCtx (&pNewCtx);
 * </code>
 * </pre>
 *
 * @param SymOperator The Operator function the ctx will use.
 * @param pOperatorInfo If the operator function needs some info in order to
 * work, pass it in here. See the documentation for each Operator to determine
 * what info it needs.
 * @param pMocCtx The MocCtx built during the call to MOCANA_initialize,
 * containing the lists of Operators the function will use to find one that can
 * do the work.
 * @param ppNewCtx The address where the function will deposit the newly
 * built MocSymCtx.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_createMocSymCtx (
  MSymOperator SymOperator,
  void *pOperatorInfo,
  MocCtx pMocCtx,
  MocSymCtx *ppNewCtx
  );

/** Create a new object based on the algorithm ID or object identifier.
 * <p>An algorithm identifier is defined as
 * <pre>
 * <code>
 *   SEQUENCE {
 *     algorithm  OBJECT IDENTIFIER,
 *     ANY defined by algorithm }
 * </code>
 * </pre>
 * <p>An OID is simply the byte array 06 len -object ID-
 * <p>A caller will pass in either an algId or an OID, and the function will call
 * each of the Operators in the MocCtx, asking if the algId or OID describes
 * their operations. If so, it will build the object using the information inside
 * the algId.
 * <p>Some Operators can only work with specific keys. For example, a
 * hardware-based Operator might be able to work with keys that are really
 * handles or tokens, not actual key data, and the handle must be from that
 * specific device. And of course, a software version can only deal with actual
 * key data, not keys that are really tokens. Hence, this function takes in an
 * optional keyy. You supply an algId and the key, the function will call on each
 * Operator to see if it can handle the algId and key combination. That way, if
 * you have a hardware-based Operator in your list (in the MocCtx) above a
 * software Operator, and the key is actual data, not a handle, the hardware
 * Operator will not accept the algId, even if it can perform the operation.
 * <p>The key data can be either the "raw" data (the same data that is returned
 * from a call to CRYPTO_generateSymKey) or the encoded key (returned by
 * CRYPTO_encodeSymKey). You must simply set the isEncoded flag to TRUE if the
 * key is encoded or FALSE if it is not.
 * <p>Note that if you pass in the key data to this function, you do not need to
 * call CRYPTO_loadSymKey or CRYPTO_loadEncodedSymKey.
 * <p>If you don't have the key data (either because the algId is for a digest or
 * some other construction that does not take a key, or you simply don't have the
 * key data), this function will simply build an object using the first Operator
 * that can handle the algId.
 * <p>Note that an algId might be for a pair of algorithms, such as HMAC with
 * SHA-256. In that case, the primary Operator (HMAC) will recognize the algId,
 * build itself and then find the supporting Operator from the list (inside the
 * MocCtx). For example, if the algId is for HMAC with SHA-256, an HMAC Operator
 * will recognize the algId, but the SHA-256 Operator will not. The HMAC Operator
 * will build itself, then search for the supporting SHA-256 Operator. That is,
 * the HMAC Operator will recognize which supporting algorithm it needs and
 * search the list of symmetric Operators for one that can perform the algorithm.
 * <p>The pMocCtx arg contains the list of Operators the application is willing
 * to support (see the documentation for MOCANA_initialize). The function will
 * cycle through that list to find an Operator that can perform the algorithm
 * described by the algId.
 *
 * @param pAlgId The algorithm ID or OID for which a ctx needs to be built.
 * @param algIdLen The length, in bytes, of the algId.
 * @param pKeyData The optional key data.
 * @param keyDataLen The length, in bytes, of the key data.
 * @param isEncoded TRUE if the key data is encoded (see CRYPTO_enocdeSymKey) or
 * FALSE if not.
 * @param pMocCtx The MocCtx built during the call to MOCANA_initialize,
 * containing the lists of Operators the function will use to find one that can
 * do the work.
 * @param ppNewCtx The address where the function will deposit the newly
 * built MocSymCtx.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_createMocSymCtxFromAlgId (
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte *pKeyData,
  ubyte4 keyDataLen,
  intBoolean isEncoded,
  MocCtx pMocCtx,
  MocSymCtx *ppNewCtx
  );

/** Free any memory and release any resources acquired in the creation and
 * operation of the MocSymCtx.
 * <p>Pass in the address of the Ctx. The function will go to that address and
 * expect to find a MocSymCtx. It will call on the Operator to free any resources
 * it acquired, it will free the MocSymCtx shell, and then place a NULL at the
 * address.
 *
 * @param ppSymCtx The address where the function will find the Ctx to free.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_freeMocSymCtx (
  MocSymCtx *ppSymCtx
  );

/** Create a randomContext using the given Operator.
 * <p>Throughout NanoCrypto, there are functions that use random numbers. For
 * example, look at CRYPTO_generateKeyPair. Generally, the caller will supply a
 * RNGFun and its argument. To use a randomContext in these situations you can
 * simply pass RANDOM_rngFun as the RNGFun and a randomContext as the argument.
 * There is a global random built during the call to MOCANA_initialize,
 * g_pRandomContext, but if you would like to use a different algorithm, or
 * if you have a hardware random number generator you would like to use, it is
 * possible to build a new provider.
 * <p>There are also functions that specifically seed a randomContext and
 * generate random bytes: RANDOM_addEntropyBit, RANDOM_numberGenerator
 * <p>To build a context that can be used wherever a randomContext is used,
 * call this function.
 * <p>The Operator will implement MOC_SYM_OP_CREATE, MOC_SYM_OP_FREE,
 * MOC_SYM_OP_SEED_RANDOM, and MOC_SYM_OP_GENERATE_RANDOM.
 *
 * @param SymOperator The Operator function to use.
 * @param pOperatorInfo If the operator function needs some info in order to
 * work, pass it in here. See the documentation for each Operator to determine
 * what info it needs.
 * @param pMocCtx The MocCtx built during the call to MOCANA_initialize,
 * containing the lists of Operators the function will use to find one that can
 * do the work.
 * @param ppMocRandom The address where the function will deposit the newly
 * built randomContext.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_createMocSymRandom (
  MSymOperator SymOperator,
  void *pOperatorInfo,
  MocCtx pMocCtx,
  randomContext **ppMocRandom
  );

/** Free a randomContext created by CRYPTO_createMocSymRandom.
 * <p>The caller passes the address of the randomContext, this function will go
 * to that address expecting to find a random. If so, it will free any memory or
 * other resources acquired during creation and usage of the context.
 * <p>NOTE! If the randomContext was not created by CRYPTO_createMocSymRandom,
 * then this function will NOT free the object. Instead, it will return an error.
 *
 * @param ppMocRandom The address where the function will find the context to
 * free.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_freeMocSymRandom (
  randomContext **ppMocRandom
  );

/**
 * This function performs the initial seeding of a randomContext. The caller
 * either provides operator specific information on how to collect entropy,
 * or directly provides entropy bytes to use in the seeding process. Note that
 * random operators may not support taking entropy bytes directly for seeding,
 * in those cases they likely take a function pointer for entropy collection.
 * See the operator documentation to determine how to properly seed the object.
 * Do not use this function to reseed an object, use CRYPTO_reseedRandomContext
 * instead.
 *
 * @param pRandom The context to seed.
 * @param pSeedInfo Pointer to an algorithm specific seeding structure.
 * @param pEntropyBytes A byte array containing the entropy material.
 * @param entropyLen The length, in bytes, of the entropy material.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_seedRandomContext (
  randomContext *pRandom,
  void *pSeedInfo,
  ubyte *pEntropyBytes,
  ubyte4 entropyLen
  );

/** Reseed a random context. The random context must have an underlying MocSymCtx,
 * this can be determined with RANDOM_isMocSymContext. This function is used to
 * reseed a random context previously instantiated using CRYPTO_seedRandomContext.
 * The entropy bytes may or may not be optional depending on the underlying
 * random operator. Use CRYPTO_getSeedType to determine what type of seed the
 * underlying implementation can work with. If the random operator supports
 * direct seeding, then the caller must provide the entropy bytes for the reseed.
 * If the seeding type is internal or using a callback, then the operator already
 * has a method to collect entropy. In those cases the entropy bytes are unused
 * even if provided.
 *
 * @param pRandom The random context to reseed.
 * @param pEntropyBytes If the provided random context supports direct seeding,
 * these bytes will be used as entropy input for the reseed. If the provided
 * random context does not support direct seeding, this parameter is unused.
 * @param entropyLen Length in bytes of the entropy material.
 * @param pAdditionalData The optional additional data that serves as extra
 * input into updating the internal state of the random object.
 * @param additionalDataLen Length in bytes of the additional data.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_reseedRandomContext (
  randomContext *pRandom,
  ubyte *pEntropyBytes,
  ubyte4 entropyLen,
  ubyte *pAdditionalData,
  ubyte4 additionalDataLen
  );

/** Get the type of seed that the provided random context supports. The random
 * context must of type MOC_RAND, this can be determined using
 * RANDOM_isMocSymContext. There are many ways to instantiate a random object
 * with seed material, typically by either providing entropy directly or by
 * providing a function pointer which is used for entropy collection. Some
 * random implementations may not support seeding at all, instead performing
 * all entropy collection internally without even giving the option for
 * entropy injection. This function will determine the type of seed that the
 * underlying random operator supports.
 *
 * @param pRandom The random context.
 * @param pSeedType Pointer to the ubyte4 which will recieve the seed type. Will
 * be MOC_SYM_RAND_SEED_TYPE_NONE, MOC_SYM_RAND_SEED_TYPE_DIRECT,
 * MOC_SYM_RAND_SEED_TYPE_CALLBACK, or MOC_SYM_RAND_SEED_TYPE_INTERNAL.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_getSeedType (
  randomContext *pRandom,
  ubyte4 *pSeedType
  );

/* Values for different types of seed support. Direct support means the random
 * object can take seed bytes directly. Callback means the random object takes
 * a function pointer that it uses for entropy collection. Internal means this
 * object knows how to get its own entropy and does not accept any external
 * entropy injection. */
#define MOC_SYM_RAND_SEED_TYPE_NONE     0
#define MOC_SYM_RAND_SEED_TYPE_DIRECT   1
#define MOC_SYM_RAND_SEED_TYPE_CALLBACK 2
#define MOC_SYM_RAND_SEED_TYPE_INTERNAL 3

/** Get the algorithm ID of the algorithm represented by the Ctx.
 * An AlgId is defined as
 * <pre>
 * <code>
 *   SEQUENCE {
 *     algorithm  OBJECT IDENTIFIER,
 *     ANY defined by algorithm }
 * </code>
 * </pre>
 * <p>The caller passes in a buffer into which the function will place the AlgId.
 * If the buffer is too small, the function will return ERR_BUFFER_TOO_SMALL and
 * set *pAlgIdLen to the required size.
 * <p>Note that the vast majority of symmetric alg Ids are shorter than 33 bytes.
 * If your buffer is 64 bytes long, it will almost certainly be big enough.
 *
 * @param pSymCtx The context built to perform some algorithm.
 * @param pAlgId The buffer into which the function will place the result.
 * @param bufferSize The size, in bytes, of the buffer.
 * @param pAlgIdLen The address where the function will deposit the length, in
 * bytes, of the algorithm Id.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_getAlgorithmId (
  MocSymCtx pSymCtx,
  ubyte *pAlgId,
  ubyte4 bufferSize,
  ubyte4 *pAlgIdLen
  );

/** This is the same as CRYPTO_getAlgorithmId, except it will allocate the output
 * buffer for you.
 * <p>If you would rather not pass in your own buffer and make sure the size is
 * big enough, call this function and it will allocate a buffer and return it.
 * <p>NOTE! You must call MOC_FREE on the returned buffer when you are done with
 * it.
 * <p>For example,
 * <pre>
 * <code>
 *   MSTATUS status;
 *   ubyte4 algIdLen;
 *   ubyte *pAlgId = NULL;
 *
 *   status = CRYPTO_getAlgorithmIdAlloc (
 *     pSymCtx, &pAlgId, &algIdLen);
 *   if (OK != status)
 *     goto exit;
 *      . . .
 * exit:
 *   MOC_FREE ((void **)&pAlgId);
 * </code>
 * </pre>
 *
 * @param pSymCtx The context built to perform some algorithm.
 * @param ppAlgId The address where the function will deposit a pointer to
 * allocated memory containing the result.
 * @param pAlgIdLen The address where the function will deposit the length, in
 * bytes, of the algorithm Id.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_getAlgorithmIdAlloc (
  MocSymCtx pSymCtx,
  ubyte **ppAlgId,
  ubyte4 *pAlgIdLen
  );

/** For algorithms that use keys, this will generate an appropriate key.
 * <p>The caller specifies the key size as measured in bits. The caller also
 * supplies an RNGFun and its argument. To use a randomContext with this
 * function, simply pass RANDOM_rngFun with the randomContext as the argument.
 * The  implementation might or might not use the random (e.g. a hardware
 * implementation might use its own random number generator), but it is there
 * in case it's needed.
 * <p>Note that generally only key lengths that are multiples of 8 are allowed.
 * <p>The output buffer, its size, and the output length are all optional. If
 * not present then the object will generate an internal key value and return
 * only a status indicator. If they are specified and valid, the object will
 * generate an internal key and copy the value to the specified buffer.
 * <p>Generally the key will be keySizeBits / 8 bytes long, but a hardware
 * implementation might return a token that could be shorter or longer than the
 * bit length indicates. Hence, the caller passes in the buffer size and the
 * function can return ERR_BUFFER_TOO_SMALL.
 * <p>Generally, a hardware key (token) is usable only by the same hardware
 * device.
 *
 * @param pSymCtx The context built to perform a symmetric algorithm that uses a
 * key.
 * @param RngFun A function pointer used to generate random bytes.
 * @param pRngFunArg The argument to the function pointer.
 * @param keySizeBits How big the generated key should be. For example, AES keys
 * are 128, 192, or 256 bits long.
 * @param pKeyBuf The optional buffer into which the function will place the
 * generated key (or token).
 * @param bufferSize The size, in bytes, of the key buffer.
 * @param pKeyLen The address where the function will deposit the length, in
 * bytes, of the key data. This will either be the required size, or else the
 * number of bytes placed into the output buffer.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_generateSymKey (
  MocSymCtx pSymCtx,
  RNGFun RngFun,
  void *pRngArg,
  ubyte4 keySizeBits,
  ubyte *pKeyBuf,
  ubyte4 bufferSize,
  ubyte4 *pKeyLen
  );

/** For algorithms that use keys, this will generate an appropriate key.
 * <p>The caller specifies the key size as measured in bits. The caller also
 * supplies any operator specific key generation arguments.
 * <p>Note that generally only key lengths that are multiples of 8 are allowed.
 * <p>Generally, a hardware key (token) is usable only by the same hardware
 * device.
 *
 * @param SymOperator The Operator function to use.
 * @param ppNewSymCtx The new context built to perform a symmetric algorithm that
 *                    uses a key.
 * @param pMocCtx     The MocCtx to use.
 * @param keySizeBits How big the generated key should be. For example, AES keys
 * @param pKeyGenArgs Operator specific key genration information.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_generateSymKeyEx (
  MSymOperator SymOperator,
  MocCtx pMocCtx,
  MocSymCtx *ppNewSymCtx,
  ubyte4 keySizeBits,
  void *pKeyGenArgs
  );

/** Load the given key into the ctx.
 * <p>The input is the key data returned by a call to CRYPTO_generateSymKey.
 * <p>This might be the actual key data, it might be a hardware token.
 * <p>You cannot load an encoded key using this function (see
 * CRYPTO_encodeSymKey).
 * <p>If you call CRYPTO_generateSymKey you will get a byte array. Use that byte
 * array in a later call to CRYPTO_loadSymKey.
 * <p>If all you have is the raw key data (maybe you obtained it from a PKCS 7
 * EnvelopedData message), you might not be able to use it with a hardware
 * implementation. So make sure your key and Ctx match.
 *
 * @param pSymCtx The ctx to load.
 * @param pKeyData The key data.
 * @param keyLen The length, in bytes, of the key.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_loadSymKey (
  MocSymCtx pSymCtx,
  ubyte *pKeyData,
  ubyte4 keyLen
  );

/** Return the symmetric key DER encoded. This is similar to serializing an
 * asymmetric key.
 * <p>There is not any standard that specifically creates an ASN.1 definition of
 * a symmetric key. There is RFC 6031 which discusses a CMS Symmetric Key Content
 * Type. But that does not define a way to encode a symmetric key as simply a
 * byte array containing identifying information.
 * <p>However, some applications might find it useful to store key data along
 * with identifying information. Probably the most important information to store
 * with a key is whether the key is raw data or a hardware key, and if a hardware
 * key, which hardware device. If the key data is for a hardware device, it might
 * also be useful to store the algorithm as well (AES, HMAC, etc.).
 * <p>For NanoCrypto, we have created this definition. It is tied to NanoTap, so
 * any new encoding implemented must be aware of the TAP_TYPE value.
 * <pre>
 * <code>
 *    SymmetricKeyInfo ::= SEQUENCE {
 *      algorithm     OBJECT IDENTIFIER,
 *      deviceType    INTEGER,
 *      keyData       OCTET STRING }
 * </code>
 * </pre>
 * <p>The algorithm will be the OID from the pSymCtx. It might be AES-CBC or
 * AES-GCM, or HMAC with SHA-256, and so on. Note that it is the OID only, not
 * the AlgId. Note also that even though an AES-CBC key can be used by an object
 * built to perform any other form of AES (such as AES-GCM or AES-OFB), the OID
 * will be for the algorithm of the object from which the key is extracted.
 * <p>If the algorithm has no OID, this function will not work. For example, if
 * you build an object to perform AES-CTR, you cannot get an encoded key. That's
 * because no standard has specified an OID for AES in counter mode (there is an
 * OID for AES-GCM which is Galois Counter Mode). Because there is no OID, the
 * function cannot build an encoding.
 * <p>The deviceType is the integer that specifies the type of device. Currently,
 * the only numbers allowed are defined as TAP_TYPEs. See
 * mss/crypto/tap/tap_common.h for a list of valid values for TAP_TYPE. For a
 * software implementation, the device value is 0.
 * <p>The keyData will be whatever the pSymCtx returns from the
 * CRYPTO_generateSymKey call. That is, if you look at the value of the OCTET
 * STRING, you might see the actual key data, you might see a token, or a key
 * blob of sorts.
 * <p>If you get the key data in this form, to set a new object with the data,
 * you must call CRYPTO_loadEncodedSymKey. The CRYPTO_loadSymKey
 *
 * @param pSymCtx The ctx with the key data.
 * @param pEncodedKeyBuf The buffer into which the function will place the
 * encoded key.
 * @param bufferSize The size, in bytes, of the key buffer.
 * @param pEncodedKeyLen The address where the function will deposit the length,
 * in bytes, of the key data. This will either be the required size, or else the
 * number of bytes placed into the output buffer.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_encodeSymKey (
  MocSymCtx pSymCtx,
  ubyte *pEncodedKeyBuf,
  ubyte4 bufferSize,
  ubyte4 *pEncodedKeyLen
  );

/** Load the given key into the ctx.
 * <p>The input is the key data returned by a call to CRYPTO_encodeSymKey.
 * <p>This might be the actual key data, it might be a hardware token.
 * <p>If you call CRYPTO_encodeSymKey, you will get a byte array. Use that byte
 * array in a later call to CRYPTO_loadEncodedSymKey.
 * <p>Note that the encoded key contains an OID. This will be the OID of the
 * algorithm of the object from which the key had been encoded. When you try to
 * load the encoded key, it will compare the OIDs. This might be an issue if you
 * want to use an "AES-CBC" key in "AES-GCM" (for example). Although an AES key
 * used in AES-CBC is valid for AES-GCM, this function will expect the OIDs to
 * match. So, for example, if you get an encoded key out of an AES-CBC object,
 * but then build an AES-GCM object and try to load the AES-CBC encoded key, the
 * function will return an error. It will likely not be a problem because if you
 * encrypt data using AES-CBC, you need to decrypt it using AES-CBC, so you will
 * likely never want to load an encoded key into an object built for another
 * algorithm.
 * <p>If the encoded key's OID or deviceType does not match what the pSymCtx is
 * built for, the function will return ERR_BAD_KEY. It is possible the function
 * returns other errors as well (such as ERR_NULL_POINTER).
 *
 * @param pSymCtx The ctx to load.
 * @param pEncodedKey The encoded key data.
 * @param encodedKeyLen The length, in bytes, of the encoded key.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_loadEncodedSymKey (
  MocSymCtx pSymCtx,
  ubyte *pEncodedKey,
  ubyte4 encodedKeyLen
  );

/** Build an object based on the type.
 * <p>NOTE there is a newer version of this function that is much easier to
 * use, so it is recommended to use CRYPTO_getMocSymObjectFromFlag instead.
 * <p>Every Operator will build an object with a particular local type. For
 * example, MAesCbcSwOperator builds an object with the following types.
 * <pre>
 * <code>
 *   MOC_LOCAL_TYPE_SYM
 *   MOC_LOCAL_TYPE_SW
 *   MOC_LOCAL_TYPE_AES
 *   MOC_LOCAL_TYPE_CBC
 * </code>
 * </pre>
 * <p>This is a collection of symmetric vs. asymmetric, SW vs. HW vs. HSM, a
 * combination algorithm, and a support algorithm.
 * <p>The caller passes in a localType, the function will search through the
 * Operators in the MocCtx for one that can perform the operation requested. It
 * will return the first one that can perform the algorithm requested.
 * <p>The caller does not need to pass in _SYM or _SW or _HW, only the
 * combination and supporting algorithms (see MOC_LOCAL_TYPE_COM_MASK and
 * MOC_LOCAL_TYPE_ALG_MASK).
 * <p>The function will look for only _SW and _HW Operators. An Operator that is
 * _HSM is one that has special requirements for keys, and this function is
 * really for building general-purpose objects, ones that work with software
 * keys. An Operator with _SW or _HW (accelerator) will work with software keys.
 * <p>The function will create a new MocSymCtx, it is the responsibility of the
 * caller to free it using CRYPTO_freeMocSymCtx.
 *
 * @param localType The OR of relevant types (MOC_LOCAL_TYPE_ values) secifying
 * the algorithm requested.
 * @param pMocCtx The MocCtx in which the function will search.
 * @param ppObj The address where the function will deposit the created object.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_getMocSymObjectFromType (
  ubyte4 localType,
  MocCtx pMocCtx,
  MocSymCtx *ppObj
  );

/** Build an object based on an algorithm flag.
 * <p>Say we have a MocCtx that has multiple implementations of a particular
 * algorithm like AES-CBC. The different implementations might be one for
 * FIPS approved, one for hardware and one for software, etc, like so:
 *   MAesCbcFipsOperator,
 *   MAesCbcHwOperator,
 *   MAesCbcSwOperator
 *
 * You could call this function and request a AES-CBC implementation and it
 * will retrieve it for you based on what is implemented for that particular
 * build. If the FIPS operator is in the library, then it will return you a
 * FIPS approved AES-CBC object. If it is not defined but there is an available
 * hardware implementation you will get back an object that performs AES-CBC in
 * hardware. If there is no FIPS operator nor a hardware implementation then
 * this function would return the software implementation of AES-CBC.
 * <p>The flag is one of the MOC_SYM_ALG_* flags defined in mocsym.h.
 * <p>You may optionally pass in the associated info for the object creation
 * call, if it is NULL then the associated info from the MocCtx will be used.
 *
 * @param flag One of the MOC_SYM_ALG_* flags indicating which algorithm is
 * being requested.
 * @param pMocCtx The MocCtx in which the function will search.
 * @param pOpInfo Optional associated info for the object creation. If it
 * is NULL then the associated info in the MocCtx will be used.
 * @param ppObj The address where the function will deposit the created object.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_getMocSymObjectFromFlag (
  ubyte4 flag,
  MocCtx pMocCtx,
  void *pOpInfo,
  MocSymCtx *ppObj
  );

/** Build an object based on an index into the MocCtx.
 * <p>Use this function if you know the exact index into the provided MocCtx
 * where the SymOperator will be found. This function will simply try to
 * create a MocSymCtx using the operator and its associated info from the
 * provided index.
 *
 * @param index The index into the MocCtx to use to select the operator to
 * be created.
 * @param pMocCtx The MocCtx in which the function will search.
 * @param pOperatorInfo The optional operator info to create the object with,
 * if NULL then the info from the list will be used.
 * @param ppObj The address where the function will deposit the created object.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_getMocSymObjectFromIndex (
  ubyte4 index,
  MocCtx pMocCtx,
  void *pOperatorInfo,
  MocSymCtx *ppObj
  );

/** Get a Symmetric Operator and its associated info from an index
 * into the provided MocCtx.
 *
 * @param index The index of the operator in the MocCtx to be retrieved.
 * @param pMocCtx The MocCtx to use for this operation.
 * @param ppSymOperator Pointer to the location that will recieve the
 * MSymOperator for the provided index.
 * @param ppOperatorInfo Pointer to the location that will recieve the
 * operator info for the provided index.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_getSymOperatorAndInfoFromIndex (
  ubyte4 index,
  MocCtx pMocCtx,
  MSymOperator *ppSymOperator,
  void **ppOperatorInfo
  );


/** Retrieve data from operator. The data is associated with an algorithm specific
 * structure, and is implemented by underlying algorithm.
 *
 * @param pCtx The MocCtx built during the call to MOCANA_initialize,
 * containing the lists of Operators the function will use to find one that can
 * do the work.
 * @param pSymCtx Pointer to operator context.
 * @param pOperatorData Pointer to the structure used to store operator data
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_getSymOperatorData (
  MocSymCtx pSymCtx,
  MocCtx    pCtx,
  MSymOperatorData *pOperatorData
  );

/** Build a new MocSymCtx based on the ht_ flag (digestAlg) and the array of
 * Operators (pSymOperators).
 * <p>If you have an algId, you can build a new object using
 * CRYPTO_createMocSymCtxFromAlgId. But if you have a flag instead of an algId,
 * you can call this function.
 * <p>The digestAlg will be one of the ht_ values defined in crypto.h (ht_sha1,
 * ht_sha256, etc.).
 * <p>The caller passes in a MocCtx which contains an array of Operators (as an
 * array of MSymOperatorAndInfo structs, each containing an Operator and
 * associated info), the function will run through the list, looking for an
 * Operator that can perform the desired digest. If one of them can perform the
 * operation, the function will build an object (MocSymCtx). It is the
 * responsibility of the caller to destroy that object using CRYPTO_freeMocSymCtx.
 * <p>If the function can find no Operator in the list that can perform the
 * algorithm requested, it will set *ppDigestObj to NULL and return
 * ERR_NOT_FOUND. In this case, the value at pIndex will have no meaning.
 *
 * @param digestAlg One of the ht_ flags, indicating which algorithm is requested.
 * @param pMocCtx The MocCtx built during the call to MOCANA_initialize,
 * containing the lists of Operators the function will use to find one that can
 * do the work.
 * @param ppDigestObj The address where the function will deposit the created
 * object.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_getDigestObjectFromFlag (
  ubyte4 digestAlg,
  MocCtx pMocCtx,
  MocSymCtx *ppDigestObj
  );

/** Retrieve the digest algorithm flag from the digest object.
 * <p>If you have a MocSym digest object, this function will retrieve the ht_*
 * flag associated with the object based on its algorithm.
 *
 * @param pDigestObj The digest object from which to retrieve the flag.
 * @param pDigestFlag Pointer to the location that will recieve the flag.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_getFlagFromDigestObj (
  MocSymCtx pDigestObj,
  ubyte4 *pDigestFlag
  );

/** Initialize for digesting.
 * <p>If the Ctx was built using an Operator that can perform a message digest,
 * this will call on the ctx to set it to the initial state. After calling
 * digestInit, you can call digestUpdate or digestFinal.
 *
 * @param pSymCtx The context built to perform a digest algorithm.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_digestInit (
  MocSymCtx pSymCtx
  );

/** Initialize for digesting with custom initial constants.
 *
 * @param pSymCtx The context built to perform a digest algorithm.
 * @param pInitialConstants Pointer to a structure containing the initial
 *             constants. Each operator is welcome to define the form
 *             of this structure.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_digestInitCustom (
  MocSymCtx pSymCtx,
  void *pInitialConstants
  );

/** Start or continue a digest process, adding the given data.
 * <p>If you have all the data to digest in one block, you can call digestFinal
 * without calling digestUpdate. But if the total data to digest is broken up into
 * different buffers, call Update for each buffer.
 * <p>Note that calling Update (A) and Update (B) is the same as calling Update
 * (A concatenate B).
 *
 * @param pSymCtx The context built to perform a digest algorithm.
 * @param pDataToDigest The data to process.
 * @param dataToDigestLen The length, in bytes, of the data to process.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_digestUpdate (
  MocSymCtx pSymCtx,
  ubyte *pDataToDigest,
  ubyte4 dataToDigestLen
  );

/** Finish a digest process, adding the given data and producing the result.
 * <p>If you have all the data to digest in one block, you can call digestFinal
 * without calling digestUpdate. But if the total data to digest is broken up into
 * different buffers, call Update for each buffer.
 * <p>Note that calling Update (A) and Final (B) is the same as calling Final (A
 * concatenate B).
 * <p>You can pass NULL for the pDataToDigest. If you pass all the data into the
 * object during a series of calls to Update and you have no more data, but want
 * the result, call Final with NULL inut.
 * <p>The caller passes in the output buffer and its size. If the buffer is not
 * big enough, the function will NOT process any data and simply return
 * ERR_BUFFER_TOO_SMALL and set pDigestLen to the required size.
 * <p>If ou don't know how big the buffer should be, call Final with a NULL
 * output buffer and 0 bufferSize, the function will set pDigestLen to the size
 * you need. Remember, Final does not process any data until it knows the output
 * buffer is big enough. So if you call Final with a buffer too small, and then
 * you call it again with a buffer big enough, you must pass any data to the
 * second call as well as the first.
 *
 * @param pSymCtx The context built to perform a digest algorithm.
 * @param pDataToDigest The data to process.
 * @param dataToDigestLen The length, in bytes, of the data to process.
 * @param pDigest The buffer into which the function will place the result.
 * @param bufferSize The size, in bytes, of the output buffer.
 * @param pDigestLen The address where the function will deposit the length, in
 * bytes, of the digest. This will either be the required size, or else the
 * number of bytes placed into the output buffer.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_digestFinal (
  MocSymCtx pSymCtx,
  ubyte *pDataToDigest,
  ubyte4 dataToDigestLen,
  ubyte *pDigest,
  ubyte4 bufferSize,
  ubyte4 *pDigestLen
  );

/** This is the same as CRYPTO_digestFinal, except that it returns the DER
 * encoding of the DigestInfo instead of the message digest data alone. The
 * DigestInfo is the input to the CRYPTO_asymSignDigestInfo and CRYPTO_asymVerifyDigestInfo functions
 * declared in mocasym.h.
 * <p>See the comments for CRYPTO_digestFinal for more information on what it
 * means to call Final.
 * <p>The DigestInfo is defined as
 * <pre>
 * <code>
 *   DigestInfo ::= SEQENCE {
 *     algId,
 *     OCTET STRING }
 * </code>
 * </pre>
 * <p>The length of the output of this function will likely be around 19 bytes
 * longer than the digest alone. But to know exactly how much longer, you should
 * call this function with a NULL output buffer. The function will return the
 * error BUFFER_TOO_SMALL and set pDigestInfoLen to ths size required.
 *
 * @param pSymCtx The context built to perform a digest algorithm.
 * @param pDataToDigest The data to process.
 * @param dataToDigestLen The length, in bytes, of the data to process.
 * @param pDigestInfo The buffer into which the function will place the result.
 * @param bufferSize The size, in bytes, of the output buffer.
 * @param pDigestInfoLen The address where the function will deposit the length,
 * in bytes, of the DigestInfo. This will either be the required size, or else
 * the number of bytes placed into the output buffer.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_digestInfoFinal (
  MocSymCtx pSymCtx,
  ubyte *pDataToDigest,
  ubyte4 dataToDigestLen,
  ubyte *pDigestInfo,
  ubyte4 bufferSize,
  ubyte4 *pDigestInfoLen
  );

/* The longest DigestInfo supported by NanoCrypto is this long.
 */
#define MOC_MAX_DIGEST_INFO_LEN  83

/** Initialize for a MAC operation (e.g. HMAC, AES-MAC).
 * <p>If the Ctx was built using an Operator that can perform a MAC, this will
 * call on the ctx to set it to the initial state. After calling macInit, you can
 * call macUpdate or macFinal.
 * <p>You can only call macInit if you have generated or loaded a key. See
 * CRYPTO_generateSymKey and CRYPTO_loadSymKey. If you want to use the same ctx
 * you have used before, but with a different key, call generate or load again,
 * then init.
 *
 * @param pSymCtx The context built to perform the MAC algorithm.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_macInit (
  MocSymCtx pSymCtx
  );

/** Start or continue processing actual data to MAC.
 * <p>If you have all the data to mac in one block, you can call macFinal
 * without calling macUpdate. But if the total data to mac is broken up into
 * different buffers, call Update for each buffer.
 * <p>Note that calling Update (A) and Update (B) is the same as calling Update
 * (A concatenate B).
 *
 * @param pSymCtx The context built to perform a mac algorithm.
 * @param pDataToMac The data to process.
 * @param dataToMacLen The length, in bytes, of the data to process.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_macUpdate (
  MocSymCtx pSymCtx,
  ubyte *pDataToMac,
  ubyte4 dataToMacLen
  );

/** Finish a mac process, adding the given data and producing the result.
 * <p>If you have all the data to mac in one block, you can call macFinal
 * without calling macUpdate. But if the total data to mac is broken up into
 * different buffers, call Update for each buffer.
 * <p>Note that calling Update (A) and Final (B) is the same as calling Final (A
 * concatenate B).
 * <p>You can pass NULL for the pDataToMac. If you pass all the data into the
 * object during a series of calls to Update and you have no more data, but want
 * the result, call Final with NULL inut.
 * <p>The caller passes in the output buffer and its size. If the buffer is not
 * big enough, the function will NOT process any data and simply return
 * ERR_BUFFER_TOO_SMALL and set pMacLen to the required size.
 * <p>If ou don't know how big the buffer should be, call Final with a NULL
 * output buffer and 0 bufferSize, the function will set pMacLen to the size
 * you need. Remember, Final does not process any data until it knows the output
 * buffer is big enough. So if you call Final with a buffer too small, and then
 * you call it again with a buffer big enough, you must pass any data to the
 * second call as well as the first.
 *
 * @param pSymCtx The context built to perform a mac algorithm.
 * @param pDataToMac The data to process.
 * @param dataToMacLen The length, in bytes, of the data to process.
 * @param pMac The buffer into which the function will place the result.
 * @param bufferSize The size, in bytes, of the output buffer.
 * @param pMacLen The address where the function will deposit the length, in
 * bytes, of the mac. This will either be the required size, or else the
 * number of bytes placed into the output buffer.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_macFinal (
  MocSymCtx pSymCtx,
  ubyte *pDataToMac,
  ubyte4 dataToMacLen,
  ubyte *pMac,
  ubyte4 bufferSize,
  ubyte4 *pMacLen
  );

/** Use this value to indicate an operation is to encrypt.
 */
#define MOC_CIPHER_FLAG_ENCRYPT  1

/** Use this value to indicate an operation is to decrypt.
 */
#define MOC_CIPHER_FLAG_DECRYPT  0

/** Initialize for a cipher operation (e.g. AES-CBC encryption).
 * <p>If the Ctx was built using an Operator that can perform a Cipher, this will
 * call on the ctx to set it to the initial state. After calling cipherInit, you can
 * call cipherUpdate or cipherFinal.
 * <p>You can only call cipherInit if you have generated or loaded a key. See
 * CRYPTO_generateSymKey and CRYPTO_loadSymKey. If you want to use the same ctx
 * you have used before, but with a different key, call generate or load again,
 * then init.
 *
 * @param pSymCtx The context built to perform the encryption algorithm.
 * @param cipherFlag If MOC_CIPHER_FLAG_ENCRYPT, initialize for encryption, if
 * MOC_CIPHER_FLAG_DECRYPT, initialize for decryption.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_cipherInit (
  MocSymCtx pSymCtx,
  ubyte4 cipherFlag
  );

/** Start or continue processing actual data to encrypt or decrypt.
 * <p>If you have all the data to process in one block, you can call cipherFinal
 * without calling cipherUpdate. But if the total data to cipher is broken up into
 * different buffers, call Update for each buffer.
 * <p>Note that calling Update (A) and Update (B) is the same as calling Update
 * (A concatenate B).
 * <p>The caller passes in a flag indicating encryption or decryption. The ctx
 * was initialized to encrypt or decrypt, th function will verify that the
 * operation requested here is the operation it was initialized for.
 * <p>The caller supplies the output buffer. It should not be the same buffer as
 * the input. If the buffer is not big enough, the function will not process any
 * data, will set pProcessedData to the size required, and return
 * ERR_BUFFER_TOO_SMALL. If you don't know how big the output buffer needs to be,
 * call this function once with a NULL output buffer, get the size, allocate the
 * memory, and call again.
 * <p>The actual number of bytes returned might not be the same as the number of
 * input bytes. This is because a block cipher might not be able to operate on
 * all bytes because it can only operate on multiples of the block size, so
 * returns fewer bytes (saving leftovers in a local buffer). Or maybe it has
 * leftover bytes from a previous call and so operates on them plus the new
 * input, which might mean more output than inut. Or maybe it pads the input to
 * make sure it is a multiple of the block size, or it generates a MAC as well as
 * encrypts.
 * <p>It is possible the number of bytes required is more than the number of
 * bytes actually returned. This can happen because the function will not know
 * how big the output really is until it actuall performs the operation (for
 * example, when stripping padding). But it won't perform an operation until it
 * knows the buffer is big enough. Hence, the function will require a buffer that
 * is the maximum possible output size, perform the operation, then indicate the
 * actual number of bytes placed into the output buffer.
 * <p>It is even possible that no bytes are placed into the output buffer.
 *
 * @param pSymCtx The context built to perform a cipher algorithm.
 * @param cipherFlag If MOC_CIPHER_FLAG_ENCRYPT, encrypt the data, if
 * MOC_CIPHER_FLAG_DECRYPT, decrypt the data.
 * @param pDataToProcess The data to process.
 * @param dataToProcessLen The length, in bytes, of the data to process.
 * @param pProcessedData The buffer into which the processed data will be placed.
 * @param bufferSize The size, in bytes, of the output buffer.
 * @param pProcessedDataLen The address where the function will deposit the
 * processed length, the number of bytes placed into the output buffer.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_cipherUpdate (
  MocSymCtx pSymCtx,
  ubyte4 cipherFlag,
  ubyte *pDataToProcess,
  ubyte4 dataToProcessLen,
  ubyte *pProcessedData,
  ubyte4 bufferSize,
  ubyte4 *pProcessedDataLen
  );

/** Finish processing actual data to encrypt or decrypt.
 * <p>If you have all the data to process in one block, you can call cipherFinal
 * without calling cipherUpdate. But if the total data to cipher is broken up into
 * different buffers, call Update for each buffer.
 * <p>Note that calling Update (A) and Update (B) is the same as calling Update
 * (A concatenate B).
 * <p>The caller passes in a flag indicating encryption or decryption. The ctx
 * was initialized to encrypt or decrypt, th function will verify that the
 * operation requested here is the operation it was initialized for.
 * <p>The caller supplies the output buffer. It should not be the same buffer as
 * the input. If the buffer is not big enough, the function will not process any
 * data, will set pProcessedData to the size required, and return
 * ERR_BUFFER_TOO_SMALL. If you don't know how big the output buffer needs to be,
 * call this function once with a NULL output buffer, get the size, allocate the
 * memory, and call again.
 * <p>The actual number of bytes returned might not be the same as the number of
 * input bytes. This is because the Final operation might pad the input, unpad
 * the output, or append a MAC/checksum.
 * <p>It is possible the number of bytes required is more than the number of
 * bytes actually returned. This can happen because the function will not know
 * how big the output really is until it actuall performs the operation (for
 * example, when stripping padding). But it won't perform an operation until it
 * knows the buffer is big enough. Hence, the function will require a buffer that
 * is the maximum possible output size, perform the operation, then indicate the
 * actual number of bytes placed into the output buffer.
 *
 * @param pSymCtx The context built to perform a cipher algorithm.
 * @param cipherFlag If MOC_CIPHER_FLAG_ENCRYPT, encrypt the data, if
 * MOC_CIPHER_FLAG_DECRYPT, decrypt the data.
 * @param pDataToProcess The data to process.
 * @param dataToProcessLen The length, in bytes, of the data to process.
 * @param pProcessedData The buffer into which the processed data will be placed.
 * @param bufferSize The size, in bytes, of the output buffer.
 * @param pProcessedDataLen The address where the function will deposit the
 * processed length, the number of bytes placed into the output buffer.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_cipherFinal (
  MocSymCtx pSymCtx,
  ubyte4 cipherFlag,
  ubyte *pDataToProcess,
  ubyte4 dataToProcessLen,
  ubyte *pProcessedData,
  ubyte4 bufferSize,
  ubyte4 *pProcessedDataLen
  );

/** Creates a clone of a MocSymCtx from another MocSymCtx.
 * <p>This function is used to create a deep copy of a MocSymCtx. This will
 * create another MocSymCtx that the user must maintain and free themselves. The
 * primary use case for this operator will allow a digest operation to "split"
 * at any point in the operation. This means the user can create a digest
 * object, then start digesting data. Then at any point in the digest operation
 * they can create a clone object which can then start digesting other data.
 * <p>For example, if the user wants to digest A || B and A || C where A, B, and
 * C are arrays of data (|| denotes concatenation). The user can create a digest
 * context and call CRYPTO_digestUpdate on A. Then the user can create a clone
 * of the context and then each context can call CRYPTO_digestFinal on B and C.
 * This allows the user to reduce the amount of work the digest operator has to
 * do, because the A array does not have to be digested twice by two different
 * digest operators. The operation to digest A only has to be performed once.
 * <p>The user must free the context themselves by calling CRYPTO_freeMocSymCtx.
 *
 * @param pSymCtx The MocSymCtx that will be copied
 * @param ppNewCtx The location where the copied context will be stored
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_cloneMocSymCtx (
  MocSymCtx pSymCtx,
  MocSymCtx *ppNewCtx
  );

/** Derive a symmetric key.
 * <p>This function will use the provided operator and its associated info to
 * derive a key a place the resultant key data at the location pointed to by
 * pDerivedKey.
 *
 * @param pSymCtx         Pointer to an instantiated MocSymCtx that supports
 *                        key derivation operations.
 * @param pAssociatedInfo Pointer to operator dependent associated info. See the
 *                        documentation for the desired KDF operator for more info.
 * @param pDerivedKey     Pointer to the already allocated buffer that will
 *                        recieve the derived key data.
 * @param bufferSize      Size in bytes of the buffer that will recieve the
 *                        derived key data.
 * @param pDerivedKeyLen  Pointer to the location that recieves the size in
 *                        bytes of the derived key data.
 * @return                \c OK (0) if successful; otherwise a negative number error
 *                        code definition from merrors.h. To retrieve a string
 *                        containing an English text error identifier corresponding
 *                        to the function's returned error status, use
 *                        the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_deriveKey (
  MocSymCtx pSymCtx,
  void *pAssociatedInfo,
  ubyte *pDerivedKey,
  ubyte4 bufferSize,
  ubyte4 *pDerivedKeyLen
  );

/** Derive a symmetric key.
 * <p>This function will use the provided operator and its associated info to
 * allocate new space for the derived key, then derive the key and place the
 * result into the new buffer.
 *
 * @param pSymCtx         Pointer to an instantiated MocSymCtx that supports
 *                        key derivation operations.
 * @param pAssociatedInfo Pointer to operator dependent associated info. See the
 *                        documentation for the desired KDF operator for more info.
 * @param ppDerivedKey    Pointer to the pointer that will be allocated and then
 *                        recieve the derived key data.
 * @param pDerivedKeyLen  Pointer to the location that recieves the size in
 *                        bytes of the derived key data.
 * @return                \c OK (0) if successful; otherwise a negative number error
 *                        code definition from merrors.h. To retrieve a string
 *                        containing an English text error identifier corresponding
 *                        to the function's returned error status, use
 *                        the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_deriveKeyAlloc (
  MocSymCtx pSymCtx,
  void *pAssociatedInfo,
  ubyte **ppDerivedKey,
  ubyte4 *pDerivedKeyLen
  );

/* Flags to indicate the AES key wrapping implementation method */
#define MOC_AES_KEY_WRAP_NONE     0
#define MOC_AES_KEY_WRAP_RFC_3394 1
#define MOC_AES_KEY_WRAP_RFC_5649 2
#define MOC_AES_KEY_WRAP_DEFAULT MOC_AES_KEY_WRAP_RFC_5649

/**
 * Wrap a symmetric or asymmetric key with an AES key.
 * <p>This function will use the AES key within the MocSymCtx pointed to by
 * pSymCtx to wrap the input key using the specified AES key wrapping method.
 * <p>The wrapping key object (pSymCtx) MUST have the MOC_SYM_OP_ENCRYPT_BLOCK
 * op code implemented, this is used by the key wrapping algorithm to perform
 * a raw ECB encryption on a single block even if the AES object is for a
 * different mode (CBC, CTR, etc).
 * <p>The different wrapping types have to do largely with padding variations,
 * it is recommended to simply use MOC_AES_KEY_WRAP_DEFAULT.
 * <p>NOTE this function will allow the caller to wrap a key with one of
 * smaller cryptographic strength (ie wrapping a RSA 4096 with an AES 128). This
 * reduces the effective strength of the key to that of the wrapping key. It is
 * highly recommended that the caller always use a wrapping key with greater
 * comprable cryptographic strength than the key being wrapped. See NIST 800-57
 * for info on comprable key strengths.
 * <pre>
 * <code>
 *   MSTATUS status;
 *   ubyte4 wrappedKeyLen;
 *   ubyte *pWrappedKey = NULL;
 *   MocSymCtx pSymCtx = NULL;
 *   AsymmetricKey *pAsymKey = NULL;
 *
 *   // pSymCtx is initialized as 256-bit AES key
 *   // pAsymKey is initialized as 2048-bit RSA key
 *
 *   // Wrap the key
 *   status = CRYPTO_wrapKeyAlloc (
 *     pSymCtx, (void *)pAsymKey, FALSE, MOC_AES_KEY_WRAP_DEFAULT,
 *     &pWrappedKey, &wrappedKeyLen, NULL, NULL);
 *   if (OK != status)
 *     goto exit;
 *
 *   // Destroy the wrapped key when finished
 *   MOC_MEMSET_FREE(&pWrappedKey, wrappedKeyLen);
 * </code>
 * </pre>
 *
 * @param pSymCtx         Pointer to the MocSymCtx containing the AES key used
 *                        to wrap the input key. Must implement the
 *                        MOC_SYM_OP_ENCRYPT_BLOCK op code.
 * @param pKeyToBeWrapped Pointer to the key object being wrapped. Must be pointing
 *                        to either a AsymmetricKey or MocSymCtx object.
 * @param isSymKey        Boolean to indicate if the key being wrapped is symmetric.
 * @param wrapType        Flag to indicate which wrapping implementation is to
 *                        be used, must be one of { MOC_AES_KEY_WRAP_DEFAULT,
 *                        MOC_AES_KEY_WRAP_RFC_3394, MOC_AES_KEY_WRAP_RFC_5649 }
 * @param ppWrappedKey    Pointer that will be allocated and recieve the wrapped
 *                        key data.
 * @param pWrappedKeyLen  Pointer that will recieve the length in bytes of the
 *                        wrapped key material.
 * @param ppAlgId         Optional pointer to the buffer that will be allocated
 *                        and will recieve the algorithm identifier.
 * @param pAlgIdLen       Optional Pointer to the location that will receive
 *                        the length of the algorithm identifier in bytes.
 * @return                \c OK (0) if successful; otherwise a negative number
 *                        error code definition from merrors.h. To retrieve a
 *                        string containing an English text error identifier
 *                        corresponding to the function's returned error status,
 *                        use the \c DISPLAY_ERROR macro.
 *
 */
MOC_EXTERN MSTATUS CRYPTO_wrapKeyAlloc (
  MocSymCtx pSymCtx,
  void *pKeyToBeWrapped,
  intBoolean isSymKey,
  ubyte4 wrapType,
  ubyte **ppWrappedKey,
  ubyte4 *pWrappedKeyLen,
  ubyte **ppAlgId,
  ubyte4 *pAlgIdLen
  );

/**
 * Unwrap a symmetric or asymmetric key with an AES key.
 * <p>This function will use the AES key within the MocSymCtx pointed to by
 * pSymCtx to unwrap the input key into a new MocSymCtx object.
 * <p>The unwrapping key object (pSymCtx) MUST have the MOC_SYM_OP_DECRYPT_BLOCK
 * op code implemented, this is used by the key unwrapping algorithm to perform
 * a raw ECB decryption on a single block even if the AES object is for a
 * different mode (CBC, CTR, etc).
 * <p>Example of unwrapping an ECC P-256 key,
 * <pre>
 * <code>
 *   MSTATUS status;
 *   ubyte4 wrappedKeyLen;
 *   ubyte *pWrappedKey;
 *   MocSymCtx pAesCtx = NULL;
 *   AsymmetricKey *pNewKey;
 *
 *   // pAesCtx is initialized with a 256-bit AES key
 *   // pWrappedKey is populated with the data, wrappedKeyLen recieves length
 *
 *   status = CRYPTO_unwrapKey (
 *     pAesCtx, pWrappedKey, wrappedKeyLen, FALSE,
 *     pMocCtx, (void **)&pNewKey);
 *   if (OK != status)
 *     goto exit;
 * </code>
 * </pre>
 *
 * @param pSymCtx                Pointer to the MocSymCtx containing the AES key
 *                               to be used as the unwrapping key. Must implement
 *                               the MOC_SYM_OP_DECRYPT_BLOCK op code.
 * @param pWrappedKey            Pointer to the buffer containg the wrapped
 *                               key data.
 * @param wrappedKeyLen          Length of wrapped key data in bytes.
 * @param isSymKey               Boolean to indicate if the key being wrapped is symmetric.
 * @param pMocCtx                The MocCtx built during the call to
 *                               MOCANA_initialize containing the lists of
 *                               Operators the function will use to find one that
 *                               can do the work.
 * @param pSymOperatorAndInfo    Pointer to a single MSymOperatorAndInfo item
 *                               containing the info used to create the symmetric
 *                               object into which the key will be loaded. Only
 *                               used when unwrapping a symmetric key (isSymKey
 *                               is TRUE). This is the same Operator and Info
 *                               used if building the Operator array passed to
 *                               the MOCANA_initialize function.
 * @param ppUnwrappedKey         Double pointer to the location that will recieve
 *                               the unwrapped key object, either a MocSymCtx for
 *                               symmetric keys or an Asymmetric key for
 *                               unwrapping asymmetric keys.
 * @return                       \c OK (0) if successful; otherwise a negative number
 *                               error code definition from merrors.h. To retrieve a
 *                               string containing an English text error identifier
 *                               corresponding to the function's returned error status,
 *                               use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_unwrapKey (
  MocSymCtx pSymCtx,
  ubyte *pWrappedKey,
  ubyte4 wrappedKeyLen,
  intBoolean isSymKey,
  MocCtx pMocCtx,
  MSymOperatorAndInfo *pSymOperatorAndInfo,
  void **ppUnwrappedKey
  );

/** Update operator associated data for a MocSymCtx.
 * <p>This function is infrequently used to update the operator data for
 * a particular MocSym object. This is usually used to accomodate unique
 * situations or facilitate uncommon functionality. For example code using
 * this function, see the AES-GCM example code for creation by algorithm ID.
 *
 * @param pSymCtx    The context that will recieve the updated operator data.
 * @param pMocCtx The MocCtx built during the call to MOCANA_initialize.
 * @param pOperatorData Pointer to implementation dependent structure containing
 *                   the new associated info to update.
 *
 * @return           \c OK (0) if successful; otherwise a negative number error
 *                   code definition from merrors.h. To retrieve a string
 *                   containing an English text error identifier corresponding
 *                   to the function's returned error status, use
 *                   the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_updateSymOperatorData (
  MocSymCtx pSymCtx,
  MocCtx pMocCtx,
  void *pOperatorData
  );

/** Does a raw transform for a hash, mac, or cipher operation.
 * @param pSymCtx The context built for the raw transform.
 * @param pDataToProcess The data to process.
 * @param dataToProcessLen The length, in bytes, of the data to process.
 * @param pProcessedData The buffer into which the processed data will be placed.
 * @param bufferSize The size, in bytes, of the output buffer.
 * @param pProcessedDataLen The address where the function will deposit the
 * processed length, the number of bytes placed into the output buffer.
 *
 * @return           \c OK (0) if successful; otherwise a negative number error
 *                   code definition from merrors.h. To retrieve a string
 *                   containing an English text error identifier corresponding
 *                   to the function's returned error status, use
 *                   the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_doRawTransform (
  MocSymCtx pSymCtx,
  ubyte *pDataToProcess,
  ubyte4 dataToProcessLen,
  ubyte *pProcessedData,
  ubyte4 bufferSize,
  ubyte4 *pProcessedDataLen
  );

typedef struct
{
  ubyte *pInitVector;
  ubyte4 initVectorLen;
  intBoolean padding;
} MDesUpdateData;

typedef MDesUpdateData MTDesUpdateData;

/** The update structure for AES ECB, CBC, CFB, XTS, and OFB */
typedef struct
{
  ubyte *pInitVector;
  ubyte4 initVectorLen;
} MAesUpdateData;

/** The update structure for Blowfish, same as that for AES */
typedef MAesUpdateData MBlowfishUpdateData;

/** The update structure for AES-GCM */
typedef struct
{
  MSymOperatorData nonce;
  MSymOperatorData aad;
  ubyte4           tagLen;
} MAesGcmUpdateData;

/** The update structure for AES-CTR */
typedef struct
{
  MSymOperatorData nonce;
  MSymOperatorData iv;
  MSymOperatorData ctr;
  byteBoolean updateStreamOffset;
  ubyte streamOffset;

} MAesCtrUpdateData;

/** The update structure for ChaCha20 */
typedef struct
{
  MSymOperatorData nonce;
  ubyte4 counter;
  MSymOperatorData aad;

} MChaChaUpdateData;

/* Typedef for function pointer for getting entropy. */
typedef MSTATUS (*MGetEntropyFunc) (
  void *pCtx,
  ubyte *pBuffer,
  ubyte4 bufferLen
  );

/* Typedef for function pointer to get personalization string */
typedef ubyte* (*MGetPersoStrCallback) (
  ubyte4 *pLen
  );

/* A generic structure that all random operators expect when performing the
 * initial seeding. The caller provides an algorithm specific structure that
 * contains information used to perform the initial seed (such as entropy
 * callback or personalization data), or direct entropy bytes to use for
 * seeding, or both. Check the documentation for a random operator to determine
 * what structures to pass here. */
typedef struct
{
  void *pOperatorSeedInfo;
  ubyte *pEntropyMaterial;
  ubyte4 entropyMaterialLen;
} MRandomSeedInfo;

/* A generic structure that all random operators expect when performing a reseed.
 * The entropy material will only be used if the random operator supports direct
 * seeding, this can be determined using CRYPTO_getSeedType. If the operator does
 * not support direct seeding, it knows how to collect its own entropy so the
 * entropyBytes will be unused. */
typedef struct
{
  ubyte *pEntropyMaterial;
  ubyte4 entropyMaterialLen;
  ubyte *pAdditionalData;
  ubyte4 additionalDataLen;
} MRandomReseedInfo;

/* This is the seeding structure that all AES based CTR-DRBG operators expect
 * when performing the initial seed.
 * <p>Some operators may or may not support a version without a derivation function.
 * <p>The key length must be one of the valid AES key size (16, 24, 32)
 * <p>The entropy collection length is the number of entropy bytes to request
 * for the initial seed and each reseed.
 * <p>The function pointer for entropy collection is required by some operators,
 * typically either this is specified or entropy bytes are provided directly.
 * <p>The context for the entropy function, can be NULL.
 * <p>pCustom contains the personalization string. If the caller also wants to
 * specify a nonce it should come in as a single concatenated string of
 * (nonce || personalizationString)
 */
typedef struct
{
  ubyte4 useDf;
  ubyte4 keyLenBytes;
  ubyte4 entropyCollectLen;
  MGetEntropyFunc EntropyFunc;
  void *pEntropyCtx;
  ubyte *pCustom;
  ubyte4 customLen;
} MCtrDrbgAesSeedInfo;

/* This is the structure to use for custom sha1 initialization */
typedef struct
{
  ubyte4 pSha1Consts[5];

} MSha1InitData;

#ifdef __cplusplus
}
#endif

#endif /* __CAP_SYM_HEADER__ */
