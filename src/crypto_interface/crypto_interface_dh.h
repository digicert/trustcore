/*
 * crypto_interface_dh.h
 *
 * Cryptographic Interface header file for declaring DH functions.
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
@file       crypto_interface_dh.h
@brief      Cryptographic Interface header file for declaring DH functions.

@filedoc    crypto_interface_dh.h
*/
#ifndef __CRYPTO_INTERFACE_DH_HEADER__
#define __CRYPTO_INTERFACE_DH_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 @brief      Allocate and initialize a \c diffieHellmanContext structure.
 
 @details    This function allocates and initializes a \c diffieHellmanContext
             structure, which the NanoCrypto DH API uses to store information
             that defines a Diffie-Hellman context.
 
 The \c diffieHellmanContext returned by this function structure is empty of
 any context information. To supply the context information, select an
 appropriate generator and prime, compute a public value, and then compute a
 shared secret.
 
 @param  ppNewCtx On return, pointer to the address of an initialized
                  \c diffieHellmanContext structure that you can use to
                  store a Diffie-Hellman context. The structure does not
                  yet contain any context information.
 
 @param  pExtCtx  Extended Context for future use.
 
 @return          \c OK (0) if successful; otherwise a negative number
                  error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_allocateExt (
    diffieHellmanContext **ppNewCtx,
    void *pExtCtx
);


/**
 @brief      Allocate and initialize a \c diffieHellmanContext structure.
 
 @details    This function allocates and initializes a \c diffieHellmanContext
             structure, which the NanoCrypto DH API uses to store information
             that defines a Diffie-Hellman context.
 
 The \c diffieHellmanContext returned by this function structure is empty of
 any context information. To supply the context information, select an
 appropriate generator and prime, compute a public value, and then compute a
 shared secret.
 
 @param  ppNewCtx On return, pointer to the address of an initialized
                  \c diffieHellmanContext structure that you can use to
                  store a Diffie-Hellman context. The structure does not
                  yet contain any context information.
 
 @return          \c OK (0) if successful; otherwise a negative number
                  error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_allocate (
    diffieHellmanContext **ppNewCtx
    );


/**
 @brief      Allocate and initialize resources for a DH server.
 
 @details    This function is a convenience function that performs the
             following tasks that normally require separate calls to the
             NanoCrypto DH API:
 -# Picks a \e Generator value, which it stores  in \c diffieHellmanContext.
 -# Picks a <em>Large Prime</em> value, which it stores in \c diffieHellmanContext.
 -# Picks a <em>Private Key</em>, which it stores in \c diffieHellmanContext.
 -# Generates the <em>Public Key</em>, which it stores in \c diffieHellmanContext.
 
 @param  pRandomContext Pointer to a \c randomContext structure, which is
                        used internally to store the information needed to
                        manage the generation of random numbers. To allocate
                        the structure, call CRYPTO_createMocSymRandom(). To
                        release the memory of the structure, call
                        CRYPTO_freeMocSymRandom().
 @param  ppNewCtx       On return, pointer to address of allocated and partially
                        populated \c diffieHellmanContext structure. Before
                        you can use this structure to calculate the shared
                        secret, you must get the public key from the client
                        and store it in the \c dh_e member of this
                        structure. You can then call
                        CRYPTO_INTERFACE_DH_computeKeyExchangeEx() to compute the
                        shared secret.
 @param  groupNum       The group number of a pre-defined Diffie-Hellman group
                        which may be hardcoded into the underlying implemenation.
                        These may be the Oakley Prime Groups for example.
 @param  pExtCtx        Extended Context for future use.
 
 @return          \c OK (0) if successful; otherwise a negative number
                  error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_allocateServerExt (
    MOC_DH(hwAccelDescr hwAccelCtx)
    randomContext *pRandomContext,
    diffieHellmanContext **ppNewCtx,
    ubyte4 groupNum,
    void *pExtCtx
    );


/**
 @brief      Allocate and initialize resources for a DH server.
 
 @details    This function is a convenience function that performs the
             following tasks that normally require separate calls to the
             NanoCrypto DH API:
 -# Picks a \e Generator value, which it stores  in \c diffieHellmanContext.
 -# Picks a <em>Large Prime</em> value, which it stores in \c diffieHellmanContext.
 -# Picks a <em>Private Key</em>, which it stores in \c diffieHellmanContext.
 -# Generates the <em>Public Key</em>, which it stores in \c diffieHellmanContext.
 
 @param  pRandomContext Pointer to a \c randomContext structure, which is
                        used internally to store the information needed to
                        manage the generation of random numbers. To allocate
                        the structure, call CRYPTO_createMocSymRandom(). To
                        release the memory of the structure, call
                        CRYPTO_freeMocSymRandom().
 @param  ppNewCtx       On return, pointer to address of allocated and partially
                        populated \c diffieHellmanContext structure. Before
                        you can use this structure to calculate the shared
                        secret, you must get the public key from the client
                        and store it in the \c dh_e member of this
                        structure. You can then call
                        CRYPTO_INTERFACE_DH_computeKeyExchangeEx() to compute the
                        shared secret.
 @param  groupNum       The group number of a pre-defined Diffie-Hellman group
                        which may be hardcoded into the underlying implemenation.
                        These may be the Oakley Prime Groups for example.
 
 @return          \c OK (0) if successful; otherwise a negative number
                   error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_allocateServer (
    MOC_DH(hwAccelDescr hwAccelCtx)
    randomContext *pRandomContext,
    diffieHellmanContext **ppNewCtx,
    ubyte4 groupNum
    );


/**
 @brief      Allocate and initialize resources for a DH client.
 
 @details    This function is a convenience function that performs the
             following tasks that normally require separate calls to the
             NanoCrypto DH API:
 -# Allocates a \c diffieHellmanContext structure for the client.
 -# Chooses a <em>Large Prime</em> value, which it stores in \c
 diffieHellmanContext.
 -# Chooses a <em>Generator</em> value, which it stores in \c
 diffieHellmanContext.
 -# Chooses a private key for the client, which it stores in \c
 diffieHellmanContext. NOTE: depending on the underlying implementation
 the public key may also be calculated.
 
 @param  pRandomContext Pointer to a \c randomContext structure, which is
                        used internally to store the information needed to
                        manage the generation of random numbers. To allocate
                        the structure, call CRYPTO_createMocSymRandom(). To
                        release the memory of the structure, call
                        CRYPTO_freeMocSymRandom().
 @param  ppNewCtx       On return, pointer to address of allocated \c
                        diffieHellmanContext structure.
 @param  groupNum       The group number of a pre-defined Diffie-Hellman group
                        which may be hardcoded into the underlying implemenation.
                        These may be the Oakley Prime Groups for example.
 @param  pExtCtx        Extended Context for future use.
 
 @return          \c OK (0) if successful; otherwise a negative number
                  error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_allocateClientAuxExt (
    MOC_DH(hwAccelDescr hwAccelCtx)
    randomContext *pRandomContext,
    diffieHellmanContext **ppNewCtx,
    ubyte4 groupNum,
    void *pExtCtx
    );


/**
 @brief      Allocate and initialize resources for a DH client.
 
 @details    This function is a convenience function that performs the
             following tasks that normally require separate calls to the
             NanoCrypto DH API:
 -# Allocates a \c diffieHellmanContext structure for the client.
 -# Chooses a <em>Large Prime</em> value, which it stores in \c
 diffieHellmanContext.
 -# Chooses a <em>Generator</em> value, which it stores in \c
 diffieHellmanContext.
 -# Chooses a private key for the client, which it stores in \c
 diffieHellmanContext. NOTE: depending on the underlying implementation
 the public key may also be calculated.
 
 @param  pRandomContext Pointer to a \c randomContext structure, which is
                        used internally to store the information needed to
                        manage the generation of random numbers. To allocate
                        the structure, call CRYPTO_createMocSymRandom(). To
                        release the memory of the structure, call
                        CRYPTO_freeMocSymRandom().
 @param  ppNewCtx       On return, pointer to address of allocated \c
                        diffieHellmanContext structure.
 @param  groupNum       The group number of a pre-defined Diffie-Hellman group
                        which may be hardcoded into the underlying implemenation.
                        These may be the Oakley Prime Groups for example.
 
 @return          \c OK (0) if successful; otherwise a negative number
                  error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_allocateClientAux (
    MOC_DH(hwAccelDescr hwAccelCtx)
    randomContext *pRandomContext,
    diffieHellmanContext **ppNewCtx,
    ubyte4 groupNum
    );


/**
 @brief      Free the memory allocated for a \c diffieHellmanContext structure.
 
 @details    This function releases (frees) the memory allocated to a \c
             diffieHellmanContext structure.  If the structure contains memory
             from a pre-allocated memory queue, use the \p ppVlongQueue
             parameter to identify that queue and free (reallocate) that memory
             back to the queue. All other allocated memory is freed back to the
             heap.
 
 @param  ppDhCtx         Pointer to the \c diffieHellmanContext structure to
                         free. On return, this value is NULL.
 @param  ppVlongQueue    Pointer to the pre-allocated vlong memory queue
                         used for the DH calculations. If the \c
                         diffieHellmanContext structure contains memory
                         allocated from that queue, it is returned there. If
                         you did not use a pre-allocated memory queue, pass
                         in NULL.
 @param  pExtCtx         Extended Context for future use.
 
 @return          \c OK (0) if successful; otherwise a negative number
                  error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_freeDhContextExt (
    diffieHellmanContext **ppDhCtx,
    vlong **ppVlongQueue,
    void *pExtCtx
    );


/**
 @brief      Free the memory allocated for a \c diffieHellmanContext structure.
 
 @details    This function releases (frees) the memory allocated to a \c
             diffieHellmanContext structure.  If the structure contains memory
             from a pre-allocated memory queue, use the \p ppVlongQueue
             parameter to identify that queue and free (reallocate) that memory
             back to the queue. All other allocated memory is freed back to the
             heap.
 
 @param  ppDhCtx         Pointer to the \c diffieHellmanContext structure to
                         free. On return, this value is NULL.
 @param  ppVlongQueue    Pointer to the pre-allocated vlong memory queue
                         used for the DH calculations. If the \c
                         diffieHellmanContext structure contains memory
                         allocated from that queue, it is returned there. If
                         you did not use a pre-allocated memory queue, pass
                         in NULL.
 
 @return          \c OK (0) if successful; otherwise a negative number
                  error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_freeDhContext (
    diffieHellmanContext **ppDhCtx,
    vlong **ppVlongQueue
    );


/**
 * Sets the key parameters stored in pSrcTemplate in the pTargetCtx.
 * pSrcTemplate may hold a groupNum of a pre-defined Diffie-Hellman group,
 * or it may hold any combination of g, p, q, y, f. If a groupNum is non-zero
 * then only p and g will be set and the rest of the template will be ignored.
 * If groupNum is DH_GROUP_TBD (0) then whatever parameters g, p, q, y, f, that
 * are defined in the template, will be set in the pTargetCtx. Any already
 * existing parameters will be overwritten.
 *
 * @param pTargetCtx         Pointer to the context whose parameters will be set.
 * @param pSrcTemplate       Pointer to the template containing the parameters
 *                           to be set.
 * @param  pExtCtx           Extended Context for future use.
 *
 * @return                   \c OK (0) if successful, otherwise a negative number
 *                           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_setKeyParametersExt (
    MOC_DH(hwAccelDescr hwAccelCtx)
    diffieHellmanContext *pTargetCtx,
    MDhKeyTemplate *pSrcTemplate,
    void *pExtCtx
    );


/**
 * Sets the key parameters stored in pSrcTemplate in the pTargetCtx.
 * pSrcTemplate may hold a groupNum of a pre-defined Diffie-Hellman group,
 * or it may hold any combination of g, p, q, y, f. If a groupNum is non-zero
 * then only p and g will be set and the rest of the template will be ignored.
 * If groupNum is DH_GROUP_TBD (0) then whatever parameters g, p, q, y, f, that
 * are defined in the template, will be set in the pTargetCtx. Any already
 * existing parameters will be overwritten.
 *
 * @param pTargetCtx         Pointer to the context whose parameters will be set.
 * @param pSrcTemplate       Pointer to the template containing the parameters
 *                           to be set.
 *
 * @return                   \c OK (0) if successful, otherwise a negative number
 *                           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_setKeyParameters (
    MOC_DH(hwAccelDescr hwAccelCtx)
    diffieHellmanContext *pTargetCtx,
    MDhKeyTemplate *pSrcTemplate
    );


/**
 * For each parameter value g, p, q, y, f that is stored in the pSrcCtx, this
 * method will allocate space for it within pTargetTemplate, and copy it there as
 * a Big Endian byte array.
 *
 * @param pTargetTemplate    Pointer to the template that will hold the key
 *                           parameters in Big Endian byte array form.
 * @param pSrcCtx            Pointer to the context already holding the key
 *                           parameters.
 * @param keyType            one of MOC_GET_PRIVATE_KEY_DATA or
 *                           MOC_GET_PUBLIC_KEY_DATA.
 * @param pExtCtx            Extended Context for future use.
 *
 * @return                   \c OK (0) if successful, otherwise a negative number
 *                           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_getKeyParametersAllocExt (
    MOC_DH(hwAccelDescr hwAccelCtx)
    MDhKeyTemplate *pTargetTemplate,
    diffieHellmanContext *pSrcCtx,
    ubyte keyType,
    void *pExtCtx
    );


/**
 * For each parameter value g, p, q, y, f that is stored in the pSrcCtx, this
 * method will allocate space for it within pTargetTemplate, and copy it there as
 * a Big Endian byte array.
 *
 * @param pTargetTemplate    Pointer to the template that will hold the key
 *                           parameters in Big Endian byte array form.
 * @param pSrcCtx            Pointer to the context already holding the key
 *                           parameters.
 * @param keyType            one of MOC_GET_PRIVATE_KEY_DATA or
 *                           MOC_GET_PUBLIC_KEY_DATA.
 *
 * @return                   \c OK (0) if successful, otherwise a negative number
 *                           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_getKeyParametersAlloc (
    MOC_DH(hwAccelDescr hwAccelCtx)
    MDhKeyTemplate *pTargetTemplate,
    diffieHellmanContext *pSrcCtx,
    ubyte keyType
    );


/**
 * Zeros and frees each parameter stored in pTemplate.
 *
 * @param pCtx               Pointer to a context. This is not needed and may
 *                           be NULL.
 * @param pTemplate          Pointer to the template to be zeroed and freed.
 *
 * @param pExtCtx            Extended Context for future use.
 *
 * @return                   \c OK (0) if successful, otherwise a negative number
 *                           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_freeKeyTemplateExt (
    diffieHellmanContext *pCtx,
    MDhKeyTemplate *pTemplate,
    void *pExtCtx
    );


/**
 * Zeros and frees each parameter stored in pTemplate.
 *
 * @param pCtx               Pointer to a context. This is not needed and may
 *                           be NULL.
 * @param pTemplate          Pointer to the template to be zeroed and freed.
 *
 * @return                   \c OK (0) if successful, otherwise a negative number
 *                           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_freeKeyTemplate (
    diffieHellmanContext *pCtx,
    MDhKeyTemplate *pTemplate
    );


/**
 * This method generates a key pair (y,f) within a context that has already had
 * had the domain params p and g set.
 *
 * @param pCtx               Pointer to the context holding at least the domain
 *                           params p and g.
 * @param pRandomContext     Pointer to a random context.
 * @param numBytes           The number of bytes that a newly generated private
 *                           key will consist of.
 * @param pExtCtx            Extended Context for future use.
 *
 * @return                   \c OK (0) if successful, otherwise a negative number
 *                           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_generateKeyPairExt (
    MOC_DH(hwAccelDescr hwAccelCtx)
    diffieHellmanContext *pCtx,
    randomContext *pRandomContext,
    ubyte4 numBytes,
    void *pExtCtx
    );


/**
 * This method generates a key pair (y,f) within a context that has already had
 * had the domain params p and g set.
 *
 * @param pCtx               Pointer to the context holding at least the domain
 *                           params p and g.
 * @param pRandomContext     Pointer to a random context.
 * @param numBytes           The number of bytes that a newly generated private
 *                           key will consist of.
 *
 * @return                   \c OK (0) if successful, otherwise a negative number
 *                           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_generateKeyPair (
    MOC_DH(hwAccelDescr hwAccelCtx)
    diffieHellmanContext *pCtx,
    randomContext *pRandomContext,
    ubyte4 numBytes
    );


/**
 * This method will allocate a buffer and fill it with our public key in Big Endian
 * binary.
 *
 * @param pCtx               Pointer to the context holding a public key.
 * @param ppPublicKey        Pointer to a buffer that will be allocated and filled
 *                           with our public key in Big Endian binary.
 * @param pPublicKeyLen      Pointer to a ubyte4 that will be filled with the
 *                           length of the public key in bytes.
 * @param pExtCtx            Extended Context for future use.
 *
 * @return                   \c OK (0) if successful, otherwise a negative number
 *                           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_getPublicKeyExt (
    MOC_DH(hwAccelDescr hwAccelCtx)
    diffieHellmanContext *pCtx,
    ubyte **ppPublicKey,
    ubyte4 *pPublicKeyLen,
    void *pExtCtx
    );


/**
 * This method will allocate a buffer and fill it with our public key in Big Endian
 * binary.
 *
 * @param pCtx               Pointer to the context holding a public key.
 * @param ppPublicKey        Pointer to a buffer that will be allocated and filled
 *                           with our public key in Big Endian binary.
 * @param pPublicKeyLen      Pointer to a ubyte4 that will be filled with the
 *                           length of the public key in bytes.
 *
 * @return                   \c OK (0) if successful, otherwise a negative number
 *                           error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_getPublicKey (
    MOC_DH(hwAccelDescr hwAccelCtx)
    diffieHellmanContext *pCtx,
    ubyte **ppPublicKey,
    ubyte4 *pPublicKeyLen
    );


/**
 * Generates a shared secret from the domain parameters and our private key stored
 * in the context, and the other partys public key as passed in.
 *
 * @param pCtx                  Pointer to the context holding at least the domain
 *                              params p and g and our private key y.
 * @param pRandomContext        Pointer to a random Context. If non-NULL then
 *                              blinding will be done.
 * @param pOtherPartysPublicKey Pointer to the the other party's public key as
 *                              a Big Endian byte string.
 * @param publicKeyLen          Length in bytes of the other party's public key.
 * @param ppSharedSecret        Pointer to a buffer that will be allocated and
 *                              filled with the shared secret in Big Endian binary.
 * @param pSharedSecretLen      Pointer to a ubyte4 that will be filled with the
 *                              length of the shared secret in bytes.
 * @param pExtCtx               Extended Context for future use.
 *
 * @return                      \c OK (0) if successful, otherwise a negative number
 *                              error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_computeKeyExchangeExExt (
    MOC_DH(hwAccelDescr hwAccelCtx)
    diffieHellmanContext *pCtx,
    randomContext *pRandomContext,
    ubyte *pOtherPartysPublicKey,
    ubyte4 publicKeyLen,
    ubyte **ppSharedSecret,
    ubyte4 *pSharedSecretLen,
    void *pExtCtx
    );


/**
 * Generates a shared secret from the domain parameters and our private key stored
 * in the context, and the other partys public key as passed in.
 *
 * @param pCtx                  Pointer to the context holding at least the domain
 *                              params p and g and our private key y.
 * @param pRandomContext        Pointer to a random Context. If non-NULL then
 *                              blinding will be done.
 * @param pOtherPartysPublicKey Pointer to the the other party's public key as
 *                              a Big Endian byte string.
 * @param publicKeyLen          Length in bytes of the other party's public key.
 * @param ppSharedSecret        Pointer to a buffer that will be allocated and
 *                              filled with the shared secret in Big Endian binary.
 * @param pSharedSecretLen      Pointer to a ubyte4 that will be filled with the
 *                              length of the shared secret in bytes.
 *
 * @return                      \c OK (0) if successful, otherwise a negative number
 *                              error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_computeKeyExchangeEx (
    MOC_DH(hwAccelDescr hwAccelCtx)
    diffieHellmanContext *pCtx,
    randomContext *pRandomContext,
    ubyte *pOtherPartysPublicKey,
    ubyte4 publicKeyLen,
    ubyte **ppSharedSecret,
    ubyte4 *pSharedSecretLen
    );

/**
 * @brief   Generates a Diffie-Hellman shared secret via one of the major modes.
 *
 * @details Generates a Diffie-Hellman shared secret via one of the major modes.
 *          This method allocates a buffer to hold the secret. Be sure to FREE
 *          this buffer when done with it.
 *
 * @param mode                  One of the following macro values
 *                              + \c DH_HYBRID1
 *                              + \c MQV2
 *                              + \c DH_EPHEMERAL
 *                              + \c DH_HYBRID_ONE_FLOW_U
 *                              + \c DH_HYBRID_ONE_FLOW_V
 *                              + \c MQV1_U
 *                              + \c MQV2_V
 *                              + \c DH_ONE_FLOW_U
 *                              + \c DH_ONE_FLOW_V
 *                              + \c DH_STATIC                        
 *
 * @param pRandomContext        Pointer to a random Context. If non-NULL then
 *                              blinding will be done.
 * @param pStatic               Our private static key.                             
 * @param pEphemeral            Our private ephemeral key.
 * @param pOtherPartysStatic    The other party's static public key as an uncompressed form byte array.
 * @param otherStaticLen        The length of the uncompressed form static key byte array in bytes.  
 * @param pOtherPartysEphemeral The other party's ephemeral public key as an uncompressed form byte array.
 * @param otherEphemeralLen     The length of the uncompressed form ephemeral key byte array in bytes.  
 * @param ppSharedSecret        Pointer to the location of the newly allocated buffer that will
 *                              store the shared secret.
 * @param pSharedSecretLen      Contents will be set to the length of the shared secret in bytes.
 *
 * @return  \c OK (0) if successful, otherwise a negative number error
 *          code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_keyAgreementScheme(
    MOC_DH(hwAccelDescr hwAccelCtx)
    ubyte4 mode,
    randomContext *pRandomContext,
    diffieHellmanContext *pStatic, 
    diffieHellmanContext *pEphemeral, 
    ubyte *pOtherPartysStatic, 
    ubyte4 otherStaticLen,
    ubyte *pOtherPartysEphemeral,
    ubyte4 otherEphemeralLen,
    ubyte **ppSharedSecret,
    ubyte4 *pSharedSecretLen);

/**
 * @brief      Validates the Diffie-Hellman domain parameters.
 *
 * @details    Validates the Diffie-Hellman domain parameters. If a seed, counter,
 *             and hashType are provided it validates that the context contains
 *             primes P and Q generated via FIPS186-4, and that G is a valid
 *             generator. If the a seed and counter are not provided, it
 *             validates that P and G are one of the fixed safe prime groups.
 *
 * @ingroup    dh_functions
 *
 * @inc_file dh.h
 *
 * @param pFipsRngCtx   Optional. Pointer to a FIPS 186 RNG context.
 * @param pCtx          Pointer to a context containing a P, G, and (optional) Q to validate.
 * @param hashType      Optional. The hash algorithm used for generating P and Q. This is one
 *                      of the \c FFCHashType values...
 *                      FFC_sha1
 *                      FFC_sha224
 *                      FFC_sha256
 *                      FFC_sha384
 *                      FFC_sha512
 *
 * @param C             Optional. The counter value returned when P and Q were generated.
 * @param pSeed         Optional. The seed used for generating P and Q.
 * @param seedSize      The length of the seed in bytes.
 * @param pIsValid      Contents will be set to \c TRUE for a valid P and Q and \c FALSE if otherwise.
 * @param pPriKeyLen    For valid parameters, contents will be set to the minimum allowable
 *                      private key size in bytes.
 * @param ppVlongQueue  Optional pointer to a \c vlong queue.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @warning    Be sure to check for both a return status of OK and a pIsValid value of TRUE
 *             before accepting that a context has valid parameters.
 *
 * @funcdoc    dh.c
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_validateDomainParams(MOC_DH(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
                                                            diffieHellmanContext *pCtx, FFCHashType hashType, ubyte4 C,
                                                            ubyte *pSeed, ubyte4 seedSize, intBoolean *pIsValid, ubyte4 *pPriKeyLen, vlong **ppVlongQueue);

/**
 * @brief      Validates that the P and G domain parameters come from one of the pre
 *             approved safe prime groups.
 *
 * @details    Validates that the P and G domain parameters come from one of the pre
 *             approved safe prime groups.
 *
 * @ingroup    dh_functions
 *
 * @inc_file dh.h
 *
 * @param pCtx          Pointer to a context containing a P and G to validate.
 * @param pIsValid      Contents will be set to \c TRUE for a valid P and G and \c FALSE if otherwise.
 * @param pPriKeyLen    For a valid P and G, contents will be set to the minimum allowable
 *                      private key size in bytes.
 * @param ppVlongQueue  Optional pointer to a \c vlong queue.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @warning    Be sure to check for both a return status of OK and a pIsValid value of TRUE
 *             before accepting that a context has a valid P and G.
 *
 * @funcdoc    dh.c
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_verifySafePG(diffieHellmanContext *pCtx, intBoolean *pIsValid, ubyte4 *pPriKeyLen, vlong **ppVlongQueue);

/**
 * @brief      Verifies the domain parameters P and Q in a context come from the
 *             FIPS 186-4 algorithm.
 *
 * @details    Verifies the domain parameters P and Q in a comtext come from the
 *             FIPS 186-4 algorithm.
 *
 * @ingroup    dh_functions
 *
 * @inc_file dh.h
 *
 * @param pFipsRngCtx   Pointer to a FIPS 186 RNG context.
 * @param pCtx          Pointer to a context containing a P and Q to validate.
 * @param hashType      The hash algorithm used for generating P and Q. This is one
 *                      of the \c FFCHashType values...
 *                      FFC_sha1
 *                      FFC_sha224
 *                      FFC_sha256
 *                      FFC_sha384
 *                      FFC_sha512
 *
 * @param C             The counter value returned when P and Q were generated.
 * @param pSeed         The seed used for generating P and Q.
 * @param seedSize      The length of the seed in bytes.
 * @param pIsValid      Contents will be set to \c TRUE for a valid P and Q and \c FALSE if otherwise.
 * @param ppVlongQueue  Optional pointer to a \c vlong queue.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @warning    Be sure to check for both a return status of OK and a pIsValid value of TRUE
 *             before accepting that a context has a valid P and Q.
 *
 * @funcdoc    dh.c
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_verifyPQ_FIPS1864(MOC_DH(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
                                                         diffieHellmanContext *pCtx, FFCHashType hashType, ubyte4 C,
                                                         ubyte *pSeed, ubyte4 seedSize, intBoolean *pIsValid, vlong **ppVlongQueue);

/**
 * @brief      Verifies the domain parameter G is valid with respect to the P and Q
 *             parameters in a \c diffieHellmanContext.
 *
 * @details    Verifies the domain parameter G is valid with respect to the P and Q
 *             parameters in a \c diffieHellmanContext.
 *
 * @ingroup    dh_functions
 *
 * @inc_file dh.h
 *
 * @param pCtx         Pointer to a context containing a G, P and Q to validate.
 * @param pIsValid     Contents will be set to \c TRUE for a valid G and \c FALSE if otherwise.
 * @param ppVlongQueue Optional pointer to a \c vlong queue.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @warning    Be sure to check for both a return status of OK and a pIsValid value of TRUE
 *             before accepting that G is valid with respect to P and Q.
 *
 * @funcdoc    dh.c
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_verifyG(MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx, intBoolean *pIsValid, vlong **ppVlongQueue);


/**
 @brief      Get a large prime number to use as your DH private key as a Big Endian
             byte array.
 
 @details    Get a large prime number to use as your DH private key as a Big Endian
             byte array. This method does not allocate memory.
 
 @ingroup    dh_functions
 
 @flags
 There are no flag dependencies to enable this function.
 
 @inc_file dh.h
 
 @param  groupNum    Group number. Use whichever group number is appropriate for your
                     application from among the following values: 1, 2, 5, 14, 15, 16,
                     17, 18, 24, 0x100, 0x101, 0x102, 0x103, 0x104.
 @param  ppBytes         Pointer to a byte array that will be set to the hard
                         coded value of P for the groupNum passed in.
 @param  pLen            Will be set with the length of P in bytes.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @funcdoc    crypto_interface_dh.c
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_getPByteString(ubyte4 groupNum, const ubyte **ppBytes, sbyte4 *pLen);

/**
 * @brief      Validates a DH public key.
 * @details    Validates a DH public key.
 *
 * @ingroup    dh_functions
 *
 * @param pCtx           A key context containing a public key.
 * @param pIsValid       Contents will be set to \c TRUE if the key is valid
 *                       and \c FALSE otherwise.
 * @param ppVlongQueue   On return, pointer to location in the \c vlong queue
 *                       that contains this function's intermediate value,
 *                       which can subsequently be used and eventually
 *                       discarded. (Before ending, your application should
 *                       be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    crypto_interface_dh.c
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_verifyPublicKey(
    MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx,
    intBoolean *pIsValid,
    vlong **ppVlongQueue);

/**
 * @brief      Validates a DH private/public key pair.
 * @details    Validates a DH private/public key pair.
 *
 * @ingroup    dh_functions
 *
 * @param pCtx           A key context containing a private and public key.
 * @param pIsValid       Contents will be set to \c TRUE if the key is valid
 *                       and \c FALSE otherwise.
 * @param ppVlongQueue   On return, pointer to location in the \c vlong queue
 *                       that contains this function's intermediate value,
 *                       which can subsequently be used and eventually
 *                       discarded. (Before ending, your application should
 *                       be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    crypto_interface_dh.c
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_verifyKeyPair(
    MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx,
    intBoolean *pIsValid,
    vlong **ppVlongQueue);

/**
 * @brief      Validates a DH private key.
 * @details    Validates a DH private key.
 *
 * @ingroup    dh_functions
 *
 * @param pCtx           A key context containing a private key.
 * @param pIsValid       Contents will be set to \c TRUE if the key is valid
 *                       and \c FALSE otherwise.
 * @param ppVlongQueue   On return, pointer to location in the \c vlong queue
 *                       that contains this function's intermediate value,
 *                       which can subsequently be used and eventually
 *                       discarded. (Before ending, your application should
 *                       be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    crypto_interface_dh.c
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_verifyPrivateKey(
    MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx,
    intBoolean *pIsValid,
    vlong **ppVlongQueue);

/**
 * @brief      Generates Diffie-Hellman domain params P,Q,G.
 * @details    Generates Diffie-Hellman domain params P,Q,G.
 *
 * @ingroup    dh_functions
 *
 * @param pCtx           A previously allocated Diffie-Hellman context.
 * @param pFipsRngCtx    A RNG context.
 * @param keySize        The size in bits of the prime P to be generated.
 * @param qSize          The size in bits of the prime Q to be generated.
 * @param hashType       The hashing method to be used in domain param generation.
 * @param ppVlongQueue   On return, pointer to location in the \c vlong queue
 *                       that contains this function's intermediate value,
 *                       which can subsequently be used and eventually
 *                       discarded. (Before ending, your application should
 *                       be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    crypto_interface_dh.c
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_generateDomainParams(
    MOC_FFC(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx,
    randomContext* pFipsRngCtx,
    ubyte4 keySize,
    ubyte4 qSize,
    FFCHashType hashType,
    vlong **ppVlongQueue
    );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_DH_HEADER__ */
