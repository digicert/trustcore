/*
 * dh.h
 *
 * Diffie-Hellman Key Exchange
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
 @file       dh.h

 @brief      Header file for the NanoCyrpto Diffie-Hellman (DH) API.
 @details    Header file for the NanoCyrpto Diffie-Hellman (DH) API.

 @sa         For information about the NanoCrypto Ecliptic Curve (EC) DH API, see primeec.h
 
 @copydoc    overview_dh
 
 @flags      There are no flag dependencies for the functions in this API.
 
 @filedoc    dh.h
*/

/*------------------------------------------------------------------*/

#ifndef __KEYEX_DH_HEADER__
#define __KEYEX_DH_HEADER__

#include "../cap/capdecl.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_dh_priv.h"
#endif

#include "../cap/capasym.h"
#include "../crypto/ffc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DH_GROUP_TBD                    0
#define DH_GROUP_1                      1
#define DH_GROUP_2                      2
#define DH_GROUP_5                      5
#define DH_GROUP_14                     14
#define DH_GROUP_15                     15
#define DH_GROUP_16                     16
#define DH_GROUP_17                     17
#define DH_GROUP_18                     18
#define DH_GROUP_24                     24

#define DH_GROUP_19                     19
#define DH_GROUP_20                     20
#define DH_GROUP_21                     21
#define DH_GROUP_25                     25
#define DH_GROUP_26                     26
#define DH_GROUP_31                     31
#define DH_GROUP_32                     32

#define DH_GROUP_FFDHE2048           0x100
#define DH_GROUP_FFDHE3072           0x101
#define DH_GROUP_FFDHE4096           0x102
#define DH_GROUP_FFDHE6144           0x103
#define DH_GROUP_FFDHE8192           0x104
    
#define COMPUTED_VLONG_G(X)             (X)->dh_g
#define COMPUTED_VLONG_Y(X)             (X)->dh_y
#define COMPUTED_VLONG_F(X)             (X)->dh_f
#define COMPUTED_VLONG_E(X)             (X)->dh_e
#define COMPUTED_VLONG_K(X)             (X)->dh_k
#define COMPUTED_VLONG_P(X)             (X)->dh_p
#define COMPUTED_VLONG_Q(X)             (X)->dh_q

#ifndef __DISABLE_DIGICERT_DH_BLINDING__
#define COMPUTED_VLONG_VF(X)             (X)->dh_vf
#define COMPUTED_VLONG_VI(X)             (X)->dh_vi
#define COMPUTED_VLONG_PY(X)             (X)->dh_py
#endif
    
/* for SSH context */
#define DIFFIEHELLMAN_CONTEXT(X)        (X)->p_dhContext

/*------------------------------------------------------------------*/

/**
@brief      Context information for an exercise of the DH protocol.

@details    This structure stores context information needed for an exercise
            of the DH protocol. Most of the members store vlong values. To
            pre-allocate the memory used for these members, the NanoCrypto DH
            API functions include a parameter that you can use to specify a
            vlong memory queue. If you do not specify such a memory queue, the
            memory for these members is allocated from the heap as needed.
*/
typedef struct diffieHellmanContext
{
    /**
    @brief      \e Generator value; see DH_getG().
    @details    \e Generator value, see DH_getG().
    */
    vlong*  dh_g;           /* generator */
    /**
    @brief      <em>Large Prime</em> modulus value; see DH_getP().
    @details    <em>Large Prime</em> modulus value; see DH_getP().
    */
    vlong*  dh_p;           /* big prime */
    /**
    @brief      <em>Prime Divisor</em> value; see DH_setPGQ().
    @details    <em>Prime Divisor</em> value; see DH_setPGQ().
    */
    vlong*  dh_q;         /* prime divisor */
    /**
    @brief      Private key of the local peer; see DH_setPG().
    @details    Private key of the local peer; see DH_setPG().
    */
    vlong*  dh_y;           /* random number - private key */
    /**
    @brief      Public key of the local peer; see DH_setPG().
    @details    Public key of the local peer; see DH_setPG().
    */
    vlong*  dh_f;           /* sent by the server - public key */
    /**
    @brief      Received public key of the remote peer.
    @details    Received public key of the remote peer.
    */
    vlong*  dh_e;           /* sent by the client - public key */
    /**
    @brief      Shared secret; see DH_computeKeyExchange().
    @details    Shared secret; see DH_computeKeyExchange().
    */
    vlong*  dh_k;           /* shared secret */

    MocAsymKey pPrivateKey;
    MocAsymKey pPublicKey;
    ubyte4     enabled;

#ifndef __DISABLE_DIGICERT_DH_BLINDING__
    
    vlong* dh_vi;     /* the blinding value */
    vlong* dh_vf;     /* the unblinding value */
    vlong* dh_py;     /* the previous value of y */
    
#endif

} diffieHellmanContext;

/*------------------------------------------------------------------*/

/**
 @brief      Get a \e Generator value for DH calculations.
 
 @details    This function returns a \e Generator value for DH calculations.
 
 @todo_eng_review (This function writeup is new since 5.3.1; don't know why it
 wasn't in the old documentation...)
 
 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_dh.jpg">DH</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>
 
 @ingroup    dh_functions
 
 @flags
 There are no flag dependencies to enable this function.
 
 @inc_file dh.h
 
 @param  groupNum    Group number. Use whichever group number is appropriate for your
                     application from among the following values: 1, 2, 5, 14, 15, 16,
                     17, 18, 24, 0x100, 0x101, 0x102, 0x103, 0x104.
 @param  ppRetG          On return, pointer to the address of a vlong value
                         containing a \e Generator value suitable for DH
 calculations.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @funcdoc    dh.c
 */
MOC_EXTERN MSTATUS DH_getG(ubyte4 groupNum, vlong **ppRetG);


/**
 @brief      Get a large prime number to use as your DH private key.
 
 @details    This function returns a large prime number for use as a DH
             private key. In its original description, DH does not mention
             Oakley group primes. However, they are required when you integrate
             DH with protocols such as IKE and IKEv2. For example, for a
             standard (not elliptic curve (EC)) DH implementation, you would
             use Oakley Group 1 (the 768-bit prime modulus group) or Oakley
             Group 2 (the 1,024-bit prime modulus group).
 
 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_dh.jpg">DH</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>
 
 @ingroup    dh_functions
 
 @flags
 There are no flag dependencies to enable this function.
 
 @inc_file dh.h
 
 @param  groupNum    Group number. Use whichever group number is appropriate for your
                     application from among the following values: 1, 2, 5, 14, 15, 16,
                     17, 18, 24, 0x100, 0x101, 0x102, 0x103, 0x104.
 @param  ppRetP      On return, pointer to a buffer containing Oakley Group Prime.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @funcdoc    dh.c
 */
MOC_EXTERN MSTATUS DH_getP(ubyte4 groupNum, vlong **ppRetP);


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
 
 @funcdoc    dh.c
 */
MOC_EXTERN MSTATUS DH_getPByteString(ubyte4 groupNum, const ubyte** ppBytes, sbyte4* pLen);


/**
 @brief      Allocate and initialize a \c diffieHellmanContext structure.
 
 @details    This function allocates and initializes a \c diffieHellmanContext
             structure, which the NanoCrypto DH API uses to store information
             that defines a Diffie-Hellman context.
 
 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_dh.jpg">DH</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>
 
 The \c diffieHellmanContext returned by this function structure is empty of
 any context information. To supply the context information, select an
 appropriate generator and prime, compute a public value, and then compute a
 shared secret.
 
 @ingroup    dh_functions
 
 @flags
 There are no flag dependencies to enable this function.
 
 @inc_file dh.h
 
 @param  pp_dhContext    On return, pointer to the address of an initialized
                         \c diffieHellmanContext structure that you can use to
                         store a Diffie-Hellman context. The structure does not
                         yet contain any context information.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @funcdoc    dh.c
 */
MOC_EXTERN MSTATUS DH_allocate(diffieHellmanContext **pp_dhContext);


/**
 @brief      Allocate and initialize resources for a DH server.
 
 @details    This function is a convenience function that performs the
             following tasks that normally require separate calls to the
             NanoCrypto DH API:
 -# Picks a \e Generator value, which it stores  in \c diffieHellmanContext::dh_g.
 -# Picks a <em>Large Prime</em> value, which it stores in \c diffieHellmanContext::dh_p.
 -# Picks a <em>Private Key</em>, which it stores in \c diffieHellmanContext::dh_y.
 -# Generates the <em>Public Key</em>, which it stores in \c diffieHellmanContext::dh_f.
 
 The DH_allocateServer() function's default operation assumes that the
 negotiation over the \e Generator and <em>Large Prime</em> modulus value
 consists of the server telling the client what the values will be. If that
 is the case, the server continues the protocol from step 4 in the process
 table in @ref section_about_dh. If that is \b not the case&mdash;that is, if
 the server truly negotiates these values with the client&mdash; the server
 picks up the protocol from step 3 in the process table in @ref
 section_about_dh.
 
 @todo_eng_review (This function writeup is new since 5.3.1; don't know why it
 wasn't in the old documentation...)
 
 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_dh.jpg">DH</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>
 
 @ingroup    dh_functions
 
 @flags
 There are no flag dependencies to enable this function.
 
 @inc_file dh.h
 
 @param  pRandomContext  Pointer to a \c randomContext structure, which is
                         used internally to store the information needed to
                         manage the generation of a random number using the
                         NanoCrypto Random API (see random.c). To allocate
                         the structure, call RANDOM_acquireContext(). To
                         release the memory of the structure, call
                         RANDOM_releaseContext().
 @param  pp_dhContext    On return, pointer to address of allocated and partially
                         populated \c diffieHellmanContext structure. Before
                         you can use this structure to calculate the shared
                         secret, you must get the public key from the client
                         and store it in the \c dh_e member of this
                         structure. You can then call DH_computeKeyExchange()
                         to compute the shared secret.
 @param  groupNum    Group number. Use whichever group number is appropriate for your
                     application from among the following values: 1, 2, 5, 14, 15, 16,
                     17, 18, 24, 0x100, 0x101, 0x102, 0x103, 0x104.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @funcdoc    dh.c
 */
MOC_EXTERN MSTATUS DH_allocateServer(MOC_DH(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, diffieHellmanContext **pp_dhContext, ubyte4 groupNum);


/**
 @brief      Allocate and initialize resources for a DH client.
 
 @details    This function is a convenience function that performs the
             following tasks that normally require separate calls to the NanoCrypto DH API:
 -# Allocates a \c diffieHellmanContext structure for the client.
 -# Chooses a <em>Large Prime</em> value, which it stores in \c
 diffieHellmanContext::dh_p member.
 -# Chooses a private key for the client, which it stores in \c
 diffieHellmanContext::dh_y member.
 
 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_dh.jpg">DH</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>
 
 @todo_eng_review (This function writeup is new since 5.3.1; don't know why it
 wasn't in the old documentation...)
 
 This function does not choose a \e Generator value. The \e Generator value
 and the <em>Large Prime</em> value are usually negotiated with the server.
 Therefore, upon receiving new values for the \e Generator and the <em>Large
 Prime</em> modulus, you must call DH_setPG() to populate the \c dh_g and \c
 dh_p members of the \c diffieHellmanContext structure, as well as to
 re-select your private key and generate your public key. You must then send
 this public key to the server.
 
 When you receive the server's public key, store it in the \c dh_e member of
 your \c diffieHellmanContext structure, and then call DH_computeKeyExchange().
 
 @ingroup    dh_functions
 
 @flags
 There are no flag dependencies to enable this function.
 
 @inc_file dh.h
 
 @param  pRandomContext  Pointer to a \c randomContext structure, which is
                         used internally to store the information needed to
                         manage the generation of a random number using the
                         NanoCrypto Random API (see random.c). To allocate
                         the structure, call RANDOM_acquireContext(). To
                         release the memory of the structure, call
                         RANDOM_releaseContext().
 @param  pp_dhContext    On return, pointer to address of allocated \c
                         diffieHellmanContext structure.
 @param  groupNum    Group number. Use whichever group number is appropriate for your
                     application from among the following values: 1, 2, 5, 14, 15, 16,
                     17, 18, 24, 0x100, 0x101, 0x102, 0x103, 0x104.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @funcdoc    dh.c
 */
MOC_EXTERN MSTATUS DH_allocateClient(MOC_DH(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, diffieHellmanContext **pp_dhContext, ubyte4 groupNum);


/**
 @brief      Allocate and initialize resources for a DH client with the group generator G.
 
 @details    This function is a convenience function that performs the
             following tasks that normally require separate calls to the NanoCrypto DH API:
 -# Allocates a \c diffieHellmanContext structure for the client.
 -# Chooses a <em>Large Prime</em> value, which it stores in \c
 diffieHellmanContext::dh_p member.
 -# Chooses a <em>Generator</em> value, which it stores in \c
 diffieHellmanContext::dh_g member.
 -# Chooses a private key for the client, which it stores in \c
 diffieHellmanContext::dh_y member.
 
 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_dh.jpg">DH</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>
 
 @todo_eng_review (This function writeup is new since 5.3.1; don't know why it
 wasn't in the old documentation...)
 
 This function does not choose a \e Generator value. The \e Generator value
 and the <em>Large Prime</em> value are usually negotiated with the server.
 Therefore, upon receiving new values for the \e Generator and the <em>Large
 Prime</em> modulus, you must call DH_setPG() to populate the \c dh_g and \c
 dh_p members of the \c diffieHellmanContext structure, as well as to
 re-select your private key and generate your public key. You must then send
 this public key to the server.
 
 When you receive the server's public key, store it in the \c dh_e member of
 your \c diffieHellmanContext structure, and then call DH_computeKeyExchange().
 
 @ingroup    dh_functions
 
 @flags
 There are no flag dependencies to enable this function.
 
 @inc_file dh.h
 
 @param  pRandomContext  Pointer to a \c randomContext structure, which is
                         used internally to store the information needed to
                         manage the generation of a random number using the
                         NanoCrypto Random API (see random.c). To allocate
                         the structure, call RANDOM_acquireContext(). To
                         release the memory of the structure, call
                         RANDOM_releaseContext().
 @param  pp_dhContext    On return, pointer to address of allocated \c
                         diffieHellmanContext structure.
 @param  groupNum    Group number. Use whichever group number is appropriate for your
                     application from among the following values: 1, 2, 5, 14, 15, 16,
                     17, 18, 24, 0x100, 0x101, 0x102, 0x103, 0x104.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @funcdoc    dh.c
 */
MOC_EXTERN MSTATUS DH_allocateClientAux(MOC_DH(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, diffieHellmanContext **pp_dhContext, ubyte4 groupNum);


/**
 @brief      Assign a prime and a generator to an allocated DH context.
 
 @details    This function stores a given <em>Large Prime</em> and \e Generator
             in the specified \c diffieHellmanContext structure. For
             convenience, this function then chooses a <em>secret
             key</em>&mdash;a random number of the specified length&mdash;
             which is then used to compute a <em>Public Key</em> to share with
             a peer in this exercise of the DH protocol for establishing a
             shared secret.
 
 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_dh.jpg">DH</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>
 
 @ingroup    dh_functions
 
 @flags
 There are no flag dependencies to enable this function.
 
 @inc_file dh.h
 
 @param  pRandomContext  Pointer to a \c randomContext structure, which is
                         used internally to store the information needed to
                         manage the generation of a random number using the
                         NanoCrypto Random API (see random.c). To allocate
                         the structure, call RANDOM_acquireContext(). To
                         release the memory of the structure, call
                         RANDOM_releaseContext().
 @param  lengthY         Number of bytes of the random number to use as the
                         secret key. This key is stored in the \c dh_y member
                         of the \p p_dhContext argument's \c
                         diffieHellmanContext structure.
 @param  p_dhContext     Pointer to the \c diffieHellmanContext structure
                         that you allocated for this exercise of the DH
                         protocol. To allocate a \c diffieHellmanContext
                         structure, call DH_allocate(). To free the memory of
                         the structure, call DH_freeDhContext().
 @param  P               Pointer to the <em>Large Prime</em> modulus value
                         (shared prime) agreed to by your peer in this
                         exercise of the DH protocol. The security of the
                         protocol depends on this value being large. While
                         negotiating this value, you can use DH_GetP() to get
                         a suitable value to propose to your peer.
 @param  G               Pointer to the shared \e Generator value that you
                         negotiated with your peer in this exercise of the DH
                         protocol. The \e Generator value should be a
                         primitive root of the <em>Large Prime</em>.
                         Typically, the \e Generator is a single-digit prime
                         number that generates a large subgroup of the
                         multiplicative group mod the <em>Large Prime</em>;
                         therefore a single-digit prime number, such as 2, is
                         the usual choice. To get a suitable value to propose
                         to your peer in this exercise of the DH protocol,
                         call use DH_GetG().
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @funcdoc    dh.c
 */
MOC_EXTERN MSTATUS DH_setPG(MOC_DH(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, ubyte4 lengthY, diffieHellmanContext *p_dhContext, const vlong *P, const vlong *G);


/**
 @brief      Assign a prime and a generator to an allocated DH context.
 
 @details    This function stores a given <em>Large Prime</em> and \e Generator
             in the specified \c diffieHellmanContext structure. For
             convenience, this function then chooses a <em>secret
             key</em>&mdash;a random number of the specified length&mdash;
             which is then used to compute a <em>Public Key</em> to share with
             a peer in this exercise of the DH protocol for establishing a
             shared secret.
 
 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_dh.jpg">DH</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>
 
 @ingroup    dh_functions
 
 @flags
 There are no flag dependencies to enable this function.
 
 @inc_file dh.h
 
 @param  pRandomContext  Pointer to a \c randomContext structure, which is
                         used internally to store the information needed to
                         manage the generation of a random number using the
                         NanoCrypto Random API (see random.c). To allocate
                         the structure, call RANDOM_acquireContext(). To
                         release the memory of the structure, call
                         RANDOM_releaseContext().
 @param  lengthY         Number of bytes of the random number to use as the
                         secret key. This key is stored in the \c dh_y member
                         of the \p p_dhContext argument's \c
                         diffieHellmanContext structure.
 @param  p_dhContext     Pointer to the \c diffieHellmanContext structure
                         that you allocated for this exercise of the DH
                         protocol. To allocate a \c diffieHellmanContext
                         structure, call DH_allocate(). To free the memory of
                         the structure, call DH_freeDhContext().
 @param  P               Pointer to the <em>Large Prime</em> modulus value
                         (shared prime) agreed to by your peer in this
                         exercise of the DH protocol. The security of the
                         protocol depends on this value being large. While
                         negotiating this value, you can use DH_GetP() to get
                         a suitable value to propose to your peer.
 @param  G               Pointer to the shared \e Generator value that you
                         negotiated with your peer in this exercise of the DH
                         protocol. The \e Generator value should be a
                         primitive root of the <em>Large Prime</em>.
                         Typically, the \e Generator is a single-digit prime
                         number that generates a large subgroup of the
                         multiplicative group mod the <em>Large Prime</em>;
                         therefore a single-digit prime number, such as 2, is
                         the usual choice. To get a suitable value to propose
                         to your peer in this exercise of the DH protocol,
                         call use DH_GetG().
 @param  Q               Pointer to the <em>Prime Divisor</em> modulus value
                         (shared prime) agreed to by your peer in this
                         exercise of the DH protocol. Need TO FIX TEXT HERE...
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @funcdoc    dh.c
 */
MOC_EXTERN MSTATUS DH_setPGQ(MOC_DH(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, ubyte4 lengthY, diffieHellmanContext *p_dhContext, const vlong *P, const vlong *G, const vlong *Q);


/**
 @brief      Free the memory allocated for a \c diffieHellmanContext structure.
 
 @details    This function releases (frees) the memory allocated to a \c
             diffieHellmanContext structure.  If the structure contains memory
             from a pre-allocated memory queue, use the \p ppVlongQueue
             parameter to identify that queue and free (reallocate) that memory
             back to the queue. All other allocated memory is freed back to the
             heap.
 
 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_dh.jpg">DH</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>
 
 @ingroup    dh_functions
 
 @flags
 There are no flag dependencies to enable this function.
 
 @inc_file dh.h
 
 @param  pp_dhContext    Pointer to the \c diffieHellmanContext structure to
                         free. On return, this value is NULL.
 @param  ppVlongQueue    Pointer to the pre-allocated vlong memory queue
                         used for the DH calculations. If the \c
                         diffieHellmanContext structure contains memory
                         allocated from that queue, it is returned there. If
                         you did not use a pre-allocated memory queue, pass
                         in NULL.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @funcdoc    dh.c
 */
MOC_EXTERN MSTATUS DH_freeDhContext(diffieHellmanContext **pp_dhContext, vlong **ppVlongQueue);


/**
 @brief      Compute the shared secret.
 
 @details    This function computes the shared secret. Call this function after
             you call DH_setPG() to populate the \c diffieHellmanContext
             structure with a \e Generator value (\c
             diffieHellmanContext::dh_g), a <em>Large Prime</em> modulus value
             (\c diffieHellmanContext::dh_p), and your private key (\c
             diffieHellmanContext::dh_y), and after you store the other
             participant's public key in the \c dh_e member of your \c
             diffieHellmanContext structure. The shared computed shared secret
             value is stored in \c diffieHellmanContext::dh_k member of the
             specified \c diffieHellmanContext structure.
 
 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_dh.jpg">DH</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>
 
 @ingroup    dh_functions
 
 @flags
 There are no flag dependencies to enable this function.
 
 @inc_file dh.h
 
 @param  p_dhContext     Pointer to the \c diffieHellmanContext structure
                         that you allocated for this exercise of the DH
                         protocol. To allocate a \c diffieHellmanContext
                         structure, call DH_allocate().
 @param  ppVlongQueue    Pointer to memory queue to reduce memory allocaiton
                         penalty; may be NULL. If you pass a pointer to the
                         address of a pre-allocated memory queue for vlong
                         values, the memory required for the DH calculations
                         is taken from this pre-allocated memory queue. If
                         you have not set up a pre-allocated memory queue for
                         this purpose, pass in NULL, in which case the memory
                         for the calculations is allocated from the heap as
                         needed.
 
 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 
 @funcdoc    dh.c
 */
MOC_EXTERN MSTATUS DH_computeKeyExchange(MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *p_dhContext, vlong** ppVlongQueue);


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
MOC_EXTERN MSTATUS DH_setKeyParameters(MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pTargetCtx, MDhKeyTemplate *pSrcTemplate);


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
 *                           MOC_GET_PUBLIC_KEY_DATA
 *
 * @return                   \c OK (0) if successful, otherwise a negative number
 *                           error code from merrors.h.
 */
MOC_EXTERN MSTATUS DH_getKeyParametersAlloc(MOC_DH(hwAccelDescr hwAccelCtx) MDhKeyTemplate *pTargetTemplate, diffieHellmanContext *pSrcCtx, ubyte keyType);


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
MOC_EXTERN MSTATUS DH_freeKeyTemplate(diffieHellmanContext *pCtx, MDhKeyTemplate *pTemplate);


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
MOC_EXTERN MSTATUS DH_generateKeyPair(MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx, randomContext *pRandomContext, ubyte4 numBytes);


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
MOC_EXTERN MSTATUS DH_getPublicKey(MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx, ubyte **ppPublicKey, ubyte4 *pPublicKeyLen);


/**
 * Generates a shared secret from the domain parameters and our private key stored
 * in the context, and the other partys public key as passed in.
 *
 * @param pCtx                  Pointer to the context holding at least the domain
 *                              params p and g and our private key y.
 * @param pRandomContext        Pointer to a random Context. If non-NULL then
 *                              blinding will be done for all non-MQV modes.
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
MOC_EXTERN MSTATUS DH_computeKeyExchangeEx(MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx, randomContext *pRandomContext, ubyte *pOtherPartysPublicKey, ubyte4 publicKeyLen,
                                           ubyte **ppSharedSecret, ubyte4 *pSharedSecretLen);


/* mode macros for DH Key Agreement Schemes */
#define DH_HYBRID1           0
#define MQV2                 1
#define DH_EPHEMERAL         2
#define DH_HYBRID_ONE_FLOW_U 3
#define DH_HYBRID_ONE_FLOW_V 4
#define MQV1_U               5
#define MQV1_V               6
#define DH_ONE_FLOW_U        7
#define DH_ONE_FLOW_V        8
#define DH_STATIC            9

/**
 * @brief   Generates a Diffie-Hellman shared secret via one of the major modes.
 *
 * @details Generates a Diffie-Hellman shared secret via one of the major modes.
 *          This method allocates a buffer to hold the secret. Be sure to FREE
 *          this buffer when done with it.
 *
 * @flags   To use this method one must define __ENABLE_DIGICERT_DH_MODES__
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
MOC_EXTERN MSTATUS DH_keyAgreementScheme(
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
MOC_EXTERN MSTATUS DH_validateDomainParams(MOC_DH(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
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
MOC_EXTERN MSTATUS DH_verifySafePG(diffieHellmanContext *pCtx, intBoolean *pIsValid, ubyte4 *pPriKeyLen, vlong **ppVlongQueue);

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
MOC_EXTERN MSTATUS DH_verifyPQ_FIPS1864(MOC_DH(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
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
 *s
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
MOC_EXTERN MSTATUS DH_verifyG(MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx, intBoolean *pIsValid, vlong **ppVlongQueue);
    

/* Ext versions of all the above methods that will be used in crypto interface */
    
/**
 * @cond
 */
MOC_EXTERN MSTATUS DH_allocateExt(diffieHellmanContext **pp_dhContext, void *pExtCtx);
MOC_EXTERN MSTATUS DH_allocateServerExt(MOC_DH(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, diffieHellmanContext **pp_dhContext, ubyte4 groupNum, void *pExtCtx);
MOC_EXTERN MSTATUS DH_allocateClientAuxExt(MOC_DH(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, diffieHellmanContext **pp_dhContext, ubyte4 groupNum, void *pExtCtx);
MOC_EXTERN MSTATUS DH_freeDhContextExt(diffieHellmanContext **pp_dhContext, vlong **ppVlongQueue, void *pExtCtx);
MOC_EXTERN MSTATUS DH_setKeyParametersExt(MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pTargetCtx, MDhKeyTemplate *pSrcTemplate, void *pExtCtx);
MOC_EXTERN MSTATUS DH_getKeyParametersAllocExt(MOC_DH(hwAccelDescr hwAccelCtx) MDhKeyTemplate *pTargetTemplate, diffieHellmanContext *pSrcCtx, ubyte keyType, void *pExtCtx);
MOC_EXTERN MSTATUS DH_freeKeyTemplateExt(diffieHellmanContext *pCtx, MDhKeyTemplate *pTemplate, void *pExtCtx);
MOC_EXTERN MSTATUS DH_generateKeyPairExt(MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx, randomContext *pRandomContext, ubyte4 numBytes, void *pExtCtx);
MOC_EXTERN MSTATUS DH_getPublicKeyExt(MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx, ubyte **ppPublicKey, ubyte4 *pPublicKeyLen, void *pExtCtx);
MOC_EXTERN MSTATUS DH_computeKeyExchangeExExt(MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx, randomContext *pRandomContext, ubyte *pOtherPartysPublicKey,
                                              ubyte4 publicKeyLen, ubyte **ppSharedSecret, ubyte4 *pSharedSecretLen, void *pExtCtx);

/**
 * @endcond
 */
#ifdef __cplusplus
}
#endif

#endif /* __KEYEX_DH_HEADER__ */
