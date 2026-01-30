/*
 * crypto_interface_hybrid_example.c
 *
 * Crypto Interface Quantum Safe Hybrid Example Code
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

#include "../../common/moptions.h"

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC__) && defined(__ENABLE_DIGICERT_PQC__)

#include "../../common/mtypes.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#include "../../common/random.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto_interface/crypto_interface_ecc.h"
#include "../../crypto_interface/crypto_interface_qs.h"
#include "../../crypto_interface/crypto_interface_qs_composite.h"
#include "../../crypto_interface/crypto_interface_qs_kem.h"

/*
Given a certificate signing request configuration file (csr.conf), a quantum safe composite
key can be generated via the tc_keygen tool and the following commands...

For an MLDSA and ECC key/cert pair...

./tc_keygen -a HYBRID -c <curve> -g MLDSA_<size> -o <name>_key.pem 
            -x <name>_cert.pem -i csr.conf -da 365

For an MLDSA and RSA key/cert pair...

./tc_keygen -a HYBRID -s <rsa size> -g MLDSA_<size> -o <name>_key.pem 
            -x <name>_cert.pem -i csr.conf -da 365 <-pss>

Here the -da option is the number of days of validity. -pss is optional and
can be added to ensure the signing algorithm uses pss padding vs pkcs1.5 #1.
*/

/* --------------------------------------------------------------------------------*/

/* Will read the pKeyFile and set the key passed in */
static MSTATUS crypto_interface_composite_example_key_from_file(AsymmetricKey *pKey, const char *pKeyFile)
{
    MSTATUS status = OK;
    ubyte *pSerializedKeyData = NULL;
    ubyte4 serializedKeyDataLen = 0;

    status = DIGICERT_readFile(pKeyFile, &pSerializedKeyData, &serializedKeyDataLen);
    if (OK != status)
        goto exit;

    /* CRYPTO_deserializeAsymKey will determine the key to be a composite key */
    status = CRYPTO_deserializeAsymKey(pSerializedKeyData, serializedKeyDataLen, NULL, pKey);

exit:

    if (NULL != pSerializedKeyData)
    {
        (void) DIGI_MEMSET_FREE(&pSerializedKeyData, serializedKeyDataLen);
    }

    return status;
}

/* --------------------------------------------------------------------------------*/

/* Will read the pCertFile and set the key passed in to the public key */
static MSTATUS crypto_interface_composite_example_key_from_cert(AsymmetricKey *pKey, const char *pCertFile)
{
    MSTATUS status = OK;
    ubyte *pCert = NULL;
    ubyte4 certLen = 0;
    ubyte *pCertDer = NULL;
    ubyte4 certLenDer = 0;
    ubyte *pSerializedKeyData = NULL;
    ubyte4 serializedKeyDataLen = 0;

    status = DIGICERT_readFile(pCertFile, &pCert, &certLen);
    if (OK != status)
        goto exit;

    /* Convert the PEM certificate to DER */
    status = CA_MGMT_decodeCertificate(pCert, certLen, &pCertDer, &certLenDer);
    if (OK != status)
        goto exit;

    /* extract the public key in a serialized keyblob form */
    status = CA_MGMT_extractPublicKeyInfo(pCertDer, certLenDer, &pSerializedKeyData, &serializedKeyDataLen);
    if (OK != status)
        goto exit;

    /* As this was a self signed certificate we will validate its signature with its own key */
    status = CA_MGMT_verifySignature(pSerializedKeyData, serializedKeyDataLen, pCertDer, certLenDer);
    if (OK != status)
        goto exit;

    /* CRYPTO_deserializeAsymKey will handle the keyblob form and determine the key to be a composite key */
    status = CRYPTO_deserializeAsymKey(pSerializedKeyData, serializedKeyDataLen, NULL, pKey);

exit:

    if (NULL != pCert)
    {
        (void) DIGI_MEMSET_FREE(&pCert, certLen);
    }

    if (NULL != pCertDer)
    {
        (void) DIGI_MEMSET_FREE(&pCertDer, certLenDer);
    }

    if (NULL != pSerializedKeyData)
    {
        (void) DIGI_MEMSET_FREE(&pSerializedKeyData, serializedKeyDataLen);
    }

    return status;
}

/* -------------------- SIGN VERIFY ROUNDTRIP EXAMPLE -------------------*/

static MSTATUS crypto_interface_composite_sign_verify_example(const char *pKeyFile, const char *pCertFile)
{
    MSTATUS status = OK;
    AsymmetricKey asymKey = {0};
    ubyte *pSig = NULL;
    ubyte4 sigLen = 0;
    ubyte4 vStatus = 1;

    /* Data to be signed and verified. (Full message) */
    ubyte pMessage[32] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    ubyte4 messageLen = 32;

    /* get the private key from the key file */
    status = crypto_interface_composite_example_key_from_file(&asymKey, pKeyFile);
    if (OK != status)
        goto exit;

    /* get the signature Len. For this example we'll do simple concatenation and enter false on length prefixing */
    status = CRYPTO_INTERFACE_QS_compositeGetSigLen(&asymKey, FALSE, &sigLen);
    if (OK != status)
        goto exit;

    /* Allocate a buffer for the signature */
    status = DIGI_MALLOC((void **) &pSig, sigLen);
    if (OK != status)
        goto exit;

    /* sign the message, false on length prefixing, and empty domain. 
       In practice domain may be an OID for SSL or a string identifier for SSH */
    status = CRYPTO_INTERFACE_QS_compositeSign(&asymKey, FALSE, RANDOM_rngFun, g_pRandomContext, NULL, 0,
                                               pMessage, messageLen, pSig, sigLen, &sigLen);
    if (OK != status)
        goto exit;

    /* done with the private key */
    status = CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    if (OK != status)
        goto exit;

    /* get the public key from the certificate */
    status = crypto_interface_composite_example_key_from_cert(&asymKey, pCertFile);
    if (OK != status)
        goto exit;

    /* verify, false length prefixing, and empty domain */
    status = CRYPTO_INTERFACE_QS_compositeVerify(&asymKey, FALSE, NULL, 0, pMessage, messageLen, pSig, sigLen, &vStatus);
    if (OK != status)
        goto exit;

    if (vStatus)
    {
        status = ERR_CERT_INVALID_SIGNATURE;
    }

exit:

    /* final cleanup, no need to change status */
    (void) CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    if (NULL != pSig)
    {
        (void) DIGI_MEMSET_FREE(&pSig, sigLen);
    }

    return status;
}

/* --------------------------------------------------------------------------------*/

static MSTATUS run_crypto_interface_composite_sign_verify_examples()
{
    MSTATUS status = OK;

    status = crypto_interface_composite_sign_verify_example (
        "mldsa44_rsa2048_pss_key.pem", "mldsa44_rsa2048_pss_cert.pem");
    if (OK != status)
        goto exit;

    status = crypto_interface_composite_sign_verify_example (
        "mldsa44_p256_key.pem", "mldsa44_p256_cert.pem");

exit:

    return status;
}

/* ---------------------------   KEY EXHANGE   --------------------------------*/

static MSTATUS crypto_interface_composite_key_exchange_example(ubyte4 curveId, ubyte4 qsAlgo)
{
    MSTATUS status = OK;
    ubyte4 eccPointLen = 0;
    ubyte4 eccElemLen = 0;

    ubyte4 qsLen = 0;
    ubyte *pTempBuffer = NULL;
    ubyte4 tempLen = 0;
    sbyte4 compare = -1;

    /***** PARTY A *****/
    ECCKey *pAEcc = NULL;
    QS_CTX *pAQs = NULL;

    ubyte *pApub = NULL;
    ubyte4 aPubLen = 0;
    ubyte *pASecret = NULL;
    ubyte4 aSecLen = 0;

    /***** PARTY B *****/
    ECCKey *pBEcc = NULL;
    QS_CTX *pBQs = NULL;

    ubyte *pBpub = NULL;
    ubyte4 bPubLen = 0;
    ubyte *pBSecret = NULL;
    ubyte4 bSecLen = 0;

    /***** Initiator PARTY A *****/

    /* First create an ECC Key pair */
    status = CRYPTO_INTERFACE_EC_generateKeyPairAllocAux(
        curveId, &pAEcc, RANDOM_rngFun, g_pRandomContext);
    if (OK != status)
        goto exit;

    /* Next we create a QS context and key pair */
    status = CRYPTO_INTERFACE_QS_newCtx(&pAQs, qsAlgo);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_generateKeyPair(pAQs, RANDOM_rngFun, g_pRandomContext);
    if (OK != status)
        goto exit;

    /* Get each of the public keys' length so that we can concatenate into a single buffer */
    status = CRYPTO_INTERFACE_EC_getPointByteStringLenAux(pAEcc, &eccPointLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_getPublicKeyLen(pAQs, &qsLen);
    if (OK != status)
        goto exit;

    aPubLen = eccPointLen + qsLen;

    /* Now we know the total length of the concatenated public keys */
    status = DIGI_MALLOC((void **) &pApub, aPubLen);
    if (OK != status)
        goto exit;

    /* Get the ECC public key */
    status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux (pAEcc, pApub, aPubLen);
    if (OK != status)
        goto exit;

    /* And put the QS public key after it */
    status = CRYPTO_INTERFACE_QS_getPublicKey(pAQs, pApub + eccPointLen, aPubLen - eccPointLen);
    if (OK != status)
        goto exit;

    /* Pass pApub and its length off to party B */

    /***** Responder PARTY B *****/

    /* Party B generates its ECC key pair but does not need to generate a QS key pair */
    status = CRYPTO_INTERFACE_EC_generateKeyPairAllocAux(
        curveId, &pBEcc, RANDOM_rngFun, g_pRandomContext);
    if (OK != status)
        goto exit;

    /* Party B will need to get its own ECC public key length since that was not passed from A */
    status = CRYPTO_INTERFACE_EC_getPointByteStringLenAux(pBEcc, &eccPointLen);
    if (OK != status)
        goto exit;

    /* Party B instead just needs a QS_CTX with party A's public key */
    status = CRYPTO_INTERFACE_QS_newCtx(&pBQs, qsAlgo);
    if (OK != status)
        goto exit;

    /* Remember the QS public key is after the ECC one */
    status = CRYPTO_INTERFACE_QS_setPublicKey(pBQs, pApub + eccPointLen, aPubLen - eccPointLen);
    if (OK != status)
        goto exit;

    /* Ready to generate the concatenated shared secret, we need the lengths first
       the ECC API will set its length so get the length of the QS part first */
    status = CRYPTO_INTERFACE_QS_KEM_getSharedSecretLen(pBQs, &tempLen);
    if (OK != status)
        goto exit;

    bSecLen += tempLen;

    /* Get the ECC shared secret and length altogether. We need to use a temp
       buffer and later copy as there is no generateSecret API that takes
       in an already created buffer */
    status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux (
        pBEcc, pApub, eccPointLen, &pTempBuffer, &eccElemLen, 1, NULL);
    if (OK != status)
        goto exit;

    bSecLen += eccElemLen;

    /* Now we can create a buffer for the combined shared secret */
    status = DIGI_MALLOC((void **) &pBSecret, bSecLen);
    if (OK != status)
        goto exit;

    /* And also we need a buffer for the combined B's public key */
    bPubLen += eccPointLen;

    /* B's public key consists of the ECC public key followed by the QS "ciphertext" */
    status = CRYPTO_INTERFACE_QS_KEM_getCipherTextLen(pBQs, &tempLen);
    if (OK != status)
        goto exit;

    bPubLen += tempLen;
    status = DIGI_MALLOC((void **) &pBpub, bPubLen);
    if (OK != status)
        goto exit;

    /* Write in the ECC public key */
    status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux (pBEcc, pBpub, bPubLen);
    if (OK != status)
        goto exit;

    /* Write in, ie copy, the ECC SS */
    status = DIGI_MEMCPY(pBSecret, pTempBuffer, eccElemLen);
    if (OK != status)
        goto exit;

    /* Now get the QS portion of the shared secret and ciphertext (public key) in one shot */
    status = CRYPTO_INTERFACE_QS_KEM_encapsulate(
        pBQs, RANDOM_rngFun, g_pRandomContext, pBpub + eccPointLen, bPubLen - eccPointLen,
        pBSecret + eccElemLen, bSecLen - eccElemLen);
    if (OK != status)
        goto exit;

    /* Party B now sends its "public key" (consisting of its ECC public key and ciphertext)
       over to party A */

    /* for simplicity of this example we will re-use pTempBuffer, so free it */
    status = DIGI_MEMSET_FREE(&pTempBuffer, eccElemLen);
    if (OK != status)
        goto exit;

    /***** Party A *****/

    /* Note party A still had its copy of the eccPointLen, so no need to recompute that */

    /* First comppute the ECC portion of the secret */
    status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux (
        pAEcc, pBpub, eccPointLen, &pTempBuffer, &eccElemLen, 1, NULL);
    if (OK != status)
        goto exit;

    aSecLen += eccElemLen;

    /* A did not have the QS shared secret len yet though */
    status = CRYPTO_INTERFACE_QS_KEM_getSharedSecretLen(pAQs, &tempLen);
    if (OK != status)
        goto exit;

    aSecLen += tempLen;

    /* Now create a buffer for the concatenetated secrets */
    status = DIGI_MALLOC((void **) &pASecret, aSecLen);
    if (OK != status)
        goto exit;

    /* copy the ECC portion */
    status = DIGI_MEMCPY(pASecret, pTempBuffer, eccElemLen);
    if (OK != status)
        goto exit;

    /* Next compute the QS portion */
    status = CRYPTO_INTERFACE_QS_KEM_decapsulate(
        pAQs, pBpub + eccPointLen, bPubLen - eccPointLen, pASecret + eccElemLen,
        aSecLen - eccElemLen);
    if (OK != status)
        goto exit;

    /***** For demonstration purposes only we'll verify the secrets match *****/

    if (aSecLen != bSecLen)
    {
        status = ERR_FALSE;
        goto exit;
    }

    status = DIGI_MEMCMP(pASecret, pBSecret, aSecLen, &compare);
    if (OK != status)
        goto exit;

    if (compare)
    {
        status = ERR_FALSE;
    }
    else
    {
        status = OK;
    }

    /* In a real use case make sure to hash or apply a kdf to the shared secrets */

exit:

    /* temp cleanup */
    if (NULL != pTempBuffer)
    {
        (void) DIGI_MEMSET_FREE(&pTempBuffer, eccElemLen);
    }

    /* A's cleanup */
    if (NULL != pAEcc)
    {
        (void) CRYPTO_INTERFACE_EC_deleteKeyAux(&pAEcc);
    }

    if (NULL != pAQs)
    {
        (void) CRYPTO_INTERFACE_QS_deleteCtx(&pAQs);
    }

    if (NULL != pApub)
    {
        (void) DIGI_MEMSET_FREE(&pApub, aPubLen);
    }

    if (NULL != pASecret)
    {
        (void) DIGI_MEMSET_FREE(&pASecret, aSecLen);
    }

    /* B's cleanup */
    if (NULL != pBEcc)
    {
        (void) CRYPTO_INTERFACE_EC_deleteKeyAux(&pBEcc);
    }

    if (NULL != pBQs)
    {
        (void) CRYPTO_INTERFACE_QS_deleteCtx(&pBQs);
    }

    if (NULL != pBpub)
    {
        (void) DIGI_MEMSET_FREE(&pBpub, bPubLen);
    }

    if (NULL != pBSecret)
    {
        (void) DIGI_MEMSET_FREE(&pBSecret, bSecLen);
    }

    return status;
}

/* --------------------------------------------------------------------------------*/

static MSTATUS run_crypto_interface_composite_key_exchange_examples()
{
    MSTATUS status = OK;

    status = crypto_interface_composite_key_exchange_example (
        cid_EC_P256, cid_PQC_MLKEM_512);
    if (OK != status)
        goto exit;

    status = crypto_interface_composite_key_exchange_example (
        cid_EC_P384, cid_PQC_MLKEM_512);
    if (OK != status)
        goto exit;

    status = crypto_interface_composite_key_exchange_example (
        cid_EC_P521, cid_PQC_MLKEM_512);

exit:
    return status;
}

/* --------------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS crypto_interface_composite_example()
{
    MSTATUS status = OK;

    status = run_crypto_interface_composite_sign_verify_examples();
    if (OK != status)
        goto exit;

    status = run_crypto_interface_composite_key_exchange_examples();

exit:

    return status;
}
#endif /* defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC__) && defined(__ENABLE_DIGICERT_PQC__) */
