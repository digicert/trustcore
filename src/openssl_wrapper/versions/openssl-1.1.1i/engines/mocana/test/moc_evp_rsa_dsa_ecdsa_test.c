/*
 * moc_evp_rsa_dsa_ecdsa_test.c
 *
 * Test program for RSA/DSA/ECDSA encryption, decryption, signing, and verification
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include <stdio.h>
#include <sys/types.h>
#ifndef __RTOS_WIN32__
#include <sys/errno.h>
#include <unistd.h>
#include <getopt.h>
#endif
#include <string.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/engine.h>

#ifdef __RTOS_WIN32__
#include <ms/applink.c>
#include "getopt.inc"
#endif

#ifdef __ENABLE_DIGICERT_TPM__
#include "crypto/secmod/moctap.h"
#endif

#ifdef __ENABLE_DIGICERT_TAP__
#include "smp/smp_cc.h"
#include "tap/tap_api.h"
#include "tap/tap_utils.h"
#include "tap/tap_smp.h"
#include "crypto/mocasym.h"
#include "crypto/mocasymkeys/tap/rsatap.h"
#include "crypto/mocasymkeys/tap/ecctap.h"
#include "crypto_interface/cryptointerface.h"

#if defined(__RTOS_WIN32__)
#define TPM2_CONFIGURATION_FILE        "tpm2.conf"
#else
#include "common/tpm2_path.h"
#endif
#define KEY_SOURCE_TPM2                "TPM2"
#endif

#ifdef __ENABLE_TAP_REMOTE__
#define taps_ServerName                 "ssltest.mydomain.net"
#define taps_ServerPort                 8277
#endif

#define MAX_NUM_CLEAR_TEXTS	100
char *clear_texts[MAX_NUM_CLEAR_TEXTS] = {
    {
		"This is a duck"
	}
};
static int num_clear_texts = 1;

static char *priv_key_pem;
static void prn_b64(unsigned char *in, int inlen);

#define OPER_ENCRYPT	1
#define OPER_SIGN	2

static int operation = OPER_ENCRYPT;

#ifdef __ENABLE_DIGICERT_TPM__
static MOCTAP_HANDLE mh;
static void *reqKeyContext = NULL;
static MKeyContextCallbackInfo callbackInfo;

static MSTATUS MOC_loadKeyContext( AsymmetricKey *pAsymKey, void *localInfo, ubyte4 state)
{
   MSTATUS status = OK;
   /* Initialize the TPM Context */

	if (OK > (status = MOCTAP_initializeTPMKeyContext(mh, pAsymKey, &reqKeyContext)))
	{
		printf("Unable to initialize TPM Key Context");
	}
  return status;
}
#endif
#ifdef __ENABLE_DIGICERT_TAP__
static TAP_EntityCredentialList *g_pEntityCredList = NULL;
static TAP_CredentialList       *g_pTapKeyCred    = NULL;
static TAP_ModuleList g_moduleList                = { 0 };
#define KEY_SOURCE_TPM2 "TPM2"

static MSTATUS
getTapContext(TAP_Context **ppTapContext,
		         TAP_EntityCredentialList **ppTapEntityCred,
		         TAP_CredentialList **ppTapKeyCred, void *pKey,
                 TapOperation op, ubyte getContext);

static
MSTATUS tapUninitialize()
{
    MSTATUS status = OK;
    TAP_ErrorContext errContext;

    status = TAP_freeModuleList(&g_moduleList);
    if (OK != status)
    {
        goto exit;
    }

    if (g_pEntityCredList)
    {
        TAP_UTILS_clearEntityCredentialList(g_pEntityCredList);
        DIGI_FREE((void **)&g_pEntityCredList);
    }

    if (g_pTapKeyCred)
    {
        TAP_UTILS_clearCredentialList(g_pTapKeyCred);
        DIGI_FREE((void **)&g_pTapKeyCred);
    }

    status = TAP_uninit(&errContext);
    if (OK != status)
        printf("tapUninitialize::TAP_uninit::status:%d\n ", status);

exit:
    return status;
}

static MSTATUS TAP_initialize(ubyte2 moduleId, sbyte *keySource)
{
	MSTATUS status = OK;
    TAP_ConfigInfoList configInfoList = { 0, };
    TAP_ErrorContext errContext;
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_EntityCredentialList *pEntityCredentialList = NULL;
    ubyte2 tapProvider = 0;
#ifdef __ENABLE_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
#else
    char *pTpm2ConfigFile = NULL;
#endif

    /* Initialize */
	//ubyte keyUsage = TAP_KEY_USAGE_SIGNING;
	//ubyte keyType = TAP_KEY_ALGORITHM_RSA;
	//ubyte keySize = TAP_KEY_SIZE_2048;

    if(DIGI_STRCMP((const sbyte *)keySource, (const sbyte *)"TPM2") == 0)
    {
        tapProvider = TAP_PROVIDER_TPM2;
    }
    else if(DIGI_STRCMP((const sbyte *)keySource, (const sbyte *)"GEMSIM") == 0)
    {
        tapProvider = TAP_PROVIDER_GEMSIM;
    }
    else if(DIGI_STRCMP((const sbyte *)keySource, (const sbyte *)"STSAFE") == 0)
    {
        tapProvider = TAP_PROVIDER_STSAFE;
    }
    else if(DIGI_STRCMP((const sbyte *)keySource, (const sbyte *)"SGX") == 0)
    {
        tapProvider = TAP_PROVIDER_SGX;
    }
    else
    {
        status = ERR_TAP_NO_PROVIDERS_AVAILABLE;
        goto exit;
    }

    status = DIGI_CALLOC((void **)&(configInfoList.pConfig), 1, sizeof(TAP_ConfigInfo));
    if (OK != status)
    {
        printf("\nMOC_CALLOC::status: %d", status);
        goto exit;
    }
#ifndef __ENABLE_TAP_REMOTE__
#if defined(__RTOS_WIN32__)
        status = TAP_UTILS_getWinConfigFilePath(&pTpm2ConfigFile, TPM2_CONFIGURATION_FILE);
        if (OK != status)
        {
            goto exit;
        }
#else
        pTpm2ConfigFile = TPM2_CONFIGURATION_FILE;
#endif
    status = TAP_readConfigFile(pTpm2ConfigFile,
                   &configInfoList.pConfig[0].configInfo, TRUE);
    if (OK != status)
    {
        printf("\nDIGICERT_readFile::status: %d", status);
        goto exit;
    }

    configInfoList.count = 1;
    configInfoList.pConfig[0].provider = tapProvider;
#endif

    status = TAP_init(&configInfoList, pErrContext);
    if (OK != status)
    {
        printf("\nTAP_init::status: %d", status);
        goto exit;
    }
#ifdef __ENABLE_TAP_REMOTE__
    /* Discover modules */
    connInfo.serverName.bufferLen = DIGI_STRLEN((char *)taps_ServerName)+1;
    status = DIGI_CALLOC ((void **)&(connInfo.serverName.pBuffer), 1, connInfo.serverName.bufferLen);
    if (OK != status)
    goto exit;

    status = DIGI_MEMCPY ((void *)(connInfo.serverName.pBuffer), (void *)taps_ServerName, DIGI_STRLEN(taps_ServerName));
    if (OK != status)
    goto exit;

    connInfo.serverPort = taps_ServerPort;

    status = TAP_getModuleList(&connInfo, TAP_PROVIDER_TPM2, NULL,
                               &g_moduleList, pErrContext);
#else
    status = TAP_getModuleList(NULL, TAP_PROVIDER_TPM2, NULL,
                               &g_moduleList, pErrContext);
#endif
    if (OK != status)
    {
        printf("\nTAP_getModuleList::status: %d", status);
        goto exit;
    }


#ifndef __ENABLE_TAP_REMOTE__
    status = TAP_getModuleCredentials(&(g_moduleList.pModuleList[0]),
            pTpm2ConfigFile, TRUE,
            &pEntityCredentialList,
            pErrContext);

    if (OK != status)
    {
        printf("\nTAP_getModuleCredentials::status: %d", status);
        goto exit;
    }
#endif

    g_pEntityCredList = pEntityCredentialList;
    g_pTapKeyCred = NULL;

exit:
#ifdef __ENABLE_TAP_REMOTE__
    if (NULL != connInfo.serverName.pBuffer)
        FREE((void *)connInfo.serverName.pBuffer);
#endif
    /* Free config info */
    if (NULL != configInfoList.pConfig)
    {
        status = TAP_UTILS_freeConfigInfoList(&configInfoList);
        if (OK != status)
            printf("\nTAP_UTILS_freeConfigInfoList::status: %d", status);
    }

    return status;
}

static MSTATUS
getTapContext(TAP_Context **ppTapContext,
        TAP_EntityCredentialList **ppTapEntityCred,
        TAP_CredentialList **ppTapKeyCred, void *pKey,
        TapOperation op,ubyte getContext)
{
    MSTATUS status = OK;
    TAP_ErrorContext *pErrContext = NULL;

    if (pKey == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if (getContext)
    {
        /* Initialize context on first module */
        status = TAP_initContext(&(g_moduleList.pModuleList[0]),
            g_pEntityCredList, NULL, ppTapContext, pErrContext);
        if (OK != status)
        {
            printf("TAP_initContext : %d\n", status);
            goto exit;
        }

        *ppTapEntityCred = g_pEntityCredList;
        *ppTapKeyCred    = g_pTapKeyCred;
    }
    else
    {
        /* Destroy the TAP context */
        if (OK > (status = TAP_uninitContext(ppTapContext, pErrContext)))
        {
            printf("TAP_uninitContext failed with status: %d\n", status);
        }
    }

exit:
    return status;
}
#endif /*__ENABLE_DIGICERT_TAP__*/

void prn_usage(char *prog)
{
    fprintf(stderr, "Usage: %s [-s] -p <private-key-pem-file> [-c <cleartext>] [-d]\n"
	    "    -s - Request Sign & verify operation (default is encrypt/decrypt)\n"
	    "    -p <file> - OpenSSL private key in PEM format.\n"
	    "        You can generate this file using\n"
	    "        %% openssl genrsa -out private.pem 2048\n"
	    "    -c <string> - Cleartext string to be encrypted or signed. It can be\n"
	    "                  given multiple times. The requested operation will be\n"
	    "                  performed on each string\n"
	    "    -d - Enable debug prints\n"
	    "    -m - module id in case of TAP key\n"
	    "    -k - key source as TPM2\n"
	    ,prog);
}

static unsigned char result[512];
static int debug = 1;

int main(int argc, char *argv[])
{
#if (defined(__ENABLE_DIGICERT_TPM__) || defined(__ENABLE_DIGICERT_TAP__))
   MSTATUS status = OK;
#endif
    int 	rv;
    FILE      * fp = NULL;
    EVP_PKEY  * pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t 	outlen = 0, inlen = 0;
    ENGINE    * e = NULL;
    unsigned char      * out = NULL;
    int		c = 0;
    size_t 	reslen = 0;
    int		n = 0;
    const char *clear = 0;
    unsigned char hash[32] = "\0";
#ifdef __ENABLE_DIGICERT_TAP__
    int moduleId = 0;
    char *keySource = NULL;
    byteBoolean useTap = FALSE;
#endif

#ifdef __ENABLE_DIGICERT_TAP__
    while ((c = getopt(argc, argv, "p:c:sdm:k:")) != -1) {
#else
    while ((c = getopt(argc, argv, "p:c:sd")) != -1) {
#endif
	    switch(c) {
	    case 'p':
	        priv_key_pem = optarg;
	        break;
	    case 'c':
	        if (num_clear_texts >= MAX_NUM_CLEAR_TEXTS) {
		        printf("Ignoring clear text string (limit of %d exceeded)", MAX_NUM_CLEAR_TEXTS);
		        break;
	        }
#ifdef __RTOS_WIN32__
	        clear_texts[num_clear_texts++] = _strdup(optarg);
#else
	        clear_texts[num_clear_texts++] = strdup(optarg);
#endif
	        break;
	    case 'd':
	        ++debug;
	        break;
	    case 's':
	        operation = OPER_SIGN;
	        break;
#ifdef __ENABLE_DIGICERT_TAP__
	    case 'm':
	        moduleId = strtol(optarg, NULL, 10);
	        break;
	    case 'k':
	        keySource = optarg;
	        break;
#endif
	    default:
	        prn_usage(argv[0]);
            goto exit;
	    }
    }
    if (NULL == priv_key_pem) {
	    fprintf(stderr, "Error: You must provide private key PEM filename\n");
	    prn_usage(argv[0]);
        goto exit;
    }
#ifdef __ENABLE_DIGICERT_TAP__
    if ((keySource != NULL) && (0 == DIGI_STRCMP((const sbyte *)keySource, (const sbyte *)KEY_SOURCE_TPM2)))
    {
        useTap = TRUE;
    }
#endif

	FIPS_mode_set(getenv("EVP_FIPS_RUNTIME_TEST") ? 1 : 0);
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();

#ifdef __ENABLE_DIGICERT_TPM__
    callbackInfo.KeyContextCallback = MOC_loadKeyContext;
#endif

#ifdef __ENABLE_DIGICERT_TAP__
    if (TRUE == useTap)
    {
        printf("using tap - initializing...\n");
        if (OK > (status = DIGICERT_initDigicert()))
        {
            printf("Error in DIGICERT_initDigicert() status = %d\n", status);
            goto exit;
        }
        if (OK > (status = TAP_initialize(moduleId, (sbyte * )keySource)))
        {
            printf("Error in TAP_initialize() status = %d\n", status);
            goto exit;
        }
        /* Register this callback with Crypto Wrapper to get TAPContext.*/
        if (OK > (status = CRYPTO_INTERFACE_registerTapCtxCallback(getTapContext)))
        {
            printf("Error in CRYPTO_INTERFACE_registerTapCtxCallback() status = %d\n",
                status);
            goto exit;
        }
    }
#endif
    ENGINE_load_builtin_engines();

    e = ENGINE_by_id("mocana");
    if (e == NULL) {
        /*
         * A failure to load is probably a platform environment problem so we
         * don't treat this as an OpenSSL test failure, i.e. we return 0
         */
        fprintf(stderr,
                "Mocana Test: Failed to load Mocana Engine - skipping test\n");
        return -1;
    }
#if defined(__ENABLE_DIGICERT_OPENSSL_DYNAMIC_ENGINE__)
    if (0 == ENGINE_set_default(e, ENGINE_METHOD_ALL))
    {
        printf("Setting the Engine methods failed");
        return -1;
    }
#endif

    if ((fp = fopen(priv_key_pem, "r")) == NULL) {
      printf("Error %s opening file %s\n", strerror(errno), argv[1]);
      goto exit;
    }
    ENGINE_set_default_RAND(e);
#ifdef __ENABLE_DIGICERT_TPM__
#ifdef __ENABLE_DIGICERT_TPM_EMULATOR__
        if (OK > (status = MOCTAP_initSecurityDescriptor(NULL, NULL, NULL, secmod_TPM12RSAKey, 9, (ubyte *)"localhost", &mh)))
#else
        if (OK > (status = MOCTAP_initSecurityDescriptor(NULL, NULL, NULL, secmod_TPM12RSAKey, 9, (ubyte *)"/dev/tpm0", &mh)))
#endif
	{
		printf("Error Unable to initialize MOCTAP Context");
        goto exit;

	}

#endif
#ifdef __ENABLE_DIGICERT_TPM__
    pkey = ENGINE_load_private_key(e, priv_key_pem, NULL, (void *)&callbackInfo);
#else
    pkey = ENGINE_load_private_key(e, priv_key_pem, NULL, NULL);
#endif
    /*pkey = ENGINE_load_private_key(e, priv_key_pem, NULL, NULL);*/

    /*pkey = PEM_read_PrivateKey(fp, NULL,  NULL, NULL);*/
    /* rv = PEM_read_PUBKEY(fp2, &pub_pkey, PEM_STRING_PUBLIC, PUBKEY); */
    if (debug) {
	    printf("EVP_PKEY = %p\n", pkey);
    }
    fclose(fp);
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
      printf("Error creating context\n");
      goto exit;
    }
    for (n = 0; n < num_clear_texts; ++n) {
	clear = clear_texts[n];
	inlen = strlen(clear);
	if (debug) {
	    if (OPER_ENCRYPT == operation)
		    printf("Encrypting %d bytes of cleartext: %s\n", (int)inlen, clear);
	    else
		    printf("Signing %d bytes of digest: %s\n", (int)inlen, clear);
	}

	if (OPER_ENCRYPT == operation) {
	    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
		    printf("Error in encrypt_init ctx\n");
            goto exit;
	    }
	    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, (const unsigned char *)clear, inlen) <= 0) {
		    printf("Error in encrypt\n");
            goto exit;
	    }
	} else {
	    if (EVP_PKEY_sign_init(ctx) <= 0) {
		    printf("Error in sign_init ctx\n");
            goto exit;
	    }

        EVP_Digest(clear, strlen((char *)clear), hash, NULL, EVP_sha256(), NULL);

	    if (EVP_PKEY_sign(ctx, NULL, &outlen, hash, 32) <= 0) {
		    printf("Error in sign with NULL buffer\n");
            goto exit;
	    }
	}
	out = OPENSSL_malloc(outlen);
	if (OPER_ENCRYPT == operation) {
	    if (EVP_PKEY_encrypt(ctx, out, &outlen, (const unsigned char *)clear, inlen) <= 0) {
		    printf("Error in encrypt\n");
	    }
	} else {
	    if (EVP_PKEY_sign(ctx, out, &outlen, hash, 32) <= 0) {
		    printf("Error in sign with NULL buffer\n");
            goto exit;
	    }
	}
	if (debug) {
	    if (OPER_ENCRYPT == operation)
		    printf("%d bytes of Ciphertext\n", (int)outlen);
	    else
		    printf("%d bytes of Signature\n", (int)outlen);
	    if (debug > 1) {
		    prn_b64(out, outlen);
	    }
	}
	/*
	 pkey = ENGINE_load_private_key(e, priv_key_pem, NULL, (void *)keyCallBack);
     ctx = EVP_PKEY_CTX_new(pkey, NULL);
      if (!ctx) {
            printf("Error creating context\n");
            exit(1);
      }
     */
	if (OPER_ENCRYPT == operation) {
	    if (0 >= (rv = EVP_PKEY_decrypt_init(ctx))) {
		    printf("decrypt_init returns error\n");
            goto exit;
	    }
	} else {
	    if (0 >= (rv = EVP_PKEY_verify_init(ctx))) {
		    printf("verify_init returns error\n");
            goto exit;
	    }
	}
	reslen = sizeof(result);
	if (OPER_ENCRYPT == operation) {
	    if (0 >= (rv = EVP_PKEY_decrypt(ctx, result, &reslen, out, outlen))) {
		    printf("decrypt returns error\n");
            goto exit;
	    }
	    result[reslen] = '\0';
	    printf("Recovered plaintext: %s\n", result);
	} else {
	    if (0 >= (rv = EVP_PKEY_verify(ctx, out, outlen, hash, 32))) {
		    printf("verification returns error\n");
            goto exit;
	    } else if (rv == 1) {
		    printf("Signature verified OK for %s\n", clear);
	    }
	}
	OPENSSL_free(out);
	out = NULL;
    }
#ifdef __ENABLE_DIGICERT_TPM__
    if (reqKeyContext && OK > (status = MOCTAP_deinitializeTPMKeyContext(mh, &reqKeyContext)))
    {
		printf("Unable to deinitialize TPM Key Context");
    }
#endif
exit:
#ifdef __ENABLE_DIGICERT_TAP__
    if (TRUE == useTap)
    {
        tapUninitialize();
        DIGICERT_freeDigicert();
    }
#endif
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    ENGINE_free(e);
    EVP_cleanup();
    ENGINE_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();
}

static void
prn_b64(unsigned char *in, int inlen)
{
    BIO	      * b64, *bio;
    BUF_MEM   * bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_write(bio, in, inlen);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);
    printf("%s", (*bufferPtr).data);
    fflush(stdout);
}
