/*
 * nanotap_api_example.c
 *
 * Sample code demonstrating the usage of NanoTAP API.
 *
 * Copyright Mocana Corp 2017. All Rights Reserved.
 * Proprietary and Confidential Material.
 * 
 */


#if (defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_EXAMPLES__))

/*------------------------------------------------------------------*/
/* Includes for this example
 */

#include <stdio.h>

#include "../common/initmocana.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/aes.h"
#include "../crypto/des.h"
#include "../crypto/three_des.h"
#include "../crypto/nist_rng_types.h"
#include "../crypto/nist_rng.h"
#include "../tap/tap_smp.h"
#include "../tap/tap_api.h"
#include "../tap/tap_utils.h"
#include "../common/debug_console.h"
#include "../crypto/cert_store.h"
#include "../common/sizedbuffer.h"
#include "../crypto/pkcs8.h"
#include "../tap/tap_conf_common.h"
#if defined(__RTOS_LINUX__) || (__RTOS_OSX__)
#include "getopt.h"
#endif /*defined(__RTOS_LINUX__) || (__RTOS_OSX__)*/

#ifdef __RTOS_WIN32__
#include "../common/mcmdline.h"
#endif

#if 0
#define SSL_ROOT_CERTIFICATE    "/etc/mocana/intermediate.cert.der"
#define SSL_CERTIFICATE_KEY     "/etc/mocana/ssltest.mydomain.net.key.pem"
#define SSL_CERTIFICATE         "/etc/mocana/ssltest.mydomain.net.cert.der"
#endif

#define SSL_ROOT_CERTIFICATE    "rootcert.der"
#define SSL_CERTIFICATE_KEY     "clientkey.pem"
#define SSL_CERTIFICATE         "clientcert.der"

#ifdef __ENABLE_TAP_REMOTE__
certStorePtr pSslCertStore = NULL;
TAP_Buffer tapClientConfig = {0};
#endif

#ifdef __ENABLE_DIGICERT_NXPA71__
#include "a71ch_api.h"
#include "a71ch_const.h"
#include "ax_util.h"
#include "../smp/smp_nxpa71/smp_nxpa71.h"
#endif

/*------------------------------------------------------------------*/
/* MACRO definitions used in example code
 */
#define PRINT_ERR(STATUS, MESSAGE) \
                printf("%s.%d: ERROR! %s, status=%d\n", \
                        __FUNCTION__, __LINE__, MESSAGE, STATUS)


#define PRINT_SUCCESS(MESSAGE)\
                printf("%s.%d: SUCCESS! %s\n", \
                        __FUNCTION__, __LINE__, MESSAGE)

#define PRINT_TEST_HEADER(MESSAGE)\
                DB_PRINT("\n---------- %s ----------\n", MESSAGE)

#define PRINT_TEST_FOOTER(MESSAGE)\
                DB_PRINT("---------- %s ----------\n\n", MESSAGE)

#if defined(__RTOS_WIN32__)
#define TPM2_CONFIGURATION_FILE "tpm2.conf"
#else
#include "../common/tpm2_path.h"
#endif

#define NanoROOT_CONFIGURATION_FILE "./config/nanoroot_smp.conf"

typedef struct
{
    char *pName;
    ubyte4 val;
} OPT_VAL_INFO;

typedef ubyte MODE_NAME;
#define FS_MODE         ((ubyte)0)
#define NON_FS_MODE     ((ubyte)1)
/*------------------------------------------------------------------*/
/* Types defined for this example
 */

/* initModuleConfig
 * Pointer to a function that would return TAP_configInfo for
 * respective module
 * In order to include a new module to test, write a new method
 * to return its configuration and append the pointer to 
 * the array configInfoList in main()
 * 
 * configInfo: OUT : TAP_ConfigInfo to be allocated and initialized
 *                      by implementer for respective module
 * Returns OK for success, or a failure status code.
 */
typedef MSTATUS (*EXAMPLE_initConfigCallback) (TAP_ConfigInfo* configInfo);

/*------------------------------------------------------------------*/
/* internal data types for example
*/

#define FILE_PATH_LEN 256
#define SERVER_NAME_LEN 256
char *pTpm2ConfigFile = NULL;
typedef struct {
    byteBoolean exitAfterParse;

    byteBoolean tpm2ConfigFileSpecified;
    char tpm2confFilePath[FILE_PATH_LEN];

#ifdef __ENABLE_TAP_REMOTE__
    ubyte4 serverNameLen;
    ubyte4 serverPort;

    byteBoolean serverNameSpecified;
    byteBoolean modeNameSpecified ;
    char serverName[SERVER_NAME_LEN];
    MODE_NAME modeName;

#endif

} CmdLineOpts;

/* Platform specific command line parsing. */
typedef MSTATUS (*platformParseCmdLineOpts)(CmdLineOpts *pOpts, 
                                        int argc, char *argv[]);

/*------------------------------------------------------------------*/
/* Function forward declarations
 */
extern MSTATUS EXAMPLE_init(EXAMPLE_initConfigCallback* pConfigInfoCallbacks, 
                            ubyte4 count);
extern MSTATUS EXAMPLE_uninit(byteBoolean isTapInit);

extern MSTATUS initTapModule(TAP_Module *pModule, TAP_Context **ppTapContext);
extern MSTATUS uninitTapModule(TAP_Context **ppTapContext);

extern MSTATUS getSmpList(TAP_ModuleList **ppModuleList);
extern MSTATUS getSmpVersionInfo(TAP_Module* pTapModule);

extern MSTATUS checkModuleProvisioned(TAP_Module* pModule, 
                                      byteBoolean* pIsProvisioned);

extern MSTATUS runTests(TAP_Module *pModule, TAP_Context* pTapContext);
extern MSTATUS runSelfTest(TAP_Context *pTapContext);
extern MSTATUS runKeyTests(TAP_Context *pTapContext);
extern MSTATUS runRngTest(TAP_Context *pTapContext);
extern MSTATUS runPolicyStorageTest(TAP_Context *pTapContext);
extern MSTATUS runTrustedDataTest(TAP_Context *pTapContext);
extern MSTATUS runSealUnsealTest(TAP_Context *pTapContext);
extern MSTATUS runRootTrustTest(TAP_Module *pModule, 
                                           TAP_Context *pTapContext);
extern MSTATUS initTapConfigInfo(TAP_ConfigInfo* configInfo);
extern const char* getTapProviderName(TAP_PROVIDER provider);
extern void printTapAttributes(const TAP_AttributeList *pAttrList);
extern void printTapBuffer(const TAP_Buffer* pTapBuffer);
extern TAP_Buffer* getPlainTextToEncrypt(void);
MOC_EXTERN MSTATUS TAP_ECDH_generateSharedSecret(TAP_Key *pTapKey,
                    TAP_AttributeList *pOpAttributes,
                    TAP_PublicKey *pPeerPublicKey, TAP_Buffer *pSharedSecret,
                    TAP_ErrorContext *pErrContext);
#if defined(__ENABLE_DIGICERT_NXPA71__)
/*Function to create NXPA71 configuration*/
extern MSTATUS initNXPA71TapConfigInfo(TAP_ConfigInfo* configInfo);
#endif

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)
MSTATUS pasrseCmdLineOpts(CmdLineOpts *pOpts, int argc, char *argv[]);
#endif /*defined(__RTOS_LINUX__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)
*/

/*------------------------------------------------------------------*/
/* Globals
 */
TAP_ErrorContext            gErrContext;
TAP_ConnectionInfo*         gpConnInfo = NULL;
TAP_EntityCredentialList*   gpEntityCredentials = NULL;
ubyte4                      gApplicationState = 0x00;
CmdLineOpts                 gCmdLineOpts = {0};

/*------------------------------------------------------------------*/
#define APP_STATE_TAP_INIT      0x00000001


/*------------------------------------------------------------------*/

MSTATUS
EXAMPLE_loadCertificateAndKey(const char *certificateFileName,
        const char *certificateKeyFileName,
        certStorePtr pSslCertStore)
{
    MSTATUS status = OK;
    certDescriptor retCertDescr = {0};
    SizedBuffer certificate[1];
    ubyte *keyBlob = NULL;
    ubyte4 keyBlobLength = 0;

    if (0 > (status = DIGICERT_readFile(certificateFileName,
                                      &retCertDescr.pCertificate,
                                      &retCertDescr.certLength)))
        goto exit;
  
    if (0 > (status = DIGICERT_readFile(certificateKeyFileName,
                             &keyBlob,
                             &keyBlobLength)))
        goto exit;

    /* Try PKCS1 format first */
    if (OK != (status = CA_MGMT_convertKeyPEM(keyBlob, keyBlobLength,
        &retCertDescr.pKeyBlob, &retCertDescr.keyBlobLength)))
    {
        if (OK != (status = PKCS8_decodePrivateKeyPEM(keyBlob, keyBlobLength,
                        &retCertDescr.pKeyBlob, &retCertDescr.keyBlobLength)))
        {
            goto exit;
        }
    }

    certificate[0].data = retCertDescr.pCertificate;
    certificate[0].length = retCertDescr.certLength;

    if (OK > (status = CERT_STORE_addIdentityWithCertificateChain(
                    pSslCertStore, certificate, 1,
                    retCertDescr.pKeyBlob, retCertDescr.keyBlobLength)))
        goto exit;

exit:
    if (retCertDescr.pKeyBlob)
        FREE(retCertDescr.pKeyBlob);

    if(retCertDescr.pCertificate)
        DIGICERT_freeReadFile(&retCertDescr.pCertificate);

    if(keyBlob)
        DIGICERT_freeReadFile(&keyBlob);

    return status;
}

/*------------------------------------------------------------------*/

/* main
 * Flow: 
 *  Initialize the configuration list
 *  Get list of modules on execution host
 *  Iterate through each module
 *      initializes tap_context for each module
 *      executes test code for each module
 *      Uninitialize context for each module
 */
#ifdef __ENABLE_DIGICERT_NXPA71__
int nanotap_api_example(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
{
    MSTATUS                     status = OK;
    TAP_Module*                 pModule = NULL;
    TAP_ModuleList*             pModuleList = NULL;
    ubyte4                      iter = 0;
    TAP_Context*                pTapContext = NULL;
    platformParseCmdLineOpts    platCmdLineParser = NULL;
#ifdef __ENABLE_TAP_REMOTE__
    ubyte* certData = NULL;
    ubyte4 certLength = 0;
    ubyte *tapClientConfigBuffer = (ubyte *)"enableunsecurecomms=0\nenablemutualauthentication=1\nserverport=8277\n"; 
#endif

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)
    platCmdLineParser = pasrseCmdLineOpts;
#endif

#ifdef __ENABLE_DIGICERT_NXPA71__
    EXAMPLE_initConfigCallback configInfoCallbackList[] =
    {
        initNXPA71TapConfigInfo,
        NULL
    };
#else
    if (NULL == platCmdLineParser)
    {
        status = ERR_GENERAL;
        PRINT_ERR(status, "No command line parser available for this platform");
        goto exit;
    }
    status = platCmdLineParser(&gCmdLineOpts, argc, argv);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed to parse command line options.");
        goto exit;
    }
    
    if (TRUE == gCmdLineOpts.exitAfterParse)
    {
        goto exit;
    }

    /* Append new methods before NULL for additional modules to be executed */
    EXAMPLE_initConfigCallback configInfoCallbackList[] = 
    {
#ifndef __ENABLE_TAP_REMOTE__
        initTapConfigInfo,
#else
        NULL,
#endif
        NULL
    };
#endif

#ifdef __ENABLE_TAP_REMOTE__
    /* Initialize Cert Store*/
    tapClientConfig.bufferLen = DIGI_STRLEN((const sbyte*)tapClientConfigBuffer);
    tapClientConfig.pBuffer = tapClientConfigBuffer;

    if(gCmdLineOpts.modeNameSpecified)
    {
        if(gCmdLineOpts.modeName == NON_FS_MODE)
        {
            if (OK == (status = DIGICERT_readFile(SSL_ROOT_CERTIFICATE, &certData, &certLength)))
            {
                if (OK != (status = CERT_STORE_createStore(&pSslCertStore)))
                    goto exit;

                if (OK > (status = CERT_STORE_addTrustPoint(pSslCertStore, certData, certLength)))
                    goto exit;

                status = EXAMPLE_loadCertificateAndKey(SSL_CERTIFICATE,
                        SSL_CERTIFICATE_KEY,
                        pSslCertStore);
                if(OK > status)
                    goto exit;
            }
            else
            {
                pSslCertStore = NULL;
                status = OK;
            }
        }
    }
#endif
    PRINT_TEST_HEADER("Mocana TAP initialization");
    status = EXAMPLE_init(configInfoCallbackList, 1);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed to initialize TAP");
        goto exit;
    }
    PRINT_TEST_FOOTER("Mocana TAP initialization");
    gApplicationState |= APP_STATE_TAP_INIT;


    PRINT_TEST_HEADER("Get list of Providers and Modules");
    status = getSmpList(&pModuleList);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed to fetch list of SMPs");
        goto exit;
    }
    PRINT_TEST_FOOTER("Get list of Providers and Modules");
    
    printf("Iterating through the available Module list ...\n");
    for (iter=0; iter < pModuleList->numModules; iter++)
    {
        pModule = (TAP_Module *)&(pModuleList->pModuleList[iter]);
#if defined(__ENABLE_DIGICERT_GEMALTO__) || defined(__ENABLE_DIGICERT_PKCS11__)
        if (pModule->moduleId == 0)/* Ignore Software module*/
            continue;
#endif
        DB_PRINT("%s.%d Initializing %d-th module of type=%s\n", 
                __FUNCTION__, __LINE__, iter+1,
                getTapProviderName(pModule->providerType));

        status = initTapModule(pModule, &pTapContext);
        if ( (OK != status) || (NULL==pTapContext) )
        {
            PRINT_ERR(status, "Failed initializing module");
            goto module_exit;
        }
        PRINT_SUCCESS("Module Initialized ...");

        status = runTests(pModule, pTapContext);
        if (OK != status)
        {
            PRINT_ERR(status, "Failed execution for module");
            goto module_exit;
        }
    module_exit:
        status = uninitTapModule(&pTapContext);
        pModule++;
    }

exit:
    EXAMPLE_uninit((gApplicationState & APP_STATE_TAP_INIT) ? TRUE : FALSE);
    gApplicationState &= ~APP_STATE_TAP_INIT;

    if (NULL != pModuleList)
    {
        TAP_freeModuleList(pModuleList);  
        DIGI_FREE((void**)&pModuleList);
    }

    if (NULL != gpEntityCredentials)
    {
        TAP_UTILS_clearEntityCredentialList(gpEntityCredentials);

        DIGI_FREE((void **)&gpEntityCredentials);
    }

#ifdef __ENABLE_TAP_REMOTE__
    if (certData)
        DIGI_FREE((void **)&certData);
#endif
    return status;
}


/*------------------------------------------------------------------*/

/* EXAMPLE_init
 * Function to perform initialization for this example.
 * Initializes top MOCANA and TAP layer.
 * pConfigInfoCallbacks - IN : Array of Callbacks to fetch 
 *                             module specific config
 * count - IN : Count of callbacks in pConfigInfoCallbacks
 */
MSTATUS 
EXAMPLE_init(EXAMPLE_initConfigCallback* pConfigInfoCallbacks, ubyte4 count)
{
    MSTATUS             status = OK;
    TAP_ConfigInfoList  configInfoList = {0, NULL};
    ubyte4              i=0;

    /* Initialize using default setup by passing in NULL */
    status = DIGICERT_initialize(NULL, NULL);
    if (OK != status)
    {
        PRINT_ERR(status, "Mocana Init failed");
        goto exit;
    }
    PRINT_SUCCESS("MOCANA Initialized successfully!");

    status = DIGI_CALLOC((void **)&(configInfoList.pConfig), count, sizeof(TAP_ConfigInfo));
    if (OK != status)
    {
        PRINT_ERR(status, "Failed allocating memory for config list");
        goto exit;
    }
    configInfoList.count = count;

    DB_PRINT("%s.%d Iterating through the modules to be configured...\n",
            __FUNCTION__, __LINE__);
    count=0;
    while (NULL != *pConfigInfoCallbacks)
    {
        DB_PRINT("%s.%d Attempting to Configure %d-th module ...\n", 
                __FUNCTION__, __LINE__, count+1);
        status = (*pConfigInfoCallbacks)(configInfoList.pConfig + count);
        if (OK != status)
        {
            PRINT_ERR(status, "Failed to retrieved a module configuration");
            goto exit;
        }
        PRINT_SUCCESS("Module configured");
        pConfigInfoCallbacks++;
        count++;
    }

#ifdef __ENABLE_TAP_REMOTE__
    if(gCmdLineOpts.modeNameSpecified)
    {
        if(gCmdLineOpts.modeName == NON_FS_MODE)
        {
            DB_PRINT("Calling TAP_initEx ...\n");

            status = TAP_initEx(&tapClientConfig,pSslCertStore);

            if(OK > status)
                goto exit;
        }
    }
#endif
    DB_PRINT("Calling TAP_init ...\n");
    status = TAP_init(&configInfoList, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "TAP_init failed");
        goto exit;
    }
    PRINT_SUCCESS("TAP Init completed successfully");

exit:
    if (NULL != configInfoList.pConfig)
    {
        for (i=0; i < configInfoList.count; i++)
        {
            if (NULL != configInfoList.pConfig[i].configInfo.pBuffer)
                TAP_UTILS_freeBuffer(&(configInfoList.pConfig[i].configInfo));
        }
        DIGI_FREE((void **) &(configInfoList.pConfig));
    }

    return status;
}


/*------------------------------------------------------------------*/

/* EXAMPLE_uninit
 * Uninitialize the top MOCANA and TAP layer,
 * that was initialized in EXAMPLE_init()
 * Demonstrates usage of - 
 *  TAP_uninit
 *  DIGICERT_free
 */
MSTATUS EXAMPLE_uninit(byteBoolean isTapInit)
{
    MSTATUS status = OK;
    
    if (isTapInit)
    {
        status = TAP_uninit(&gErrContext);
#ifdef __ENABLE_TAP_REMOTE__
        status = TAP_uninitEx();

        if (pSslCertStore)
            CERT_STORE_releaseStore(&pSslCertStore);
#endif
    }

#ifdef __RTOS_WIN32__
    if (  (NULL != pTpm2ConfigFile)
       && (FALSE == gCmdLineOpts.tpm2ConfigFileSpecified)
       )
    {
        DIGI_FREE(&pTpm2ConfigFile);
    }
#endif
    
    DIGICERT_free(NULL);

    return status;
}


/*------------------------------------------------------------------*/

/* initTapModule
 * Function to initialize a SE/SMP 
 *
 * Demonstrates usage of - 
 *  TAP_initContext
 */
MSTATUS initTapModule(TAP_Module *pModule, TAP_Context **ppTapContext)
{
    MSTATUS status = OK;
    /*TAP_EntityCredentialList* pModuleCredentials = NULL;*/
    TAP_AttributeList*  pAttributes = NULL;
    TAP_ErrorContext    gErrContext;

    if (NULL == pModule || NULL == ppTapContext)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "NULL input arguments received");
        goto exit;
    }
   
#ifndef __ENABLE_TAP_REMOTE__
    status = TAP_getModuleCredentials(pModule,
            pTpm2ConfigFile, gCmdLineOpts.tpm2ConfigFileSpecified,
            &gpEntityCredentials,
            &gErrContext);

    if (OK != status)
    {
        DB_PRINT("Failed to get credentials from Credential configuration file", status);
        goto exit;
    }
#endif 
    status = TAP_initContext(pModule, gpEntityCredentials, pAttributes,
                                ppTapContext, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed initializing context for TAP Module");
        goto exit;
    }

    if (NULL == *ppTapContext)
    {
        status = ERR_GENERAL;
        PRINT_ERR(status, "Error initializing tap context");
        goto exit;
    }
    PRINT_SUCCESS("TAP Module initialized");

exit:
    return status;
}


/*------------------------------------------------------------------*/

/* uninitTapModule
 * Function to uninitialize a SE/SMP 
 *
 * Demonstrates usage of - 
 *  TAP_uninitContext
 */
MSTATUS uninitTapModule(TAP_Context **ppTapContext)
{
    MSTATUS status = OK;

    /* uninitialize context */
    status = TAP_uninitContext(ppTapContext, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "TAP_uninitContext call failed");
    }
    else
    {
        PRINT_SUCCESS("TAP_Context uninitialized");
    }
    if (*ppTapContext)
    {
        status = DIGI_FREE((void **)ppTapContext);
        if (OK != status)
        {
            PRINT_ERR(status, "Failed releasing memory for ppTAPContext");
        }
        else
        {
            PRINT_SUCCESS("Released memory from ppTAPContext");
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

/* getSmpList
 * Function to retrieve the list of providers and modules available locally
 *
 * Demonstrates usage of - 
 *  TAP_getProviderList
 *  TAP_getModuleList
 *  TAP_getModuleVersionInfo
 */
MSTATUS getSmpList(TAP_ModuleList **ppModuleList)
{
    MSTATUS             status = OK;
    TAP_ProviderList    providerList = {0, NULL};
    int                 iter=0;
#ifndef __ENABLE_TAP_REMOTE__
    const char *        providerName = "";
#endif
    TAP_Module *        pIterTapModule = NULL;
    ubyte4              numModules;
#ifdef __ENABLE_TAP_REMOTE__
    TAP_ConnectionInfo connInfo = { 0 };
#endif

    if (NULL == ppModuleList)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "ppModuleList argument is NULL");
        goto exit;
    }
    if (NULL != *ppModuleList)
    {
        status = ERR_INVALID_ARG;
        PRINT_ERR(status, 
                "ppModuleList argument points to an existing memory space");
        goto exit;
    }

#ifndef __ENABLE_TAP_REMOTE__
    /* Get Provider List */
    status = TAP_getProviderList(gpConnInfo, &providerList, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed retrieving provider list");
        goto exit;
    }
    PRINT_SUCCESS("Retrieved Providers list");
    
    DB_PRINT("SMPs present on this host are as below:\n"
            "\tNo\tProvider\n"
            "\t--\t--------\n");
    for (iter=0; iter < providerList.listLen ; iter++)
    {
        providerName = getTapProviderName(providerList.pProviderCmdList[iter].provider);
        DB_PRINT("\t%d : %s\n", iter+1, providerName);
    }
#endif

#ifdef __ENABLE_TAP_REMOTE__
    /* Discover modules */
    connInfo.serverName.pBuffer = (ubyte *)gCmdLineOpts.serverName;
    connInfo.serverName.bufferLen = gCmdLineOpts.serverNameLen;
    connInfo.serverPort = gCmdLineOpts.serverPort;
#endif
    /* Get Modules list */
    status = DIGI_CALLOC((void **)ppModuleList, 1, sizeof(TAP_ModuleList));
    if (OK != status)
    {
        PRINT_ERR(status, "Error allocating memory for TAP_ModuleList");    
        goto exit;
    }
#if defined( __ENABLE_DIGICERT_TPM2__)
#ifdef __ENABLE_TAP_REMOTE__
#if 0
    /* Get Provider List */
    status = TAP_getProviderList(&connInfo, &providerList, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed retrieving provider list");
        goto exit;
    }
    PRINT_SUCCESS("Retrieved Providers list");
#endif
    status = TAP_getModuleList(&connInfo, TAP_PROVIDER_TPM2, NULL, *ppModuleList, &gErrContext);
#else
    status = TAP_getModuleList(NULL, TAP_PROVIDER_TPM2, NULL,
                               *ppModuleList, &gErrContext);
#endif
#elif defined(__ENABLE_DIGICERT_GEMALTO__)
    status = TAP_getModuleList(NULL, TAP_PROVIDER_GEMSIM, NULL,
                               *ppModuleList, &gErrContext);
#elif defined(__ENABLE_DIGICERT_SMP_PKCS11__)
    status = TAP_getModuleList(NULL, TAP_PROVIDER_PKCS11, NULL,
                               *ppModuleList, &gErrContext);
#elif defined (__ENABLE_DIGICERT_NXPA71__)
    status = TAP_getModuleList(NULL, TAP_PROVIDER_NXPA71, NULL,
                               *ppModuleList, &gErrContext);
#elif defined (__ENABLE_DIGICERT_SMP_NANOROOT__)
    status = TAP_getModuleList(NULL, TAP_PROVIDER_NANOROOT, NULL,
                               *ppModuleList, &gErrContext);
#endif    
    
    if (OK != status)
    {
        PRINT_ERR(status,"Failed getting modules list on current host");
        goto exit;
    }
    PRINT_SUCCESS("Retrieved modules list");

    numModules = (*ppModuleList)->numModules;
    if ((0 == (*ppModuleList)->numModules) || (NULL == (*ppModuleList)->pModuleList))
    {
        status = ERR_NOT_FOUND;
        DB_PRINT("TAP_getModuleList returned invalid list; numModules = %d, pModuleList = %p",
                 (*ppModuleList)->numModules, (*ppModuleList)->pModuleList);
        goto exit;
    }
    DB_PRINT("Found %d modules\n", numModules);

    DB_PRINT("\tNumber\tProvider-Type\n"
             "\t------\t-------------\n");
    for (iter=0; iter < numModules; iter++)
    {
        pIterTapModule = (TAP_Module *)&((*ppModuleList)->pModuleList[iter]);
        DB_PRINT("\t%d\t%s\n", iter+1, getTapProviderName(pIterTapModule->providerType));
    }

    DB_PRINT("Getting version info for first module ...\n");
#if defined(__ENABLE_DIGICERT_TPM2__ )|| defined(__ENABLE_DIGICERT_NXPA71__)
    status = getSmpVersionInfo(&((*ppModuleList)->pModuleList[0]));
#elif defined(__ENABLE_DIGICERT_GEMALTO__)
    status = getSmpVersionInfo(&((*ppModuleList)->pModuleList[1]));
#elif defined(__ENABLE_DIGICERT_SMP_PKCS11__)
    status = getSmpVersionInfo(&((*ppModuleList)->pModuleList[1]));
#endif

exit:
    /*Free provider list*/
    if (NULL != providerList.pProviderCmdList)
    {
        if ( OK != TAP_UTILS_freeProviderList(&providerList) )
        {
            DB_PRINT("%s.%d Failed to free memory for providerList\n",
                    __FUNCTION__, __LINE__);
        }
    }

   return status;
}


/*------------------------------------------------------------------*/

/* getSmpVersionInfo
 * Function to fetch version of a module 
 * Demonstrates usage of - 
 *  TAP_getModuleVersionInfo
 */
MSTATUS getSmpVersionInfo(TAP_Module* pTapModule)
{
    MSTATUS             status = OK;
    TAP_AttributeList   versionInfo = { 0 };
    ubyte4              i = 0;
    char *              pVendorInfo = NULL;
    int                 vIndex = 0;

    status = TAP_getModuleVersionInfo(pTapModule, &versionInfo, &gErrContext);
    
    if (OK != status)
    {
        PRINT_ERR(status, "TAP_getModuleVersionInfo");
        goto exit;
    }
    PRINT_SUCCESS("TAP_getModuleVersionInfo operation");

    if (NULL == versionInfo.pAttributeList)
    {
        status = ERR_NOT_FOUND;                                    
        PRINT_ERR(status, "TAP_getModuleVersionInfo returned "
                "an empty attribute list");
        goto exit;
    }

    DB_PRINT("SMP Version Info:\n");
    for (i = 0; i < versionInfo.listLen; i++)
    {
        if (NULL == versionInfo.pAttributeList[i].pStructOfType)
            break;
        switch(versionInfo.pAttributeList[i].type)
        {
            case TAP_ATTR_FIRMWARE_VERSION:
                printf("  Chip Version:  %08x.%08x\n", 
                       ((TAP_Version*)(versionInfo.pAttributeList[i].pStructOfType))->major,
                       ((TAP_Version*)(versionInfo.pAttributeList[i].pStructOfType))->minor);
                break;
            case TAP_ATTR_VENDOR_INFO:
                printf("  Vendor Info:  ");
                pVendorInfo = (char *)((TAP_Buffer*)(versionInfo.pAttributeList[i].pStructOfType))->pBuffer;
                for (vIndex = 0; vIndex < ((TAP_Buffer*)(versionInfo.pAttributeList[i].pStructOfType))->bufferLen; 
                        vIndex++)
                    printf("%c", pVendorInfo[vIndex]);

                printf("\n");
                break;
            default:
                break;
        }
    }

    status = TAP_UTILS_freeAttributeList(&versionInfo);
    if (OK != status)
    {
        PRINT_ERR(status, "TAP_UTILS_freeAttributeList");
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

/* runTests
 * Invokes methods to test below things on the module- 
 *  IsModuleProvisioned
 *  Executes self test
 *  Execute Random number generation test
 *  Executes collection of Key related tests
 */

MSTATUS runTests(TAP_Module *pModule, TAP_Context *pTapContext)
{
    MSTATUS         status = OK;
    byteBoolean     isModuleProvisioned = FALSE;

    DB_PRINT("\n---- RUNNING SAMPLE CODE FOR MODULE %d ----\n",
            pModule->moduleId); 

#ifndef __ENABLE_DIGICERT_SMP_NANOROOT__
    PRINT_TEST_HEADER("Checking Module provisioned");
    status = checkModuleProvisioned(pModule, &isModuleProvisioned);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed to check provisioned status");
        goto exit;
    }
    if (FALSE == isModuleProvisioned)
    {
       status = ERR_GENERAL;
       PRINT_ERR(status, "Module is not provisioned. Can't continue.");
       goto exit;
    }
    PRINT_SUCCESS("Module is provisioned");
    PRINT_TEST_FOOTER("Check Module provisioned");
#endif

#if defined(__ENABLE_DIGICERT_TPM2__)
    PRINT_TEST_HEADER("SelfTest");
    status = runSelfTest(pTapContext);
    PRINT_TEST_FOOTER("SelfTest completed");
#endif

#if defined(__ENABLE_DIGICERT_TPM2__) || defined(__ENABLE_DIGICERT_NXPA71__)
    PRINT_TEST_HEADER("Random number generation test");
    status = runRngTest(pTapContext);
    PRINT_TEST_FOOTER("Random number generation test completed");
#endif

#ifndef __ENABLE_DIGICERT_SMP_NANOROOT__
    PRINT_TEST_HEADER("KEY Test");
    status = runKeyTests(pTapContext);
    PRINT_TEST_FOOTER("KEY Test completed");
#endif

#if defined(__ENABLE_DIGICERT_TPM2__)
    PRINT_TEST_HEADER("Policy Storage Test");
    status = runPolicyStorageTest(pTapContext);
    PRINT_TEST_FOOTER("Policy Storage completed");
#endif

#if defined(__ENABLE_DIGICERT_TPM2__)
    PRINT_TEST_HEADER("Trusted Data READ / UPDATE Test");
    status = runTrustedDataTest(pTapContext);
    PRINT_TEST_FOOTER("Trusted Data READ / UPDATE Test");
#endif

#if defined(__ENABLE_DIGICERT_TPM2__) || defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
    PRINT_TEST_HEADER("Seal Unseal data test");
    status = runSealUnsealTest(pTapContext);
    PRINT_TEST_FOOTER("Seal Unseal data test");
#endif

 #if defined(__ENABLE_DIGICERT_TPM2__)
   PRINT_TEST_HEADER("Root of Trust certificate test");
    status = runRootTrustTest(pModule, pTapContext);
    PRINT_TEST_FOOTER("Root of Trust certificate test");
#endif
exit:
    DB_PRINT("\n---- FINISHED RUNNING SAMPLE CODE FOR MODULE %d ----\n", 
            pModule->moduleId);
    return status;
}


/*------------------------------------------------------------------*/

/* checkModuleProvisioned
 * pModule : IN : ptr to TAP_Module to check for provisioned status
 * pIsProvisioned : OUT : ptr to byteBoolean. 
 *           set to TRUE if the module is provisioned else FALSE.
 * Returns OK on success.
 *
 * Demonstrates usage of - 
 *  TAP_isModuleProvisioned
 */
MSTATUS 
checkModuleProvisioned(TAP_Module* pModule, byteBoolean* pIsProvisioned)
{
    MSTATUS             status = OK;
    TAP_ErrorContext    gErrContext;

    if (NULL == pModule)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "pModule is NULL");
        goto exit;
    }

    status = TAP_isModuleProvisioned(pModule, pIsProvisioned, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "TAP_isModuleProvisioned Operation failed");
        goto exit;
    }
    PRINT_SUCCESS("TAP_isModuleProvisioned operation completed");

    DB_PRINT("%s.%d Module is%s provisioned\n", 
            __FUNCTION__, __LINE__,
            (TRUE==*pIsProvisioned)?"":" NOT");

exit:
    return status;
}


/*------------------------------------------------------------------*/

/* runSelfTest
 * Demonstrates usage of - 
 *  TAP_selfTest
 */
#ifndef __ENABLE_DIGICERT_NXPA71__
MSTATUS runSelfTest(TAP_Context *pTapContext)
{
    MSTATUS                     status = OK;
    TAP_TEST_MODE               testMode = TAP_TEST_MODE_FULL;
    TAP_Attribute               reqAttribute  = {
                                                TAP_ATTR_TEST_MODE,
                                                sizeof(TAP_TEST_MODE),
                                                &testMode
                                                };
    TAP_TestRequestAttributes   requestAttributes = { 1, &reqAttribute};
    TAP_TestResponseAttributes  responseAttributes = {0};
    TAP_TEST_STATUS             testStatus = 0;
    ubyte4                      iter = 0;

    status = TAP_selfTest(pTapContext, &requestAttributes, &responseAttributes,
                            &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "TAP_selfTest operation failed");
    }
    else
    {
        PRINT_SUCCESS("TAP_selfTest operation completed");
        for (iter = 0; iter < responseAttributes.listLen; iter++)
        {
            if (NULL == responseAttributes.pAttributeList[iter].pStructOfType)
                break;
            switch(responseAttributes.pAttributeList[iter].type)
            {
                case TAP_ATTR_TEST_STATUS:
                    testStatus = *(TAP_TEST_STATUS *)
                        (responseAttributes.pAttributeList[iter].pStructOfType);
                    DB_PRINT("Test Status: ");
                    switch(testStatus)
                    {
                        case TAP_TEST_STATUS_SUCCESS:
                            DB_PRINT("Success\n");
                            break;
                        case TAP_TEST_STATUS_FAILURE:
                            DB_PRINT("Failure\n");
                            break;
                        case TAP_TEST_STATUS_PENDING:
                            DB_PRINT("Pending\n");
                            break;
                        default:
                            DB_PRINT("TAP_selfTest returned invalid attribute of type %d\n",
                                      responseAttributes.pAttributeList[iter].type);
                            break;
                    }
                    break;
                case TAP_ATTR_TEST_REPORT:
                    DB_PRINT("Test Report: %s", 
                            ((TAP_Buffer *)(responseAttributes.pAttributeList[iter].pStructOfType))->pBuffer);
                    break;
                default:
                    break;
            }
        }
    }
    return status;
}
#endif

/*------------------------------------------------------------------*/

/* runRngTest
 * Demonstrates usage of - 
 *  TAP_getRandom
 *  TAP_stirRandom
 */
MSTATUS runRngTest(TAP_Context *pTapContext)
{
    MSTATUS             status = OK;
    TAP_AttributeList*  pRandAttributes = NULL;
    ubyte               randomNo[20] = {0};
    ubyte4              randomNoSize = sizeof(randomNo);
    ubyte               entropyBytes[10] = {0};
    ubyte4              entropySize = sizeof(entropyBytes);
    ubyte4              i = 0;
    TAP_Buffer          randomData = 
                            {
                                .pBuffer    = randomNo,
                                .bufferLen  = randomNoSize,    
                            };
    TAP_Buffer          entropyData = 
                            {
                                .pBuffer    = entropyBytes,
                                .bufferLen  = entropySize,    
                            };

    status = TAP_getRandom(pTapContext, randomNoSize, pRandAttributes,
                           &randomData, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Random number generation failed");
        goto exit;
    }
    PRINT_SUCCESS("TAP_getRandom operation completed");

    printf("\nGet random number:\n");
    for (i = 0; i < randomData.bufferLen; i++)
    {
        if (!(i % 8))
            printf("\n");
        printf("0x%02x ", randomData.pBuffer[i]);
    }
    printf("\n");

#ifndef __ENABLE_DIGICERT_NXPA71__
    /* Stir */
    printf("\nStir Random ...\n");
    status = TAP_stirRandom(pTapContext, entropySize, pRandAttributes, 
                            &entropyData, &gErrContext);

    if (OK != status)
    {
        PRINT_ERR(status, "TAP_stirRandom operation failed");
        goto exit;
    }
    PRINT_SUCCESS("TAP_stirRandom operation completed");

    /* Randomize again */
    status = TAP_getRandom(pTapContext, randomNoSize, pRandAttributes,
                           &randomData, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Random number generation failed");
        goto exit;
    }
    PRINT_SUCCESS("TAP_getRandom operation completed");

    printf("\nGet random number:\n");
    for (i = 0; i < randomData.bufferLen; i++)
    {
        if (!(i % 8))
            printf("\n");
        printf("0x%02x ", randomData.pBuffer[i]);
    }
    printf("\n");
#endif

exit:
    return status;
}

/*------------------------------------------------------------------*/

/* testAsymEncryptDecrypt
 * Flow - 
 *  Encrypt a plain text to create a cipher text
 *  Decrypt the cipher and compares with original plain text
 * Demonstrates usage of - 
 *  TAP_asymEncrypt
 *  TAP_asymDecrypt
 */
#ifndef __ENABLE_DIGICERT_NXPA71__
MSTATUS testAsymEncryptDecrypt(TAP_Key *pTapKey, TAP_ENC_SCHEME encScheme)
{
    MSTATUS             status = OK;
    TAP_Buffer*         pPlainTextBuffer = NULL;
    TAP_AttributeList*  pOperAttributes = NULL;
    TAP_Buffer          cipherText = {0};
    TAP_Buffer          decryptedText = {0};
    TAP_OP_EXEC_FLAG    opExecFlag = TAP_OP_EXEC_FLAG_HW;
    sbyte4              cmpResult = 0;

    pPlainTextBuffer = getPlainTextToEncrypt();

    if (!pPlainTextBuffer)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "getPlainTextToEncrypt failed");
        goto exit;
    }

    DB_PRINT("Encrypting...\n");

    /* Encrypt with the key */
    status = TAP_asymEncrypt(pTapKey, gpEntityCredentials, pOperAttributes, 
                            opExecFlag, encScheme, pPlainTextBuffer, 
                            &cipherText, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Could not encrypt using TAP_asymEncrypt");
        goto exit;
    }
    PRINT_SUCCESS("Completed encryption operation using TAP_asymEncrypt");
    
    DB_PRINT("%s.%d Encrypted text", __FUNCTION__, __LINE__);

    /*	Decrypt with the key */
    DB_PRINT("Decrypting...\n");
    status = TAP_asymDecrypt(pTapKey, gpEntityCredentials, pOperAttributes, 
                        encScheme, &cipherText, &decryptedText, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Could not decrypt using TAP_asymDecrypt");
        goto exit;
    }
    PRINT_SUCCESS("Decrypted the cipher text");

    /* Check the decrypted data */
    status = DIGI_MEMCMP(pPlainTextBuffer->pBuffer, decryptedText.pBuffer, 
                        pPlainTextBuffer->bufferLen, &cmpResult);
    if ( OK != status)
    {
        PRINT_ERR(status, "DIGI_MEMCMP failed");
    }
    else
    {
        if (cmpResult == 0)
        {
            DB_PRINT("Decrypted data matched the plain text.\n");
            status = OK;
        }
        else
        {
            DB_PRINT("Decrypted data did NOT match the plain text.\n");
            status = ERR_TAP_ENCRYPT_DECRYPT_FAILED;
        }
    }

exit:
    /* Clean up cipherText and decryptedText */
    if (NULL != cipherText.pBuffer)
    {
        TAP_UTILS_freeBuffer(&cipherText);
    }
    if (NULL != decryptedText.pBuffer)
    {
        TAP_UTILS_freeBuffer(&decryptedText);
    }
    if (NULL != pPlainTextBuffer && NULL != pPlainTextBuffer->pBuffer)
    {
        TAP_UTILS_freeBuffer(pPlainTextBuffer);
    }

    return status;
}


/*------------------------------------------------------------------*/

/* runAsymEncryptDecryptTest
 * Flow -
 *  Generate a ASYM key with input key-info mentioning type and enc
 *  Encrypt a plain text using that key  
 *  Decrypt the cipher and compare with plain text
 *  Unload and Free the generated key
 */

MSTATUS 
runAsymEncryptDecryptTest(TAP_Context*      pTapContext, 
                        TAP_CredentialList* pKeyCredentials, 
                        TAP_AttributeList*  pKeyAttributes,
                        TAP_KeyInfo*        keyInfo,
                        TAP_ENC_SCHEME      encScheme)
{
    MSTATUS     status = OK;
    TAP_Key*    pTapKey = NULL;

    DB_PRINT("Generating asymmetric key ...\n");
    status = TAP_asymGenerateKey(pTapContext, gpEntityCredentials, 
                                keyInfo, pKeyAttributes, 
                                pKeyCredentials, &pTapKey, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed creating Key...");
        goto exit;
    }
    PRINT_SUCCESS("Key created ...");

    status = testAsymEncryptDecrypt(pTapKey, encScheme);

exit:
    /* Unload key and free key */
    if (NULL != pTapKey)
    {
        DB_PRINT("%s.%d Unloading the generated key...\n",
                __FUNCTION__, __LINE__);
        status = TAP_unloadKey(pTapKey, &gErrContext);
        if (OK != status)
        {
            PRINT_ERR(status, "TAP_unloadKey operation failed");
        }
        else
        {
            PRINT_SUCCESS("TAP_unloadKey operation done");
        }

        DB_PRINT("%s.%d Releasing the unloaded key...\n",
                __FUNCTION__, __LINE__);
        status = TAP_freeKey(&pTapKey);
        if (OK != status)
        {
            PRINT_ERR(status, "TAP_freeKey operation failed");
        }
        else
        {
            PRINT_SUCCESS("TAP_freeKey operation done");
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

/* runAsymEncryptSerialize
 * Flow -
 *  Generate a ASYM key with input key-info mentioning type and enc
 *  Serialize the key and save it in an input buffer
 *  Unload and Free the generated key
 */

MSTATUS 
runAsymEncryptSerialize(TAP_Context*      pTapContext, 
                        TAP_CredentialList* pKeyCredentials, 
                        TAP_AttributeList*  pKeyAttributes,
                        TAP_KeyInfo*        keyInfo,
                        TAP_ENC_SCHEME      encScheme,
                        TAP_Buffer*         pCipherText,
                        const char *        keyOutFileName
                        )
{
    MSTATUS             status = OK;
    TAP_Key*            pTapKey = NULL;
    TAP_BLOB_FORMAT     blobFormat = TAP_BLOB_FORMAT_MOCANA;
    TAP_BLOB_ENCODING   blobEncoding = TAP_BLOB_ENCODING_BINARY;
    TAP_Buffer          privateKeyBuffer = {0};
    TAP_Buffer*         pPlainTextBuffer = NULL;
    TAP_AttributeList*  pOperAttributes = NULL;
    TAP_OP_EXEC_FLAG    opExecFlag = TAP_OP_EXEC_FLAG_HW;

    DB_PRINT("Generating asymmetric key ...\n");
    status = TAP_asymGenerateKey(pTapContext, gpEntityCredentials, 
                                keyInfo, pKeyAttributes, 
                                pKeyCredentials, &pTapKey, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed creating Key...");
        goto exit;
    }
    PRINT_SUCCESS("Key created ...");

    /* TAP_Key is the Private key, it should contain everything about the key,
       will need that when it is loaded in future for crypto operations */
    DB_PRINT("Serializing generated key. "
            "Will contain the private key and everything about key ... \n");
    status = TAP_serializeKey(pTapKey, blobFormat, blobEncoding, &privateKeyBuffer,
                              &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "TAP_serializeKey operation failed");
        goto exit;
    }
    PRINT_SUCCESS("TAP_serializeKey operation done");

    pPlainTextBuffer = getPlainTextToEncrypt();
    if (!pPlainTextBuffer)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "getPlainTextToEncrypt failed");
        goto exit;
    }

    DB_PRINT("Encrypting...");

    /* Encrypt with the key */
    status = TAP_asymEncrypt(pTapKey, gpEntityCredentials, pOperAttributes, 
                            opExecFlag, encScheme, pPlainTextBuffer, 
                            pCipherText, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Could not encrypt using TAP_asymEncrypt");
        goto exit;
    }
    PRINT_SUCCESS("Completed encryption operation using TAP_asymEncrypt");

    /* Write private key to file */
    status = DIGICERT_writeFile(keyOutFileName, privateKeyBuffer.pBuffer, 
                              privateKeyBuffer.bufferLen);
    if (OK != status)
    {
        DB_PRINT("Failed to write Private Key to file, error %d\n", status);
        goto exit;
    }
    DB_PRINT("Successfully wrote Private Key to file \"%s\"\n", keyOutFileName);
 
exit:
    /* Unload key and free key */
    if (NULL != pTapKey)
    {
        DB_PRINT("%s.%d Unloading the generated key...\n",
                __FUNCTION__, __LINE__);
        status = TAP_unloadKey(pTapKey, &gErrContext);
        if (OK != status)
        {
            PRINT_ERR(status, "TAP_unloadKey operation failed");
        }
        else
        {
            PRINT_SUCCESS("TAP_unloadKey operation done");
        }

        DB_PRINT("%s.%d Releasing the unloaded key...\n",
                __FUNCTION__, __LINE__);
        status = TAP_freeKey(&pTapKey);
        if (OK != status)
        {
            PRINT_ERR(status, "TAP_freeKey operation failed");
        }
        else
        {
            PRINT_SUCCESS("TAP_freeKey operation done");
        }
    }

    if (NULL != pPlainTextBuffer && NULL != pPlainTextBuffer->pBuffer)
    {
        TAP_UTILS_freeBuffer(pPlainTextBuffer);
    }
    if (NULL != privateKeyBuffer.pBuffer)
    {
        TAP_UTILS_freeBuffer(&privateKeyBuffer); 
    } 

    return status;
}


/*------------------------------------------------------------------*/

/* runSymEncryptSerialize
 * Flow -
 *  Generate a SYM key with input key-info mentioning type
 *  Serialize the key and save it in an input buffer
 *  Unload and Free the generated key
 */

MSTATUS 
runSymEncryptSerialize( TAP_Context*        pTapContext, 
                        TAP_CredentialList* pKeyCredentials, 
                        TAP_AttributeList*  pKeyAttributes,
                        TAP_KeyInfo*        pKeyInfo,
                        TAP_Buffer*         pCipherText,
                        TAP_SYM_KEY_MODE    symMode,
                        TAP_Buffer*         pIvBuffer,      
                        const char *        keyOutFileName )
{
    MSTATUS             status = OK;
    TAP_Key*            pTapKey = NULL;
    TAP_BLOB_FORMAT     blobFormat = TAP_BLOB_FORMAT_MOCANA;
    TAP_BLOB_ENCODING   blobEncoding = TAP_BLOB_ENCODING_BINARY;
    TAP_Buffer          privateKeyBuffer = {0};
    TAP_Buffer*         pPlainTextBuffer = NULL;
    TAP_AttributeList*  pOperAttributes = NULL;

    DB_PRINT("Generating symmetric key ...\n");
    status = TAP_symGenerateKey(pTapContext, gpEntityCredentials, pKeyInfo,
                                pKeyAttributes, pKeyCredentials,
                                &pTapKey, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Symmetric Key generation failed "
                  "using TAP_symGenerateKey");
        goto exit;
    }
    PRINT_SUCCESS("Symmetric Key Generated using TAP_symGenerateKey");

    /* TAP_Key should contain everything about the key,
       will need that when it is loaded in future for crypto operations */
    DB_PRINT("Serializing generated key. "
            "Will contain the private key and everything about key ... \n");
    status = TAP_serializeKey(pTapKey, blobFormat, blobEncoding, &privateKeyBuffer,
                              &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "TAP_serializeKey operation failed");
        goto exit;
    }
    PRINT_SUCCESS("TAP_serializeKey operation done");

    pPlainTextBuffer = getPlainTextToEncrypt();
    if (!pPlainTextBuffer)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "getPlainTextToEncrypt failed");
        goto exit;
    }

    DB_PRINT("Encrypting plain Text\n");

    /* Encrypt with the key */
    status = TAP_symEncrypt(pTapKey, gpEntityCredentials, pOperAttributes, 
                            symMode, pIvBuffer, pPlainTextBuffer, 
                            pCipherText, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Symmetric key encryption operation failed "
                  "using TAP_symEncrypt");
        goto exit;
    }
    PRINT_SUCCESS("Symmetric key encryption completed using TAP_symEncrypt");


    /* Write key to file */
    status = DIGICERT_writeFile(keyOutFileName, privateKeyBuffer.pBuffer, 
                              privateKeyBuffer.bufferLen);
    if (OK != status)
    {
        DB_PRINT("Failed to write Key to file, error %d\n", status);
        goto exit;
    }
    DB_PRINT("Successfully wrote Key to file \"%s\"\n", keyOutFileName);
 
exit:
    /* Unload key and free key */
    if (NULL != pTapKey)
    {
        DB_PRINT("%s.%d Unloading the generated key...\n",
                __FUNCTION__, __LINE__);
        status = TAP_unloadKey(pTapKey, &gErrContext);
        if (OK != status)
        {
            PRINT_ERR(status, "TAP_unloadKey operation failed");
        }
        else
        {
            PRINT_SUCCESS("TAP_unloadKey operation done");
        }

        DB_PRINT("%s.%d Releasing the unloaded key...\n",
                __FUNCTION__, __LINE__);
        status = TAP_freeKey(&pTapKey);
        if (OK != status)
        {
            PRINT_ERR(status, "TAP_freeKey operation failed");
        }
        else
        {
            PRINT_SUCCESS("TAP_freeKey operation done");
        }
    }

    if (NULL != pPlainTextBuffer && NULL != pPlainTextBuffer->pBuffer)
    {
        TAP_UTILS_freeBuffer(pPlainTextBuffer);
    }
    if (NULL != privateKeyBuffer.pBuffer)
    {
        TAP_UTILS_freeBuffer(&privateKeyBuffer); 
    } 

    return status;
}


/*------------------------------------------------------------------*/

/* runDeserializeDecrypt
 * Flow -
 *  Deserialize Key from a file
 *  Load the key
 *  Decrypt cipher text using the key
 *  Unload and Free the generated key
 */

MSTATUS 
runDeserializeDecrypt(  TAP_Context*        pTapContext, 
                        const char*         keyInFile,
                        TAP_CredentialList* pKeyCredentials, 
                        TAP_Buffer*         pCipherText,
                        TAP_Buffer*         pPlainText,
                        TAP_Buffer*         pIvBuffer
                     )
{
    MSTATUS             status = OK;
    TAP_Key*            pTapKey = NULL;
    TAP_Buffer          keyBlob = { 0 };
    TAP_Buffer          iv = {0};
    TAP_SYM_KEY_MODE    keySymMode = TAP_SYM_KEY_MODE_UNDEFINED;
    TAP_ENC_SCHEME      keyEncScheme = TAP_ENC_SCHEME_NONE;

    DB_PRINT("%s.%d Reading Key blob from file - \"%s\"\n",
            __FUNCTION__, __LINE__, keyInFile);
    /* Read key file */
    status = DIGICERT_readFile(keyInFile, &(keyBlob.pBuffer), 
                            &(keyBlob.bufferLen));
    if (OK != status)
    {
        PRINT_ERR(status, "Error reading key file");
        goto exit;
    }
    PRINT_SUCCESS("Read Key blob");

    /* Deserialize into TAP_Key */
    status = TAP_deserializeKey(&keyBlob, &pTapKey, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "TAP_deserializeKey operation failed");
        goto exit;
    }
    PRINT_SUCCESS("TAP_deserializeKey operation done");

    status = TAP_loadKey(pTapContext, gpEntityCredentials, pTapKey,
                        pKeyCredentials, NULL, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "TAP_loadKey operation failed");
        goto exit;
    }
    PRINT_SUCCESS("TAP_loadKey operation done");

    /* Decrypt using the correct API */
    switch(pTapKey->keyData.keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_AES:
            keySymMode = pTapKey->keyData.algKeyInfo.aesInfo.symMode;
            status = TAP_symDecrypt(pTapKey, gpEntityCredentials, NULL, keySymMode, pIvBuffer,
                                        pCipherText, pPlainText, &gErrContext);
            break;

        case TAP_KEY_ALGORITHM_RSA:
            keyEncScheme = pTapKey->keyData.algKeyInfo.rsaInfo.encScheme;
        case TAP_KEY_ALGORITHM_ECC:
            status = TAP_asymDecrypt(pTapKey, gpEntityCredentials, NULL, keyEncScheme,
                                         pCipherText, pPlainText, &gErrContext);
            break;

        default:
            DB_PRINT("Invalid key algorithm %d\n", pTapKey->keyData.keyAlgorithm);
            status = ERR_TAP_INVALID_ALGORITHM;
            goto exit;
            break;
    }

    if (OK != status)
    {
        PRINT_ERR(status, "Decrypt operation failed");
        goto exit;
    }
    PRINT_SUCCESS("Decrypt operation done");
 
exit:

    if (NULL != keyBlob.pBuffer)
        DIGICERT_freeReadFile(&(keyBlob.pBuffer));

    /* Unload key and free key */
    if (NULL != pTapKey)
    {
        DB_PRINT("%s.%d Unloading the generated key...\n",
                __FUNCTION__, __LINE__);
        status = TAP_unloadKey(pTapKey, &gErrContext);
        if (OK != status)
        {
            PRINT_ERR(status, "TAP_unloadKey operation failed");
        }
        else
        {
            PRINT_SUCCESS("TAP_unloadKey operation done");
        }

        DB_PRINT("%s.%d Releasing the unloaded key...\n",
                __FUNCTION__, __LINE__);
        status = TAP_freeKey(&pTapKey);
        if (OK != status)
        {
            PRINT_ERR(status, "TAP_freeKey operation failed");
        }
        else
        {
            PRINT_SUCCESS("TAP_freeKey operation done");
        }
    }

    return status;
}
#endif

/*------------------------------------------------------------------*/

/* runAsymSharedSecretGenerationTest
 * Flow -
 *  Generate a ASYM key with input key-info mentioning type and enc
 *  execute ECDH shared secret key generation test with provided public key
 *  Unload and Free the generated key
 */

MSTATUS
runAsymSharedSecretGenerationTest(TAP_Context*      pTapContext,
                        TAP_CredentialList* pKeyCredentials,
                        TAP_AttributeList*  pKeyAttributes,
                        TAP_KeyInfo*        keyInfo,
                        TAP_ENC_SCHEME      encScheme,
						TAP_SIG_SCHEME sigScheme
                        )
{
    MSTATUS             status = OK;
    TAP_Key*            pTapKey = NULL;
    TAP_AttributeList*  pOperAttributes = NULL;
    TAP_PublicKey peerPublicKey = {0};
    TAP_Buffer sharedSecret = {0};

    DB_PRINT("Generating asymmetric key ...\n");
    status = TAP_asymGenerateKey(pTapContext, gpEntityCredentials,
                                keyInfo, pKeyAttributes,
                                pKeyCredentials, &pTapKey, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed creating Key...");
        goto exit;
    }
    PRINT_SUCCESS("Key created ...");

    /* Load peer public key */
    peerPublicKey.keyAlgorithm = TAP_KEY_ALGORITHM_ECC;
    peerPublicKey.publicKey.eccKey.pubXLen = 32;
    peerPublicKey.publicKey.eccKey.pubYLen = 32;
    ubyte publicX[32] = {0x9c, 0x3a, 0xa3, 0x15, 0xa9, 0x2c, 0x77, 0x4d, 0xf2, 0x73, 0xf4, 0xc2, 0xfd, 0xfa, 0x3d, 0x49,
    0x7f, 0xc4, 0x7c, 0x59, 0x0f, 0xe2, 0xbf, 0x43, 0x58, 0xda, 0x54, 0x26, 0x90, 0xbf, 0xc0, 0xb5 };
    ubyte publicY[32] = {0x75, 0x9d, 0x13, 0x76, 0x0a, 0xcc, 0xc3, 0xf3, 0xe4, 0xbb, 0x49, 0x79, 0x18, 0xb6, 0xcb, 0xf2,
    0x48, 0xc2, 0x0b, 0x96, 0xc2, 0xd4, 0x00, 0x2d, 0x09, 0xb0, 0x11, 0xcb, 0xec, 0xd9, 0xfc, 0x58 };
    peerPublicKey.publicKey.eccKey.pPubX = publicX;
    peerPublicKey.publicKey.eccKey.pPubY = publicY;

    DB_PRINT("Generate shared secret with provided peer public key...\n");
    DB_PRINT("Peer public key X:\n");
    DEBUG_HEXDUMP(DEBUG_TEST, publicX, 32);
    DB_PRINT("Peer public key Y:\n");
    DEBUG_HEXDUMP(DEBUG_TEST, publicY, 32);
    status = TAP_ECDH_generateSharedSecret(pTapKey, pOperAttributes,
                          &peerPublicKey, &sharedSecret, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Generate shared secret with provided peer public key failed");
        goto exit;
    }
    DB_PRINT("shared secret: \n");
    DEBUG_HEXDUMP(DEBUG_TEST, sharedSecret.pBuffer, sharedSecret.bufferLen);
    PRINT_SUCCESS("Generate shared secret with provided peer public key done");

exit:
    /* Unload key and free key */
    if (NULL != pTapKey)
    {
        DB_PRINT("%s.%d Unloading the generated key...\n",
        __FUNCTION__, __LINE__);
        status = TAP_unloadKey(pTapKey, &gErrContext);
        if (OK != status)
        {
            PRINT_ERR(status, "TAP_unloadKey operation failed");
        }
        else
        {
            PRINT_SUCCESS("TAP_unloadKey operation done");
        }

        DB_PRINT("%s.%d Releasing the unloaded key...\n",
            __FUNCTION__, __LINE__);
        status = TAP_freeKey(&pTapKey);
        if (OK != status)
        {
            PRINT_ERR(status, "TAP_freeKey operation failed");
        }
        else
        {
            PRINT_SUCCESS("TAP_freeKey operation done");
        }
        pTapKey = NULL;
    }
    return status;
}
/*------------------------------------------------------------------*/

/* runAsymSerializeDeserializeTest
 * Flow -
 *  Generate a ASYM key with input key-info mentioning type and enc
 *  Serialize the key and save it in an input buffer
 *  execute sign test using the above key
 *  Unload and Free the generated key
 *  execute verify test using the Deserialize key from saved buffer
 */

MSTATUS
runAsymSerializeDeserializeTest(TAP_Context*      pTapContext,
                        TAP_CredentialList* pKeyCredentials,
                        TAP_AttributeList*  pKeyAttributes,
                        TAP_KeyInfo*        keyInfo,
                        TAP_ENC_SCHEME      encScheme,
						TAP_SIG_SCHEME sigScheme
                        )
{
    MSTATUS             status = OK;
    TAP_Key*            pTapKey = NULL;
    TAP_BLOB_FORMAT     blobFormat = TAP_BLOB_FORMAT_MOCANA;
    TAP_BLOB_ENCODING   blobEncoding = TAP_BLOB_ENCODING_BINARY;
    TAP_Buffer          privateKeyBuffer = {0};
    TAP_Buffer*         pPlainTextBuffer = NULL;
    TAP_AttributeList*  pOperAttributes = NULL;
    TAP_OP_EXEC_FLAG    opExecFlag = TAP_OP_EXEC_FLAG_HW;

    byteBoolean         isSigValid = FALSE;
    ubyte               isSigned = FALSE;
    TAP_Signature       signature = {0};
    byteBoolean         isDataNotDigest = FALSE;
    ubyte               digestBuf[SHA256_RESULT_SIZE] = {0};
    TAP_Buffer          digestBuffer =
                            {
                                .pBuffer    = digestBuf,
                                .bufferLen  = SHA256_RESULT_SIZE,
                            };

    hwAccelDescr hwAccelCtx = 0;
    
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
        goto exit;

    DB_PRINT("Generating asymmetric key ...\n");
    status = TAP_asymGenerateKey(pTapContext, gpEntityCredentials,
                                keyInfo, pKeyAttributes,
                                pKeyCredentials, &pTapKey, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed creating Key...");
        goto exit;
    }
    PRINT_SUCCESS("Key created ...");

    /* TAP_Key is the Private key, it should contain everything about the key,
       will need that when it is loaded in future for crypto operations */
    DB_PRINT("Serializing generated key. "
            "Will contain the private key and everything about key ... \n");
    status = TAP_serializeKey(pTapKey, blobFormat, blobEncoding, &privateKeyBuffer,
                              &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "TAP_serializeKey operation failed");
        goto exit;
    }
    PRINT_SUCCESS("TAP_serializeKey operation done");

    pPlainTextBuffer = getPlainTextToEncrypt();
    if (!pPlainTextBuffer)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "getPlainTextToEncrypt failed");
        goto exit;
    }

    /* Digest the input data */
    status = SHA256_completeDigest(MOC_HASH(hwAccelCtx) pPlainTextBuffer->pBuffer,
                                   pPlainTextBuffer->bufferLen,
                                   digestBuffer.pBuffer);
    if (OK != status)
    {
        DB_PRINT("SHA256_completeDigest failed with status %d\n", status);
        goto exit;
    }
    digestBuffer.bufferLen = SHA256_RESULT_SIZE;

    /* Sign the digestBuffer */
    DB_PRINT("Signing using generated asymmetric key...\n");
    status = TAP_asymSign(pTapKey, gpEntityCredentials, pOperAttributes,
                          sigScheme, isDataNotDigest, &digestBuffer,
                          &signature, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Asymmetric Sign operation using TAP_asymSign failed");
        goto exit;
    }
    PRINT_SUCCESS("Asymmetric Sign operation using TAP_asymSign done");
    isSigned = TRUE;

    /* Unload key and free key */
    if (NULL != pTapKey)
    {
        DB_PRINT("%s.%d Unloading the generated key...\n",
        __FUNCTION__, __LINE__);
        status = TAP_unloadKey(pTapKey, &gErrContext);
        if (OK != status)
        {
            PRINT_ERR(status, "TAP_unloadKey operation failed");
        }
        else
        {
            PRINT_SUCCESS("TAP_unloadKey operation done");
        }
        
        DB_PRINT("%s.%d Releasing the unloaded key...\n",
            __FUNCTION__, __LINE__);
        status = TAP_freeKey(&pTapKey);
        if (OK != status)
        {
            PRINT_ERR(status, "TAP_freeKey operation failed");
        }
        else
        {
            PRINT_SUCCESS("TAP_freeKey operation done");
        }
        pTapKey = NULL;
    }

    /* Deserialize into TAP_Key */
    status = TAP_deserializeKey(&privateKeyBuffer, &pTapKey, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "TAP_deserializeKey operation failed");
        goto exit;
    }
    PRINT_SUCCESS("TAP_deserializeKey operation done");

    status = TAP_loadKey(pTapContext, gpEntityCredentials, pTapKey,
                        pKeyCredentials, NULL, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "TAP_loadKey operation failed");
        goto exit;
    }
    PRINT_SUCCESS("TAP_loadKey operation done");

    /* Verify signature */
    DB_PRINT("Verifying the created signature...\n");
    status = TAP_asymVerifySignature(pTapKey, gpEntityCredentials, pOperAttributes,
                                     opExecFlag, sigScheme, &digestBuffer,
                                     &signature, &isSigValid, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Sign verification using TAP_asymVerifySignature failed");
        goto exit;
    }
    PRINT_SUCCESS("Sign verification completed using TAP_asymVerifySignature");

    DB_PRINT("%s.%d Signature verification result = %s\n",
            __FUNCTION__, __LINE__, (TRUE==isSigValid)?"YES":"NO");
    /* Check the verification result */
    if (TRUE != isSigValid)
    {
        status = ERR_TAP_SIGN_VERIFY_FAIL;
        PRINT_ERR(status, "Signature verification failed");
        goto exit;
    }
    PRINT_SUCCESS("Signature verification completed successfully");

exit:

    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    /* Unload key and free key */
    if (NULL != pTapKey)
    {
        DB_PRINT("%s.%d Unloading the generated key...\n",
            __FUNCTION__, __LINE__);
        status = TAP_unloadKey(pTapKey, &gErrContext);
        if (OK != status)
        {
            PRINT_ERR(status, "TAP_unloadKey operation failed");
        }
        else
        {
            PRINT_SUCCESS("TAP_unloadKey operation done");
        }
        
        DB_PRINT("%s.%d Releasing the unloaded key...\n",
            __FUNCTION__, __LINE__);
        status = TAP_freeKey(&pTapKey);
        if (OK != status)
        {
            PRINT_ERR(status, "TAP_freeKey operation failed");
        }
        else
        {
            PRINT_SUCCESS("TAP_freeKey operation done");
        }
    }
    
    if (NULL != pPlainTextBuffer && NULL != pPlainTextBuffer->pBuffer)
    {
        TAP_UTILS_freeBuffer(pPlainTextBuffer);
    }
    if (NULL != privateKeyBuffer.pBuffer)
    {
        TAP_UTILS_freeBuffer(&privateKeyBuffer);
    }
    /* Clean up */
    if (isSigned)
    {
        /* Free the signature */
        status = TAP_freeSignature(&signature);
        if (OK != status)
        {
            PRINT_ERR(status, "Failed releasing signature");
        }
        PRINT_SUCCESS("Released the created signature");
    }

    return status;
}

/*------------------------------------------------------------------*/

/* runAsymSignVerify
 * Flow - 
 *  Create a digest from plain text
 *  Create signature using incoming key and digest created above
 *  Verify the signature against the digest
 * Demonstrates usage of  
 *  TAP_asymSign
 *  TAP_asymVerifySignature
 */
MSTATUS testAsymSignVerify(TAP_Key *pTapKey, TAP_SIG_SCHEME sigScheme)
{
    MSTATUS             status = OK;
    ubyte               isSigned = FALSE;
    TAP_Signature       signature = {0};
    byteBoolean         isDataNotDigest = FALSE;
    TAP_Attribute       attributes = {
        TAP_ATTR_IS_DATA_NOT_DIGEST, sizeof(isDataNotDigest), &isDataNotDigest
    };
    TAP_AttributeList   operAttributes = {1, &attributes};
    byteBoolean         isSigValid = FALSE;
    TAP_Buffer*         pPlainTextBuffer = NULL;
    TAP_OP_EXEC_FLAG    opExecFlag = TAP_OP_EXEC_FLAG_HW;
    ubyte               digestBuf[SHA256_RESULT_SIZE] = {0};
    TAP_Buffer          digestBuffer = 
                            {
                                .pBuffer    = digestBuf,
                                .bufferLen  = SHA256_RESULT_SIZE,    
                            };

    hwAccelDescr hwAccelCtx = 0;
    
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
        goto exit;

    pPlainTextBuffer = getPlainTextToEncrypt();
    if (!pPlainTextBuffer)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "getPlainTextToEncrypt failed");
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_TPM2__) || defined(__ENABLE_DIGICERT_NXPA71__)
    /* Digest the input data */
    status = SHA256_completeDigest(MOC_HASH(hwAccelCtx) pPlainTextBuffer->pBuffer, 
                                   pPlainTextBuffer->bufferLen, 
                                   digestBuffer.pBuffer);
    if (OK != status)
    {
        DB_PRINT("SHA256_completeDigest failed with status %d\n", status);
        goto exit;
    }
    digestBuffer.bufferLen = SHA256_RESULT_SIZE;
#elif defined(__ENABLE_DIGICERT_GEMALTO__) || defined(__ENABLE_DIGICERT_SMP_PKCS11__)
    isDataNotDigest = TRUE;
    digestBuffer.pBuffer = pPlainTextBuffer->pBuffer;
    digestBuffer.bufferLen = pPlainTextBuffer->bufferLen;
#endif

    /* Sign the digestBuffer */
    DB_PRINT("Signing using generated asymmetric key...\n");
    status = TAP_asymSign(pTapKey, gpEntityCredentials, &operAttributes, 
                          sigScheme, isDataNotDigest, &digestBuffer, 
                          &signature, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Asymmetric Sign operation using TAP_asymSign failed");
        goto exit;
    }
    PRINT_SUCCESS("Asymmetric Sign operation using TAP_asymSign done");
    isSigned = TRUE;

    /* Verify signature */
    DB_PRINT("Verifying the created signature...\n");
    status = TAP_asymVerifySignature(pTapKey, gpEntityCredentials, &operAttributes, 
                                     opExecFlag, sigScheme, &digestBuffer, 
                                     &signature, &isSigValid, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Sign verification using TAP_asymVerifySignature failed");
        goto exit;
    }
    PRINT_SUCCESS("Sign verification completed using TAP_asymVerifySignature");

    DB_PRINT("%s.%d Signature verification result = %s\n",
            __FUNCTION__, __LINE__, (TRUE==isSigValid)?"YES":"NO");
    /* Check the verification result */
    if (TRUE != isSigValid)
    {
        status = ERR_TAP_SIGN_VERIFY_FAIL;
        PRINT_ERR(status, "Signature verification failed");
        goto exit;
    }
    PRINT_SUCCESS("Signature verification completed successfully");

exit:

    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    /* Clean up */
    if (isSigned)
    {
        /* Free the signature */
        status = TAP_freeSignature(&signature);
        if (OK != status)
        {
            PRINT_ERR(status, "Failed releasing signature");
        }
        PRINT_SUCCESS("Released the created signature");
    }

    if (NULL != pPlainTextBuffer && NULL != pPlainTextBuffer->pBuffer)
    {
        TAP_UTILS_freeBuffer(pPlainTextBuffer);
    }

    return status;
}


/*------------------------------------------------------------------*/

/* runAsymKeySignVerifyTest
 * Flow
 *  Create an asymmetric key
 *  execute sign-verify test using the above key
 *
 * Demonstrates usage of - 
 *  TAP_asymGenerateKey
 */
MSTATUS runAsymKeySignVerifyTest(   TAP_Context *pTapContext, 
                                    TAP_KeyInfo *pKeyInfo, 
                                    TAP_CredentialList* pKeyCredentials,
                                    TAP_AttributeList*  pKeyAttributes,
                                    TAP_ENC_SCHEME encScheme,
                                    TAP_SIG_SCHEME sigScheme )
{
    MSTATUS     status = OK;
    TAP_Key*    pTapKey = NULL;

    DB_PRINT("%s.%d Generating asymmetric key....\n",
             __FUNCTION__, __LINE__);
    status = TAP_asymGenerateKey(pTapContext, gpEntityCredentials, 
                                pKeyInfo, pKeyAttributes, 
                                pKeyCredentials, &pTapKey, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Asymmetric Key generation failed "
                  "using TAP_asymGenerateKey");
        goto exit;
    }
    PRINT_SUCCESS("Asymmetric Key Generated using TAP_asymGenerateKey");

    DB_PRINT("%s.%d Executing sign+verify using the above generated key...\n",
            __FUNCTION__, __LINE__);
    status = testAsymSignVerify(pTapKey, sigScheme);

exit:
    if (NULL != pTapKey)
    {
        DB_PRINT("%s.%d Unloading the generated key...\n",
                __FUNCTION__, __LINE__);
        status = TAP_unloadKey(pTapKey, &gErrContext);
        if (OK != status)
        {
            PRINT_ERR(status, "TAP_unloadKey operation failed");
        }
        else
        {
            PRINT_SUCCESS("TAP_unloadKey operation done");
        }

        DB_PRINT("%s.%d Releasing the unloaded key...\n",
                __FUNCTION__, __LINE__);
        status = TAP_freeKey(&pTapKey);
        if (OK != status)
        {
            PRINT_ERR(status, "TAP_freeKey operation failed");
        }
        else
        {
            PRINT_SUCCESS("TAP_freeKey operation done");
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

/* runAsymKeyTest
 * Executes a series of key related TAP methods as below: 
 *  - Encryption + Decryption
 *  - Encryption + Serialize + Deserialize + Decrypt
 */
MSTATUS runAsymKeyTest( TAP_Context *pTapContext, 
                        TAP_KeyInfo *pKeyInfo, 
                        TAP_CredentialList* pKeyCredentials,
                        TAP_AttributeList*  pKeyAttributes,
                        const char* keyFile,
                        TAP_ENC_SCHEME encScheme,
                        TAP_SIG_SCHEME sigScheme )
{
    MSTATUS                     status = OK;
    TAP_Buffer                  cipherText = {0};
    TAP_Buffer                  plainText = {0};
   
#ifndef __ENABLE_DIGICERT_NXPA71__
    if ( (TAP_KEY_USAGE_DECRYPT == pKeyInfo->keyUsage) 
       || (TAP_KEY_USAGE_GENERAL == pKeyInfo->keyUsage) ) 
    {
        PRINT_TEST_HEADER("Executing Encryption + Decryption");
        status = runAsymEncryptDecryptTest(pTapContext, pKeyCredentials, 
                                           pKeyAttributes, pKeyInfo, encScheme);
        PRINT_TEST_FOOTER("Execution ends for Encryption + Decryption");

        PRINT_TEST_HEADER("Executing Encryption + Serialize");
        status = runAsymEncryptSerialize(pTapContext, pKeyCredentials, 
                                         pKeyAttributes, pKeyInfo, 
                                         encScheme, &cipherText, keyFile);
        PRINT_TEST_FOOTER("Execution ends for Encryption + serialize");

        if (OK != status)
        {
            PRINT_ERR(status, "Error in runAsymEncryptSerialize");
            goto exit;
        }
        PRINT_SUCCESS("runAsymEncryptSerialize completed, "
                      "received encrypted text in cipherText buffer");


        PRINT_TEST_HEADER("Executing Deserialization + Decryption");
        status = runDeserializeDecrypt(pTapContext, keyFile, pKeyCredentials, 
                                       &cipherText, &plainText, NULL);
        if (OK != status)
        {
            PRINT_ERR(status, "Deserialize + Decrypt operation failed");
            goto exit;
        }
        PRINT_SUCCESS("Deserialize + Decrypt operation done");
        PRINT_TEST_FOOTER("Execution ends for Deserialization + Decryption");
    }
#endif

    if ( (TAP_KEY_USAGE_SIGNING == pKeyInfo->keyUsage) 
       || (TAP_KEY_USAGE_GENERAL == pKeyInfo->keyUsage) ) 
    {
        PRINT_TEST_HEADER("BEGIN: Execution of Sign + Verification");
        status = runAsymKeySignVerifyTest(pTapContext, pKeyInfo, 
                                          pKeyCredentials, pKeyAttributes,
                                          encScheme, sigScheme);
        PRINT_TEST_HEADER("END: Execution of Sign + Verification");
    }
#ifdef __ENABLE_DIGICERT_NXPA71__

    if (TAP_KEY_USAGE_SIGNING == pKeyInfo->keyUsage)
    {
        PRINT_TEST_HEADER("Executing Sign + Serialize and Deserialize + Verification");
        status = runAsymSerializeDeserializeTest(pTapContext, pKeyCredentials,
                pKeyAttributes, pKeyInfo, encScheme, sigScheme);
        if (OK != status)
        {
            PRINT_ERR(status, "Error in Sign + Serialize and Deserialize + Verification");
            goto exit;
        }
        PRINT_SUCCESS("Sign + Serialize and Deserialize + Verification operation done");
        PRINT_TEST_FOOTER("Execution ends for Sign + Serialize and Deserialize + Verification");
        
        PRINT_TEST_HEADER("Executing ECDH Shared Secret generation");
        status = runAsymSharedSecretGenerationTest(pTapContext, pKeyCredentials,
                 pKeyAttributes, pKeyInfo, encScheme, sigScheme);
        if (OK != status)
        {
            PRINT_ERR(status, "Error in ECDH Shared Secret generation");
            goto exit;
        }
        PRINT_SUCCESS("ECDH Shared Secret generation operation done");
        PRINT_TEST_FOOTER("Execution ends for ECDH Shared Secret generation");

    }
#endif

exit:
    if (NULL != cipherText.pBuffer)
    {
        TAP_UTILS_freeBuffer(&cipherText);
    }
    if (NULL != plainText.pBuffer)
    {
        TAP_UTILS_freeBuffer(&plainText);
    }

    return status;
}


/*------------------------------------------------------------------*/

/* runAsym_RsaGeneralKeyTest
 * Executes a series of key related TAP methods,
 * for Asymmetric key of usage type GENERAL
 */
MSTATUS runAsym_RsaGeneralKeyTest(TAP_Context *pTapContext)
{
    MSTATUS             status = OK;
    TAP_CredentialList* pKeyCredentials = NULL;
    TAP_AttributeList*  pKeyAttributes= NULL;
    TAP_ENC_SCHEME      encScheme = TAP_ENC_SCHEME_OAEP_SHA1;
    TAP_SIG_SCHEME      sigScheme = TAP_SIG_SCHEME_PSS_SHA256;
    const char *        keyFile = "asym_general_rsa.key";         
    TAP_KeyInfo         keyInfo_GeneralRsa = 
                            {
                                .keyAlgorithm   = TAP_KEY_ALGORITHM_RSA,
                                .keyUsage       = TAP_KEY_USAGE_GENERAL,
                                .algKeyInfo.rsaInfo = { .keySize = TAP_KEY_SIZE_2048, 
                                                        .exponent = 3, 
                                                        .encScheme = encScheme, 
                                                        .sigScheme = sigScheme
                                                      }
                            };

    status = runAsymKeyTest(pTapContext, &keyInfo_GeneralRsa, pKeyCredentials,
                            pKeyAttributes, keyFile, encScheme, sigScheme);

    return status;
}


/*------------------------------------------------------------------*/

/* runAsym_RsaSigningKeyTest
 * Executes a series of key related TAP methods,
 * for Asymmetric RSA key of usage type as SIGNING 
 */
MSTATUS runAsym_RsaSigningKeyTest(TAP_Context *pTapContext)
{
    MSTATUS             status = OK;
    TAP_CredentialList* pKeyCredentials = NULL;
    TAP_AttributeList*  pKeyAttributes= NULL;
    TAP_ENC_SCHEME      encScheme = TAP_ENC_SCHEME_NONE;
    TAP_SIG_SCHEME      sigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA256;
    const char *        keyFile = "asym_signing_rsa.key";         
    TAP_KeyInfo         keyInfo_RsaSign = 
                            {
                                .keyAlgorithm   = TAP_KEY_ALGORITHM_RSA,
                                .keyUsage       = TAP_KEY_USAGE_SIGNING,
                                .algKeyInfo.rsaInfo = { .keySize = TAP_KEY_SIZE_2048, 
                                                        .exponent = 17, 
                                                        .encScheme = encScheme, 
                                                        .sigScheme = sigScheme
                                                      }
                            };

    status = runAsymKeyTest(pTapContext, &keyInfo_RsaSign, pKeyCredentials,
                            pKeyAttributes, keyFile, encScheme, sigScheme);

    return status;
}


/*------------------------------------------------------------------*/

/* runAsym_EccDecryptKeyTest
 * Executes a series of key related TAP methods,
 * for Asymmetric ECC key of type DECRYPT
 */
 #if 0
MSTATUS runAsym_EccDecryptKeyTest(TAP_Context *pTapContext)
{
    MSTATUS             status = OK;
    TAP_CredentialList* pKeyCredentials = NULL;
    TAP_AttributeList*  pKeyAttributes= NULL;
    TAP_ENC_SCHEME      encScheme = TAP_ENC_SCHEME_NONE;
    TAP_SIG_SCHEME      sigScheme = TAP_SIG_SCHEME_NONE;
    const char *        keyFile = "asym_decrypt_ecc.key";         
    TAP_KeyInfo         keyInfo_DecryptEcc = 
                            {
                                .keyAlgorithm   = TAP_KEY_ALGORITHM_ECC,
                                .keyUsage       = TAP_KEY_USAGE_DECRYPT,
                                .algKeyInfo.eccInfo = { .curveId = TAP_ECC_CURVE_NIST_P256, 
                                                        .sigScheme = sigScheme
                                                      }
                            };

     status = runAsymKeyTest(pTapContext, &keyInfo_DecryptEcc, pKeyCredentials,
                            pKeyAttributes, keyFile, encScheme, sigScheme);

    return status;
}
#endif

/* runAsym_EccSigningKeyTest
* Executes a series of key related TAP methods,
* for Asymmetric ECC key of type SIGNING
*/
MSTATUS runAsym_EccSigningKeyTest(TAP_Context *pTapContext)
{
    MSTATUS             status = OK;
    TAP_CredentialList* pKeyCredentials = NULL;
    TAP_AttributeList*  pKeyAttributes = NULL;
    TAP_ENC_SCHEME      encScheme = TAP_ENC_SCHEME_NONE;
#if defined(__ENABLE_DIGICERT_TPM2__) || defined(__ENABLE_DIGICERT_NXPA71__)
    TAP_SIG_SCHEME      sigScheme = TAP_SIG_SCHEME_ECDSA_SHA256;
#elif defined(__ENABLE_DIGICERT_GEMALTO__)
    TAP_SIG_SCHEME      sigScheme = TAP_SIG_SCHEME_ECDSA_SHA1;
#elif defined(__ENABLE_DIGICERT_SMP_PKCS11__)
    TAP_SIG_SCHEME      sigScheme = TAP_SIG_SCHEME_ECDSA_SHA1;
#elif defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
    TAP_SIG_SCHEME      sigScheme = TAP_SIG_SCHEME_ECDSA_SHA1;
#endif
#ifdef __ENABLE_DIGICERT_NXPA71__
    const char *        keyFile = NULL;
#else
    const char *        keyFile = "asym_sign_ecc.key";
#endif

    TAP_KeyInfo         keyInfo_SignEcc =
    {
        .keyAlgorithm = TAP_KEY_ALGORITHM_ECC,
        .keyUsage = TAP_KEY_USAGE_SIGNING,
        .algKeyInfo.eccInfo = 
                {   .curveId = TAP_ECC_CURVE_NIST_P256,
                    .sigScheme = sigScheme
                }
    };

    status = runAsymKeyTest(pTapContext, &keyInfo_SignEcc, pKeyCredentials,
        pKeyAttributes, keyFile, encScheme, sigScheme);

    return status;
}

/*------------------------------------------------------------------*/

/* testSymEncryptDecrypt
 * Flow - 
 *  Encrypts a plain text to create a cipher text
 *  Decrypts the cipher using and compares with original plain text
 * Demonstrates usage of - 
 *  TAP_symEncrypt
 *  TAP_symDecrypt
 */
#ifndef __ENABLE_DIGICERT_NXPA71__
MSTATUS testSymEncryptDecrypt(  TAP_Key*            pTapKey, 
                                TAP_SYM_KEY_MODE    symMode,
                                TAP_Buffer*         pIvBuffer )
{
    MSTATUS             status = OK;
    TAP_Buffer*         pPlainTextBuffer = NULL;
    TAP_AttributeList*  pOperAttributes = NULL;
    TAP_Buffer          cipherText = {0};
    TAP_Buffer          decryptedText = {0};
    sbyte4              cmpResult = 0;

    pPlainTextBuffer = getPlainTextToEncrypt();
    if (!pPlainTextBuffer)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "getPlainTextToEncrypt failed");
        goto exit;
    }

    /* Encrypt with the key */
    DB_PRINT("Encrypting...\n");
    status = TAP_symEncrypt(pTapKey, gpEntityCredentials, pOperAttributes, 
                            symMode, pIvBuffer, pPlainTextBuffer, 
                            &cipherText, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Symmetric key encryption operation failed "
                  "using TAP_symEncrypt");
        goto exit;
    }
    PRINT_SUCCESS("Symmetric key encryption completed using TAP_symEncrypt");


    /*	Decrypt with the key */
    DB_PRINT("Decrypting...\n");
    status = TAP_symDecrypt(pTapKey, gpEntityCredentials, pOperAttributes, 
                            symMode, pIvBuffer, &cipherText, &decryptedText, 
                            &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Could not decrypt using TAP_symDecrypt");
        goto exit;
    }
    PRINT_SUCCESS("Decrypted the cipher text");

    /* Check the decrypted data */
    status = DIGI_MEMCMP(pPlainTextBuffer->pBuffer, decryptedText.pBuffer, 
                        pPlainTextBuffer->bufferLen, &cmpResult);
    if ( OK != status)
    {
        PRINT_ERR(status, "DIGI_MEMCMP failed");
    }
    else
    {
        if (cmpResult == 0)
        {
            DB_PRINT("Decrypted data matched the plain text.\n");
            status = OK;
        }
        else
        {
            DB_PRINT("Decrypted data did NOT match the plain text.\n");
            status = ERR_TAP_ENCRYPT_DECRYPT_FAILED;
        }
    }

exit:
    /* Clean up cipherText and decryptedText */
    if (NULL != cipherText.pBuffer)
    {
        TAP_UTILS_freeBuffer(&cipherText);
    }
    if (NULL != decryptedText.pBuffer)
    {
        TAP_UTILS_freeBuffer(&decryptedText);
    }
    if (NULL != pPlainTextBuffer && NULL != pPlainTextBuffer->pBuffer)
    {
        TAP_UTILS_freeBuffer(pPlainTextBuffer);
    }

    return status;
}


/*------------------------------------------------------------------*/

/* runSymEncryptDecryptTest
 * Flow -
 *  Generate a SYM key with input key-info mentioning type and enc
 *  Encrypt a plain text using that key  
 *  Decrypt the cipher and compare with plain text
 *  Unload and Free the generated key
 */
MSTATUS 
runSymEncryptDecryptTest(   TAP_Context*        pTapContext, 
                            TAP_CredentialList* pKeyCredentials, 
                            TAP_AttributeList*  pKeyAttributes,
                            TAP_KeyInfo*        pKeyInfo,
                            TAP_SYM_KEY_MODE    symMode,
                            TAP_Buffer*         pIvBuffer )
{
    MSTATUS     status = OK;
    TAP_Key*    pTapKey = NULL;

    DB_PRINT("Generating symmetric key ...\n");
    status = TAP_symGenerateKey(pTapContext, gpEntityCredentials, pKeyInfo,
                                pKeyAttributes, pKeyCredentials,
                                &pTapKey, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Symmetric Key generation failed "
                  "using TAP_symGenerateKey");
        goto exit;
    }
    PRINT_SUCCESS("Symmetric Key Generated using TAP_symGenerateKey");

    DB_PRINT("%s.%d Executing encrypt+decrypt using "
             "the above generated key...\n", __FUNCTION__, __LINE__);
    status = testSymEncryptDecrypt(pTapKey, symMode, pIvBuffer);

exit:
    if (NULL != pTapKey)
    {
        DB_PRINT("%s.%d Unloading the generated key...\n",
                __FUNCTION__, __LINE__);
        status = TAP_unloadKey(pTapKey, &gErrContext);
        if (OK != status)
        {
            PRINT_ERR(status, "TAP_unloadKey operation failed");
        }
        else
        {
            PRINT_SUCCESS("TAP_unloadKey operation done");
        }

        DB_PRINT("%s.%d Releasing the unloaded key...\n",
                __FUNCTION__, __LINE__);
        status = TAP_freeKey(&pTapKey);
        if (OK != status)
        {
            PRINT_ERR(status, "TAP_freeKey operation failed");
        }
        else
        {
            PRINT_SUCCESS("TAP_freeKey operation done");
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

/* runSymKeyTest
 * Executes a series of key related TAP methods,
 * for symmetric key 
 */
MSTATUS runSymKeyTest( TAP_Context *pTapContext, 
                        TAP_KeyInfo *pKeyInfo, 
                        TAP_CredentialList* pKeyCredentials,
                        TAP_AttributeList*  pKeyAttributes,
                        const char* keyFile,
                        TAP_SYM_KEY_MODE symMode,
                        TAP_Buffer *pIvBuffer )
{
    MSTATUS                     status = OK;
    TAP_Buffer                  cipherText = {0};
    TAP_Buffer                  plainText = {0};
    ubyte               ivBuf[AES_BLOCK_SIZE] = {0};
    TAP_Buffer          iv =
                            {
                                .pBuffer    = ivBuf,
                                .bufferLen  = AES_BLOCK_SIZE,   
                            };


    PRINT_TEST_HEADER("Executing Encryption + Decryption");
    status = runSymEncryptDecryptTest(pTapContext, pKeyCredentials, 
                                      pKeyAttributes, pKeyInfo, symMode, 
                                      pIvBuffer);
    PRINT_TEST_FOOTER("Execution ends for Encryption + Decryption");

    PRINT_TEST_HEADER("Executing Encryption + Serialize");
    status = runSymEncryptSerialize(pTapContext, pKeyCredentials, 
                                     pKeyAttributes, pKeyInfo, 
                                     &cipherText, symMode, &iv, keyFile);
    PRINT_TEST_FOOTER("Execution ends for Encryption + serialize");

    if (OK != status)
    {
        PRINT_ERR(status, "Error in runSymEncryptSerialize");
        goto exit;
    }
    PRINT_SUCCESS("runSymEncryptSerialize completed, "
                  "received encrypted text in cipherText buffer");

    PRINT_TEST_HEADER("Executing Deserialization + Decryption");
    status = runDeserializeDecrypt(pTapContext, keyFile, pKeyCredentials, 
                                   &cipherText, &plainText, &iv);
    if (OK != status)
    {
        PRINT_ERR(status, "Deserialize + Decrypt operation failed");
        goto exit;
    }
    PRINT_SUCCESS("Deserialize + Decrypt operation done");
    PRINT_TEST_FOOTER("Execution ends for Deserialization + Decryption");

exit:
    if (NULL != cipherText.pBuffer)
    {
        TAP_UTILS_freeBuffer(&cipherText);
    }
    if (NULL != plainText.pBuffer)
    {
        TAP_UTILS_freeBuffer(&plainText);
    }

    return status;
}


/*------------------------------------------------------------------*/

/* runSym_AesDecryptKeyTest
 * Executes a series of key related TAP methods,
 * for symmetric AES key of type DECRYPT
 */
MSTATUS runSym_AesDecryptKeyTest(TAP_Context *pTapContext)
{
    MSTATUS             status = OK;
    TAP_CredentialList* pKeyCredentials = NULL;
    TAP_AttributeList*  pKeyAttributes= NULL;
    const char*         keyFile = "sym_decrypt_aes.key";         
    TAP_SYM_KEY_MODE    symMode = TAP_SYM_KEY_MODE_CBC;
    TAP_KeyInfo         keyInfo_AesDecrypt = 
                                {
                                    .keyAlgorithm   = TAP_KEY_ALGORITHM_AES,
                                    .keyUsage       = TAP_KEY_USAGE_DECRYPT,
                                    .algKeyInfo.aesInfo.keySize = TAP_KEY_SIZE_128,
                                    .algKeyInfo.aesInfo.symMode =  symMode
                                };
    ubyte               ivBuf[AES_BLOCK_SIZE] = {0};
    TAP_Buffer          iv =
                            {
                                .pBuffer    = ivBuf,
                                .bufferLen  = AES_BLOCK_SIZE,   
                            };

    status = runSymKeyTest(pTapContext, &keyInfo_AesDecrypt, pKeyCredentials,
                            pKeyAttributes, keyFile, symMode, &iv);

    return status;
}
#endif

/*------------------------------------------------------------------*/

/* runSymSignVerify
 * Flow - 
 *  Create a digest from plain text
 *  Create signature using incoming key and digest created above
 *  Verify the signature against the digest
 * Demonstrates usage of  
 *  TAP_symSign
 *  TAP_symVerifySignature
 */
MSTATUS testSymSignVerify(TAP_Key *pTapKey)
{
    MSTATUS             status = OK;
    ubyte               isSigned = FALSE;
    TAP_Signature       signature = {0};
    TAP_AttributeList*  pOperAttributes = NULL;
    byteBoolean         isDataNotDigest = FALSE;
    byteBoolean         isSigValid = FALSE;
    TAP_Buffer*         pPlainTextBuffer = NULL;
    ubyte               digestBuf[SHA256_RESULT_SIZE] = {0};
    TAP_Buffer          digestBuffer = 
                            {
                                .pBuffer    = digestBuf,
                                .bufferLen  = SHA256_RESULT_SIZE,    
                            };
    hwAccelDescr hwAccelCtx = 0;
    
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
        goto exit;

    pPlainTextBuffer = getPlainTextToEncrypt();
    if (!pPlainTextBuffer)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "getPlainTextToEncrypt failed");
        goto exit;
    }

    /* Digest the input data */
    status = SHA256_completeDigest(MOC_HASH(hwAccelCtx) pPlainTextBuffer->pBuffer, 
                                   pPlainTextBuffer->bufferLen, 
                                   digestBuffer.pBuffer);
    if (OK != status)
    {
        DB_PRINT("SHA256_completeDigest failed with status %d\n", status);
        goto exit;
    }
    digestBuffer.bufferLen = SHA256_RESULT_SIZE;

    /* Sign the digestBuffer */
    DB_PRINT("Signing using generated symmetric key...\n");
    status = TAP_symSign(pTapKey, gpEntityCredentials, pOperAttributes, 
                         isDataNotDigest, &digestBuffer, 
                         &signature, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Symmetric Sign operation using TAP_symSign failed");
        goto exit;
    }
    PRINT_SUCCESS("Symmetric Sign operation using TAP_symSign done");
    isSigned = TRUE;

    /* Verify signature */
    DB_PRINT("Verifying the created signature...\n");
    status = TAP_symVerifySignature(pTapKey, gpEntityCredentials, pOperAttributes, 
                                    &digestBuffer, &signature, 
                                    &isSigValid, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Sign verification using TAP_symVerifySignature failed");
        goto exit;
    }
    PRINT_SUCCESS("Sign verifitaion completed using TAP_symVerifySignature");

    DB_PRINT("%s.%d Signature verification result = %s\n",
            __FUNCTION__, __LINE__, (TRUE==isSigValid)?"YES":"NO");
    /* Check the verification result */
    if (TRUE != isSigValid)
    {
        status = ERR_TAP_SIGN_VERIFY_FAIL;
        PRINT_ERR(status, "Signature verification failed");
        goto exit;
    }
    PRINT_SUCCESS("Signature verification completed successfully");

exit:
    
    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    
    /* Clean up */
    if (isSigned)
    {
        /* Free the signature */
        status = TAP_freeSignature(&signature);
        if (OK != status)
        {
            PRINT_ERR(status, "Failed releasing signature");
        }
        PRINT_SUCCESS("Released the created signature");
    }

    if (NULL != pPlainTextBuffer && NULL != pPlainTextBuffer->pBuffer)
    {
        TAP_UTILS_freeBuffer(pPlainTextBuffer);
    }

    return status;
}


/*------------------------------------------------------------------*/

/* runSym_HmacSigningKeyTest
 * Flow
 *  Create a symmetric key
 *  execute sign-verify test using the above key
 *
 * Demonstrates usage of - 
 *  TAP_symGenerateKey
 */
MSTATUS runSym_HmacSigningKeyTest (TAP_Context* pTapContext)
{
    MSTATUS             status = OK;
    TAP_Key*            pTapKey = NULL;
    TAP_AttributeList*  pKeyAttributes = NULL;
    TAP_CredentialList* pKeyCredentials = NULL;
    TAP_KeyInfo         keyInfo_Sign = 
                            {
                                .keyAlgorithm   = TAP_KEY_ALGORITHM_HMAC,
                                .keyUsage       = TAP_KEY_USAGE_SIGNING,
                                .algKeyInfo.hmacInfo.hashAlg = TAP_HASH_ALG_SHA256
                            };

    DB_PRINT("%s.%d Generating a symmetric key for usage type=SIGNING, "
             "and algorithm=HMAC ....\n", __FUNCTION__, __LINE__);
    status = TAP_symGenerateKey(pTapContext, gpEntityCredentials, &keyInfo_Sign, pKeyAttributes, pKeyCredentials,
                                &pTapKey, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Symmetric Key generation failed "
                  "using TAP_symGenerateKey");
        goto exit;
    }
    PRINT_SUCCESS("Symmetric Key Generated using TAP_symGenerateKey");

    DB_PRINT("%s.%d Executing sign+verify using the above generated key...\n",
            __FUNCTION__, __LINE__);
    status = testSymSignVerify(pTapKey);

exit:
    if (NULL != pTapKey)
    {
        DB_PRINT("%s.%d Unloading the generated key...\n",
                __FUNCTION__, __LINE__);
        status = TAP_unloadKey(pTapKey, &gErrContext);
        if (OK != status)
        {
            PRINT_ERR(status, "TAP_unloadKey operation failed");
        }
        else
        {
            PRINT_SUCCESS("TAP_unloadKey operation done");
        }

        DB_PRINT("%s.%d Releasing the unloaded key...\n",
                __FUNCTION__, __LINE__);
        status = TAP_freeKey(&pTapKey);
        if (OK != status)
        {
            PRINT_ERR(status, "TAP_freeKey operation failed");
        }
        else
        {
            PRINT_SUCCESS("TAP_freeKey operation done");
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

/* runKeyTests
 * Executes a series of key related operations for certain combinations
 * in symmetric and asymmetric key types.
 */
MSTATUS runKeyTests(TAP_Context *pTapContext)
{
    MSTATUS status = OK;

#ifdef __ENABLE_DIGICERT_NXPA71__

    PRINT_TEST_HEADER("***** BEGIN - KEY TEST USING a ECC key of type SIGNING "
                      "*****");
    status = runAsym_EccSigningKeyTest(pTapContext);
    PRINT_TEST_FOOTER("***** END - KEY TEST USING a ECC key of type SIGNING "
                      "*****");
#else
    PRINT_TEST_HEADER("***** BEGIN - KEY TEST USING a RSA KEY of type GENERAL "
                      "*****");
    status = runAsym_RsaGeneralKeyTest(pTapContext);
    PRINT_TEST_FOOTER("***** END - KEY TEST USING a RSA KEY of type GENERAL "
                      "*****");

    /*
    PRINT_TEST_HEADER("***** BEGIN - KEY TEST USING a ECC KEY of type DECRYPT "
                      "*****");
    status = runAsym_EccDecryptKeyTest(pTapContext);
    PRINT_TEST_FOOTER("***** END - KEY TEST USING a ECC KEY of type DECRYPT "
                      "*****");
    */

    PRINT_TEST_HEADER("***** BEGIN - KEY TEST USING a ECC KEY of type SIGNING "
        "*****");
    status = runAsym_EccSigningKeyTest(pTapContext);
    PRINT_TEST_FOOTER("***** END - KEY TEST USING a ECC KEY of type SIGNING "
        "*****");

    PRINT_TEST_HEADER("***** BEGIN - KEY TEST USING a RSA key of type SIGNING "
                      "*****");
    status = runAsym_RsaSigningKeyTest(pTapContext); 
    PRINT_TEST_FOOTER("***** END - KEY TEST USING a RSA key of type SIGNING "
                      "*****");

    PRINT_TEST_HEADER("***** BEGIN - KEY TEST USING a SYMMETRIC KEY of "
                      "type DECRYPT *****");
    status = runSym_AesDecryptKeyTest(pTapContext);
    PRINT_TEST_FOOTER("***** END - KEY TEST USING a SYMMETRIC KEY of "
                      "type DECRYPT *****");

    PRINT_TEST_HEADER("***** BEGIN - SIGN + VERIFY TEST USING a SYMMETRIC KEY "
                      "of type SIGNING *****");
    status = runSym_HmacSigningKeyTest(pTapContext); 
    PRINT_TEST_FOOTER("***** END - SIGN + VERIFY TEST USING a SYMMETRIC KEY "
                      "of type SIGNING *****");
#endif
    return status;
}


/*------------------------------------------------------------------*/

/* Configuration initialization callbacks
 */
MSTATUS initTapConfigInfo(TAP_ConfigInfo* pConfigInfo)
{
    MSTATUS status = OK;

    if (NULL == pConfigInfo)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "NULL parameter pConfigInfo");
        goto exit;
    }

    if (TRUE == gCmdLineOpts.tpm2ConfigFileSpecified)
    {
       pTpm2ConfigFile = gCmdLineOpts.tpm2confFilePath;
    }
    else
    {
#if defined(__RTOS_WIN32__)
        status = TAP_UTILS_getWinConfigFilePath(&pTpm2ConfigFile, TPM2_CONFIGURATION_FILE);
        if (OK != status)
        {
            goto exit;
        }
#elif defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
        pTpm2ConfigFile = NanoROOT_CONFIGURATION_FILE;
#else
        pTpm2ConfigFile = TPM2_CONFIGURATION_FILE;
#endif
    }

    status = TAP_readConfigFile(pTpm2ConfigFile,&pConfigInfo->configInfo,
                            gCmdLineOpts.tpm2ConfigFileSpecified);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed to read TPM2 config from config file");
        goto exit;
    }
#if defined(__ENABLE_DIGICERT_TPM2__)
    pConfigInfo->provider = TAP_PROVIDER_TPM2;
#elif defined(__ENABLE_DIGICERT_GEMALTO__)
    pConfigInfo->provider = TAP_PROVIDER_GEMSIM;
#elif defined(__ENABLE_DIGICERT_SMP_PKCS11__)
    pConfigInfo->provider = TAP_PROVIDER_PKCS11;
#elif defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
    pConfigInfo->provider = TAP_PROVIDER_NANOROOT;
#endif

exit:
    return status;
}



/*------------------------------------------------------------------*/
/*  Policy Storage Methods                                          */
/*------------------------------------------------------------------*/

#define NV_WRITE_INDEX           0x01000000
#define NV_WRITE_SIZE            32
#define NV_WRITE_STORAGE_TYPE    0

/*------------------------------------------------------------------*/

/* listPolicyStorages
 * Demonstrates usage of
 *  TAP_getPolicyStorageList
 */
MSTATUS listPolicyStorages( TAP_Context *pTapContext, 
                            TAP_EntityCredentialList* pUsageCredentials
                          )
{
    MSTATUS                         status = OK;
    TAP_ObjectInfoList              objectInfoList = {0};
    TAP_PolicyStorageAttributes*    pStorageAttributes = NULL;
    int                             iter = 0;

    status = TAP_getPolicyStorageList(pTapContext, pUsageCredentials, pStorageAttributes,
                                        &objectInfoList, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "TAP_getPolicyStorageList operation failed");
        goto exit;
    }
    PRINT_SUCCESS("TAP_getPolicyStorageList operation completed");

    printf("Number of objects in Policy storage = %d\n", objectInfoList.count);
    DB_PRINT("Policy storage list -> \n\tIndex\n"
                                      "\t-----\n");
    for(iter= 0 ; iter < objectInfoList.count ; iter++)
    {
        DB_PRINT("\t%02x\n", objectInfoList.pInfo[iter].objectId);
    }

    /*
    TAP_StorageObjectList           detailsList = {0};
    TAP_StorageInfo*                pStorageInfo = NULL;
    const char*                     pName = NULL;       
    const char* const               storageTypeNames[] = 
                                        {
                                        "unknown",
                                        "ordinary", "counter",
                                        "bits", "extend", "clear"
                                        };


    status = TAP_getPolicyStorageDetails(pTapContext, pUsageCredentials, pStorageAttributes,
                                            &objectInfoList, &detailsList, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "TAP_getPolicyStorageDetails operation failed");
        goto exit;
    }
    PRINT_SUCCESS("TAP_getPolicyStorageDetails operation completed");

    printf("Details of Policy Storage Objects:- \n"
           "\tIndex\tSize\tStorage-Type\tStorage-Type Name\n"
           "\t-----\t----\t------------\t-----------------\n");
    for (iter=0; iter < detailsList.count; iter++)
    {
        pStorageInfo = &(detailsList.pObjects[iter].storageInfo);
        pName = (sizeof(storageTypeNames) <= pStorageInfo->storageType) ? 
                "Unknown" : storageTypeNames[pStorageInfo->storageType] ;
        printf("\t%d\t%d\t%d\t%s\n",
               pStorageInfo->index,
               pStorageInfo->size,
               pStorageInfo->storageType, pName);
    }
    */

exit:
   return status;
}


/*------------------------------------------------------------------*/

/* getPsObjectAtIndex
 * Demonstrates usage of
 *  TAP_getPolicyStorageList 
 */
MSTATUS
getPsObjectAtIndex( TAP_Context*                    pTapContext,
                    TAP_EntityCredentialList*       pUsageCredentials,
                    TAP_PolicyStorageAttributes*    pStorageAttributes,
                    TAP_EntityId                    objectIndex, 
                    TAP_ObjectInfo**                ppObjectInfo
                  )
{
    MSTATUS             status = OK;
    TAP_ObjectInfoList  objectInfoList = {0};
    ubyte4              iter = 0;

    status = TAP_getPolicyStorageList(pTapContext, pUsageCredentials, pStorageAttributes,
                                        &objectInfoList, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Could not fetch list of policy storage object info");
        goto exit;
    }

    for(iter= 0 ; iter < objectInfoList.count ; iter++)
    {
        if(objectInfoList.pInfo[iter].objectId == objectIndex) 
            break ;
    }
    if(iter == objectInfoList.count)
    {
        status = ERR_NOT_FOUND;
        PRINT_ERR(status, "Invalid storage index");
        goto exit;
    }

    *ppObjectInfo = &objectInfoList.pInfo[iter];
    
exit:
    return status;
}


/*------------------------------------------------------------------*/

/* writeNewPolicyStorage
 * Demonstrates usage of 
 *  TAP_allocatePolicyStorage
 *  TAP_setPolicyStorage
 */
MSTATUS writeNewPolicyStorage(TAP_Context*               pTapContext,
                              TAP_EntityCredentialList*  pUsageCredentials,
                              TAP_StorageInfo*           pWriteStorageInfo,            
                              TAP_Buffer*                pWriteData
                             )
{
    MSTATUS                     status = OK;
    TAP_ObjectAttributes*       pObjAttributes = NULL;
    TAP_CredentialList*         pStorageCredentials = NULL;
    TAP_ObjectInfo*             pObjectInfo = NULL;
    TAP_ObjectInfoList              objectInfoList = {0};
    TAP_CAPABILITY_FUNCTIONALITY  capability = TAP_CAPABILITY_STORAGE_WITH_POLICY;
    TAP_Attribute storageAttribute = {
                                        TAP_ATTR_CAPABILITY_FUNCTIONALITY,
                                        sizeof(TAP_CAPABILITY_FUNCTIONALITY),
                                        &capability
                                    };
    TAP_PolicyStorageAttributes  storageAttributes = {1, &storageAttribute};
    
    /* Allocate policy */
    status = TAP_allocatePolicyStorage(pTapContext, pUsageCredentials, 
                                       pWriteStorageInfo, pObjAttributes, 
                                       pStorageCredentials, &gErrContext);
    if (ERR_TAP_NV_INDEX_EXISTS == status)
    {
        DB_PRINT("%s.%d Index(%02x) already allocated in policy storage, "
                 "using the existing index\n", __FUNCTION__, __LINE__, 
                 pWriteStorageInfo->index);
    }
    else if (OK != status)     
    {
        PRINT_ERR(status, "Operation to allocate policy storage failed");
        goto exit;
    }
    PRINT_SUCCESS("Operation to allocate policy storage completed");
#if (defined(__ENABLE_DIGICERT_SMP_PKCS11__) || defined(__ENABLE_DIGICERT_GEMALTO__))
    status = TAP_getPolicyStorageList(pTapContext, pUsageCredentials, &storageAttributes,
                                        &objectInfoList, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "TAP_getPolicyStorageList operation failed");
        goto exit;
    }
    PRINT_SUCCESS("TAP_getPolicyStorageList operation completed");
 
    status = getPsObjectAtIndex(pTapContext, pUsageCredentials,
                                &storageAttributes, objectInfoList.pInfo[0].objectId,
                                &pObjectInfo );
#else
    /* Get ObjectInfo for the above allocated index, for write operation */
    status = getPsObjectAtIndex(pTapContext, pUsageCredentials,
                                NULL, pWriteStorageInfo->index,
                                &pObjectInfo );
#endif
    if (OK != status)
    {
        PRINT_ERR(status, "Could not locate the objectInfo for "
                          "above created storage index");
        goto exit;
    }

    /* Write */
    status = TAP_setPolicyStorage(pTapContext, pUsageCredentials, pObjectInfo, 
                                  &pObjectInfo->objectAttributes, pWriteData, 
                                  &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Write operation to the "
                          "allocated policy storage failed");
        goto exit;
    }
    PRINT_SUCCESS("Data written succesfully to newly allocted policy storage");    

exit:
   return status;
}


/*------------------------------------------------------------------*/

/* readFromPolicyStorage
 * Demonstrates usage of 
 *  TAP_getPolicyStorage
 */
MSTATUS readFromPolicyStorage(TAP_Context*               pTapContext,
                              TAP_EntityCredentialList*  pUsageCredentials,
                              TAP_StorageInfo*           pReadStorageInfo,            
                              TAP_Buffer*                pReadData
                             )
{
    MSTATUS                         status = OK;
    TAP_PolicyStorageAttributes*    pStorageAttributes = NULL;
    TAP_ObjectInfo*                 pObjectInfo = NULL;

    /* Get ObjectInfo for the above allocated index, for read operation */
    status = getPsObjectAtIndex(pTapContext, pUsageCredentials,
                                pStorageAttributes, pReadStorageInfo->index, 
                                &pObjectInfo );
    if (OK != status)
    {
        PRINT_ERR(status, "Could not locate the objectInfo for "
                          "above created storage index");
        goto exit;
    }

    status = TAP_getPolicyStorage(pTapContext, pUsageCredentials, 
                                  pObjectInfo, &pObjectInfo->objectAttributes,
                                  pReadData, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Read operation from policy storage failed");
        goto exit;
    }                                
    PRINT_SUCCESS("Read from policy storage");

exit:
    return status;
}

/*------------------------------------------------------------------*/

/* runPolicyStorageTest
 * Flow - 
 *  Lists the initali list of policy storage
 *  Allocates a new one
 *  Writes data to allocated storgae
 *  Reads from this allocated storage
 *  Compares the data 
 *  Releases allocated policy-storage
 */

MSTATUS runPolicyStorageTest(TAP_Context *pTapContext)
{
    MSTATUS                     status = OK;
    TAP_EntityCredentialList*   pUsageCredentials = NULL;
    ubyte                       writeBuf[NV_WRITE_SIZE];
    TAP_Buffer                  writeData = 
                                {
                                    .pBuffer     = writeBuf,
                                    .bufferLen  = NV_WRITE_SIZE
                                };
    TAP_Buffer                  readData = {0};
    sbyte4                      result = 0;
    TAP_StorageInfo             writeStorageInfo =
        {
        .index  = NV_WRITE_INDEX,
        .size   = NV_WRITE_SIZE,
        .storageType       = NV_WRITE_STORAGE_TYPE,
        .ownerPermission    = (TAP_PERMISSION_BITMASK_READ | TAP_PERMISSION_BITMASK_WRITE),
        .publicPermission   = (TAP_PERMISSION_BITMASK_READ | TAP_PERMISSION_BITMASK_WRITE),
        .pAttributes        = NULL 
        };

    status = listPolicyStorages(pTapContext, gpEntityCredentials);
    if (OK != status)
    {
        goto exit;
    }
 
    DIGI_MEMSET(writeBuf, 0xff, NV_WRITE_SIZE);

    status = writeNewPolicyStorage(pTapContext, gpEntityCredentials, 
                                       &writeStorageInfo, &writeData);
    if (OK != status)
    {
        goto exit;
    }

    printTapBuffer(&writeData);

    printf("List of policy storages after allocating a new storage");
    status = listPolicyStorages(pTapContext, pUsageCredentials);

    /* Read */
    status = readFromPolicyStorage(pTapContext, gpEntityCredentials,
                                   &writeStorageInfo, &readData );
    if (OK != status)
    {
        goto exit;
    }
    printTapBuffer(&readData);
    status = DIGI_MEMCMP(writeData.pBuffer, readData.pBuffer, readData.bufferLen, &result);
    if ( OK != status)
    {
        PRINT_ERR(status, "Comparison failed");
    }
    else
    {
        if (result == 0)
        {
            PRINT_SUCCESS("Read and written data are equal");
        }
        else
        {
            status = ERR_GENERAL;
            PRINT_ERR(status, "Read and written data are not equal");
        }
    }

exit:
    /* Clean up */
    if (NULL != readData.pBuffer)
    {
        status = TAP_UTILS_freeBuffer(&readData);
        if (OK != status)
        {
            PRINT_ERR(status, "Error freeing memory from readData");
        }
    }

    /* Uninitialize/free the allocated policystorage*/
    status = TAP_freePolicyStorage(pTapContext, gpEntityCredentials, 
                                   &writeStorageInfo, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Error freeing the allocated policy storage");
    } 
    PRINT_SUCCESS("Freed policy storage");

    return status;
}



/*------------------------------------------------------------------*/
/* TRUSTED DATA                                                     */
/*------------------------------------------------------------------*/
#define EXAMPLE_TAP_TRUSTED_DATA_SUBTYPE_NONE   1

/*------------------------------------------------------------------*/

/* readTrustedData
 * Demonstrates usage of 
 *  TAP_getTrustedData
 */
MSTATUS readTrustedData(TAP_Context *pTapContext, TAP_Buffer *pReadData,
                        TAP_TRUSTED_DATA_TYPE trustedDataType, 
                        TAP_TrustedDataInfo* pTrustedDataInfo)
{
    MSTATUS status = OK;
    ubyte4  iter = 0;

    /* Read Trusted-Data value */
    status = TAP_getTrustedData(pTapContext, gpEntityCredentials, 
                                trustedDataType, pTrustedDataInfo, 
                                pReadData, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Read operation using TAP_getTrustedData failed");
        goto exit;
    }
    PRINT_SUCCESS("Read operation using TAP_getTrustedData completed");

    if ((NULL == pReadData->pBuffer) || (0 >= pReadData->bufferLen))
    {
        status = ERR_NOT_FOUND;
        PRINT_ERR(status, "Read data is empty");
        goto exit;
    }
    
    DB_PRINT("%s.%d Length of data read = %d", 
            __FUNCTION__, __LINE__, pReadData->bufferLen);
    for (iter = 0; iter < pReadData->bufferLen; iter++) 
    {
        if (0 == iter%32)
            DB_PRINT("\n\t");
        DB_PRINT("%02x ",pReadData->pBuffer[iter]);
    }
    DB_PRINT("\n");

exit:
    return status;

}


/*------------------------------------------------------------------*/

/* extendTrustedData
 * update data in configured trusted data key
 * read data again, and compare to validate if data same as updated one.
 * Demonstrates usage of 
 *  TAP_updateTrustedData
 */
MSTATUS extendTrustedData(  TAP_Context *pTapContext, TAP_Buffer *pWriteData,
                            TAP_Buffer *pUpdatedData, 
                            TAP_TRUSTED_DATA_TYPE trustedDataType, 
                            TAP_TrustedDataInfo* pTrustedDataInfo)
{
    MSTATUS     status = OK;

    /* Update */
    status = TAP_updateTrustedData(pTapContext, gpEntityCredentials, 
                                   trustedDataType, pTrustedDataInfo, 
                                   TAP_TRUSTED_DATA_OPERATION_UPDATE, 
                                   pWriteData, pUpdatedData, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Update operation using TAP_updateTrustedData failed");
        goto exit;
    }
    PRINT_SUCCESS("Update operation using TAP_updateTrustedData completed");

    /* Read current data after update */
    status = readTrustedData(pTapContext, pUpdatedData, trustedDataType, 
                             pTrustedDataInfo);
    if (OK != status)
    {
        goto exit;
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

/* runTrustedDataTest
 * Flow - 
 *  Reads the Trusted-Data
 *  Prepares a SHA256 digest of some plain text
 *  Extends using the above digest
 *  Compares original and extended data 
 */
MSTATUS runTrustedDataTest(TAP_Context *pTapContext)
{
    MSTATUS                 status = OK;
    ubyte                   trustedDataKey = 23; /* Trusted Data Key being read */
    ubyte4                  iter = 0;
    TAP_TRUSTED_DATA_TYPE   trustedDataType = TAP_TRUSTED_DATA_TYPE_MEASUREMENT;
    TAP_HASH_ALG            tapTrustKeyHashAlg = TAP_HASH_ALG_SHA256;
    sbyte4                  result = 0;
    TAP_Buffer              readData = {0};
    ubyte                   writeBuf[SHA256_RESULT_SIZE] = {0};
    TAP_Buffer              updatedData = {0};
    TAP_Buffer              writeData = 
                            {
                                .pBuffer    = writeBuf,
                                .bufferLen  = SHA256_RESULT_SIZE,    
                            };

    TAP_Buffer*             pPlainTextBuffer = NULL;

    /* Define TAP_Attribute for TAP_ATTR_TRUSTED_DATA_KEY type,
     * with key value to read/update */
    TAP_Buffer              tapTrustKeyAttr = 
                                    {
                                        .pBuffer = &trustedDataKey,
                                        .bufferLen = sizeof(trustedDataKey)
                                    };
    TAP_Attribute           trustDataKey_Attribute = 
                                    {
                                        .type = TAP_ATTR_TRUSTED_DATA_KEY,
                                        .length = sizeof(tapTrustKeyAttr),
                                        .pStructOfType = &tapTrustKeyAttr
                                    };
    /* Define TAP_Attribute for TAP_ATTR_HASH_ALG type, 
     * with hash algorithm to use */
    TAP_Attribute           trustDataHashAlg_Attribute = 
                                    {
                                        .type = TAP_ATTR_HASH_ALG, 
                                        .length = sizeof(tapTrustKeyHashAlg), 
                                        .pStructOfType = &tapTrustKeyHashAlg
                                    };
    /* Define TAP_Attribute list/array with all the attributes defined above,
     * for trusted data operations */
    TAP_Attribute           tapTrustKeyAttrList[] = 
                            {
                                trustDataKey_Attribute,
                                trustDataHashAlg_Attribute
                            };
    TAP_TrustedDataInfo     trustedDataInfo =
                            {
                                .subType = EXAMPLE_TAP_TRUSTED_DATA_SUBTYPE_NONE,
                                .attributes = 
                                {
                                    .listLen = sizeof(tapTrustKeyAttrList)/sizeof(TAP_Attribute), 
                                    .pAttributeList = tapTrustKeyAttrList
                                }
                            };

    hwAccelDescr hwAccelCtx = 0;
    
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
        goto exit;
    
    /* Read */
    status = readTrustedData(pTapContext, &readData, trustedDataType, 
                             &trustedDataInfo); 
    if (OK != status)
    {
        PRINT_ERR(status, "Read operation failed for trusted-data");
        goto exit;
    }

    /* Prepare new data to write for update
     * Get some text and prepare its digest using SHA-256 */
    pPlainTextBuffer = getPlainTextToEncrypt();
    if (!pPlainTextBuffer)
    {
        status = ERR_NULL_POINTER;
        PRINT_ERR(status, "getPlainTextToEncrypt failed");
        goto exit;
    }
    /* Digest the input data */
    status = SHA256_completeDigest(MOC_HASH(hwAccelCtx) pPlainTextBuffer->pBuffer, 
                                   pPlainTextBuffer->bufferLen, 
                                   writeData.pBuffer);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed creating SHA256 digest");
    }
    writeData.bufferLen  = SHA256_RESULT_SIZE;   

    /* Update */
    DB_PRINT("Data to be extended to Trusted-Data:\n\t");
    for (iter=0; iter < writeData.bufferLen; iter++)
    {
        DB_PRINT("%02x ", writeData.pBuffer[iter]);
    }
    DB_PRINT("\n");

    status = extendTrustedData(pTapContext, &writeData, &updatedData,
                               trustedDataType, &trustedDataInfo); 
    if (OK != status)
    {
        PRINT_ERR(status, "Update operation failed for trusted-data");
        goto exit;
    }

    /* Compare latest read data with updated data */ 
    status = DIGI_MEMCMP(readData.pBuffer, writeData.pBuffer, 
                        readData.bufferLen, &result);
    if ( ( OK != status) || (0 == result) )
    {
        PRINT_ERR(status, "Comparison failed: "
                          "Updated and Original data cant be equal");
        goto exit;
    }
    else
    {
        PRINT_SUCCESS("Trusted Data successfully read and extended");
    }

exit:

    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    
    if (NULL != readData.pBuffer)
    {
        TAP_UTILS_freeBuffer(&readData);
    }
    if (NULL != pPlainTextBuffer && NULL != pPlainTextBuffer->pBuffer)
    {
        TAP_UTILS_freeBuffer(pPlainTextBuffer);
    }
    if (NULL != updatedData.pBuffer)
    {
        TAP_UTILS_freeBuffer(&updatedData);
    }

    return status;
}
 

/*------------------------------------------------------------------*/
/*  SEAL WITH TRUSTED DATA                                          */
/*------------------------------------------------------------------*/

/*------------------------------------------------------------------*/

/* sealData
 * Demonstrates usage of 
 *  TAP_sealWithTrustedData
 */
MSTATUS sealData(   TAP_Context*        pTapContext,
                    TAP_Buffer*         pSealedData,
                    TAP_Buffer*         pDataToSeal,
                    TAP_SealAttributes* pSealAttributes,
                    TAP_OBJECT_TYPE     objectType
                )
{
    MSTATUS             status = OK;
    ubyte4              iter = 0;

    status = TAP_sealWithTrustedData(pTapContext, gpEntityCredentials, 
                                     objectType, NULL,
                                     NULL, pSealAttributes,
                                     pDataToSeal, pSealedData, 
                                     &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Seal operation using "
                          "TAP_sealWithTrustedData failed");
        goto exit;
    }
    PRINT_SUCCESS("Seal With Trusted Data completed");


    if( NULL == pSealedData->pBuffer || 0 >= pSealedData->bufferLen )
    {
        status = ERR_GENERAL;
        PRINT_ERR(status, "Sealed data is empty");
        goto exit;
    }

    DB_PRINT("Sealed Data size = %d\nSealed data buffer:-\n\t",
             pSealedData->bufferLen, pSealedData->pBuffer);
    for (iter = 0; iter < pSealedData->bufferLen; iter++) 
    {
        if (0 == iter%32)
            DB_PRINT("\n\t");
        DB_PRINT("%02x ",pSealedData->pBuffer[iter]);
    }
    DB_PRINT("\n");


exit:
    return status;
}


/*------------------------------------------------------------------*/

/* unsealData
 * Demonstrates usage of 
 *  TAP_unsealWithTrustedData
 */
MSTATUS unsealData( TAP_Context*        pTapContext,
                    TAP_Buffer*         pSealedData,
                    TAP_Buffer*         pUnsealedData,
                    TAP_SealAttributes* pSealAttributes,
                    TAP_OBJECT_TYPE     objectType
                  )
{
    MSTATUS status = OK;
    ubyte4  iter = 0;

    status = TAP_unsealWithTrustedData(pTapContext, gpEntityCredentials, 
                                       objectType , NULL,
                                       pSealAttributes, pSealedData, 
                                       pUnsealedData, &gErrContext);
    if (OK != status)
    {
        DB_PRINT("TAP_unsealWithTrustedData failed with status %d\n", status);
        goto exit;
    }
    DB_PRINT("UnSeal With Trusted Data OK.\n");

    if (OK != status)
    {
        PRINT_ERR(status, "Unseal operation using "
                          "TAP_unsealWithTrustedData failed");
        goto exit;
    }
    PRINT_SUCCESS("Unseal With Trusted Data completed");


    if( NULL == pUnsealedData->pBuffer || 0 >= pUnsealedData->bufferLen )
    {
        status = ERR_GENERAL;
        PRINT_ERR(status, "Unsealed data is empty");
        goto exit;
    }

    DB_PRINT("Unsealed Data size = %d\nUnsealed data buffer:-\n\t",
             pUnsealedData->bufferLen, pUnsealedData->pBuffer);
    for (iter = 0; iter < pUnsealedData->bufferLen; iter++) 
    {
        if (0 == iter%32)
            DB_PRINT("\n\t");
        DB_PRINT("%02x ", pUnsealedData->pBuffer[iter]);
    }
    DB_PRINT("\n");

exit:
    return status;
}

/*------------------------------------------------------------------*/

/* runSealUnsealTest
 * Flow - 
 *  Get a plain text data
 *  Seal the plain text and get SealedData
 *  Unseal the sealed-data from above
 *  compare with plain data
 */
MSTATUS runSealUnsealTest(TAP_Context *pTapContext)
{
    MSTATUS             status = OK;
    sbyte4              result = 0;
    TAP_Buffer*         pDataToSeal = NULL;
    TAP_Buffer          sealedData = {0};
    TAP_Buffer          unsealedData = {0};
    TAP_SealAttributes* pSealAttributes = NULL;
    TAP_OBJECT_TYPE     objectType = TAP_OBJECT_TYPE_UNDEFINED;

    pDataToSeal = getPlainTextToEncrypt();

    if (!pDataToSeal)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("getPlainTextToEncrypt failed\n");
        goto exit;
    }

    /* Seal data */
    status = sealData(pTapContext, &sealedData, 
                      pDataToSeal, pSealAttributes, objectType);   
    if (OK != status)
    {
        DB_PRINT("sealData failed with status %d\n", status);
        goto exit; 
    }

    /* Unseal data */  
    status = unsealData(pTapContext, &sealedData, &unsealedData, 
                        pSealAttributes, objectType);

    /* Comparing dataToSeal and unSealedData */
    status = DIGI_MEMCMP(pDataToSeal->pBuffer, unsealedData.pBuffer, 
                        pDataToSeal->bufferLen, &result);
    if ( OK != status)
    {
        DB_PRINT("DIGI_MEMCMP failed with status %d\n", status);
    }
    else
    {
        if (result == 0)
        {
            PRINT_SUCCESS("Sealed data matched the unsealed data");
        }
        else
        {
            status = ERR_GENERAL;
            PRINT_ERR(status, "Sealed data did not match the unsealed data.\n");
        }
    }

exit:
    if (NULL != pDataToSeal && NULL != pDataToSeal->pBuffer)
    {
        TAP_UTILS_freeBuffer(pDataToSeal);
    }
    if (NULL != sealedData.pBuffer)
    {
        TAP_UTILS_freeBuffer(&sealedData);
    }
    if (NULL != unsealedData.pBuffer)
    {
        TAP_UTILS_freeBuffer(&unsealedData);
    }

    return status;
}


/*------------------------------------------------------------------*/
/*  Root of Trust Certificate                                       */
/*------------------------------------------------------------------*/


/*------------------------------------------------------------------*/

/* getRootKeyHandle - Internal method
 * get key handle for the root of trust certificate's corresponding objectID
 * This depends on the algorithm used to provision the TAP module, 
 * can be determined using TAP_getRootOfTrustHandle
 */
TAP_ObjectId getRootKeyHandle(TAP_PROVIDER providerType)
{
    /* The object id varies per SMP */ 
    switch(providerType)
    {
        case TAP_PROVIDER_TPM2:
            /* for TPM2, it is the EK that will be persisted at the 
             * first reserved handle in the Endorsement heirarchy
             */
#if defined(__RTOS_WIN32__) && !defined(__USE_TPM_EMULATOR__)
            return 0x81010001;
#else
            return 0x81010000;
#endif
        default:
            DB_PRINT("%s.%f Key-Handle undefined for Prorvider-Type=%d\n",
                    __FUNCTION__, __LINE__, providerType);
            return 0;   /*Invalid Id*/
    }
}


/*------------------------------------------------------------------*/

/* getTrustRootKey
 * Gets Public Key of the Root of Trust.
 * Demonstrates usage of - 
 *  TAP_getRootOfTrustKey
 */ 
MSTATUS getTrustRootKey(    TAP_Module*   pTapModule,
                            TAP_Context*  pTapContext,
                            TAP_Key**     ppRootKey 
                       )
{
    MSTATUS         status = OK;
    TAP_KeyInfo     rootKeyInfo = {0};

    rootKeyInfo.objectId  = getRootKeyHandle(pTapModule->providerType);
    if (0 >= rootKeyInfo.objectId)
    {
        status = ERR_NOT_FOUND;
        PRINT_ERR(status, "Invalid Key handle for root trust,");
        goto exit;
    }

    /* Get Root of Trust public Key */
    status = TAP_getRootOfTrustKey(pTapContext, &rootKeyInfo, 
                                   TAP_ROOT_OF_TRUST_TYPE_UNKNOWN,
                                   ppRootKey, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Could not get Root-of-Trust Key using "
                          "TAP_getRootOfTrustKey");
        goto exit;
    }
    if (NULL == *ppRootKey)
    {
        status = ERR_NOT_FOUND;
        PRINT_ERR(status, "TAP_getRootOfTrustKey returned NULL value in key");
        goto exit;
    }

    PRINT_SUCCESS("Fetched Root-Of-Trust Key");

    switch ((*ppRootKey)->keyData.publicKey.keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
            DB_PRINT("Root of Trust Key is of type - RSA\n");
            break;

        case TAP_KEY_ALGORITHM_ECC:
            DB_PRINT("Root of Trust Key is of type - ECC\n");
            break;

        case TAP_KEY_ALGORITHM_DSA:
            DB_PRINT("Root of Trust Key is of type - DSA\n");
            break;

        default:
            DB_PRINT("Root of Trust Key is of type - Unknown\n");
            break;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

/* getTrustRootCertificate
 * Gets Root of Trust Certificate
 * Demonstrates usgae of - 
 *  TAP_getRootOfTrustCertificate
 */ 
MSTATUS getTrustRootCertificate ( TAP_Module*   pTapModule,
                                  TAP_Context*  pTapContext,
                                  TAP_Key*      pRootKey,
                                  TAP_Blob*     pRootCertBlob,
                                  const char*   rootTrustCertFilePath )
{
    MSTATUS                 status = OK;
    TAP_ROOT_OF_TRUST_TYPE  certType = TAP_ROOT_OF_TRUST_TYPE_UNKNOWN;
    TAP_ObjectInfo          rootInfo = {0};

    /* Set object-id according to the TAP-provider type */
    rootInfo.objectId = getRootKeyHandle(pTapModule->providerType);

    status = TAP_getRootOfTrustCertificate( pTapContext,  &rootInfo, certType,
                                            pRootCertBlob, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "Could not retrieve root-of-trust certificate "
                          "using TAP_getRootOfTrustCertificate API");
        goto exit;
    }
    if ( (NULL == pRootCertBlob->blob.pBuffer) || 
         (0 >= pRootCertBlob->blob.bufferLen) )
    {
        PRINT_ERR(status, "Retrieved EMPTY root-of-trust certificate blob");
        goto exit;
    }

    PRINT_SUCCESS("Retrieved root-of-trust certificate "
                  "using TAP_getRootOfTrustCertificate API");

    /* Write private key to file */
    status = DIGICERT_writeFile(rootTrustCertFilePath, 
                              pRootCertBlob->blob.pBuffer,
                              pRootCertBlob->blob.bufferLen );
    if (OK != status)
    {
        DB_PRINT("Failed to write root-of-trust certificate blob, error %d\n",
                 status);
        goto exit;
    }
    DB_PRINT("Successfully wrote root-of-trust certificate blob to file "
             "\"%s\"\n", rootTrustCertFilePath);

exit:
    return status;
}


/*------------------------------------------------------------------*/

/* Unlike hardware modules, emulators are not employed with a root certificate,
 * Hence, these methods prepare test data at certain Policy-Storage indices,
 * depending on the TAP Provider type
 * NOTE - THIS IS ONLY NEEDED FOR TESTING ON EMULATOR
 */
#ifdef __USE_TPM_EMULATOR__

#define TPM2_RSA_EK_CERTIFICATE_NVRAM_ID    0x01c00002
#define TPM2_ECC_EK_CERTIFICATE_NVRAM_ID    0x01c0000a
#define EK_CERT_BLOB_LEN                    32
#define EK_CERT_TEST_DATA_CHAR              0x41

/* prepareRootTrustDataTpm2 - ONLY FOR TESTING on EMULATOR
 * writes test data of random size to the index where 
 * EK certificate is fetched from
 */
MSTATUS prepareRootTrustDataTpm2(TAP_Context* pTapContext, 
                                 TAP_KEY_ALGORITHM trustKeyAlgType)
{
    MSTATUS         status = OK;
    ubyte           writeBuf[EK_CERT_BLOB_LEN];
    TAP_Buffer      writeData = 
                    {
                        .pBuffer    = writeBuf,
                        .bufferLen  = EK_CERT_BLOB_LEN
                    };
    TAP_StorageInfo certWriteStorageInfo =
        {
        .index              = TPM2_RSA_EK_CERTIFICATE_NVRAM_ID,
        .size               = EK_CERT_BLOB_LEN,
        .storageType        = 0,
        .ownerPermission    = (TAP_PERMISSION_BITMASK_READ | TAP_PERMISSION_BITMASK_WRITE),
        .publicPermission   = (TAP_PERMISSION_BITMASK_READ | TAP_PERMISSION_BITMASK_WRITE),
        .pAttributes        = NULL 
        };
    TAP_EntityCredentialList*   pUsageCredentials = NULL;

    switch (trustKeyAlgType)
    {
        case TAP_KEY_ALGORITHM_RSA:
            certWriteStorageInfo.index = TPM2_RSA_EK_CERTIFICATE_NVRAM_ID;
            break;

        case TAP_KEY_ALGORITHM_ECC:
            certWriteStorageInfo.index = TPM2_ECC_EK_CERTIFICATE_NVRAM_ID;
            break;

        default:
            status = ERR_NOT_FOUND; /* To add as needed */
            goto exit;
    }

    DIGI_MEMSET(writeBuf, EK_CERT_TEST_DATA_CHAR, EK_CERT_BLOB_LEN);

    status = writeNewPolicyStorage(pTapContext, pUsageCredentials, 
                                       &certWriteStorageInfo, &writeData);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed writing test data to NVRAM at " 
                          "root-of-trust location");
        goto exit;
    }
    DB_PRINT("%s.%d Test data written to NVRAM index for "
            "Root-Of-Trust certificate\n", __FUNCTION__, __LINE__);

exit: 
    return status;
}

#endif /* __USE_TPM_EMULATOR__ */


/*------------------------------------------------------------------*/

/* initTestTrustCertIfNeeded
 * Needed only for testing on emulators. 
 * Add accordingly for more supported TAP Provider types as needed.
 */
MSTATUS initTestTrustCertIfNeeded(TAP_Module* pTapModule, TAP_Context *pTapContext,
                                  TAP_KEY_ALGORITHM trustKeyAlgType)
{
    MSTATUS status = OK;

    switch(pTapModule->providerType)
    {
        case TAP_PROVIDER_TPM2:
#ifdef __USE_TPM_EMULATOR__
            status = prepareRootTrustDataTpm2(pTapContext, trustKeyAlgType);
#else
            DB_PRINT("%s.%f No test data preparation needed\n");
#endif
        break;

        default:
            DB_PRINT("%s.%f No test data preparation needed\n");
        break;
    }

    return status;
}

/*------------------------------------------------------------------*/

/* runRootTrustTest
 * Executes TAP APIs for fetching root of trust certificate and key
 * Flow - 
 *  get root-of-trust key
 *  if executing on emulator set the test data for trust certificate
 *  check the root-of-trust key algorithm type
 *  get root-of-trust certificate as per the key algorithm type
 */
MSTATUS runRootTrustTest(   TAP_Module* pTapModule, 
                            TAP_Context *pTapContext)
{
    MSTATUS         status = OK;
    TAP_Blob        rootTrustCertBlob = {0};
    const char*     rootTrustCertFilePath = "root_trust_certificate";
    TAP_Key*        pRootKey = NULL;

    status = getTrustRootKey(pTapModule, pTapContext, &pRootKey);
    if (OK != status)
    {
        PRINT_ERR(status, "Could not get Root Key");
        goto exit;
    }
    PRINT_SUCCESS("Fetched Root Key");

    initTestTrustCertIfNeeded(pTapModule, pTapContext,
                                pRootKey->keyData.publicKey.keyAlgorithm);

    /* Call TAP API to get Root of Trust Certificate */
    status = getTrustRootCertificate(pTapModule, pTapContext, 
                                     pRootKey, &rootTrustCertBlob, 
                                     rootTrustCertFilePath);
    if (OK != status)
    {
        PRINT_ERR(status, "Could not get Root Certificate");
        goto exit;
    }
    PRINT_SUCCESS("Fetched Root Certificate");

exit:
    if (NULL != pRootKey)
    {
        if (OK != TAP_freeKey(&pRootKey))
        {
            DB_PRINT("%s.%d Failed to release memory for pRootKey\n",
                    __FUNCTION__, __LINE__);
        }
    }

    if (NULL != rootTrustCertBlob.blob.pBuffer)
    {
        TAP_UTILS_freeBuffer(&(rootTrustCertBlob.blob));
    }

    return status;
}


/*------------------------------------------------------------------*/
/* Internal Util methods
 */
 
const char* getTapProviderName(TAP_PROVIDER provider)
{
    switch (provider)
    {
        case  TAP_PROVIDER_SW:
            return "TAP_PROVIDER_SW";
        case  TAP_PROVIDER_TPM:
            return "TAP_PROVIDER_TPM";
        case  TAP_PROVIDER_TPM2:
            return "TAP_PROVIDER_TPM2";
        case  TAP_PROVIDER_SGX:
            return "TAP_PROVIDER_SGX";
        case  TAP_PROVIDER_STSAFE:
            return "TAP_PROVIDER_STSAFE";
        case  TAP_PROVIDER_NXPA71:
            return "TAP_PROVIDER_NXPA71";
        case  TAP_PROVIDER_GEMSIM:
            return "TAP_PROVIDER_GEMSIM";
        case  TAP_PROVIDER_PKCS11:
            return "TAP_PROVIDER_PKCS11";
        case  TAP_PROVIDER_RENS5:
            return "TAP_PROVIDER_RENS5";
        case  TAP_PROVIDER_TRUSTX:
            return "TAP_PROVIDER_TRUSTX";
        case  TAP_PROVIDER_ARMM23:
            return "TAP_PROVIDER_ARMM23";
        case  TAP_PROVIDER_ARMM33:
            return "TAP_PROVIDER_ARMM33";
        case  TAP_PROVIDER_EPID:
            return "TAP_PROVIDER_EPID";
        case  TAP_PROVIDER_TEE:
            return "TAP_PROVIDER_TEE";
        case  TAP_PROVIDER_NANOROOT:
            return "TAP_PROVIDER_NANOROOT";
        case  TAP_PROVIDER_UNDEFINED:
        default:
            return "UNDEFINED";
    }
}


/*------------------------------------------------------------------*/

void printTapAttributes(const TAP_AttributeList *pAttrList)
{
    int iter = 0;
    if ( (NULL == pAttrList) || (0 >= pAttrList->listLen) )
    {
        DB_PRINT("Attribute list is empty!!!\n");
        return;
    }

    DB_PRINT("\tNo\tType\tLength\tIs NULL?\n"
             "\t--\t----\t------\t--------\n");
    for (iter=0; iter < pAttrList->listLen; iter++)
    {
        DB_PRINT("\t%d\t%d\t%d\t%s\n", iter+1,
                 pAttrList->pAttributeList[iter].type,
                 pAttrList->pAttributeList[iter].length,
                 (NULL==pAttrList->pAttributeList[iter].pStructOfType)?"YES":"NO" );
    }
}


/*------------------------------------------------------------------*/

void printTapBuffer(const TAP_Buffer* pTapBuffer)
{
    int iter = 0;
    if ( (NULL == pTapBuffer) || (0 >= pTapBuffer->bufferLen) )
    {
        DB_PRINT("Buffer is empty!!!\n");
        return;
    }

    for (iter=0; iter < pTapBuffer->bufferLen; iter++)
    {
        DB_PRINT("%c%02x",
                (0==iter%8)?'\n':'\t',
                pTapBuffer->pBuffer[iter] );
    }
    DB_PRINT("\n");
}



/*------------------------------------------------------------------*/

TAP_Buffer* getPlainTextToEncrypt(void)
{
    TAP_Buffer* plainBuffer = NULL;
    char*       plainText = "Mocana secures your world";
    MSTATUS     status = OK;

    status = DIGI_CALLOC((void**)(&plainBuffer), 1, sizeof(TAP_Buffer));

    if (OK == status)
    {
       plainBuffer->bufferLen = DIGI_STRLEN((sbyte *)plainText);
       status = DIGI_CALLOC((void**)&(plainBuffer->pBuffer), 
               plainBuffer->bufferLen, sizeof(ubyte)); 
       if (OK == status)
       {
           status = DIGI_MEMCPY((void*)plainBuffer->pBuffer, 
                            (void*)plainText, plainBuffer->bufferLen); 
       }
    }

    if (OK != status)
    {
        if (NULL != plainBuffer)
        {
            if (NULL != plainBuffer->pBuffer)
            {
                DIGI_FREE((void**)&(plainBuffer->pBuffer));
            }
            DIGI_FREE((void **)&plainBuffer);
        }
        plainBuffer = NULL;
    }

    return plainBuffer;
}


/*------------------------------------------------------------------*/

void printHelp()
{
    printf("tap_api_example: Help Menu\n\n"
           "This example demonstrates usage of Mocana TAP APIs to "
           "leverage functionality offered by underlying security element\n\n"
           "Options:\n"
           "\t\t\t--h [Display help]\n"
           "\t\t\t\tHelp menu\n");
#ifdef __ENABLE_TAP_REMOTE__
    printf("\t\t\t--s=[server name]\n");
    printf("\t\t\t\tMandatory. Host on which TPM chip is located.  This can be 'localhost' or a\n"
           "\t\t\t\tremote host running a TAP server.\n");
    printf("\t\t\t--p=[server port]\n");
    printf("\t\t\t\tPort on which the TAP server is listening.\n");
    printf("\t\t\t--fsmode=[Filesystem mode]\n");
    printf("\t\t\t\tOptional, Demonstrates use of TAP client configuration using configuration\n"
           "\t\t\t\tbuffer instead of tapc.conf. Possible values are fs and non-fs\n"
           "\t\t\t\tNote: In non-fs mode Root Certificate (rootcert.der), \n"
           "\t\t\t\tClient key file (clientkey.pem) and Client Certificate (clientcert.der)\n"
           "\t\t\t\tmust be present in the same directory as the application\n"); 
#else
    printf("\t\t\t--tpm2conf [TPM2 Configuration file]\n"
           "\t\t\t\tPath to configuration file for TPM2 module\n"
           );
#endif
    return;
}


/*------------------------------------------------------------------*/
enum CmdOpt {
    HELP            =   1,
    SERVER_NAME     =   2,
    SERVER_PORT     =   3,
    MODE            =   4,
    TPM2_CONF_FILE  =   5,
};

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__) || defined(__RTOS_WIN32__)
MSTATUS pasrseCmdLineOpts(CmdLineOpts *pOpts, int argc, char *argv[])
{
    MSTATUS         status = -1;
    int             c = 0;
    int             options_index = 0;
    const char *    optstring = "";
    const struct    option options[] = {
                        {"h", no_argument, NULL, HELP},
                        {"s", required_argument, NULL, SERVER_NAME},
                        {"p", required_argument, NULL, SERVER_PORT},
                        {"fsmode",required_argument, NULL, MODE},
                        {"tpm2conf", required_argument, NULL, TPM2_CONF_FILE},
                        {NULL, 0, NULL, 0},
                    };
    int             optValueLen = 0;
#ifdef __ENABLE_TAP_REMOTE__
    sbyte4      cmpResult = 0;
#endif
    if ( (NULL == pOpts) || (NULL == argv) || (0 == argc) )
    {
        status = ERR_INVALID_ARG;
        PRINT_ERR(status, "Invalid parameters.");
        goto exit;
    }

    while (TRUE)
    {
        c = getopt_long(argc, argv, optstring, options, &options_index);
        if ((-1 == c))
            break;

        switch (c)
        {
            case TPM2_CONF_FILE:
                {
                    pOpts->tpm2ConfigFileSpecified = TRUE;
                    optValueLen = DIGI_STRLEN((const sbyte *)optarg); 
                    if (optValueLen > FILE_PATH_LEN)
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("Server name too long. Max size: %d bytes\n", 
                                FILE_PATH_LEN);
                        goto exit;
                    }
                    if ((optValueLen == 0) || ('-' == optarg[0]))
                    {
                        status = ERR_INVALID_ARG;
                        PRINT_ERR(status, 
                                  "Configuration file path not specified");
                        goto exit;
                    }

                    status = DIGI_MEMCPY(pOpts->tpm2confFilePath, 
                                        optarg, optValueLen);
                    if (OK != status)
                    {
                        PRINT_ERR(status, "Failed to copy memory");
                        goto exit;
                    }
                    DB_PRINT("TPM2 Configuration file path: %s\n", 
                             pOpts->tpm2confFilePath);
                }
                break;

                case SERVER_NAME:
#ifdef __ENABLE_TAP_REMOTE__
                pOpts->serverNameSpecified = TRUE;
                if (DIGI_STRLEN((const sbyte *)optarg) > SERVER_NAME_LEN)
                {
                    status = ERR_INVALID_ARG;
                    DB_PRINT("Server name too long. Max size: %d bytes",
                            SERVER_NAME_LEN);
                    goto exit;
                }
                pOpts->serverNameLen = DIGI_STRLEN((const sbyte *)optarg) + 1;
                if ((pOpts->serverNameLen == 0) ||
                    ('-' == optarg[0]))
                {
                    status = ERR_INVALID_ARG;
                    PRINT_ERR(status,"-s Server name not specified");
                    goto exit;
                }

                if (OK != DIGI_MEMCPY(pOpts->serverName, optarg,
                            DIGI_STRLEN((const sbyte *)optarg)))
                {
                    DB_PRINT("Failed to copy memory");
                    goto exit;
                }
                DB_PRINT("TPM2 Server/Module name: %s", pOpts->serverName);
#else
                status = ERR_INVALID_ARG;
                PRINT_ERR(status,"Server name not a valid option in a local-only build\n");
                goto exit;
#endif
                break;

            case SERVER_PORT:
#ifdef __ENABLE_TAP_REMOTE__
                pOpts->serverPort = strtol(optarg, NULL, 0);
                if (pOpts->serverPort == 0)
                {
                    status = ERR_INVALID_ARG;
                    PRINT_ERR(status,"Invalid or no port number specified");
                    goto exit;
                }
                DB_PRINT("Server Port: %d", pOpts->serverPort);
#else
                status = ERR_INVALID_ARG;
                PRINT_ERR(status,"Server port not a valid option in a local-only build\n");
                goto exit;
#endif
                break;

            case MODE:
#ifdef __ENABLE_TAP_REMOTE__
                pOpts->modeNameSpecified = TRUE;

                OPT_VAL_INFO optionValues[] = {
                        {"fs", FS_MODE},
                        {"non-fs", NON_FS_MODE},
                        {NULL, 0},
                    };   
                    ubyte oIndex;

                    if ((DIGI_STRLEN((const sbyte *)optarg) == 0) ||
                        ('-' == optarg[0]))
                    {
                        status = ERR_INVALID_ARG;
                        PRINT_ERR(status,"-fsmode not specified");
                        goto exit;
                    }    

                    for (oIndex = 0; optionValues[oIndex].pName; oIndex++)
                    {    
                        cmpResult = 1; 
                        if (DIGI_STRLEN((const sbyte *)optionValues[oIndex].pName) ==
                                DIGI_STRLEN((const sbyte *)optarg))
                        {    
                            if (OK != DIGI_MEMCMP((const ubyte *)optarg, (const ubyte *)optionValues[oIndex].pName,
                                        DIGI_STRLEN((const sbyte *)optionValues[oIndex].pName), &cmpResult))
                            {
                                status = ERR_INVALID_ARG;
                                PRINT_ERR(status,"Failed to compare memory");
                                goto exit;
                            }

                            if (!cmpResult)
                            {
                                pOpts->modeName = optionValues[oIndex].val;
                                DB_PRINT("Mode - %s ",
                                        optionValues[oIndex].pName);
                                break;
                            }
                        }
                    }

                    if (NULL == optionValues[oIndex].pName)
                    {
                        status = ERR_INVALID_ARG;
                        PRINT_ERR(status,"--mode is not fs or non-fs");
                        goto exit;
                    }
#else
                status = ERR_INVALID_ARG;
                PRINT_ERR(status,"Mode name not a valid option in a local-only build\n");
                goto exit;
#endif
                break;
            case HELP:
            default:
                {
                    printHelp();
                    pOpts->exitAfterParse = TRUE;
                }
                break;
        }
    }
    status = OK;

exit:
    return status;
}
#endif

#ifdef __ENABLE_DIGICERT_NXPA71__
MSTATUS nanotap_get_nv_data(ubyte4 nvIndex, char *pFileName)
{
    MSTATUS                     status = OK;
    TAP_Module*                 pModule = NULL;
    TAP_ModuleList*             pModuleList = NULL;
    TAP_Context*                pTapContext = NULL;
    TAP_ConfigInfo      configInfo = {0};
    TAP_ConfigInfoList  configInfoList = {1, &configInfo};
    TAP_AttributeList getAttributes = { 0, NULL}  ;          
    TAP_ObjectInfo              *pObjectInfo = NULL;
    TAP_ObjectInfoList          objectInfoList = {0};
    TAP_Buffer nvOut = { 0 };
    int i = 0;

    status = DIGICERT_initialize(NULL, NULL);
    if (OK != status)
    {
        PRINT_ERR(status, "Mocana Init failed");
        goto exit;
    }
    status = initNXPA71TapConfigInfo(&configInfo);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed to retrieved a module configuration");
        goto exit;
    }
    status = TAP_init(&configInfoList, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "TAP_init failed");
        goto exit;
    }
    PRINT_SUCCESS("TAP Init completed successfully");
    TAP_UTILS_freeBuffer(&(configInfoList.pConfig->configInfo));
    status = getSmpList(&pModuleList);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed to fetch list of SMPs");
        goto exit;
    }
    PRINT_TEST_FOOTER("Get list of Providers and Modules");
    
    pModule = (TAP_Module *)&(pModuleList->pModuleList[0]);
    DB_PRINT("%s.%d Initializing module of type=%s\n", 
                __FUNCTION__, __LINE__, 
                getTapProviderName(pModule->providerType));

    status = initTapModule(pModule, &pTapContext);
    if ( (OK != status) || (NULL==pTapContext) )
    {
        PRINT_ERR(status, "Failed initializing module");
        goto exit;
    }
    PRINT_SUCCESS("Module Initialized ...");
    status = TAP_getPolicyStorageList(pTapContext, gpEntityCredentials, NULL,
                                        &objectInfoList, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "TAP_getPolicyStorageList failed with error %d");
        goto exit;
    }
    for(i= 0 ; i < objectInfoList.count ; i++)
    {
        if(objectInfoList.pInfo[i].objectId == nvIndex) 
            break ;
    }
    if(i == objectInfoList.count)
    {
        PRINT_ERR(nvIndex, "Invalid storage index %d\n");
        goto exit;
    
    }
    pObjectInfo = &objectInfoList.pInfo[i];
    
    /* Read */
    status = TAP_getPolicyStorage(pTapContext, gpEntityCredentials, pObjectInfo,
                  &getAttributes, &nvOut, &gErrContext);

    if (OK != status)
    {
        PRINT_ERR(status, "Error reading NVRAM, status = %d\n");
        goto exit;
    }
    else
    {
        /* Save output file */
        status = DIGICERT_writeFile((const char *)pFileName,
                nvOut.pBuffer, nvOut.bufferLen);
        if (OK != status)
        {
            PRINT_ERR(status, "Error writing NVRAM content to file, status = %d\n");
            goto exit;
        }

    }

exit:
    if(NULL != pTapContext)
    {
        uninitTapModule(&pTapContext);
    }
    TAP_uninit(&gErrContext);
    if (NULL != pModuleList)
    {
        TAP_freeModuleList(pModuleList);  
        DIGI_FREE((void**)&pModuleList);
    }
    if (NULL != gpEntityCredentials)
    {
        TAP_UTILS_clearEntityCredentialList(gpEntityCredentials);

        DIGI_FREE((void **)&gpEntityCredentials);
    }

    if (NULL != nvOut.pBuffer)
        DIGI_FREE((void **)&nvOut.pBuffer);

     if(NULL != objectInfoList.pInfo)
        DIGI_FREE((void**)&objectInfoList.pInfo);
    DIGICERT_free(NULL);

    return status ;
}

MSTATUS nanotap_set_nv_data(ubyte4 nvIndex, char *pFileName)
{
    MSTATUS                     status = OK;
    TAP_Module*                 pModule = NULL;
    TAP_ModuleList*             pModuleList = NULL;
    TAP_Context*                pTapContext = NULL;
    TAP_ConfigInfo      configInfo = {0};
    TAP_ConfigInfoList  configInfoList = {1, &configInfo};
    TAP_AttributeList getAttributes = { 0, NULL}  ;          
    TAP_ObjectInfo              *pObjectInfo = NULL;
    TAP_ObjectInfoList          objectInfoList = {0};
    TAP_StorageInfo storageInfo = {0} ;
    TAP_CredentialList   storageCredentials = {0} ;
    TAP_Buffer nvIn = { 0 };
    int i = 0;

    status = DIGICERT_initialize(NULL, NULL);
    if (OK != status)
    {
        PRINT_ERR(status, "Mocana Init failed");
        goto exit;
    }
    status = initNXPA71TapConfigInfo(&configInfo);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed to retrieved a module configuration");
        goto exit;
    }
    status = TAP_init(&configInfoList, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "TAP_init failed");
        goto exit;
    }
    PRINT_SUCCESS("TAP Init completed successfully");
    TAP_UTILS_freeBuffer(&(configInfoList.pConfig->configInfo));
    status = getSmpList(&pModuleList);
    if (OK != status)
    {
        PRINT_ERR(status, "Failed to fetch list of SMPs");
        goto exit;
    }
    PRINT_TEST_FOOTER("Get list of Providers and Modules");
    
    pModule = (TAP_Module *)&(pModuleList->pModuleList[0]);
    DB_PRINT("%s.%d Initializing module of type=%s\n", 
                __FUNCTION__, __LINE__, 
                getTapProviderName(pModule->providerType));

    status = initTapModule(pModule, &pTapContext);
    if ( (OK != status) || (NULL==pTapContext) )
    {
        PRINT_ERR(status, "Failed initializing module");
        goto exit;
    }
    PRINT_SUCCESS("Module Initialized ...");
    status = DIGICERT_readFile((const char *)pFileName,
            &nvIn.pBuffer, &nvIn.bufferLen);
    if (OK != status)
    {
        PRINT_ERR(status, "Error reading NVRAM contents from file, status = %d\n");
        goto exit;
    }

    status = TAP_getPolicyStorageList(pTapContext, gpEntityCredentials, NULL,
                                        &objectInfoList, &gErrContext);
    if (OK != status)
    {
        PRINT_ERR(status, "TAP_getPolicyStorageList failed with error %d");
        goto exit;
    }
    for(i= 0 ; i < objectInfoList.count ; i++)
    {
        if(objectInfoList.pInfo[i].objectId == nvIndex) 
            break ;
    }
    if(i == objectInfoList.count)
    {
        PRINT_ERR(nvIndex, "Invalid storage index %d\n");
        goto exit;
    
    }
    pObjectInfo = &objectInfoList.pInfo[i];
    
    storageInfo.index = nvIndex ;
    storageInfo.size = nvIn.bufferLen ;
    storageInfo.storageType = TAP_WRITE_OP_DIRECT ;
    storageInfo.ownerPermission = (TAP_PERMISSION_BITMASK_READ | TAP_PERMISSION_BITMASK_WRITE
                                        | TAP_PERMISSION_BITMASK_DELETE) ;
    storageInfo.publicPermission = (TAP_PERMISSION_BITMASK_READ | TAP_PERMISSION_BITMASK_WRITE
                                        | TAP_PERMISSION_BITMASK_DELETE) ;
    storageInfo.pAttributes = NULL ;
    /* Allocate policy */
    status = TAP_allocatePolicyStorage(pTapContext, gpEntityCredentials, &storageInfo,
                                         NULL, &storageCredentials, 
                                         &gErrContext);


    if (OK != status)
    {
        PRINT_ERR(status, "Error allocating policy storage, status = %d\n");
        goto exit;
    }
    /* Read */
    status = TAP_setPolicyStorage(pTapContext, gpEntityCredentials, pObjectInfo,
                  &getAttributes, &nvIn, &gErrContext);

    if (OK != status)
    {
        PRINT_ERR(status, "Error reading NVRAM, status = %d\n");
        goto exit;
    }

exit:
    if(NULL != pTapContext)
    {
        uninitTapModule(&pTapContext);
    }
    TAP_uninit(&gErrContext);
    if (NULL != pModuleList)
    {
        TAP_freeModuleList(pModuleList);  
        DIGI_FREE((void**)&pModuleList);
    }
    if (NULL != gpEntityCredentials)
    {
        TAP_UTILS_clearEntityCredentialList(gpEntityCredentials);
        DIGI_FREE((void **)&gpEntityCredentials);
    }

    if (NULL != nvIn.pBuffer)
        DIGI_FREE((void **)&nvIn.pBuffer);

     if(NULL != objectInfoList.pInfo)
        DIGI_FREE((void**)&objectInfoList.pInfo);
    DIGICERT_free(NULL);

    return status ;
}
#endif

/*------------------------------------------------------------------*/
#endif  /* defined(__ENABLE_DIGICERT_TAP__)) && defined(__ENABLE_DIGICERT_EXAMPLES__) */
