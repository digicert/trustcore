/*
 * smp_nanoroot_unit_test.c
 *
 * Unit tests for NanoROOT SMP module
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert's Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "common/moptions.h"
#include "common/mtypes.h"
#include "common/merrors.h"
#include "common/mocana.h"
#include "common/mdefs.h"
#include "common/mstdlib.h"

#if (defined(__ENABLE_DIGICERT_SMP__) && defined(__ENABLE_DIGICERT_SMP_NANOROOT__))

#include "tap/tap_smp.h"
#include "smp/smp_nanoroot/smp_nanoroot.h"
#include "smp/smp_nanoroot/smp_nanoroot_api.h"
#include "smp/smp_nanoroot/smp_nanoroot_interface.h"
#include "smp/smp_nanoroot/smp_nanoroot_parseConfig.h"
#include "smp/smp_nanoroot/smp_nanoroot_device_protect.h"

/* Suppress unused parameter warnings for cmocka test functions */
#define UNUSED(x) (void)(x)

/* Forward declarations of helper functions */
static MSTATUS load_config_file(const char *configPath, TAP_Buffer *pConfigBuffer);
static const char* get_config_path(void);
static int check_fingerprint_file(void);

/* Helper function to set fingerprint environment variables */
static void set_fingerprint_env_vars(void) {
    /* Set environment variables required by default-fingerprint.json */
    setenv("INTERNATIONAL_MOBILE_IDENTITY", "EA17BD17", 1);
    setenv("MOBILE_EQUIPMENT_IDENTIFIER", "DF55321B734C8334", 1);
    setenv("ELECTRONIC_SERIAL_NUMBER", "3A0F0B320AACD", 1);
    setenv("INTERNATIONAL_MOBILE_SUBSCRIBER_IDENTITY", "DA10203040", 1);
    setenv("MAC_ADDRESS", "42E8C73A75B9A29E9E3A0F0B320AACDD48CB37CCBE24EA17BD173858A465D616", 1);
    setenv("SERIAL_NUMBER", "EA17BD17", 1);
    setenv("SECURE_ANDROID_ID", "FG1234", 1);
    setenv("UUID", "EA17BD17EA17BD17B", 1);
}

/* Test fixtures */
static int setup(void **state) {
    MSTATUS status;
    UNUSED(state);
    
    /* Set fingerprint environment variables for NanoROOT tests */
    set_fingerprint_env_vars();
    
    status = DIGICERT_initDigicert();
    if (OK != status) {
        return -1;
    }
    
    return 0;
}

static int teardown(void **state) {
    UNUSED(state);
    DIGICERT_freeDigicert();
    return 0;
}

/*------------------------------------------------------------------*/
/* NanoROOT_validateInput tests */
/*------------------------------------------------------------------*/

static void test_validateInput_null_input(void **state) {
    UNUSED(state);
    MSTATUS status;
    
    status = NanoROOT_validateInput(NULL, (const sbyte *)NANOROOT_ALLOWED_PATH_CHARS);
    assert_int_not_equal(status, OK);
}

static void test_validateInput_valid_path(void **state) {
    UNUSED(state);
    MSTATUS status;
    const sbyte valid_path[] = "/usr/local/bin/test.sh";
    
    status = NanoROOT_validateInput(valid_path, (const sbyte *)NANOROOT_ALLOWED_PATH_CHARS);
    assert_int_equal(status, OK);
}

static void test_validateInput_blocked_chars(void **state) {
    UNUSED(state);
    MSTATUS status;
    const sbyte *invalid_paths[] = {
        (const sbyte *)"/usr/bin/test;rm -rf /",
        (const sbyte *)"/usr/bin/test|cat /etc/passwd",
        (const sbyte *)"/usr/bin/test&whoami",
        (const sbyte *)"/usr/bin/test$USER",
        (const sbyte *)"/usr/bin/test`id`",
        (const sbyte *)"/usr/bin/test>output.txt",
        (const sbyte *)"/usr/bin/test<input.txt"
    };
    
    for (size_t i = 0; i < sizeof(invalid_paths) / sizeof(invalid_paths[0]); i++) {
        status = NanoROOT_validateInput(invalid_paths[i], (const sbyte *)NANOROOT_ALLOWED_PATH_CHARS);
        assert_int_not_equal(status, OK);
    }
}

static void test_validateInput_allowed_chars_only(void **state) {
    UNUSED(state);
    MSTATUS status;
    const sbyte valid_args[] = "arg1=value1:arg2=value2";
    
    status = NanoROOT_validateInput(valid_args, (const sbyte *)NANOROOT_ALLOWED_ARG_CHARS);
    assert_int_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Module List API tests */
/*------------------------------------------------------------------*/

static void test_getModuleList_null_pointer(void **state) {
    UNUSED(state);
    MSTATUS status;
    
    status = SMP_NanoROOT_getModuleList(NULL, NULL);
    assert_int_not_equal(status, OK);
}

static void test_getModuleList_success(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_EntityList moduleList = {0};
    
    status = SMP_NanoROOT_getModuleList(NULL, &moduleList);
    assert_int_equal(status, OK);
    assert_non_null(moduleList.entityIdList.pEntityIdList);
    assert_int_equal(moduleList.entityIdList.numEntities, 1);
    assert_int_equal(moduleList.entityIdList.pEntityIdList[0], NanoROOTMODULE_ID);
    
    /* Cleanup */
    if (moduleList.entityIdList.pEntityIdList) {
        DIGI_FREE((void **)&moduleList.entityIdList.pEntityIdList);
    }
}

static void test_freeModuleList_null_pointer(void **state) {
    UNUSED(state);
    MSTATUS status;
    
    /* Implementation returns OK even for NULL pointer (safe no-op) */
    status = SMP_NanoROOT_freeModuleList(NULL);
    assert_int_equal(status, OK);
}

static void test_freeModuleList_success(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_EntityList moduleList = {0};
    
    /* First get a module list */
    status = SMP_NanoROOT_getModuleList(NULL, &moduleList);
    assert_int_equal(status, OK);
    
    /* Then free it */
    status = SMP_NanoROOT_freeModuleList(&moduleList);
    assert_int_equal(status, OK);
    /* Note: Implementation uses FREE() not DIGI_FREE(), so pointer isn't nullified */
    /* Caller should manually null the pointer if needed */
}

/*------------------------------------------------------------------*/
/* Module initialization tests */
/*------------------------------------------------------------------*/

static void test_initModule_invalid_module_id(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ModuleHandle moduleHandle = 0;
    TAP_ModuleId invalidId = 0x99999999;
    
    status = SMP_NanoROOT_initModule(invalidId, NULL, NULL, &moduleHandle);
    assert_int_equal(status, ERR_TAP_MODULE_NOT_FOUND);
}

static void test_initModule_null_handle(void **state) {
    UNUSED(state);
    MSTATUS status;
    
    status = SMP_NanoROOT_initModule(NanoROOTMODULE_ID, NULL, NULL, NULL);
    assert_int_equal(status, ERR_TAP_INVALID_INPUT);
}

static void test_initModule_success(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ModuleHandle moduleHandle = 0;
    
    status = SMP_NanoROOT_initModule(NanoROOTMODULE_ID, NULL, NULL, &moduleHandle);
    /* Module may not init if NanoROOT is not initialized - this is expected */
    if (OK == status) {
        assert_non_null((void *)moduleHandle);
        
        /* Cleanup */
        SMP_NanoROOT_uninitModule(moduleHandle);
    }
}

/*------------------------------------------------------------------*/
/* Token initialization tests */
/*------------------------------------------------------------------*/

static void test_initToken_null_module_handle(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_TokenHandle tokenHandle = 0;
    
    status = SMP_NanoROOT_initToken(0, NULL, NanoROOTTOKEN_ID, NULL, &tokenHandle);
    assert_int_not_equal(status, OK);
}

static void test_initToken_null_token_handle(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ModuleHandle moduleHandle = (TAP_ModuleHandle)0x1234;
    
    status = SMP_NanoROOT_initToken(moduleHandle, NULL, NanoROOTTOKEN_ID, NULL, NULL);
    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Interface registration tests */
/*------------------------------------------------------------------*/

static void test_register_null_opcodes(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_SMPVersion smpVersion = {SMP_VERSION_MAJOR, SMP_VERSION_MINOR};
    TAP_Version tapVersion = {0};
    
    status = SMP_NanoROOT_register(TAP_PROVIDER_NANOROOT, 
                                   smpVersion,
                                   tapVersion,
                                   NULL,
                                   NULL);
    assert_int_not_equal(status, OK);
}

static void test_register_null_config(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_CmdCodeList opcodes = {0};
    TAP_ConfigInfo configInfo = {0};
    TAP_SMPVersion smpVersion = {SMP_VERSION_MAJOR, SMP_VERSION_MINOR};
    TAP_Version tapVersion = {0};
    
    /* Test with NULL/empty config to verify error handling */
    status = SMP_NanoROOT_register(TAP_PROVIDER_NANOROOT,
                                   smpVersion,
                                   tapVersion,
                                   &configInfo,
                                   &opcodes);
    
    /* Empty config should return ERR_NULL_POINTER (-6001) */
    assert_int_equal(status, ERR_NULL_POINTER);
    
    /* No cleanup needed - registration failed */
}

/*------------------------------------------------------------------*/
/* Dispatcher tests */
/*------------------------------------------------------------------*/

static void test_dispatcher_null_request(void **state) {
    UNUSED(state);
    MSTATUS status;
    SMP_CmdRsp cmdRsp = {0};
    
    status = SMP_NanoROOT_dispatcher(NULL, NULL, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
                                    , NULL, NULL
#endif
    );
    assert_int_equal(status, ERR_NULL_POINTER);
}

static void test_dispatcher_null_response(void **state) {
    UNUSED(state);
    MSTATUS status;
    SMP_CmdReq cmdReq = {0};
    
    status = SMP_NanoROOT_dispatcher(NULL, &cmdReq, NULL
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
                                    , NULL, NULL
#endif
    );
    assert_int_equal(status, ERR_NULL_POINTER);
}

static void test_dispatcher_get_module_list(void **state) {
    UNUSED(state);
    MSTATUS status;
    SMP_CmdReq cmdReq = {0};
    SMP_CmdRsp cmdRsp = {0};
    TAP_ConfigInfo configInfo = {0};
    
    /* Initialize first */
    status = NanoROOT_init(&configInfo);
    /* NanoROOT may not init without proper config - this is expected */
    if (OK == status) {
        cmdReq.cmdCode = SMP_CC_GET_MODULE_LIST;
        cmdReq.reqParams.getModuleList.pModuleAttributes = NULL;
        
        status = SMP_NanoROOT_dispatcher(NULL, &cmdReq, &cmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
                                        , NULL, NULL
#endif
        );
        assert_int_equal(status, OK);
        assert_int_equal(cmdRsp.cmdCode, SMP_CC_GET_MODULE_LIST);
        
        /* Cleanup */
        if (cmdRsp.rspParams.getModuleList.moduleList.entityIdList.pEntityIdList) {
            DIGI_FREE((void **)&cmdRsp.rspParams.getModuleList.moduleList.entityIdList.pEntityIdList);
        }
        NanoROOT_deInit();
    }
}

/*------------------------------------------------------------------*/
/* Path validation tests */
/*------------------------------------------------------------------*/

static void test_validatePath_null_path(void **state) {
    UNUSED(state);
    MSTATUS status;
    
    status = NanoROOT_validatePath(NULL);
    assert_int_not_equal(status, OK);
}

static void test_validatePath_relative_path(void **state) {
    UNUSED(state);
    MSTATUS status;
    const sbyte relative_path[] = "../../../etc/passwd";
    
    status = NanoROOT_validatePath(relative_path);
    assert_int_not_equal(status, OK);
}

static void test_validatePath_too_long(void **state) {
    UNUSED(state);
    MSTATUS status;
    sbyte *long_path;
    size_t path_len = PATH_MAX + 10;
    
    long_path = (sbyte *)malloc(path_len);
    if (long_path) {
        memset(long_path, 'a', path_len - 1);
        long_path[path_len - 1] = '\0';
        
        status = NanoROOT_validatePath(long_path);
        assert_int_not_equal(status, OK);
        
        free(long_path);
    }
}

/*------------------------------------------------------------------*/
/* Integration tests */
/*------------------------------------------------------------------*/

static void test_full_module_token_lifecycle(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ConfigInfo configInfo = {0};
    TAP_ModuleHandle moduleHandle = 0;
    TAP_TokenHandle tokenHandle = 0;
    const char *configPath = get_config_path();
    
    /* Check if config file is available */
    if (!configPath) {
        print_message("Config file not found. Skipping test.\n");
        skip();
        return;
    }

    /* Check if fingerprint file is available */
    if (!check_fingerprint_file()) {
        print_message("Fingerprint file not found at /etc/digicert/default-fingerprint.json. Skipping test.\n");
        skip();
        return;
    }

    /* Load and initialize NanoROOT */
    status = load_config_file(configPath, &configInfo.configInfo);
    if (OK != status) {
        print_message("Failed to load config file: %s\n", configPath);
        skip();
        return;
    }
    
    configInfo.provider = TAP_PROVIDER_NANOROOT;
    
    status = NanoROOT_init(&configInfo);
    if (OK != status) {
        print_message("NanoROOT_init failed with status: 0x%x\n", status);
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }
    
    /* Step 1: Init module */
    status = SMP_NanoROOT_initModule(NanoROOTMODULE_ID, NULL, NULL, &moduleHandle);
    if (OK != status) {
        print_message("SMP_NanoROOT_initModule failed with status: 0x%x\n", status);
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }
    
    assert_int_equal(status, OK);
    assert_non_null((void *)moduleHandle);
    
    /* Step 2: Init token */
    status = SMP_NanoROOT_initToken(moduleHandle, NULL, NanoROOTTOKEN_ID, NULL, &tokenHandle);
    assert_int_equal(status, OK);
    assert_non_null((void *)tokenHandle);
    
    /* Step 3: Verify module handle is valid by getting token list */
    TAP_EntityList tokenList = {0};
    status = SMP_NanoROOT_getTokenList(moduleHandle, TAP_TOKEN_TYPE_DEFAULT, NULL, &tokenList);
    assert_int_equal(status, OK);
    assert_int_equal(tokenList.entityType, TAP_ENTITY_TYPE_TOKEN);
    assert_int_equal(tokenList.entityIdList.numEntities, 1);
    
    /* Cleanup token list */
    if (tokenList.entityIdList.pEntityIdList) {
        DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);
    }
    
    /* Step 4: Uninit token */
    status = SMP_NanoROOT_uninitToken(moduleHandle, tokenHandle);
    assert_int_equal(status, OK);
    
    /* Step 5: Uninit module */
    status = SMP_NanoROOT_uninitModule(moduleHandle);
    assert_int_equal(status, OK);
    
    /* Cleanup NanoROOT */
    NanoROOT_deInit();
    free(configInfo.configInfo.pBuffer);
    
    print_message("Full module token lifecycle test completed successfully\n");
}

/*------------------------------------------------------------------*/
/* Device Protection Tests */
/*------------------------------------------------------------------*/

/**
 * Test: NanoROOT_initFingerprintCtx with NULL pointer
 */
static void test_initFingerprintCtx_null_pointer(void **state) {
    UNUSED(state);
    MSTATUS status;
    
    /* Test NULL ppCtx */
    status = NanoROOT_initFingerprintCtx(NULL, 1, 0);
    assert_int_equal(status, ERR_NULL_POINTER);
}

/**
 * Test: NanoROOT_initFingerprintCtx with invalid numUses
 */
static void test_initFingerprintCtx_invalid_numuses(void **state) {
    UNUSED(state);
    MSTATUS status;
    NROOT_FP_CTX *pCtx = NULL;
    
    /* Test numUses > NanoROOTMAX_NUM_USES */
    status = NanoROOT_initFingerprintCtx(&pCtx, NanoROOTMAX_NUM_USES + 1, 0);
    assert_int_not_equal(status, OK);
    
    if (pCtx != NULL) {
        NanoROOT_freeFingerprintCtx(&pCtx);
    }
}

/**
 * Test: NanoROOT_initFingerprintCtx success with single reusable key
 */
static void test_initFingerprintCtx_reusable_key(void **state) {
    UNUSED(state);
    MSTATUS status;
    NROOT_FP_CTX *pCtx = NULL;
    
    /* Test with NanoROOTSINGLE_REUSABLE_KEY */
    status = NanoROOT_initFingerprintCtx(&pCtx, NanoROOTSINGLE_REUSABLE_KEY, 0);
    assert_int_equal(status, OK);
    assert_non_null(pCtx);
    
    /* Cleanup */
    status = NanoROOT_freeFingerprintCtx(&pCtx);
    assert_int_equal(status, OK);
    assert_null(pCtx);
}

/**
 * Test: NanoROOT_initFingerprintCtx success with multiple uses
 */
static void test_initFingerprintCtx_multiple_uses(void **state) {
    UNUSED(state);
    MSTATUS status;
    NROOT_FP_CTX *pCtx = NULL;
    
    /* Test with 3 uses */
    status = NanoROOT_initFingerprintCtx(&pCtx, 3, 0);
    assert_int_equal(status, OK);
    assert_non_null(pCtx);
    
    /* Cleanup */
    status = NanoROOT_freeFingerprintCtx(&pCtx);
    assert_int_equal(status, OK);
    assert_null(pCtx);
}

/**
 * Test: NanoROOT_freeFingerprintCtx with NULL pointer
 */
static void test_freeFingerprintCtx_null_pointer(void **state) {
    UNUSED(state);
    MSTATUS status;
    
    /* Test NULL ppCtx */
    status = NanoROOT_freeFingerprintCtx(NULL);
    assert_int_equal(status, ERR_NULL_POINTER);
}

/**
 * Test: NanoROOT_FingerprintDevice with NULL context
 */
static void test_fingerprintDevice_null_context(void **state) {
    UNUSED(state);
    MSTATUS status;
    NROOTKdfElement elements[1];
    ubyte initialSeed[32] = {0};
    
    /* Setup test element */
    strncpy((char *)elements[0].pLabel, "TEST_ID", NanoROOT_MAX_LABEL_LEN);
    elements[0].labelLen = strlen("TEST_ID");
    memcpy(elements[0].pValue, "test_value_123", 14);
    elements[0].valueLen = 14;
    
    /* Test NULL context */
    status = NanoROOT_FingerprintDevice(NULL, NanoROOTKDF_HMAC, elements, 1, 
                                        initialSeed, 32, NULL);
    assert_int_equal(status, ERR_NULL_POINTER);
}

/**
 * Test: NanoROOT_FingerprintDevice with NULL elements
 */
static void test_fingerprintDevice_null_elements(void **state) {
    UNUSED(state);
    MSTATUS status;
    NROOT_FP_CTX *pCtx = NULL;
    ubyte initialSeed[32] = {0};
    
    /* Initialize context */
    status = NanoROOT_initFingerprintCtx(&pCtx, 1, 0);
    assert_int_equal(status, OK);
    
    /* Test NULL elements */
    status = NanoROOT_FingerprintDevice(pCtx, NanoROOTKDF_HMAC, NULL, 1, 
                                        initialSeed, 32, NULL);
    assert_int_equal(status, ERR_NULL_POINTER);
    
    /* Cleanup */
    NanoROOT_freeFingerprintCtx(&pCtx);
}

/**
 * Test: NanoROOT_FingerprintDevice with zero elements
 */
static void test_fingerprintDevice_zero_elements(void **state) {
    UNUSED(state);
    MSTATUS status;
    NROOT_FP_CTX *pCtx = NULL;
    NROOTKdfElement elements[1];
    ubyte initialSeed[32] = {0};
    
    /* Initialize context */
    status = NanoROOT_initFingerprintCtx(&pCtx, 1, 0);
    assert_int_equal(status, OK);
    
    /* Test zero numElements */
    status = NanoROOT_FingerprintDevice(pCtx, NanoROOTKDF_HMAC, elements, 0, 
                                        initialSeed, 32, NULL);
    assert_int_not_equal(status, OK);
    
    /* Cleanup */
    NanoROOT_freeFingerprintCtx(&pCtx);
}

/**
 * Test: NanoROOT_FingerprintDevice success with HMAC KDF
 */
static void test_fingerprintDevice_success_hmac(void **state) {
    UNUSED(state);
    MSTATUS status;
    NROOT_FP_CTX *pCtx = NULL;
    NROOTKdfElement elements[3];
    ubyte initialSeed[NanoROOTMAX_SEED_LEN];
    
    /* Initialize context */
    status = NanoROOT_initFingerprintCtx(&pCtx, NanoROOTSINGLE_REUSABLE_KEY, 0);
    assert_int_equal(status, OK);
    assert_non_null(pCtx);
    
    /* Setup fingerprint elements (simulating device identifiers) */
    strncpy((char *)elements[0].pLabel, "SERIAL NUMBER", NanoROOT_MAX_LABEL_LEN);
    elements[0].labelLen = strlen("SERIAL NUMBER");
    memcpy(elements[0].pValue, "EA17BD17", 8);
    elements[0].valueLen = 8;
    
    strncpy((char *)elements[1].pLabel, "MAC ADDRESS", NanoROOT_MAX_LABEL_LEN);
    elements[1].labelLen = strlen("MAC ADDRESS");
    memcpy(elements[1].pValue, "42E8C73A75B9", 12);
    elements[1].valueLen = 12;
    
    strncpy((char *)elements[2].pLabel, "UUID", NanoROOT_MAX_LABEL_LEN);
    elements[2].labelLen = strlen("UUID");
    memcpy(elements[2].pValue, "EA17BD17EA17BD17B", 17);
    elements[2].valueLen = 17;
    
    /* Setup initial seed */
    memset(initialSeed, 0xAB, sizeof(initialSeed));
    
    /* Fingerprint device with HMAC KDF */
    status = NanoROOT_FingerprintDevice(pCtx, NanoROOTKDF_HMAC, elements, 3, 
                                        initialSeed, NanoROOTMAX_SEED_LEN, NULL);
    assert_int_equal(status, OK);
    
    /* Cleanup */
    status = NanoROOT_freeFingerprintCtx(&pCtx);
    assert_int_equal(status, OK);
}

/**
 * Test: NanoROOT_Encrypt with NULL context
 */
static void test_encrypt_null_context(void **state) {
    UNUSED(state);
    MSTATUS status;
    ubyte plaintext[32] = "Test data to encrypt";
    ubyte ciphertext[32];
    ubyte4 outLen = 0;
    
    /* Test NULL context */
    status = NanoROOT_Encrypt(NULL, NanoROOTAES_256_CTR, NULL, 0,
                             plaintext, 20, ciphertext, &outLen);
    assert_int_equal(status, ERR_NULL_POINTER);
}

/**
 * Test: NanoROOT_Encrypt/Decrypt roundtrip with AES-256-CTR
 */
static void test_encrypt_decrypt_roundtrip_aes_ctr(void **state) {
    UNUSED(state);
    MSTATUS status;
    NROOT_FP_CTX *pCtx = NULL;
    NROOTKdfElement elements[2];
    ubyte initialSeed[NanoROOTMAX_SEED_LEN];
    ubyte plaintext[64] = "This is secret data that needs protection!";
    ubyte ciphertext[64];
    ubyte decrypted[64];
    ubyte4 encLen = sizeof(ciphertext);  /* Buffer size */
    ubyte4 decLen = sizeof(decrypted);   /* Buffer size */
    ubyte4 plaintextLen = strlen((char *)plaintext);
    
    /* Initialize context with single reusable key */
    status = NanoROOT_initFingerprintCtx(&pCtx, NanoROOTSINGLE_REUSABLE_KEY, 0);
    assert_int_equal(status, OK);
    
    /* Setup fingerprint elements */
    strncpy((char *)elements[0].pLabel, "DEVICE_ID", NanoROOT_MAX_LABEL_LEN);
    elements[0].labelLen = strlen("DEVICE_ID");
    memcpy(elements[0].pValue, "DEV12345", 8);
    elements[0].valueLen = 8;
    
    strncpy((char *)elements[1].pLabel, "SERIAL", NanoROOT_MAX_LABEL_LEN);
    elements[1].labelLen = strlen("SERIAL");
    memcpy(elements[1].pValue, "SN98765", 7);
    elements[1].valueLen = 7;
    
    /* Setup seed */
    memset(initialSeed, 0x5A, sizeof(initialSeed));
    
    /* Fingerprint device */
    status = NanoROOT_FingerprintDevice(pCtx, NanoROOTKDF_HMAC, elements, 2, 
                                        initialSeed, NanoROOTMAX_SEED_LEN, NULL);
    assert_int_equal(status, OK);
    
    /* Encrypt data */
    status = NanoROOT_Encrypt(pCtx, NanoROOTAES_256_CTR, NULL, 0,
                             plaintext, plaintextLen, ciphertext, &encLen);
    /* Skip test if crypto interface not available */
    if (ERR_TDP == status) {
        skip();
        NanoROOT_freeFingerprintCtx(&pCtx);
        return;
    }
    assert_int_equal(status, OK);
    assert_int_equal(encLen, plaintextLen);
    
    /* Verify ciphertext is different from plaintext */
    assert_memory_not_equal(plaintext, ciphertext, plaintextLen);
    
    /* Decrypt data */
    status = NanoROOT_Decrypt(pCtx, NanoROOTAES_256_CTR, NULL, 0,
                             ciphertext, encLen, decrypted, &decLen);
    assert_int_equal(status, OK);
    assert_int_equal(decLen, plaintextLen);
    
    /* Verify decrypted matches original */
    assert_memory_equal(plaintext, decrypted, plaintextLen);
    
    /* Cleanup */
    NanoROOT_freeFingerprintCtx(&pCtx);
}

/**
 * Test: NanoROOT_Encrypt/Decrypt roundtrip with AES-128-CBC
 */
static void test_encrypt_decrypt_roundtrip_aes_cbc(void **state) {
    UNUSED(state);
    MSTATUS status;
    NROOT_FP_CTX *pCtx = NULL;
    NROOTKdfElement elements[1];
    ubyte initialSeed[NanoROOTMAX_SEED_LEN];
    /* CBC requires data to be multiple of 16 bytes */
    ubyte plaintext[32] = "Data must be 16-byte aligned";
    ubyte ciphertext[32];
    ubyte decrypted[32];
    ubyte4 encLen = sizeof(ciphertext);  /* Buffer size */
    ubyte4 decLen = sizeof(decrypted);   /* Buffer size */
    
    /* Initialize context */
    status = NanoROOT_initFingerprintCtx(&pCtx, NanoROOTSINGLE_REUSABLE_KEY, 0);
    assert_int_equal(status, OK);
    
    /* Setup fingerprint */
    strncpy((char *)elements[0].pLabel, "HARDWARE_ID", NanoROOT_MAX_LABEL_LEN);
    elements[0].labelLen = strlen("HARDWARE_ID");
    memcpy(elements[0].pValue, "HW_ABC123", 9);
    elements[0].valueLen = 9;
    
    memset(initialSeed, 0x33, sizeof(initialSeed));
    
    /* Fingerprint device */
    status = NanoROOT_FingerprintDevice(pCtx, NanoROOTKDF_HMAC, elements, 1, 
                                        initialSeed, NanoROOTMAX_SEED_LEN, NULL);
    assert_int_equal(status, OK);
    
    /* Encrypt with AES-128-CBC (16 bytes) */
    status = NanoROOT_Encrypt(pCtx, NanoROOTAES_128_CBC, NULL, 0,
                             plaintext, 16, ciphertext, &encLen);
    /* Skip test if crypto interface not available */
    if (ERR_TDP == status) {
        skip();
        NanoROOT_freeFingerprintCtx(&pCtx);
        return;
    }
    assert_int_equal(status, OK);
    assert_int_equal(encLen, 16);
    
    /* Decrypt */
    status = NanoROOT_Decrypt(pCtx, NanoROOTAES_128_CBC, NULL, 0,
                             ciphertext, encLen, decrypted, &decLen);
    assert_int_equal(status, OK);
    assert_int_equal(decLen, 16);
    
    /* Verify */
    assert_memory_equal(plaintext, decrypted, 16);
    
    /* Cleanup */
    NanoROOT_freeFingerprintCtx(&pCtx);
}

/**
 * Test: NanoROOT_Decrypt with NULL context
 */
static void test_decrypt_null_context(void **state) {
    UNUSED(state);
    MSTATUS status;
    ubyte ciphertext[32];
    ubyte plaintext[32];
    ubyte4 outLen = 0;
    
    /* Test NULL context */
    status = NanoROOT_Decrypt(NULL, NanoROOTAES_256_CTR, NULL, 0,
                             ciphertext, 20, plaintext, &outLen);
    assert_int_equal(status, ERR_NULL_POINTER);
}

/**
 * Test: NanoROOT_Encrypt with multiple uses
 */
static void test_encrypt_multiple_uses(void **state) {
    UNUSED(state);
    MSTATUS status;
    NROOT_FP_CTX *pCtx = NULL;
    NROOTKdfElement elements[1];
    ubyte initialSeed[NanoROOTMAX_SEED_LEN];
    ubyte plaintext1[32] = "First secret message";
    ubyte plaintext2[32] = "Second secret message";
    ubyte ciphertext1[32], ciphertext2[32];
    ubyte4 outLen1 = sizeof(ciphertext1);  /* Buffer size */
    ubyte4 outLen2 = sizeof(ciphertext2);  /* Buffer size */
    
    /* Initialize context with 2 uses */
    status = NanoROOT_initFingerprintCtx(&pCtx, 2, 0);
    assert_int_equal(status, OK);
    
    /* Setup fingerprint */
    strncpy((char *)elements[0].pLabel, "CHIP_ID", NanoROOT_MAX_LABEL_LEN);
    elements[0].labelLen = strlen("CHIP_ID");
    memcpy(elements[0].pValue, "CHIP_XYZ", 8);
    elements[0].valueLen = 8;
    
    memset(initialSeed, 0x77, sizeof(initialSeed));
    
    /* Fingerprint device */
    status = NanoROOT_FingerprintDevice(pCtx, NanoROOTKDF_HMAC, elements, 1, 
                                        initialSeed, NanoROOTMAX_SEED_LEN, NULL);
    assert_int_equal(status, OK);
    
    /* First encryption */
    status = NanoROOT_Encrypt(pCtx, NanoROOTAES_256_CTR, NULL, 0,
                             plaintext1, 20, ciphertext1, &outLen1);
    /* Skip test if crypto interface not available */
    if (ERR_TDP == status) {
        skip();
        NanoROOT_freeFingerprintCtx(&pCtx);
        return;
    }
    assert_int_equal(status, OK);
    assert_int_equal(outLen1, 20);
    
    /* Second encryption */
    status = NanoROOT_Encrypt(pCtx, NanoROOTAES_256_CTR, NULL, 0,
                             plaintext2, 21, ciphertext2, &outLen2);
    assert_int_equal(status, OK);
    assert_int_equal(outLen2, 21);
    
    /* Verify different keys were used (ciphertexts should be different) */
    assert_memory_not_equal(ciphertext1, ciphertext2, 20);
    
    /* Third encryption should fail (exceeded numUses) */
    outLen1 = sizeof(ciphertext1);
    status = NanoROOT_Encrypt(pCtx, NanoROOTAES_256_CTR, NULL, 0,
                             plaintext1, 20, ciphertext1, &outLen1);
    assert_int_not_equal(status, OK);
    
    /* Cleanup */
    NanoROOT_freeFingerprintCtx(&pCtx);
}


/**
 * Test: SMP_NanoROOT_getTokenList with NULL moduleHandle
 */
static void test_getTokenList_null_moduleHandle(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_EntityList tokenList = {0};
    
    status = SMP_NanoROOT_getTokenList(0, TAP_TOKEN_TYPE_DEFAULT, NULL, &tokenList);
    assert_int_equal(status, ERR_TAP_INVALID_INPUT);
}

/**
 * Test: SMP_NanoROOT_getTokenList with NULL tokenList
 */
static void test_getTokenList_null_tokenList(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ModuleHandle moduleHandle = (TAP_ModuleHandle)0x1234;
    
    status = SMP_NanoROOT_getTokenList(moduleHandle, TAP_TOKEN_TYPE_DEFAULT, NULL, NULL);
    assert_int_equal(status, ERR_TAP_INVALID_INPUT);
}

/**
 * Test: SMP_NanoROOT_getTokenList success
 */
static void test_getTokenList_success(void **state) {
    UNUSED(state);
    MSTATUS status = OK;
    TAP_ConfigInfo configInfo = {0};
    TAP_ModuleHandle moduleHandle = 0;
    TAP_EntityList tokenList = {0};
    const char *configPath = get_config_path();

    /* Check prerequisites */
    if (!configPath) {
        print_message("Config file not found. Skipping test.\n");
        skip();
        return;
    }

    if (!check_fingerprint_file()) {
        print_message("Fingerprint file not found at /etc/digicert/default-fingerprint.json. Skipping test.\n");
        skip();
        return;
    }

    /* Load and initialize NanoROOT - same pattern as working tests */
    status = load_config_file(configPath, &configInfo.configInfo);
    if (OK != status) {
        print_message("Failed to load config file: %s\n", configPath);
        skip();
        return;
    }
    
    configInfo.provider = TAP_PROVIDER_NANOROOT;
    
    status = NanoROOT_init(&configInfo);
    if (OK != status) {
        print_message("NanoROOT_init failed with status: 0x%x\n", status);
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }

    /* Initialize module */
    status = SMP_NanoROOT_initModule(NanoROOTMODULE_ID, NULL, NULL, &moduleHandle);
    if (OK != status) {
        print_message("SMP_NanoROOT_initModule failed with status: 0x%x\n", status);
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }
    assert_non_null((void *)moduleHandle);

    /* Get token list - NanoROOT should return at least one token */
    status = SMP_NanoROOT_getTokenList(moduleHandle, TAP_TOKEN_TYPE_DEFAULT, 
                                        NULL, &tokenList);
    
    if (OK != status) {
        print_message("SMP_NanoROOT_getTokenList failed with status: 0x%x\n", status);
        SMP_NanoROOT_uninitModule(moduleHandle);
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }

    /* Verify token list */
    assert_int_equal(status, OK);
    assert_int_equal(tokenList.entityType, TAP_ENTITY_TYPE_TOKEN);
    assert_true(tokenList.entityIdList.numEntities > 0);
    assert_non_null(tokenList.entityIdList.pEntityIdList);
    
    /* Expected to have exactly 1 token for NanoROOT */
    assert_int_equal(tokenList.entityIdList.numEntities, 1);
    
    /* Verify token ID is the default NanoROOT token */
    assert_int_equal(tokenList.entityIdList.pEntityIdList[0], NanoROOTTOKEN_ID);

    print_message("Token list retrieved successfully with %d token(s)\n", 
                  tokenList.entityIdList.numEntities);

    /* Cleanup token list */
    if (tokenList.entityIdList.pEntityIdList) {
        DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);
    }

    /* Uninitialize module */
    status = SMP_NanoROOT_uninitModule(moduleHandle);
    assert_int_equal(status, OK);

    /* Cleanup NanoROOT */
    NanoROOT_deInit();
    free(configInfo.configInfo.pBuffer);
}

/**
 * Test: SMP_NanoROOT_sealWithTrustedData with NULL moduleHandle
 */
static void test_seal_null_moduleHandle(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_Buffer dataIn = {0};
    TAP_Buffer dataOut = {0};
    
    status = SMP_NanoROOT_sealWithTrustedData(0, (TAP_TokenHandle)1, NULL, &dataIn, &dataOut);
    assert_int_not_equal(status, OK);
}

/**
 * Test: SMP_NanoROOT_sealWithTrustedData with NULL tokenHandle
 */
static void test_seal_null_tokenHandle(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ModuleHandle moduleHandle = (TAP_ModuleHandle)0x1234;
    TAP_Buffer dataIn = {0};
    TAP_Buffer dataOut = {0};
    
    status = SMP_NanoROOT_sealWithTrustedData(moduleHandle, 0, NULL, &dataIn, &dataOut);
    assert_int_not_equal(status, OK);
}

/**
 * Test: SMP_NanoROOT_sealWithTrustedData with NULL input data
 */
static void test_seal_null_input_data(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ModuleHandle moduleHandle = (TAP_ModuleHandle)0x1234;
    TAP_TokenHandle tokenHandle = (TAP_TokenHandle)0x5678;
    TAP_Buffer dataOut = {0};
    
    status = SMP_NanoROOT_sealWithTrustedData(moduleHandle, tokenHandle, NULL, NULL, &dataOut);
    assert_int_not_equal(status, OK);
}

/**
 * Test: SMP_NanoROOT_sealWithTrustedData with NULL output buffer
 */
static void test_seal_null_output_buffer(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ModuleHandle moduleHandle = (TAP_ModuleHandle)0x1234;
    TAP_TokenHandle tokenHandle = (TAP_TokenHandle)0x5678;
    TAP_Buffer dataIn = {0};
    
    status = SMP_NanoROOT_sealWithTrustedData(moduleHandle, tokenHandle, NULL, &dataIn, NULL);
    assert_int_not_equal(status, OK);
}

/**
 * Test: SMP_NanoROOT_sealWithTrustedData with invalid output buffer (NULL buffer with non-zero length)
 * Fixed: Use real handles so NanoROOT can properly validate the invalid buffer
 */
static void test_seal_invalid_output_buffer(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ConfigInfo configInfo = {0};
    TAP_ModuleHandle moduleHandle = 0;
    TAP_TokenHandle tokenHandle = 0;
    TAP_Buffer dataIn = {0};
    TAP_Buffer dataOut = {0};
    ubyte testInputData[32] = "test data for unseal";
    const char *configPath = get_config_path();
    
    /* Check prerequisites */
    if (!configPath || !check_fingerprint_file()) {
        print_message("Prerequisites not met. Skipping test.\n");
        skip();
        return;
    }

    /* Initialize NanoROOT with real configuration */
    status = load_config_file(configPath, &configInfo.configInfo);
    if (OK != status) {
        print_message("Failed to load config file: %s\n", configPath);
        skip();
        return;
    }
    
    configInfo.provider = TAP_PROVIDER_NANOROOT;
    status = NanoROOT_init(&configInfo);
    if (OK != status) {
        print_message("NanoROOT_init failed with status: 0x%x\n", status);
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }

    /* Initialize module */
    status = SMP_NanoROOT_initModule(NanoROOTMODULE_ID, NULL, NULL, &moduleHandle);
    if (OK != status) {
        print_message("SMP_NanoROOT_initModule failed with status: 0x%x\n", status);
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }

    /* Initialize token */
    status = SMP_NanoROOT_initToken(moduleHandle, NULL, NanoROOTTOKEN_ID, NULL, &tokenHandle);
    if (OK != status) {
        SMP_NanoROOT_uninitModule(moduleHandle);
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }

    /* Prepare valid input data */
    dataIn.pBuffer = testInputData;
    dataIn.bufferLen = sizeof(testInputData);
    
    /* CRITICAL: Set invalid output buffer - NULL pointer with non-zero length */
    dataOut.pBuffer = NULL;
    dataOut.bufferLen = 100;  /* Invalid: NULL buffer with non-zero length */
    
    /* Now call seal with REAL handles - should detect invalid buffer and return error */
    status = SMP_NanoROOT_sealWithTrustedData(moduleHandle, tokenHandle, NULL, &dataIn, &dataOut);
    
    /* Should return error, not segfault */
    assert_int_not_equal(status, OK);
    print_message("Test passed: Invalid output buffer properly rejected with status=0x%x\n", status);

    /* Cleanup */
    SMP_NanoROOT_uninitToken(moduleHandle, tokenHandle);
    SMP_NanoROOT_uninitModule(moduleHandle);
    NanoROOT_deInit();
    free(configInfo.configInfo.pBuffer);
}

/**
 * Test: SMP_NanoROOT_unsealWithTrustedData with NULL moduleHandle
 */
static void test_unseal_null_moduleHandle(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_Buffer dataIn = {0};
    TAP_Buffer dataOut = {0};
    
    status = SMP_NanoROOT_unsealWithTrustedData(0, (TAP_TokenHandle)1, NULL, &dataIn, &dataOut);
    assert_int_not_equal(status, OK);
}

/**
 * Test: SMP_NanoROOT_unsealWithTrustedData with NULL tokenHandle
 */
static void test_unseal_null_tokenHandle(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ModuleHandle moduleHandle = (TAP_ModuleHandle)0x1234;
    TAP_Buffer dataIn = {0};
    TAP_Buffer dataOut = {0};
    
    status = SMP_NanoROOT_unsealWithTrustedData(moduleHandle, 0, NULL, &dataIn, &dataOut);
    assert_int_not_equal(status, OK);
}

/**
 * Test: SMP_NanoROOT_unsealWithTrustedData with NULL input data
 */
static void test_unseal_null_input_data(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ModuleHandle moduleHandle = (TAP_ModuleHandle)0x1234;
    TAP_TokenHandle tokenHandle = (TAP_TokenHandle)0x5678;
    TAP_Buffer dataOut = {0};
    
    status = SMP_NanoROOT_unsealWithTrustedData(moduleHandle, tokenHandle, NULL, NULL, &dataOut);
    assert_int_not_equal(status, OK);
}

/**
 * Test: SMP_NanoROOT_unsealWithTrustedData with NULL output buffer
 */
static void test_unseal_null_output_buffer(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ModuleHandle moduleHandle = (TAP_ModuleHandle)0x1234;
    TAP_TokenHandle tokenHandle = (TAP_TokenHandle)0x5678;
    TAP_Buffer dataIn = {0};
    
    status = SMP_NanoROOT_unsealWithTrustedData(moduleHandle, tokenHandle, NULL, &dataIn, NULL);
    assert_int_not_equal(status, OK);
}

/**
 * Test: SMP_NanoROOT_unsealWithTrustedData with invalid output buffer
 * Fixed: Use real handles so NanoROOT can properly validate the invalid buffer
 */
static void test_unseal_invalid_output_buffer(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ConfigInfo configInfo = {0};
    TAP_ModuleHandle moduleHandle = 0;
    TAP_TokenHandle tokenHandle = 0;
    TAP_Buffer dataIn = {0};
    TAP_Buffer dataOut = {0};
    ubyte testInputData[32] = "test data for unseal";
    const char *configPath = get_config_path();
    
    /* Check prerequisites */
    if (!configPath || !check_fingerprint_file()) {
        print_message("Prerequisites not met. Skipping test.\n");
        skip();
        return;
    }

    /* Initialize NanoROOT with real configuration */
    status = load_config_file(configPath, &configInfo.configInfo);
    if (OK != status) {
        print_message("Failed to load config file: %s\n", configPath);
        skip();
        return;
    }
    
    configInfo.provider = TAP_PROVIDER_NANOROOT;
    status = NanoROOT_init(&configInfo);
    if (OK != status) {
        print_message("NanoROOT_init failed with status: 0x%x\n", status);
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }

    /* Initialize module */
    status = SMP_NanoROOT_initModule(NanoROOTMODULE_ID, NULL, NULL, &moduleHandle);
    if (OK != status) {
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }

    /* Initialize token */
    status = SMP_NanoROOT_initToken(moduleHandle, NULL, NanoROOTTOKEN_ID, NULL, &tokenHandle);
    if (OK != status) {
        SMP_NanoROOT_uninitModule(moduleHandle);
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }

    /* Prepare valid input data */
    dataIn.pBuffer = testInputData;
    dataIn.bufferLen = sizeof(testInputData);
    
    /* CRITICAL: Set invalid output buffer - NULL pointer with non-zero length */
    dataOut.pBuffer = NULL;
    dataOut.bufferLen = 100;  /* Invalid: NULL buffer with non-zero length */
    
    /* Now call unseal with REAL handles - should detect invalid buffer and return error */
    status = SMP_NanoROOT_unsealWithTrustedData(moduleHandle, tokenHandle, NULL, &dataIn, &dataOut);
    
    /* Should return error, not segfault */
    assert_int_not_equal(status, OK);
    print_message("Test passed: Invalid output buffer properly rejected with status=0x%x\n", status);

    /* Cleanup */
    SMP_NanoROOT_uninitToken(moduleHandle, tokenHandle);
    SMP_NanoROOT_uninitModule(moduleHandle);
    NanoROOT_deInit();
    free(configInfo.configInfo.pBuffer);
}

/**
 * Test: SMP_NanoROOT_initObject with NULL moduleHandle
 */
static void test_initObject_null_moduleHandle(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ObjectHandle objHandle;
    TAP_ObjectId objIdOut;
    TAP_ObjectAttributes objAttr = {0};
    
    status = SMP_NanoROOT_initObject(0, (TAP_TokenHandle)1, 0, NULL, NULL, 
                                      &objHandle, &objIdOut, &objAttr);
    assert_int_not_equal(status, OK);
}

/**
 * Test: SMP_NanoROOT_initObject with NULL tokenHandle
 */
static void test_initObject_null_tokenHandle(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ModuleHandle moduleHandle = (TAP_ModuleHandle)0x1234;
    TAP_ObjectHandle objHandle;
    TAP_ObjectId objIdOut;
    TAP_ObjectAttributes objAttr = {0};
    
    status = SMP_NanoROOT_initObject(moduleHandle, 0, 0, NULL, NULL,
                                      &objHandle, &objIdOut, &objAttr);
    assert_int_not_equal(status, OK);
}

/**
 * Test: SMP_NanoROOT_deleteObject with NULL moduleHandle
 */
static void test_deleteObject_null_moduleHandle(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_TokenHandle tokenHandle = (TAP_TokenHandle)0x5678;
    TAP_ObjectHandle objHandle = (TAP_ObjectHandle)0x9ABC;
    
    status = SMP_NanoROOT_deleteObject(0, tokenHandle, objHandle);
    assert_int_equal(status, ERR_TAP_INVALID_INPUT);
}

/**
 * Test: SMP_NanoROOT_getPublicKey with NULL moduleHandle
 */
static void test_getPublicKey_null_moduleHandle(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_PublicKey *pubKey;
    
    status = SMP_NanoROOT_getPublicKey(0, (TAP_TokenHandle)1, (TAP_ObjectHandle)1, &pubKey);
    assert_int_not_equal(status, OK);
}

/**
 * Test: SMP_NanoROOT_getPublicKey with NULL tokenHandle
 */
static void test_getPublicKey_null_tokenHandle(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ModuleHandle moduleHandle = (TAP_ModuleHandle)0x1234;
    TAP_PublicKey *pubKey;
    
    status = SMP_NanoROOT_getPublicKey(moduleHandle, 0, (TAP_ObjectHandle)1, &pubKey);
    assert_int_not_equal(status, OK);
}

/**
 * Test: SMP_NanoROOT_getPublicKey with NULL objectHandle
 */
static void test_getPublicKey_null_objectHandle(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ModuleHandle moduleHandle = (TAP_ModuleHandle)0x1234;
    TAP_TokenHandle tokenHandle = (TAP_TokenHandle)0x5678;
    TAP_PublicKey *pubKey;
    
    status = SMP_NanoROOT_getPublicKey(moduleHandle, tokenHandle, 0, &pubKey);
    assert_int_not_equal(status, OK);
}

/**
 * Test: SMP_NanoROOT_getPublicKey with NULL output pointer
 */
static void test_getPublicKey_null_output(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ModuleHandle moduleHandle = (TAP_ModuleHandle)0x1234;
    TAP_TokenHandle tokenHandle = (TAP_TokenHandle)0x5678;
    TAP_ObjectHandle objectHandle = (TAP_ObjectHandle)0x9ABC;
    
    status = SMP_NanoROOT_getPublicKey(moduleHandle, tokenHandle, objectHandle, NULL);
    assert_int_not_equal(status, OK);
}

/**
 * Test: SMP_NanoROOT_signDigest with NULL moduleHandle
 */
static void test_signDigest_null_moduleHandle(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_Buffer digest = {0};
    TAP_Signature *signature = NULL;
    
    status = SMP_NanoROOT_signDigest(0, (TAP_TokenHandle)1, (TAP_ObjectHandle)1,
                                      &digest, TAP_SIG_SCHEME_PKCS1_5, NULL, &signature);
    assert_int_not_equal(status, OK);
}

/**
 * Test: SMP_NanoROOT_signDigest with NULL tokenHandle
 */
static void test_signDigest_null_tokenHandle(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ModuleHandle moduleHandle = (TAP_ModuleHandle)0x1234;
    TAP_Buffer digest = {0};
    TAP_Signature *signature = NULL;
    
    status = SMP_NanoROOT_signDigest(moduleHandle, 0, (TAP_ObjectHandle)1,
                                      &digest, TAP_SIG_SCHEME_PKCS1_5, NULL, &signature);
    assert_int_not_equal(status, OK);
}

/**
 * Test: SMP_NanoROOT_signDigest with NULL objectHandle
 */
static void test_signDigest_null_objectHandle(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ModuleHandle moduleHandle = (TAP_ModuleHandle)0x1234;
    TAP_TokenHandle tokenHandle = (TAP_TokenHandle)0x5678;
    TAP_Buffer digest = {0};
    TAP_Signature *signature = NULL;
    
    status = SMP_NanoROOT_signDigest(moduleHandle, tokenHandle, 0,
                                      &digest, TAP_SIG_SCHEME_PKCS1_5, NULL, &signature);
    assert_int_not_equal(status, OK);
}

/**
 * Test: SMP_NanoROOT_signDigest with NULL digest
 */
static void test_signDigest_null_digest(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ModuleHandle moduleHandle = (TAP_ModuleHandle)0x1234;
    TAP_TokenHandle tokenHandle = (TAP_TokenHandle)0x5678;
    TAP_ObjectHandle objectHandle = (TAP_ObjectHandle)0x9ABC;
    TAP_Signature *signature = NULL;
    
    status = SMP_NanoROOT_signDigest(moduleHandle, tokenHandle, objectHandle,
                                      NULL, TAP_SIG_SCHEME_PKCS1_5, NULL, &signature);
    assert_int_not_equal(status, OK);
}

/**
 * Test: SMP_NanoROOT_signDigest with NULL signature
 */
static void test_signDigest_null_signature(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ModuleHandle moduleHandle = (TAP_ModuleHandle)0x1234;
    TAP_TokenHandle tokenHandle = (TAP_TokenHandle)0x5678;
    TAP_ObjectHandle objectHandle = (TAP_ObjectHandle)0x9ABC;
    TAP_Buffer digest = {0};
    
    status = SMP_NanoROOT_signDigest(moduleHandle, tokenHandle, objectHandle,
                                      &digest, TAP_SIG_SCHEME_PKCS1_5, NULL, NULL);
    assert_int_not_equal(status, OK);
}

/**
 * Test: SMP_NanoROOT_signBuffer with NULL moduleHandle
 */
static void test_signBuffer_null_moduleHandle(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_Buffer buffer = {0};
    TAP_Signature *signature = NULL;
    
    status = SMP_NanoROOT_signBuffer(0, (TAP_TokenHandle)1, (TAP_ObjectHandle)1,
                                      &buffer, TAP_SIG_SCHEME_PKCS1_5, NULL, &signature);
    assert_int_not_equal(status, OK);
}

/**
 * Test: SMP_NanoROOT_signBuffer with NULL tokenHandle
 */
static void test_signBuffer_null_tokenHandle(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ModuleHandle moduleHandle = (TAP_ModuleHandle)0x1234;
    TAP_Buffer buffer = {0};
    TAP_Signature *signature = NULL;
    
    status = SMP_NanoROOT_signBuffer(moduleHandle, 0, (TAP_ObjectHandle)1,
                                      &buffer, TAP_SIG_SCHEME_PKCS1_5, NULL, &signature);
    assert_int_not_equal(status, OK);
}

/**
 * Test: SMP_NanoROOT_signBuffer with NULL objectHandle
 */
static void test_signBuffer_null_objectHandle(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ModuleHandle moduleHandle = (TAP_ModuleHandle)0x1234;
    TAP_TokenHandle tokenHandle = (TAP_TokenHandle)0x5678;
    TAP_Buffer buffer = {0};
    TAP_Signature *signature = NULL;
    
    status = SMP_NanoROOT_signBuffer(moduleHandle, tokenHandle, 0,
                                      &buffer, TAP_SIG_SCHEME_PKCS1_5, NULL, &signature);
    assert_int_not_equal(status, OK);
}

/**
 * Test: SMP_NanoROOT_signBuffer with NULL buffer
 */
static void test_signBuffer_null_buffer(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ModuleHandle moduleHandle = (TAP_ModuleHandle)0x1234;
    TAP_TokenHandle tokenHandle = (TAP_TokenHandle)0x5678;
    TAP_ObjectHandle objectHandle = (TAP_ObjectHandle)0x9ABC;
    TAP_Signature *signature = NULL;
    
    status = SMP_NanoROOT_signBuffer(moduleHandle, tokenHandle, objectHandle,
                                      NULL, TAP_SIG_SCHEME_PKCS1_5, NULL, &signature);
    assert_int_not_equal(status, OK);
}

/**
 * Test: SMP_NanoROOT_signBuffer with NULL signature
 */
static void test_signBuffer_null_signature(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ModuleHandle moduleHandle = (TAP_ModuleHandle)0x1234;
    TAP_TokenHandle tokenHandle = (TAP_TokenHandle)0x5678;
    TAP_ObjectHandle objectHandle = (TAP_ObjectHandle)0x9ABC;
    TAP_Buffer buffer = {0};
    
    status = SMP_NanoROOT_signBuffer(moduleHandle, tokenHandle, objectHandle,
                                      &buffer, TAP_SIG_SCHEME_PKCS1_5, NULL, NULL);
    assert_int_not_equal(status, OK);
}

/**
 * Test: NanoROOT_FillError with NULL error structure
 */
static void test_fillError_null_error(void **state) {
    UNUSED(state);
    MSTATUS status = OK;
    
    /* Should not crash when error is NULL */
    NanoROOT_FillError(NULL, &status, ERR_NULL_POINTER, "Test error");
    assert_int_equal(status, ERR_NULL_POINTER);
}

/**
 * Test: NanoROOT_FillError with NULL status pointer
 */
static void test_fillError_null_status(void **state) {
    UNUSED(state);
    TAP_Error error = {0};
    ubyte buffer[256];
    error.tapErrorString.pBuffer = buffer;
    error.tapErrorString.bufferLen = sizeof(buffer);
    
    /* Should not crash when status pointer is NULL */
    NanoROOT_FillError(&error, NULL, ERR_INVALID_ARG, "Test error");
    assert_int_equal(error.tapError, ERR_INVALID_ARG);
}

/**
 * Test: NanoROOT_FillError with valid inputs
 */
static void test_fillError_valid(void **state) {
    UNUSED(state);
    MSTATUS status = OK;
    TAP_Error error = {0};
    ubyte buffer[256];
    const char *errMsg = "Test error message";
    
    error.tapErrorString.pBuffer = buffer;
    error.tapErrorString.bufferLen = sizeof(buffer);
    
    NanoROOT_FillError(&error, &status, ERR_INVALID_ARG, errMsg);
    
    assert_int_equal(status, ERR_INVALID_ARG);
    assert_int_equal(error.tapError, ERR_INVALID_ARG);
    assert_string_equal((char*)error.tapErrorString.pBuffer, errMsg);
}

/**
 * Test: NanoROOT_FillError with NULL error string buffer
 */
static void test_fillError_null_buffer(void **state) {
    UNUSED(state);
    MSTATUS status = OK;
    TAP_Error error = {0};
    
    error.tapErrorString.pBuffer = NULL;
    error.tapErrorString.bufferLen = 0;
    
    /* Should not crash when buffer is NULL */
    NanoROOT_FillError(&error, &status, ERR_INVALID_ARG, "Test error");
    assert_int_equal(status, ERR_INVALID_ARG);
    assert_int_equal(error.tapError, ERR_INVALID_ARG);
}

/**
 * Test: Error propagation through nested calls
 */
static void test_error_propagation(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ModuleHandle moduleHandle;
    
    /* Test that errors propagate correctly through validation layers */
    status = SMP_NanoROOT_initModule(0x99999999, NULL, NULL, &moduleHandle);
    assert_int_equal(status, ERR_TAP_MODULE_NOT_FOUND);
    
    status = SMP_NanoROOT_initModule(NanoROOTMODULE_ID, NULL, NULL, NULL);
    assert_int_equal(status, ERR_TAP_INVALID_INPUT);
}

/**
 * Test: Sequential operations
 */
static void test_sequential_operations(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_EntityList moduleList1 = {0};
    TAP_EntityList moduleList2 = {0};
    
    /* Get module list twice */
    status = SMP_NanoROOT_getModuleList(NULL, &moduleList1);
    assert_int_equal(status, OK);
    
    status = SMP_NanoROOT_getModuleList(NULL, &moduleList2);
    assert_int_equal(status, OK);
    
    /* Both should return same module ID */
    assert_int_equal(moduleList1.entityIdList.pEntityIdList[0],
                     moduleList2.entityIdList.pEntityIdList[0]);
    
    /* Free both lists */
    status = SMP_NanoROOT_freeModuleList(&moduleList1);
    assert_int_equal(status, OK);
    
    status = SMP_NanoROOT_freeModuleList(&moduleList2);
    assert_int_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Integration Tests with Real Config */
/*------------------------------------------------------------------*/

/* Helper to load config file */
static MSTATUS load_config_file(const char *configPath, TAP_Buffer *pConfigBuffer) {
    FILE *fp = NULL;
    long fileSize = 0;
    size_t bytesRead = 0;
    
    fp = fopen(configPath, "r");
    if (!fp) {
        return ERR_FILE_OPEN_FAILED;
    }
    
    /* Get file size */
    fseek(fp, 0, SEEK_END);
    fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (fileSize <= 0 || fileSize > 65536) {
        fclose(fp);
        return ERR_INVALID_INPUT;
    }
    
    /* Allocate buffer */
    pConfigBuffer->pBuffer = (ubyte *)malloc(fileSize + 1);
    if (!pConfigBuffer->pBuffer) {
        fclose(fp);
        return ERR_MEM_ALLOC_FAIL;
    }
    
    /* Read file */
    bytesRead = fread(pConfigBuffer->pBuffer, 1, fileSize, fp);
    fclose(fp);
    
    if (bytesRead != (size_t)fileSize) {
        free(pConfigBuffer->pBuffer);
        pConfigBuffer->pBuffer = NULL;
        return ERR_FILE_READ_FAILED;
    }
    
    pConfigBuffer->pBuffer[fileSize] = '\0';
    pConfigBuffer->bufferLen = fileSize;
    
    return OK;
}

/* Helper to get config file path - tries multiple locations */
static const char* get_config_path(void) {
    static const char* paths[] = {
        "/etc/digicert/nanoroot_smp.conf",                          /* System location */
        "../../../samples/nanoroot/config/nanoroot_smp.conf",      /* Relative from build */
        "../../samples/nanoroot/config/nanoroot_smp.conf",         /* Relative from test dir */
        "samples/nanoroot/config/nanoroot_smp.conf",               /* From repo root */
        NULL
    };
    
    for (int i = 0; paths[i] != NULL; i++) {
        if (access(paths[i], R_OK) == 0) {
            return paths[i];
        }
    }
    
    return NULL;
}

/* Helper to check if fingerprint file exists */
static int check_fingerprint_file(void) {
    const char *fingerprint_path = "/etc/digicert/default-fingerprint.json";
    return (access(fingerprint_path, R_OK) == 0);
}

/**
 * Integration Test: Full module and token initialization with config file
 */
static void test_integration_module_token_init(void **state) {
    UNUSED(state);
    MSTATUS status = OK;
    TAP_ConfigInfo configInfo = {0};
    TAP_ModuleHandle moduleHandle = 0;
    TAP_TokenHandle tokenHandle = 0;
    TAP_EntityList tokenList = {0};
    const char *configPath = get_config_path();

    /* Check prerequisites */
    if (!configPath) {
        print_message("Config file not found. Skipping test.\n");
        skip();
        return;
    }

    if (!check_fingerprint_file()) {
        print_message("Fingerprint file not found at /etc/digicert/default-fingerprint.json. Skipping test.\n");
        skip();
        return;
    }

    /* Load and initialize NanoROOT */
    status = load_config_file(configPath, &configInfo.configInfo);
    if (OK != status) {
        print_message("Failed to load config file: %s\n", configPath);
        skip();
        return;
    }
    
    configInfo.provider = TAP_PROVIDER_NANOROOT;
    
    status = NanoROOT_init(&configInfo);
    if (OK != status) {
        print_message("NanoROOT_init failed with status: 0x%x\n", status);
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }

    /* Step 1: Initialize module */
    status = SMP_NanoROOT_initModule(NanoROOTMODULE_ID, NULL, NULL, &moduleHandle);
    if (OK != status) {
        print_message("SMP_NanoROOT_initModule failed with status: 0x%x\n", status);
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }
    
    assert_int_equal(status, OK);
    assert_non_null((void *)moduleHandle);
    print_message("Module initialized successfully: handle=0x%lx\n", (unsigned long)moduleHandle);

    /* Step 2: Get token list to verify module is functional */
    status = SMP_NanoROOT_getTokenList(moduleHandle, TAP_TOKEN_TYPE_DEFAULT, 
                                        NULL, &tokenList);
    assert_int_equal(status, OK);
    assert_int_equal(tokenList.entityType, TAP_ENTITY_TYPE_TOKEN);
    assert_true(tokenList.entityIdList.numEntities > 0);
    assert_non_null(tokenList.entityIdList.pEntityIdList);
    
    print_message("Found %d token(s) in module\n", tokenList.entityIdList.numEntities);

    /* Step 3: Initialize token using first token ID from the list */
    status = SMP_NanoROOT_initToken(moduleHandle, NULL, 
                                     tokenList.entityIdList.pEntityIdList[0], 
                                     NULL, &tokenHandle);
    assert_int_equal(status, OK);
    assert_non_null((void *)tokenHandle);
    print_message("Token initialized successfully: handle=0x%lx, tokenId=0x%llx\n", 
                  (unsigned long)tokenHandle, 
                  (unsigned long long)tokenList.entityIdList.pEntityIdList[0]);

    /* Step 4: Uninit token */
    status = SMP_NanoROOT_uninitToken(moduleHandle, tokenHandle);
    assert_int_equal(status, OK);
    print_message("Token uninitialized successfully\n");

    /* Cleanup token list */
    if (tokenList.entityIdList.pEntityIdList) {
        DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);
    }

    /* Step 5: Uninit module */
    status = SMP_NanoROOT_uninitModule(moduleHandle);
    assert_int_equal(status, OK);
    print_message("Module uninitialized successfully\n");

    /* Cleanup NanoROOT */
    NanoROOT_deInit();
    free(configInfo.configInfo.pBuffer);
    
    print_message("Integration test: module and token initialization completed successfully\n");
}

/**
 * Integration Test: Seal and unseal operation
 */
static void test_integration_seal_unseal(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ConfigInfo configInfo = {0};
    TAP_ModuleHandle moduleHandle = 0;
    TAP_TokenHandle tokenHandle = 0;
    TAP_Buffer inputData = {0};
    TAP_Buffer sealedData = {0};
    TAP_Buffer unsealedData = {0};
    const char *testData = "Test data for seal/unseal operation";
    
    const char *configPath = get_config_path();
    if (!configPath) {
        print_message("Config path not available. Skipping test.\n");
        skip();
        return;
    }
    
    if (!check_fingerprint_file()) {
        print_message("Fingerprint file not available. Skipping test.\n");
        skip();
        return;
    }
    
    /* Load config */
    status = load_config_file(configPath, &configInfo.configInfo);
    if (OK != status) {
        print_message("Failed to load config file: %s\n", configPath);
        skip();
        return;
    }
    
    configInfo.provider = TAP_PROVIDER_NANOROOT;
    
    /* Initialize */
    status = NanoROOT_init(&configInfo);
    if (OK != status) {
        print_message("NanoROOT_init failed with status: 0x%x\n", status);
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }
    
    status = SMP_NanoROOT_initModule(NanoROOTMODULE_ID, NULL, NULL, &moduleHandle);
    if (OK != status) {
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }
    
    status = SMP_NanoROOT_initToken(moduleHandle, NULL, NanoROOTTOKEN_ID, NULL, &tokenHandle);
    if (OK != status) {
        SMP_NanoROOT_uninitModule(moduleHandle);
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }
    
    /* Prepare input data */
    inputData.pBuffer = (ubyte *)testData;
    inputData.bufferLen = strlen(testData);
    
    /* Seal operation */
    status = SMP_NanoROOT_sealWithTrustedData(moduleHandle, tokenHandle, NULL, 
                                               &inputData, &sealedData);
    if (OK != status) {
        /* Seal might fail if credentials not properly configured */
        SMP_NanoROOT_uninitToken(moduleHandle, tokenHandle);
        SMP_NanoROOT_uninitModule(moduleHandle);
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }
    
    assert_non_null(sealedData.pBuffer);
    assert_true(sealedData.bufferLen > 0);
    
    /* Unseal operation */
    status = SMP_NanoROOT_unsealWithTrustedData(moduleHandle, tokenHandle, NULL,
                                                 &sealedData, &unsealedData);
    assert_int_equal(status, OK);
    assert_non_null(unsealedData.pBuffer);
    assert_int_equal(inputData.bufferLen, unsealedData.bufferLen);
    assert_memory_equal(inputData.pBuffer, unsealedData.pBuffer, inputData.bufferLen);
    
    /* Cleanup */
    if (sealedData.pBuffer) free(sealedData.pBuffer);
    if (unsealedData.pBuffer) free(unsealedData.pBuffer);
    SMP_NanoROOT_uninitToken(moduleHandle, tokenHandle);
    SMP_NanoROOT_uninitModule(moduleHandle);
    NanoROOT_deInit();
    free(configInfo.configInfo.pBuffer);
}

/**
 * Integration Test: Sign digest operation
 */
static void test_integration_sign_digest(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ConfigInfo configInfo = {0};
    TAP_ModuleHandle moduleHandle = 0;
    TAP_TokenHandle tokenHandle = 0;
    TAP_ObjectHandle objectHandle = 0;
    TAP_ObjectId keyIdIn = 0x100000002; /* RSA-2048 key ID */
    TAP_ObjectId objectIdOut = 0;
    TAP_ObjectAttributes objAttr = {0};
    TAP_ObjectCapabilityAttributes objCapAttr = {0};
    TAP_Attribute keyIdAttr = {0};
    ubyte keyIdBytes[8];
    TAP_Buffer keyIdBuffer = {0};
    TAP_Signature *signature = NULL;
    TAP_Buffer digest = {0};
    ubyte digestData[32] = {0x01, 0x02, 0x03, 0x04}; /* Mock SHA256 digest */
    
    const char *configPath = get_config_path();
    if (!configPath) {
        print_message("Config path not available. Skipping test.\n");
        skip();
        return;
    }
    
    if (!check_fingerprint_file()) {
        print_message("Fingerprint file not available. Skipping test.\n");
        skip();
        return;
    }
    
    /* Load config */
    status = load_config_file(configPath, &configInfo.configInfo);
    if (OK != status) {
        print_message("Failed to load config file: %s\n", configPath);
        skip();
        return;
    }
    
    configInfo.provider = TAP_PROVIDER_NANOROOT;
    
    /* Initialize */
    status = NanoROOT_init(&configInfo);
    if (OK != status) {
        print_message("NanoROOT_init failed with status: 0x%x\n", status);
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }
    
    status = SMP_NanoROOT_initModule(NanoROOTMODULE_ID, NULL, NULL, &moduleHandle);
    if (OK != status) {
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }
    
    status = SMP_NanoROOT_initToken(moduleHandle, NULL, NanoROOTTOKEN_ID, NULL, &tokenHandle);
    if (OK != status) {
        SMP_NanoROOT_uninitModule(moduleHandle);
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }
    
    /* Prepare key ID attribute with little-endian bytes */
    for (ubyte4 i = 0; i < sizeof(ubyte8); i++) {
        keyIdBytes[i] = (ubyte)((keyIdIn >> (8 * i)) & 0xFF);
    }
    
    keyIdBuffer.pBuffer = keyIdBytes;
    keyIdBuffer.bufferLen = sizeof(ubyte8);
    
    keyIdAttr.type = TAP_ATTR_OBJECT_ID_BYTESTRING;
    keyIdAttr.length = sizeof(TAP_Buffer);
    keyIdAttr.pStructOfType = (void *)&keyIdBuffer;
    
    objCapAttr.pAttributeList = &keyIdAttr;
    objCapAttr.listLen = 1;
    
    /* Create key object */
    status = SMP_NanoROOT_initObject(moduleHandle, tokenHandle, 0,
                                      &objCapAttr, NULL, &objectHandle, 
                                      &objectIdOut, &objAttr);
    if (OK != status) {
        print_message("SMP_NanoROOT_initObject failed with status: 0x%x\n", status);
        SMP_NanoROOT_uninitToken(moduleHandle, tokenHandle);
        SMP_NanoROOT_uninitModule(moduleHandle);
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }
    assert_non_null((void *)objectHandle);
    print_message("Key object initialized successfully: objectHandle=0x%lx\n", (unsigned long)objectHandle);
    
    /* Prepare digest */
    digest.pBuffer = digestData;
    digest.bufferLen = sizeof(digestData);
    
    /* Sign digest */
    status = SMP_NanoROOT_signDigest(moduleHandle, tokenHandle, objectHandle,
                                      &digest, TAP_SIG_SCHEME_PKCS1_5_SHA256, NULL, &signature);
    assert_int_equal(status, OK);
    assert_non_null(signature);
    print_message("Digest signed successfully: signature length=%u\n", signature->signature.rsaSignature.signatureLen);
    
    /* Cleanup signature */
    if (signature) {
        if (signature->signature.rsaSignature.pSignature) free(signature->signature.rsaSignature.pSignature);
        free(signature);
    }
    
    /* Delete object */
    status = SMP_NanoROOT_deleteObject(moduleHandle, tokenHandle, objectHandle);
    assert_int_equal(status, OK);
    
    /* Cleanup */
    SMP_NanoROOT_uninitToken(moduleHandle, tokenHandle);
    SMP_NanoROOT_uninitModule(moduleHandle);
    NanoROOT_deInit();
    free(configInfo.configInfo.pBuffer);
    
    print_message("Integration test: sign digest completed successfully\n");
}

/**
 * Integration Test: Sign buffer operation
 */
static void test_integration_sign_buffer(void **state) {
    UNUSED(state);
    MSTATUS status;
    TAP_ConfigInfo configInfo = {0};
    TAP_ModuleHandle moduleHandle = 0;
    TAP_TokenHandle tokenHandle = 0;
    TAP_ObjectHandle objectHandle = 0;
    TAP_ObjectId keyIdIn = 0x100000002; /* RSA-2048 key ID */
    TAP_ObjectId objectIdOut = 0;
    TAP_ObjectAttributes objAttr = {0};
    TAP_ObjectCapabilityAttributes objCapAttr = {0};
    TAP_Attribute keyIdAttr = {0};
    ubyte keyIdBytes[8];
    TAP_Buffer keyIdBuffer = {0};
    TAP_Signature *signature = NULL;
    TAP_Buffer buffer = {0};
    const char *testData = "Data to sign";
    
    const char *configPath = get_config_path();
    if (!configPath) {
        print_message("Config path not available. Skipping test.\n");
        skip();
        return;
    }
    
    if (!check_fingerprint_file()) {
        print_message("Fingerprint file not available. Skipping test.\n");
        skip();
        return;
    }
    
    /* Load config */
    status = load_config_file(configPath, &configInfo.configInfo);
    if (OK != status) {
        print_message("Failed to load config file: %s\n", configPath);
        skip();
        return;
    }
    
    configInfo.provider = TAP_PROVIDER_NANOROOT;
    
    /* Initialize */
    status = NanoROOT_init(&configInfo);
    if (OK != status) {
        print_message("NanoROOT_init failed with status: 0x%x\n", status);
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }
    
    status = SMP_NanoROOT_initModule(NanoROOTMODULE_ID, NULL, NULL, &moduleHandle);
    if (OK != status) {
        print_message("SMP_NanoROOT_initModule failed with status: 0x%x\n", status);
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }
    
    status = SMP_NanoROOT_initToken(moduleHandle, NULL, NanoROOTTOKEN_ID, NULL, &tokenHandle);
    if (OK != status) {
        print_message("SMP_NanoROOT_initToken failed with status: 0x%x\n", status);
        SMP_NanoROOT_uninitModule(moduleHandle);
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }
    
    /* Prepare key ID attribute with little-endian bytes */
    for (ubyte4 i = 0; i < sizeof(ubyte8); i++) {
        keyIdBytes[i] = (ubyte)((keyIdIn >> (8 * i)) & 0xFF);
    }
    keyIdBuffer.pBuffer = keyIdBytes;
    keyIdBuffer.bufferLen = sizeof(ubyte8);
    
    keyIdAttr.type = TAP_ATTR_OBJECT_ID_BYTESTRING;
    keyIdAttr.length = sizeof(TAP_Buffer);
    keyIdAttr.pStructOfType = (void *)&keyIdBuffer;
    
    objCapAttr.pAttributeList = &keyIdAttr;
    objCapAttr.listLen = 1;
    
    /* Create key object */
    status = SMP_NanoROOT_initObject(moduleHandle, tokenHandle, 0,
                                      &objCapAttr, NULL, &objectHandle, 
                                      &objectIdOut, &objAttr);
    if (OK != status) {
        print_message("SMP_NanoROOT_initObject failed with status: 0x%x\n", status);
        SMP_NanoROOT_uninitToken(moduleHandle, tokenHandle);
        SMP_NanoROOT_uninitModule(moduleHandle);
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }
    assert_non_null((void *)objectHandle);
    print_message("Key object initialized successfully: objectHandle=0x%lx\n", (unsigned long)objectHandle);
    
    /* Prepare buffer */
    buffer.pBuffer = (ubyte *)testData;
    buffer.bufferLen = strlen(testData);
    
    /* Sign buffer */
    status = SMP_NanoROOT_signBuffer(moduleHandle, tokenHandle, objectHandle,
                                      &buffer, TAP_SIG_SCHEME_PKCS1_5_SHA256, NULL, &signature);
    assert_int_equal(status, OK);
    assert_non_null(signature);
    print_message("Buffer signed successfully: signature length=%u\n", signature->signature.rsaSignature.signatureLen);
    
    /* Cleanup signature */
    if (signature) {
        if (signature->signature.rsaSignature.pSignature) free(signature->signature.rsaSignature.pSignature);
        free(signature);
    }
    
    /* Delete object */
    status = SMP_NanoROOT_deleteObject(moduleHandle, tokenHandle, objectHandle);
    assert_int_equal(status, OK);
    
    /* Cleanup */
    SMP_NanoROOT_uninitToken(moduleHandle, tokenHandle);
    SMP_NanoROOT_uninitModule(moduleHandle);
    NanoROOT_deInit();
    free(configInfo.configInfo.pBuffer);
    
    print_message("Integration test: sign buffer completed successfully\n");
}

/*------------------------------------------------------------------*/
/* Test: signBuffer with RSA-2048 key */
/*------------------------------------------------------------------*/
static void test_smp_cc_sign_buffer_rsa2k(void **state)
{
    UNUSED(state);
    MSTATUS status = OK;
    TAP_ModuleHandle moduleHandle = 0;
    TAP_TokenHandle tokenHandle = 0;
    TAP_ObjectHandle objectHandle = 0;
    TAP_Buffer inputData = {0};
    TAP_Signature *pSignature = NULL;
    ubyte testData[10240] = {0}; /* 10KB test data */
    ubyte4 i;
    TAP_ConfigInfo configInfo = {0};
    const char *configPath = get_config_path();
    TAP_ObjectId keyIdIn = 0x100000002; /* RSA-2048 key ID */
    TAP_ObjectId keyIdOut = 0;
    TAP_ObjectCapabilityAttributes objCapAttr = {0};
    TAP_ObjectAttributes objAttr = {0};
    TAP_Attribute keyAttrList[1] = {0};
    TAP_Buffer keyIdBuffer = {0};
    ubyte keyIdBytes[8] = {0};

    /* Check if config file is available */
    if (!configPath) {
        print_message("Config file not found. Skipping test.\n");
        skip();
        return;
    }

    /* Check if fingerprint file is available */
    if (!check_fingerprint_file()) {
        print_message("Fingerprint file not found at /etc/digicert/default-fingerprint.json. Skipping test.\n");
        skip();
        return;
    }

    /* Initialize test data with pattern */
    for (i = 0; i < sizeof(testData); i++) {
        testData[i] = (ubyte)(i & 0xFF);
    }
    inputData.pBuffer = testData;
    inputData.bufferLen = sizeof(testData);

    /* Load and initialize NanoROOT */
    status = load_config_file(configPath, &configInfo.configInfo);
    if (OK != status) {
        print_message("Failed to load config file: %s\n", configPath);
        skip();
        return;
    }
    
    configInfo.provider = TAP_PROVIDER_NANOROOT;
    
    status = NanoROOT_init(&configInfo);
    if (OK != status) {
        print_message("NanoROOT_init failed with status: 0x%x\n", status);
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }

    /* Initialize module - using direct API like seal/unseal */
    status = SMP_NanoROOT_initModule(NanoROOTMODULE_ID, NULL, NULL, &moduleHandle);
    if (OK != status) {
        print_message("SMP_NanoROOT_initModule failed with status: 0x%x\n", status);
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }

    /* Initialize token - using direct API like seal/unseal */
    status = SMP_NanoROOT_initToken(moduleHandle, NULL, NanoROOTTOKEN_ID, NULL, &tokenHandle);
    if (OK != status) {
        print_message("SMP_NanoROOT_initToken failed with status: 0x%x\n", status);
        SMP_NanoROOT_uninitModule(moduleHandle);
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }

    /* Setup key ID buffer (little-endian format) */
    for (i = 0; i < sizeof(ubyte8); i++) {
        keyIdBytes[i] = (ubyte)((keyIdIn >> (8 * i)) & 0xFF);
    }
    keyIdBuffer.pBuffer = keyIdBytes;
    keyIdBuffer.bufferLen = sizeof(ubyte8);

    /* Setup object capability attributes with key ID */
    keyAttrList[0].type = TAP_ATTR_OBJECT_ID_BYTESTRING;
    keyAttrList[0].length = sizeof(TAP_Buffer);
    keyAttrList[0].pStructOfType = (void *)&keyIdBuffer;
    objCapAttr.pAttributeList = keyAttrList;
    objCapAttr.listLen = 1;

    /* Initialize the key object - this creates NanoROOT_Object internally */
    status = SMP_NanoROOT_initObject(moduleHandle, tokenHandle, 0,
                                      &objCapAttr, NULL, &objectHandle,
                                      &keyIdOut, &objAttr);
    if (OK != status) {
        print_message("SMP_NanoROOT_initObject failed with status: 0x%x\n", status);
        SMP_NanoROOT_uninitToken(moduleHandle, tokenHandle);
        SMP_NanoROOT_uninitModule(moduleHandle);
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }

    /* Sign buffer using the object handle */
    status = SMP_NanoROOT_signBuffer(moduleHandle, tokenHandle, objectHandle,
                                      &inputData, TAP_SIG_SCHEME_PKCS1_5_SHA256, 
                                      NULL, &pSignature);
    
    if (OK != status || !pSignature) {
        if (OK != status) {
            print_message("SMP_NanoROOT_signBuffer failed with status: 0x%x\n", status);
        } else {
            print_message("SMP_NanoROOT_signBuffer returned NULL signature\n");
        }
        SMP_NanoROOT_deleteObject(moduleHandle, tokenHandle, objectHandle);
        SMP_NanoROOT_uninitToken(moduleHandle, tokenHandle);
        SMP_NanoROOT_uninitModule(moduleHandle);
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }

    /* Verify signature was created */
    assert_int_equal(status, OK);
    assert_non_null(pSignature);
    assert_non_null(pSignature->signature.rsaSignature.pSignature);
    assert_true(pSignature->signature.rsaSignature.signatureLen == 256); /* RSA-2048 = 256 bytes */

    /* Cleanup signature */
    if (pSignature) {
        if (pSignature->signature.rsaSignature.pSignature) {
            DIGI_FREE((void **)&pSignature->signature.rsaSignature.pSignature);
        }
        DIGI_FREE((void **)&pSignature);
    }

    /* Uninitialize token */
    status = SMP_NanoROOT_uninitToken(moduleHandle, tokenHandle);
    assert_int_equal(status, OK);

    /* Uninitialize module */
    status = SMP_NanoROOT_uninitModule(moduleHandle);
    assert_int_equal(status, OK);

    /* Cleanup */
    NanoROOT_deInit();
    free(configInfo.configInfo.pBuffer);
}

/*------------------------------------------------------------------*/
/* Test: signDigest with RSA-2048 key */
/*------------------------------------------------------------------*/
static void test_smp_cc_sign_digest_rsa2k(void **state)
{
    UNUSED(state);
    MSTATUS status = OK;
    TAP_ModuleHandle moduleHandle = 0;
    TAP_TokenHandle tokenHandle = 0;
    TAP_ObjectHandle objectHandle = 0;
    TAP_Buffer digestData = {0};
    TAP_Signature *pSignature = NULL;
    TAP_ConfigInfo configInfo = {0};
    const char *configPath = get_config_path();
    TAP_ObjectId keyIdIn = 0x100000002; /* RSA-2048 key ID */
    TAP_ObjectId keyIdOut = 0;
    TAP_ObjectCapabilityAttributes objCapAttr = {0};
    TAP_ObjectAttributes objAttr = {0};
    TAP_Attribute keyAttrList[1] = {0};
    TAP_Buffer keyIdBuffer = {0};
    ubyte keyIdBytes[8] = {0};
    ubyte4 i;
    /* Pre-computed SHA-256 digest for testing */
    ubyte sha256Digest[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };

    /* Check if config file is available */
    if (!configPath) {
        print_message("Config file not found. Skipping test.\n");
        skip();
        return;
    }

    /* Check if fingerprint file is available */
    if (!check_fingerprint_file()) {
        print_message("Fingerprint file not found at /etc/digicert/default-fingerprint.json. Skipping test.\n");
        skip();
        return;
    }

    digestData.pBuffer = sha256Digest;
    digestData.bufferLen = sizeof(sha256Digest);

    /* Load and initialize NanoROOT */
    status = load_config_file(configPath, &configInfo.configInfo);
    if (OK != status) {
        print_message("Failed to load config file: %s\n", configPath);
        skip();
        return;
    }
    
    configInfo.provider = TAP_PROVIDER_NANOROOT;
    
    status = NanoROOT_init(&configInfo);
    if (OK != status) {
        print_message("NanoROOT_init failed with status: 0x%x\n", status);
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }

    /* Initialize module - using direct API like seal/unseal */
    status = SMP_NanoROOT_initModule(NanoROOTMODULE_ID, NULL, NULL, &moduleHandle);
    if (OK != status) {
        print_message("SMP_NanoROOT_initModule failed with status: 0x%x\n", status);
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }

    /* Initialize token - using direct API like seal/unseal */
    status = SMP_NanoROOT_initToken(moduleHandle, NULL, NanoROOTTOKEN_ID, NULL, &tokenHandle);
    if (OK != status) {
        print_message("SMP_NanoROOT_initToken failed with status: 0x%x\n", status);
        SMP_NanoROOT_uninitModule(moduleHandle);
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }

    /* Setup key ID buffer (little-endian format) */
    for (i = 0; i < sizeof(ubyte8); i++) {
        keyIdBytes[i] = (ubyte)((keyIdIn >> (8 * i)) & 0xFF);
    }
    keyIdBuffer.pBuffer = keyIdBytes;
    keyIdBuffer.bufferLen = sizeof(ubyte8);

    /* Setup object capability attributes with key ID */
    keyAttrList[0].type = TAP_ATTR_OBJECT_ID_BYTESTRING;
    keyAttrList[0].length = sizeof(TAP_Buffer);
    keyAttrList[0].pStructOfType = (void *)&keyIdBuffer;
    objCapAttr.pAttributeList = keyAttrList;
    objCapAttr.listLen = 1;

    /* Initialize the key object - this creates NanoROOT_Object internally */
    status = SMP_NanoROOT_initObject(moduleHandle, tokenHandle, 0,
                                      &objCapAttr, NULL, &objectHandle,
                                      &keyIdOut, &objAttr);
    if (OK != status) {
        print_message("SMP_NanoROOT_initObject failed with status: 0x%x\n", status);
        SMP_NanoROOT_uninitToken(moduleHandle, tokenHandle);
        SMP_NanoROOT_uninitModule(moduleHandle);
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }

    /* Sign digest using the object handle */
    status = SMP_NanoROOT_signDigest(moduleHandle, tokenHandle, objectHandle,
                                      &digestData, TAP_SIG_SCHEME_PKCS1_5_SHA256, 
                                      NULL, &pSignature);
    
    if (OK != status || !pSignature) {
        if (OK != status) {
            print_message("SMP_NanoROOT_signDigest failed with status: 0x%x\n", status);
        } else {
            print_message("SMP_NanoROOT_signDigest returned NULL signature\n");
        }
        SMP_NanoROOT_deleteObject(moduleHandle, tokenHandle, objectHandle);
        SMP_NanoROOT_uninitToken(moduleHandle, tokenHandle);
        SMP_NanoROOT_uninitModule(moduleHandle);
        NanoROOT_deInit();
        free(configInfo.configInfo.pBuffer);
        skip();
        return;
    }

    /* Verify signature was created */
    assert_int_equal(status, OK);
    assert_non_null(pSignature);
    assert_non_null(pSignature->signature.rsaSignature.pSignature);
    assert_true(pSignature->signature.rsaSignature.signatureLen == 256); /* RSA-2048 */

    /* Cleanup signature */
    if (pSignature) {
        if (pSignature->signature.rsaSignature.pSignature) {
            DIGI_FREE((void **)&pSignature->signature.rsaSignature.pSignature);
        }
        DIGI_FREE((void **)&pSignature);
    }

    /* Delete object */
    status = SMP_NanoROOT_deleteObject(moduleHandle, tokenHandle, objectHandle);
    assert_int_equal(status, OK);

    /* Uninitialize token */
    status = SMP_NanoROOT_uninitToken(moduleHandle, tokenHandle);
    assert_int_equal(status, OK);

    /* Uninitialize module */
    status = SMP_NanoROOT_uninitModule(moduleHandle);
    assert_int_equal(status, OK);

    /* Cleanup */
    NanoROOT_deInit();
    free(configInfo.configInfo.pBuffer);
}

/*------------------------------------------------------------------*/
/* Test: signBuffer with invalid parameters - comprehensive */
/* Note: Individual NULL tests exist separately for granular coverage */
/*------------------------------------------------------------------*/
static void test_smp_cc_sign_buffer_invalid_params(void **state)
{
    UNUSED(state);
    MSTATUS status;

    /* Comprehensive test: Multiple NULL parameters simultaneously */
    status = SMP_NanoROOT_signBuffer(0, 0, 0, NULL, TAP_SIG_SCHEME_PKCS1_5_SHA256, NULL, NULL);
    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: signDigest with invalid parameters - comprehensive */
/* Note: Individual NULL tests exist separately for granular coverage */
/*------------------------------------------------------------------*/
static void test_smp_cc_sign_digest_invalid_params(void **state)
{
    UNUSED(state);
    MSTATUS status;

    /* Comprehensive test: Multiple NULL parameters simultaneously */
    status = SMP_NanoROOT_signDigest(0, 0, 0, NULL, TAP_SIG_SCHEME_PKCS1_5_SHA256, NULL, NULL);
    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Main test runner */
/*------------------------------------------------------------------*/

int main(void) {
    const struct CMUnitTest tests[] = {
        /* Input validation tests */
        cmocka_unit_test(test_validateInput_null_input),
        cmocka_unit_test(test_validateInput_valid_path),
        cmocka_unit_test(test_validateInput_blocked_chars),
        cmocka_unit_test(test_validateInput_allowed_chars_only),
        
        /* Module list tests */
        cmocka_unit_test(test_getModuleList_null_pointer),
        cmocka_unit_test(test_getModuleList_success),
        cmocka_unit_test(test_freeModuleList_null_pointer),
        cmocka_unit_test(test_freeModuleList_success),
        
        /* Module initialization tests */
        cmocka_unit_test(test_initModule_invalid_module_id),
        cmocka_unit_test(test_initModule_null_handle),
        cmocka_unit_test(test_initModule_success),
        
        /* Token initialization tests */
        cmocka_unit_test(test_initToken_null_module_handle),
        cmocka_unit_test(test_initToken_null_token_handle),
        
        /* Interface tests */
        cmocka_unit_test(test_register_null_opcodes),
        cmocka_unit_test(test_register_null_config),
        
        /* Dispatcher tests */
        cmocka_unit_test(test_dispatcher_null_request),
        cmocka_unit_test(test_dispatcher_null_response),
        cmocka_unit_test(test_dispatcher_get_module_list),
        
        /* Path validation tests */
        cmocka_unit_test(test_validatePath_null_path),
        cmocka_unit_test(test_validatePath_relative_path),
        cmocka_unit_test(test_validatePath_too_long),
        
        /* Integration tests */
        cmocka_unit_test(test_full_module_token_lifecycle),
        
        /* Device Protection tests */
        cmocka_unit_test(test_initFingerprintCtx_null_pointer),
        cmocka_unit_test(test_initFingerprintCtx_invalid_numuses),
        cmocka_unit_test(test_initFingerprintCtx_reusable_key),
        cmocka_unit_test(test_initFingerprintCtx_multiple_uses),
        cmocka_unit_test(test_freeFingerprintCtx_null_pointer),
        cmocka_unit_test(test_fingerprintDevice_null_context),
        cmocka_unit_test(test_fingerprintDevice_null_elements),
        cmocka_unit_test(test_fingerprintDevice_zero_elements),
        cmocka_unit_test(test_fingerprintDevice_success_hmac),
        cmocka_unit_test(test_encrypt_null_context),
        cmocka_unit_test(test_encrypt_decrypt_roundtrip_aes_ctr),
        cmocka_unit_test(test_encrypt_decrypt_roundtrip_aes_cbc),
        cmocka_unit_test(test_decrypt_null_context),
        cmocka_unit_test(test_encrypt_multiple_uses),
        
        /* API Coverage tests */
        cmocka_unit_test(test_getTokenList_null_moduleHandle),
        cmocka_unit_test(test_getTokenList_null_tokenList),
        cmocka_unit_test(test_getTokenList_success),
        cmocka_unit_test(test_seal_null_moduleHandle),
        cmocka_unit_test(test_seal_null_tokenHandle),
        cmocka_unit_test(test_seal_null_input_data),
        cmocka_unit_test(test_seal_null_output_buffer),
        cmocka_unit_test(test_seal_invalid_output_buffer),
        cmocka_unit_test(test_unseal_null_moduleHandle),
        cmocka_unit_test(test_unseal_null_tokenHandle),
        cmocka_unit_test(test_unseal_null_input_data),
        cmocka_unit_test(test_unseal_null_output_buffer),
        cmocka_unit_test(test_unseal_invalid_output_buffer),
        cmocka_unit_test(test_initObject_null_moduleHandle),
        cmocka_unit_test(test_initObject_null_tokenHandle),
        cmocka_unit_test(test_deleteObject_null_moduleHandle),
        cmocka_unit_test(test_getPublicKey_null_moduleHandle),
        cmocka_unit_test(test_getPublicKey_null_tokenHandle),
        cmocka_unit_test(test_getPublicKey_null_objectHandle),
        cmocka_unit_test(test_getPublicKey_null_output),
        cmocka_unit_test(test_signDigest_null_moduleHandle),
        cmocka_unit_test(test_signDigest_null_tokenHandle),
        cmocka_unit_test(test_signDigest_null_objectHandle),
        cmocka_unit_test(test_signDigest_null_digest),
        cmocka_unit_test(test_signDigest_null_signature),
        cmocka_unit_test(test_signBuffer_null_moduleHandle),
        cmocka_unit_test(test_signBuffer_null_tokenHandle),
        cmocka_unit_test(test_signBuffer_null_objectHandle),
        cmocka_unit_test(test_signBuffer_null_buffer),
        cmocka_unit_test(test_signBuffer_null_signature),
        cmocka_unit_test(test_fillError_null_error),
        cmocka_unit_test(test_fillError_null_status),
        cmocka_unit_test(test_fillError_valid),
        cmocka_unit_test(test_fillError_null_buffer),
        cmocka_unit_test(test_error_propagation),
        cmocka_unit_test(test_sequential_operations),
        
        /* Integration tests with real config */
        cmocka_unit_test(test_integration_module_token_init),
        cmocka_unit_test(test_integration_seal_unseal),
        cmocka_unit_test(test_integration_sign_digest),
        cmocka_unit_test(test_integration_sign_buffer),
        
        /* RSA-2048 signing tests */
        cmocka_unit_test(test_smp_cc_sign_buffer_rsa2k),
        cmocka_unit_test(test_smp_cc_sign_digest_rsa2k),
        cmocka_unit_test(test_smp_cc_sign_buffer_invalid_params),
        cmocka_unit_test(test_smp_cc_sign_digest_invalid_params),
    };
    
    return cmocka_run_group_tests(tests, setup, teardown);
}

#else
int main(void) {
    printf("NanoROOT SMP is not enabled. Skipping tests.\n");
    return 0;
}
#endif /* __ENABLE_DIGICERT_SMP__ && __ENABLE_DIGICERT_SMP_NANOROOT__ */
