/*
 * moctap_tools_utils.h
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

#ifndef __MOCTAP_TOOLS_UTILS_HEADER__
#define __MOCTAP_TOOLS_UTILS_HEADER__

#include "../tap_smp.h"
#include "../../common/debug_console.h"

#define MOCTAP_DEBUG_PRINT_1(msg) \
    do {\
        DB_PRINT("%s() - %d: "msg"\n", __FUNCTION__, __LINE__);\
    } while (0)

#define MOCTAP_DEBUG_PRINT(fmt, ...) \
    do {\
        DB_PRINT("%s() - %d: "fmt"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__ );\
    } while (0)

#ifdef __RTOS_WIN32__
#define LOG_MESSAGE(fmt, ...) \
    do {\
        char buffer[512];\
        sprintf_s(buffer, sizeof(buffer), fmt"\n", ##__VA_ARGS__);\
        fputs(buffer, stdout);\
    } while (0)
#else
#define LOG_MESSAGE(fmt, ...) \
    do {\
        char buffer[512];\
        snprintf(buffer, sizeof(buffer), fmt"\n", ##__VA_ARGS__);\
        fputs(buffer, stdout);\
    } while (0)
#endif

#ifdef __RTOS_WIN32__
#define LOG_ERROR(fmt, ...) \
    do {\
        char buffer[512];\
        sprintf_s(buffer, sizeof(buffer), "ERROR: "fmt"\n", ##__VA_ARGS__);\
        fputs(buffer, stdout);\
    } while (0)
#else
#define LOG_ERROR(fmt, ...) \
    do {\
        char buffer[512];\
        snprintf(buffer, sizeof(buffer), "ERROR: "fmt"\n", ##__VA_ARGS__);\
        fputs(buffer, stdout);\
    } while (0)
#endif

#define PRINT_STATUS(x,y)   \
    DB_PRINT("%s %s status %d = %s\n", x, (y==OK ? "SUCCESS":"FAILED"),\
                y, MERROR_lookUpErrorCode(y))

typedef struct {
    char *providerName;
    TAP_PROVIDER providerType;
    char *configFilePath;
} tapProviderEntry;

/* Internal method - validates incoming name against supported provider-names
 * and returns back TAP_PROVIDER as tapProviderEntry*
 * Returns OK if TAP_PROVIDER value if supported,
 * else returns an error
 * Caller should free ppTapProvider by calling freeTapProviderEntry
 */
extern MSTATUS getProviderFromName(const ubyte* providerName,
                                tapProviderEntry** ppTapProviderEntry);


extern MSTATUS freeTapProviderEntry(tapProviderEntry **ppTapProviderEntry);
#endif /*__MOCTAP_TOOLS_UTILS_HEADER__*/
