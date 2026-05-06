/*
 * trustedge_agent_attributes.c
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

/* Windows headers must come first to avoid macro conflicts */
#if defined (__RTOS_WIN32__)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

#include "../../trustedge/agent/trustedge_agent_attributes.h"
#include "../../common/mfmgmt.h"
#include "../../common/build_info.h"
#include "../../common/common_utils.h"
#include "../../common/base64.h"

#if defined (__RTOS_LINUX__)
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#if defined (__RTOS_ZEPHYR__)
#include <zephyr/net/net_if.h>
#include <zephyr/drivers/hwinfo.h>
#include <zephyr/version.h>
#else
#include <linux/if.h>
#include <linux/if_ether.h>
#include <ifaddrs.h>
#endif
#include <fcntl.h>
#include <unistd.h>
#endif
#if defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__)
/* TODO: Temporary fix
 *
 * Issue: The header file mqtt_client.h includes merrors.h and redefines OK to
 * MOC_OK for ESP32 builds. The ssl.h header below includes a ESP32 toolchain
 * header file which also defines OK which then gets redefined to MOC_OK causing
 * compilation errors.
 *
 * Fix: Undefine OK before including ssl.h, then redefine it back to MOC_OK
 */
#undef OK
#include <esp_efuse.h>
#include <esp_mac.h>
#include <esp_netif.h>
/* TODO: Temporary fix - see comment above */
#define OK MOC_OK
#endif
#include <stdio.h>
#include <string.h>

#define TRUSTEDGE_ATTR_OS "operating_system"
#define TRUSTEDGE_ATTR_OS_VERSION "operating_system_version"
#define TRUSTEDGE_ATTR_MAC_ADDR "mac_address"
#define TRUSTEDGE_ATTR_SERIAL_NUMBER "serial_number"
#define TRUSTEDGE_ATTR_HARDWARE_MODEL "hardware_model"
#define TRUSTEDGE_ATTR_IP_ADDR "ip_address"
#define TRUSTEDGE_ATTR_CPU_ID "cpu_id"
#define TRUSTEDGE_ATTR_LOCATION "location"
#define TRUSTEDGE_ATTR_TRUSTEDGE_VERSION "trustedge_version"

#if defined (__RTOS_LINUX__) && !defined (__RTOS_ZEPHYR__)
#define TRUSTEDGE_OS_RELEASE_FILE "/etc/os-release"
#define TRUSTEDGE_HARDWARE_MODEL_FILE "/sys/class/dmi/id/product_name"
#endif

#define TRUSTEDGE_OS_ID "ID"
#define TRUSTEDGE_OS_VERSION_ID "VERSION_ID"

#define TRUSTEDGE_AGENT_ATTRIBUTES "attributes"
#define TRUSTEDGE_AGENT_ATTRIBUTE_NAME "attribute_name"
#define TRUSTEDGE_AGENT_ATTRIBUTE_NAMES "attribute_names"
#define TRUSTEDGE_AGENT_ATTRIBUTE_VALUE "attribute_value"
#define TRUSTEDGE_AGENT_ATTRIBUTE_TYPE "type"
#define TRUSTEDGE_AGENT_ATTRIBUTE_PATH "path"
#define TRUSTEDGE_AGENT_ATTRIBUTE_VAR_NAME "variable_name"
#define TRUSTEDGE_AGENT_ATTRIBUTE_OUTPUT_FORMAT "output_format"
#define TRUSTEDGE_AGENT_ATTRIBUTE_ARGUMENT "argument"

#define TRUSTEDGE_AGENT_ATTRIBUTE_TYPE_ENV      "ENV"
#define TRUSTEDGE_AGENT_ATTRIBUTE_TYPE_PROGRAM  "program"

#define TRUSTEDGE_AGENT_ATTRIBUTE_OUTPUT_FORMAT_JSON "JSON"

/*----------------------------------------------------------------------------*/

/* Inventory attribute structure */
typedef MSTATUS (*funcPtrDefaultAttrHandler)(ubyte **ppVal, ubyte4 *pValLen);

typedef struct
{
    sbyte *pAttributeName;
    funcPtrDefaultAttrHandler pHandler;
} InventoryAttributes;

static MSTATUS TRUSTEDGE_agentAttributesMACAddr(
    ubyte **ppVal,
    ubyte4 *pValLen);

static MSTATUS TRUSTEDGE_agentAttributesHardwareModel(
    ubyte **ppVal,
    ubyte4 *pValLen);

static MSTATUS TRUSTEDGE_agentAttributesOS(
    ubyte **ppVal,
    ubyte4 *pValLen);

static MSTATUS TRUSTEDGE_agentAttributesOSVersion(
    ubyte **ppVal,
    ubyte4 *pValLen);

static MSTATUS TRUSTEDGE_agentAttributesIPAddr(
    ubyte **ppVal,
    ubyte4 *pValLen);

static MSTATUS TRUSTEDGE_agentAttributesTrustedgeVersion(
    ubyte **ppVal,
    ubyte4 *pValLen);

static InventoryAttributes gpDefaultAttributes[] = {
    {TRUSTEDGE_ATTR_MAC_ADDR,           TRUSTEDGE_agentAttributesMACAddr},
    {TRUSTEDGE_ATTR_SERIAL_NUMBER,      NULL},
    {TRUSTEDGE_ATTR_HARDWARE_MODEL,     TRUSTEDGE_agentAttributesHardwareModel},
    {TRUSTEDGE_ATTR_LOCATION,           NULL},
    {TRUSTEDGE_ATTR_OS,                 TRUSTEDGE_agentAttributesOS},
#if !defined(__RTOS_ZEPHYR__)
    {TRUSTEDGE_ATTR_OS_VERSION,         TRUSTEDGE_agentAttributesOSVersion},
#endif
    {TRUSTEDGE_ATTR_IP_ADDR,            TRUSTEDGE_agentAttributesIPAddr},
    {TRUSTEDGE_ATTR_CPU_ID,             TRUSTEDGE_agentAttributesCPUId},
    {TRUSTEDGE_ATTR_TRUSTEDGE_VERSION,  TRUSTEDGE_agentAttributesTrustedgeVersion}
};

/* Structure for parsing customer provided attributes */
typedef enum
{
    ATTRIBUTE_TYPE_NONE = 0,
    ATTRIBUTE_TYPE_ENV,
    ATTRIBUTE_TYPE_PROGRAM
} AttributeType;

typedef enum
{
    ATTRIBUTE_OUTPUT_NONE = 0,
    ATTRIBUTE_OUTPUT_JSON,
    ATTRIBUTE_OUTPUT_STRING
} AttributeOutput;

typedef struct
{
    sbyte **ppNames;
    ubyte4 nameCount;
    AttributeType type;
    sbyte *pEnv;
    sbyte *pPath;
    sbyte *pArg;
    AttributeOutput output;
} AttributeItem;

typedef struct
{
    AttributeItem *pItems;
    ubyte4 itemCount;
} AttributeList;

/*----------------------------------------------------------------------------*/

#if !defined(__RTOS_ZEPHYR__)
static MSTATUS TRUSTEDGE_parseGetOSAttribute(
    sbyte *pAttributeName,
    sbyte **ppValue)
{
#if defined(TRUSTEDGE_OS_RELEASE_FILE)
    MSTATUS status;
    ubyte *pData = NULL, *pLine;
    ubyte4 dataLen = 0, lineLen;
    ubyte4 attrLen;
    ubyte *pEnd;
    sbyte *pValue = NULL;
    ubyte4 i;

    *ppValue = NULL;

    status = DIGICERT_readFile(TRUSTEDGE_OS_RELEASE_FILE, &pData, &dataLen);
    if (OK != status)
    {
        goto exit;
    }

    attrLen = DIGI_STRLEN(pAttributeName);
    pLine = pData;
    while (dataLen > 0)
    {
        pEnd = DIGI_STRCHR(pLine, '\n', dataLen);
        if (NULL != pEnd)
        {
            lineLen = pEnd - pLine;
            if (lineLen > attrLen && 0 == DIGI_STRNCMP(pLine, pAttributeName, attrLen) && '=' == pLine[attrLen])
            {
                status = DIGI_MALLOC_MEMCPY(
                    (void **)ppValue,
                    lineLen - attrLen, pLine + attrLen + 1, lineLen - attrLen - 1);
                if (OK != status)
                {
                    goto exit;
                }
                (*ppValue)[lineLen - attrLen - 1] = '\0';

                pValue = *ppValue;
                if (lineLen - attrLen > 2 && '"' == pValue[0] && '"' == pValue[lineLen - attrLen - 2])
                {
                    for (i = 0; i < lineLen - attrLen - 2; i++)
                    {
                        pValue[i] = pValue[i + 1];
                    }
                    pValue[lineLen - attrLen - 3] = '\0';
                }
                break;
            }
            pLine = pEnd;
        }
        else
        {
            break;
        }

        pLine++;
        dataLen -= (pEnd - pLine);
    }

exit:

    DIGI_FREE((void **)&pData);

    return status;
#else
    MOC_UNUSED(pAttributeName);
    MOC_UNUSED(ppValue);

    return ERR_NOT_IMPLEMENTED;
#endif
}
#endif /* !__RTOS_ZEPHYR__ */

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentAttributesOS(
    ubyte **ppVal,
    ubyte4 *pValLen)
{
    MSTATUS status;
#if defined (__RTOS_ZEPHYR__)
    sbyte *pName = "zephyr";
    *pValLen = DIGI_STRLEN(pName);
    *ppVal = TRUSTEDGE_utilsCloneString(pName);
    status = OK;
#elif defined (__RTOS_WIN32__)
    HKEY hKey;
    DWORD dwType = REG_SZ;
    DWORD dwSize = 0;
    ubyte *pValue = NULL;
    LONG lResult;

    /* Open the registry key for Windows version info */
    lResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                            0, KEY_READ, &hKey);
    if (lResult != ERROR_SUCCESS)
    {
        status = ERR_TRUSTEDGE_AGENT_ATTRIBUTE_ERROR;
        goto exit;
    }

    /* First call to get the required buffer size */
    lResult = RegQueryValueExA(hKey, "ProductName", NULL, &dwType, NULL, &dwSize);
    if (lResult != ERROR_SUCCESS || dwSize == 0)
    {
        RegCloseKey(hKey);
        status = ERR_TRUSTEDGE_AGENT_ATTRIBUTE_ERROR;
        goto exit;
    }

    status = DIGI_MALLOC((void **)&pValue, dwSize);
    if (OK != status)
    {
        RegCloseKey(hKey);
        goto exit;
    }

    /* Get the actual value */
    lResult = RegQueryValueExA(hKey, "ProductName", NULL, &dwType, pValue, &dwSize);
    RegCloseKey(hKey);

    if (lResult != ERROR_SUCCESS)
    {
        DIGI_FREE((void **)&pValue);
        status = ERR_TRUSTEDGE_AGENT_ATTRIBUTE_ERROR;
        goto exit;
    }

    /* Validate the type is a string */
    if (dwType != REG_SZ && dwType != REG_EXPAND_SZ)
    {
        DIGI_FREE((void **)&pValue);
        status = ERR_TRUSTEDGE_AGENT_ATTRIBUTE_ERROR;
        goto exit;
    }

    /* Ensure NUL termination - registry strings may not be terminated */
    if (dwSize > 0)
    {
        pValue[dwSize - 1] = '\0';
    }

    *ppVal = pValue;
    *pValLen = DIGI_STRLEN(pValue);
exit:
    /* Default to "windows" if we couldn't retrieve the OS name */
    if (OK != status)
    {
        sbyte *pDefault = "Windows";
        *pValLen = DIGI_STRLEN(pDefault);
        *ppVal = TRUSTEDGE_utilsCloneString(pDefault);
        if (NULL != *ppVal)
        {
            status = OK;
        }
    }
#else
    status = TRUSTEDGE_parseGetOSAttribute(TRUSTEDGE_OS_ID, (sbyte **)ppVal);
    if (OK != status)
    {
        goto exit;
    }
    *pValLen = DIGI_STRLEN(*ppVal);
exit:
#endif

    return status;
}

static MSTATUS TRUSTEDGE_agentAttributesOSVersion(
    ubyte **ppVal,
    ubyte4 *pValLen)
{
    MSTATUS status;
#if defined (__RTOS_ZEPHYR__)
    ubyte major, minor, patch;
    ubyte4 version;
    sbyte pVersion[16] = {0};

    version = KERNELVERSION;
    major = (version >> 24) & 0xFF;
    minor = (version >> 16) & 0xFF;
    patch = (version >> 8) & 0xFF;

    snprintf(pVersion, sizeof(pVersion), "%d.%d.%d", major, minor, patch);
    *pValLen = DIGI_STRLEN(pVersion);
    *ppVal = TRUSTEDGE_utilsCloneString(pVersion);
    status = OK;
#elif defined (__RTOS_WIN32__)
    OSVERSIONINFOA osvi;
    sbyte pVersion[32] = {0};
    ubyte4 len;

    ZeroMemory(&osvi, sizeof(OSVERSIONINFOA));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);

    /* GetVersionExA is deprecated but still works for basic version info */
#pragma warning(push)
#pragma warning(disable: 4996)
    if (!GetVersionExA(&osvi))
    {
        status = ERR_TRUSTEDGE_AGENT_ATTRIBUTE_ERROR;
        goto exit;
    }
#pragma warning(pop)

    snprintf(pVersion, sizeof(pVersion), "%lu.%lu.%lu",
             osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);

    len = DIGI_STRLEN(pVersion);
    status = DIGI_MALLOC((void **)ppVal, len + 1);
    if (OK != status)
    {
        goto exit;
    }
    DIGI_MEMCPY(*ppVal, pVersion, len);
    (*ppVal)[len] = '\0';
    *pValLen = len;
exit:
#else
    status = TRUSTEDGE_parseGetOSAttribute(TRUSTEDGE_OS_VERSION_ID, (sbyte **)ppVal);
    if (OK != status)
    {
        goto exit;
    }
    *pValLen = DIGI_STRLEN(*ppVal);
exit:
#endif

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentAttributesMACAddr(
    ubyte **ppVal,
    ubyte4 *pValLen)
{
#if defined (__RTOS_ZEPHYR__)
    MSTATUS status = ERR_NOT_FOUND;
    struct net_if *iface;
    int iface_count = 1;
    sbyte *pMac = NULL;
    sbyte4 macLen = 0;

    while((iface = net_if_get_by_index(iface_count++)) != NULL)
    {
        struct net_linkaddr *linkaddr = net_if_get_link_addr(iface);
        if (linkaddr && linkaddr->len == 6)
        {
            macLen = 18;
            status = DIGI_MALLOC((void **) &pMac, macLen);
            if (OK != status)
            {
                goto exit;
            }

            snprintf(pMac, macLen, "%02X:%02X:%02X:%02X:%02X:%02X",
                    linkaddr->addr[0], linkaddr->addr[1], linkaddr->addr[2],
                    linkaddr->addr[3], linkaddr->addr[4], linkaddr->addr[5]);

            *ppVal = pMac;
            *pValLen = DIGI_STRLEN(pMac);
            status = OK;
            break;
        }
    }
exit:

    return status;
#elif defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__)
    MSTATUS status = OK;
    uint8_t mac[6];
    sbyte *pMac = NULL;
    sbyte4 macLen = 18;
    esp_err_t err;

    /* Get base MAC address from eFuse */
    err = esp_efuse_mac_get_default(mac);
    if (err != ESP_OK)
    {
        status = ERR_TRUSTEDGE_AGENT_ATTRIBUTE_ERROR;
        goto exit;
    }

    status = DIGI_MALLOC((void **)&pMac, macLen);
    if (OK != status)
    {
        goto exit;
    }

    snprintf(pMac, macLen, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    *ppVal = (ubyte *)pMac;
    *pValLen = DIGI_STRLEN(pMac);

exit:

    return status;
#elif defined (__RTOS_LINUX__)
    MSTATUS status = OK;
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;
    int i;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1)
    {
        status = ERR_TRUSTEDGE_AGENT_ATTRIBUTE_ERROR;
        goto exit;
    };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1)
    {
        status = ERR_TRUSTEDGE_AGENT_ATTRIBUTE_ERROR;
        goto exit;
    }

    struct ifreq *it = ifc.ifc_req;
    const struct ifreq *const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it)
    {
        (void) DIGI_MEMCPY(ifr.ifr_name, it->ifr_name, IFNAMSIZ);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0)
        {
            if (!(ifr.ifr_flags & IFF_LOOPBACK))
            { /* don't count loopback */
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
                {
                    success = 1;
                    break;
                }
            }
        }
        else
        {
            status = ERR_TRUSTEDGE_AGENT_ATTRIBUTE_ERROR;
            goto exit;
        }
    }

    if (success)
    {
        status = DIGI_MALLOC((void **)ppVal, 18);
        if (OK != status)
        {
            goto exit;
        }
        for (i = 0; i < 6; i++)
        {
            (*ppVal)[i * 3] = returnHexDigit(((unsigned char)ifr.ifr_hwaddr.sa_data[i]) >> 4);
            (*ppVal)[i * 3 + 1] = returnHexDigit(((unsigned char)ifr.ifr_hwaddr.sa_data[i]) & 0x0F);
            (*ppVal)[i * 3 + 2] = (i < 5) ? ':' : '\0';
        }
        (*ppVal)[17] = '\0';
        *pValLen = 17;
    }
    else
    {
        status = ERR_TRUSTEDGE_AGENT_ATTRIBUTE_ERROR;
    }

exit:

    return status;
#elif defined (__RTOS_WIN32__)
    MSTATUS status = OK;
    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    PIP_ADAPTER_INFO pAdapter = NULL;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    sbyte *pMac = NULL;
    DWORD dwRetVal;

    /* First call to get the required buffer size */
    pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
    {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
        if (pAdapterInfo == NULL)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }

    dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
    if (dwRetVal != NO_ERROR)
    {
        status = ERR_TRUSTEDGE_AGENT_ATTRIBUTE_ERROR;
        goto exit;
    }

    /* Find the first non-loopback adapter with a valid MAC */
    pAdapter = pAdapterInfo;
    while (pAdapter)
    {
        if (pAdapter->AddressLength == 6)
        {
            status = DIGI_MALLOC((void **)&pMac, 18);
            if (OK != status)
            {
                goto exit;
            }

            snprintf(pMac, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
                     pAdapter->Address[0], pAdapter->Address[1],
                     pAdapter->Address[2], pAdapter->Address[3],
                     pAdapter->Address[4], pAdapter->Address[5]);

            *ppVal = (ubyte *)pMac;
            *pValLen = DIGI_STRLEN(pMac);
            break;
        }
        pAdapter = pAdapter->Next;
    }

    if (pMac == NULL)
    {
        status = ERR_TRUSTEDGE_AGENT_ATTRIBUTE_ERROR;
    }

exit:
    if (pAdapterInfo)
    {
        free(pAdapterInfo);
    }

    return status;
#else
    return ERR_NOT_IMPLEMENTED;
#endif
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentAttributesHardwareModel(
    ubyte **ppVal,
    ubyte4 *pValLen)
{
#if defined(TRUSTEDGE_HARDWARE_MODEL_FILE)
    MSTATUS status = OK;
    FileDescriptor pFileCtx = NULL;
    sbyte4 fileChar;
    ubyte4 i, fileSize = 0, length = 0;
    ubyte *pValue = NULL;

    status = FMGMT_fopen(
        TRUSTEDGE_HARDWARE_MODEL_FILE, "r", &pFileCtx);
    if (OK != status)
    {
        goto exit;
    }

    /* Get file size */
    status = FMGMT_fseek(pFileCtx, 0, MSEEK_END);
    if (OK != status)
    {
        goto exit;
    }

    status = FMGMT_ftell(pFileCtx, &fileSize);
    if (OK != status)
    {
        goto exit;
    }

    /* Start at beginning of file */
    status = FMGMT_fseek(pFileCtx, 0, MSEEK_SET);
    if (OK != status)
    {
        goto exit;
    }

    /* Assuming file contains ASCII string, determine length */
    for (i = 0; i < fileSize; i++)
    {
        fileChar = FMGMT_fgetc(pFileCtx);
        if (MOC_EOF == fileChar || '\0' == fileChar || (!(fileChar >> 8) && (FALSE == DIGI_ISASCII(fileChar & 0xFF))))
            break;

        length++;
    }

    /* Allocate memory and read contents into buffer */
    status = DIGI_MALLOC((void **)&pValue, length + 1);
    if (OK != status)
    {
        goto exit;
    }

    status = FMGMT_fseek(pFileCtx, 0, MSEEK_SET);
    if (OK != status)
    {
        goto exit;
    }

    for (i = 0; i < length; i++)
    {
        pValue[i] = (ubyte)FMGMT_fgetc(pFileCtx);
    }

    pValue[length] = '\0';
    *ppVal = pValue;
    pValue = NULL;
    *pValLen = length;

exit:

    if (NULL != pValue)
    {
        DIGI_FREE((void **)&pValue);
    }

    if (NULL != pFileCtx)
    {
        FMGMT_fclose(&pFileCtx);
    }

    return status;
#elif defined (__RTOS_WIN32__)
    MSTATUS status = OK;
    HKEY hKey;
    DWORD dwType = REG_SZ;
    DWORD dwSize = 0;
    ubyte *pValue = NULL;
    LONG lResult;

    /* Open the registry key for system information */
    lResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                            "HARDWARE\\DESCRIPTION\\System\\BIOS",
                            0, KEY_READ, &hKey);
    if (lResult != ERROR_SUCCESS)
    {
        status = ERR_TRUSTEDGE_AGENT_ATTRIBUTE_ERROR;
        goto exit;
    }

    /* First call to get the required buffer size */
    lResult = RegQueryValueExA(hKey, "SystemProductName", NULL, &dwType, NULL, &dwSize);
    if (lResult != ERROR_SUCCESS || dwSize == 0)
    {
        RegCloseKey(hKey);
        status = ERR_TRUSTEDGE_AGENT_ATTRIBUTE_ERROR;
        goto exit;
    }

    status = DIGI_MALLOC((void **)&pValue, dwSize);
    if (OK != status)
    {
        RegCloseKey(hKey);
        goto exit;
    }

    /* Get the actual value */
    lResult = RegQueryValueExA(hKey, "SystemProductName", NULL, &dwType, pValue, &dwSize);
    RegCloseKey(hKey);

    if (lResult != ERROR_SUCCESS)
    {
        DIGI_FREE((void **)&pValue);
        status = ERR_TRUSTEDGE_AGENT_ATTRIBUTE_ERROR;
        goto exit;
    }

    /* Validate the type is a string */
    if (dwType != REG_SZ && dwType != REG_EXPAND_SZ)
    {
        DIGI_FREE((void **)&pValue);
        status = ERR_TRUSTEDGE_AGENT_ATTRIBUTE_ERROR;
        goto exit;
    }

    /* Ensure NUL termination - registry strings may not be terminated */
    if (dwSize > 0)
    {
        pValue[dwSize - 1] = '\0';
    }

    *ppVal = pValue;
    *pValLen = DIGI_STRLEN(pValue);

exit:

    return status;
#else
    MOC_UNUSED(ppVal);
    MOC_UNUSED(pValLen);
    return ERR_NOT_IMPLEMENTED;
#endif
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentAttributesIPAddr(
    ubyte **ppVal,
    ubyte4 *pValLen)
{
#if defined (__RTOS_ZEPHYR__)
    MSTATUS status = ERR_NOT_FOUND;
    struct net_if *iface;
    int iface_count = 1; /* this is first index, not zero */
	char pStr[NET_IPV4_ADDR_LEN];
    sbyte4 ipLen;
    ubyte *pIpStr;
    struct in_addr *addr;

    /* Loop through all network interfaces by index */
    while((iface = net_if_get_by_index(iface_count++)) != NULL)
    {
        addr = net_if_ipv4_get_global_addr(iface, NET_ADDR_PREFERRED);
        if (!addr) {
            addr = net_if_ipv4_get_global_addr(iface, NET_ADDR_TENTATIVE);
        }

        if (addr && !net_ipv4_is_addr_loopback(addr))
        {
            net_addr_ntop(AF_INET, addr, pStr, sizeof(pStr));
            ipLen = DIGI_STRLEN(pStr) + 1;
            status = DIGI_MALLOC((void **) &pIpStr, ipLen);
            if (OK != status)
            {
                goto exit;
            }

            status = DIGI_MEMCPY(pIpStr, pStr, ipLen);
            if (OK != status)
            {
                DIGI_FREE((void **) &pIpStr);
                goto exit;
            }

            *ppVal = pIpStr;
            *pValLen = DIGI_STRLEN(pIpStr);
            status = OK;
            break;
        }
    }

exit:

    return status;
#elif defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__)
    MSTATUS status = OK;
    esp_netif_t *netif = NULL;
    esp_netif_ip_info_t ip_info;
    sbyte *pIpStr = NULL;
    sbyte ipStrBuf[16];
    sbyte4 ipLen;

    /* Try to get default WiFi station interface first, then Ethernet */
    netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (netif == NULL)
    {
        netif = esp_netif_get_handle_from_ifkey("ETH_DEF");
    }

    if (netif == NULL)
    {
        status = ERR_TRUSTEDGE_AGENT_ATTRIBUTE_ERROR;
        goto exit;
    }

    if (esp_netif_get_ip_info(netif, &ip_info) != ESP_OK)
    {
        status = ERR_TRUSTEDGE_AGENT_ATTRIBUTE_ERROR;
        goto exit;
    }

    /* Convert IP address to string */
    snprintf(ipStrBuf, sizeof(ipStrBuf), IPSTR, IP2STR(&ip_info.ip));
    ipLen = DIGI_STRLEN(ipStrBuf) + 1;

    status = DIGI_MALLOC((void **)&pIpStr, ipLen);
    if (OK != status)
    {
        goto exit;
    }

    DIGI_MEMCPY(pIpStr, ipStrBuf, ipLen);
    *ppVal = (ubyte *)pIpStr;
    *pValLen = DIGI_STRLEN(pIpStr);

exit:

    return status;
#elif defined (__RTOS_LINUX__)
    MSTATUS status = OK;
    struct ifaddrs *addr, *iaddr;
    int success = 0;
    char *ip = NULL;

    if (getifaddrs(&addr) == -1)
    {
        status = ERR_TRUSTEDGE_AGENT_ATTRIBUTE_ERROR;
        goto exit;
    }

    for (iaddr = addr; iaddr != NULL; iaddr = iaddr->ifa_next)
    {
        if (iaddr->ifa_addr == NULL)
            continue;

        int family = iaddr->ifa_addr->sa_family;
        char *interface = iaddr->ifa_name;

        if (family == AF_INET)
        {
            int descriptor;
            struct ifreq interface_request;

            descriptor = socket(AF_INET, SOCK_DGRAM, 0);
            if (descriptor == -1)
            {
                status = ERR_TRUSTEDGE_AGENT_ATTRIBUTE_ERROR;
                goto exit;
            }

            strncpy(interface_request.ifr_name, interface, IFNAMSIZ - 1);
            interface_request.ifr_name[IFNAMSIZ - 1] = '\0';

            if (ioctl(descriptor, SIOCGIFFLAGS, &interface_request) == 0)
            {
                if (!(interface_request.ifr_flags & IFF_LOOPBACK))
                {
                    if (ioctl(descriptor, SIOCGIFADDR, &interface_request) == 0)
                    {
                        struct sockaddr_in *addr = (struct sockaddr_in *)&interface_request.ifr_addr;
                        ip = inet_ntoa(addr->sin_addr);
                        if (ip != NULL)
                        {
                            success = 1;
                            close(descriptor);
                            break;
                        }
                    }

                    else
                    {
                        /* Error getting interface address, continue to next interface */
                        close(descriptor);
                        continue;
                    }
                }
            }
            else
            {
                /* Error getting interface flag, conitnue to next interface */
                close(descriptor);
                continue;
            }
            close(descriptor);
        }
    }

    if (success)
    {
        status = DIGI_MALLOC((void **)ppVal, 16);
        if (OK != status)
            goto exit;

        strncpy(*ppVal, ip, 15);
        (*ppVal)[15] = '\0';

        *pValLen = DIGI_STRLEN(*ppVal);
    }
    else
    {
        status = ERR_TRUSTEDGE_AGENT_ATTRIBUTE_ERROR;
    }

exit:

    if (addr != NULL)
    {
        freeifaddrs(addr);
    }

    return status;
#elif defined (__RTOS_WIN32__)
    MSTATUS status = OK;
    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    PIP_ADAPTER_INFO pAdapter = NULL;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    sbyte *pIpStr = NULL;
    DWORD dwRetVal;
    sbyte4 ipLen;

    /* First call to get the required buffer size */
    pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
    {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
        if (pAdapterInfo == NULL)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }

    dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
    if (dwRetVal != NO_ERROR)
    {
        status = ERR_TRUSTEDGE_AGENT_ATTRIBUTE_ERROR;
        goto exit;
    }

    /* Find the first adapter with a valid IP address */
    pAdapter = pAdapterInfo;
    while (pAdapter)
    {
        /* Skip if no IP address or if it's 0.0.0.0 */
        if (pAdapter->IpAddressList.IpAddress.String[0] != '\0' &&
            strcmp(pAdapter->IpAddressList.IpAddress.String, "0.0.0.0") != 0)
        {
            ipLen = (sbyte4)strlen(pAdapter->IpAddressList.IpAddress.String) + 1;
            status = DIGI_MALLOC((void **)&pIpStr, ipLen);
            if (OK != status)
            {
                goto exit;
            }

            strncpy(pIpStr, pAdapter->IpAddressList.IpAddress.String, ipLen - 1);
            pIpStr[ipLen - 1] = '\0';

            *ppVal = (ubyte *)pIpStr;
            *pValLen = DIGI_STRLEN(pIpStr);
            break;
        }
        pAdapter = pAdapter->Next;
    }

    if (pIpStr == NULL)
    {
        status = ERR_TRUSTEDGE_AGENT_ATTRIBUTE_ERROR;
    }

exit:
    if (pAdapterInfo)
    {
        free(pAdapterInfo);
    }

    return status;
#else
    return ERR_NOT_IMPLEMENTED;
#endif
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentAttributesTrustedgeVersion(
    ubyte **ppVal,
    ubyte4 *pValLen)
{
    MSTATUS status = OK;
    ubyte4 strLen;

    strLen = DIGI_STRLEN(BUILD_INFO_VERSION_VAL);

    status = DIGI_MALLOC((void **)ppVal, strLen + 1);
    if (OK != status)
        goto exit;

    DIGI_MEMCPY(*ppVal, BUILD_INFO_VERSION_VAL, strLen);
    (*ppVal)[strLen] = '\0';
    *pValLen = strLen;

exit:
    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentDeleteAttributeList(
    AttributeList **ppAttrList)
{
    MSTATUS status = OK, fstatus;
    ubyte4 i, j;

    if (NULL != ppAttrList && NULL != *ppAttrList)
    {
        for (i = 0; i < (*ppAttrList)->itemCount; i++)
        {
            for (j = 0; j < (*ppAttrList)->pItems[i].nameCount; j++)
            {
                fstatus = DIGI_FREE((void **) &((*ppAttrList)->pItems[i].ppNames[j]));
                if (OK == status)
                    status = fstatus;
            }

            fstatus = DIGI_FREE((void **) &((*ppAttrList)->pItems[i].ppNames));
            if (OK == status)
                status = fstatus;

            if (NULL != (*ppAttrList)->pItems[i].pEnv)
            {
                fstatus = DIGI_FREE((void **) &((*ppAttrList)->pItems[i].pEnv));
                if (OK == status)
                    status = fstatus;
            }

            if (NULL != (*ppAttrList)->pItems[i].pPath)
            {
                fstatus = DIGI_FREE((void **) &((*ppAttrList)->pItems[i].pPath));
                if (OK == status)
                    status = fstatus;
            }

            if (NULL != (*ppAttrList)->pItems[i].pArg)
            {
                fstatus = DIGI_FREE((void **) &((*ppAttrList)->pItems[i].pArg));
                if (OK == status)
                    status = fstatus;
            }
        }

        fstatus = DIGI_FREE((void **) &((*ppAttrList)->pItems));
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_FREE((void **) ppAttrList);
        if (OK == status)
            status = fstatus;
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentParseAttributes(
    TrustEdgeAgentCtx *pAgentCtx,
    sbyte *pAttributeFile,
    AttributeList **ppAttrList)
{
    MSTATUS status;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens = 0;
    ubyte4 index, objIndex, i, j;
    JSON_TokenType token = {0}, objToken = {0}, nameToken = {0};
    AttributeList *pAttrList = NULL;
    sbyte *pTemp = NULL;
    ubyte expectedType;

    status = DIGICERT_readFile(pAttributeFile, &pData, &dataLen);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_acquireContext(&pJCtx);
    if (OK != status)
    {
        goto exit;
    }

    /* Parse JSON */
    status = JSON_parse(pJCtx, pData, dataLen, &numTokens);
    if (OK != status)
    {
        goto exit;
    }

    /* Get array of attributes */
    status = JSON_getJsonArrayValue(
        pJCtx, 0, TRUSTEDGE_AGENT_ATTRIBUTES, &index, &token, TRUE);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_CALLOC((void **) &pAttrList, 1, sizeof(AttributeList));
    if (OK != status)
    {
        goto exit;
    }

    pAttrList->itemCount = token.elemCnt;

    status = DIGI_CALLOC((void **) &pAttrList->pItems, token.elemCnt, sizeof(AttributeItem));
    if (OK != status)
    {
        goto exit;
    }

    /* Loop through array of attributes */
    for (i = 0; i < token.elemCnt; i++)
    {
        index++;

        expectedType = JSON_String;
        status = JSON_getObjectIndex(
            pJCtx, TRUSTEDGE_AGENT_ATTRIBUTE_NAME, index, &objIndex, TRUE);
        if (OK != status)
        {
            expectedType = JSON_Array;
            status = JSON_getObjectIndex(
                pJCtx, TRUSTEDGE_AGENT_ATTRIBUTE_NAMES, index, &objIndex, TRUE);
            if (OK != status)
            {
                goto exit;
            }
        }

        objIndex++;
        status = JSON_getToken(pJCtx, objIndex, &objToken);
        if (OK != status)
        {
            goto exit;
        }

        if (objToken.type != expectedType)
        {
            status = ERR_JSON_UNEXPECTED_TYPE;
            goto exit;
        }

        /* Get attribute name, could be a string or array value */
        if (JSON_Array == objToken.type)
        {
            /* Attribute name is array, loop through each element and store it */
            status = DIGI_CALLOC(
                (void **) &(pAttrList->pItems[i].ppNames),
                objToken.elemCnt, sizeof(sbyte *));
            if (OK != status)
            {
                goto exit;
            }

            for (j = 0; j < objToken.elemCnt; j++)
            {
                objIndex++;

                status = JSON_getToken(pJCtx, objIndex, &nameToken);
                if (OK != status)
                {
                    goto exit;
                }

                if (JSON_String != nameToken.type)
                {
                    status = ERR_JSON_UNEXPECTED_TYPE;
                    goto exit;
                }

                status = DIGI_MALLOC_MEMCPY(
                    (void **) &(pAttrList->pItems[i].ppNames[j]),
                    nameToken.len + 1, (void *) nameToken.pStart, nameToken.len);
                if (OK != status)
                {
                    goto exit;
                }
                pAttrList->pItems[i].ppNames[j][nameToken.len] = '\0';

                pAttrList->pItems[i].nameCount++;
            }

            DIGI_FREE((void **) &pTemp);
            status = JSON_getJsonStringValue(
                pJCtx, index, TRUSTEDGE_AGENT_ATTRIBUTE_OUTPUT_FORMAT, &pTemp, TRUE);
            if (OK != status)
            {
                goto exit;
            }

            if (0 == DIGI_STRCMP(pTemp, TRUSTEDGE_AGENT_ATTRIBUTE_OUTPUT_FORMAT_JSON))
            {
                pAttrList->pItems[i].output = ATTRIBUTE_OUTPUT_JSON;
            }
        }
        else if (JSON_String == objToken.type)
        {
            /* Attribute name is string, store single value */
            status = DIGI_CALLOC(
                (void **) &(pAttrList->pItems[i].ppNames), 1, sizeof(sbyte *));
            if (OK != status)
            {
                goto exit;
            }

            status = DIGI_MALLOC_MEMCPY(
                (void **) &(pAttrList->pItems[i].ppNames[0]),
                objToken.len + 1, (void *) objToken.pStart, objToken.len);
            if (OK != status)
            {
                goto exit;
            }
            pAttrList->pItems[i].ppNames[0][objToken.len] = '\0';

            pAttrList->pItems[i].nameCount = 1;

            /* Assume string format */
            pAttrList->pItems[i].output = ATTRIBUTE_OUTPUT_STRING;
        }

        /* Get attribute type */
        DIGI_FREE((void **) &pTemp);
        status = JSON_getJsonStringValue(
            pJCtx, index, TRUSTEDGE_AGENT_ATTRIBUTE_TYPE, &pTemp, TRUE);
        if (OK != status)
        {
            goto exit;
        }

        if (0 == DIGI_STRCMP(pTemp, TRUSTEDGE_AGENT_ATTRIBUTE_TYPE_ENV))
        {
            /* Assign type */
            pAttrList->pItems[i].type = ATTRIBUTE_TYPE_ENV;

            /* Assign environment variable name */
            DIGI_FREE((void **) &pTemp);
            status = JSON_getJsonStringValue(
                pJCtx, index, TRUSTEDGE_AGENT_ATTRIBUTE_VAR_NAME, &pTemp, TRUE);
            if (OK != status)
            {
                goto exit;
            }
            pAttrList->pItems[i].pEnv = pTemp; pTemp = NULL;
        }
        else if (0 == DIGI_STRCMP(pTemp, TRUSTEDGE_AGENT_ATTRIBUTE_TYPE_PROGRAM))
        {
            /* Assign type */
            pAttrList->pItems[i].type = ATTRIBUTE_TYPE_PROGRAM;

            /* Assign path */
            DIGI_FREE((void **) &pTemp);
            status = JSON_getJsonStringValue(
                pJCtx, index, TRUSTEDGE_AGENT_ATTRIBUTE_PATH, &pTemp, TRUE);
            if (OK != status)
            {
                goto exit;
            }

            status = COMMON_UTILS_evaluatePlaceholder(
                CONF_DIR_PLACEHOLDER, pAgentCtx->pConfig->pConfDir,
                &pTemp);
            if (OK != status)
            {
                goto exit;
            }

            pAttrList->pItems[i].pPath = pTemp; pTemp = NULL;

            /* Assign optional argument */
            DIGI_FREE((void **) &pTemp);
            status = JSON_getJsonStringValue(
                pJCtx, index, TRUSTEDGE_AGENT_ATTRIBUTE_ARGUMENT, &pTemp, TRUE);
            if (OK == status)
            {
                pAttrList->pItems[i].pArg = pTemp; pTemp = NULL;
            }
        }

        /* Move to next object */
        status = JSON_getLastIndexInObject(pJCtx, index, &index);
        if (OK != status)
        {
            goto exit;
        }
    }

    *ppAttrList = pAttrList; pAttrList = NULL;

exit:

    if (NULL != pAttrList)
    {
        TRUSTEDGE_agentDeleteAttributeList(&pAttrList);
    }

    DIGI_FREE((void **) &pTemp);
    if (NULL != pJCtx)
    {
        JSON_releaseContext(&pJCtx);
    }
    DIGI_FREE((void **) &pData);

    return status;
}

/*----------------------------------------------------------------------------*/

#if !defined(__RTOS_ZEPHYR__)
static MSTATUS TRUSTEDGE_agentExecuteScript(
    sbyte *pPath,
    ubyte *pArg,
    sbyte **ppOutput)
{
    MSTATUS status;
    ubyte4 cmdSize;
    sbyte *pCmd = NULL;

    /* Path */
    cmdSize = DIGI_STRLEN(pPath);
    /* Space + Optional Argument */
    if (NULL != pArg)
    {
        cmdSize += 1 + DIGI_STRLEN(pArg);
    }
    /* NULL Terminator */
    cmdSize += 1;

    status = DIGI_CALLOC((void **) &pCmd, 1, cmdSize);
    if (OK != status)
    {
        goto exit;
    }

    DIGI_STRCAT(pCmd, pPath);
    if (NULL != pArg)
    {
        DIGI_STRCAT(pCmd, " ");
        DIGI_STRCAT(pCmd, pArg);
    }

    status = RTOS_processExecute(pCmd, ppOutput);
    MOC_UNUSED(ppOutput);

exit:

    if (NULL != pCmd)
    {
        DIGI_FREE((void **) &pCmd);
    }

    return status;
}
#endif /* !__RTOS_ZEPHYR__ */

/*----------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_agentProcessAttribute(
    TrustEdgeAgentCtx *pAgentCtx,
    sbyte *pName,
    AttributeItem *pAttrItem)
{
    MSTATUS status = OK;
    ubyte *pOutput = NULL;
    ubyte4 outputLen = 0;
    ubyte4 numTokens;
    JSON_ContextType *pJCtx = NULL;
    sbyte *pResult = NULL;

    if (ATTRIBUTE_TYPE_ENV == pAttrItem->type)
    {
        status = FMGMT_getEnvironmentVariableValueAlloc(
            pAttrItem->pEnv, (sbyte **) &pOutput);
        if (OK != status)
        {
            goto exit;
        }
        outputLen = DIGI_STRLEN(pOutput);
    }
    else if (ATTRIBUTE_TYPE_PROGRAM == pAttrItem->type)
    {
#if !defined(__RTOS_ZEPHYR__)
        status = TRUSTEDGE_agentExecuteScript(
            pAttrItem->pPath,
            pAttrItem->pArg,
            (sbyte **) &pOutput);
        if (OK != status)
        {
            goto exit;
        }
        outputLen = DIGI_STRLEN(pOutput);
#else
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
#endif
    }

    if (NULL != pOutput)
    {
        if (ATTRIBUTE_OUTPUT_JSON == pAttrItem->output)
        {
            status = JSON_acquireContext(&pJCtx);
            if (OK != status)
            {
                goto exit;
            }

            status = JSON_parse(pJCtx, pOutput, outputLen, &numTokens);
            if (OK != status)
            {
                goto exit;
            }

            status = JSON_getJsonStringValue(
                pJCtx, 0, pName, &pResult, TRUE);
            if (OK != status)
            {
                goto exit;
            }

            status = TRUSTEDGE_agentAddMetric(
                pAgentCtx,
                TE_METRICS_FILE,
                pName, DIGI_STRLEN(pName),
                pResult, DIGI_STRLEN(pResult));
            if (OK != status)
            {
                goto exit;
            }
        }
        else if (ATTRIBUTE_OUTPUT_STRING == pAttrItem->output)
        {
            status = TRUSTEDGE_agentAddMetric(
                pAgentCtx,
                TE_METRICS_FILE,
                pName, DIGI_STRLEN(pName),
                pOutput, outputLen);
            if (OK != status)
            {
                goto exit;
            }
        }
    }

exit:

    if (NULL != pResult)
    {
        DIGI_FREE((void **) &pResult);
    }

    if (NULL != pOutput)
    {
        DIGI_FREE((void **) &pOutput);
    }

    if (NULL != pJCtx)
    {
        JSON_releaseContext(&pJCtx);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS TRUSTEDGE_agentCustomerAttributes(
    TrustEdgeAgentCtx *pAgentCtx,
    sbyte *pAttributeFile)
{
    MSTATUS status;
    AttributeList *pAttrList = NULL;
    AttributeItem *pAttrItem = NULL;
    ubyte4 i, j;

    status = TRUSTEDGE_agentParseAttributes(
        pAgentCtx, pAttributeFile, &pAttrList);
    if (OK != status)
    {
        goto exit;
    }

    for (i = 0; i < pAttrList->itemCount; i++)
    {
       for (j = 0; j < pAttrList->pItems[i].nameCount; j++)
       {
            pAttrItem = &pAttrList->pItems[i];
            (void) TRUSTEDGE_agentProcessAttribute(pAgentCtx, pAttrList->pItems[i].ppNames[j], pAttrItem);
       }
    }

exit:

    if (NULL != pAttrList)
    {
        TRUSTEDGE_agentDeleteAttributeList(&pAttrList);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS TRUSTEDGE_agentInventoryAttributes(
    TrustEdgeAgentCtx *pAgentCtx,
    byteBoolean overwrite)
{
    MSTATUS status;
    ubyte4 i;
    intBoolean isPresent;
    ubyte *pVal = NULL;
    ubyte4 *pValLen = NULL;

    status = DIGI_MALLOC((void **) &pValLen, sizeof(*pValLen));
    if (OK != status)
    {
        goto exit;
    }

    for (i = 0; i < COUNTOF(gpDefaultAttributes); i++)
    {
        if (FALSE == overwrite)
        {
            status = TRUSTEDGE_agentIsMetricPresent(
            pAgentCtx,
            gpDefaultAttributes[i].pAttributeName,
            DIGI_STRLEN(gpDefaultAttributes[i].pAttributeName),
            &isPresent);
            if (OK != status)
            {
                goto exit;
            }
        }
        else
        {
            isPresent = FALSE;
        }

        if (FALSE == isPresent && NULL != gpDefaultAttributes[i].pHandler)
        {
            DIGI_FREE((void **) &pVal);
            status = gpDefaultAttributes[i].pHandler(&pVal, pValLen);
            if (OK == status && NULL != pVal)
            {
                status = TRUSTEDGE_agentAddMetric(
                    pAgentCtx,
                    TE_METRICS_FILE,
                    gpDefaultAttributes[i].pAttributeName,
                    DIGI_STRLEN(gpDefaultAttributes[i].pAttributeName),
                    pVal,
                    *pValLen);
                if (OK != status)
                {
                    goto exit;
                }
            }
        }
    }

    status = OK;

exit:

    DIGI_FREE((void **) &pVal);
    DIGI_FREE((void **) &pValLen);

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS TRUSTEDGE_agentReplaceWithAttribute(
    TrustEdgeAgentCtx *pAgentCtx,
    ubyte *pExpr,
    ubyte4 exprLen,
    ubyte **ppVal,
    ubyte4 *pValLen)
{
    MSTATUS status = OK;
    ubyte4 i, j, k;
    ubyte *pMetric = NULL;
    ubyte4 metricLen = 0;
    ubyte4 totalLen = exprLen;
    ubyte *pVal = NULL;

    *ppVal = NULL;
    *pValLen = 0;

    /* Requires at least 5 bytes for replacement -> ##<eval value>## */
    if (5 > exprLen)
    {
        goto exit;
    }

    /* Iterate through eval expression */
    for (i = 0; i < exprLen - 1; i++)
    {
        /* Check for starting ## */
        if (pExpr[i] == '#' && pExpr[i + 1] == '#')
        {
            for (j = i + 2; j < exprLen - 1; j++)
            {
                /* Find ending ## */
                if (pExpr[j] == '#' && pExpr[j + 1] == '#')
                {
                    status = TRUSTEDGE_agentGetMetric(
                        pAgentCtx, pExpr + i + 2, j - i - 2, &pMetric, &metricLen);
                    if (OK != status)
                        goto exit;

                    /* Couldn't find metric, just exit */
                    if (NULL == pMetric)
                    {
                        goto exit;
                    }

                    /* Adjust total length */
                    totalLen -= (j - i + 2);
                    totalLen += (metricLen - 1);
                    break;
                }
            }

            /* If we didn't find ending ## then keep i the same and continue
             * iterating through the string */
            if (j != exprLen - 1)
                i = j + 1;
        }
    }

    status = DIGI_MALLOC((void **) &pVal, totalLen);
    if (OK != status)
        goto exit;

    /* Same loop as above, but now we need to actually replace the values. k is
     * used as the index into the new evaluated value */
    k = 0;
    for (i = 0; i < exprLen - 1; i++)
    {
        if (pExpr[i] == '#' && pExpr[i + 1] == '#')
        {
            for (j = i + 2; j < exprLen - 1; j++)
            {
                if (pExpr[j] == '#' && pExpr[j + 1] == '#')
                {
                    status = TRUSTEDGE_agentGetMetric(
                        pAgentCtx, pExpr + i + 2, j - i - 2, &pMetric, &metricLen);
                    if (OK != status)
                        goto exit;

                    DIGI_MEMCPY(pVal + k, pMetric, (metricLen - 1));
                    k += (metricLen - 1);
                    break;
                }
            }

            if (j != exprLen - 1)
                i = j + 1;
            else
                pVal[k++] = pExpr[i]; /* End not found, copy # as is */
        }
        else
        {
            pVal[k++] = pExpr[i]; /* Copy value as is from original eval expression */
        }
    }
    /* Copy over last byte as needed */
    if (i < exprLen)
        pVal[k] = pExpr[i];

    *ppVal = pVal; pVal = NULL;
    *pValLen = totalLen;

exit:

    if (NULL != pVal)
    {
        DIGI_FREE((void **) &pVal);
    }

    return status;
}
