/*
 * tpm2_test_utils.c
 *
 * This file contains common utility functions needed by TPM2 test and tools
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
 */

#include "../../../common/moptions.h"
#include "../../../common/mtypes.h"
#include "../../../common/merrors.h"
#include "../../../common/mstdlib.h"

#if defined(__RTOS_WIN32__)
#include <ShlObj.h>
#include <Shlwapi.h>
#endif /*  __RTOS_WIN32__ */

#include "tpm2_test_utils.h"


/*------------------------------------------------------------------*/

#ifdef __RTOS_WIN32__
/* Path relative to %PogramData% */
#define NANOTAP_APP_REL_PATH    "Mocana"
#endif


/*------------------------------------------------------------------*/


#if defined(__RTOS_WIN32__)
/*------------------------------------------------------------------*/
/*
* Function to retrieve Folder path for directory containing MOCANA files
* Caller should free memory allocated to ppMocAppPath usign DIGI_FREE
* This function does check for physical existence of MOCANA app path.
*
* MOCANA app path "%PROGRAMDATA%\Mocana" is expected 
* to be created as part of the deployment
* This function computes PATH of length lesser than MAX_FILE_PATH(256)
*/

static MSTATUS
getTapWinAppPath(ubyte **ppTapAppPath, ubyte4 *pTapAppPathLength)
{
    MSTATUS status = OK;
    HRESULT hr = S_OK;
    ubyte*  pAppPath = NULL;
    ubyte*  pAppMocDirName = NULL;
    ubyte*  pRetVal = NULL;

    if (NULL == ppTapAppPath || NULL == pTapAppPathLength)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_CALLOC(&pAppPath, MAX_PATH, sizeof(ubyte));
    if (OK != status)
    {
        goto exit;
    }

    /* Call windows shell function to retrieve program data location.
    Using the SHGetFolderPathA() version instead of SHGetFolderPath(), as incoming buffer ppMocAppPath is of type ubyte* */
    hr = SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, pAppPath);
    if (!SUCCEEDED(hr))
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }

    status = DIGI_CALLOC(ppTapAppPath, MAX_PATH, sizeof(ubyte));
    if (OK != status)
    {
        goto exit;
    }

    /* Combine path received from SHGetFolderPathA() with mocana directory */
    pRetVal = PathCombineA(*ppTapAppPath, pAppPath, NANOTAP_APP_REL_PATH);

    if (NULL == pRetVal || NULL == *ppTapAppPath)
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }

    *pTapAppPathLength = DIGI_STRLEN(*ppTapAppPath);

exit:

    DIGI_FREE(&pAppPath);
    DIGI_FREE(&pAppMocDirName);

    return status;
}

/********************************************************************/
/*
* Function to retrieve absolute file path of configuration files for windows.
* Caller is responsible to free memory allocated to 
* ppConfigFilePath using DIGI_FREE
* This function does NOT check for resulting file path's existence.
* This function computes PATH of length lesser than MAX_FILE_PATH(256)
*/

MOC_EXTERN MSTATUS
TPM2_TEST_UTILS_getTapWinConfigFilePath(ubyte **ppConfigFilePath, 
                                const ubyte *pConfigFileRelativePath)
{
    MSTATUS status = OK;
    ubyte*  pNanotapAppPath = NULL;
    ubyte4  pathLength = 0;

    if (NULL == ppConfigFilePath || NULL == pConfigFileRelativePath)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = getTapWinAppPath(&pNanotapAppPath, &pathLength);
    if (OK != status)
    {
        goto exit;
    }    

    status = DIGI_CALLOC(ppConfigFilePath, MAX_PATH, sizeof(ubyte));
    if (OK != status)
    {
        goto exit;
    }

    /* Combine path received from getTapWinAppPath with mocana directory */
    ubyte *pRetVal = PathCombineA(*ppConfigFilePath, 
                                    pNanotapAppPath, pConfigFileRelativePath);

    if (NULL == pRetVal || NULL == *ppConfigFilePath)
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }

exit:
    
    DIGI_FREE(&pNanotapAppPath);

    return status;
}

#endif /* __RTOS_WIN32__ */
