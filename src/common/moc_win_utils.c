/*
 * moc_win_utils.c
 *
 * Utilities used for windows platform
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

/*------------------------------------------------------------------*/

#ifdef __RTOS_WIN32__

#include <ShlObj.h>
#include <Shlwapi.h>

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"


/*------------------------------------------------------------------*/
/* Path relative to %PogramData% */
#define MOCANA_APPDATA_DIR_NAME    "Mocana"


/*------------------------------------------------------------------*/
/*
* Function to retrieve Folder path for directory containing MOCANA files
* Caller should free memory allocated to ppMocAppPath usign DIGI_FREE
* This function does not check for physical existence of MOCANA app path.
* MOCANA app path "%PROGRAMDATA%\Mocana" is expected
* to be created as part of the deployment
* This function computes PATH of length lesser than MAX_FILE_PATH(256)
*/

static MSTATUS
getWinAppDataPath(ubyte **ppTapAppPath, ubyte4 *pTapAppPathLength)
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
    pRetVal = PathCombineA(*ppTapAppPath, pAppPath, MOCANA_APPDATA_DIR_NAME);

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
* Function to retrieve absolute dir path of configuration files for windows.
* Configuration files are located inside '%ProgramData%\Mocana\',
* To retrieve a dir-path relateive to this location the pConfigDirName value
* has to be relative to this path,
*
* if pConfigDirName is empty then, the root Mocana dir is returned
* '%ProgramData%\Mocana\'
*
* Caller is responsible to free memory allocated to
* ppConfigFilePath using DIGI_FREE
*
* This function does NOT check for resulting file path's existence.
* This function computes PATH of length lesser than MAX_FILE_PATH(256)
*/

MOC_EXTERN MSTATUS
UTILS_getWinConfigDir(ubyte **ppConfigDirPath, const ubyte *pConfigDirName)
{
    MSTATUS status = OK;
    ubyte*  pNanotapAppPath = NULL;
    ubyte4  pathLength = 0;
    ubyte*  pRetVal  = NULL;

    if (NULL == ppConfigDirPath)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = getWinAppDataPath(&pNanotapAppPath, &pathLength);
    if (OK != status && NULL != pNanotapAppPath)
    {
        goto exit;
    }

    status = DIGI_CALLOC(ppConfigDirPath, MAX_PATH, sizeof(ubyte));
    if (OK != status)
    {
        goto exit;
    }

    /* Combine path received from getWinAppDataPath with mocana directory */
    pRetVal = PathCombineA(*ppConfigDirPath,
                                  pNanotapAppPath, pConfigDirName);
    if (NULL == pRetVal || NULL == *ppConfigDirPath)
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }

    pRetVal = PathAddBackslashA(*ppConfigDirPath);
    if (NULL == pRetVal)
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }

exit:
    DIGI_FREE(&pNanotapAppPath);
    return status;
}

/********************************************************************/
/*
* Function to retrieve absolute file path of configuration files for windows.
* Configuration files are located inside "%ProgramData%\Mocana\",
* hence pConfigFileRelativePath value has to be relative to this path
* Caller is responsible to free memory allocated to
* ppConfigFilePath using DIGI_FREE
* This function does NOT check for resulting file path's existence.
* This function computes PATH of length lesser than MAX_FILE_PATH(256)
*/

MOC_EXTERN MSTATUS
UTILS_getWinConfigFilePath(ubyte **ppConfigFilePath,
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

    status = getWinAppDataPath(&pNanotapAppPath, &pathLength);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_CALLOC(ppConfigFilePath, MAX_PATH, sizeof(ubyte));
    if (OK != status)
    {
        goto exit;
    }

    /* Combine path received from getWinAppDataPath with mocana directory */
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

