/*
 * trustedge_agent_linux.c
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

/* trustedge_agent_linux.c
 *
 * linux specific functionality for update packages
 *
*/
#if defined(__RTOS_LINUX__) && !defined(__RTOS_ZEPHYR__)

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include "../../common/common_utils.h"
#include "../../trustedge/utils/trustedge_utils.h"
#include "../../trustedge/agent/trustedge_agent_priv.h"
#include "../../trustedge/agent/trustedge_agent_updatepolicy.h"

#define ARTIFACTS_DIR "artifacts"
#define TRUSTEDGE_UPDATE_SLEEP 60

#define TRUSTEDGE_UPDATE_ITSELF_ARTIFACT \
    "{\n" \
    "    \"artifactId\":\"%s\",\n" \
    "    \"policyId\":\"%s\",\n" \
    "    \"deploymentId\":\"%s\",\n" \
    "    \"mode\":\"%s\",\n" \
    "    \"status\":\"%s\",\n" \
    "    \"timestamp\":\"%s\"\n" \
    "}\n"

static char* DIGI_STRTOLWR(char* s) {
    sbyte4 len = strlen(s);
    sbyte4 i = 0;
    for (i = 0; i < len; ++i)
        if (s[i] >= 'A' && s[i] <= 'Z')
            s[i] += 'a' - 'A';
    return s;
}

static MSTATUS TRUSTEDGE_getCmdPath(sbyte *pCmd, sbyte **ppCmdPath)
{
    /* Resolve the executable by probing compile-time search directories with access(2) */
    static const sbyte * const searchPaths[] = {
        "/usr/bin/", "/bin/", "/usr/local/bin/", NULL
    };

    MSTATUS status = OK;
    sbyte *pCmdPath = NULL;
    int k;

    status = DIGI_MALLOC((void **) &pCmdPath, MAX_PATH_LENGTH);
    if (OK != status)
        return ERR_NULL_POINTER;

    for (k = 0; searchPaths[k] != NULL; k++)
    {
        if (snprintf(pCmdPath, MAX_PATH_LENGTH, "%s%s", searchPaths[k], pCmd) >= MAX_PATH_LENGTH)
            continue;
        if (0 == access(pCmdPath, X_OK))
        {
            *ppCmdPath = pCmdPath;
            return OK;
        }
    }

    status = ERR_TRUSTEDGE_AGENT;

    DIGI_FREE((void **) &pCmdPath);
    return status;
}

static MSTATUS TRUSTEDGE_agentCreateStatusFile(TrustEdgeAgentCtx *pCtx)
{
    MSTATUS status;
    sbyte *pArtifactDir = NULL;
    sbyte *pFilePath = NULL;
    sbyte *pTimestamp = NULL;
    sbyte *pStr = NULL;
    FileDescriptorInfo fdInfo = { 0 };
    sbyte4 len;

    MSG_LOG_print(MSG_LOG_INFO, "Conf dir: %s\n", pCtx->pConfig->pConfDir);
    MSG_LOG_print(MSG_LOG_INFO, "Artifact ID : %s\n", pCtx->curPolicy.data.ups.pArtifact->pId);
    MSG_LOG_print(MSG_LOG_INFO, "Policy ID : %s\n", pCtx->curPolicy.pPolicy->pId);
    MSG_LOG_print(MSG_LOG_INFO, "Deployment ID : %s\n", pCtx->curPolicy.pPolicy->pDeploymentId);

    status = COMMON_UTILS_addPathComponent(
        pCtx->pConfig->pConfDir, ARTIFACTS_DIR , &pArtifactDir);
    if (OK != status)
    {
        goto exit;
    }
    MSG_LOG_print(MSG_LOG_INFO, "Artifact dir: %s\n", pArtifactDir);
    if (FALSE == FMGMT_pathExists(pArtifactDir, &fdInfo))
    {
        status = FMGMT_mkdir(pArtifactDir, 0744);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
    else if (FTDirectory != fdInfo.type)
    {
        /* if not a directory delete it */
        status = FMGMT_remove(pArtifactDir, FALSE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));

            goto exit;
        }

        status = FMGMT_mkdir(pArtifactDir, 0744);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    status = COMMON_UTILS_addPathComponent(
        pArtifactDir, pCtx->curPolicy.data.ups.pArtifact->pId, &pFilePath);
    if (OK != status)
    {
        goto exit;
    }
    MSG_LOG_print(MSG_LOG_VERBOSE, "Artifact status file : %s\n", pFilePath);

    status = TRUSTEDGE_utilsGetTime(&pTimestamp, 0);
    if(OK != status)
    {
        goto exit;
    }
    MSG_LOG_print(MSG_LOG_VERBOSE, "timestamp: %s\n", pTimestamp);

    len = snprintf(NULL, 0, TRUSTEDGE_UPDATE_ITSELF_ARTIFACT,
        pCtx->curPolicy.data.ups.pArtifact->pId,
        pCtx->curPolicy.pPolicy->pId,
        pCtx->curPolicy.pPolicy->pDeploymentId,
        "install",
        "Pending",
        pTimestamp);
    if (len <= 0)
    {
        status = ERR_TRUSTEDGE_AGENT;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }
    status = DIGI_MALLOC((void **) &pStr, len + 1);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }
    len = snprintf(pStr, len + 1, TRUSTEDGE_UPDATE_ITSELF_ARTIFACT,
        pCtx->curPolicy.data.ups.pArtifact->pId,
        pCtx->curPolicy.pPolicy->pId,
        pCtx->curPolicy.pPolicy->pDeploymentId,
        "install",
        "Pending",
        pTimestamp);
    if (len <= 0)
    {
        status = ERR_TRUSTEDGE_AGENT;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = DIGICERT_writeFile(pFilePath, pStr, len);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:
    DIGI_FREE((void **) &pArtifactDir);
    DIGI_FREE((void **) &pFilePath);
    DIGI_FREE((void **) &pTimestamp);
    DIGI_FREE((void **) &pStr);
    return status;
}

/*  command format
 * /usr/bin/bash bash payload/script/install_trustedge.sh --dpkg payload/package/trustedge_44.9.711-131-linux.x86_64.deb
 * */

static MSTATUS TRUSTEDGE_actionHandlerIsTrustedgeUpdateArtifact(
    TrustEdgeArtifactAction *pAction,
    sbyte *pDir,
    TrustEdgeAgentCtx *pCtx,
    intBoolean *te_update)
{
    MSTATUS status = OK;
    sbyte **ppS;
    int pipeFd[2] = {-1, -1};
    pid_t child = -1;
    int childStatus = 0;
    ssize_t readRet = 0;
    size_t totalRead = 0;
    ssize_t n = 0;
    int readErr = 0;
    ubyte *pStr = NULL;
    ubyte *pOutput = NULL;
    ubyte *substr = " package: trustedge";
    ubyte *ptr = NULL;
    *te_update = FALSE;
    sbyte4 i = 0;
    sbyte4 j = 0;
    sbyte *pCmdPath = NULL;
    sbyte **ppActionArgs = NULL;
    sbyte4 arraySize;

    if (pAction->type == TE_ACTION_INSTALL
     && pAction->handler.type == TE_ACTION_HANDLER_SCRIPT
     && pAction->handler.subtype == TE_ACTION_HANDLER_SUBTYPE_BASH)
    {
        MSG_LOG_print(MSG_LOG_VERBOSE, "Action Type: %s Handler Type: %s Subtype: %s\n",
            TRUSTEDGE_actionTypeToString(pAction->type),
            TRUSTEDGE_actionHandlerTypeToString (pAction->handler.type),
            TRUSTEDGE_actionHandlerSubTypeToString (pAction->handler.subtype));
        MSG_LOG_print(MSG_LOG_VERBOSE, "Action Path: %s \n",pAction->pActionPath);

        ppS = pAction->ppActionArgs;
        while (NULL != ppS[i])
        {
            MSG_LOG_print(MSG_LOG_VERBOSE, "      Arg[%d]: %s\n", i, ppS[i]);
            if(0 == DIGI_STRCMP(ppS[i],"--dpkg"))
            {
                MSG_LOG_print(MSG_LOG_VERBOSE, "%s\n", "Got --dpkg option\n");
                if (NULL == ppS[i+1])
                {
                    return ERR_TRUSTEDGE_AGENT;
                }

                status = DIGI_MALLOC((void **) &pStr, MAX_PATH_LENGTH + 1);
                if (OK != status)
                {
                    return ERR_TRUSTEDGE_AGENT;
                }
                MSG_LOG_print(MSG_LOG_VERBOSE, "pDir: %s\n", pDir);
                MSG_LOG_print(MSG_LOG_VERBOSE, "ppS[%d]: %s\n", i+1, ppS[i+1]);

                {
                    sbyte4 pathLen = snprintf(pStr, MAX_PATH_LENGTH + 1, "%s/%s", pDir, ppS[i+1]);
                    if (pathLen < 0 || pathLen >= MAX_PATH_LENGTH + 1)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR, "%s\n", "Dpkg path truncated or snprintf failed");
                        status = ERR_TRUSTEDGE_AGENT;
                        goto exit;
                    }
                }
                MSG_LOG_print(MSG_LOG_VERBOSE, "dpkg file: %s\n", pStr);

                if (FALSE == FMGMT_pathExists(pStr, NULL))
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "Dpkg file %s does not exist.\n", pStr);
                    status = ERR_TRUSTEDGE_AGENT;
                    goto exit;
                }
                MSG_LOG_print(MSG_LOG_VERBOSE, "Dpkg file %s exist.\n", pStr);

                status = TRUSTEDGE_getCmdPath(TE_ACTION_COMMAND_DPKG, &pCmdPath);
                if(OK != status)
                {
                    goto exit;
                }
                MSG_LOG_print(MSG_LOG_VERBOSE, "Dpkg cmd path :%s.\n", pCmdPath);

                if (0 != pipe(pipeFd))
                {
                    status = ERR_TRUSTEDGE_AGENT;
                    goto exit;
                }
                child = fork();
                if (child < 0)
                {
                    status = ERR_TRUSTEDGE_AGENT;
                    goto exit;
                }
                if (0 == child)
                {
                    sbyte *dpkgArgs[4];
                    dpkgArgs[0] = pCmdPath;
                    dpkgArgs[1] = "-I";
                    dpkgArgs[2] = (sbyte *)pStr;
                    dpkgArgs[3] = NULL;
                    close(pipeFd[0]);
                    if (-1 == dup2(pipeFd[1], STDOUT_FILENO))
                    {
                        _exit(1);
                    }

                    close(pipeFd[1]);
                    execv(pCmdPath, (char * const *)dpkgArgs);
                    _exit(1);
                }

                close(pipeFd[1]);
                pipeFd[1] = -1;
                status = DIGI_MALLOC((void **) &pOutput, MAX_PATH_LENGTH + 1);
                if (OK != status)
                {
                    goto exit;
                }
                totalRead = 0;
                readErr = 0;
                while (totalRead < (size_t)MAX_PATH_LENGTH)
                {
                    n = read(pipeFd[0], pOutput + totalRead, (size_t)MAX_PATH_LENGTH - totalRead);
                    if (n < 0)
                    {
                        readErr = 1;
                        break;
                    }

                    if (0 == n)
                    {
                        break;
                    }

                    totalRead += (size_t)n;
                }

                readRet = readErr ? -1 : (ssize_t)totalRead;
                close(pipeFd[0]);
                pipeFd[0] = -1;
                waitpid(child, &childStatus, 0);
                child = -1;
                if (WIFEXITED(childStatus) && 0 != WEXITSTATUS(childStatus))
                    MSG_LOG_print(MSG_LOG_ERROR, "dpkg -I exited with status: %d\n", WEXITSTATUS(childStatus));
                if (0 >= readRet)
                {
                    status = ERR_TRUSTEDGE_AGENT;
                    goto exit;
                }
                pOutput[readRet] = '\0';

                DIGI_STRTOLWR(pOutput);
                ptr = strstr(pOutput, substr);
                if(ptr)
                {
                    MSG_LOG_print(MSG_LOG_VERBOSE, "found %s\n", substr);
                    *te_update = TRUE;
                }
            }
            i++;
        }
        /* --artftId <artifactID>*/
        if(*te_update == TRUE)
        {
            arraySize = i + 5;
            status = DIGI_MALLOC((void **) &ppActionArgs, sizeof(*ppActionArgs)*(arraySize));
            if (OK != status)
                goto exit;
            for(j = 0; j < i; j++)
            {
                ppActionArgs[j] = ppS[j];
                MSG_LOG_print(MSG_LOG_VERBOSE, "ppActionArgs[%d]: %s\n", j, ppActionArgs[j]);
            }
            ppActionArgs[j++] = TRUSTEDGE_utilsCloneString("--aId");
            ppActionArgs[j++] = TRUSTEDGE_utilsCloneString( pCtx->curPolicy.data.ups.pArtifact->pId);
            ppActionArgs[j++] = TRUSTEDGE_utilsCloneString("--service");
            if (TRUE == pCtx->service)
                ppActionArgs[j++] = TRUSTEDGE_utilsCloneString("TRUE");
            else
                ppActionArgs[j++] = TRUSTEDGE_utilsCloneString("FALSE");
            ppActionArgs[j++] = NULL;

            DIGI_FREE((void **) &pAction->ppActionArgs);
            pAction->ppActionArgs = ppActionArgs;

            MSG_LOG_print(MSG_LOG_VERBOSE, "%s:\n", "Printing modified array");
            j = 0;
            while(pAction->ppActionArgs[j])
            {
                MSG_LOG_print(MSG_LOG_VERBOSE, "pAction->ppActionArgs[%d]: %s\n", j, pAction->ppActionArgs[j]);
                j++;
            }
	        ppActionArgs = NULL;
            MSG_LOG_print(MSG_LOG_VERBOSE, "%s:\n", "Array modified successfully\n");
        }
    }

exit:
    if (pipeFd[0] >= 0) close(pipeFd[0]);
    if (pipeFd[1] >= 0) close(pipeFd[1]);
    if (child > 0) waitpid(child, NULL, 0);
    DIGI_FREE((void **) &pCmdPath);
    DIGI_FREE((void **) &pStr);
    DIGI_FREE((void **) &pOutput);
    return status;
}

/* TODO: Test this function for RPM as Pkg Manager on RPM based Distro */
static void TRUSTEDGE_actionHandlerLinux(
    TrustEdgeArtifactAction *pAction,
    sbyte *pArtifactDir)
{
    MSTATUS status;
    struct stat fileStat;

    MSG_LOG_print(MSG_LOG_VERBOSE, "%s : %s\n", "--- Entered Action Handler  --- ", __func__);
    status = FMGMT_changeCWD(pArtifactDir);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_VERBOSE, "Could not change directory to : %s\n", pArtifactDir);
        goto exit;
    }


    MSG_LOG_print(MSG_LOG_DEBUG, "Action Type: %s Handler Type: %s Subtype: %s\n",
        TRUSTEDGE_actionTypeToString(pAction->type),
        TRUSTEDGE_actionHandlerTypeToString (pAction->handler.type),
        TRUSTEDGE_actionHandlerSubTypeToString (pAction->handler.subtype));
    MSG_LOG_print(MSG_LOG_DEBUG, "Action Path: %s \n",pAction->pActionPath);

    /* Validate the action Path, type and handler to be valid values
     * Argument can be NULL in some cases so we wont enforce that */
    if((TE_ACTION_INSTALL == pAction->type && NULL == pAction->pActionPath) || TE_ACTION_UNKNOWN == pAction->type ||
        TE_ACTION_HANDLER_UNKNOWN == pAction->handler.type ||
        (TE_ACTION_HANDLER_EXE != pAction->handler.type && TE_ACTION_HANDLER_SUBTYPE_UNKNOWN == pAction->handler.subtype))
    {
        MSG_LOG_print(MSG_LOG_ERROR,"%s", "action validation failed! Handler returning failure \n");
        status = ERR_TRUSTEDGE_AGENT;
        goto exit;
    }

    if(pAction->pActionArgument != NULL)
    {
        MSG_LOG_print(MSG_LOG_DEBUG, "Action Argument: %s\n", pAction->pActionArgument);
    }

    MSG_LOG_print(MSG_LOG_DEBUG, "Handler Type: %s Subtype: %s\n",
        TRUSTEDGE_actionHandlerTypeToString(pAction->handler.type),
        TRUSTEDGE_actionHandlerSubTypeToString(pAction->handler.subtype));

    if (TE_ACTION_HANDLER_SCRIPT == pAction->handler.type ||
        TE_ACTION_HANDLER_EXE    == pAction->handler.type)
    {
        int actionFd = open(pAction->pActionPath, O_RDONLY | O_NOFOLLOW);
        if (0 > actionFd)
        {
            status = ERR_TRUSTEDGE_AGENT;
            goto exit;
        }

        if (0 > fstat(actionFd, &fileStat))
        {
            status = ERR_TRUSTEDGE_AGENT;
            close(actionFd);
            goto exit;
        }

        if (0 > fchmod(actionFd, fileStat.st_mode | S_IXUSR | S_IXGRP))
        {
            status = ERR_TRUSTEDGE_AGENT;
            close(actionFd);
            goto exit;
        }

        close(actionFd);
    }

    execv(pAction->ppActionArgs[0], (char * const *)(1 + pAction->ppActionArgs));
    exit(-1);

exit:
    exit(status);
}

extern MSTATUS TRUSTEDGE_launchActionHandlerLinux(
    TrustEdgeArtifactAction *pAction,
    sbyte *pFile,
    TrustEdgeAgentCtx *pCtx
)
{
    MSTATUS status = ERR_TRUSTEDGE_AGENT_ACTION_FAILED;
    sbyte4 pid;
    sbyte4 pidStatus;
    sbyte4 pidChild;
    sbyte4 childRetStatus;
    time_t startTime;
    intBoolean isTEUpdateArtifact = FALSE;
    sbyte4 timeout;

    if (NULL == pAction || NULL == pCtx)
    {
        goto exit;
    }

    timeout = pCtx->actionHandlerTimeout;

    status = TRUSTEDGE_actionHandlerIsTrustedgeUpdateArtifact(pAction, pFile, pCtx, &isTEUpdateArtifact);
    if(OK != status)
    {
        status = ERR_TRUSTEDGE_AGENT;
        goto exit;
    }

    pid = fork();
    if (0 > pid)
    {
        goto exit;
    }

    if (0 == pid)
    {
        if(isTEUpdateArtifact)
            RTOS_sleepMS(TRUSTEDGE_UPDATE_SLEEP*1000);

        /* child process: TRUSTEDGE_actionHandlerLinux will not return */
        TRUSTEDGE_actionHandlerLinux(pAction, pFile);
    }
    else
    {
        if (isTEUpdateArtifact)
        {
            pCtx->curPolicy.data.ups.pArtifact->isAsync = TRUE;
            /*create json status file with status as Pending */
            MSG_LOG_print(MSG_LOG_VERBOSE,"%s", "TRUSTEDGE agent is updating itself\n");
            status = TRUSTEDGE_agentCreateStatusFile(pCtx);
            goto exit;
        }
        /* this is parent process, wait for child process to complete */
        startTime = time(NULL);
        do {
            pidChild = waitpid(pid, &pidStatus, WNOHANG);
            if (0 == pidChild && (time(NULL) - startTime >= timeout))
            {
                kill(pid, SIGKILL);
                waitpid(pid, &pidStatus, 0);
                status = ERR_TRUSTEDGE_AGENT_ACTION_TIMEOUT;
                goto exit;
            }
            RTOS_sleepMS(1); /* TODO: this be configurable */
        } while (0 == pidChild);

        if (0 <= pidChild)
        {
            if (WIFEXITED(pidStatus))
            {
                childRetStatus = WEXITSTATUS(pidStatus);
                if (0 == childRetStatus)
                {
                    MSG_LOG_print(MSG_LOG_VERBOSE,"%s", "action exited successfully\n");
                    status = OK;
                }
                else
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "action exited with status: %d\n", childRetStatus);
                    status = ERR_TRUSTEDGE_AGENT_ACTION_FAILED;
                }
            }
            else
            {
                MSG_LOG_print(MSG_LOG_ERROR, "%s", "action exited abnormally\n");
                status = ERR_TRUSTEDGE_AGENT_ACTION_FAILED;
            }
        }
        else
        {
            MSG_LOG_print(MSG_LOG_ERROR, "%s", "action failed\n");
            status = ERR_TRUSTEDGE_AGENT_ACTION_FAILED;
        }
    }
exit:

    return status;
}

/* if pActionArgument points to a string in read-only memory, strtok will cause a seg. fault
 * this is because strtok modifies the first argument */
extern sbyte** TRUSTEDGE_actionHandlerGenerateArgsLinux(TrustEdgeArtifactAction *pAction)
{
    MSTATUS status;
    sbyte **pStr = NULL;
    sbyte4 i = 0, size;
    intBoolean foundWord = FALSE;
    sbyte4 argCount = 0;
    sbyte *token;
    sbyte *pArgs;
    sbyte *pCmdPath = NULL;
    sbyte *pCmd = NULL;
    sbyte4 arraySize;

    MSG_LOG_print(MSG_LOG_VERBOSE, "%s", "Entered TRUSTEDGE_actionHandlerGenerateArgsLinux\n");

    pArgs = pAction->pActionArgument;
    size = DIGI_STRLEN(pArgs);

    while (i < size)
    {
        if (' ' != pArgs[i])
        {
            if (FALSE == foundWord)
            {
                argCount++;
                foundWord = TRUE;
            }
        }
        else
        {
            foundWord = FALSE;
        }

        i++;
    }

    switch (pAction->handler.subtype)
    {
        case TE_ACTION_HANDLER_SUBTYPE_BASH:
            pCmd = TRUSTEDGE_utilsCloneString(TE_ACTION_COMMAND_BASH);
            break;
        case TE_ACTION_HANDLER_SUBTYPE_PYTHON3:
            pCmd = TRUSTEDGE_utilsCloneString(TE_ACTION_COMMAND_PYTHON3);
            break;
        case TE_ACTION_HANDLER_SUBTYPE_DPKG:
            pCmd = TRUSTEDGE_utilsCloneString(TE_ACTION_COMMAND_DPKG);
            break;
        case TE_ACTION_HANDLER_SUBTYPE_RPM:
            pCmd = TRUSTEDGE_utilsCloneString(TE_ACTION_COMMAND_RPM);
            break;
        case TE_ACTION_HANDLER_SUBTYPE_NODEJS:
            pCmd = TRUSTEDGE_utilsCloneString(TE_ACTION_COMMAND_NODEJS);
            break;
        case TE_ACTION_HANDLER_SUBTYPE_UNKNOWN:
            if (TE_ACTION_HANDLER_EXE != pAction->handler.type)
            {
                status = ERR_TRUSTEDGE_AGENT;
                goto exit;
            }
            pCmd = NULL;
            break;
        default:
            status = ERR_TRUSTEDGE_AGENT;
            goto exit;
    }

    if (TE_ACTION_HANDLER_EXE != pAction->handler.type)
    {
        status = TRUSTEDGE_getCmdPath(pCmd, &pCmdPath);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = DIGI_MALLOC((void **) &pCmdPath, MAX_PATH_LENGTH);
        if (OK != status)
            goto exit;
    }

    /* build command */
    if (TE_ACTION_HANDLER_SCRIPT == pAction->handler.type)
    {
        arraySize = argCount + 4;
        status = DIGI_MALLOC((void **) &pStr, sizeof(*pStr)*(arraySize));
        if (OK != status)
            goto exit;

        pStr [0] = pCmdPath; pCmdPath = NULL;
        pStr [1] = pCmd; pCmd = NULL;
        pStr [2] = TRUSTEDGE_utilsCloneString(pAction->pActionPath);
        pStr[arraySize - 1] = NULL;

        if (0 < argCount)
        {
            i = 3;
            token = strtok(pArgs, " ");
            while (NULL != token)
            {
                pStr[i] = TRUSTEDGE_utilsCloneString(token);
                i++;
                token = strtok(NULL, " ");
            }
        }
        pAction->ppActionArgs = pStr;
    }
    else if (TE_ACTION_HANDLER_PKG_MGR_TYPE == pAction->handler.type)
    {
        switch (pAction->handler.subtype)
        {
            case TE_ACTION_HANDLER_SUBTYPE_RPM:
            case TE_ACTION_HANDLER_SUBTYPE_DPKG:
                break;
            default:
                MSG_LOG_print(MSG_LOG_ERROR, "package manager subtype %s not supported\n",
                    TRUSTEDGE_actionHandlerSubTypeToString (pAction->handler.subtype));
                status = ERR_TRUSTEDGE_AGENT;
                goto exit;
        };

        switch (pAction->type)
        {
            case TE_ACTION_INSTALL:
                arraySize = argCount + 5;
                break;
            case TE_ACTION_ROLLBACK:
                if (0 == argCount)
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "action type %s for handler type %s requires package name\n",
                        TRUSTEDGE_actionTypeToString(pAction->type),
                        TRUSTEDGE_actionHandlerTypeToString(pAction->handler.type));
                    status = ERR_TRUSTEDGE_AGENT;
                    goto exit;
                }

                arraySize = 5;
                break;
            default:
                status = ERR_TRUSTEDGE_AGENT;
                MSG_LOG_print(MSG_LOG_ERROR, "action type %s not supported\n",
                    TRUSTEDGE_actionTypeToString(pAction->type));
                goto exit;
        }

        status = DIGI_MALLOC((void **) &pStr, sizeof(*pStr)*(arraySize));
        if (OK != status)
            return NULL;

        pStr [0] = pCmdPath; pCmdPath = NULL;
        pStr [1] = pCmd; pCmd = NULL;
        pStr[arraySize - 1] = NULL;
        i = 2;

        switch (pAction->type)
        {
            case TE_ACTION_INSTALL:
            {
                if (0 < argCount)
                {
                    token = strtok(pArgs, " ");
                    while (NULL != token)
                    {
                        pStr[i] = TRUSTEDGE_utilsCloneString(token);
                        i++;
                        token = strtok(NULL, " ");
                    }
                }

                pStr[i] = TRUSTEDGE_utilsCloneString("-i");
                i++;
                pStr[i] = TRUSTEDGE_utilsCloneString(pAction->pActionPath);
                break;
            }
            case TE_ACTION_ROLLBACK:
            {
                if (TE_ACTION_HANDLER_SUBTYPE_DPKG == pAction->handler.subtype)
                    pStr[i] = TRUSTEDGE_utilsCloneString("-r");
                else if (TE_ACTION_HANDLER_SUBTYPE_RPM == pAction->handler.subtype)
                    pStr[i] = TRUSTEDGE_utilsCloneString("-e");
                i++;

                /* rollback mode only supports a single argument
                 * consisting of the package name */
                token = strtok(pArgs, " ");
                if (NULL != token)
                {
                    pStr[i] = TRUSTEDGE_utilsCloneString(token);
                }
                break;
            }
            case TE_ACTION_PREINSTALL:
            case TE_ACTION_POSTINSTALL:
            case TE_ACTION_UNKNOWN:
                status = ERR_TRUSTEDGE_AGENT;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
        }
        pAction->ppActionArgs = pStr;
    }
    else if (TE_ACTION_HANDLER_EXE == pAction->handler.type)
    {

        size = DIGI_STRLEN(pAction->pActionPath);
        if (0 == size)
        {
            status = ERR_TRUSTEDGE_AGENT;
            goto exit;
        }

        i = size - 1;
        while (0 <= i)
        {
            if ('/' == pAction->pActionPath[i])
            {
                i++;
                break;
            }

            i--;
        }

        status = DIGI_MEMCPY(pCmdPath, pAction->pActionPath+i, size - i);
        if (OK != status)
            goto exit;

        pCmdPath[size - i] = '\0';

        arraySize = argCount + 3;
        status = DIGI_MALLOC((void **) &pStr, sizeof(*pStr)*(arraySize));
        if (OK != status)
            goto exit;

        pStr [0] = TRUSTEDGE_utilsCloneString(pAction->pActionPath);
        pStr [1] = pCmdPath; pCmdPath = NULL;
        pStr[arraySize - 1] = NULL;

        if (0 < argCount)
        {
            i = 2;
            token = strtok(pArgs, " ");
            while (NULL != token)
            {
                pStr[i] = TRUSTEDGE_utilsCloneString(token);
                i++;
                token = strtok(NULL, " ");
            }
        }
        pAction->ppActionArgs = pStr;
    }

#if 0
    MSG_LOG_print(MSG_LOG_DEBUG, "%s", "cmd arguments:\n");
    for(i = 0; i < arraySize; i++)
    {
        MSG_LOG_print(MSG_LOG_DEBUG, "  %d: %s\n", i, pStr[i]);
    }
#endif

exit:

    MSG_LOG_print(MSG_LOG_VERBOSE, "%s", "Exiting TRUSTEDGE_actionHandlerGenerateArgsLinux\n");

    DIGI_FREE((void **) &pCmdPath);
    DIGI_FREE((void **) &pCmd);

    if (OK != status)
        return NULL;
    return pStr;
}

void TRUSTEDGE_actionHandlerDeleteArgsLinux (TrustEdgeArtifactAction *pAction)
{
    sbyte **ppS;
    sbyte4 i;
    if (NULL == pAction || NULL == pAction->ppActionArgs)
        return;

    MSG_LOG_print(MSG_LOG_VERBOSE, "%s", "Entered TRUSTEDGE_actionHandlerDeleteArgsLinux\n");
    ppS = pAction->ppActionArgs;
    i = 0;
    while (NULL != ppS[i]) {
        MSG_LOG_print(MSG_LOG_DEBUG, "    %s\n", ppS[i]);
        DIGI_FREE((void **) &ppS[i++]);
    }

    DIGI_FREE((void **) &(pAction->ppActionArgs));
    MSG_LOG_print(MSG_LOG_VERBOSE, "%s", "Exiting TRUSTEDGE_actionHandlerDeleteArgsLinux\n");
}

#endif /* __RTOS_LINUX__ */
