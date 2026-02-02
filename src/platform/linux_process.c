#include "../common/moptions.h"

#if defined(__LINUX_RTOS__) && !defined(__RTOS_ZEPHYR__)
#if defined(__ENABLE_DIGICERT_RTOS_PROCESS__)

#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mfmgmt.h"

#define INITIAL_BUFFER_SIZE 1024
#define MAX_ARGS 256

extern MSTATUS LINUX_processExecute(
    sbyte *pCmd,
    sbyte **ppOutput)
{
    MSTATUS status;
    sbyte pBuffer[INITIAL_BUFFER_SIZE];
    ubyte4 bufferLen = 0;
    FILE *pPipe = NULL;
    sbyte *pTmp = NULL;
    sbyte *pOutput = NULL;
    ubyte4 outputLen = 0;

    if (NULL == pCmd || NULL == ppOutput)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pPipe = popen(pCmd, "r");
    if (NULL == pPipe)
    {
        status = ERR_FILE_INVALID_DESCRIPTOR;
        goto exit;
    }

    while (FMGMT_fgets(pBuffer, INITIAL_BUFFER_SIZE, pPipe) != NULL)
    {
        bufferLen = DIGI_STRLEN(pBuffer);

        status = DIGI_MALLOC((void **) &pTmp, outputLen + bufferLen + 1);
        if (OK != status)
        {
            goto exit;
        }

        DIGI_MEMCPY(pTmp, pOutput, outputLen);
        DIGI_MEMCPY(pTmp + outputLen, pBuffer, bufferLen);

        DIGI_FREE((void **) &pOutput);
        pOutput = pTmp; pTmp = NULL;
        outputLen += bufferLen;
    }

    if (outputLen > 0)
        pOutput[outputLen] = '\0';

    *ppOutput = pOutput; pOutput = NULL;

exit:

    if (NULL != pOutput)
    {
        DIGI_FREE((void **) &pOutput);
    }

    if (NULL != pTmp)
    {
        DIGI_FREE((void **) &pTmp);
    }

    if (NULL != pPipe)
    {
        pclose(pPipe);
    }

    return status;
}

extern MSTATUS LINUX_processExecuteWithArg(
    sbyte *pPath,
    sbyte *pArg,
    sbyte **ppOutput)
{
    MSTATUS status = OK;
    sbyte pBuffer[INITIAL_BUFFER_SIZE];
    ubyte4 bufferLen = 0;
    sbyte *pTmp = NULL;
    sbyte *pOutput = NULL;
    ubyte4 outputLen = 0;
    int pipefd[2];
    pid_t pid;
    FILE *pReadStream = NULL;
    int childStatus;
    sbyte *argv[MAX_ARGS];
    ubyte4 argc = 0;

    if (NULL == pPath || NULL == ppOutput)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Build argument array */
    argv[argc++] = pPath;
    if (NULL != pArg && DIGI_STRLEN(pArg) > 0)
    {
        argv[argc++] = pArg;
    }
    argv[argc] = NULL;

    /* Create pipe for reading child process output */
    if (pipe(pipefd) == -1)
    {
        status = ERR_FILE_INVALID_DESCRIPTOR;
        goto exit;
    }

    /* Fork child process */
    pid = fork();
    if (pid == -1)
    {
        close(pipefd[0]);
        close(pipefd[1]);
        status = ERR_RTOS_PROCESS_CREATE;
        goto exit;
    }

    if (pid == 0)
    {
        /* Child process */
        close(pipefd[0]); /* Close read end */
        
        /* Redirect stdout and stderr to pipe */
        if (dup2(pipefd[1], STDOUT_FILENO) == -1 ||
            dup2(pipefd[1], STDERR_FILENO) == -1)
        {
            close(pipefd[1]);
            _exit(127);
        }
        
        close(pipefd[1]);
        
        execv((const char *)argv[0], (char *const *)argv);
        
        /* If execv returns, it failed - write error to stderr (goes to pipe) */
        perror("execv failed");
        _exit(127);
    }
    else
    {
        /* Parent process */
        close(pipefd[1]); /* Close write end */
        
        /* Open read end as FILE stream */
        pReadStream = fdopen(pipefd[0], "r");
        if (NULL == pReadStream)
        {
            close(pipefd[0]);
            waitpid(pid, NULL, 0); /* Reap child */
            status = ERR_FILE_INVALID_DESCRIPTOR;
            goto exit;
        }
        
        /* Read output from child process */
        while (FMGMT_fgets(pBuffer, INITIAL_BUFFER_SIZE, pReadStream) != NULL)
        {
            bufferLen = DIGI_STRLEN(pBuffer);
            
            status = DIGI_MALLOC((void **) &pTmp, outputLen + bufferLen + 1);
            if (OK != status)
            {
                fclose(pReadStream);
                waitpid(pid, NULL, 0); /* Reap child */
                goto exit;
            }
            
            if (pOutput != NULL)
            {
                DIGI_MEMCPY(pTmp, pOutput, outputLen);
            }
            DIGI_MEMCPY(pTmp + outputLen, pBuffer, bufferLen);
            
            DIGI_FREE((void **) &pOutput);
            pOutput = pTmp; pTmp = NULL;
            outputLen += bufferLen;
        }
        
        fclose(pReadStream); /* This also closes pipefd[0] */
        pReadStream = NULL;
        
        /* Wait for child process to complete */
        if (waitpid(pid, &childStatus, 0) == -1)
        {
            status = ERR_RTOS_PROCESS_WAIT;
            goto exit;
        }
        
        /* Check if child exited normally */
        if (!WIFEXITED(childStatus) || WEXITSTATUS(childStatus) != 0)
        {
            /* Child process failed - still return output but log error */
            if (WIFEXITED(childStatus))
            {
                /* Child exited with non-zero status */
                status = ERR_RTOS_PROCESS_FAILED;
            }
            else
            {
                /* Child was terminated by signal */
                status = ERR_RTOS_PROCESS_TERMINATED;
            }
        }
    }

    if (outputLen > 0)
        pOutput[outputLen] = '\0';

    *ppOutput = pOutput; pOutput = NULL;

exit:

    if (NULL != pOutput)
    {
        DIGI_FREE((void **) &pOutput);
    }

    if (NULL != pTmp)
    {
        DIGI_FREE((void **) &pTmp);
    }

    if (NULL != pReadStream)
    {
        fclose(pReadStream);
    }

    return status;
}

#endif /* __ENABLE_DIGICERT_RTOS_PROCESS__ */
#endif /* __LINUX_RTOS__ */
