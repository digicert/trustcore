/*
 * missiu.c
 *
 * Mocana IPsec Stack In Userspace - main utility
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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/un.h>
#include <stdlib.h>

#define HELP_TEXT \
"Usage: missiu [options] <command>\n\n" \
"command can be one of the following:\n" \
"start        start missiu daemon\n" \
"stop         stop missiu daemon\n" \
"\n" \
"-h           Print this help text\n" \
"-i <iface>   Interface to operate on\n" \
"-l <file>    logfile for the missiu daemon\n"

#include "missiu.h"

int send_missiu_cmd(const char *iface, const struct missiu_tlv *tlv)
{

    int cmd_fd = -1, ret = 0;

    cmd_fd = MISSIU_findMissiu(iface);
    if(cmd_fd == -1)
    {
        ret = errno;
        goto done;
    }

    ret = sendto(cmd_fd, tlv, tlv->len, 0, NULL, 0);
    if (ret !=  tlv->len)
    {
        fprintf(stderr, "failed to send message to daemon\n");
        ret = errno;
        goto done;
    }

done:
    if (cmd_fd != -1)
        close(cmd_fd);

    return ret;
}

extern char *optarg;
extern int optind;

int main(int argc, char **argv)
{

    int opt, i, ret, lock;
    char *cmd, *iface = NULL, *logfile = NULL;
    char str[IFNAMSIZ + sizeof(CMDFIFO_FMT) + sizeof(RUN_DIR)];
    struct missiu_tlv *cmdbuf;

    while ((opt = getopt(argc, argv, "hi:l:")) != -1)
    {
        switch (opt)
        {
        case 'h':
            printf(HELP_TEXT);
            return 0;
            break;

        case 'i':
            iface = optarg;
            break;

        case 'l':
            logfile = optarg;
            break;

        default:
            fprintf(stderr, "Unknown option: %c\n", opt);
            return -1;
        }
    }

    if (optind >= argc)
    {
        fprintf(stderr, "Expected <command> after options.\n");
        return -1;
    }
    cmd = argv[optind];

    if (iface == NULL)
    {
        fprintf(stderr, "Cannot start missiu without an interface.\n");
        return -1;
    }

    if (0 == strcmp(cmd, "start"))
    {
        /* check the lock file */
        sprintf(str, PIDFILE_FMT, iface);
        chdir(RUN_DIR);
        lock = open(str, O_RDWR|O_CREAT, 0640);
        if (0 > lock)
        {
            return errno;
        }
        ret = lockf(lock, F_TEST, 0);
        if (-1 == ret && (errno == EACCES || errno == EAGAIN))
        {
            fprintf(stderr, "pid file is locked.  missiu already running?\n");
            return -1;
        }
        if (0 != ret)
        {
            perror("failed to check lock file");
            return errno;
        }

        /* looks good.  set everything up, then fork */
        ret = missiu_setup(iface);
        if (0 > ret)
        {
            fprintf(stderr, "Failed to launch missiu\n");
            return ret;
        }
        ret = fork();
        if (0 > ret)
        {
            perror("failed to fork missiu");
            return errno;
        }
        else if (ret > 0)
        {
            /* parent process. */
            printf("started missiu on interface %s\n", iface);
            return 0;
        }
        else
        {

            setsid();

            /* redirect stdin, out, and err */
            freopen("/dev/null", "r", stdin);
            if (logfile)
            {
                if (freopen(logfile, "w", stdout) == NULL)
                {
                    return errno;
                }
            }
            else
            {
                freopen("/dev/null", "w", stdout);
            }

            umask(027);

            ret = lockf(lock, F_TLOCK, 0);
            if (0 > ret)
            {
                return errno;
            }

            sprintf(str, "%d\n", getpid());
            ret = write(lock, str, strlen(str));
            if (0 > ret)
            {
                return errno;
            }

            signal(SIGCHLD, SIG_IGN);
            signal(SIGTSTP, SIG_IGN);
            signal(SIGTTOU, SIG_IGN);
            signal(SIGTTIN, SIG_IGN);
            signal(SIGHUP, missiu_signal);
            signal(SIGTERM, missiu_signal);

            return missiu_tap();
        }
    }
    else if(0 == strcmp(cmd, "stop"))
    {
        cmdbuf = (struct missiu_tlv *)malloc(sizeof(struct missiu_tlv));
        if (!cmdbuf)
        {
            fprintf(stderr, "failed to allocate command buffer\n");
            return -1;
        }
        cmdbuf->type = MISSIU_TAP_STOP;
        cmdbuf->len = sizeof(struct missiu_tlv);
        ret = send_missiu_cmd(iface, cmdbuf);
        free(cmdbuf);
        return ret;
    }
    else
    {
        fprintf(stderr, "Unimplemented command: %s\n", cmd);
    }

    return 0;
}
