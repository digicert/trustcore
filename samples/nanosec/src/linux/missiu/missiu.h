/*
 * missiu.h
 *
 * Mocana IPsec Stack In Userspace - header
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

#ifndef __MISSIU_H__
#define __MISSIU_H__

#include "moptions.h"
#include "../gpl/nf_ipsec.h"

/* Directory in which the daemon runs */
#define RUN_DIR "/var/run/"

/* The %s is populated by the network interface name.  In order for missiu to
 * be detected by these strings using sscanf, the %s must be on th end.
 */
#define PIDFILE_FMT "missiu.pid.%s"
#define CMDFIFO_FMT "missiu.fifo.%s"

/* setup the missiu tap process */
int missiu_setup(char *iface);

/* launch the missiu tap interface */
int missiu_tap(void);

/* missiu signal handler */
void missiu_signal(int sig);

/* These are the command types for communicating with the missiu_tap process.
 * missiu_tap also accepts all of the existing ipsec driver IOCTLs, so we start
 * the new commands at the end of the existing IOCTLs.
 */
enum missiu_tap_cmd {
    /* stop the missiu_tap process.  To ensure that the process has stopped, you
     * can poll the pid file.  Expect it to vanish after the process has
     * terminated cleanly.
     */
    MISSIU_TAP_STOP = IOC_END,
};

/* commands sent to the missiu_tap process are of the form type-length-value */
struct missiu_tlv {
    enum missiu_tap_cmd type;
    unsigned int len; /* size of value PLUS sizeof(struct missiu_tlv) */
    char value[0];
};


/* IOCTLs take an generic 4-byte argument.  Depending on the IOCTL, this
 * argument may be a 4-byte value, or perhaps a pointer to a region of memory
 * with some sort of data structure.  The argument may be an argument to the
 * target (e.g., missiu), or perhaps a region of memory where the target is
 * supposed to write its return value.  To accomodate all of these
 * possibilities while avoiding copying the argument between processes, we use
 * shared memory IPC.  Programs wishing to perform the regular IOCTLs pass a
 * struct missiu_shmem as the value argument of the missiu_tlv.  This struct
 * contains the null-terminated name and the size of a shared memory segment in
 * which the argument to the ipsec_ioctl lives.
 */
#define SHMEM_TEMPLATE "/missiuXXXXXX"

struct missiu_shmem {
    char name[sizeof(SHMEM_TEMPLATE)];
    int size;
};

/* helper functions for communicating with missiu */
extern int MISSIU_findMissiu(const char *iface);
extern sbyte4 MISSIU_sendIoCtl(char *iface, struct missiu_tlv *cmdbuf);
extern void MISSIU_destroySharedMem(struct missiu_shmem *shmem, void **mem);
extern sbyte4 MISSIU_createSharedMem(struct missiu_shmem *shmem, void **mem);
extern sbyte4 MISSIU_prepareTLV(ubyte4 cmd, ubyte4 size, struct missiu_tlv **cmdbuf);
extern sbyte4 MISSIU_ioctlSimple(char *iface, ubyte4 cmd, ubyte4 value);

#endif/*  __MISSIU_H__ */
