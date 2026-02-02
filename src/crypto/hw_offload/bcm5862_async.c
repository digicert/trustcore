/*
 * bcm5862_async.c
 *
 * Broadcom 5862 Hardware Acceleration Asynchronous Adapter
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

/*------------------------------------------------------------------*/

#include "../../common/moptions.h"

#if (defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) && defined(__ENABLE_BROADCOM_5862_HARDWARE_ACCEL__))

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../common/merrors.h"
#include "../../crypto/hw_accel.h"
#include "../../common/mdefs.h"
#include "../../common/mrtos.h"
#include "../../common/mtcp.h"
#include "../../common/mstdlib.h"
#include "../../common/random.h"
#include "../../common/vlong.h"
#include "../../common/debug_console.h"
#include "../../crypto/crypto.h"
#include "../../crypto/md5.h"
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../crypto/rsa.h"
#include "../../crypto/des.h"
#include "../../crypto/three_des.h"
#include "../../crypto/rc4algo.h"
#include "../../crypto/aes.h"
#include "../../crypto/nil.h"
#include "../../crypto/hmac.h"
#include "../../crypto/dh.h"

#include "../../harness/harness.h"
#include "../../harness/harness_intf.h"
#include "../../harness/harness_drv.h"
#include "../../crypto/hw_offload/bcm5862.h"
#include "../../harness/harness.h"
#include "../../harness/harness_drv.h"

#ifdef __KERNEL__
#include <linux/kernel.h>
#include <asm/delay.h>
#include <asm/page.h>
#include <asm/string.h>
#else
#include <stdio.h>
#include <time.h>
#endif

#define VLONG_BYTE_SIZE(a) ((a)->numUnitsUsed << 2)

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
  #define DUMP_VLONGS(a,b,c)    dump_vlongs(a,b,c)

static void
/*************************************************************
 *    Function: dump_vlongs
 * Description: .
 *************************************************************/
dump_vlongs(const vlong *input, int limit, char *title)
{
    ubyte  *obuf = NULL;
    sbyte4 olen;
    char   tbuf[80];

    olen = VLONG_BYTE_SIZE(input) + 4;
    obuf = (ubyte *)MALLOC(olen);
    if (NULL != obuf) {
        sprintf(tbuf, "len:%04d - ", VLONG_bitLength(input));
        if (title) {
            strncat (tbuf, title, sizeof(tbuf)-20);
        }
        VLONG_byteStringFromVlong(input, obuf, &olen);
        DEBUG_CONSOLE_dump_data(obuf, olen, limit, 4, tbuf);
    }
    if (NULL != obuf) {
        FREE(obuf);
        obuf = NULL;
    }
}

#else
  #define DUMP_VLONGS(a,b,c)
#endif

extern int HARNESS_INTF26_ioCtl(hwAccelDescr hwAccelCtx, int, int);

typedef struct {
    ubyte hnSending;                    /* Set to send cmd to kernel */
    ubyte totalSent[4];                 /* Total sent per mcr */
} AsyncCtl_t;

static AsyncCtl_t asyncCtl = {
    .hnSending = 1
};

static int kalloc_size = 0;

typedef struct {
   ubyte4 size;
   ubyte4 reserved;
   ubyte  data[0];
} MemDb_t;

void *
/*************************************************************
 *    Function: HDOS_kernelAlloc
 * Description: .
 *  hwAccelCtx:
 *        size:
 *************************************************************/
HDOS_kernelAlloc (hwAccelDescr hwAccelCtx, int size)
{
    MemDb_t *result = NULL;

    if (OK > HARNESS_kernelAlloc(hwAccelCtx, sizeof(MemDb_t) + size,
                                 TRUE, (void **)&result)) {
        return NULL;
    }
    kalloc_size += size;
    result->size = size;
    DBUG_PRINT(DEBUG_HARNESS, ("Total allocation: %d [+%d]", kalloc_size, size));
    return result->data;
}

void
HDOS_kernelFree (hwAccelDescr hwAccelCtx, void *data)
{
    MemDb_t *memDb;
    int     size;

    if (!data)
        return;

    memDb = (MemDb_t *)((char *)data - sizeof(MemDb_t));
    size  = memDb->size;
    if (OK > HARNESS_kernelFree(hwAccelCtx, TRUE, (void **)&memDb)) {
        ERROR_PRINT(("Error freeing data %x", (int)data));
        return;
    }
    kalloc_size -= size;
    DBUG_PRINT(DEBUG_HARNESS, ("Total allocation: %d [-%d]", kalloc_size, size));
}

PhysAddr_t
/*************************************************************
 *    Function: HDOS_user2phy
 * Description: .
 *       kaddr:
 *************************************************************/
HDOS_user2phy(hwAccelDescr hwAccelCtx, void * kaddr)
{
    void *phyAddr;

#ifdef  __KERNEL__
    return (PhysAddr_t)__pa(kaddr);
#else
    if (OK == HARNESS_mapAllocToPhysical(hwAccelCtx, kaddr, &phyAddr)) {
        return phyAddr;
    }
#endif
    ERROR_PRINT(("Cannot map %x to phy address", (int)kaddr));
    return NULL;
}

static void cmdDelete(Command_t *pCmd);

static Command_t *
/*************************************************************
 *    Function: cmdCreate
 * Description: .
 *  hwAccelCtx:
 *  numPackets:
 *   mcrNumber: 0 based
 *************************************************************/
cmdCreate(hwAccelDescr hwAccelCtx, ubyte4 numPackets, ubyte mcrNumber)
{
    ubyte4       i, blockSize, offset;
    Command_t*   pCmd;
    ubyte*       block = NULL;
    PktDescr2_t* pktDescr;

    blockSize = sizeof(*pCmd) +
        (sizeof(pCmd->subCmd[0]) * numPackets) +
        sizeof(ubyte4) +                /* For mcr header */
        (sizeof(pCmd->subCmd->pktDescr[0]) * (numPackets));

    block = HDOS_kernelAlloc(hwAccelCtx, blockSize);
    if (!block) {
    ERROR_PRINT(("allocation failed for %d bytes", blockSize));
    return NULL;
    }
    DBUG_PRINT(DEBUG_HARNESS, ("allocation successful for %d bytes", blockSize));
    DIGI_MEMSET((ubyte *) block, 0x00, blockSize);

    pCmd = (Command_t *)block;
    pCmd->maxPackets = numPackets;
    pCmd->mcrNum     = mcrNumber;
    pCmd->hwAccelCtx = hwAccelCtx;

    /* Skip pass the subcmd area */
    offset    = sizeof(*pCmd) + sizeof(pCmd->subCmd[0])*numPackets;

    /* The mcr must go just in front of the pktDescr block */
    pCmd->mcr = (Mcr2_t *)&block[offset];
    offset    = offset + sizeof(ubyte4);

    pktDescr  = (PktDescr2_t *)&block[offset];
    offset    = offset + sizeof(pCmd->subCmd->pktDescr[0])*numPackets;

    /* Prepare linkage and physical address map */
    for (i = 0; i < numPackets; i++) {
    if (NULL == (pktDescr[i].commandCtx =
            HDOS_user2phy(hwAccelCtx,
                              (void *)&pCmd->subCmd[i].command))) {
            /* This must not happen b/c it was from the same allocated
             * block */
            goto errExit;
        }
        pCmd->subCmd[i].pktDescr   = &pktDescr[i];
        pCmd->subCmd[i].hwAccelCtx = hwAccelCtx;
        pCmd->subCmd[i].owner      = pCmd;
    }
    return pCmd;

errExit:
    if (pCmd) {
        cmdDelete(pCmd);
        pCmd = NULL;
    }
    return NULL;
}

static MSTATUS
/*************************************************************
 *    Function: cmdAddExtraData
 * Description: .
 *        pCmd:
 *   blockSize:
 *************************************************************/
cmdAddExtraData(Command_t *pCmd, ubyte2 blockSize)
{
    MSTATUS status = OK;
    ubyte   *block;

    if (NULL != pCmd->extraData) {
        ERROR_PRINT(("Block already attached.  Skip it", 0));
    } else {
        block = HDOS_kernelAlloc(pCmd->hwAccelCtx, blockSize);
        if (!block) {
            ERROR_PRINT(("allocation failed for %d bytes", blockSize));
            status = ERR_MEM_ALLOC_FAIL;
            goto errExit;
        }
        DBUG_PRINT(DEBUG_HARNESS, ("Allocation successful for %d bytes", blockSize));
        DIGI_MEMSET((ubyte *) block, 0x00, blockSize);

        pCmd->extraData = block;
        pCmd->exdSize   = blockSize;
    }
    pCmd->exdUse    = 0;

errExit:
    return status;
}

static ubyte *
/*************************************************************
 *    Function: cmdGetExtraData
 * Description: .
 *        pCmd:
 *        size:
 *************************************************************/
cmdGetExtraData(Command_t *pCmd, ubyte size)
{
    ubyte *address = NULL;

    if ((pCmd->exdUse + size) > pCmd->exdSize) {
        ERROR_PRINT(("No more extra data. Use=%d, size=%d, need=%d",
                  pCmd->exdUse, pCmd->exdSize, size));
        return NULL;
    }
    address = &pCmd->extraData[pCmd->exdUse];
    pCmd->exdUse = (pCmd->exdUse + size);
    return address;
}

static void
/*************************************************************
 *    Function: cmdDelete
 * Description: .
 *        pCmd:
 *************************************************************/
cmdDelete(Command_t *pCmd)
{
    hwAccelDescr    hwAccelCtx = pCmd->hwAccelCtx;
    int             i, j;
    SubCommand_t*   subCmd;

    if (!pCmd)
        return;

    DBUG_PRINT(DEBUG_HARNESS, ("Deleting %x", (int)pCmd));
    for (i = 0, subCmd = &pCmd->subCmd[0]; i < pCmd->usedPackets;
         i++, subCmd++) {
        for (j = 0; j < subCmd->nifrags; j++) {
            if (subCmd->ifMem[j].copied) {
                HDOS_kernelFree(hwAccelCtx, subCmd->ifMem[j].kernelAddr);
                subCmd->ifMem[j].kernelAddr = NULL;
            }
        }
        for (j = 0; j < subCmd->nofrags; j++) {
            if (subCmd->ofMem[j].copied) {
                HDOS_kernelFree(hwAccelCtx, subCmd->ofMem[j].kernelAddr);
                subCmd->ofMem[j].kernelAddr = NULL;
            }
        }
    }
    if (pCmd->extraData) {
        HDOS_kernelFree(hwAccelCtx, pCmd->extraData);
        pCmd->extraData = NULL;
    }
    HDOS_kernelFree(hwAccelCtx, pCmd);
}

static SubCommand_t *
/*************************************************************
 *    Function: cmdAddPacket
 * Description: .
 *        pCmd:
 *      opcode:
 *************************************************************/
cmdAddPacket(Command_t *pCmd, ubyte2 opcode,
             ubyte4 ctxSize, ubyte isNewForm, ubyte isNewOp)
{
    SubCommand_t*           subCmd = NULL;
    ubyte4                  pktNum;
    volatile PktDescr2_t*   pktDescr;
    volatile CommandCtx2_t* cCtx;

    if (pCmd->usedPackets >= pCmd->maxPackets) {
    ERROR_PRINT(("More packets used than allocated", 0));
    goto exit;
    }
    pktNum = pCmd->usedPackets;
    subCmd = &pCmd->subCmd[pktNum];

    subCmd->isNewForm = isNewForm;
    subCmd->isNewOp   = isNewOp;
    subCmd->opcode    = opcode;

    cCtx     = &subCmd->command;
    pktDescr = subCmd->pktDescr;

    /* newop use the common CCH and SCTX size definition */
    if (isNewOp) {
        cCtx->d[0] = CCF_SCTX_PR + (opcode << 16) + ctxSize;
        cCtx->d[1] = (ctxSize - 4)/4;
        if (opcode == OPC_HASH)         /* Why? thv. From BCM test vector */
            cCtx->d[0] |= 0x8000;
    } else {
        cCtx->d[0] = (opcode << 16) + ctxSize;
    }
    if (isNewForm) {
        pktDescr->cctxLen = ctxSize;
    }

    /* Keep 2 status b/c DMA may overwrite the 1st one */
    pCmd->mcr->numPackets = ++(pCmd->usedPackets);
exit:
    return subCmd;
}

static MSTATUS
/*************************************************************
 *    Function: cmdResetPackets
 * Description: Call to reset/reuse of packet
 *        pCmd:
 *************************************************************/
cmdResetPackets(Command_t *pCmd)
{
    MSTATUS       status = OK;
    ubyte4        i, j;
    SubCommand_t* subCmd;
    hwAccelDescr  hwAccelCtx = pCmd->hwAccelCtx;

    for (i = 0, subCmd = &pCmd->subCmd[0]; i < pCmd->usedPackets;
         i++, subCmd++) {
        for (j = 0; j < subCmd->nifrags; j++) {
            if (subCmd->ifMem[j].copied) {
                HDOS_kernelFree(hwAccelCtx, subCmd->ifMem[j].kernelAddr);
                subCmd->ifMem[j].kernelAddr = NULL;
            }
        }
        for (j = 0; j < subCmd->nofrags; j++) {
            if (subCmd->ofMem[j].copied) {
                HDOS_kernelFree(hwAccelCtx, subCmd->ofMem[j].kernelAddr);
                subCmd->ofMem[j].kernelAddr = NULL;
            }
        }
        subCmd->nifrags = 0;
        subCmd->nofrags = 0;
        subCmd->isize   = 0;
        subCmd->osize   = 0;

        /* Should not need to.  May remove later on for perf */
        DIGI_MEMSET((void *)subCmd->ifMem, 0, sizeof(subCmd->ifMem));
        DIGI_MEMSET((void *)subCmd->ofMem, 0, sizeof(subCmd->ofMem));
        DIGI_MEMSET((void *)&subCmd->ui, 0, sizeof(subCmd->ui));
        DIGI_MEMSET((void *)&subCmd->uo, 0, sizeof(subCmd->uo));
    }
    if (pCmd->extraData) {
        /* Should not need to.  May remove later on for perf */
        DIGI_MEMSET((void *)pCmd->extraData, 0, pCmd->exdSize);
    }
    pCmd->exdUse = 0;
    return status;
}

static MSTATUS
/*************************************************************
 *    Function: cmdWaitDone
 * Description: .
 *        pCmd:
 *************************************************************/
cmdWaitDone(Command_t *pCmd)
{
    int                i, count, pktIdx, curTime;
    hwAccelDescr       hwAccelCtx = pCmd->hwAccelCtx;
    static int         maxCount = 0;
    mahCompletionDescr *pCompleteDescr = NULL;
    SubCommand_t       *subCmd;
    MSTATUS            status = OK;
    int                timeout = 0;

    count        = 0;
    curTime      = RTOS_getUpTimeInMS();

    /* wait for job to finish */
    timeout = 0;
    while (OK > HARNESS_getNorthChannelHead(hwAccelCtx, &pCompleteDescr)) {
    /* time out code here */
#ifdef __KERNEL__
        udelay(1);
#else
        {
            struct timespec    treq = {0};

            treq.tv_nsec = 10;
            nanosleep(&treq, NULL);
        }
#endif
        count++;

        /* Some timeout issue.  I reset the chip */
        if (count >= 1000) {
            timeout = 1;
            HARNESS_INTF26_ioCtl(hwAccelCtx, HW_IOCTL_START+3, 0);
            HARNESS_INTF26_ioCtl(hwAccelCtx, HW_IOCTL_START+1, 0);
        }
    }

    for (pktIdx = 0; pktIdx < pCmd->usedPackets; pktIdx++) {
        subCmd   = &pCmd->subCmd[pktIdx];
        if (subCmd->nofrags > 1) {
            /* Dump with the wider old format */
            DUMP_LONGS((void *)&subCmd->uo,
                 sizeof(subCmd->uo.oofragTbl[0])*(subCmd->nofrags-1), 128,
                 "Output Fragment Table");
        }
        for (i = 0; i < subCmd->nofrags; i++) {
            DUMP_LONGS((void *)subCmd->ofMem[i].kernelAddr,
                  subCmd->ofMem[i].size, 128, "Output Fragment nn");
            if (subCmd->ofMem[i].kernelAddr != subCmd->ofMem[i].userAddr) {
                DIGI_MEMCPY(subCmd->ofMem[i].userAddr,
                           subCmd->ofMem[i].kernelAddr,
                           subCmd->ofMem[i].size);
            }
        }
    }

    if (count > maxCount) {
        ERROR_PRINT(("HW crypto() took %d ms (count=%d) to give notice", (int)RTOS_getUpTimeInMS() - curTime, count));
        maxCount = count;
    }

    HARNESS_incrementNorthChannelHead(hwAccelCtx);

    if (timeout) {
        ERROR_PRINT(("Timeout executing last command", 0));
        status = ERR_HARDWARE_ACCEL_TIMEOUT;
    } else {
        if (pCompleteDescr)
            status = pCompleteDescr->hwAccelError;
    }

    if (OK > status) {
    ERROR_PRINT(("return w/ error, return status = %d", status));
    }
    return status;
}

static MSTATUS
/*************************************************************
 *    Function: cmdSendToHarness
 * Description: .
 *        pCmd:
 *************************************************************/
cmdSendToHarness(Command_t *pCmd, int waitDone)
{
    SubCommand_t           *subCmd;
    volatile PktDescr2_t   *pktDescr;
    volatile CommandCtx2_t *cmdCtx;
    int                    i;
    mahCellDescr           *pMahCell;
    MSTATUS                status = OK;
    hwAccelDescr           hwAccelCtx = pCmd->hwAccelCtx;
    ubyte4                 ctxlen, pktIdx;

    DBUG_PRINT(DEBUG_HARNESS, ("MCR: %d, # of descr: %d\n", pCmd->mcrNum, pCmd->usedPackets));
    if (!waitDone) {
        pCmd->mcr->suppresIntr = 1;
    }
    for (pktIdx = 0; pktIdx < pCmd->usedPackets; pktIdx++) {
        subCmd   = &pCmd->subCmd[pktIdx];
        pktDescr = subCmd->pktDescr;
        cmdCtx   = &subCmd->command;

        if ((1 == pCmd->mcrNum) && (
              (0x41 == subCmd->opcode) || (0x42 == subCmd->opcode))) {
            pktDescr->pktLen = subCmd->osize;
        } else {
            pktDescr->pktLen = subCmd->isize;
        }

        DUMP_LONGS((void *)pktDescr, 32, 32, "PKTDESCR");
        ctxlen = cmdCtx->d[0] & 0x7fff;
        DUMP_LONGS((void *)cmdCtx, ctxlen, 256, "CMDCTX");

        if (subCmd->nifrags > 1) {
            /* Dump with the wider old format */
            DUMP_LONGS((void *)&subCmd->ui,
                 sizeof(subCmd->ui.oifragTbl[0])*(subCmd->nifrags-1),
                 128, "Input Fragment Table");
        }
        for (i = 0; i < subCmd->nifrags; i++) {
            DUMP_LONGS((void *)subCmd->ifMem[i].kernelAddr,
                  subCmd->ifMem[i].size, 128, "Input Fragment nn");
        }
    }
    pCmd->useCount++;
    asyncCtl.totalSent[pCmd->mcrNum]++;

    /* Don't send for now (for debug) */
    if (!asyncCtl.hnSending)
        goto exit;

    if (OK > (status = HARNESS_reserveSouth(hwAccelCtx, &pMahCell))) {
    ERROR_PRINT(("HARNESS_reserveSouth return status = %d", status));
    goto exit;
    }

    pMahCell->mcrNumber  = pCmd->mcrNum;
    pMahCell->mcrContext = (void *)HDOS_user2phy(hwAccelCtx,
                                (void *)pCmd->mcr);
    if (!pMahCell->mcrContext)
        goto exit;

    /* fire off the crypto job */
    if (OK > (status = HARNESS_activateSouthTail(hwAccelCtx)))
    goto exit;

#define TESTMODE
#ifdef TESTMODE
    /* HARNESS_INTF26_ioCtl(hwAccelCtx, HW_IOCTL_START + 4, 0); */
#endif
#undef TESTMODE

    if (!waitDone) {
        goto exit;
    }
    status = cmdWaitDone(pCmd);
exit:
    return status;
}

static void
/*************************************************************
 *    Function: pktSetCtxSize
 * Description: Reset the context size after creation.  Some command
 *      sequence (i.e. hash) changes the context size depending on
 *      the phase of operation.
 *      subCmd:
 *     ctxSize:
 *************************************************************/
pktSetCtxSize(SubCommand_t *subCmd, ubyte2 ctxSize)
{
    subCmd->command.d[0] = (subCmd->command.d[0] & 0xffff8000) | ctxSize;
    if (subCmd->isNewOp) {
        subCmd->command.d[1] = (ctxSize - 4)/4;
        subCmd->pktDescr->cctxLen = ctxSize;
    }
}

static ubyte *
/*************************************************************
 *    Function: pktAddInputFragment
 * Description: .
 *      subCmd:
 *    fragment:
 *************************************************************/
pktAddInputFragment(SubCommand_t *subCmd, const ubyte *fragment,
                    ubyte4 fsize, ubyte isControl)
{
    int                   fpos;
    MSTATUS               status   = OK;
    volatile PktDescr2_t* pktDescr = subCmd->pktDescr;
    void                  *bufferPAddr;
    hwAccelDescr           hwAccelCtx  = subCmd->hwAccelCtx;
    ubyte                 *kfragment;

    if (subCmd->nifrags >= MAX_INPUT_FRAGMENTS) {
        ERROR_PRINT(("Too many input fragments: max is %d",
                    MAX_INPUT_FRAGMENTS));
        status = ERR_HARDWARE_ACCEL_NO_MEMORY;
        goto exit;
    }
    if (NULL == fragment) {
        fragment = cmdGetExtraData(subCmd->owner, fsize);
        if (NULL == fragment) {
            goto exit;
        }
    }
    subCmd->ifMem[subCmd->nifrags].size       = fsize;
    subCmd->ifMem[subCmd->nifrags].userAddr   = (void *)fragment;
    subCmd->ifMem[subCmd->nifrags].kernelAddr = (void *)fragment;
    bufferPAddr = HDOS_user2phy(hwAccelCtx, (void *)fragment);
    if (NULL == bufferPAddr) {
        /* Not kernel data? We allocate it */
        kfragment = HDOS_kernelAlloc(hwAccelCtx, fsize);
        if (NULL == kfragment) {
            DBUG_PRINT(DEBUG_HARNESS, ("No more memory for %d bytes", fsize));
            fragment = NULL;
            status   = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DBUG_PRINT(DEBUG_HARNESS, ("Allocate new block for user fragment [size=%d]", fsize));
        DIGI_MEMCPY(kfragment, fragment, fsize);
        subCmd->ifMem[subCmd->nifrags].kernelAddr = kfragment;
        subCmd->ifMem[subCmd->nifrags].copied     = 1;
        fragment    = kfragment;
        bufferPAddr = HDOS_user2phy(hwAccelCtx, (void *)fragment);
    }

    if (0 == subCmd->nifrags) {
        pktDescr->input.dataAddr = bufferPAddr;
        pktDescr->input.fragLen  = fsize;
        if (isControl && subCmd->isNewForm) {
            pktDescr->input.control = 1;
            /* DBUG_PRINT(DEBUG_HARNESS, ("Set control bit for input f %d", subCmd->nifrags)); */
        }
    } else {
        if (1 == subCmd->nifrags) {
            pktDescr->input.nextFrag = HDOS_user2phy(hwAccelCtx,
                                                &subCmd->ui);
        }
        fpos = subCmd->nifrags-1;
        if (subCmd->isNewForm) {
            subCmd->ui.ifragTbl[fpos].dataAddr = bufferPAddr;
            subCmd->ui.ifragTbl[fpos].fragLen  = fsize;
            if (isControl) {
                subCmd->ui.ifragTbl[fpos].control = 1;
                /* DBUG_PRINT(DEBUG_HARNESS, ("Set control bit for input f %d", subCmd->nifrags)); */
            }
        } else {
            subCmd->ui.oifragTbl[fpos].dataAddr = bufferPAddr;
            subCmd->ui.oifragTbl[fpos].nextFrag = 0;
            subCmd->ui.oifragTbl[fpos].fragLen  = fsize;
            if (0 < fpos) {
                subCmd->ui.oifragTbl[fpos-1].nextFrag =
                    HDOS_user2phy(hwAccelCtx,
                                  &subCmd->ui.ifragTbl[fpos]);
            }
        }
    }
    subCmd->nifrags++;
    if (subCmd->isNewForm) {
        pktDescr->input.numFrags = subCmd->nifrags;
    }
    subCmd->isize   += fsize;
exit:
    return (ubyte *)fragment;
}

static ubyte *
/*************************************************************
 *    Function: pktAddOutputFragment
 * Description: .
 *      subCmd:
 *    fragment:
 *************************************************************/
pktAddOutputFragment(SubCommand_t *subCmd, ubyte *fragment,
                    ubyte4 fsize, ubyte isControl, ubyte isNewField)
{
    int                   fpos;
    MSTATUS               status   = OK;
    volatile PktDescr2_t* pktDescr = subCmd->pktDescr;
    void                  *bufferPAddr;
    hwAccelDescr           hwAccelCtx = subCmd->hwAccelCtx;
    ubyte                 *kfragment;

    if (subCmd->nofrags >= MAX_OUTPUT_FRAGMENTS) {
        ERROR_PRINT(("Too many output fragments: max is %d", MAX_OUTPUT_FRAGMENTS));
        status = ERR_HARDWARE_ACCEL_NO_MEMORY;
        goto exit;
    }
    if (NULL == fragment) {
        fragment = cmdGetExtraData(subCmd->owner, fsize);
        if (NULL == fragment) {
            goto exit;
        }
    }

    subCmd->ofMem[subCmd->nofrags].size       = fsize;
    subCmd->ofMem[subCmd->nofrags].userAddr   = fragment;
    subCmd->ofMem[subCmd->nofrags].kernelAddr = fragment;

    bufferPAddr = HDOS_user2phy(hwAccelCtx, fragment);
    if (NULL == bufferPAddr) {
        /* Not kernel data? We allocate it */
        kfragment = HDOS_kernelAlloc(hwAccelCtx, fsize);
        if (NULL == kfragment) {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DBUG_PRINT(DEBUG_HARNESS, ("Allocate new block for user fragment [size=%d]", fsize));
        subCmd->ofMem[subCmd->nofrags].kernelAddr = kfragment;
        subCmd->ofMem[subCmd->nofrags].copied     = 1;
        fragment    = kfragment;
        bufferPAddr = HDOS_user2phy(hwAccelCtx, fragment);
    }

    if (0 == subCmd->nofrags) {
        pktDescr->output.dataAddr = bufferPAddr;
        pktDescr->output.fragLen  = fsize;
        if (isControl && subCmd->isNewForm) {
            pktDescr->output.control = 1;
        }
    } else {
        if (1 == subCmd->nofrags) {
            pktDescr->output.nextFrag = HDOS_user2phy(hwAccelCtx,
                                                 &subCmd->uo);
        }
        fpos = subCmd->nofrags-1;
        if (subCmd->isNewForm) {
            subCmd->uo.ofragTbl[fpos].dataAddr = bufferPAddr;
            subCmd->uo.ofragTbl[fpos].fragLen  = fsize;
            if (isControl)
                subCmd->uo.ofragTbl[fpos].control  = 1;
            if (isNewField)
                subCmd->uo.ofragTbl[fpos].newField = 1;
        } else {
            subCmd->uo.oofragTbl[fpos].dataAddr = bufferPAddr;
            subCmd->uo.oofragTbl[fpos].nextFrag = 0;
            subCmd->uo.oofragTbl[fpos].fragLen  = fsize;
            if (0 < fpos) {
                subCmd->uo.oofragTbl[fpos-1].nextFrag =
                    HDOS_user2phy(hwAccelCtx,
                                  &subCmd->uo.ofragTbl[fpos]);
            }
        }
    }

    subCmd->nofrags++;
    if (subCmd->isNewForm) {
        pktDescr->output.numFrags = subCmd->nofrags;
    }
    subCmd->osize   += fsize;
exit:
    return fragment;
}

static MSTATUS
/*************************************************************
 *    Function: pktAddBDESCFragment
 * Description: .
 *  subCommand:
 *************************************************************/
pktAddBDESCFragment(SubCommand_t * subCommand,
            ubyte2 authOfs, ubyte2 authSize,
            ubyte2 cryptOfs, ubyte2 cryptSize,
            ubyte2 icvOfs, ubyte2 ivOfs)
{
    MSTATUS status    = OK;
    ubyte4  *fragment = NULL;

    fragment = (ubyte4 *) pktAddInputFragment(subCommand, NULL, 12, 1);
    if (NULL == fragment) {
        status = ERR_HARDWARE_ACCEL_NO_MEMORY;
        goto exit;
    }
    fragment[0] = (authOfs  << 16) + authSize;
    fragment[1] = (cryptOfs << 16) + cryptSize;
    fragment[2] = (icvOfs   << 16) + ivOfs;
    subCommand->command.d[0] |= CCF_BDESC_PR;
exit:
    return status;
}

static MSTATUS
/*************************************************************
 *    Function: pktAddBDFragment
 * Description: .
 *************************************************************/
pktAddBDFragment(SubCommand_t * subCommand,
         ubyte *iBuffer, ubyte2 iSize,
                 ubyte *oBuffer, ubyte2 oSize,
                 ubyte2 prevCount)
{
    MSTATUS status = OK;
    ubyte4 *fragment = NULL;

    if (iSize) {
        fragment = (ubyte4 *) pktAddInputFragment(subCommand, NULL, 4, 1);
        if (NULL == fragment) {
            status = ERR_HARDWARE_ACCEL_NO_MEMORY;
            goto exit;
        }
        fragment[0] = (iSize << 16) + prevCount;
        if (iBuffer)
            pktAddInputFragment(subCommand, iBuffer, iSize, 0);
    }
    if (oSize) {
        fragment = (ubyte4 *) pktAddOutputFragment(subCommand, NULL, 4, 1, 0);
        if (NULL == fragment) {
            status = ERR_HARDWARE_ACCEL_NO_MEMORY;
            goto exit;
        }
        fragment[0] = oSize << 16;
        if (oBuffer)
            pktAddOutputFragment(subCommand, oBuffer, oSize, 0, 0);
    }
    subCommand->command.d[0] |= CCF_BD_PR;
  exit:
    return status;
}

static void
/*************************************************************
 *    Function: flipBuffer
 * Description: .
 *        dest:
 *         src:
 *      wcount:
 *************************************************************/
flipBuffer(ubyte4 *dest, ubyte4 *src, ubyte wcount)
{
    ubyte4 i;
    ubyte4 *dp, *sp, newWord;

    for (sp = src, dp = dest, i = 0; i < wcount; i++, sp++, dp++) {
        /* I must xfer to temp var b/c src could be same as dst */
        newWord = ((*sp >> 24) & 0xff) +
                    (((*sp >> 16) & 0xff) << 8) +
                    (((*sp >> 8) & 0xff) << 16) +
                    (((*sp & 0xff)) << 24);
        *dp = newWord;
    }
}


/*------------------------------------------------------------------*/

#if((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__))
extern BulkCtx
CreateAESCtx(hwAccelDescr hwAccelCtx, ubyte * keyMaterial, sbyte4 keyLength,
         sbyte4 encrypt)
{
    Command_t              *pCmd   = NULL;
    SubCommand_t           *subCmd = NULL;
    volatile CommandCtx2_t *cmdCtx;
    ubyte4                 ctxLen, ckeySize;

    switch (keyLength) {
    case 16:
        ctxLen = 80;
        ckeySize = 0;
        break;
    case 24:
        ctxLen = 88;
        ckeySize = 1;
        break;
    case 32:
        ctxLen = 96;
        ckeySize = 2;
        break;
    default:                            /* Catch all */
        goto errExit;
        break;
    }

    pCmd = cmdCreate(hwAccelCtx, 1, 0);
    if (NULL == pCmd) {
        goto errExit;
    }

    subCmd = cmdAddPacket(pCmd, OPC_IPSEC_AES, ctxLen, 0, 0);
    if (NULL == subCmd) {
        goto errExit;
    }

    subCmd->keyLength = keyLength;
    cmdCtx            = &subCmd->command;
    subCmd->command.d[1] = (1<<15) + (ckeySize<<8);
    flipBuffer((ubyte4 *)&cmdCtx->d[2], (ubyte4 *)keyMaterial,
               keyLength >> 2);

    return (BulkCtx)pCmd;

  errExit:
    if (pCmd) {
        cmdDelete(pCmd);
        pCmd = NULL;
    }
    return (BulkCtx)pCmd;
}

extern MSTATUS
/*************************************************************
 *    Function: DoAES
 * Description: .
 *  hwAccelCtx:
 *         ctx:
 *        data:
 *  dataLength:
 *************************************************************/
DoAES(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte * data, sbyte4 dataLength,
      sbyte4 encrypt, ubyte * iv)
{
    MSTATUS      status  = OK;
    Command_t   *pCmd    = (Command_t *)ctx;
    SubCommand_t *subCmd = &pCmd->subCmd[0];
    ubyte        oiv[IVSIZE_AES];

    if (NULL == ctx) {
    status = ERR_NULL_POINTER;
    goto exit;
    }

    if (0 == hwAccelCtx) {
    status = ERR_HARDWARE_ACCEL_BAD_CTX;
    goto exit;
    }

    if (0 != (dataLength % AES_BLOCK_SIZE)) {
    status = ERR_AES_BAD_LENGTH;
    goto exit;
    }

    if (SEC_MAX_LENGTH < dataLength) {
    status = ERR_AES_BAD_LENGTH;
    goto exit;
    }

    cmdResetPackets(pCmd);
    if (encrypt) {
        subCmd->command.d[1] &= ~(1<<14);
    } else {
        subCmd->command.d[1] |= (1<<14);
        DIGI_MEMCPY(oiv, data + dataLength - IVSIZE_AES, IVSIZE_AES);
        /* DIGI_MEMCPY(oiv, data, IVSIZE_AES); */
    }

    if (iv) {
        flipBuffer((ubyte4 *)&subCmd->command.d[(subCmd->keyLength/4)+2],
                   (ubyte4 *)iv, IVSIZE_AES >> 2);
    }

    pktAddInputFragment(subCmd, data, dataLength, 0);
    pktAddOutputFragment(subCmd, data, dataLength, 0, 0);

    if (OK > (status = cmdSendToHarness(pCmd, 1))) {
    goto exit;
    }
    if (encrypt) {
        DIGI_MEMCPY(iv, data + dataLength - IVSIZE_AES, IVSIZE_AES);
    } else {
        DIGI_MEMCPY(iv, oiv, IVSIZE_AES);
    }

exit:
    return status;
}               /* DoAES */

/*------------------------------------------------------------------*/

extern MSTATUS
DeleteAESCtx(hwAccelDescr hwAccelCtx, BulkCtx * ctx)
{
    cmdDelete((Command_t *)*ctx);
    *ctx = NULL;
    return OK;
}
#endif /*((!defined(__DISABLE_AES_CIPHERS__)) && defined(__AES_HARDWARE_CIPHER__)) */

/*------------------------------------------------------------------*/
#if(defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__))
extern BulkCtx
CreateDESCtx(hwAccelDescr hwAccelCtx, ubyte * keyMaterial, sbyte4 keyLength,
         sbyte4 encrypt)
{
    Command_t              *pCmd   = NULL;
    SubCommand_t           *subCmd = NULL;
    volatile CommandCtx2_t *cmdCtx;
    ubyte4                 ofs, i;

    if ((DES_KEY_LENGTH != keyLength) || (NULL == keyMaterial)) {
        ERROR_PRINT(("Bad key size: %d <> %d", keyLength, DES_KEY_LENGTH));
    goto errExit;
    }

    pCmd = cmdCreate(hwAccelCtx, 1, 0);
    if (NULL == pCmd) {
        goto errExit;
    }

    subCmd = cmdAddPacket(pCmd, OPC_IPSEC_3DES, 80, 0, 0);
    if (NULL == subCmd) {
        goto errExit;
    }

    subCmd->keyLength = keyLength;
    cmdCtx            = &subCmd->command;
    for (ofs = 2, i = 0; i < 3; i++) {
        DIGI_MEMCPY((void *)&cmdCtx->d[ofs], keyMaterial, keyLength);
        ofs = ofs + (keyLength/sizeof(ubyte4));
    }
    return (BulkCtx)pCmd;

  errExit:
    if (pCmd) {
        cmdDelete(pCmd);
        pCmd = NULL;
    }
    return (BulkCtx)pCmd;
}

extern MSTATUS
DoDES(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte * data, sbyte4 dataLength,
      sbyte4 encrypt, ubyte *iv)
{
    return Do3DES(hwAccelCtx, ctx, data, dataLength, encrypt, iv);
}

extern MSTATUS
DeleteDESCtx(hwAccelDescr hwAccelCtx, BulkCtx * ctx)
{
    cmdDelete((Command_t *)*ctx);
    *ctx = NULL;
    return OK;
}
#endif /*(defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__)) */

/*------------------------------------------------------------------*/

#if((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__))
extern BulkCtx
/*************************************************************
 *    Function: Create3DESCtx
 * Description: .
 *************************************************************/
Create3DESCtx(hwAccelDescr hwAccelCtx, ubyte * keyMaterial, sbyte4 keyLength,
          sbyte4 encrypt)
{
    Command_t              *pCmd   = NULL;
    SubCommand_t           *subCmd = NULL;
    volatile CommandCtx2_t *cmdCtx;

    if ((THREE_DES_KEY_LENGTH != keyLength) || (NULL == keyMaterial))
    return NULL;

    pCmd = cmdCreate(hwAccelCtx, 1, 0);
    if (NULL == pCmd) {
        goto errExit;
    }

    subCmd = cmdAddPacket(pCmd, OPC_IPSEC_3DES, 80, 0, 0);
    if (NULL == subCmd) {
        goto errExit;
    }

    subCmd->keyLength = keyLength;
    cmdCtx            = &subCmd->command;
    flipBuffer((ubyte4 *)&cmdCtx->d[2],
               (ubyte4 *)keyMaterial, keyLength/4);
    return (BulkCtx)pCmd;

  errExit:
    if (pCmd) {
        cmdDelete(pCmd);
        pCmd = NULL;
    }
    return (BulkCtx)pCmd;
}

extern MSTATUS
/*************************************************************
 *    Function: Do3DES
 * Description: 3DES encryption/decryption
 *************************************************************/
Do3DES(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte * data, sbyte4 dataLength,
       sbyte4 encrypt, ubyte * iv)
{
    MSTATUS      status = OK;
    Command_t    *pCmd  = (Command_t *)ctx;
    SubCommand_t *subCmd = &pCmd->subCmd[0];
    ubyte        oiv[IVSIZE_3DES];

    if (NULL == ctx) {
    status = ERR_NULL_POINTER;
    goto errExit;
    }
    if (0 == hwAccelCtx) {
    status = ERR_HARDWARE_ACCEL_BAD_CTX;
    goto errExit;
    }
    if (0 != (dataLength % THREE_DES_BLOCK_SIZE)) {
    status = ERR_DES_BAD_LENGTH;
    goto errExit;
    }
    if (SEC_MAX_LENGTH < dataLength) {
    status = ERR_DES_BAD_LENGTH;
    goto errExit;
    }

    cmdResetPackets(pCmd);
    if (encrypt)
        subCmd->command.d[1] = (1<<15) + (0<<14);
    else {
        subCmd->command.d[1] = (1<<15) + (1<<14);
        DIGI_MEMCPY(oiv, data + dataLength - IVSIZE_3DES, IVSIZE_3DES);
    }

    if (iv) {
        flipBuffer((ubyte4 *)&subCmd->command.d[8], (ubyte4 *)iv,
                   IVSIZE_3DES>>2);
    }

    pktAddInputFragment(subCmd, data, dataLength, 0);
    pktAddOutputFragment(subCmd, data, dataLength, 0, 0);

    if (OK > (status = cmdSendToHarness(pCmd, 1))) {
    goto errExit;
    }
    if (encrypt) {
        DIGI_MEMCPY(iv, data + dataLength - IVSIZE_3DES, IVSIZE_3DES);
    } else {
        DIGI_MEMCPY(iv, oiv, IVSIZE_3DES);
    }
    return status;

errExit:
    return status;
}

extern MSTATUS
/*************************************************************
 *    Function: Delete3DESCtx
 * Description: .
 *************************************************************/
Delete3DESCtx(hwAccelDescr hwAccelCtx, BulkCtx * ctx)
{
    cmdDelete((Command_t *)*ctx);
    *ctx = NULL;
    return OK;
}
#endif /*((!defined(__DISABLE_3DES_CIPHERS__)) && defined(__3DES_HARDWARE_CIPHER__)) */

/*------------------------------------------------------------------*/

#if((!defined(__DISABLE_ARC4_CIPHERS__)) && defined(__ARC4_HARDWARE_CIPHER__))
extern BulkCtx
CreateRC4Ctx(hwAccelDescr hwAccelCtx, ubyte * keyMaterial, sbyte4 keyLength,
         sbyte4 encrypt)
{
    Command_t*              pCmd;
    SubCommand_t*           subCmd = &pCmd->subCmd[0];
    ubyte4                  ctxLen;
    volatile CommandCtx2_t* cmdCtx;
    ubyte*                  bptr;
    ubyte4                  remain;

    if ((1 > keyLength) || (256 < keyLength))
    goto errExit;       /* bad key size */

    pCmd = cmdCreate(hwAccelCtx, 1, 0);
    if (NULL == pCmd) {
        goto errExit;
    }
    if (OK != cmdAddExtraData(pCmd, 260 + 12 + 4 + 4 + 32)) {
        goto errExit;
    }

    ctxLen = 16 + 260;                  /* header + key */
    subCmd = cmdAddPacket(pCmd, OPC_CRYPTO, ctxLen, 1, 1);
    if (NULL == subCmd) {
        goto errExit;
    }
    subCmd->keyLength = keyLength;
    cmdCtx            = &subCmd->command;

    bptr   = (ubyte *)&cmdCtx->d[5];
    remain = 256;
    while (0 < remain) {
        DIGI_MEMCPY(bptr, keyMaterial,
                   keyLength > remain ? remain : keyLength);
        bptr += keyLength;
        remain -= keyLength;

    }
    return (BulkCtx)pCmd;

  errExit:
    if (pCmd) {
        cmdDelete(pCmd);
        pCmd = NULL;
    }
    return NULL;
}

extern MSTATUS
DoRC4(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte * data, sbyte4 dataLength,
      sbyte4 encrypt, ubyte * iv)
{
    MSTATUS                 status  = OK;
    Command_t               *pCmd    = (Command_t *)ctx;
    SubCommand_t            *subCmd = &pCmd->subCmd[0];
    volatile CommandCtx2_t* cmdCtx;

    if (NULL == pCmd) {
    status = ERR_NULL_POINTER;
    goto exit;
    }

    if (0 > hwAccelCtx) {
    status = ERR_HARDWARE_ACCEL_BAD_CTX;
    goto exit;
    }

    if (SEC_MAX_LENGTH < dataLength) {
    status = ERR_ARC4_BAD_LENGTH;
    goto exit;
    }

    cmdResetPackets(pCmd);
    cmdCtx  = &subCmd->command;

    if (0 == pCmd->useCount) {
        cmdCtx->d[4] &= ~0x01000000;     /* Update flag clear */
    } else {
        cmdCtx->d[4] |= 0x01000000;     /* Update flag set */
    }

    subCmd->command.d[1] = SCTX_TYPE_GENERIC | SCTX_UP_ENA;
    if (encrypt) {
        subCmd->command.d[2] = SCTX_OUTBOUND + BCRYPT_ALGO_ARC4 +
                                BHASH_ALGO_NULL + 3;
    } else {
        subCmd->command.d[2] = SCTX_INBOUND + BCRYPT_ALGO_ARC4 +
                                BHASH_ALGO_NULL + 3;
    }

    /* Add the BDESC */
    if (OK != (status =
        pktAddBDESCFragment(subCmd, 0, 0, 0, dataLength, 0, 0))) {
    goto exit;
    }

    /* And the data header */
    if (OK != (status =
        pktAddBDFragment(subCmd, data, dataLength, data, dataLength, 0))) {
        goto exit;
    }

    /* Add the output for RC4 result */
    if (NULL == pktAddOutputFragment(subCmd, NULL, 260, 0, 1)) {
        status = ERR_HARDWARE_ACCEL_NO_MEMORY;
        goto exit;
    }

    if (OK > (status = cmdSendToHarness(pCmd, 1))) {
    goto exit;
    }
  exit:
    return status;
}               /* DoRC4 */

extern MSTATUS
DeleteRC4Ctx(hwAccelDescr hwAccelCtx, BulkCtx * ctx)
{
    cmdDelete((Command_t *)*ctx);
    *ctx = NULL;
    return OK;
}
#endif /*((!defined(__DISABLE_ARC4_CIPHERS__)) && defined(__ARC4_HARDWARE_CIPHER__)) */

#define HKEY_LENGTH(a) ((a) == BHASH_ALGO_MD5) ? 16 : 20

#if defined(__MD5_ONE_STEP_HARDWARE_HASH__) || defined(__SHA1_ONE_STEP_HARDWARE_HASH__)
static MSTATUS
/*************************************************************
 *    Function: doCompleteDigest
 * Description: .
 *  hwAccelCtx:
 *   algorithm:
 *************************************************************/
doCompleteDigest(hwAccelDescr hwAccelCtx, ubyte4 algorithm,
                 ubyte *pData, ubyte4 dataLen,
                 ubyte *xData, ubyte4 xDataLen,
                 ubyte *pDigestOut)
{
    MSTATUS      status = OK;
    Command_t    *pCmd;
    ubyte4       oalgo = (algorithm >> 13) << 12;
    ubyte        *bData;
    SubCommand_t *subCommand;

    /* Normalized to old position of hash algorithm */
    ubyte4       digestLen = HKEY_LENGTH(algorithm);

    pCmd = cmdCreate(hwAccelCtx, 1, 0);
    if (NULL == pCmd) {
        goto exit;
    }

    subCommand = cmdAddPacket(pCmd, OPC_HASH, 8, 0, 0);
    if (NULL == subCommand) {
        goto exit;
    }
    subCommand->command.d[1] = oalgo;
    pktAddInputFragment(subCommand, pData, dataLen, 0);
    if (xData && xDataLen) {
        pktAddInputFragment(subCommand, xData, xDataLen, 0);
    }

    bData = pktAddOutputFragment(subCommand, pDigestOut, digestLen, 0, 0);

    subCommand->pktDescr->output.nextFrag =
                HDOS_user2phy(pCmd->hwAccelCtx, bData);
    if (OK > (status = cmdSendToHarness(pCmd, 1))) {
    goto exit;
    }
    DUMP_LONGS((void *)pDigestOut, 32, 32, "Digest Output");

exit:
    if (pCmd) {
        cmdDelete(pCmd);
        pCmd = NULL;
    }
    return status;
}
#endif

/*------------------------------------------------------------------*/

#ifdef __MD5_ONE_STEP_HARDWARE_HASH__
extern MSTATUS
MD5_completeDigest(hwAccelDescr hwAccelCtx, ubyte * pData,
           ubyte4 dataLen, ubyte * pMdOutput)
{
    return doCompleteDigest(hwAccelCtx, BHASH_ALGO_MD5,
                            pData, dataLen, NULL, 0, pMdOutput);
}
extern MSTATUS
MD5_completeDigest2(hwAccelDescr hwAccelCtx, ubyte * pData, ubyte4 dataLen,
                    ubyte *xData, ubyte4 xDataLen, ubyte * pMdOutput)
{
    return doCompleteDigest(hwAccelCtx, BHASH_ALGO_MD5,
                            pData, dataLen, xData, xDataLen, pMdOutput);
}
#endif

/*------------------------------------------------------------------*/

#ifdef __SHA1_ONE_STEP_HARDWARE_HASH__
extern MSTATUS
SHA1_completeDigest(hwAccelDescr hwAccelCtx, ubyte * pData,
            ubyte4 dataLen, ubyte * pShaOutput)
{
    return doCompleteDigest(hwAccelCtx, BHASH_ALGO_SHA1,
                            pData, dataLen, NULL, 0, pShaOutput);
}
extern MSTATUS
SHA1_completeDigest2(hwAccelDescr hwAccelCtx, ubyte * pData, ubyte4 dataLen,
             ubyte *xData, ubyte4 xDataLen, ubyte * pShaOutput)
{
    return doCompleteDigest(hwAccelCtx, BHASH_ALGO_SHA1,
                            pData, dataLen, xData, xDataLen, pShaOutput);
}
#endif

/*------------------------------------------------------------------*/
#ifdef __HMAC_MD5_HARDWARE_HASH__
static MSTATUS
doHmac2(hwAccelDescr hwAccelCtx, ubyte4 algorithm, ubyte * key, sbyte4 keyLen,
        ubyte *text, sbyte4 textLen, ubyte *textOpt, sbyte4 textOptLen,
        ubyte *result);

extern MSTATUS
HMAC_MD5(hwAccelDescr hwAccelCtx, ubyte * key, sbyte4 keyLen, ubyte * text,
     sbyte4 textLen, ubyte * textOpt, sbyte4 textOptLen,
     ubyte result[MD5_DIGESTSIZE])
{
    ubyte        *pTempResult = NULL;
    MSTATUS       status = OK;

    /* if key is longer than HMAC_BLOCK_SIZE bytes reset it to key=MD5(key) */
    if (keyLen > HMAC_BLOCK_SIZE) {
    if (OK > (status =
         MD5_completeDigest(hwAccelCtx, key, keyLen, pTempResult))) {
        goto exit;
        }
    key    = pTempResult;
    keyLen = MD5_DIGESTSIZE;
    }
    DUMP_LONGS((void *)key,  keyLen,  128, "MD5 HMAC key");
    DUMP_LONGS((void *)text, textLen, 128, "MD5 HMAC data");
    status = doHmac2(hwAccelCtx, BHASH_ALGO_MD5, key, keyLen,
                     text, textLen, textOpt, textOptLen, result);
exit:
    return status;
}

extern MSTATUS
HMAC_MD5_quick(hwAccelDescr hwAccelCtx, ubyte* pKey, sbyte4 keyLen, ubyte* pText, sbyte4 textLen,
               ubyte* pResult /* MD5_DIGESTSIZE */)
{
    return HMAC_MD5(hwAccelCtx, pKey, keyLen, pText, textLen, NULL, 0,
                    pResult);
}
#endif

/*------------------------------------------------------------------*/

#ifdef __HMAC_SHA1_HARDWARE_HASH__
extern MSTATUS
HMAC_SHA1(hwAccelDescr hwAccelCtx, ubyte * key, sbyte4 keyLen, ubyte * text,
      sbyte4 textLen, ubyte * textOpt, sbyte4 textOptLen,
      ubyte result[SHA_HASH_RESULT_SIZE])
{
    ubyte         *pTempResult = NULL;
    MSTATUS       status = OK;

    if (keyLen > HMAC_BLOCK_SIZE) {
    if (OK > (status =
         SHA1_completeDigest(hwAccelCtx, key, keyLen, pTempResult))) {
        goto exit;
    }
    key    = pTempResult;
    keyLen = SHA_HASH_RESULT_SIZE;
    }
    DUMP_LONGS((void *)key,  keyLen,  128, "SHA1 HMAC key");
    DUMP_LONGS((void *)text, textLen, 128, "SHA1 HMAC data");
    status = doHmac2(hwAccelCtx, BHASH_ALGO_SHA1, key, keyLen,
                    text, textLen, textOpt, textOptLen, result);
exit:
    return status;
}

extern MSTATUS
HMAC_SHA1_quick(hwAccelDescr hwAccelCtx, ubyte* pKey, sbyte4 keyLen, ubyte* pText, sbyte4 textLen,
                ubyte* pResult /* SHA_HASH_RESULT_SIZE */)
{
    return HMAC_SHA1(hwAccelCtx, pKey, keyLen, pText, textLen, NULL, 0,
                     pResult);
}
#endif

/*------------------------------------------------------------------*/

#if defined(__CUSTOM_MD5_CONTEXT__) || defined(__CUSTOM_SHA1_CONTEXT__)
#define MD_CTX_BUFF_AVAIL(c)          (MD_CTX_HASHDATA_SIZE -(c)->index)
#endif

static MSTATUS
/*************************************************************
 *    Function: doHashCommon
 * Description: Except for the last call at FINI.  All data must
 *              be block padded.
 *        pCmd:
 *    hashAlgo:
 *    hashType:
 *************************************************************/
doHashCommon(HwHashContext_t *context, ubyte4 hashType,
             const ubyte *data0, ubyte4 data0Length,
             const ubyte *data1, ubyte4 data1Length,
             ubyte *output, ubyte4 prevLength)
{
    ubyte4       dataSize;
    MSTATUS      status      = OK;
    Command_t    *pCmd       = NULL;
    SubCommand_t *subCmd     = NULL;
    ubyte4       hashSize    = context->digestSize;
    ubyte        *lastDigest = context->lastDigest;

    pCmd = cmdCreate(context->hwAccelCtx, 1, 0);
    if (NULL == pCmd) {
    status = ERR_HARDWARE_ACCEL_BAD_CTX;
        goto exit;
    }
    if (OK != cmdAddExtraData(pCmd, 32)) {
        status = ERR_HARDWARE_ACCEL_NO_MEMORY;
        goto exit;
    }
    if (NULL == cmdAddPacket(pCmd, OPC_HASH,
                             16 + context->digestSize, 1, 1)) {
        status = ERR_HARDWARE_ACCEL_NO_MEMORY;
        goto exit;
    }
    subCmd = &pCmd->subCmd[0];

    DBUG_PRINT(DEBUG_HARNESS, ("hash calc for %d + %d bytes", data0Length, data1Length));
    /* cmdResetPackets(pCmd); */             /* Reinit before use */
    if ((hashType == BHASH_TYPE_INIT) || (hashType == BHASH_TYPE_FULL)) {
        pktSetCtxSize(subCmd, 16);
    } else {
        pktSetCtxSize(subCmd, 16 + hashSize);
        flipBuffer((ubyte4 *)&subCmd->command.d[4], (ubyte4 *)lastDigest,
                    hashSize>>2);
        /* memcpy(&subCmd->command.d[4], lastDigest, hashSize); */
    }

    subCmd->command.d[2] = context->algorithm + hashType;
    subCmd->command.d[3] = (hashSize >> 2) << 8;

    dataSize = data0Length + data1Length;

    /* Add the BDESC */
    if (OK != (status =
        pktAddBDESCFragment(subCmd, 0, dataSize, 0, 0, 0, 0))) {
    goto exit;
    }
    /* And the data header */
    if (OK != (status =
        pktAddBDFragment(subCmd, NULL, dataSize, NULL, 0,
                         prevLength))) {
        goto exit;
    }
    if (data0Length && (NULL != data0)) {
        if (NULL == pktAddInputFragment(subCmd, data0, data0Length, 0)) {
            status = ERR_HARDWARE_ACCEL_NO_MEMORY;
            goto exit;
        }
    }
    if (data1Length && (NULL != data1)) {
        if (NULL == pktAddInputFragment(subCmd, data1, data1Length, 0)) {
            status = ERR_HARDWARE_ACCEL_NO_MEMORY;
            goto exit;
        }
    }

    if (NULL == pktAddOutputFragment(subCmd, lastDigest, hashSize, 0, 1)) {
        status = ERR_HARDWARE_ACCEL_NO_MEMORY;
        goto exit;
    }

    /* Hack for opcode 5.  Use nextfrag ptr */
    subCmd->pktDescr->output.nextFrag =
        HDOS_user2phy(pCmd->hwAccelCtx, lastDigest);

    if (OK > (status = cmdSendToHarness(pCmd, 1))) {
    goto exit;
    }
    if (NULL != output) {
        DIGI_MEMCPY(output, lastDigest, hashSize);
    }

  exit:
    if (pCmd) {
        cmdDelete(pCmd);
        pCmd = NULL;
    }
    return status;
}

#if defined(__MD5_HARDWARE_HASH__) || defined(__SHA1_HARDWARE_HASH__)
static MSTATUS
/*************************************************************
 *    Function: hashContextInit
 * Description: .
 *  hwAccelCtx:
 *     context:
 *************************************************************/
hashContextInit(hwAccelDescr hwAccelCtx, HwHashContext_t *context,
                ubyte4 algorithm, ubyte4 digestSize)
{
    MSTATUS      status = OK;

    context->hwAccelCtx = hwAccelCtx;
    context->index      = 0;
    context->totalSent  = 0;
    context->algorithm  = algorithm;
    context->digestSize = digestSize;
    return status;
}

static MSTATUS
/*************************************************************
 *    Function: hashContextUpdate
 * Description: .
 *     context:
 *       pData:
 *     dataLen:
 *************************************************************/
hashContextUpdate(HwHashContext_t *context,
                  const ubyte *pData, ubyte4 dataLen)
{
    ubyte4          remainder, hashType, dsendLen;
    MSTATUS         status = OK;
#define LEN_64_MASK             (0x0000003F)

    if (0 == dataLen) {
    status = ERR_BAD_LENGTH;
    goto exit;
    }
    DBUG_PRINT(DEBUG_HARNESS, ("Update for %d bytes", dataLen));
    DUMP_LONGS((void *)pData, dataLen, 1024, "Update data");

    /* Not enough to send.  We cache it for now */
    if ((context->index + dataLen) <= MD_CTX_HASHDATA_SIZE) {
        DIGI_MEMCPY(context->cacheData + context->index,
                   pData, dataLen);
        context->index += dataLen;
        goto exit;
    }

    remainder = (context->index + dataLen) & LEN_64_MASK;
    dsendLen  = dataLen - remainder;

    /* We have to keep something in cache for the FIN use */
    if (0 == remainder) {
        dsendLen -= MD_CTX_HASHDATA_SIZE;
        remainder = MD_CTX_HASHDATA_SIZE;
    }

    hashType = (context->totalSent <= 0) ?
                        BHASH_TYPE_INIT : BHASH_TYPE_UPDT;
    if (OK > (status =
        doHashCommon(context, hashType,
                     context->cacheData, context->index,
                     pData, dsendLen, NULL, 0))) {
        goto exit;
    }
    context->totalSent += (dsendLen + context->index);
    DBUG_PRINT(DEBUG_HARNESS, ("Total sent is %d", context->totalSent));

    /* Transfer the remaining part to cache */
    DIGI_MEMCPY(context->cacheData, &pData[dsendLen], remainder);
    context->index = remainder;

  exit:
    return status;
}

static MSTATUS
/*************************************************************
 *    Function: hashContextFinalize
 * Description: .
 *     context:
 *      digest:
 *************************************************************/
hashContextFinalize(HwHashContext_t *context, ubyte *digest)
{
    ubyte4          hashType;
    MSTATUS         status   = OK;

    if (0 == context->index) {
    /* data should always be available */
    status = ERR_BAD_LENGTH;
    goto exit;
    }

    hashType = (context->totalSent <= 0) ?
                        BHASH_TYPE_FULL : BHASH_TYPE_FIN;

    if (OK > (status =
        doHashCommon(context, hashType,
                     context->cacheData, context->index,
                     NULL, 0, digest, context->totalSent))) {
        goto exit;
    }
    context->totalSent += context->index;
    context->index = 0;

  exit:
    return status;
}
#endif

#if defined(__HMAC_MD5_HARDWARE_HASH__) || defined(__HMAC_SHA1_HARDWARE_HASH__)
static MSTATUS
/*************************************************************
 *    Function: doHashContext
 * Description: .
 *  hwAccelCtx:
 *   algorithm:
 *         key:
 *      output:
 *************************************************************/
doHashContext(hwAccelDescr hwAccelCtx, ubyte4 algorithm,
              ubyte *key, sbyte4 keyLen, ubyte *output)
{
    MSTATUS       status = OK;
    ubyte4        digestLen, outLen;
    Command_t*    pCmd;
    SubCommand_t* subCmd;

    digestLen = HKEY_LENGTH(algorithm);
    outLen    = digestLen << 1;

    pCmd = cmdCreate(hwAccelCtx, 1, 0);
    if (NULL == pCmd) {
        status = ERR_HARDWARE_ACCEL_NO_MEMORY;
        goto exit;
    }

    subCmd = cmdAddPacket(pCmd, OPC_HASH_CONTEXT, 16+keyLen, 1, 1);
    if (NULL == subCmd) {
        status = ERR_HARDWARE_ACCEL_NO_MEMORY;
        goto exit;
    }

    subCmd->command.d[2] = algorithm + BHASH_MODE_CTXT + BHASH_TYPE_FULL;
    subCmd->command.d[3] = ((outLen >> 2) << 8);

    flipBuffer((ubyte4 *)&subCmd->command.d[4], (ubyte4 *)key, keyLen>>2);

    pktAddOutputFragment(subCmd, output, outLen, 0, 0);

    if (OK > (status = cmdSendToHarness(pCmd, 1))) {
    goto exit;
    }
exit:
    if (pCmd) {
        cmdDelete(pCmd);
        pCmd = NULL;
    }
    return status;
}

static MSTATUS
doHashContext2(hwAccelDescr hwAccelCtx, ubyte4 algorithm,
               ubyte *key, sbyte4 keyLen, ubyte *output)
{
    MSTATUS status = OK;
    ubyte4  digestLen, i;
    ubyte   ipad[65], opad[65];

    digestLen = HKEY_LENGTH(algorithm);

    DIGI_MEMSET(ipad, 0, sizeof(ipad));
    DIGI_MEMSET(opad, 0, sizeof(opad));
    DIGI_MEMCPY(ipad, key, keyLen);
    DIGI_MEMCPY(opad, key, keyLen);

    for(i = 0; i < 64; i++) {
        ipad[i] ^= 0x36;
        opad[i] ^= 0x5c;
    }
    if (OK > (status =
        MD5_completeDigest(hwAccelCtx, ipad, 64, &output[0]))) {
        goto exit;
    }
    if (OK > (status =
        MD5_completeDigest(hwAccelCtx, opad, 64, &output[digestLen]))) {
        goto exit;
    }
exit:
    return status;
}

extern MSTATUS
MD5_hashContext(hwAccelDescr hwAccelCtx, ubyte *key, sbyte4 keyLen, ubyte *output)
{
    return doHashContext(hwAccelCtx, BHASH_ALGO_MD5, key, keyLen, output);
}

extern MSTATUS
SHA1_hashContext(hwAccelDescr hwAccelCtx, ubyte *key, sbyte4 keyLen, ubyte *output)
{
    return doHashContext(hwAccelCtx, BHASH_ALGO_SHA1, key, keyLen, output);
}


static MSTATUS
/*************************************************************
 *    Function: doHmac
 * Description: .
 *  hwAccelCtx:
 *   algorithm:
 *         key:
 *        text:
 *************************************************************/
doHmac(hwAccelDescr hwAccelCtx, ubyte4 algorithm, ubyte * key, sbyte4 keyLen,
       ubyte *text, sbyte4 textLen, ubyte *textOpt, sbyte4 textOptLen,
       ubyte *result)
{
    ubyte4        *hcontext;
    ubyte4        pktLen;
    MSTATUS       status = OK;
    Command_t*    pCmd;
    SubCommand_t* subCommand;
    ubyte4        digestLen = HKEY_LENGTH(algorithm);

    if (0 == hwAccelCtx) {
    status = ERR_HARDWARE_ACCEL_BAD_CTX;
    goto exit;
    }

    pCmd = cmdCreate(hwAccelCtx, 1, 0);
    if (NULL == pCmd) {
        status = ERR_HARDWARE_ACCEL_NO_MEMORY;
        goto exit;
    }
    cmdAddExtraData(pCmd, 64);

    subCommand = cmdAddPacket(pCmd, OPC_CRYPTO, 16+digestLen*2, 1, 1);
    if (NULL == subCommand) {
        status = ERR_HARDWARE_ACCEL_NO_MEMORY;
        goto exit;
    }

    subCommand->command.d[2] = algorithm + BHASH_MODE_HMAC;
    subCommand->command.d[3] = BF_ICV_INSERT + ((keyLen >> 2) << 8);

    /* Add the BDESC */
    pktLen = textLen + textOptLen;
    if (OK != (status =
        pktAddBDESCFragment(subCommand, 0, pktLen, 0, 0, pktLen, 0))) {
    goto exit;
    }

    /* Add the BD header for input + output */
    if (OK != (status =
        pktAddBDFragment(subCommand, NULL, pktLen+keyLen,
                         NULL, pktLen+keyLen, 0))) {
    goto exit;
    }

    /* Followed immediately by the data chain itself (3 parts) */
    pktAddInputFragment(subCommand, text, textLen, 0);
    if (textOpt)
        pktAddInputFragment(subCommand, textOpt, textOptLen, 0);
    if (NULL == pktAddInputFragment(subCommand, NULL, digestLen, 0)) {
        status = ERR_HARDWARE_ACCEL_NO_MEMORY;
        goto exit;
    }

    pktAddOutputFragment(subCommand, text, textLen, 0, 0);
    if (textOpt)
        pktAddOutputFragment(subCommand, textOpt, textOptLen, 0, 0);
    pktAddOutputFragment(subCommand, result, digestLen, 0, 0);

    hcontext = (ubyte4 *)&subCommand->command.d[4];
    if (OK > (status =
        doHashContext(hwAccelCtx, algorithm, key, keyLen,
                      (ubyte *)hcontext))) {
        goto exit;
    }

    if (OK > (status = cmdSendToHarness(pCmd, 1))) {
    goto exit;
    }

  exit:
    if (pCmd) {
        cmdDelete(pCmd);
        pCmd = NULL;
    }
    return status;
}

static MSTATUS
doHmac2(hwAccelDescr hwAccelCtx, ubyte4 algorithm, ubyte * key, sbyte4 keyLen,
        ubyte *text, sbyte4 textLen, ubyte *textOpt, sbyte4 textOptLen,
        ubyte *result)
{
    MSTATUS status = OK;
    ubyte   *kbuffer = NULL;
    ubyte   *digest, *ipad, *opad;
    ubyte4  i, bufsize;
    ubyte4  hashLen = HKEY_LENGTH(algorithm);

    if (0 == hwAccelCtx) {
    status = ERR_HARDWARE_ACCEL_BAD_CTX;
    goto exit;
    }

    bufsize = 64*2+32+16;
    kbuffer = HDOS_kernelAlloc(hwAccelCtx, bufsize);
    if (NULL == kbuffer) {
    status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    ipad   = kbuffer;
    opad   = &kbuffer[64];
    digest = &kbuffer[64+64];

    DIGI_MEMSET(kbuffer, 0, bufsize);
    DIGI_MEMCPY(ipad, key, keyLen);
    DIGI_MEMCPY(opad, key, keyLen);

    for(i = 0; i < 64; i++) {
        ipad[i] ^= 0x36;
        opad[i] ^= 0x5c;
    }
#if 0
    {
        MD5_CTX md5Context;

        hashContextInit(hwAccelCtx, &md5Context.cctx, algorithm,
                        hashLen);
        hashContextUpdate(&md5Context.cctx, ipad, 64);
        hashContextUpdate(&md5Context.cctx, text, textLen);
        hashContextFinalize(&md5Context.cctx, digest);

        hashContextInit(hwAccelCtx, &md5Context.cctx, algorithm,
                        hashLen);
        hashContextUpdate(&md5Context.cctx, opad, 64);
        hashContextUpdate(&md5Context.cctx, digest, hashLen);
        hashContextFinalize(&md5Context.cctx, result);
    }

#else
    doCompleteDigest(hwAccelCtx, algorithm, ipad, 64, text, textLen,
                     digest);
    doCompleteDigest(hwAccelCtx, algorithm, opad, 64,
                     digest, hashLen, result);
#endif
exit:
    if (NULL != kbuffer) {
        HDOS_kernelFree(hwAccelCtx, kbuffer);
        kbuffer = NULL;
    }
    return status;
}
#endif                                  /* __HMAC_(MD5|SHA1)_HARDWARE_HASH__ */

/*------------------------------------------------------------------*/

#ifdef __MD5_HARDWARE_HASH__
extern BulkCtx
MD5Alloc_m(void)
{
    return (BulkCtx) MALLOC(sizeof(MD5_CTX));
}

/*------------------------------------------------------------------*/

extern MSTATUS
MD5Free_m(BulkCtx * pp_context)
{
    if (NULL != *pp_context) {
    FREE(*pp_context);
    *pp_context = NULL;
    }
    return OK;
}

extern MSTATUS
MD5Init_m(hwAccelDescr hwAccelCtx, MD5_CTX * md5Context)
{
    MOC_UNUSED(hwAccelCtx);

    return hashContextInit(hwAccelCtx, &md5Context->cctx, BHASH_ALGO_MD5,
                           MD5_DIGESTSIZE);
}

extern MSTATUS
MD5Update_m(hwAccelDescr hwAccelCtx, MD5_CTX * pMd5Context,
        const ubyte * pData, ubyte4 dataLen)
{
    MOC_UNUSED(hwAccelCtx);

    return hashContextUpdate(&pMd5Context->cctx, pData, dataLen);
}

extern MSTATUS
MD5Final_m(hwAccelDescr hwAccelCtx, MD5_CTX * pMd5Context,
       ubyte digest[MD5_DIGESTSIZE])
{
    MOC_UNUSED(hwAccelCtx);

    return hashContextFinalize(&pMd5Context->cctx, digest);
}
#endif /* __MD5_HARDWARE_HASH__ */

/*------------------------------------------------------------------*/

#ifdef __SHA1_HARDWARE_HASH__
extern BulkCtx
SHA1_allocDigest(void)
{
    return (shaDescr *) MALLOC(sizeof(shaDescr));
}

/*------------------------------------------------------------------*/

extern MSTATUS
SHA1_freeDigest(BulkCtx * pp_shaContext)
{
    if (NULL != *pp_shaContext) {
    FREE(*pp_shaContext);
    *pp_shaContext = NULL;
    }

    return OK;
}

MSTATUS
/*************************************************************
 *    Function: SHA1_initDigest
 * Description: .
 *  hwAccelCtx:
 * p_shaContext:
 *************************************************************/
SHA1_initDigest(hwAccelDescr hwAccelCtx, shaDescr *pSha1Context)
{
    return hashContextInit(hwAccelCtx, &pSha1Context->cctx,
                           BHASH_ALGO_SHA1, SHA_HASH_RESULT_SIZE);
}

extern MSTATUS
SHA1_updateDigest(hwAccelDescr hwAccelCtx, shaDescr *pSha1Context,
          const ubyte * pData, ubyte4 dataLen)
{
    MOC_UNUSED(hwAccelCtx);

    return hashContextUpdate(&pSha1Context->cctx, pData, dataLen);
}

extern MSTATUS
SHA1_finalDigest(hwAccelDescr hwAccelCtx, shaDescr *pSha1Context, ubyte *digest)
{
    MOC_UNUSED(hwAccelCtx);

    return hashContextFinalize(&pSha1Context->cctx, digest);
}
#endif /* __SHA1_HARDWARE_HASH__ */

/*------------------------------------------------------------------*/

#ifdef __DISABLE_DIGICERT_RNG__
#define NUM_PER_GENERATOR       (128)
typedef struct
{
    hwAccelDescr    hwAccelCtx;
    ubyte           pool[NUM_PER_GENERATOR];
    sbyte4          use;

} RandomCtx_t;

extern MSTATUS
RANDOM_acquireContext(randomContext **ctx)
{
    MSTATUS         status = OK;
    hwAccelDescr    hwAccelCtx = 0;
    RandomCtx_t*    rContext = NULL;

    if (OK > (status =
        HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx))) {
        goto errExit;
    }
    if (NULL == (
        rContext = HDOS_kernelAlloc(hwAccelCtx, sizeof(RandomCtx_t)))) {
        status = ERR_MEM_ALLOC_FAIL;
        goto errExit;
    }
    rContext->hwAccelCtx = hwAccelCtx;
    rContext->use        = -1;

    *ctx = (randomContext *)rContext;
    return status;

errExit:
    if (rContext) {
        HDOS_kernelFree(hwAccelCtx, rContext);
        rContext = NULL;
    }
    if (hwAccelCtx != 0) {
        HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
        hwAccelCtx = 0;
    }
    return status;
}

extern MSTATUS
RANDOM_releaseContext(randomContext **ctx)
{
    RandomCtx_t*    rCtx = (RandomCtx_t *)(*ctx);
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status    = OK;

    if ((NULL == rCtx) || (0 == (hwAccelCtx = rCtx->hwAccelCtx))) {
    status = ERR_HARDWARE_ACCEL_BAD_CTX;
    goto exit;
    }
    status = HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &rCtx->hwAccelCtx);
    HDOS_kernelFree(hwAccelCtx, rCtx);
  exit:
    return status;
}

extern MSTATUS
/*************************************************************
 *    Function: RANDOM_numberGenerator
 * Description: .
 * pRandomContext:
 *     pBuffer:
 *************************************************************/
RANDOM_numberGenerator(randomContext *pRandomContext, ubyte * pBuffer,
               sbyte4 bufSize)
{
    Command_t    *pCmd = NULL;
    SubCommand_t *subCommand;
    RandomCtx_t  *rCtx  = (RandomCtx_t *)pRandomContext;
    MSTATUS      status = OK;

    if ((rCtx->use < 0) || (rCtx->use + bufSize) > sizeof(rCtx->pool)) {
        pCmd = cmdCreate(rCtx->hwAccelCtx, 1, 1);
        if (NULL == pCmd) {
            status = ERR_HARDWARE_ACCEL_BAD_CTX;
            goto exit;
        }

        subCommand = cmdAddPacket(pCmd, OPC_RNG_DIRECT, 4, 0, 0);
        if (NULL == subCommand) {
            goto exit;
        }

        /* Is size ok to cache ? */
        if (bufSize > sizeof(rCtx->pool)) {
            pktAddOutputFragment(subCommand, pBuffer, bufSize, 0, 0);
            if (OK > (status = cmdSendToHarness(pCmd, 1))) {
                goto exit;
            }
        } else {
            pktAddOutputFragment(subCommand, rCtx->pool,
                                 sizeof(rCtx->pool), 0, 0);
            if (OK > (status = cmdSendToHarness(pCmd, 1))) {
                goto exit;
            }
            DIGI_MEMCPY(pBuffer, rCtx->pool, bufSize);
            rCtx->use = bufSize;
        }
    } else {
        DIGI_MEMCPY(pBuffer, &rCtx->pool[rCtx->use], bufSize);
        rCtx->use += bufSize;
    }
exit:
    if (pCmd) {
        cmdDelete(pCmd);
        pCmd = NULL;
    }
    return status;
}

extern sbyte4
RANDOM_rngFun(void *rngFunArg, ubyte4 length, ubyte * buffer)
{
    return RANDOM_numberGenerator((randomContext *) rngFunArg,
                  buffer, (sbyte4) length);
}


#endif

static MSTATUS
vlongToArray(Command_t *pCmd, const vlong * pValue,
             ubyte ** ppRetByteArray, ubyte4 needed)
{
    sbyte4  index;
    ubyte4  elem, nLen;
    ubyte   *pDest;
    MSTATUS status = OK;

    /* clear out in case of an error */
    *ppRetByteArray = NULL;

    /* allocate necessary memory */
    if (NULL == (pDest = cmdGetExtraData(pCmd, needed))) {
        status = ERR_HARDWARE_ACCEL_NO_MEMORY;
    goto exit;
    }

    *ppRetByteArray   = pDest;

    nLen   = VLONG_BYTE_SIZE(pValue);
    pDest += (nLen-1);

    for (index = pValue->numUnitsUsed-1; index >= 0; index--) {
    elem = VLONG_getVlongUnit(pValue, index);

    *(pDest--) = (ubyte) ((elem >> 24) & 0xff);
    *(pDest--) = (ubyte) ((elem >> 16) & 0xff);

    *(pDest--) = (ubyte) ((elem >> 8) & 0xff);
    *(pDest--) = (ubyte) (elem & 0xff);
    }
  exit:
    return status;
}

static void
reverseBuffer(ubyte4 *block, ubyte4 nwords)
{
    ubyte4 i, limit, tmp;

    limit = nwords >> 1;
    for (i = 0; i < limit; i++) {
        tmp = block[i];
        block[i] = block[nwords-i-1];
        block[nwords-i-1] = tmp;
    }
}

typedef struct {
    ubyte2 bitmin;
    ubyte2 bitmax;
    ubyte4 bytesize;
} PSizeTbl_t;

static PSizeTbl_t psizeTbl[] = {
    /*{16,  256,  32}, */
    {16,  512,  64},
    {513, 768,  96},
    {769, 1024, 128},
    {1025, 1536, 192},
    {1537, 2048, 256},
    {2049, 3072, 384},
    {3073, 4096, 512}
};

static ubyte4
getStoredTableSize(const vlong *value)
{
    ubyte4     numBits = VLONG_bitLength(value);
    ubyte4     i;
    PSizeTbl_t *sp;

    for (i = 0, sp = psizeTbl; i < sizeof(psizeTbl)/sizeof(psizeTbl[0]);
         i++, sp++) {
        if ((numBits >= sp->bitmin) && (numBits <= sp->bitmax))
            return sp->bytesize;
    }
    ERROR_PRINT(("Can't get stored table size for nbits=%d", numBits));
    return 0;
}

/*------------------------------------------------------------------*/
#ifdef __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
extern MSTATUS
/*************************************************************
 *    Function: VLONG_modexp
 * Description: .
 *  hwAccelCtx:
 *           x:
 *           e:
 *************************************************************/
VLONG_modexp(MOC_MOD(hwAccelDescr hwAccelCtx) const vlong * x, const vlong * e,
         const vlong * m, vlong ** ppRetModExp, vlong ** ppVlongQueue)
{
    /* x^e mod n or a^e mod n */
    ubyte                  *pA   = NULL;
    ubyte                  *pE   = NULL;
    ubyte                  *pN   = NULL;
    ubyte4                 ctxLen, nLen, reqlen, bxLen;
    MSTATUS                status = OK;
    Command_t              *pCmd   = NULL;
    SubCommand_t           *subCmd = NULL;
    ubyte*                 bData;

    pCmd = cmdCreate(hwAccelCtx, 1, 1);
    if (NULL == pCmd) {
        status = ERR_HARDWARE_ACCEL_NO_MEMORY;
        goto exit;
    }

    nLen   = VLONG_BYTE_SIZE(m);
    bxLen  = getStoredTableSize(m);     /* Store size */
    if (0 == bxLen) {
        status = ERR_HARDWARE_ACCEL_BAD_INPUT;
        goto exit;
    }

    reqlen = bxLen*4 + 32;
    if (OK != cmdAddExtraData(pCmd, reqlen)) {
        status = ERR_HARDWARE_ACCEL_NO_MEMORY;
        goto exit;
    }

    if (OK > (status = vlongToArray(pCmd, x, &pA, bxLen))) {
        status = ERR_BAD_EXPONENT;
    goto exit;
    }

    if (OK > (status = vlongToArray(pCmd, e, &pE, VLONG_BYTE_SIZE(e)))) {
        status = ERR_BAD_EXPONENT;
    goto exit;
    }


    if (OK > (status = vlongToArray(pCmd, m, &pN, bxLen))) {
        status = ERR_BAD_EXPONENT;
    goto exit;
    }

    ctxLen = 8 + bxLen;
    subCmd = cmdAddPacket(pCmd, OPC_MOD_EXPONENT, ctxLen, 1, 0);
    if (NULL == subCmd) {
        goto exit;
    }
    subCmd->command.d[1] = (VLONG_bitLength(m) << 16) + VLONG_bitLength(e);

    DIGI_MEMCPY((void *)&subCmd->command.d[2], pN, bxLen);

    pktAddInputFragment(subCmd, pA, bxLen, 1);
    pktAddInputFragment(subCmd, pE, VLONG_BYTE_SIZE(e), 1);

    bData = pktAddOutputFragment(subCmd, NULL, bxLen, 1, 0);
    if (NULL == bData) {
        status = ERR_HARDWARE_ACCEL_NO_MEMORY;
        goto exit;
    }

    if (OK > (status = cmdSendToHarness(pCmd, 1))) {
    goto exit;
    }

    /* convert byte array to vlong */
    reverseBuffer((ubyte4 *)bData, nLen >> 2);
    status = VLONG_vlongFromByteString(bData, nLen,
                                       ppRetModExp, ppVlongQueue);
    /* DUMP_VLONGS(*ppRetModExp, 128, "ModExp output"); */

  exit:
    if (pCmd) {
        cmdDelete(pCmd);
        pCmd = NULL;
    }
    return status;
}
#endif /* __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__ */

/*------------------------------------------------------------------*/

#ifdef __RSAINT_HARDWARE__
extern MSTATUS
RSAINT_decrypt(hwAccelDescr hwAccelCtx, RSAKey * pRSAKeyInt,
           vlong * pCipher, RNGFun rngFun, void *rngFunArg,
           vlong ** ppRetDecrypt, vlong ** ppVlongQueue)
{
    vlong *pm = NULL;
    vlong *qm = NULL;
    vlong *d = NULL;
    vlong *pm_qm = NULL;
    MSTATUS status;
    MOC_UNUSED(rngFun);     /* for RSA blinding */
    MOC_UNUSED(rngFunArg);  /* for RSA blinding */

    if (OK > (status = VLONG_allocVlong(&pm_qm, ppVlongQueue)))
    goto exit;

    /* vlong pm = p - 1; */
    if (OK >
    (status = VLONG_makeVlongFromVlong(RSA_P(pRSAKeyInt), &pm, ppVlongQueue)))
    goto exit;

    if (OK > (status = VLONG_decrement(pm, ppVlongQueue)))
    goto exit;

    /* vlong qm = q - vlong(1); */
    if (OK >
    (status = VLONG_makeVlongFromVlong(RSA_Q(pRSAKeyInt), &qm, ppVlongQueue)))
    goto exit;

    if (OK > (status = VLONG_decrement(qm, ppVlongQueue)))
    goto exit;

    /* vlong d = modinv( e, (pm)*(qm) ); */
    if (OK > (status = VLONG_vlongSignedMultiply(pm_qm, pm, qm)))
    goto exit;

    if (OK >
    (status =
     VLONG_modularInverse(MOC_MOD(hwAccelCtx) RSA_E(pRSAKeyInt), pm_qm, &d,
                  ppVlongQueue)))
    goto exit;

    /* decrypt: m = c^d mod n */
    status =
      VLONG_modexp(hwAccelCtx, pCipher, d, RSA_N(pRSAKeyInt), ppRetDecrypt,
           ppVlongQueue);

  exit:
    VLONG_freeVlong(&pm, ppVlongQueue);
    VLONG_freeVlong(&qm, ppVlongQueue);
    VLONG_freeVlong(&d, ppVlongQueue);
    VLONG_freeVlong(&pm_qm, ppVlongQueue);

    return status;

}               /* RSAINT_decrypt */
#endif

extern void
BCM5862_asyncControl(ubyte4 operation, ubyte4 value)
{
    switch (operation) {
    case DCOP_HNSENDING:
        asyncCtl.hnSending = value;
        DBUG_PRINT(DEBUG_HARNESS, ("Setting hnSending to %d", value));
        break;
    }
}
#endif /*(defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) && defined(__ENABLE_BROADCOM_5862_HARDWARE_ACCEL__)) */
