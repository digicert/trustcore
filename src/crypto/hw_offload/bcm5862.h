/*************************************************************************
 * File:        src/crypto/hw_offload/bcm5862.h
 * Created:     Thu Nov 30 13:27:15 PST 2006
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
 * Description:
 *************************************************************************/
#ifndef __BCM5862_H__
#define __BCM5862_H__

#ifdef __cplusplus
extern "C" {
#endif

/*#include "../common/mtypes.h"*/

#define MAX_SUPPORTED_DEVICES 4

/*#include "../harness/harness_drv.h" */

/*
 * List of Vendor/Device IDs supported
 */
#define BROADCOM_VENDOR_ID  0x14e4  /* Broadcom vendor ID */
#define BROADCOM_DEVICE_ID_5801  0x5801 /* Release board. */
#define BROADCOM_DEVICE_ID_5802  0x5802 /* Release board. */
#define BROADCOM_DEVICE_ID_5805  0x5805 /* Release board  */
#define BROADCOM_DEVICE_ID_5820  0x5820 /* Release board  */
#define BROADCOM_DEVICE_ID_5821  0x5821 /* Release board  */
#define BROADCOM_DEVICE_ID_5822  0x5822 /* Release board  */
#define BROADCOM_DEVICE_ID_5823  0x5823 /* Release board  */
#define BROADCOM_DEVICE_ID_5824  0x5824 /* Release board  */
#define BROADCOM_DEVICE_ID_5825  0x5825 /* Release board  */
/* Centurion Product Family*/
#define BROADCOM_DEVICE_ID_5827  0x5827 /* Release board  */
#define BROADCOM_DEVICE_ID_5828  0x5828 /* Release board  */
#define BROADCOM_DEVICE_ID_5829  0x5829 /* Release board  */
#define BROADCOM_DEVICE_ID_5852  0x5852 /* Release board  */
#define BROADCOM_DEVICE_ID_5854  0x5854 /* Release board  */
#define BROADCOM_DEVICE_ID_5856  0x5856 /* Release board  */
#define BROADCOM_DEVICE_ID_5860  0x5860 /* Release board  */
#define BROADCOM_DEVICE_ID_5861  0x5861 /* Release board  */
#define BROADCOM_DEVICE_ID_5862  0x5862 /* Release board  */
#define SEC_MAX_LENGTH                  32767

#define IVSIZE_3DES     (8)
#define IVSIZE_AES      (16)

typedef struct {
    ubyte4   inputXfer;
    ubyte4   outputXfer;
    ubyte4   reserved[2];
} CsrDmaConf_t;

/* Layout of CSR (Phys Address) */
typedef struct {
    ubyte4 mcr1;
    ubyte4 dmaControl;
#define CSDMA_RESET          (0x80000000)
#define CSDMA_MCR2INT_EN     (0x40000000)
#define CSDMA_MCR1INT_EN     (0x20000000)
#define CSDMA_LITTLE_ENDIAN  (0x08000000)
#define CSDMA_NORMAL_PCI     (0x04000000)
#define CSDMA_DMAERR_EN      (0x02000000)
#define CSDMA_RNG_MODE_SLOW  (0x00800000)
#define CSDMA_MCR3INT_EN     (0x00400000)
#define CSDMA_MCR4INT_EN     (0x00200000)
#define CSDMA_LEGACYDESC_DIS (0x00008000)

#define CSDMA_MCRINT_EN      (CSDMA_MCR1INT_EN|CSDMA_MCR2INT_EN|CSDMA_MCR3INT_EN|CSDMA_MCR4INT_EN)

    ubyte4 dmaStatus;

#define CSDMA_MCR_BUSY       (0x80000000)
#define CSDMA_MCR1_FULL      (0x40000000)
#define CSDMA_MCR1_DONE      (0x20000000)
#define CSDMA_DMA_ERROR      (0x10000000)
#define CSDMA_MCR2_FULL      (0x08000000)
#define CSDMA_MCR2_DONE      (0x04000000)
#define CSDMA_MCR1_ALL_EMPTY (0x02000000)
#define CSDMA_MCR2_ALL_EMPTY (0x01000000)
#define CSDMA_MCR3_ALL_EMPTY (0x00800000)
#define CSDMA_MCR4_ALL_EMPTY (0x00400000)
#define CSDMA_MCR3_FULL      (0x00080000)
#define CSDMA_MCR3_DONE      (0x00040000)
#define CSDMA_MCR4_FULL      (0x00020000)
#define CSDMA_MCR4_DONE      (0x00010000)

#define CSDMA_MCR_ANYDONE    (CSDMA_MCR1_DONE|CSDMA_MCR2_DONE|CSDMA_MCR3_DONE|CSDMA_MCR4_DONE)

    ubyte4       dmaError;
    ubyte4       mcr2;
    ubyte4       mcr3;
    ubyte4       mcr4;
    ubyte4       reserved0[3];
    ubyte4       mcr4_pend:4;
    ubyte4       mcr3_pend:4;
    ubyte4       mcr2_pend:4;
    ubyte4       mcr1_pend:4;
    ubyte4       reserved1[3];
    CsrDmaConf_t dmaConfig[4];
} Csr_t;

/* Offset defined is in 32 bit word */
#define BOFS_MCR1         0
#define BOFS_DMA_CONTROL  1
#define BOFS_DMA_STATUS   2
#define BOFS_DMA_ERR_ADDR 3
#define BOFS_MCR2         4
#define BOFS_MCR3         5
#define BOFS_MCR4         6

#define BOFS_CACHE_CONFIG      0x0100
#define BOFS_CACHE_ACCESS      0x0104
#define BOFS_CACHE_ADDRESS     0x0108
#define BOFS_CACHE_INDEX       0x010c
#define BOFS_CACHE_PKTCOUNT    0x0120
#define BOFS_CACHE_HITCOUNT    0x0124

#define BOFS_SYSTIME           0x0200
#define BOFS_SYSTIME_PRESCALAR 0x0204
#define BOFS_USHM_CONFIG       0x0208

#define BOFS_GRP_INTERRUPT     0x0f00
#define BOFS_PIPELINE_CTL      0x0f04

#define BOFS_SPU_RESOURCE_CFG  0x0400
#define BOFS_SPU_CONTROL       0x0404

#define BOFS_OPU_CONTROL       0x0500
#define BOFS_OPU_PIP_DESC      0x0504

/* Word 0 of SCTX (1 of CTX) */
#define SCTX_UP_ENA       (1<<28)
#define SCTX_CACHEABLE    (1<<29)
#define SCTX_TYPE_GENERIC (0<<30)
#define SCTX_TYPE_IPSEC   (1<<30)
#define SCTX_TYPE_SSL     (2<<30)

/* Word 1 of SCTX (2 of CX) */

#define SCTX_OUTBOUND     (0<<31)
#define SCTX_INBOUND      (1<<31)

#define BHASH_TYPE_FULL   (0<<8)
#define BHASH_TYPE_INIT   (1<<8)
#define BHASH_TYPE_UPDT   (2<<8)
#define BHASH_TYPE_FIN    (3<<8)

#define BHASH_MODE_XCBC   (5<<10)
#define BHASH_MODE_CCM    (4<<10)
#define BHASH_MODE_SSLMAC (3<<10)
#define BHASH_MODE_HMAC   (2<<10)
#define BHASH_MODE_CTXT   (1<<10)
#define BHASH_MODE_HASH   (0<<10)

#define BHASH_ALGO_AES    (4<<13)
#define BHASH_ALGO_SHA256 (3<<13)
#define BHASH_ALGO_SHA1   (2<<13)
#define BHASH_ALGO_MD5    (1<<13)
#define BHASH_ALGO_NULL   (0<<13)

#define BCRYPT_MODE_CCM (5<<18)
#define BCRYPT_MODE_CTR (4<<18)
#define BCRYPT_MODE_CFB (3<<18)
#define BCRYPT_MODE_OFB (2<<18)
#define BCRYPT_MODE_CBC (1<<18)
#define BCRYPT_MODE_EBC (0<<18)

#define BCRYPT_ALGO_AES  (4<<21)
#define BCRYPT_ALGO_3DES (3<<21)
#define BCRYPT_ALGO_DES  (2<<21)
#define BCRYPT_ALGO_ARC4 (1<<21)
#define BCRYPT_ALGO_NULL (0<<21)

/* Word 2 of SCTX (3 of CTX */
#define BF_ICV_INSERT (1<<13)
#define BF_ICV_CHECK  (1<<12)

typedef struct SFragment_t {            /* Short fragment def */
    PhysAddr_t dataAddr;
    ubyte4     fragLen:16;
    ubyte4     reserved1:6;
    ubyte4     newField:1;
    ubyte4     control:1;
    ubyte4     reserved0:8;
} SFragment_t;

typedef struct SFragmentOld_t {            /* Short fragment def */
    PhysAddr_t dataAddr;
    PhysAddr_t nextFrag;
    ubyte4     fragLen:16;
    ubyte4     reserved0:16;
} SFragmentOld_t;

typedef struct {
    PhysAddr_t dataAddr;
    PhysAddr_t nextFrag;                   /* Fragment_t (DMA view) */
    ubyte4     fragLen:16;
    ubyte4     numFrags:6;
    ubyte4     newField:1;
    ubyte4     control:1;
    ubyte4     reserved:8;
} Fragment_t;

typedef struct {
    ubyte4 reserved:12;
    ubyte4 authentication:2;
    ubyte4 direction:1;
    ubyte4 encryption:1;
    ubyte4 offset:16;
    ubyte  deskey[3][8];
    ubyte  iv[8];
    ubyte  innerHash[20];
    ubyte  outerHash[20];
} SctxTdes_t;

typedef struct {
    ubyte4 len:12;
    ubyte4 reserved:4;
    ubyte4 opcode:8;
/* Note: the MCR# is encoded into the opcode.  Mask it out when */
/* setting to hardware */
#define OPC_IPSEC_3DES          0x000       /* OLD */
#define OPC_CRYPTO              0x001
#define OPC_HASH                0x005       /* OLD */
#define OPC_HASH_CONTEXT        0x006
#define OPC_SHA256              0x007
#define OPC_AES_XCBC            0x010
#define OPC_AES_CCMP            0x011
#define OPC_IPSEC_AES           0x040       /* OLD */
#define OPC_IPSEC_IV_3DES       0x041       /* OLD */
#define OPC_IPSEC_IV_AES        0x042       /* OLD */
#define OPC_TLS_DEC_STREAM      0x085
#define OPC_TLS_ENC_STREAM      0x086
#define OPC_TLS_DEC_BLOCK       0x087
#define OPC_TLS_ENC_BLOCK       0x088
#define OPC_IPSEC_OUT_TRANSPORT 0x090
#define OPC_IPSEC_OUT_TUNNEL    0x091
#define OPC_IPSEC_IN_TRANSPORT  0x092
#define OPC_IPSEC_IN_TUNNEL     0x093

#define OPC_DH_PUBLIC_KEY       0x001
#define OPC_DH_SHARED_KEY       0x002
#define OPC_RSA_PUBLIC_KEY      0x003
#define OPC_RSA_SHARED_KEY      0x004
#define OPC_DSA_SIGN            0x005
#define OPC_DSA_VERIFY          0x006
#define OPC_RNG_DIRECT          0x041
#define OPC_RNG_SHA             0x042
#define OPC_MOD_ADD             0x043
#define OPC_MOD_SUB             0x044
#define OPC_MOD_MULT            0x045
#define OPC_MOD_REMAINDER       0x046
#define OPC_MOD_EXPONENT        0x047
#define OPC_MOD_INVERSE         0x048
#define OPC_DOUBLE_MOD_EXPONENT 0x049

#define OPC_TLS_ICS             0x201
#define OPC_TLS_PFD             0x202
#define OPC_TLS_CCV             0x203

#define OPC_RNG4_DIRECT         0x301
#define OPC_RNG_FIPS            0x302
    ubyte4            flags:8;

    union {
        SctxTdes_t   tdes;
        ubyte4       d[128];        /* large overlay structure */
    } u;
} CommandCtx_t;

/* Definition for CCH flag */
#define CCF_SCTX_PR     (0x80<<24)
#define CCF_BCT_PR      (0x40<<24)
#define CCF_BDESC_PR    (0x20<<24)
#define CCF_MFM_PR      (0x10<<24)
#define CCF_BD_PR       (0x08<<24)
#define CCF_HASH_PR     (0x04<<24)
#define CCF_SPS_PR      (0x02<<24)
#define CCF_SUPTD_PR    (0x01<<24)

/* Layout for BCM packet descriptor */
typedef struct {
    PhysAddr_t commandCtx;
    Fragment_t input;
    ubyte4     cctxLen:12;
    ubyte4     reserved1:3;
    ubyte4     evict:1;
    ubyte4     pktLen:16;
    Fragment_t output;
} PktDescr2_t;

typedef struct{
    volatile ubyte4      d[128];            /* A simpler form of CCTX */
} CommandCtx2_t;

#define MAX_INPUT_FRAGMENTS     (8)
#define MAX_OUTPUT_FRAGMENTS    (8)

typedef struct {
    ubyte4      numPackets:8;
    ubyte4      expErrorCode:8;
    ubyte4      done:1;
    ubyte4      error:1;
    ubyte4      errPktIndex:8;
    ubyte4      errorCode:5;
    ubyte4      suppresIntr:1;
    PktDescr2_t pktDescr[0];
} Mcr2_t;

struct Command_t;

typedef struct {
    ubyte2 size;
    ubyte  copied;
    ubyte  *userAddr;
    ubyte  *kernelAddr;
} FragmentMem_t;

typedef struct {
    hwAccelDescr           hwAccelCtx;
    struct Command_t*      owner;
    ubyte                  isNewForm;         /* New DMA frag layout */
    ubyte                  isNewOp;           /* CCH/SCTX layout */
    ubyte                  nifrags;
    ubyte                  nofrags;

    ubyte2                 isize;
    ubyte2                 osize;

    ubyte                  opcode;
    ubyte2                 keyLength;

    volatile PktDescr2_t*  pktDescr;
    volatile CommandCtx2_t command;

    /* To store the fragment header list */
    union {
        SFragment_t    ifragTbl[MAX_INPUT_FRAGMENTS-1];
        SFragmentOld_t oifragTbl[MAX_INPUT_FRAGMENTS-1];
    } ui;
    union {
        SFragment_t     ofragTbl[MAX_OUTPUT_FRAGMENTS-1];
        SFragmentOld_t  oofragTbl[MAX_OUTPUT_FRAGMENTS-1];
    } uo;

    /* To store the user space addresses (debug only) */
    FragmentMem_t ifMem[MAX_OUTPUT_FRAGMENTS];
    FragmentMem_t ofMem[MAX_OUTPUT_FRAGMENTS];

} SubCommand_t;

/* Contains the user command definition.  This includes both the MCR
 * and the input/output data.  For small request, the storage is alloc
 * here.  For larger, it maintains pointers to support management
 */
typedef struct Command_t {
    hwAccelDescr    hwAccelCtx;
    ubyte           maxPackets;
    ubyte           usedPackets;
    ubyte           mcrNum;             /* 0-based */
    ubyte           useCount;

    ubyte*          extraData;          /* Attach extra data */
    ubyte2          exdSize;
    ubyte2          exdUse;

    volatile Mcr2_t* mcr;
    SubCommand_t    subCmd[0];
} Command_t;

#define MCR_QSIZE       16

typedef struct {
    ubyte4 reserved:16;
    ubyte4 size:16;
    ubyte4 d[0];
} BufferData_t;

typedef struct ChannelState_t {
    intBoolean isActive;    /* channel is busy, no jobs can be added */
    intBoolean jobsStarted; /* jobs are being handled, but more jobs can potentially be added */

    ubyte4 numJobsPending;
    struct mahCellDescr *pHead;
    struct mahCellDescr *pTail;

    ubyte4 highWater;
    ubyte4 numJobsProcessed;
    ubyte4 channelUsed;
} ChannelState_t;

struct pci_dev;
struct resource;
typedef struct {
    ubyte4         magic;               /* Set to 'ABCD' */
#define DCTL_MAGIC      0x41424344

    ChannelState_t st;

    ubyte2 irq;
    ubyte2 deviceId;
    ubyte4 resource;
    ubyte4 actMcrMask;                  /* Active MCR mask */
    struct resource *mregion;
    struct pci_dev  *pDev;

    ubyte4 intrcount;
    ubyte4 bintrcount;
    ubyte4 fastpolls;

    ubyte4 mcrSent[4];

    union {
        volatile Csr_t  *csr;           /* KernAddr_t */
        volatile ubyte4 *csrw;
    } u;

} DevControl_t;

typedef enum {
  /* Kernel space control code */
  DCOP_RESET = 1,
  DCOP_INTR_ENABLE,
  DCOP_INTR_DISABLE,
  DCOP_WRITE_MCR,
  DCOP_WRITE_MCRPHY,
  DCOP_CHIP_INIT,
  DCOP_DUMP_CSR,

  /* Userland control code */
  DCOP_HNRESET = 0x1000,                /* Don't send to harness */
  DCOP_HNSENDING,                       /* Don't send to harness */
  DCOP_HNDUMP_STATUS,                   /* Dumping status */
  DCOP_END
} DevCtlOp_e;

#define BCER_WARNING    (0x37)

#define BCM_IOC_RESET       (HW_IOCTL_START + 1)
#define BCM_IOC_DUMP        (HW_IOCTL_START + 2)
#define BCM_IOC_SOFT_INTR   (HW_IOCTL_START + 3)
#define BCM_IOC_TIMER_INTR  (HW_IOCTL_START + 4)
#define BCM_IOC_STATS       (HW_IOCTL_START + 5)
#define BCM_IOC_STATS_RESET (HW_IOCTL_START + 6)

#ifdef __cplusplus
}
#endif

#endif
