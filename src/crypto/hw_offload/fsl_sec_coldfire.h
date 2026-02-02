/*
 * fsl_sec_coldfire.h
 *
 * Freescale Security Definitions for Coldfire Processors
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

#ifndef __FSL_SEC_COLDFIRE_HEADER__
#define __FSL_SEC_COLDFIRE_HEADER__

/*------------------------------------------------------------------*/

/*
 * bit 31 is msb
 * bit  0 is lsb
 */


#define OFFSET_MDMR                     (0x190000)
/* Message Digest Hardware Acceleration (MDHA) Mode Register */

#define BIT_MDMR_SSL                    FSL_BIT(10)
/*
 * MDMR (SSL) BIT
 *
 * Secure socket layer MAC. Implements the SSL defined MAC. Only applicable for the MD5
 * algorithm.
 *
 * 0 Do not perform SSL.
 *
 * 1 Perform SSL
 */


#define BIT_MDMR_MACFULL                FSL_BIT(9)
/*
 * MDMR (MACFULL) BIT
 *
 * Message authentication code full. Allows the user to input a key and message data and
 * have the accelerator do the complete MAC in one step. Used directly with HMAC or
 * EHMAC mode.
 *
 * 0 Do not perform MAC FULL.
 *
 * 1 Perform MAC FULL.
 */


#define BIT_MDMR_SWAP                   FSL_BIT(8)
/*
 * MDMR (SWAP) BIT
 *
 * Swap message digest. For SHA-1 only. Swap the output direction of the Message Digest
 * data. The data registers are reversed and byte swapped. This allows for viewing data in
 * the reverse order which might be used by other algorithms. See the table below for an
 * example.
 *
 * 0 Do not perform swap.
 *
 * 1 Swap output direction.
 */


#define BIT_MDMR_OPAD                   FSL_BIT(7)
/*
 * MDMR (OPAD) BIT
 *
 * Outer padding of message. Exlusive OR the message with 0x5C5C_5C5C. Hash used
 * with HMAC. Requires key to be loaded into the FIFO
 *
 * 0 Do not perform padding
 *
 * 1 Perform padding
 */


#define BIT_MDMR_IPAD                   FSL_BIT(6)
/*
 * MDMR (IPAD) BIT
 *
 * Inner padding of message. Exclusive OR the message with 0x3636_3636. Hash used with
 * HMAC. Requires key to be loaded into the FIFO
 *
 * 0 Do not perform padding
 *
 * 1 Perform padding
 */


#define BIT_MDMR_INIT                   FSL_BIT(5)
/*
 * MDMR (INIT) BIT
 *
 * Initialization. Performs algorithm specific initialization of the digest registers. Most
 * operation will require this bit to be set. Only static operations that are continuing from a
 * known intermediate hash value should clear this bit.
 *
 * 0 Do not perform initialization
 *
 * 1 Initialize the selected algorithm�s starting registers
 */


#define VALUE_MDMR_MAC                  FSL_VALUE(4,3)
/*
 * MDMR (MAC) VALUE
 *
 * Message authentication code. Performs message authentication on messages. Requires
 * keys loaded into the context and key registers.
 *
 * 00 Do not perform MAC
 *
 * 01 Perform HMAC
 *
 * 10 Perform EHMAC
 *
 * 11 Reserved
 */


#define BIT_MDMR_PDATA                  FSL_BIT(2)
/*
 * MDMR (PDATA) BIT
 *
 * Pad data bit. Performs automatic message padding on the current partial message block.
 *
 * 0 Do not perform padding
 *
 * 1 Perform padding
 */


#define BIT_MDMR_ALG                    FSL_BIT(0)
/*
 * MDMR (ALG) BIT
 *
 * Algorithm. Selects which algorithm the MDHA module uses
 *
 * 0 Secure Hash Algorithm (SHA-1)
 *
 * 1 Message Digest 5 (MD5)
 */


/*------------------------------------------------------------------*/

#define OFFSET_MDCR                     (0x190004)
/* Message Digest Hardware Acceleration (MDHA) Control Register */

#define BIT_MDCR_IE                     FSL_BIT(0)
/*
 * MDCR (IE) BIT
 *
 * Interrupt enable. Enables/Disables interrupts from the MDHA module.
 *
 * 0 Disable interrupt
 *
 * 1 Enable interrupt
 */


/*------------------------------------------------------------------*/

#define OFFSET_MDCMR                    (0x190008)
/* Message Digest Hardware Acceleration (MDHA) Command Register */

#define BIT_MDCMR_GO                    FSL_BIT(3)
/*
 * MDCMR (GO) BIT
 *
 * Indicates that all data has been loaded into the input FIFO and the module should
 * complete all processing. This bit is self clearing.
 *
 * 0 Do not complete all processing.
 *
 * 1 Finish all processing.
 */


#define BIT_MDCMR_CI                    FSL_BIT(2)
/*
 * MDCMR (CI) BIT
 *
 * Clear IRQ. Clears errors in the MDISR register and deasserts any interrupt requests from
 * the MDHA module. This bit is self clearing.
 *
 * 0 Do not clear interrupts & errors.
 *
 * 1 Clear interrupts & errors.
 */


#define BIT_MDCMR_RI                    FSL_BIT(1)
/*
 * MDCMR (RI) BIT
 *
 * Re-initialize. Re-initializes memory and clears all registers except the MDESM and MDCR.
 *
 * 0 No re-initialization
 *
 * 1 Re-initialize the MDHA module
 */


#define BIT_MDCMR_SWR                   FSL_BIT(0)
/*
 * MDCMR (SWR) BIT
 *
 * Software reset. Resets all registers and re-initialize memory of the MDHA. Functionally
 * equivalent to hardware reset. This bit is self clearing.
 *
 * 0 No reset
 *
 * 1 Software reset
 */


/*------------------------------------------------------------------*/

#define OFFSET_MDSR                     (0x19000c)
/* Message Digest Hardware Acceleration (MDHA) Status Register */

#define VALUE_MDSR_IFL                  FSL_VALUE(23,16)
/*
 * MDSR (IFL) VALUE
 *
 * Input FIFO level. Read-only. The current number of longwords that are in the Input FIFO.
 * IFL will range from 0�16 longwords (0x00-0x10).
 */


#define VALUE_MDSR_APD                  FSL_VALUE(15,13)
/*
 * MDSR (APD) VALUE
 *
 * Auto pad state. Read-only. Indicates the current state of the autopadder for debug
 * purposes.
 *
 * 001 Pad last word.
 *
 * 010 Add a word for padding.
 *
 * 011 Last hash for the EHMAC.
 *
 * 100 Stall state (Auto Padder will pass no data to engine). This is the default state
 * that the module enters whenever there is an error.
 *
 * All other settings are reserved.
 */


#define VALUE_MDSR_FS                   FSL_VALUE(10,8)
/*
 * MDSR (FS) VALUE
 *
 * FIFO size. Read-only. Indicates the size of the internal FIFO, which is fixed at 16 longwords
 * for the MCF5275.
 *
 * 100 16 longwords
 */


#define BIT_MDSR_GNW                    FSL_BIT(7)
/*
 * MDSR (GNW) BIT
 *
 * Get next word. Read-only. Indicates that the MDHA engine has not filled an entire block
 * and is requesting more data.
 *
 * 0 Does not need any data
 *
 * 1 Requesting more data
 */


#define BIT_MDSR_HSH                    FSL_BIT(6)
/*
 * MDSR (HSH) BIT
 *
 * Hashing. Read-only. Indicates that data is currently being hashed
 *
 * 0 Waiting for more data
 *
 * 1 Hashing current data
 */


#define BIT_MDSR_BUSY                   FSL_BIT(4)
/*
 * MDSR (BUSY) BIT
 *
 * Busy. Read-only. Indicates that the module is busy processing data.
 *
 * 0 Idle or done
 *
 * 1 Busy processing data
 */


#define BIT_MDSR_RD                     FSL_BIT(3)
/*
 * MDSR (RD) BIT
 *
 * Reset interrupt. Read-only. Indicates the MDHA module has completed resetting.
 *
 * 0 Reset in progress
 *
 * 1 Completed reset sequence
 */


#define BIT_MDSR_ERR                    FSL_BIT(2)
/*
 * MDSR (ERR) BIT
 *
 * Error interrupt. Read-only. Indicates that an error has occurred. Set if any bit in the MDISR
 * is set.
 *
 * 0 No Error
 *
 * 1 Error has occurred
 */


#define BIT_MDSR_DONE                   FSL_BIT(1)
/*
 * MDSR (DONE) BIT
 *
 * Done interrupt. Read-only. Indicates that the MDHA module has completed processing the
 * requested amount of data.
 *
 * 0 Not complete
 *
 * 1 Done processing
 */


#define BIT_MDSR_INT                    FSL_BIT(0)
/*
 * MDSR (INT) BIT
 *
 * MDHA single interrupt. Read-only. Indicates that either the MDHA module has finished
 * processing the message and the hash result is ready to be read from the message digest
 * register or there is an error.
 *
 * 0 No interrupt
 *
 * 1 Done or error interrupt
 */


/*------------------------------------------------------------------*/

#define OFFSET_MDISR                    (0x190010)
/* Message Digest Hardware Acceleration (MDHA) Interrupt Status Register */

#define BIT_MDISR_GTDS                  FSL_BIT(9)
/*
 * MDISR (GTDS) BIT
 *
 * Greater than data size error. Read only. Indicates that the GO bit was set in
 * the MDCR and the data size written to the MDDSR is greater then the amount of
 * data written to the FIFO.
 *
 * 0 No error
 *
 * 1 Datasize is greater than the message size
 */


#define BIT_MDISR_ERE                   FSL_BIT(8)
/*
 * MDISR (ERE) BIT
 *
 * Early read error. Read only. A context register was read from while the module was busy
 & processing data.
 *
 * 0 No error
 *
 * 1 Early read error
 */


#define BIT_MDISR_RMDP                  FSL_BIT(7)
/*
 * MDISR (RMDP) BIT
 *
 * Register modified during processing. Read only. An MDHA register was modified while the
 * module was busy processing data.
 *
 * 0 No error
 *
 * 1 Register modified
 */


#define BIT_MDISR_DSE                   FSL_BIT(5)
/*
 * MDISR (DSE) BIT
 *
 * Illegal data size. Read only. Illegal data size was written to the MDHA Data Size Register
 * (MDDSR). Data size written into the MDDSR is greater than the allocated size.
 *
 * 0 No error
 *
 * 1 Illegal data size in MDDSR
 */


#define BIT_MDISR_IME                   FSL_BIT(4)
/*
 * MDISR (IME) BIT
 *
 * Illegal mode interrupt. Read only. Illegal mode is set in the MDMR. Consult
 * Section 28.2.1.1, �Invalid Modes,� for more information on invalid modes.
 *
 * 0 No error
 *
 * 1 Illegal value in MDMR
 */


#define BIT_MDISR_NEIF                   FSL_BIT(2)
/*
 * MDISR (NEIF) BIT
 *
 * Non-empty input FIFO upon done. Read only. The Input FIFO contained data when
 * processing was completed
 *
 * 0 No error
 *
 * 1 FIFO contained data when finished processing
 */


#define BIT_MDISR_IFO                   FSL_BIT(0)
/*
 * MDISR (IFO) BIT
 *
 * Input FIFO Overflow. Read only. The Input FIFO has been written to while full.
 *
 * 0 No overflow occurred
 *
 * 1 Input FIFO overflow error
 */


/*------------------------------------------------------------------*/

#define OFFSET_MDIMR                    (0x190014)
/* Message Digest Hardware Acceleration (MDHA) Interrupt Mask Register */

#define BIT_MDIMR_GTDS                  FSL_BIT(9)
/*
 * MDIMR (GTDS) BIT
 *
 * Greater than data size error. Read only. Indicates that the GO bit was set in
 * the MDCR and the data size written to the MDDSR is greater then the amount of
 * data written to the FIFO.
 *
 * 0 No error
 *
 * 1 Datasize is greater than the message size
 */


#define BIT_MDIMR_ERE                   FSL_BIT(8)
/*
 * MDIMR (ERE) BIT
 *
 * Early read error. Read only. A context register was read from while the module was busy
 & processing data.
 *
 * 0 No error
 *
 * 1 Early read error
 */


#define BIT_MDIMR_RMDP                  FSL_BIT(7)
/*
 * MDIMR (RMDP) BIT
 *
 * Register modified during processing. Read only. An MDHA register was modified while the
 * module was busy processing data.
 *
 * 0 No error
 *
 * 1 Register modified
 */


#define BIT_MDIMR_DSE                   FSL_BIT(5)
/*
 * MDIMR (DSE) BIT
 *
 * Illegal data size. Read only. Illegal data size was written to the MDHA Data Size Register
 * (MDDSR). Data size written into the MDDSR is greater than the allocated size.
 *
 * 0 No error
 *
 * 1 Illegal data size in MDDSR
 */


#define BIT_MDIMR_IME                   FSL_BIT(4)
/*
 * MDIMR (IME) BIT
 *
 * Illegal mode interrupt. Read only. Illegal mode is set in the MDMR. Consult
 * Section 28.2.1.1, �Invalid Modes,� for more information on invalid modes.
 *
 * 0 No error
 *
 * 1 Illegal value in MDMR
 */


#define BIT_MDIMR_NEIF                   FSL_BIT(2)
/*
 * MDIMR (NEIF) BIT
 *
 * Non-empty input FIFO upon done. Read only. The Input FIFO contained data when
 * processing was completed
 *
 * 0 No error
 *
 * 1 FIFO contained data when finished processing
 */


#define BIT_MDIMR_IFO                   FSL_BIT(0)
/*
 * MDIMR (IFO) BIT
 *
 * Input FIFO Overflow. Read only. The Input FIFO has been written to while full.
 *
 * 0 No overflow occurred
 *
 * 1 Input FIFO overflow error
 */


/*------------------------------------------------------------------*/

#define OFFSET_MDIN                     (0x190020)
/* Message Digest Hardware Acceleration (MDHA) Input FIFO
 *
 * The MDIN provides temporary storage for data to be used during hashing. The FIFO is a write
 * only register and attempting to read from this register will always return 0. If the FIFO is written
 * to when the FIFO Level is full then an interrupt request is generated and the MDISR[IFO] bit will
 * be set. The MDSR[IFL], described in Section 28.2.4, �MDHA Status Register (MDSR),� can be
 * polled to monitor how many 32-bit longwords are currently resident in the FIFO.
 */

/*------------------------------------------------------------------*/

#define OFFSET_MDA0                     (0x190030)
/* Message Digest Hardware Acceleration (MDHA) Message Digest Register A0
 *
 * The MDHA message digest registers 0 consist of five 32-bit registers (MDA0, MDB0, MDC0,
 * MDD0, and MDE0). These registers store the five (SHA-1) or four (MD5) 32-bit longwords that
 * are the final answer (digest/context) of the hashing process. Message digest data may only be read
 * if the MDSR[DONE] bit is set. Any reads prior to this result is an early read error (MDISR[ERE]).
 * The message digest registers will always return all zeros when an error is generated. Each word
 * (4 bytes) in the MDx0 is assumed to be in little endian byte order for all reads/writes. All
 * corrections will be done internal. This register is cleared when the MDHA is reset or re-initialized.
 * The reset values for the registers are the algorithms defined chaining variable values.
 */

/*------------------------------------------------------------------*/

#define OFFSET_MDB0                     (0x190034)
/* Message Digest Hardware Acceleration (MDHA) Message Digest Register B0
 *
 * The MDHA message digest registers 0 consist of five 32-bit registers (MDA0, MDB0, MDC0,
 * MDD0, and MDE0). These registers store the five (SHA-1) or four (MD5) 32-bit longwords that
 * are the final answer (digest/context) of the hashing process. Message digest data may only be read
 * if the MDSR[DONE] bit is set. Any reads prior to this result is an early read error (MDISR[ERE]).
 * The message digest registers will always return all zeros when an error is generated. Each word
 * (4 bytes) in the MDx0 is assumed to be in little endian byte order for all reads/writes. All
 * corrections will be done internal. This register is cleared when the MDHA is reset or re-initialized.
 * The reset values for the registers are the algorithms defined chaining variable values.
 */


/*------------------------------------------------------------------*/

#define OFFSET_MDC0                     (0x190038)
/* Message Digest Hardware Acceleration (MDHA) Message Digest Register C0
 *
 * The MDHA message digest registers 0 consist of five 32-bit registers (MDA0, MDB0, MDC0,
 * MDD0, and MDE0). These registers store the five (SHA-1) or four (MD5) 32-bit longwords that
 * are the final answer (digest/context) of the hashing process. Message digest data may only be read
 * if the MDSR[DONE] bit is set. Any reads prior to this result is an early read error (MDISR[ERE]).
 * The message digest registers will always return all zeros when an error is generated. Each word
 * (4 bytes) in the MDx0 is assumed to be in little endian byte order for all reads/writes. All
 * corrections will be done internal. This register is cleared when the MDHA is reset or re-initialized.
 * The reset values for the registers are the algorithms defined chaining variable values.
 */


/*------------------------------------------------------------------*/

#define OFFSET_MDD0                     (0x19003c)
/* Message Digest Hardware Acceleration (MDHA) Message Digest Register D0
 *
 * The MDHA message digest registers 0 consist of five 32-bit registers (MDA0, MDB0, MDC0,
 * MDD0, and MDE0). These registers store the five (SHA-1) or four (MD5) 32-bit longwords that
 * are the final answer (digest/context) of the hashing process. Message digest data may only be read
 * if the MDSR[DONE] bit is set. Any reads prior to this result is an early read error (MDISR[ERE]).
 * The message digest registers will always return all zeros when an error is generated. Each word
 * (4 bytes) in the MDx0 is assumed to be in little endian byte order for all reads/writes. All
 * corrections will be done internal. This register is cleared when the MDHA is reset or re-initialized.
 * The reset values for the registers are the algorithms defined chaining variable values.
 */


/*------------------------------------------------------------------*/

#define OFFSET_MDE0                     (0x190040)
/* Message Digest Hardware Acceleration (MDHA) Message Digest Register E0
 *
 * The MDHA message digest registers 0 consist of five 32-bit registers (MDA0, MDB0, MDC0,
 * MDD0, and MDE0). These registers store the five (SHA-1) or four (MD5) 32-bit longwords that
 * are the final answer (digest/context) of the hashing process. Message digest data may only be read
 * if the MDSR[DONE] bit is set. Any reads prior to this result is an early read error (MDISR[ERE]).
 * The message digest registers will always return all zeros when an error is generated. Each word
 * (4 bytes) in the MDx0 is assumed to be in little endian byte order for all reads/writes. All
 * corrections will be done internal. This register is cleared when the MDHA is reset or re-initialized.
 * The reset values for the registers are the algorithms defined chaining variable values.
 */


/*------------------------------------------------------------------*/

#define OFFSET_MDMDS                    (0x190044)
/* Message Digest Hardware Acceleration (MDHA) Message Data Size Register
 *
 * The MDMDS is a 32-bit register which, when read, will store the size of the current hash
 * operation. This register is also used to write in the data size from a resumed hash operation. This
 * data size will be added to the MDDSR to complete the auto pad step.
 */


/*------------------------------------------------------------------*/

#define OFFSET_MDA1                     (0x190070)
/* Message Digest Hardware Acceleration (MDHA) Message Digest Register
 *
 * The MDHA message digest registers 1 consist of five 32-bit digest registers (MDA1, MDB1,
 * MDC1, MDD1, and MDE1). These registers store the OPAD resulted digest to be used for the
 * second hash operation in the HMAC or EHMAC mode. This digest is written directly to the
 * message digest registers 0 after the first hash has been completed. The registers are write only and
 * any attempts to read from them will always return the value zero.
 */


/*------------------------------------------------------------------*/

#define OFFSET_MDB1                     (0x190074)
/* Message Digest Hardware Acceleration (MDHA) Message Digest Register
 *
 * The MDHA message digest registers 1 consist of five 32-bit digest registers (MDA1, MDB1,
 * MDC1, MDD1, and MDE1). These registers store the OPAD resulted digest to be used for the
 * second hash operation in the HMAC or EHMAC mode. This digest is written directly to the
 * message digest registers 0 after the first hash has been completed. The registers are write only and
 * any attempts to read from them will always return the value zero.
 */


/*------------------------------------------------------------------*/

#define OFFSET_MDC1                     (0x190078)
/* Message Digest Hardware Acceleration (MDHA) Message Digest Register
 *
 * The MDHA message digest registers 1 consist of five 32-bit digest registers (MDA1, MDB1,
 * MDC1, MDD1, and MDE1). These registers store the OPAD resulted digest to be used for the
 * second hash operation in the HMAC or EHMAC mode. This digest is written directly to the
 * message digest registers 0 after the first hash has been completed. The registers are write only and
 * any attempts to read from them will always return the value zero.
 */


/*------------------------------------------------------------------*/

#define OFFSET_MDD1                     (0x19007c)
/* Message Digest Hardware Acceleration (MDHA) Message Digest Register
 *
 * The MDHA message digest registers 1 consist of five 32-bit digest registers (MDA1, MDB1,
 * MDC1, MDD1, and MDE1). These registers store the OPAD resulted digest to be used for the
 * second hash operation in the HMAC or EHMAC mode. This digest is written directly to the
 * message digest registers 0 after the first hash has been completed. The registers are write only and
 * any attempts to read from them will always return the value zero.
 */


/*------------------------------------------------------------------*/

#define OFFSET_MDE1                     (0x190080)
/* Message Digest Hardware Acceleration (MDHA) Message Digest Register
 *
 * The MDHA message digest registers 1 consist of five 32-bit digest registers (MDA1, MDB1,
 * MDC1, MDD1, and MDE1). These registers store the OPAD resulted digest to be used for the
 * second hash operation in the HMAC or EHMAC mode. This digest is written directly to the
 * message digest registers 0 after the first hash has been completed. The registers are write only and
 * any attempts to read from them will always return the value zero.
 */


/*------------------------------------------------------------------*/

#define OFFSET_RNGCR                    (0x1a0000)
/* RNG Control Register
 *
 * Immediately following reset, the RNG begins generating entropy in its internal shift registers.
 * Random data is not pushed to the output FIFO until after the GO bit in the RNGCR is set to a one.
 * After this, a random 32-bit word is pushed to the FIFO every 256 cycles. If the FIFO is full, then
 * no push will occur.
 */

#define BIT_RNGCR_CI                    FSL_BIT(3)
/*
 * RNGCR (CI) BIT
 *
 * Clear interrupt. Writing a one to this bit clears the error interrupt and RNGSR[EI].
 *
 * 0 Do not clear error interrupt.
 *
 * 1 Clear error interrupt.
 */


#define BIT_RNGCR_IM                    FSL_BIT(2)
/*
 * RNGCR (IM) BIT
 *
 * Interrupt mask
 *
 * 0 Error interrupt is enabled.
 *
 * 1 Error interrupt is masked.
 */


#define BIT_RNGCR_HA                    FSL_BIT(1)
/*
 * RNGCR (HA) BIT
 *
 * High assurance. Notifies core when FIFO underflow has occurred (FIFO is read while
 * empty). Enables the Security Violation bit in the RNGSR. Bit is sticky and can only be
 * cleared by hardware reset.
 *
 * 0 Disable security violation notification.
 *
 * 1 Enable security violation notification.
 */


#define BIT_RNGCR_GO                    FSL_BIT(0)
/*
 * RNGCR (GO) BIT
 *
 * Go bit. Starts/stops random data from being generated. Bit is sticky and can only be
 * cleared by hardware reset.
 *
 * 0 FIFO is not loaded with random data.
 *
 * 1 FIFO will be loaded with random data.
 */


/*------------------------------------------------------------------*/

#define OFFSET_RNGSR                    (0x1a0004)
/* RNG Status Register */

#define BIT_RNGSR_OFS                   FSL_VALUE(23,16)
/*
 * RNGSR (OFS) BIT
 *
 * Output FIFO size. Indicates size of the Output FIFO (16 words) & maximum possible value
 * of RNGR[OFL].
 */


#define BIT_RNGSR_OFL                   FSL_VALUE(15,8)
/*
 * RNGSR (OFL) BIT
 *
 * Output FIFO level. Indicates current number of random words in the Output FIFO. Used to
 * determine if valid random data is available for reading from the FIFO without causing an
 * underflow condition.
 */


#define BIT_RNGSR_EI                    FSL_BIT(3)
/*
 * RNGSR (EI) BIT
 *
 * Error interrupt. Signals a FIFO underflow. Reset by a write to RNGCR[CI] and not masked
 * by RNGCR[IM].
 *
 * 0 FIFO not read while empty.
 *
 * 1 FIFO read while empy.
 */


#define BIT_RNGSR_FUF                   FSL_BIT(2)
/*
 * RNGSR (FUF) BIT
 *
 * FIFO underflow. Signals FIFO underflow. Reset by reading status register.
 *
 * 0 FIFO not read while empy, since last read of RNGSR.
 *
 * 1 FIFO read while empty, since last read of RNGSR.
 */


#define BIT_RNGSR_LRS                   FSL_BIT(1)
/*
 * RNGSR (LRS) BIT
 *
 * Last read status. Reflects status of most recent read of the FIFO
 *
 * 0 During last read, FIFO was not empty.
 *
 * 1 During last read, FIFO was empy (underflow condition).
 */


#define BIT_RNGSR_SV                    FSL_BIT(0)
/*
 * RNGSR (SV) BIT
 *
 * Security violation. When enabled by RNGCR[HA], signals that a FIFO underflow has
 * occurred. Bit is sticky and is only cleared by hardware reset
 *
 * 0 No violation occurred or RNGCR[HA] is cleared.
 *
 * 1 Security violation (FIFO underflow) has occurred.
 */


/*------------------------------------------------------------------*/

#define OFFSET_RNGER                    (0x1a0008)
/* RNG Entropy Register
 *
 * The RNGER is a write-only register which allows the user to insert entropy into the RNG. This
 * register allows an external user to continually seed the RNG with externally generated random
 * data. Although the use of this register is recommended, it is optional. The RNGER can be written
 * at any time during operation.
 *
 * Each time the RNGER is written, the value is used to update the internal state of the RNG. The
 * update is performed in such a way that the entropy in the RNG�s internal state is preserved. Use of
 * the RNGER can increase the entropy but never decrease it.
 */


/*------------------------------------------------------------------*/

#define OFFSET_RNGOUT                   (0x1a000c)
/* RNG Output FIFO
 *
 * The RNGOUT provides temporary storage for random data generated by the RNG. As long as the
 * FIFO is not empty, a read of this address will return 32 bits of random data. If the FIFO is read
 * when it is empty, Error Interrupt, FIFO Underflow and Last Read bits in the RNGSR will be set.
 * If the interrupt is enabled in the RNGCR an interrupt will be triggered to the interrupt controller.
 * The RNGSR[OFL], described in Section 29.2.2, �RNG Status Register (RNGSR),� can be polled
 * to monitor how many 32-bit words are currently resident in the FIFO. A new random word is
 * pushed into the FIFO every 256 clock cycles (as long as the FIFO is not full). It is very important
 * that the user polls RNGSR[OFL] to make sure random values are present before reading from the
 * FIFO.
 */


/*------------------------------------------------------------------*/

#define OFFSET_SKMR                     (0x1b0000)
/* Symmetric Key Hardware Accelerator (SKHA) Mode Register */

#define VALUE_SKMR_CTRM                 FSL_VALUE(11,8)
/*
 * SKMR (CTRM) VALUE
 *
 * Counter mode modulus. Specifies modulus size for counter mode. In counter mode, the
 * initial counter value will be incremented modulo 2N.
 */


#define BIT_SKMR_DKP                    FSL_BIT(7)
/*
 * SKMR (DKP) BIT
 *
 * Disable key parity check. Disables checking DES parity
 *
 * 0 Check for DES key parity errors
 *
 * 1 Do not check for DES key parity errors
 *
 * Note: A mode error will be generated if this bit is set to one while in AES mode.
 */


#define VALUE_SKMR_CM                   FSL_VALUE(4,3)
/*
 * SKMR (CM) VALUE
 *
 * Cipher mode. Selects the cipher mode.
 *
 * 00 ECB
 *
 * 01 CBC
 *
 * 10 Reserved
 *
 * 11 CTR
 */


#define BIT_SKMR_DIR                    FSL_BIT(2)
/*
 * SKMR (DIR) BIT
 *
 * Direction. Selects encryption or decryption
 *
 * 0 Decrypt
 *
 * 1 Encrypt
 */


#define VALUE_SKMR_ALG                  FSL_VALUE(1,0)
/*
 * SKMR (ALG) VALUE
 *
 * Algorithm. Selects which algorithm the SKHA module uses
 *
 * 00 AES
 *
 * 01 DES
 *
 * 10 3DES
 *
 * 11 Reserved
 */


/*------------------------------------------------------------------*/

#define OFFSET_SKCR                     (0x1b0004)
/* Symmetric Key Hardware Accelerator (SKHA) Control Register */

#define BIT_SKCR_IE                     FSL_BIT(0)
/*
 * SKCR (IE) BIT
 *
 * Interrupt enable.
 *
 * 0 Interrupts disabled
 *
 * 1 Interrupts enabled
 */


/*------------------------------------------------------------------*/

#define OFFSET_SKCMR                    (0x1b0008)
/* Symmetric Key Hardware Accelerator (SKHA) Command Register */

#define BIT_SKCMR_GO                    FSL_BIT(3)
/*
 * SKCMR (GO) BIT
 *
 * Go. Indicates that all data has been loaded into the module and the module should complete
 * all processing. This bit is self resetting.
 *
 * 0 Do not finish processing
 *
 * 1 Complete all processing
 */


#define BIT_SKCMR_CI                    FSL_BIT(2)
/*
 * SKCMR (CI) BIT
 *
 * Clear Interrupt Request. Clears errors in the SKHA error status registers and deasserts any
 * pending interrupt request to the interrupt controller. This bit is self resetting.
 *
 * 0 Do not clear interrupts & errors
 *
 * 1 Clear interrupt requests & errors
 */


#define BIT_SKCMR_RI                    FSL_BIT(1)
/*
 * SKCMR (RI) BIT
 *
 * Reinitialize. Reinitializes memory and clears all registers except SKHA Error Status Mask and
 * Control registers. This bit is self clearing.
 *
 * 0 No Reinitialization
 *
 * 1 Reinitialize SKHA module
 */


#define BIT_SKCMR_SWR                   FSL_BIT(0)
/*
 * SKCMR (SWR) BIT
 *
 * Software Reset. Functionally equivalent to a hardware resert. All registers are reset and
 * FIFOs are cleared. This bit is self clearing.
 *
 * 0 No reset
 *
 * 1 Perform software reset
 */


/*------------------------------------------------------------------*/

#define OFFSET_SKSR                     (0x1b000c)
/* Symmetric Key Hardware Accelerator (SKHA) Status Register
 *
 * The SKSR is read-only and reflects the current state of the SKHA. It also contains the internal state
 * values of the DES and AES state machines for the purposes of debugging. A write to this register
 * has no effect.
 */

#define VALUE_SKSR_OFL                  FSL_VALUE(31,24)
/*
 * SKSR (OFL) VALUE
 *
 * Output FIFO level. This 8-bit value indicates the number of data words in the Output FIFO.
 */


#define VALUE_SKSR_IFL                  FSL_VALUE(23,16)
/*
 * SKSR (IFL) VALUE
 *
 * Input FIFO level. This 8-bit value indicates the number data words in the Input FIFO.
 */


#define VALUE_SKSR_AESES                FSL_VALUE(15,11)
/*
 * SKSR (AESES) VALUE
 *
 * AES engine state. Current value of AES engine state machine (Debug only)
 */


#define VALUE_SKSR_DESES                FSL_VALUE(10,8)
/*
 * SKSR (DESES) VALUE
 *
 * DES engine state. Current value of DES engine state machine (Debug only)
 */


#define BIT_SKSR_BUSY                   FSL_BIT(4)
/*
 * SKSR (BUSY) BIT
 *
 * Busy. Indicates the SKHA is busy. Mode, key data, context, and key size registers may not
 * be modified and context registers may not be read while busy.
 *
 * 0 SKHA idle
 *
 * 1 SKHA busy
 */


#define BIT_SKSR_RD                     FSL_BIT(3)
/*
 * SKSR (RD) BIT
 *
 * Reset done. Indicates if reset of the SKHA module has completed.
 *
 * 0 Reset in progress
 *
 * 1 Reset complete
 */


#define BIT_SKSR_ERR                    FSL_BIT(2)
/*
 * SKSR (ERR) BIT
 *
 * Error interrupt. Indicates that an error has occurred.
 *
 * 0 No error
 *
 * 1 Error occurred
 */


#define BIT_SKSR_DONE                   FSL_BIT(1)
/*
 * SKSR (DONE) BIT
 *
 * Done interrupt. Indicates that the module has finished processing.
 *
 * 0 Not done
 *
 * 1 Done processing
 */


#define BIT_SKSR_INT                    FSL_BIT(0)
/*
 * SKSR (INT) BIT
 *
 * SKHA interrupt. Indicates that the module has finished processing data and the result is
 * ready to be read from the Output FIFO or there is an error. This bit will assert when an
 * interrupt request in generated unless the SKHACR[IE] bit is not set.
 *
 * 0 No interrupt
 *
 * 1 Done or error interrupt
 */


/*------------------------------------------------------------------*/

#define OFFSET_SKESR                    (0x1b0010)
/* Symmetric Key Hardware Accelerator (SKHA) Error Status Register
 *
 * The read-only SKESR indicates the type of error that has occurred. These errors are described
 * below and shown in Table 30-6. When an error occurs, the SKHA engine will halt and assert an
 * interrupt request to the interrupt controller. If multiple errors occur, only the first error will be
 * flagged. The SKHA must be reset when any error occurs. A write to this register has no effect.
 */

#define BIT_SKESR_KRE                   FSL_BIT(10)
/*
 * SKESR (KRE) BIT
 *
 * Key read error. An illegal attempt to read the key registers during processing has been
 * detected.
 *
 * 0 No error
 *
 * 1 Key read error occurred
 */

#define BIT_SKESR_KPE                   FSL_BIT(9)
/*
 * SKESR (KPE) BIT
 *
 * Key parity error. Indicates if a DES key parity error has occurred. Key parity checking can
 * be disabled by setting the SKMR[DKP] bit (See Section 30.2.1.1, �SKHA Mode Register
 * (SKMR).�).
 *
 * 0 No error
 *
 * 1 Key parity error occurred
 */

#define BIT_SKESR_ERE                   FSL_BIT(8)
/*
 * SKESR (ERE) BIT
 *
 * Early read.
 *
 * 0 No error
 *
 * 1 A context register was read from while the module was busy processing data.
 */

#define BIT_SKESR_RMDP                  FSL_BIT(7)
/*
 * SKESR (RMDP) BIT
 *
 * Register modified during processing
 *
 * 0 No error
 *
 * 1 A register was modified during processing
 */

#define BIT_SKESR_KSE                   FSL_BIT(6)
/*
 * SKESR (KSE) BIT
 *
 * Key size Error
 *
 * 0 No error
 *
 * 1 Illegal key size was written into the SKHA key size register
 */

#define BIT_SKESR_DSE                   FSL_BIT(5)
/*
 * SKESR (DSE) BIT
 *
 * Data size error
 *
 * 0 No error
 *
 * 1 Illegal data size was written into the SKHA data size register
 */

#define BIT_SKESR_IME                   FSL_BIT(4)
/*
 * SKESR (IME) BIT
 *
 * Illegal mode error.
 *
 * 0 No error
 *
 * 1 Illegal mode specified
 */

#define BIT_SKESR_NEOF                  FSL_BIT(3)
/*
 * SKESR (NEOF) BIT
 *
 * Non-empty output FIFO upon start.
 *
 * 0 No error
 *
 * 1 Output FIFO contains data upon start of processing
 */

#define BIT_SKESR_NEIF                  FSL_BIT(2)
/*
 * SKESR (NEIF) BIT
 *
 * Non-empty input FIFO upon done.
 *
 * 0 No error
 *
 * 1 Input FIFO contained data when processing was complete
 */

#define BIT_SKESR_OFU                   FSL_BIT(1)
/*
 * SKESR (OFU) BIT
 *
 * Output FIFO underflow
 *
 * 0 No error
 *
 * 1 Output FIFO was read while empty
 */

#define BIT_SKESR_IFO                   FSL_BIT(0)
/*
 * SKESR (IFO) BIT
 *
 * Input FIFO overflow.
 *
 * 0 No error
 *
 * 1 Input FIFO has been written to while full
 */


#endif /* __FSL_SEC_COLDFIRE_HEADER__ */
