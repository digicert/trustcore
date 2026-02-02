/*
 * freescale_8548.h
 *
 * Freescale 8548 Definitions
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

#ifndef __FREESCALE_8548_HEADER__
#define __FREESCALE_8548_HEADER__


/*------------------------------------------------------------------*/

/* Configuration, Control, and Status Register Map (CCSRBAR) */
#ifndef CCSRBAR_ADDRESS
#define CCSRBAR_ADDRESS                 0xe0000000
#endif


/*------------------------------------------------------------------*/

/*
 * bit  0 is msb
 * bit 31 is lsb
 */

/* #define MOC_UL(X)                    X ## UL */
#define MOC_UL(X)                       ((ubyte4)(X))
#define FSL_BIT(X)                      MOC_UL((1 << (31 - (X % 32))))
#define FSL_BIT_16(X)                   MOC_UL((1 << (15 - (X % 16))))
#define FSL_BITS(X,V)                   MOC_UL(((V) << (31 - (X % 32))))

#define FSL_MASK(X,Y)                   MOC_UL((((2 << (31 - (X % 32))) - 1) - ((1 << (31 - (Y % 32))) - 1)))
#define FSL_VALUE(X,Y)                  MOC_UL((((FSL_MASK(X,Y))) >> (31 - (Y % 32))))


#define OFFSET_FETCH_ADRS               0x1148
#define OFFSET_DESCR_BUFS               0x1180


/*------------------------------------------------------------------*/

#define OFFSET_SECBR                    0x101B4
#define OFFSET_SECMR                    0x101BC

/*------------------------------------------------------------------*/

#define INT_EXTERNAL_EXCEPTION          5
#define INT_TIMER                       (-1)    /*!!!*/

/*------------------------------------------------------------------*/

#define EU_SELECT_NONE                  0x0
#define EU_SELECT_AFEU                  0x1
#define EU_SELECT_DEU                   0x2
#define EU_SELECT_MDEU                  0x3
#define EU_SELECT_RNG                   0x4
#define EU_SELECT_PKEU                  0x5
#define EU_SELECT_AESU                  0x6
#define EU_SELECT_MASK                  0xf

#define OP_0_EU_SELECT_OFFSET           3
#define OP_0_EU_SELECT_MASK             FSL_BITS(OP_0_EU_SELECT_OFFSET, EU_SELECT_MASK)
#define OP_1_EU_SELECT_OFFSET           15
#define OP_1_EU_SELECT_MASK             FSL_BITS(OP_1_EU_SELECT_OFFSET, EU_SELECT_MASK)


/*------------------------------------------------------------------*/

#define DPD_HEADER_DN_BIT               FSL_BIT(31)
#define DPD_HEADER_IN_BIT               FSL_BIT(30)


/*------------------------------------------------------------------*/

#define RAND_EU0                        FSL_BITS(OP_0_EU_SELECT_OFFSET, EU_SELECT_RNG)


/*------------------------------------------------------------------*/

/* need to shift right (>>) bits to appropriate location */

#define AESU_EU0                        FSL_BITS(OP_0_EU_SELECT_OFFSET, EU_SELECT_AESU)
#define AES_CBC_MODE                    FSL_BIT(6)

#define AES_ENCRYPT                     FSL_BIT(7)
#define AES_DECRYPT                     0


/*------------------------------------------------------------------*/

/* need to shift right (>>) bits to appropriate location */

#define SDES_EU0                        FSL_BITS(OP_0_EU_SELECT_OFFSET, EU_SELECT_DEU)
#define DES_CBC_MODE                    FSL_BIT(5)

#define DES_ENCRYPT                     FSL_BIT(7)
#define DES_DECRYPT                     0


/*------------------------------------------------------------------*/

/* need to shift right (>>) bits to appropriate location */

#define TDES_EU0                        FSL_BITS(OP_0_EU_SELECT_OFFSET, EU_SELECT_DEU)
#define TDES_CBC_MODE                   (FSL_BIT(5) | FSL_BIT(6))

#define TDES_ENCRYPT                    FSL_BIT(7)
#define TDES_DECRYPT                    0


/*------------------------------------------------------------------*/

/* need to shift right (>>) bits to appropriate location */

#define ARC4_EU0                        FSL_BITS(OP_0_EU_SELECT_OFFSET, EU_SELECT_AFEU)

#define RC4_CS                          FSL_BIT(5)
#define RC4_DC                          FSL_BIT(6)
#define RC4_PP                          FSL_BIT(7)


/*------------------------------------------------------------------*/

/* need to shift right (>>) bits to appropriate location */
#define MDEU_EU0                        FSL_BITS(OP_0_EU_SELECT_OFFSET, EU_SELECT_MDEU)
#define MDEU_EU1                        FSL_BITS(OP_1_EU_SELECT_OFFSET, EU_SELECT_MDEU)

#define MDEU_UPDATE                     FSL_BIT(0)
#define MDEU_FINAL                      0

/*
 * Continue (Cont): Used during HMAC/HASH processing when the data to be hashed is
 * spread across multiple descriptors.
 *
 * 0 Don�t Continue- operate the MDEU in auto completion mode.
 *
 * 1 Preserve context to operate the MDEU in Continuation mode.
 */


#define MDEU_INIT                       FSL_BIT(3)
/*
 * Initialization Bit (INT): Cause an algorithm-specific initialization of the digest registers. Most
 * operations will require this bit to be set. Only static operations that are continuing from a
 * know intermediate hash value would not initialize the registers.
 *
 * 0 Do not initialize
 *
 * 1 Initialize the selected algorithm�s starting registers
 */


#define MDEU_HMAC                       FSL_BIT(4)
/*
 * Identifies the hash operation to execute:
 *
 * 0 Perform standard hash
 *
 * 1 Perform HMAC operation. This requires a key and key length information.
 */


#define MDEU_PAD                        FSL_BIT(5)
/*
 * If set, configures the MDEU to automatically pad partial message blocks.
 *
 * 0 Do not autopad
 *
 * 1 Perform automatic message padding whenever an incomplete message block is
 * detected.
 */


#define MDEU_SHA1                       0
#define MDEU_SHA256                     FSL_BIT(7)
#define MDEU_MD5                        FSL_BIT(6)
/*
 * Message Digest algorithm selection
 * 00 SHA-160 algorithm (full name for SHA-1)
 * 01 SHA-256 algorithm
 * 10 MD5 algorithm
 * 11 Reserved
 */


/*------------------------------------------------------------------*/

#define MD5_INIT                        (MDEU_MD5    | MDEU_INIT                            )
#define MD5_INIT_UPDATE                 (MDEU_MD5    | MDEU_INIT | MDEU_UPDATE              )
#define MD5_UPDATE                      (MDEU_MD5    |             MDEU_UPDATE              )
#define MD5_FINAL                       (MDEU_MD5    |                           MDEU_FINAL )
#define MD5_FINAL_UPDATE                (MDEU_MD5    |             MDEU_UPDATE | MDEU_FINAL )
#define MD5_COMPLETE                    (MDEU_MD5    | MDEU_INIT |               MDEU_FINAL )


#define SHA1_INIT                       (MDEU_SHA1   | MDEU_INIT                            )
#define SHA1_INIT_UPDATE                (MDEU_SHA1   | MDEU_INIT | MDEU_UPDATE              )
#define SHA1_UPDATE                     (MDEU_SHA1   |             MDEU_UPDATE              )
#define SHA1_FINAL                      (MDEU_SHA1   |                           MDEU_FINAL )
#define SHA1_FINAL_UPDATE               (MDEU_SHA1   |             MDEU_UPDATE | MDEU_FINAL )
#define SHA1_COMPLETE                   (MDEU_SHA1   | MDEU_INIT |               MDEU_FINAL )


#define SHA256_INIT                     (MDEU_SHA256 | MDEU_INIT                            )
#define SHA256_INIT_UPDATE              (MDEU_SHA256 | MDEU_INIT | MDEU_UPDATE              )
#define SHA256_UPDATE                   (MDEU_SHA256 |             MDEU_UPDATE              )
#define SHA256_FINAL                    (MDEU_SHA256 |                           MDEU_FINAL )
#define SHA256_COMPLETE                 (MDEU_SHA256 | MDEU_INIT |               MDEU_FINAL )


/*------------------------------------------------------------------*/

#define PKEU_EU0                        FSL_BITS(OP_0_EU_SELECT_OFFSET, EU_SELECT_PKEU)

#define PK_CLEAR_MEM                    FSL_BIT(7)
#define PK_MODEXP                       FSL_BIT(6)
#define PK_MODINV                       FSL_BITS(7, 0x0F)
#define PK_MOD_ADD                      FSL_BITS(7, 0x10)
#define PK_MOD_SUBTRACT                 FSL_BITS(7, 0x20)
#define PK_MOD_MULT1                    FSL_BITS(7, 0x30)
#define PK_MOD_MULT2                    FSL_BITS(7, 0x40)
#define PK_MOD_R2MODN                   FSL_BITS(7, 0x03)


/*------------------------------------------------------------------*/

/* CHANNELS */

/* SEC, 4 Channels */
#define OFFSET_CHANNEL_1                (0x00000100)
#define OFFSET_CHANNEL_2                (0x00000200)
#define OFFSET_CHANNEL_3                (0x00000300)
#define OFFSET_CHANNEL_4                (0x00000400)


/*------------------------------------------------------------------*/

#define OFFSET_ICR                      (0x00001018)
/* Interrupt Clear Register */


#define ICR_ITO                         FSL_BIT(15)
/*
 * ICR (ITO) BIT
 *
 * Internal time out
 *
 * 0 No internal time out
 *
 * 1 An internal time out was detected
 *
 * The internal time out interrupt is triggered by the controller if a slave access to an SEC register
 * does not result in successful data transfer within 16 clock cycles. With ITO enabled the SEC
 * controller terminates the transaction and signals and interrupt.
 */


#define ICR_DONE_OVERFLOW_CH1           FSL_BIT(20)
#define ICR_DONE_OVERFLOW_CH2           FSL_BIT(21)
#define ICR_DONE_OVERFLOW_CH3           FSL_BIT(22)
#define ICR_DONE_OVERFLOW_CH4           FSL_BIT(23)
/*
 * ICR (DONE OVERFLOW) BIT
 *
 * Done overflow
 *
 * 0 No done overflow
 *
 * 1 Done overflow error. Indicates that more than 15 Done interrupts were queued from the
 * interrupting channel without an interrupt clear.
 */


#define ICR_CHA_ERR_CH1                 FSL_BIT(30)
#define ICR_CHA_ERR_CH2                 FSL_BIT(28)
#define ICR_CHA_ERR_CH3                 FSL_BIT(26)
#define ICR_CHA_ERR_CH4                 FSL_BIT(24)
/*
 * ICR (CHA_ERR) BIT
 *
 * Each of the 4 channels has Error & Done bits.
 *
 * 0 No error detected.
 *
 * 1 Error detected. Indicates that execution unit status register must be read to determine exact
 * cause of the error.
 */


#define ICR_CHA_DN_CH1                  FSL_BIT(31)
#define ICR_CHA_DN_CH2                  FSL_BIT(29)
#define ICR_CHA_DN_CH3                  FSL_BIT(27)
#define ICR_CHA_DN_CH4                  FSL_BIT(25)
/*
 * ICR (CHA_DN) BIT
 *
 * Each of the 4 channels has Error & Done bits.
 *
 * 0 Not DONE.
 *
 * 1 DONE bit indicates that the interrupting channel or EU has completed its operation.
 */


#define ICR_PKEU_ERR                    FSL_BIT(42)
/*
 * ICR (PKEU_ERR) BIT
 *
 * The channel has an Error bit.
 *
 * 0 No error detected.
 *
 * 1 Error detected. Indicates that execution unit status register must be read to
 * determine exact cause of the error.
 */


#define ICR_PKEU_DN                     FSL_BIT(43)
/*
 * ICR (PKEU_DN) BIT
 *
 * The channel has a Done bit.
 *
 * 0 Not DONE.
 *
 * 1 DONE bit indicates that the interrupting channel or EU has completed its
 * operation.
 */


#define ICR_RNG_ERR                     FSL_BIT(46)
/*
 * ICR (RNG_ERR) BIT
 *
 * The channel has an Error bit.
 *
 * 0 No error detected.
 *
 * 1 Error detected. Indicates that execution unit status register must be read to
 * determine exact cause of the error.
 */


#define ICR_RNG_DN                      FSL_BIT(47)
/*
 * ICR (RNG_DN) BIT
 *
 * The channel has a Done bit.
 *
 * 0 Not DONE.
 *
 * 1 DONE bit indicates that the interrupting channel or EU has completed its
 * operation.
 */


#define ICR_MDEU_ERR                    FSL_BIT(14)
/*
 * ICR (MDEU_ERR) BIT
 *
 * The channel has an Error bit.
 *
 * 0 No error detected.
 *
 * 1 Error detected. Indicates that execution unit status register must be read to
 * determine exact cause of the error.
 */


#define ICR_MDEU_DN                     FSL_BIT(15)
/*
 * ICR (MDEU_DN) BIT
 *
 * The channel has a Done bit.
 *
 * 0 Not DONE.
 *
 * 1 DONE bit indicates that the interrupting channel or EU has completed its
 * operation.
 */


#define ICR_AFEU_ERR                    FSL_BIT(50)
/*
 * ICR (AFEU_ERR) BIT
 *
 * The channel has an Error bit.
 *
 * 0 No error detected.
 *
 * 1 Error detected. Indicates that execution unit status register must be read to
 * determine exact cause of the error.
 */


#define ICR_AFEU_DN                     FSL_BIT(51)
/*
 * ICR (AFEU_DN) BIT
 *
 * The channel has a Done bit.
 *
 * 0 Not DONE.
 *
 * 1 DONE bit indicates that the interrupting channel or EU has completed its
 * operation.
 */


#define ICR_AESU_ERR                    FSL_BIT(58)
/*
 * ICR (AESU_ERR) BIT
 *
 * The channel has an Error bit.
 *
 * 0 No error detected.
 *
 * 1 Error detected. Indicates that execution unit status register must be read to
 * determine exact cause of the error.
 */


#define ICR_AESU_DN                     FSL_BIT(59)
/*
 * ICR (AESU_DN) BIT
 *
 * The channel has a Done bit.
 *
 * 0 Not DONE.
 *
 * 1 DONE bit indicates that the interrupting channel or EU has completed its
 * operation.
 */


#define ICR_DEU_ERR                     FSL_BIT(62)
/*
 * ICR (DEU_ERR) BIT
 *
 * The channel has an Error bit.
 *
 * 0 No error detected.
 *
 * 1 Error detected. Indicates that execution unit status register must be read to
 * determine exact cause of the error.
 */


#define ICR_DEU_DN                      FSL_BIT(63)
/*
 * ICR (DEU_DN) BIT
 *
 * The channel has a Done bit.
 *
 * 0 Not DONE.
 *
 * 1 DONE bit indicates that the interrupting channel or EU has completed its
 * operation.
 */


/*------------------------------------------------------------------*/

#define OFFSET_ID_LO32                 (0x00001020)
#define OFFSET_ID_HI32                 (0x00001024)
/* ID Register */


#define VALUE_ID_VERSION                FSL_VALUE(57,63)
/*
 * ID (VERSION) VALUE
 *
 * The Read-Only ID Register, displayed in Figure 51-7, contains a 32-bit value that uniquely
 * identifies the version of the SEC Lite. The value of this register is always 0x0000_0040.
 */


/*------------------------------------------------------------------*/

#define OFFSET_MCR_LO32                 (0x00001030)
#define OFFSET_MCR_HI32                 (0x00001034)
/* Master Control Register */


#define MCR_SWR                         FSL_BIT(31)
/*
 * MCR (SWR) BIT
 *
 * Software Reset. Writing 1 to this bit will cause a global software reset.
 * Upon completion of the reset, this bit will be automatically cleared.
 *
 * 0 Don�t reset
 *
 * 1 Global Reset
 */


/*------------------------------------------------------------------*/

#define OFFSET_CCCR_LO32                (0x00001108)
#define OFFSET_CCCR_HI32                (0x0000110c)

#define OFFSET_CCCR_LO32_1              (0x00001008 + OFFSET_CHANNEL_1)
#define OFFSET_CCCR_HI32_1              (0x0000100c + OFFSET_CHANNEL_1)

#define OFFSET_CCCR_LO32_2              (0x00001008 + OFFSET_CHANNEL_2)
#define OFFSET_CCCR_HI32_2              (0x0000100c + OFFSET_CHANNEL_2)

#define OFFSET_CCCR_LO32_3              (0x00001008 + OFFSET_CHANNEL_3)
#define OFFSET_CCCR_HI32_3              (0x0000100c + OFFSET_CHANNEL_3)

#define OFFSET_CCCR_LO32_4              (0x00001008 + OFFSET_CHANNEL_4)
#define OFFSET_CCCR_HI32_4              (0x0000100c + OFFSET_CHANNEL_4)
/* Crypto-Channel Configuration Register */


#define BIT_CCCR_CON                    FSL_BIT(30)
/*
 * CCCR (CON) BIT
 *
 * Continue bit
 *
 * 0 No special action.
 *
 * 1 Causes the same channel reset actions as bit R, except that the fetch FIFO and the lower half of
 * the CCR register are not cleared. After the reset sequence is complete, this bit automatically
 * returns to 0 and the channel resumes normal operation, servicing the next descriptor pointer in
 * the fetch FIFO, if any.
 */


#define BIT_CCCR_R                      FSL_BIT(31)
/*
 * CCCR (R) BIT
 *
 * Reset channel
 *
 * 0 No special action.
 *
 * 1 Causes a software reset of the channel, clearing all its internal state. The details of the software
 * reset actions depend upon what the channel is doing when the bit is set:
 * If the R bit is set while the channel is requesting an EU assignment from the controller, the channel
 * cancels its request by asserting the release output signals. The channel then resets all its registers,
 * clears the R bit, and return the channel state machine to the idle state.
 * If the R bit is set after the channel has been assigned an EU, the channel requests a write from the
 * controller to set the software reset bit of the EU. If a secondary EU has been reserved, the channel
 * requests a write to reset that EU as well. The channel next asserts the appropriate release signal to
 * notify the controller that the channel has finished with the reserved EU(s). The channel then resets
 * all the registers, clears the RESET bit and returns the channel state machine to the idle state.
 */


#define BIT_CCCR_BS                     FSL_BIT(55)
/*
 * CCCR (BS) BIT
 *
 * Burst size. The SEC accesses long text-data parcels in main memory through bursts of
 * programmable size:
 *
 * 0 Burst size is 64 bytes
 *
 * 1 Burst size is 128 bytes
 */


#define BIT_CCCR_CDWE                   FSL_BIT(59)
/*
 * CCCR (CDWE) BIT
 *
 * Channel done writeback enable:
 *
 * 0 Channel done writeback disabled.
 *
 * 1 Channel done writeback enabled. Upon completion of descriptor processing, if the NT bit is set
 * for global, or if the DN (done notification) bit is set in the header word of the descriptor, then notify
 * the host by writing back the descriptor header with 0xFF in bits 0-7. This enables the host to poll
 * the memory location of the original descriptor header to determine if that descriptor has been
 * completed.
 */


#define BIT_CCCR_NT                     FSL_BIT(61)
/*
 * CCCR (NT) BIT
 *
 * Notification type. Channel DONE notification type. This bit controls when the crypto-channel will
 * generate channel DONE notification. Channel DONE notification can take the form of an interrupt or
 * modified header writeback or both, depending on the state of the CDIE and WE control bits.
 *
 * 0 Global: The crypto-channel will generate channel done notification (if enabled) at the end of each
 * descriptor.
 *
 * 1 Done bit: The crypto-channel will generate channel done notification (if enabled) at the end of
 * every descriptor with the Done bit set in the descriptor header.
 */


#define BIT_CCCR_CDIE                   FSL_BIT(62)
/*
 * CCCR (CDIE) BIT
 *
 * Channel done interrupt enable
 *
 * 0 Channel done interrupt disabled
 *
 * 1 Channel done interrupt enabled. Upon completion of descriptor processing, if the NT bit is set for
 * global, or if the DN (done notification) bit is set in the header word of the descriptor, then notify the
 * host by asserting an interrupt.
 */


/*------------------------------------------------------------------*/

/* SEC Lite, 1 Channel */
#define OFFSET_CCPSR_1                  (0x00001110)
/* Crypto-Channel Pointer Status Register 1 */

/* SEC, 4 Channels */
#define OFFSET_CHANNEL_CCPSR_1          (0x00000010)

#define OFFSET_CCPSR1_1                 (OFFSET_CHANNEL_1 + OFFSET_CHANNEL_CCPSR_1)
/* Channel 1 CCPSR MSW */
#define OFFSET_CCPSR2_1                 (OFFSET_CHANNEL_2 + OFFSET_CHANNEL_CCPSR_1)
/* Channel 2 CCPSR MSW */
#define OFFSET_CCPSR3_1                 (OFFSET_CHANNEL_3 + OFFSET_CHANNEL_CCPSR_1)
/* Channel 3 CCPSR MSW */
#define OFFSET_CCPSR4_1                 (OFFSET_CHANNEL_4 + OFFSET_CHANNEL_CCPSR_1)
/* Channel 4 CCPSR MSW */


#define MASK_CCPSR_STATE                FSL_MASK(24,31)
/*
 * CCPSR (STATE) MASK
 *
 * State of the crypto-channel state machine. This field reflects the state of
 * the crypto-channel control state machine. The value of this field
 * indicates exactly which stage the crypto-channel is in the sequence of
 * fetching and processing data descriptors. Table 50-5 shows the
 * meaning of all possible values of the STATE field.
 * Note: State is documented for information only. The user will not
 * typically care about the crypto-channel state machine.
 */


/*------------------------------------------------------------------*/

/* SEC Lite, 1 Channel */
#define OFFSET_CCPSR_2                  (0x00001210)
/* Crypto-Channel Pointer Status Register 2 */

/* SEC, 4 Channels */
#define OFFSET_CHANNEL_CCPSR_2          (0x00000014)

#define OFFSET_CCPSR1_2                 (OFFSET_CHANNEL_1 + OFFSET_CHANNEL_CCPSR_2)
/* Channel 1 CCPSR LSW */
#define OFFSET_CCPSR2_2                 (OFFSET_CHANNEL_2 + OFFSET_CHANNEL_CCPSR_2)
/* Channel 2 CCPSR LSW */
#define OFFSET_CCPSR3_2                 (OFFSET_CHANNEL_3 + OFFSET_CHANNEL_CCPSR_2)
/* Channel 3 CCPSR LSW */
#define OFFSET_CCPSR4_2                 (OFFSET_CHANNEL_4 + OFFSET_CHANNEL_CCPSR_2)
/* Channel 4 CCPSR LSW */

#define BIT_CCPSR_STATIC                FSL_BIT(5)
/*
 * CCPSR (STATIC) BIT
 *
 * Crypto-channel static mode enable.
 *
 * 0 Crypto-channel is operating in dynamic mode.
 *
 * 1 Crypto-channel is operating in static mode.
 *
 * The STATIC bit is set when descriptor processing is initiated and the
 * EUs indicated in the descriptor header register are already assigned to
 * the channel. This bit is cleared when descriptor processing is initiated
 * for the next descriptor and no EUs are assigned to the channel.
 */


#define BIT_CCPSR_MULTI_EU_IN           FSL_BIT(6)
/*
 * CCPSR (Multi_EU_IN) BIT
 *
 * If enabled, the secondary assigned EU will receive the same data as the
 * primary assigned EU.
 *
 * 0 Data input snooping by secondary EU disabled.
 *
 * 1 Data input snooping by secondary EU enabled.
 */


#define BIT_CCPSR_MULTI_EU_OUT          FSL_BIT(7)
/*
 * CCPSR (Multi_EU_OUT) BIT
 *
 * If enabled, the secondary assigned EU will received data generated as
 * output by the primary assigned EU.
 *
 * 0 Data output snooping by secondary EU disabled.
 *
 * 1 Data output snooping by secondary EU enabled.
 */


#define BIT_CCPSR_PRI_REQ               FSL_BIT(8)
/*
 * CCPSR (PRI_REQ) BIT
 *
 * Request primary EU assignment.
 *
 * 0 Primary EU assignment request is inactive.
 *
 * 1 The crypto-channel is requesting assignment of primary EU to the
 * channel. The channel will assert the EU request signal indicated by
 * the op0 field in the Descriptor Header register as long as this bit
 * remains set.
 *
 * The PRI_REQ bit is set when descriptor processing is initiated in
 * dynamic mode and the Op_0 field in the descriptor header contains a
 * valid EU identifier. This bit is cleared when the request is granted, which
 * will be reflected in the status register by the setting the PRI_GRANT bit.
 */


#define BIT_CCPSR_SEC_REQ               FSL_BIT(9)
/*
 * CCPSR (SEC_REQ) BIT
 *
 * Request secondary EU assignment.
 *
 * 0 Secondary EU assignment request is inactive.
 *
 * 1 The crypto-channel is requesting assignment of secondary EU to the
 * channel. The channel will assert the EU request signal indicated by
 * the Op_1 field in the descriptor header register as long as this bit
 * remains set.
 *
 * The SEC_REQ bit is set when descriptor processing is initiated in
 * dynamic mode and the Op_1 field in the descriptor header contains a
 * valid EU identifier. This bit is cleared when the request is granted, which
 * will be reflected in the status register by the setting the SEC_GRANT bit.
 */


#define BIT_CCPSR_PRI_GRANT             FSL_BIT(10)
/*
 * CCPSR (PRI_GRANT) BIT
 *
 * Primary EU granted. The PRI_GRANT bit reflects the state of the EU
 * grant signal for the requested primary EU from the controller.
 *
 * 0 The primary EU grant signal is inactive.
 *
 * 1 The EU grant signal is active indicating the controller has assigned the
 * requested primary EU to the channel.
 */


#define BIT_CCPSR_SEC_GRANT             FSL_BIT(11)
/*
 * CCPSR (SEC_GRANT) BIT
 *
 * Secondary EU granted. The SEC_GRANT bit reflects the state of the
 * EU grant signal for the requested secondary EU from the controller.
 *
 * 0 The secondary EU grant signal is inactive.
 *
 * 1 The EU grant signal is active indicating the controller has assigned the
 * requested secondary EU to the channel.
 */


#define BIT_CCPSR_PRI_RESET_DONE        FSL_BIT(12)
/*
 * CCPSR (PRI_RESET_DONE) BIT
 *
 * Primary EU reset done. The PRI_RST_DONE bit reflects the state of
 * the reset done signal from the assigned primary EU.
 *
 * 0 The assigned primary EU reset done signal is inactive.
 *
 * 1 The assigned primary EU reset done signal is active indicating its
 * reset sequence has completed and it is ready to accept data.
 */


#define BIT_CCPSR_SEC_RESET_DONE        FSL_BIT(13)
/*
 * CCPSR (SEC_RESET_DONE) BIT
 *
 * Secondary EU reset done. The SEC_RST_DONE bit reflects the state
 * of the reset done signal from the assigned secondary EU.
 *
 * 0 The assigned secondary EU reset done signal is inactive.
 *
 * 1 The assigned secondary EU reset done signal is active indicating its
 * reset sequence has completed and it is ready to accept data.
 */


#define BIT_CCPSR_PRI_DONE              FSL_BIT(14)
/*
 * CCPSR (PRI_DONE) BIT
 *
 * Primary EU done. The PRI_DONE bit reflects the state of the done
 * interrupt from the assigned primary EU.
 *
 * 0 The assigned primary EU done interrupt is inactive.
 *
 * 1 The assigned primary EU done interrupt is active indicating the EU
 * has completed processing and is ready to provide output data.
 */


#define BIT_CCPSR_SEC_DONE              FSL_BIT(15)
/*
 * CCPSR (SEC_DONE) BIT
 *
 * Secondary EU done. The SEC_DONE bit reflects the state of the done
 * interrupt from the assigned secondary EU.
 *
 * 0 The assigned secondary EU done interrupt is inactive.
 *
 * 1 The assigned secondary EU done interrupt is active indicating the EU
 * has completed processing and is ready to provide output data.
 */


#define VALUE_CCPSR_ERROR               FSL_VALUE(16,23)
/*
 * CCPSR (ERROR) BITS
 *
 * Crypto-channel error status. This field reflects the error status of the
 * crypto-channel. When a channel error interrupt is generated, this field
 * will reflect the source of the error. The bits in the ERROR field are
 * registered at specific stages in the descriptor processing flow. Once
 * registered, an error can only be cleared only by resetting the
 * crypto-channel or writing the appropriate registers to initiate the
 * processing of a new descriptor.
 *
 * Table 50-6 lists the conditions which can cause a crypto-channel error
 * and how they are represented in the ERROR field.
 */


#define VALUE_CCPSR_PAIR_PTR            FSL_VALUE(24,31)
/*
 * CCPSR (PAIR_PTR) BITS
 *
 * Descriptor buffer register length/pointer pair. This field indicates which
 * of the length/pointer pairs are currently being processed by the channel.
 *
 * Table 50-7 shows the meaning of all possible values of the PAIR_PTR
 * field.
 */


/*------------------------------------------------------------------*/

/* SEC Lite, 1 Channel */
#define OFFSET_CDPR                     (0x00001040)
/* Crypto-Channel Current Descriptor Pointer Register */

#define OFFSET_CDPR1                    (OFFSET_CHANNEL_1 + OFFSET_CDPR)
#define OFFSET_CDPR2                    (OFFSET_CHANNEL_2 + OFFSET_CDPR)
#define OFFSET_CDPR3                    (OFFSET_CHANNEL_3 + OFFSET_CDPR)
#define OFFSET_CDPR4                    (OFFSET_CHANNEL_4 + OFFSET_CDPR)

/* Pointer to system memory location of the current descriptor. This field
 * reflects the starting location in system memory of the descriptor currently
 * loaded into the DB. This value is updated whenever the crypto-channel
 * requests a fetch of a descriptor from the controller. Either the value of the
 * fetch register or of word 16 of the DB is transferred to the current
 * descriptor pointer register immediately after the fetch is completed.
 * This address will be used as destination of the write back of the modified
 * header word, if header write back notification is enabled. If a descriptor
 * is written directly into the descriptor buffer, the host is responsible for
 * writing a meaningful pointer value into the
 * CURRENT_DESCRIPTOR_POINTER field.
 */


/*------------------------------------------------------------------*/

/* SEC Lite, 1 Channel */
#define OFFSET_FR                       (0x00002048)
/* Fetch Register */


#define FETCH_ADRS                      (0x00002048)
/* Pointer to system memory location of a descriptor the host wants the SEC Lite to fetch.*/


/* SEC, 4 Channels */
#define OFFSET_CHANNEL_FR               (0x0000004C)

#define OFFSET_FR1                      (OFFSET_CHANNEL_1 + OFFSET_CHANNEL_FR)
/* Channel 1 FR */
#define OFFSET_FR2                      (OFFSET_CHANNEL_2 + OFFSET_CHANNEL_FR)
/* Channel 2 FR */
#define OFFSET_FR3                      (OFFSET_CHANNEL_3 + OFFSET_CHANNEL_FR)
/* Channel 3 FR */
#define OFFSET_FR4                      (OFFSET_CHANNEL_4 + OFFSET_CHANNEL_FR)
/* Channel 4 FR */

#define CH1_FETCH_ADRS                  (OFFSET_FR1)
#define CH2_FETCH_ADRS                  (OFFSET_FR2)
#define CH3_FETCH_ADRS                  (OFFSET_FR3)
#define CH4_FETCH_ADRS                  (OFFSET_FR4)


/*------------------------------------------------------------------*/

#define OFFSET_IMR                      (0x00001008)
/* Interrupt Mask Register 1 */

#define IMR_ITO                         FSL_BIT(15)
/*
 * Internal time out
 *
 * 0 No internal time out
 *
 * 1 An internal time out was detected
 * The internal time out interrupt is triggered by the controller if a slave access to an SEC register
 * does not result in successful data transfer within 16 clock cycles. With ITO enabled the SEC
 * controller terminates the transaction and signals and interrupt.*
 */

#define IMR_CHA_DONE_OVERFLOW1          FSL_BIT(23)
#define IMR_CHA_DONE_OVERFLOW2          FSL_BIT(22)
#define IMR_CHA_DONE_OVERFLOW3          FSL_BIT(21)
#define IMR_CHA_DONE_OVERFLOW4          FSL_BIT(20)
/*
 * Done overflow
 *
 * 0 No done overflow
 *
 * 1 Done overflow error. Indicates that more than 15 Done interrupts were queued from the
 * interrupting channel without an interrupt clear.
 */

#define IMR_CHA_ERR_CH1                 FSL_BIT(30)
#define IMR_CHA_ERR_CH2                 FSL_BIT(28)
#define IMR_CHA_ERR_CH3                 FSL_BIT(26)
#define IMR_CHA_ERR_CH4                 FSL_BIT(24)
/*
 * IMR (CHA_ERR) BIT
 *
 * The channel has an Error bit.
 *
 * 0 No error detected.
 *
 * 1 Error detected. Indicates that execution unit status register must be read to
 * determine exact cause of the error.
 */

#define IMR_CHA_DN_CH1                  FSL_BIT(31)
#define IMR_CHA_DN_CH2                  FSL_BIT(29)
#define IMR_CHA_DN_CH3                  FSL_BIT(27)
#define IMR_CHA_DN_CH4                  FSL_BIT(25)
/*
 * IMR (CHA_DN) BIT
 *
 * The channel has a Done bit.
 *
 * 0 Not DONE.
 *
 * 1 DONE bit indicates that the interrupting channel or EU has completed its
 * operation.
 */


/*------------------------------------------------------------------*/

#define OFFSET_IMR_2                    (0x0000100c)
/* Interrupt Mask Register 2 */


#define IMR_2_MDEU_ERR                  FSL_BIT(14)
/*
 * IMR (MDEU_ERR) BIT
 *
 * The channel has an Error bit.
 *
 * 0 No error detected.
 *
 * 1 Error detected. Indicates that execution unit status register must be read to
 * determine exact cause of the error.
 */


#define IMR_2_MDEU_DN                   FSL_BIT(15)
/*
 * IMR (MDEU_DN) BIT
 *
 * The channel has a Done bit.
 *
 * 0 Not DONE.
 *
 * 1 DONE bit indicates that the interrupting channel or EU has completed its
 * operation.
 */


#define IMR_2_AESU_ERR                  FSL_BIT(18)
/*
 * IMR (AESU_ERR) BIT
 *
 * The channel has an Error bit.
 *
 * 0 No error detected.
 *
 * 1 Error detected. Indicates that execution unit status register must be read to
 * determine exact cause of the error.
 */


#define IMR_2_AESU_DN                   FSL_BIT(19)
/*
 * IMR (AESU_DN) BIT
 *
 * The channel has a Done bit.
 *
 * 0 Not DONE.
 *
 * 1 DONE bit indicates that the interrupting channel or EU has completed its
 * operation.
 */


#define IMR_2_DEU_ERR                   FSL_BIT(22)
/*
 * IMR (DEU_ERR) BIT
 *
 * The channel has an Error bit.
 *
 * 0 No error detected.
 *
 * 1 Error detected. Indicates that execution unit status register must be read to
 * determine exact cause of the error.
 */


#define IMR_2_DEU_DN                    FSL_BIT(23)
/*
 * IMR (DEU_DN) BIT
 *
 * The channel has a Done bit.
 *
 * 0 Not DONE.
 *
 * 1 DONE bit indicates that the interrupting channel or EU has completed its
 * operation.
 */

#define IMR_2_TEA                       FSL_BIT(25)
/*
 * IMR (TEA) BIT
 *
 * Transfer Error Acknowledge. Set when the SEC Lite as a master receives a
 * Transfer Error Acknowledge.
 *
 * 0 No error detected.
 *
 * 1 TEA detected on bus.
 */


/*------------------------------------------------------------------*/

#define OFFSET_ISR                      (0x00001010)
/* Interrupt Status Register */

#define ISR_ITO                         FSL_BIT(15)
/*
 * Internal time out
 *
 * 0 No internal time out
 *
 * 1 An internal time out was detected
 * The internal time out interrupt is triggered by the controller if a slave access to an SEC register
 * does not result in successful data transfer within 16 clock cycles. With ITO enabled the SEC
 * controller terminates the transaction and signals and interrupt.*
 */

#define ISR_CHA_DONE_OVERFLOW1          FSL_BIT(23)
#define ISR_CHA_DONE_OVERFLOW2          FSL_BIT(22)
#define ISR_CHA_DONE_OVERFLOW3          FSL_BIT(21)
#define ISR_CHA_DONE_OVERFLOW4          FSL_BIT(20)
/*
 * Done overflow
 *
 * 0 No done overflow
 *
 * 1 Done overflow error. Indicates that more than 15 Done interrupts were queued from the
 * interrupting channel without an interrupt clear.
 */

#define ISR_CHA_ERR_CH1                 FSL_BIT(30)
#define ISR_CHA_ERR_CH2                 FSL_BIT(28)
#define ISR_CHA_ERR_CH3                 FSL_BIT(26)
#define ISR_CHA_ERR_CH4                 FSL_BIT(24)
/*
 * ISR (CHA_ERR) BIT
 *
 * The channel has an Error bit.
 *
 * 0 No error detected.
 *
 * 1 Error detected. Indicates that execution unit status register must be read to
 * determine exact cause of the error.
 */

#define ISR_CHA_DN_CH1                  FSL_BIT(31)
#define ISR_CHA_DN_CH2                  FSL_BIT(29)
#define ISR_CHA_DN_CH3                  FSL_BIT(27)
#define ISR_CHA_DN_CH4                  FSL_BIT(25)
/*
 * IMR (CHA_DN) BIT
 *
 * The channel has a Done bit.
 *
 * 0 Not DONE.
 *
 * 1 DONE bit indicates that the interrupting channel or EU has completed its
 * operation.
 */


/*------------------------------------------------------------------*/

#define OFFSET_ISR_2                    (0x00001014)
/* Interrupt Status Register 2 */


#define ISR_2_MDEU_ERR                  FSL_BIT(14)
/*
 * ISR (MDEU_ERR) BIT
 *
 * The channel has an Error bit.
 *
 * 0 No error detected.
 *
 * 1 Error detected. Indicates that execution unit status register must be read to
 * determine exact cause of the error.
 */


#define ISR_2_MDEU_DN                   FSL_BIT(15)
/*
 * ISR (MDEU_DN) BIT
 *
 * The channel has a Done bit.
 *
 * 0 Not DONE.
 *
 * 1 DONE bit indicates that the interrupting channel or EU has completed its
 * operation.
 */


#define ISR_2_AESU_ERR                  FSL_BIT(18)
/*
 * ISR (AESU_ERR) BIT
 *
 * The channel has an Error bit.
 *
 * 0 No error detected.
 *
 * 1 Error detected. Indicates that execution unit status register must be read to
 * determine exact cause of the error.
 */


#define ISR_2_AESU_DN                   FSL_BIT(19)
/*
 * ISR (AESU_DN) BIT
 *
 * The channel has a Done bit.
 *
 * 0 Not DONE.
 *
 * 1 DONE bit indicates that the interrupting channel or EU has completed its
 * operation.
 */


#define ISR_2_DEU_ERR                   FSL_BIT(22)
/*
 * ISR (DEU_ERR) BIT
 *
 * The channel has an Error bit.
 *
 * 0 No error detected.
 *
 * 1 Error detected. Indicates that execution unit status register must be read to
 * determine exact cause of the error.
 */


#define ISR_2_DEU_DN                    FSL_BIT(23)
/*
 * ISR (DEU_DN) BIT
 *
 * The channel has a Done bit.
 *
 * 0 Not DONE.
 *
 * 1 DONE bit indicates that the interrupting channel or EU has completed its
 * operation.
 */

#define ISR_2_TEA                       FSL_BIT(25)
/*
 * ISR (TEA) BIT
 *
 * Transfer Error Acknowledge. Set when the SEC Lite as a master receives a
 * Transfer Error Acknowledge.
 *
 * 0 No error detected.
 *
 * 1 TEA detected on bus.
 */


/*------------------------------------------------------------------*/

#define OFFSET_CPTR                     (0x00000adc)
/* Communications Processor Timing Register */


#define CPTR_SEC_INT                    FSL_VALUE(16,18)
/*
 * CPTR (SEC_INT) VALUE
 *
 * SEC Lite Interrupt Level
 * 000 Level 0
 * 001 Level 1
 * 010 Level 2
 * 011 Level 3
 * 100 Level 4
 * 101 Level 5
 * 110 Level 6
 * 111 Level 7
 */


#define CPTR_SEC_BO                     FSL_BIT(19)
/*
 * CPTR (SEC_BO) BIT
 *
 * SEC Lite Byte Order
 *
 * 0 Big endian
 * 1 Little endian
 */


#define CPTR_SEC_AT1_AT3                FSL_VALUE(20,22)
/*
 * CPTR (SEC_AT1_AT3) VALUE
 *
 * SEC Lite Address Type AT1-3 --- the function code used during bus access (AT0 is
 * driven with a 1 to identify a DMA type access)
 */


#define CPTR_FEC1                       FSL_BIT(23)
/*
 * CPTR (FEC1) BIT
 *
 * RMII/MII1 interface mode
 *
 * 0 FEC1 MII interface (and RMII logic reset)
 * 1 FEC1 RMII interface.
 */


#define CPTR_FEC2                       FSL_BIT(24)
/*
 * CPTR (FEC2) BIT
 *
 * RMII/MII2 interface mode
 *
 * 0 FEC2 MII interface (and RMII logic reset)
 * 1 FEC2 RMII interface.
 */


#define CPTR_1TCI                       FSL_BIT(25)
/*
 * CPTR (1TCI) BIT
 *
 * RMII1 Transmit Clock Invert
 *
 * 0 normal mode
 * 1 FEC1 RMII internal transmit clock is inverted before it is used
 */


#define CPTR_2TCI                       FSL_BIT(26)
/*
 * CPTR (2TCI) BIT
 *
 * RMII2 Transmit Clock Invert
 *
 * 0 normal mode
 * 1 FEC2 RMII internal transmit clock is inverted before it is used
 */


#define CPTR_RE1                        FSL_BIT(27)
/*
 * CPTR (RE1) BIT
 *
 * RMII1 rate (for 50 Mhz input clock from external oscillator)
 *
 * 0 FEC1 works in 100M mode fast Ethernet)
 * 1 FEC1 works in 10M mode
 */


#define CPTR_RE2                        FSL_BIT(28)
/*
 * CPTR (RE2) BIT
 *
 * RMII2 rate (for 50 Mhz input clock from external oscillator)
 *
 * 0 FEC2 works in 100M mode (fast Ethernet)
 * 1 FEC2 works in 10M mode
 */


/*------------------------------------------------------------------*/

/*
 * This section may need to be expanded. This is enough to reset the
 * EUs.
 */

#define DEURCR                          0x02018
#define AESURCR                         0x04018
#define MDEURCR                         0x06018
#define AFEURCR                         0x08018
#define RNGRCR                          0x0a018
#define PKEURCR                         0x0c018

#define DEUICR                          0x02038
#define AESUICR                         0x04038
#define MDEUICR                         0x06038
#define AFEUICR                         0x08038
#define RNGICR                          0x0a038
#define PKEUICR                         0x0c038

#define EURCR_RI                        FSL_BIT(61)
#define EURCR_MI                        FSL_BIT(62)
#define EURCR_SR                        FSL_BIT(63)


/*------------------------------------------------------------------*/

#define SEC_MAX_LENGTH                  32767


/*------------------------------------------------------------------*/

#ifdef MAH_CUSTOM_HARDWARE_ACCEL_STRUCTURE

typedef struct {
    MAH_CUSTOM_HARDWARE_ACCEL_STRUCTURE
} dpd;

#endif

/*------------------------------------------------------------------*/

/*
 * DPD HEADER ADDITIONS
 */
#define DPD_HDR_OP_MODE_DATA_SHIFT(X)           ((X) >> 4)
#define DPD_HDR_DESC(X)                         FSL_BITS(28, (X))

#define DPD_HDR_DN_MASK                         FSL_MASK(0,7)
#define DPD_HDR_DN_VALUE                        DPD_HDR_DN_MASK

#define DPD_HDR_SMAC                            FSL_BIT(18)
#define DPD_HDR_HMAC                            FSL_BIT(20)
#define DPD_HDR_HMAC_PD                         FSL_BIT(21)

/* original SEC v1.0 */
#define DPD_HDR_DESC_AES_CTR_NOSNOOP            DPD_HDR_DESC(0x00)  /* 0000_0 AES CTR nonsnooping */
#define DPD_HDR_DESC_COMMON_NONSNOOP            DPD_HDR_DESC(0x02)  /* 0001_0 Common, nonsnooping, non-PKEU, non-AFEU */
#define DPD_HDR_DESC_SNOOP_HMAC_NOAF            DPD_HDR_DESC(0x04)  /* 0010_0 Snooping, HMAC, non-AFEU */
#define DPD_HDR_DESC_CMN_NOSNOOP_AFEU           DPD_HDR_DESC(0x0a)  /* 0101_0 Common, nonsnooping, AFEU */
#define DPD_HDR_DESC_PKEU_MM                    DPD_HDR_DESC(0x10)  /* 1000_0 PKEU-Montgomery multiplication */
#define DPD_HDR_DESC_HMAC_SNOOP_AESU_CTR        DPD_HDR_DESC(0x18)  /* 1100_0 AESU CTR hmac snooping */

/* new SEC v2.0 */
#define DPD_HDR_DESC_IPSEC_ESP                  DPD_HDR_DESC(0x01)  /* 0000_1 IPsec ESP mode encryption and hashing */
#define DPD_HDR_DESC_802_11I_AES_CCMP           DPD_HDR_DESC(0x03)  /* 0001_1 CCMP encryption and hashing, suitable for 802.11i */
#define DPD_HDR_DESC_SRTP                       DPD_HDR_DESC(0x05)  /* 0010_1 SRTP encryption and hashing */
#define DPD_HDR_DESC_PKEU_ASSEMBLE              DPD_HDR_DESC(0x07)  /* 0011_1 pkeu_assemble elliptical curve cryptography */
#define DPD_HDR_DESC_PKEU_PTMUL                 DPD_HDR_DESC(0x09)  /* 0100_1 pkeu_ptmul elliptical curve cryptography */
#define DPD_HDR_DESC_PKEU_PTADD_DBL             DPD_HDR_DESC(0x0b)  /* 0101_1 pkeu_ptadd_dbl elliptical curve cryptography */
#define DPD_HDR_DESC_TLS_SSL_BLOCK              DPD_HDR_DESC(0x11)  /* 1000_1 TLS/SSL generic block cipher */
#define DPD_HDR_DESC_TLS_SSL_STREAM             DPD_HDR_DESC(0x13)  /* 1001_1 TLS/SSL generic stream cipher */
#define DPD_HDR_DESC_RAID_XOR                   DPD_HDR_DESC(0x15)  /* 1010_1 XOR data streams */

/* common MDEU combinations */

/* All-at-once MD5 and SHA1, MAC and HMAC */
#define DPD_HEADER_MD_MD5_HASH_COMPLETE         (MDEU_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(MD5_COMPLETE|MDEU_PAD)            | DPD_HDR_DESC_COMMON_NONSNOOP)
#define DPD_HEADER_MD_SHA1_HASH_COMPLETE        (MDEU_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(SHA1_COMPLETE|MDEU_PAD)           | DPD_HDR_DESC_COMMON_NONSNOOP)

#define DPD_HEADER_MD_MD5_HMAC_COMPLETE         (MDEU_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(MD5_COMPLETE|MDEU_PAD|MDEU_HMAC)  | DPD_HDR_DESC_COMMON_NONSNOOP)
#define DPD_HEADER_MD_SHA1_HMAC_COMPLETE        (MDEU_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(SHA1_COMPLETE|MDEU_PAD|MDEU_HMAC) | DPD_HDR_DESC_COMMON_NONSNOOP)

/* MD5 and SHA1 in parts */
#define DPD_HEADER_MD_MD5_HASH_INIT             (MDEU_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(MD5_INIT_UPDATE)                  | DPD_HDR_DESC_COMMON_NONSNOOP)
#define DPD_HEADER_MD_MD5_HASH_UPDATE           (MDEU_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(MD5_UPDATE)                       | DPD_HDR_DESC_COMMON_NONSNOOP)
#define DPD_HEADER_MD_MD5_HASH_FINAL            (MDEU_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(MD5_FINAL_UPDATE|MDEU_PAD)        | DPD_HDR_DESC_COMMON_NONSNOOP)

#define DPD_HEADER_MD_SHA1_HASH_INIT            (MDEU_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(SHA1_INIT)                        | DPD_HDR_DESC_COMMON_NONSNOOP)
#define DPD_HEADER_MD_SHA1_HASH_UPDATE          (MDEU_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(SHA1_UPDATE)                      | DPD_HDR_DESC_COMMON_NONSNOOP)
#define DPD_HEADER_MD_SHA1_HASH_FINAL           (MDEU_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(SHA1_FINAL_UPDATE|MDEU_PAD)       | DPD_HDR_DESC_COMMON_NONSNOOP)

/* AES, CBC */
#define DPD_HEADER_AES_DECRYPT                  (AESU_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(AES_CBC_MODE|AES_DECRYPT)         | DPD_HDR_DESC_COMMON_NONSNOOP)
#define DPD_HEADER_AES_ENCRYPT                  (AESU_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(AES_CBC_MODE|AES_ENCRYPT)         | DPD_HDR_DESC_COMMON_NONSNOOP)

/* DES */
#define DPD_HEADER_DES_DECRYPT                  (SDES_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(DES_CBC_MODE|DES_DECRYPT)         | DPD_HDR_DESC_COMMON_NONSNOOP)
#define DPD_HEADER_DES_ENCRYPT                  (SDES_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(DES_CBC_MODE|DES_ENCRYPT)         | DPD_HDR_DESC_COMMON_NONSNOOP)

/* TRIPLE DES */
#define DPD_HEADER_TDES_DECRYPT                 (TDES_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(TDES_CBC_MODE|TDES_DECRYPT)       | DPD_HDR_DESC_COMMON_NONSNOOP)
#define DPD_HEADER_TDES_ENCRYPT                 (TDES_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(TDES_CBC_MODE|TDES_ENCRYPT)       | DPD_HDR_DESC_COMMON_NONSNOOP)

/* RC4 */
#define DPD_HEADER_RC4_CIPHER_START             (ARC4_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(RC4_DC)                           | DPD_HDR_DESC_CMN_NOSNOOP_AFEU)
#define DPD_HEADER_RC4_CIPHER_CONTINUE          (ARC4_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(RC4_CS|RC4_DC|RC4_PP)             | DPD_HDR_DESC_CMN_NOSNOOP_AFEU)

/* PK */
#define DPD_HEADER_CLEAR_MEM                    (PKEU_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(PK_CLEAR_MEM)                     | DPD_HDR_DESC_PKEU_MM)
#define DPD_HEADER_MODEXP                       (PKEU_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(PK_MODEXP)                        | DPD_HDR_DESC_PKEU_MM)
#define DPD_HEADER_MODINV                       (PKEU_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(PK_MODINV)                        | DPD_HDR_DESC_PKEU_MM)
#define DPD_HEADER_MODMULT1                     (PKEU_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(PK_MOD_MULT1)                     | DPD_HDR_DESC_PKEU_MM)
#define DPD_HEADER_MODMULT2                     (PKEU_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(PK_MOD_MULT2)                     | DPD_HDR_DESC_PKEU_MM)
#define DPD_HEADER_MOD_ADD                      (PKEU_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(PK_MOD_ADD)                       | DPD_HDR_DESC_PKEU_MM)
#define DPD_HEADER_MOD_SUBTRACT                 (PKEU_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(PK_MOD_SUBTRACT)                  | DPD_HDR_DESC_PKEU_MM)
#define DPD_HEADER_MOD_R2MODN                   (PKEU_EU0 | DPD_HDR_OP_MODE_DATA_SHIFT(PK_MOD_R2MODN)                    | DPD_HDR_DESC_PKEU_MM)


/* RNG */
#define DPD_HEADER_RNG                          (RAND_EU0                                                                | DPD_HDR_DESC_COMMON_NONSNOOP)

#endif /* __FREESCALE_8548_HEADER__ */
