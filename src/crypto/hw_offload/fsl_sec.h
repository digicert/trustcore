/*
 * fsl_sec.h
 *
 * Freescale Security Definitions
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

#ifndef __FSL_SEC_HEADER__
#define __FSL_SEC_HEADER__

/*------------------------------------------------------------------*/

/*
 * bit  0 is msb
 * bit 31 is lsb
 */

/* #define MOC_UL(X)            X ## UL */
#define MOC_UL(X)               X
#define FSL_BIT(X)              MOC_UL((1 << (31 - (X % 32))))
#define FSL_BIT_16(X)           MOC_UL((1 << (15 - (X % 16))))
#define FSL_BITS(X,V)           MOC_UL(((V) << (31 - (X % 32))))

#define FSL_MASK(X,Y)           MOC_UL((((2 << (31 - (X % 32))) - 1) - ((1 << (31 - (Y % 32))) - 1)))
#define FSL_VALUE(X,Y,V)        MOC_UL((((FSL_MASK(X,Y)) & V) >> (31 - (Y % 32))))


/*------------------------------------------------------------------*/

#ifndef IMMR_ADDRESS
/* IMPORTANT: YOUR BSP WILL MOST LIKELY BE DIFFERENT */
#define IMMR_ADDRESS            0x04700000
#endif

#define IMMR_MASK_875           0xFFFF0000
#define SEC_OFFSET_875          0x00020000

#define OFFSET_SECBR            0x101B4
#define OFFSET_SECMR            0x101BC

/*------------------------------------------------------------------*/

#define INT_EXTERNAL_EXCEPTION  5
#define INT_TIMER               (-1)    /*!!!*/

/*------------------------------------------------------------------*/

#define EU_SELECT_NONE          0x0
#define EU_SELECT_AFEU          0x1
#define EU_SELECT_DEU           0x2
#define EU_SELECT_MDEU          0x3
#define EU_SELECT_RNG           0x4
#define EU_SELECT_PKEU          0x5
#define EU_SELECT_AESU          0x6

#define OP_0_EU_SELECT_OFFSET   3

/*------------------------------------------------------------------*/

#define RNG_CIPHER_SUITE                FSL_BITS(OP_0_EU_SELECT_OFFSET, EU_SELECT_RNG)

/*------------------------------------------------------------------*/

/* need to shift right (>>) bits to appropriate location */

#define AES_CIPHER_SUITE                FSL_BITS(OP_0_EU_SELECT_OFFSET, EU_SELECT_AESU)
#define AES_CBC_MODE                    FSL_BIT(6)

#define AES_ENCRYPT                     FSL_BIT(7)
#define AES_DECRYPT                     0


/*------------------------------------------------------------------*/

/* need to shift right (>>) bits to appropriate location */

#define DES_CIPHER_SUITE                FSL_BITS(OP_0_EU_SELECT_OFFSET, EU_SELECT_DEU)
#define DES_CBC_MODE                    FSL_BIT(5)

#define DES_ENCRYPT                     FSL_BIT(7)
#define DES_DECRYPT                     0


/*------------------------------------------------------------------*/

/* need to shift right (>>) bits to appropriate location */

#define TRIPLE_DES_CIPHER_SUITE         FSL_BITS(OP_0_EU_SELECT_OFFSET, EU_SELECT_DEU)
#define TRIPLE_DES_CBC_MODE             (FSL_BIT(5) | FSL_BIT(6))

#define TRIPLE_DES_ENCRYPT              FSL_BIT(7)
#define TRIPLE_DES_DECRYPT              0


/*------------------------------------------------------------------*/

/* need to shift right (>>) bits to appropriate location */

#define RC4_CIPHER_SUITE                FSL_BITS(OP_0_EU_SELECT_OFFSET, EU_SELECT_AFEU)

#define RC4_CS                          FSL_BIT(5)
#define RC4_DC                          FSL_BIT(6)
#define RC4_PP                          FSL_BIT(7)


/*------------------------------------------------------------------*/

/* need to shift right (>>) bits to appropriate location */
#define MDEU_SUITE                      FSL_BITS(OP_0_EU_SELECT_OFFSET, EU_SELECT_MDEU)

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

#define PK_CIPHER_SUITE                 FSL_BITS(OP_0_EU_SELECT_OFFSET, EU_SELECT_PKEU)

#define PK_CLEAR_MEM                    FSL_BIT(7)
#define PK_MODEXP                       FSL_BIT(6)
#define PK_MODINV                       FSL_BITS(7, 0x0F)
#define PK_MOD_ADD                      FSL_BITS(7, 0x10)
#define PK_MOD_SUBTRACT                 FSL_BITS(7, 0x20)
#define PK_MOD_MULT1                    FSL_BITS(7, 0x30)
#define PK_MOD_MULT2                    FSL_BITS(7, 0x40)
#define PK_MOD_R2MODN                   FSL_BITS(7, 0x03)

#define MIN_PK_BYTES_LENGTH             (16)     /* actually 97 bits; this is nice, round, and bigger */

/*------------------------------------------------------------------*/

/* CHANNELS */

/* SEC, 4 Channels */
#define OFFSET_CHANNEL_1                (0x00002000)
#define OFFSET_CHANNEL_2                (0x00003000)
#define OFFSET_CHANNEL_3                (0x00004000)
#define OFFSET_CHANNEL_4                (0x00005000)

/*------------------------------------------------------------------*/

/* SEC Lite, 1 Channel */
#define OFFSET_CCCR_1                   (0x00002008)
/* Crypto-Channel Configuration Register 1 */


/* SEC, 4 Channels */
#define OFFSET_CHANNEL_CCCR_1           (0x00000008)

#define OFFSET_CCCR1_1                  (OFFSET_CHANNEL_1 + OFFSET_CHANNEL_CCCR_1)
/* Channel 1 CCCR MSW */
#define OFFSET_CCCR2_1                  (OFFSET_CHANNEL_2 + OFFSET_CHANNEL_CCCR_1)
/* Channel 2 CCCR MSW */
#define OFFSET_CCCR3_1                  (OFFSET_CHANNEL_3 + OFFSET_CHANNEL_CCCR_1)
/* Channel 3 CCCR MSW */
#define OFFSET_CCCR4_1                  (OFFSET_CHANNEL_4 + OFFSET_CHANNEL_CCCR_1)
/* Channel 4 CCCR MSW */

/*------------------------------------------------------------------*/

/* SEC Lite, 1 Channel */
#define OFFSET_CCCR_2                   (0x0000200c)
/* Crypto-Channel Configuration Register 2 */

/* SEC, 4 Channels */
#define OFFSET_CHANNEL_CCCR_2           (0x0000000c)

#define OFFSET_CCCR1_2                  (OFFSET_CHANNEL_1 + OFFSET_CHANNEL_CCCR_2)
/* Channel 1 CCCR LSW */
#define OFFSET_CCCR2_2                  (OFFSET_CHANNEL_2 + OFFSET_CHANNEL_CCCR_2)
/* Channel 2 CCCR LSW */
#define OFFSET_CCCR3_2                  (OFFSET_CHANNEL_3 + OFFSET_CHANNEL_CCCR_2)
/* Channel 3 CCCR LSW */
#define OFFSET_CCCR4_2                  (OFFSET_CHANNEL_4 + OFFSET_CHANNEL_CCCR_2)
/* Channel 4 CCCR LSW */


#define BIT_CCCR_WE                     FSL_BIT(27)
/*
 * CCCR (WE) BIT
 *
 * Writeback_Enable. This bit determines if the crypto-channel is allowed to notify
 * the host of the completion of descriptor processing by setting (writing back) a
 * DONE bit in the descriptor header. This enables the host to poll the memory
 * location of the original descriptor header to determine if that descriptor has been
 * completed.
 *
 * 0 Descriptor header writeback notification is disabled.
 * 1 Descriptor header writeback notification is enabled.
 *
 * Header write back notification will occur at the end of every descriptor if
 * NOTIFICATION_TYPE is set to end-of-descriptor and Writeback_Enable is set.
 * Write back will occur only after the last descriptor in the chain (Next Descriptor
 * Pointer is NIL) if NOTIFICATION_TYPE is set to end-of-chain.
 *
 * WARNING: The SEC Lite is capable ONLY of performing initiator write cycles to
 * 32-bit-word aligned addresses. Enabling header write back when the SEC Lite fetches
 * a descriptor from a non-aligned location will yield unpredictable results.
 */


#define BIT_CCCR_NE                     FSL_BIT(28)
/*
 * CCCR (NE) BIT
 *
 * Fetch next descriptor enable. This bit determines if the crypto-channel is
 * allowed to request a transfer of the next descriptor, in a multi-descriptor chain,
 * into its descriptor buffer.
 *
 * 0 Disable fetching of next descriptor when crypto-channel has finished
 * processing the current one.
 *
 * 1 Enable fetching of next descriptor when crypto-channel has finished
 * processing the current one.
 *
 * The address of the next descriptor in a multi-descriptor chain is either the
 * contents of the next descriptor pointer in the descriptor buffer or the contents of
 * the fetch register. Only if both of these registers are NIL upon completion of the
 * descriptor currently being processed will that descriptor be considered the end
 * of the chain.
 */


#define BIT_CCCR_NT                     FSL_BIT(29)
/*
 * CCCR (NT) BIT
 *
 * Channel DONE notification type. This bit controls when the crypto-channel will
 * generate channel DONE notification.
 *
 * 0 End-of-chain - The crypto-channel will generate channel done notification (if
 * enabled) when it completes the processing of the last descriptor in a
 * descriptor chain. The last descriptor is identified by having NIL loaded into
 * both the next descriptor pointer in the descriptor buffer and the fetch register.
 *
 * 1 End-of-descriptor - The crypto-channel will generate channel done notification
 * (if enabled) at the end of every data descriptor it processes
 *
 * Channel DONE notification can take the form of an interrupt or modified header
 * writeback or both, depending on the state of the INTERRUPT_ENABLE and
 * WRITEBACK_ENABLE control bits.
 */


#define BIT_CCCR_CDIE                   FSL_BIT(30)
/*
 * CCCR (CDIE) BIT
 *
 * Channel DONE interrupt enable. This bit determines whether or not the
 * crypto-channel is allowed to assert interrupts to notify the host that the channel
 * has completed descriptor processing.
 *
 * 0 Channel Done interrupt disabled
 *
 * 1 Channel Done interrupt enabled
 *
 * When CDIE is set, the NOTIFICATION_TYPE control bit determines when the
 * CHANNEL_DONE interrupt is asserted. Channel error interrupts are asserted
 * as soon as the error is detected. Refer to Section 50.2, "Interrupts," for complete
 * description of crypto-channel interrupt operation.
 */


#define BIT_CCCR_R                      FSL_BIT(31)
/*
 * CCCR (R) BIT
 *
 * Reset crypto-channel. This bit allows the crypto-channel to be software reset.
 *
 * 0 Automatically cleared by the crypto-channel when reset sequence is
 * complete. Refer to Section 50.2.3, "Channel Reset," for complete description
 * of crypto-channel reset operation.
 *
 * 1 Reset the registers and internal state of the crypto-channel, any EU assigned
 * to the crypto-channel and the controller state associated with the
 * crypto-channel.
 */


/*------------------------------------------------------------------*/

/* SEC Lite, 1 Channel */
#define OFFSET_CCPSR_1                  (0x00002010)
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
#define OFFSET_CCPSR_2                  (0x00002014)
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
#define OFFSET_CDPR_1                   (0x00002040)
/* Crypto-Channel Current Descriptor Pointer Register */


/* SEC, 4 Channels */
#define OFFSET_CHANNEL_CDPR_1           (0x00000040)

#define OFFSET_CDPR1_1                  (OFFSET_CHANNEL_1 + OFFSET_CHANNEL_CDPR_1)
/* Channel 1 CDPR MSW */
#define OFFSET_CDPR2_1                  (OFFSET_CHANNEL_2 + OFFSET_CHANNEL_CDPR_1)
/* Channel 2 CDPR MSW */
#define OFFSET_CDPR3_1                  (OFFSET_CHANNEL_3 + OFFSET_CHANNEL_CDPR_1)
/* Channel 3 CDPR MSW */
#define OFFSET_CDPR4_1                  (OFFSET_CHANNEL_4 + OFFSET_CHANNEL_CDPR_1)
/* Channel 4 CDPR MSW */

/*------------------------------------------------------------------*/

/* SEC Lite, 1 Channel */
#define OFFSET_CDPR_2                   (0x00002044)
/* Crypto-Channel Current Descriptor Pointer Register */


#define CUR_DES_PTR_ADRS                (0x00002044)
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


/* SEC, 4 Channels */
#define OFFSET_CHANNEL_CDPR_2           (0x00000044)

#define OFFSET_CDPR1_2                  (OFFSET_CHANNEL_1 + OFFSET_CHANNEL_CDPR_2)
/* Channel 1 CDPR LSW */
#define OFFSET_CDPR2_2                  (OFFSET_CHANNEL_2 + OFFSET_CHANNEL_CDPR_2)
/* Channel 2 CDPR LSW */
#define OFFSET_CDPR3_2                  (OFFSET_CHANNEL_3 + OFFSET_CHANNEL_CDPR_2)
/* Channel 3 CDPR LSW */
#define OFFSET_CDPR4_2                  (OFFSET_CHANNEL_4 + OFFSET_CHANNEL_CDPR_2)
/* Channel 4 CDPR LSW */

#define CH1_CUR_DES_PTR_ADRS            (OFFSET_CDPR1_2)
#define CH2_CUR_DES_PTR_ADRS            (OFFSET_CDPR2_2)
#define CH3_CUR_DES_PTR_ADRS            (OFFSET_CDPR3_2)
#define CH4_CUR_DES_PTR_ADRS            (OFFSET_CDPR4_2)


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

#define OFFSET_IMR_1                    (0x00001008)
/* Interrupt Mask Register 1 */

/* SEC Lite, 1 Channel */
#define IMR_1_CHA_ERR                   FSL_BIT(2)
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

#define IMR_1_CHA_DN                    FSL_BIT(3)
/*
 * IMR (CHA_ERR) BIT
 *
 * The channel has a Done bit.
 *
 * 0 Not DONE.
 *
 * 1 DONE bit indicates that the interrupting channel or EU has completed its
 * operation.
 */

/* SEC, 4 Channels */
#define IMR_CH1_DN_1                    FSL_BIT(3)
#define IMR_CH1_ERR_1                   FSL_BIT(2)
#define IMR_CH2_DN_1                    FSL_BIT(1)
#define IMR_CH2_ERR_1                   FSL_BIT(0)

#define IMR_CH3_DN_1                    FSL_BIT(15)
#define IMR_CH3_ERR_1                   FSL_BIT(14)
#define IMR_CH4_DN_1                    FSL_BIT(13)
#define IMR_CH4_ERR_1                   FSL_BIT(12)


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

#define OFFSET_ISR_1                    (0x00001010)
/* Interrupt Status Register 1 */


/* SEC Lite, 1 Channel */
#define ISR_1_CHA_ERR                   FSL_BIT(2)
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

#define ISR_1_CHA_DN                    FSL_BIT(3)
/*
 * ISR (CHA_ERR) BIT
 *
 * The channel has a Done bit.
 *
 * 0 Not DONE.
 *
 * 1 DONE bit indicates that the interrupting channel or EU has completed its
 * operation.
 */

/* SEC, 4 Channels */
#define ISR_CH1_DN_1                    FSL_BIT(3)
#define ISR_CH1_ERR_1                   FSL_BIT(2)
#define ISR_CH2_DN_1                    FSL_BIT(1)
#define ISR_CH2_ERR_1                   FSL_BIT(0)

#define ISR_CH3_DN_1                    FSL_BIT(15)
#define ISR_CH3_ERR_1                   FSL_BIT(14)
#define ISR_CH4_DN_1                    FSL_BIT(13)
#define ISR_CH4_ERR_1                   FSL_BIT(12)

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

#define OFFSET_ICR_1                    (0x00001018)
/* Interrupt Clear Register 1 */

/* SEC Lite, 1 Channel */
#define ICR_1_CHA_ERR                   FSL_BIT(2)
/*
 * ICR (CHA_ERR) BIT
 *
 * The channel has an Error bit.
 *
 * 0 No error detected.
 *
 * 1 Error detected. Indicates that execution unit status register must be read to
 * determine exact cause of the error.
 */

#define ICR_1_CHA_DN                    FSL_BIT(3)
/*
 * ICR (CHA_ERR) BIT
 *
 * The channel has a Done bit.
 *
 * 0 Not DONE.
 *
 * 1 DONE bit indicates that the interrupting channel or EU has completed its
 * operation.
 */

/* SEC, 4 Channels */
#define ICR_CH1_DN_1                    FSL_BIT(3)
#define ICR_CH1_ERR_1                   FSL_BIT(2)
#define ICR_CH2_DN_1                    FSL_BIT(1)
#define ICR_CH2_ERR_1                   FSL_BIT(0)

#define ICR_CH3_DN_1                    FSL_BIT(15)
#define ICR_CH3_ERR_1                   FSL_BIT(14)
#define ICR_CH4_DN_1                    FSL_BIT(13)
#define ICR_CH4_ERR_1                   FSL_BIT(12)


/*------------------------------------------------------------------*/

#define OFFSET_ICR_2                    (0x0000101c)
/* Interrupt Clear Register 2 */


#define ICR_2_MDEU_ERR                  FSL_BIT(14)
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


#define ICR_2_MDEU_DN                   FSL_BIT(15)
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


#define ICR_2_AESU_ERR                  FSL_BIT(18)
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


#define ICR_2_AESU_DN                   FSL_BIT(19)
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


#define ICR_2_DEU_ERR                   FSL_BIT(22)
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


#define ICR_2_DEU_DN                    FSL_BIT(23)
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

#define ICR_2_TEA                       FSL_BIT(25)
/*
 * ICR (TEA) BIT
 *
 * Transfer Error Acknowledge. Set when the SEC Lite as a master receives a
 * Transfer Error Acknowledge.
 *
 * 0 No error detected.
 *
 * 1 TEA detected on bus.
 */


/*------------------------------------------------------------------*/

#define OFFSET_ID                       (0x00001020)
/* ID Register */


#define VALUE_ID_VERSION                FSL_VALUE(0,7)
/*
 * ID (VERSION) VALUE
 *
 * The Read-Only ID Register, displayed in Figure 51-7, contains a 32-bit value that uniquely
 * identifies the version of the SEC Lite. The value of this register is always 0x2000_0000.
 */


/*------------------------------------------------------------------*/

#define OFFSET_MCR                      (0x00001030)
/* Master Control Register */


#define MCR_SWR                         FSL_BIT(7)
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


#define MCR_GI                          FSL_BIT(25)
/*
 * MCR (GI) BIT
 *
 * Global Inhibit.
 *
 * 0 - Master will always drive GBL_B active (low).
 *
 * 1 - Master will always drive GBL_B inactive (high).
 */


/*------------------------------------------------------------------*/

#define OFFSET_MEAR                     (0x00001030)
/*
 * Master Error Address Register
 * This register saves the address of the transaction whose data phase was terminated with a
 * TEA or Master Parity Error. A Transfer Error Acknowledge (TEA) signal indicates a fatal
 * error has occurred during the data phase of a bus transaction. Invalid data may have been
 * received and stored prior to the receipt of the TEA. The channel that was initiating the
 * transaction will be evident from that channel�s error interrupt. The PowerQUICC 1 PPC core
 * may chose to reset the channel reporting the TEA, reset the whole SEC Lite, or reset the entire
 * system with a machine check error. In any case, the host may chose to preserve this TEA
 * information prior to reset to assist in debug.
 *
 * The MEAR only holds the address of the first error reported, in the event multiple errors
 * are received before the first is cleared.
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

#define MSR_EE                          FSL_BIT(16)

/*------------------------------------------------------------------*/

/* SIU */

#define OFFSET_SIUMCR                   0x10000

#define SIUMCR_SECDIS                   FSL_BIT(22)

#define OFFSET_SIPNR_H                  0x10C08
#define OFFSET_SIPNR_L                  0x10C0E

#define OFFSET_SIPRR                    0x10C10

#define OFFSET_PPC_ALRH                 0x1002C
#define OFFSET_PPC_ALRL                 0x10030

#define SIPNR_H_PIT                     FSL_BIT(30)     /* Periodic Int Timer */
#define SIPNR_L_SEC                     FSL_BIT(15)

#define OFFSET_SIMR_H                   0x10C1C
#define OFFSET_SIMR_L                   0x10C20

#define SIMR_H_PIT                      FSL_BIT(30)
#define SIMR_L_SEC                      FSL_BIT(15)

#define OFFSET_SIVEC                    0x10C04

#define INT_CODE_SEC                    47
#define INT_CODE_TMCNT                  16
#define INT_CODE_PIT                    17

#define INT_CODE_USER                   1234567
/* Fake ID for when calling the ISR from outside an interupt context */

/*------------------------------------------------------------------*/

#define OFFSET_TMCNTSC                  0x10220         /* 16 bits */

#define TMCNTSC_SEC                     FSL_BIT_16(8)
/* SEC Once-per-second status bit - 1 write 1 to clear */

#define TMCNTSC_ALR                     FSL_BIT_16(8)
/* Alarm interrupt status bit - write 1 to clear */

#define TMCNTSC_SIE                     FSL_BIT_16(8)
/* IF 1, time ctr generates int when SEC is set */

#define TMCNTSC_ALE                     FSL_BIT_16(8)
/* Alarm Int enable */

#define TMCNTSC_TCF                     FSL_BIT_16(8)
/* Time ctr frequency. 0 = 4MHz, 1 = 32 khz */

#define TMCNTSC_TCE                     FSL_BIT_16(8)
/* Time Ctr enable. */

#define OFFSET_TMCNT                    0x10226
#define OFFSET_TMCNTAL                  0x1222E
/* interrupt fires when TMCNT == TMCNTAL */

/*------------------------------------------------------------------*/

/* PERIODIC INTERRUPT REGISTERS */
#define OFFSET_PISCR                    0x10240

#define PISCR_PS                        FSL_BIT_16(8)
/* Periodic Interrupt status - write 1 to clear */

#define PISCR_PIE                       FSL_BIT_16(13)
/* periodic interrupt enable */

#define PISCR_PTF                       FSL_BIT_16(14)
/* Periodic interrupt frequency; 0 = 4 MHz, 1 = 32 khz */

#define PISCR_PTE                       FSL_BIT_16(15)
/* Periodic timer enable. When Timer is disabled it maintains old value.
 * When ctr is enabled, it continues running using previous value. */

#define OFFSET_PITC                     0x10244
/* hi word contains 16 bits to be loaded into modulus counter */

#define OFFSET_PITR                     0x10248

/*------------------------------------------------------------------*/

/* Baud Rate Generator 1 */
#define OFFSET_BRG1                     0x119F0

#define BRG1_RST                        FSL_BIT(14)
/* Software reset of BRG */

#define BRG1_EN                         FSL_BIT(15)
#define BRG1_EXTC_MASK                  FSL_MASK(16,17)
#define BRG1_ATB                        FSL_BIT(18)
#define BRG1_CD_MASK                    FSL_MASK(19,30)
#define BRG1_CD_SET(val)                FSL_BITS(30,val)
#define BRG1_DIV16                      FSL_BIT(31)

/*------------------------------------------------------------------*/

/* SCCR System Clock Control Register */
#define OFFSET_SCCR                     0x10C80



/*
 * This section may need to be expanded. This is enough to reset the
 * EUs.
 */

#define PKEURCR                         0x10018
#define DEURCR                          0x0A018
#define AFEURCR                         0x08018
#define MDEURCR                         0x0C018
#define RNGRCR                          0x0E018
#define AESURCR                         0x12018

#define EURCR_RI                        FSL_BIT(5)
#define EURCR_MI                        FSL_BIT(6)
#define EURCR_SR                        FSL_BIT(7)

#define EUASR_1                         0x01028
#define EUASR_2                         0x0102C

#define EUASR_1_RNG_BITS                4,7
#define EUASR_1_PKEU_BITS               12,15
#define EUASR_1_MDEU_BITS               20,23
#define EUASR_1_AFEU_BITS               28,31

#define EUASR_2_DEU_BITS                4,7
#define EUASR_2_AESU_BITS               12,15

/*------------------------------------------------------------------*/

#define SEC_MAX_LENGTH                  32767

/* Needs to be 1 for SEC_LITE */
#if defined(__ENABLE_FREESCALE_875_HARDWARE_ACCEL__)
#   define SEC_CHANNEL_COUNT               1
#elif defined(__ENABLE_FREESCALE_8248_HARDWARE_ACCEL__)
#define SEC_CHANNEL_COUNT               4
#else
#   define SEC_CHANNEL_COUNT               0
#endif


enum {
    SEC_CH_ALL      = 0,
    SEC_CH_1        = 1,
    SEC_CH_2        = 2,
    SEC_CH_3        = 3,
    SEC_CH_4        = 4,
    SEC_CH_INVALID  = -1
};

/*------------------------------------------------------------------*/

#ifdef MAH_CUSTOM_HARDWARE_ACCEL_STRUCTURE

typedef struct dpd {
    MAH_CUSTOM_HARDWARE_ACCEL_STRUCTURE
} dpd;

#endif

/*------------------------------------------------------------------*/

/*
 * DPD HEADER ADDITIONS
 */
#define DPD_HDR_OP_MODE_DATA_SHIFT(X)           ((X) >> 4)
#define DPD_HDR_DESC(X)                         FSL_BITS(27, (X))

#define DPD_HDR_DN_MASK                         FSL_MASK(0,7)
#define DPD_HDR_DN_VALUE                        DPD_HDR_DN_MASK

/* nibble (SEC v1) */
#define DPD_HDR_DESC_AES_CTR_NOSNOOP            0x0
#define DPD_HDR_DESC_CMN_NOSNOOP_NOPK_NOAF      0x1
#define DPD_HDR_DESC_SNOOP_HMAC_NOAF            0x2
#define DPD_HDR_DESC_SNOOP_NOHMAC_NOAF          0x3
#define DPD_HDR_DESC_CMN_NOSNOOP_AFEU           0x5
#define DPD_HDR_DESC_PK_MM                      0x8
#define DPD_HDR_DESC_HMAC_SNOOP_AES_CTR         0xC

/* common MDEU combinations */

/* All-at-once MD5, non-HMAC */
#define DPD_HEADER_MD_MD5_HASH_COMPLETE         (MDEU_SUITE              | DPD_HDR_OP_MODE_DATA_SHIFT(MD5_COMPLETE|MDEU_PAD)                   | DPD_HDR_DESC(DPD_HDR_DESC_SNOOP_NOHMAC_NOAF))
#define DPD_HEADER_MD_SHA1_HASH_COMPLETE        (MDEU_SUITE              | DPD_HDR_OP_MODE_DATA_SHIFT(SHA1_COMPLETE|MDEU_PAD)                  | DPD_HDR_DESC(DPD_HDR_DESC_SNOOP_NOHMAC_NOAF))
#define DPD_HEADER_MD_MD5_HMAC_COMPLETE         (MDEU_SUITE              | DPD_HDR_OP_MODE_DATA_SHIFT(MD5_COMPLETE|MDEU_PAD|MDEU_HMAC)         | DPD_HDR_DESC(DPD_HDR_DESC_CMN_NOSNOOP_NOPK_NOAF))
#define DPD_HEADER_MD_SHA1_HMAC_COMPLETE        (MDEU_SUITE              | DPD_HDR_OP_MODE_DATA_SHIFT(SHA1_COMPLETE|MDEU_PAD|MDEU_HMAC)        | DPD_HDR_DESC(DPD_HDR_DESC_CMN_NOSNOOP_NOPK_NOAF))

/* MD5 and SHA1 in parts */
#define DPD_HEADER_MD_MD5_HASH_INIT             (MDEU_SUITE              | DPD_HDR_OP_MODE_DATA_SHIFT(MD5_INIT_UPDATE)                         | DPD_HDR_DESC(DPD_HDR_DESC_SNOOP_NOHMAC_NOAF))
#define DPD_HEADER_MD_MD5_HASH_UPDATE           (MDEU_SUITE              | DPD_HDR_OP_MODE_DATA_SHIFT(MD5_UPDATE)                              | DPD_HDR_DESC(DPD_HDR_DESC_SNOOP_NOHMAC_NOAF))
#define DPD_HEADER_MD_MD5_HASH_FINAL            (MDEU_SUITE              | DPD_HDR_OP_MODE_DATA_SHIFT(MD5_FINAL_UPDATE|MDEU_PAD)               | DPD_HDR_DESC(DPD_HDR_DESC_SNOOP_NOHMAC_NOAF))

#define DPD_HEADER_MD_SHA1_HASH_INIT            (MDEU_SUITE              | DPD_HDR_OP_MODE_DATA_SHIFT(SHA1_INIT)                               | DPD_HDR_DESC(DPD_HDR_DESC_SNOOP_NOHMAC_NOAF))
#define DPD_HEADER_MD_SHA1_HASH_UPDATE          (MDEU_SUITE              | DPD_HDR_OP_MODE_DATA_SHIFT(SHA1_UPDATE)                             | DPD_HDR_DESC(DPD_HDR_DESC_SNOOP_NOHMAC_NOAF))
#define DPD_HEADER_MD_SHA1_HASH_FINAL           (MDEU_SUITE              | DPD_HDR_OP_MODE_DATA_SHIFT(SHA1_FINAL_UPDATE|MDEU_PAD)              | DPD_HDR_DESC(DPD_HDR_DESC_SNOOP_NOHMAC_NOAF))

/* AES, CBC */
#define DPD_HEADER_AES_ENCRYPT                  (AES_CIPHER_SUITE        | DPD_HDR_OP_MODE_DATA_SHIFT(AES_CBC_MODE|AES_ENCRYPT)                | DPD_HDR_DESC(DPD_HDR_DESC_CMN_NOSNOOP_NOPK_NOAF))
#define DPD_HEADER_AES_DECRYPT                  (AES_CIPHER_SUITE        | DPD_HDR_OP_MODE_DATA_SHIFT(AES_CBC_MODE|AES_DECRYPT)                | DPD_HDR_DESC(DPD_HDR_DESC_CMN_NOSNOOP_NOPK_NOAF))

/* DES */
#define DPD_HEADER_DES_ENCRYPT                  (DES_CIPHER_SUITE        | DPD_HDR_OP_MODE_DATA_SHIFT(DES_CBC_MODE|DES_ENCRYPT)                | DPD_HDR_DESC(DPD_HDR_DESC_CMN_NOSNOOP_NOPK_NOAF))
#define DPD_HEADER_DES_DECRYPT                  (DES_CIPHER_SUITE        | DPD_HDR_OP_MODE_DATA_SHIFT(DES_CBC_MODE|DES_DECRYPT)                | DPD_HDR_DESC(DPD_HDR_DESC_CMN_NOSNOOP_NOPK_NOAF))

/* TRIPLE DES */
#define DPD_HEADER_TDES_ENCRYPT                 (TRIPLE_DES_CIPHER_SUITE | DPD_HDR_OP_MODE_DATA_SHIFT(TRIPLE_DES_CBC_MODE|TRIPLE_DES_ENCRYPT)  | DPD_HDR_DESC(DPD_HDR_DESC_CMN_NOSNOOP_NOPK_NOAF))
#define DPD_HEADER_TDES_DECRYPT                 (TRIPLE_DES_CIPHER_SUITE | DPD_HDR_OP_MODE_DATA_SHIFT(TRIPLE_DES_CBC_MODE|TRIPLE_DES_DECRYPT)  | DPD_HDR_DESC(DPD_HDR_DESC_CMN_NOSNOOP_NOPK_NOAF))

/* RC4 */
#define DPD_HEADER_RC4_CIPHER_START             (RC4_CIPHER_SUITE        | DPD_HDR_OP_MODE_DATA_SHIFT(RC4_DC)                                  | DPD_HDR_DESC(DPD_HDR_DESC_CMN_NOSNOOP_AFEU))
#define DPD_HEADER_RC4_CIPHER_CONTINUE          (RC4_CIPHER_SUITE        | DPD_HDR_OP_MODE_DATA_SHIFT(RC4_CS|RC4_DC|RC4_PP)                    | DPD_HDR_DESC(DPD_HDR_DESC_CMN_NOSNOOP_AFEU))

/* PK */
#define DPD_HEADER_CLEAR_MEM                    (PK_CIPHER_SUITE         | DPD_HDR_OP_MODE_DATA_SHIFT(PK_CLEAR_MEM)                            | DPD_HDR_DESC(DPD_HDR_DESC_PK_MM))
#define DPD_HEADER_MODEXP                       (PK_CIPHER_SUITE         | DPD_HDR_OP_MODE_DATA_SHIFT(PK_MODEXP)                               | DPD_HDR_DESC(DPD_HDR_DESC_PK_MM))
#define DPD_HEADER_MODINV                       (PK_CIPHER_SUITE         | DPD_HDR_OP_MODE_DATA_SHIFT(PK_MODINV)                               | DPD_HDR_DESC(DPD_HDR_DESC_PK_MM))
#define DPD_HEADER_MODMULT1                     (PK_CIPHER_SUITE         | DPD_HDR_OP_MODE_DATA_SHIFT(PK_MOD_MULT1)                            | DPD_HDR_DESC(DPD_HDR_DESC_PK_MM))
#define DPD_HEADER_MODMULT2                     (PK_CIPHER_SUITE         | DPD_HDR_OP_MODE_DATA_SHIFT(PK_MOD_MULT2)                            | DPD_HDR_DESC(DPD_HDR_DESC_PK_MM))
#define DPD_HEADER_MOD_ADD                      (PK_CIPHER_SUITE         | DPD_HDR_OP_MODE_DATA_SHIFT(PK_MOD_ADD)                              | DPD_HDR_DESC(DPD_HDR_DESC_PK_MM))
#define DPD_HEADER_MOD_SUBTRACT                 (PK_CIPHER_SUITE         | DPD_HDR_OP_MODE_DATA_SHIFT(PK_MOD_SUBTRACT)                         | DPD_HDR_DESC(DPD_HDR_DESC_PK_MM))
#define DPD_HEADER_MOD_R2MODN                   (PK_CIPHER_SUITE         | DPD_HDR_OP_MODE_DATA_SHIFT(PK_MOD_R2MODN)                           | DPD_HDR_DESC(DPD_HDR_DESC_PK_MM))


/* RNG */
#define DPD_HEADER_RNG                          (RNG_CIPHER_SUITE                                                                              | DPD_HDR_DESC(DPD_HDR_DESC_CMN_NOSNOOP_NOPK_NOAF))

/* CONTROLLER */


/* SInce bits are common across IMR, ISR and ICR the ISR macros will be used for all three */

/* MSW */
#define ISR_CHANNEL_1_DONE              FSL_BIT(3)
#define ISR_CHANNEL_1_ERR               FSL_BIT(2)
#define ISR_CHANNEL_2_DONE              FSL_BIT(1)
#define ISR_CHANNEL_2_ERR               FSL_BIT(0)

#define ISR_CHANNEL_3_DONE              FSL_BIT(15)
#define ISR_CHANNEL_3_ERR               FSL_BIT(14)
#define ISR_CHANNEL_4_DONE              FSL_BIT(13)
#define ISR_CHANNEL_4_ERR               FSL_BIT(12)

/* LSW */
#define ISR_PKEU_DONE                   FSL_BIT(3)
#define ISR_PKEU_ERR                    FSL_BIT(2)
#define ISR_RNG_DONE                    FSL_BIT(7)
#define ISR_RNG_ERR                     FSL_BIT(6)
#define ISR_AFEU_DONE                   FSL_BIT(11)
#define ISR_AFEU_ERR                    FSL_BIT(10)
#define ISR_MDEU_DONE                   FSL_BIT(15)
#define ISR_MDEU_ERR                    FSL_BIT(14)
#define ISR_MDEU_DONE                   FSL_BIT(15)
#define ISR_MDEU_ERR                    FSL_BIT(14)


#endif /* __FSL_SEC_HEADER__ */
