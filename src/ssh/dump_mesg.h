/*
 * dump_mesg.h
 *
 * Dump Message Header
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

#ifndef __DUMP_MESG_HEADER__
#define __DUMP_MESG_HEADER__

#ifdef __ENABLE_ALL_DEBUGGING__

/**
 * @brief Dumps an SSH message for debugging
 *
 * This function prints the SSH message type, direction (inbound/outbound),
 * and a hex/ascii dump of the message payload for debugging purposes.
 *
 * @param pMesg Pointer to the message data
 * @param mesgLen Length of the message
 * @param isOutBound Boolean indicating if the message is outbound
 *
 * @return void
 *
 */
MOC_EXTERN void DUMP_MESG_sshMessage(ubyte *pMesg, ubyte4 mesgLen, intBoolean isOutBound);

/**
 * @brief Dumps an SFTP message for debugging
 *
 * This function prints the SFTP message type, direction (inbound/outbound),
 * and a hex/ascii dump of the message payload for debugging purposes.
 *
 * @param pMesg Pointer to the message data
 * @param mesgLen Length of the message
 * @param isOutBound Boolean indicating if the message is outbound
 *
 * @return void
 *
 */
MOC_EXTERN void DUMP_MESG_sftpMessage(ubyte *pMesg, ubyte4 mesgLen, intBoolean isOutBound);
#endif /* __ENABLE_ALL_DEBUGGING__ */

#endif /* __DUMP_MESG_HEADER__ */
