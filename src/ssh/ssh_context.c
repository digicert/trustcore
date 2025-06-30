/*
 * ssh_context.c
 *
 * SSH Context
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


#define __ENABLE_OUTBOUND_SSH_DEFINITIONS__
#define __ENABLE_INBOUND_SSH_DEFINITIONS__

#include "../common/moptions.h"

#ifdef __ENABLE_MOCANA_SSH_SERVER__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/mem_pool.h"
#include "../common/moc_stream.h"
#include "../common/memory_debug.h"
#include "../crypto/crypto.h"
#include "../crypto/dsa.h"
#include "../crypto/dh.h"
#ifdef __ENABLE_MOCANA_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../crypto/pubcrypto.h"
#include "../common/sizedbuffer.h"
#include "../crypto/cert_store.h"
#include "../crypto/ca_mgmt.h"
#include "../ssh/ssh_str.h"
#include "../ssh/ssh_context.h"
#include "../ssh/ssh_auth.h"
#include "../ssh/ssh_in_mesg.h"
#include "../ssh/ssh_out_mesg.h"
#include "../ssh/ssh.h"
#include "../ssh/ssh_ftp.h"
#include "../harness/harness.h"

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_dh.h"
#endif
/*------------------------------------------------------------------*/

#define SSH2_DEFAULT_CIPER_SIZE     8
#define SSH_SMALL_TEMP_BUF_SIZE     (64)
#define SSH_MEDIUM_TEMP_BUF_SIZE    (160)

static BulkEncryptionAlgo NULLSuite = { 1, NULL, NULL, NULL, NULL };
static SSH_CipherSuiteInfo mNullCipherSuite = { (sbyte *)"null", 4, 0, SSH2_DEFAULT_CIPER_SIZE, &NULLSuite, NULL };
static SSH_hmacSuiteInfo   mNullHmacSuite   = { (sbyte *)"null", 4, 0, 0, NULL, NULL };

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
static void destroyLpfData(sshContext* pContextSSH)
{
    sshPfSession*  pTemp   = NULL;
    sshPfSession*  pTarget = NULL;

    if ( NULL != pContextSSH->pPfSessionHead )
    {
        pTemp = pContextSSH->pPfSessionHead;

        while( NULL != pTemp )
        {
            pTarget = pTemp->pNextSession;
            FREE(pTemp);
            pTemp = pTarget;
        }/* End of while loop */

        pContextSSH->pPfSessionHead = NULL;
    }
}
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */

extern MSTATUS
SSH_CONTEXT_allocStructures(sshContext **ppContextSSH)
{
    MSTATUS status;
    ubyte*  pTempMemBuffer = NULL;

    if (NULL == ppContextSSH)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (*ppContextSSH = MALLOC(sizeof(sshContext))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    MOC_MEMSET((ubyte *)(*ppContextSSH), 0x00, sizeof(sshContext));

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSH, &((*ppContextSSH)->hwAccelCookie))))
        goto exit;

    /*** Small Memory Pool ***/
    if (OK > (status = CRYPTO_ALLOC((*ppContextSSH)->hwAccelCookie, SSH_SMALL_TEMP_BUF_SIZE * 5, TRUE, &pTempMemBuffer)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pTempMemBuffer);
    MOC_MEMSET((ubyte *)(pTempMemBuffer), 0x00, SSH_SMALL_TEMP_BUF_SIZE * 5);
    if (OK > (status = MEM_POOL_initPool(&((*ppContextSSH)->smallPool), pTempMemBuffer, SSH_SMALL_TEMP_BUF_SIZE * 5, SSH_SMALL_TEMP_BUF_SIZE)))
        goto exit;

    pTempMemBuffer = NULL;
    /*** Medium Memory Pool ***/
    if (OK > (status = CRYPTO_ALLOC((*ppContextSSH)->hwAccelCookie, SSH_MEDIUM_TEMP_BUF_SIZE * 5, TRUE, &pTempMemBuffer)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pTempMemBuffer);
    MOC_MEMSET((ubyte *)(pTempMemBuffer), 0x00, SSH_MEDIUM_TEMP_BUF_SIZE * 5);
    if (OK > (status = MEM_POOL_initPool(&((*ppContextSSH)->mediumPool), pTempMemBuffer, SSH_MEDIUM_TEMP_BUF_SIZE * 5, SSH_MEDIUM_TEMP_BUF_SIZE)))
        goto exit;

    OUTBOUND_BUFFER_SIZE(*ppContextSSH)       = SSH_MAX_BUFFER_SIZE;
    OUTBOUND_MAX_MESSAGE_SIZE(*ppContextSSH)  = SSH_MAX_BUFFER_SIZE;
    OUTBOUND_CIPHER_SUITE_INFO(*ppContextSSH) = &mNullCipherSuite;
    OUTBOUND_MAC_INFO(*ppContextSSH)          = &mNullHmacSuite;

    INBOUND_BUFFER_SIZE(*ppContextSSH)        = SSH_MAX_BUFFER_SIZE;
    INBOUND_MAX_MESSAGE_SIZE(*ppContextSSH)   = SSH_MAX_BUFFER_SIZE; /*!!!! add growing buffer support here */
    INBOUND_CIPHER_SUITE_INFO(*ppContextSSH)  = &mNullCipherSuite;
    INBOUND_MAC_INFO(*ppContextSSH)           = &mNullHmacSuite;

    if (OK > (status = SSH_IN_MESG_allocStructures(*ppContextSSH)))
        goto exit;

    if (OK > (status = SSH_OUT_MESG_allocStructures(*ppContextSSH)))
        goto exit;

    if (OK > (status = SSH_AUTH_allocStructures(*ppContextSSH)))
        goto exit;

    if (NULL == ((*ppContextSSH)->pTerminal = MALLOC(sizeof(terminalState))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    MOC_MEMSET((*ppContextSSH)->pTerminal, 0x00, sizeof(terminalState));

    if (NULL == (*ppContextSSH)->decryptIV)
    {
        if (OK > (status = CRYPTO_ALLOC((*ppContextSSH)->hwAccelCookie, 40, TRUE, &(*ppContextSSH)->decryptIV)))
            goto exit;
    }

    if (NULL == (*ppContextSSH)->encryptIV)
    {
        if (OK > (status = CRYPTO_ALLOC((*ppContextSSH)->hwAccelCookie, 40, TRUE, &(*ppContextSSH)->encryptIV)))
            goto exit;
    }

    /* default value when no cipher suite has been selected */
    INBOUND_CIPHER_TYPE(*ppContextSSH) = IGNORE;
    OUTBOUND_CIPHER_TYPE(*ppContextSSH) = IGNORE;

exit:
    if ((OK > status) && (NULL != ppContextSSH) && (NULL != *ppContextSSH))
        SSH_CONTEXT_deallocStructures(ppContextSSH);

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_CONTEXT_deallocStructures(sshContext **ppContextSSH)
{
    sbyte4  i;
    MSTATUS status = OK;

    if (NULL == ppContextSSH)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != CLIENT_KEX_INIT_PAYLOAD(*ppContextSSH))
    {
        CRYPTO_FREE((*ppContextSSH)->hwAccelCookie, TRUE, &(CLIENT_KEX_INIT_PAYLOAD(*ppContextSSH)));
        CLIENT_KEX_INIT_PAYLOAD(*ppContextSSH) = NULL;
    }

    if (NULL != SERVER_KEX_INIT_PAYLOAD(*ppContextSSH))
    {
        CRYPTO_FREE((*ppContextSSH)->hwAccelCookie, TRUE, &(SERVER_KEX_INIT_PAYLOAD(*ppContextSSH)));
        SERVER_KEX_INIT_PAYLOAD(*ppContextSSH) = NULL;
    }

    if (NULL != CLIENT_HELLO_COMMENT(*ppContextSSH))
    {
        CRYPTO_FREE((*ppContextSSH)->hwAccelCookie, TRUE, &(CLIENT_HELLO_COMMENT(*ppContextSSH)));
        CLIENT_HELLO_COMMENT(*ppContextSSH) = NULL;
    }

    if (NULL != SERVER_HELLO_COMMENT(*ppContextSSH))
    {
        CRYPTO_FREE((*ppContextSSH)->hwAccelCookie, TRUE, &(SERVER_HELLO_COMMENT(*ppContextSSH)));
        SERVER_HELLO_COMMENT(*ppContextSSH) = NULL;
    }

    if (NULL != INBOUND_MAC_BUFFER(*ppContextSSH))
    {
        FREE(INBOUND_MAC_BUFFER(*ppContextSSH));
        INBOUND_MAC_BUFFER(*ppContextSSH) = NULL;
    }

    if (NULL != INBOUND_KEY_DATA(*ppContextSSH))
    {
        CRYPTO_FREE( (*ppContextSSH)->hwAccelCookie, TRUE, &(INBOUND_KEY_DATA(*ppContextSSH)) ) ;
        INBOUND_KEY_DATA(*ppContextSSH) = NULL;
    }

    if (NULL != OUTBOUND_KEY_DATA(*ppContextSSH))
    {
        CRYPTO_FREE( (*ppContextSSH)->hwAccelCookie, TRUE, &(OUTBOUND_KEY_DATA(*ppContextSSH)) ) ;
        OUTBOUND_KEY_DATA(*ppContextSSH) = NULL;
    }

    if (NULL != INBOUND_CIPHER_CONTEXT_FREE(*ppContextSSH))
    {
        (INBOUND_CIPHER_CONTEXT_FREE(*ppContextSSH))(MOC_SYM((*ppContextSSH)->hwAccelCookie) &INBOUND_CIPHER_CONTEXT(*ppContextSSH));
        (INBOUND_CIPHER_CONTEXT_FREE(*ppContextSSH))(MOC_SYM((*ppContextSSH)->hwAccelCookie) &INBOUND_CIPHER_CONTEXT2(*ppContextSSH));
    }

    if (NULL != OUTBOUND_CIPHER_CONTEXT_FREE(*ppContextSSH))
    {
        OUTBOUND_CIPHER_CONTEXT_FREE(*ppContextSSH)(MOC_SYM((*ppContextSSH)->hwAccelCookie) &OUTBOUND_CIPHER_CONTEXT(*ppContextSSH));
        OUTBOUND_CIPHER_CONTEXT_FREE(*ppContextSSH)(MOC_SYM((*ppContextSSH)->hwAccelCookie) &OUTBOUND_CIPHER_CONTEXT2(*ppContextSSH));
    }

    if (NULL != SSH_SESSION_ID(*ppContextSSH))
    {
        CRYPTO_FREE ( (*ppContextSSH)->hwAccelCookie, TRUE, &SSH_SESSION_ID(*ppContextSSH) );
        SSH_SESSION_ID(*ppContextSSH) = NULL;
    }
    SSH_IN_MESG_deallocStructures(*ppContextSSH);
    SSH_OUT_MESG_deallocStructures(*ppContextSSH);
    SSH_AUTH_deallocStructures(*ppContextSSH);

    if (NULL != SSH_HASH_H(*ppContextSSH))
    {
        CRYPTO_FREE((*ppContextSSH)->hwAccelCookie, TRUE, &SSH_HASH_H(*ppContextSSH));
        SSH_HASH_H(*ppContextSSH) = NULL;
    }

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DH_freeDhContext(&SSH_DIFFIEHELLMAN_CONTEXT(*ppContextSSH), NULL);
#else
    DH_freeDhContext(&SSH_DIFFIEHELLMAN_CONTEXT(*ppContextSSH), NULL);
#endif

#ifdef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
    MOC_STREAM_close(&((*ppContextSSH)->pSocketOutStreamDescr));
#endif

#ifdef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
    if (NULL != (*ppContextSSH)->pAsyncCacheMessage)
    {
        FREE((*ppContextSSH)->pAsyncCacheMessage);
        (*ppContextSSH)->pAsyncCacheMessage = NULL;
    }
#endif

#ifdef __ENABLE_MOCANA_SSH_FTP_SERVER__
    if (NULL != (*ppContextSSH)->p_sftpIncomingBuffer)
        FREE((*ppContextSSH)->p_sftpIncomingBuffer);

    /* free any unproperly closed handles */
    SSH_FTP_closeAllOpenHandles(*ppContextSSH);

    /* free the home directory */
    SSH_STR_freeStringBuffer(&(SFTP_CURRENT_PATH(*ppContextSSH)));

    for (i = 0; i < SFTP_NUM_HANDLES; i++)
        SSH_STR_freeStringBuffer((sshStringBuffer **)(&((*ppContextSSH)->sessionState.fileHandles[i].pHandleName)));
#endif

    if ((NULL != (*ppContextSSH)->pKeyExSuiteInfo) &&
        (NULL != (*ppContextSSH)->pKeyExSuiteInfo->pKeyExMethods) &&
        (NULL != (*ppContextSSH)->pKeyExSuiteInfo->pKeyExMethods->freeCtx))
    {
        /* free key exchange context (dh, rsa, ecdh, etc) */
        (*ppContextSSH)->pKeyExSuiteInfo->pKeyExMethods->freeCtx(*ppContextSSH);
    }

    if ((NULL != (*ppContextSSH)->pKeyExSuiteInfo) &&
        (NULL != (*ppContextSSH)->pKeyExSuiteInfo->pHashHandshakeAlgo) &&
        (NULL != (*ppContextSSH)->sshKeyExCtx.pKeyExHash))
    {
        (*ppContextSSH)->pKeyExSuiteInfo->pHashHandshakeAlgo->pFreeFunc(MOC_HASH((*ppContextSSH)->hwAccelCookie) &(*ppContextSSH)->sshKeyExCtx.pKeyExHash);
    }

    CRYPTO_uninitAsymmetricKey(&((*ppContextSSH)->hostKey), NULL);
    VLONG_freeVlong(&SSH_K(*ppContextSSH), NULL);

    for (i = 0; i < 10; i++)
    {
        if (NULL != ((*ppContextSSH)->useThisList[i].pString))
        {
            FREE((*ppContextSSH)->useThisList[i].pString);
            (*ppContextSSH)->useThisList[i].pString = NULL;
        }
    }

    if (NULL != (*ppContextSSH)->pTerminal)
    {
        terminalState* pTerminal = (*ppContextSSH)->pTerminal;

        if (NULL != pTerminal->pTerminalEnvironment)
            FREE(pTerminal->pTerminalEnvironment);

        if (NULL != pTerminal->pEncodedTerminalModes)
            FREE(pTerminal->pEncodedTerminalModes);

        MOC_MEMSET((ubyte *)pTerminal, 0x00, sizeof(terminalState));
        FREE((*ppContextSSH)->pTerminal);
    }

    if (NULL != (*ppContextSSH)->authAdvertised.pString)
    {
       FREE((*ppContextSSH)->authAdvertised.pString);
    }

    if (NULL != (*ppContextSSH)->decryptIV)
    {
        CRYPTO_FREE ( (*ppContextSSH)->hwAccelCookie, TRUE, &(*ppContextSSH)->decryptIV );
    }

    if (NULL != (*ppContextSSH)->encryptIV)
    {
        CRYPTO_FREE ( (*ppContextSSH)->hwAccelCookie, TRUE, &(*ppContextSSH)->encryptIV );
    }

    if ( NULL != (*ppContextSSH)->smallPool.pStartOfPool )
    {
        CRYPTO_FREE ( (*ppContextSSH)->hwAccelCookie, TRUE, &(*ppContextSSH)->smallPool.pStartOfPool );
    }

    if ( NULL != (*ppContextSSH)->mediumPool.pStartOfPool )
    {
        CRYPTO_FREE ( (*ppContextSSH)->hwAccelCookie, TRUE, &(*ppContextSSH)->mediumPool.pStartOfPool );
    }

    if (NULL != (*ppContextSSH)->pHostBlob)
    {
        CRYPTO_FREE((*ppContextSSH)->hwAccelCookie, TRUE, &((*ppContextSSH)->pHostBlob));
    }

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
    destroyLpfData(*ppContextSSH);
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSH, &(*ppContextSSH)->hwAccelCookie);
    FREE(*ppContextSSH);
    *ppContextSSH = NULL;

exit:
    return status;
}

#endif /* __ENABLE_MOCANA_SSH_SERVER__ */



