/*
 * sshc_context.c
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
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 * 
 */


#include "../../common/moptions.h"

#ifdef __ENABLE_MOCANA_SSH_CLIENT__

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"

#define __ENABLE_OUTBOUND_SSH_DEFINITIONS__
#define __ENABLE_INBOUND_SSH_DEFINITIONS__

#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../crypto/secmod.h"
#include "../../common/mrtos.h"
#include "../../common/mtcp.h"
#include "../../common/mstdlib.h"
#include "../../common/random.h"
#include "../../common/vlong.h"
#include "../../common/debug_console.h"
#include "../../common/mem_pool.h"
#include "../../common/memory_debug.h"
#include "../../common/circ_buf.h"
#include "../../crypto/dsa.h"
#include "../../crypto/dh.h"
#include "../../crypto/crypto.h"
#ifdef __ENABLE_MOCANA_ECC__
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#endif
#include "../../crypto/pubcrypto.h"
#include "../../common/sizedbuffer.h"
#include "../../crypto/cert_store.h"
#include "../../crypto/ca_mgmt.h"
#include "../../ssh/client/sshc.h"
#include "../../ssh/ssh_str.h"
#include "../../ssh/client/sshc_str_house.h"
#include "../../ssh/client/sshc_filesys.h"
#include "../../ssh/client/sshc_context.h"
#include "../../ssh/client/sshc_in_mesg.h"
#include "../../ssh/client/sshc_out_mesg.h"
#include "../../ssh/client/sshc_client.h"
#include "../../ssh/client/sshc_session.h"
#include "../../ssh/client/sshc_ftp.h"
#include "../../ssh/client/sshc_trans.h"
#include "../../ssh/client/sshc_auth.h"
#include "../../harness/harness.h"


/*------------------------------------------------------------------*/

#define SSH2_DEFAULT_CIPER_SIZE     (8)
#define SSH_SMALL_TEMP_BUF_SIZE     (64)
#define SSH_MEDIUM_TEMP_BUF_SIZE    (160)
#define SSH_SHA1_TEMP_BUF_SIZE      (96)

static BulkEncryptionAlgo NULLSuite = { 1, NULL, NULL, NULL, NULL };
static SSH_CipherSuiteInfo mNullCipherSuite = { (sbyte *)"null", 4, 0, SSH2_DEFAULT_CIPER_SIZE, &NULLSuite, NULL };
static SSH_hmacSuiteInfo   mNullHmacSuite   = { (sbyte *)"null", 4, 0, 0, NULL, NULL };

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
static void destroyLpfData(sshClientContext* pContextSSH)
{
    sshcPfSession*  pTemp   = NULL;
    sshcPfSession*  pTarget = NULL;

    if ( NULL != pContextSSH->pLpfHead )
    {
        pTemp = pContextSSH->pLpfHead;

        while( NULL != pTemp )
        {
            pTarget = pTemp->pNextSession;
            FREE(pTemp);
            pTemp = pTarget;
        }/* End of while loop */

        pContextSSH->pLpfHead = NULL;
    }
}
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */

extern MSTATUS
SSHC_CONTEXT_allocStructures(sshClientContext **ppContextSSH)
{
    ubyte*  pTempMemBuffer = NULL;
    MSTATUS status;

    if (NULL == ppContextSSH)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (*ppContextSSH = MALLOC(sizeof(sshClientContext))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    MOC_MEMSET((ubyte *)(*ppContextSSH), 0x00, sizeof(sshClientContext));

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

    pTempMemBuffer = NULL;
    /*** SHA-1 Context Memory Pool ***/
    /*if (OK > (status = CRYPTO_ALLOC((*ppContextSSH)->hwAccelCookie, SSH_SHA1_TEMP_BUF_SIZE * 5, TRUE, &pTempMemBuffer)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pTempMemBuffer);
    MOC_MEMSET((ubyte *)(pTempMemBuffer), 0x00, SSH_SHA1_TEMP_BUF_SIZE * 5);
    if (OK > (status = MEM_POOL_initPool(&((*ppContextSSH)->sha1Pool), pTempMemBuffer, SSH_SHA1_TEMP_BUF_SIZE * 5, SSH_SMALL_TEMP_BUF_SIZE)))
        goto exit;

    pTempMemBuffer = NULL;*/

    OUTBOUND_BUFFER_SIZE(*ppContextSSH)       = SSHC_MAX_BUFFER_SIZE;
    OUTBOUND_MAX_MESSAGE_SIZE(*ppContextSSH)  = SSHC_MAX_BUFFER_SIZE;
    OUTBOUND_CIPHER_SUITE_INFO(*ppContextSSH) = &mNullCipherSuite;
    OUTBOUND_MAC_INFO(*ppContextSSH)          = &mNullHmacSuite;

    INBOUND_BUFFER_SIZE(*ppContextSSH)        = SSHC_MAX_BUFFER_SIZE;
    INBOUND_MAX_MESSAGE_SIZE(*ppContextSSH)   = SSHC_MAX_BUFFER_SIZE; /*!!!! add growing buffer support here */
    INBOUND_CIPHER_SUITE_INFO(*ppContextSSH)  = &mNullCipherSuite;
    INBOUND_MAC_INFO(*ppContextSSH)           = &mNullHmacSuite;

    if (OK > (status = SSHC_IN_MESG_allocStructures(*ppContextSSH)))
        goto exit;

    if (OK > (status = SSHC_OUT_MESG_allocStructures(*ppContextSSH)))
        goto exit;

    if (OK > (status = SSHC_AUTH_allocStructures(*ppContextSSH)))
        goto exit;

    if (NULL == ((*ppContextSSH)->pTerminal = MALLOC(sizeof(clientTerminalState))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if ( OK > (status = CRYPTO_ALLOC ( (*ppContextSSH)->hwAccelCookie, 40 , TRUE, &(*ppContextSSH)->decryptIV ) ) )
        goto exit;
    MOC_MEMSET((ubyte *)((*ppContextSSH)->decryptIV), 0x00, 40);
    if ( OK > (status = CRYPTO_ALLOC ( (*ppContextSSH)->hwAccelCookie, 40 , TRUE, &(*ppContextSSH)->encryptIV ) ) )
        goto exit;
    MOC_MEMSET((ubyte *)((*ppContextSSH)->encryptIV), 0x00, 40);

    MOC_MEMSET((*ppContextSSH)->pTerminal, 0x00, sizeof(clientTerminalState));

    /* default value when no cipher suite has been selected */
    INBOUND_CIPHER_TYPE(*ppContextSSH) = IGNORE;
    OUTBOUND_CIPHER_TYPE(*ppContextSSH) = IGNORE;

exit:
    if ((OK > status) && (NULL != ppContextSSH) && (NULL != *ppContextSSH))
        SSHC_CONTEXT_deallocStructures(ppContextSSH);

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_CONTEXT_deallocStructures(sshClientContext **ppContextSSH)
{
    sbyte4  index;
    MSTATUS status = OK;

    if (NULL == ppContextSSH)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if (defined(__ENABLE_MOCANA_SSH_FTP_CLIENT__))
    SSHC_FTP_freeAllHandles(*ppContextSSH);
#endif

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

    if (NULL != ((*ppContextSSH)->pCertificate))
        SSH_STR_freeStringBuffer(&((*ppContextSSH)->pCertificate));

    if ((NULL != ((*ppContextSSH)->pDecryptSuiteInfoIn->pBEAlgo)) && (NULL != INBOUND_CIPHER_CONTEXT_FREE(*ppContextSSH)))
    {
        (INBOUND_CIPHER_CONTEXT_FREE(*ppContextSSH))(MOC_SYM((*ppContextSSH)->hwAccelCookie) &INBOUND_CIPHER_CONTEXT(*ppContextSSH));
        (INBOUND_CIPHER_CONTEXT_FREE(*ppContextSSH))(MOC_SYM((*ppContextSSH)->hwAccelCookie) &INBOUND_CIPHER_CONTEXT2(*ppContextSSH));
    }

    if ((NULL != ((*ppContextSSH)->pEncryptSuiteInfoOut->pBEAlgo)) && (NULL != OUTBOUND_CIPHER_CONTEXT_FREE(*ppContextSSH)))
    {
        OUTBOUND_CIPHER_CONTEXT_FREE(*ppContextSSH)(MOC_SYM((*ppContextSSH)->hwAccelCookie) &OUTBOUND_CIPHER_CONTEXT(*ppContextSSH));
        OUTBOUND_CIPHER_CONTEXT_FREE(*ppContextSSH)(MOC_SYM((*ppContextSSH)->hwAccelCookie) &OUTBOUND_CIPHER_CONTEXT2(*ppContextSSH));
    }

    if (NULL != SSH_SESSION_ID(*ppContextSSH))
    {
        CRYPTO_FREE ( (*ppContextSSH)->hwAccelCookie, TRUE, &(SSH_SESSION_ID(*ppContextSSH)));
        SSH_SESSION_ID(*ppContextSSH) = NULL;
    }

    SSHC_IN_MESG_deallocStructures(*ppContextSSH);
    SSHC_OUT_MESG_deallocStructures(*ppContextSSH);
    SSHC_AUTH_deallocStructures(*ppContextSSH);

    for (index = 0; index < 10; index++)
    {
        if (NULL != ((*ppContextSSH)->sshc_algorithmMethods[index].pString))
        {
            FREE((*ppContextSSH)->sshc_algorithmMethods[index].pString);
            (*ppContextSSH)->sshc_algorithmMethods[index].pString = NULL;
        }
    }

    if (NULL != (*ppContextSSH)->pTerminal)
    {
        clientTerminalState* pTerminal = (*ppContextSSH)->pTerminal;

        if (NULL != pTerminal->pTerminalEnvironment)
            FREE(pTerminal->pTerminalEnvironment);

        if (NULL != pTerminal->pEncodedTerminalModes)
            FREE(pTerminal->pEncodedTerminalModes);

        MOC_MEMSET((ubyte *)pTerminal, 0x00, sizeof(clientTerminalState));
        FREE((*ppContextSSH)->pTerminal);
    }

#ifdef __ENABLE_MOCANA_SSH_FTP_CLIENT__
    if (NULL != (*ppContextSSH)->p_sftpIncomingBuffer)
    {
        FREE((*ppContextSSH)->p_sftpIncomingBuffer);
        (*ppContextSSH)->p_sftpIncomingBuffer = NULL;
    }
#endif

    if (NULL != (*ppContextSSH)->pKeyExSuiteInfo)
    {
        if ((NULL != (*ppContextSSH)->pKeyExSuiteInfo->pKeyExMethods) &&
            (NULL != (*ppContextSSH)->pKeyExSuiteInfo->pKeyExMethods->freeCtx))
        {
            /* free key exchange context (dh, rsa, ecdh, etc) */
            (*ppContextSSH)->pKeyExSuiteInfo->pKeyExMethods->freeCtx(*ppContextSSH);
        }

        if ((NULL != (*ppContextSSH)->pKeyExSuiteInfo->pHashHandshakeAlgo) && (NULL != (*ppContextSSH)->pKeyExSuiteInfo->pHashHandshakeAlgo->pFreeFunc))
        {
            /* free hash context to avoid memory leak when we re-key */
            if (NULL != (*ppContextSSH)->sshKeyExCtx.pKeyExHash)
                (*ppContextSSH)->pKeyExSuiteInfo->pHashHandshakeAlgo->pFreeFunc(MOC_HASH((*ppContextSSH)->hwAccelCookie) &((*ppContextSSH)->sshKeyExCtx.pKeyExHash));

            CRYPTO_FREE((*ppContextSSH)->hwAccelCookie, TRUE, &SSH_HASH_H((*ppContextSSH)));
        }
    }

    CRYPTO_FREE((*ppContextSSH)->hwAccelCookie, TRUE, &(*ppContextSSH)->sshKeyExCtx.pTempBuffer);
    CRYPTO_FREE((*ppContextSSH)->hwAccelCookie, TRUE, &(*ppContextSSH)->encryptIV );
    CRYPTO_FREE((*ppContextSSH)->hwAccelCookie, TRUE, &(*ppContextSSH)->decryptIV );
    VLONG_freeVlong(&SSH_K(*ppContextSSH), NULL);

    if ( NULL != (*ppContextSSH)->smallPool.pStartOfPool )
    {
        CRYPTO_FREE ( (*ppContextSSH)->hwAccelCookie, TRUE, &(*ppContextSSH)->smallPool.pStartOfPool );
    }

    if ( NULL != (*ppContextSSH)->mediumPool.pStartOfPool )
    {
        CRYPTO_FREE ( (*ppContextSSH)->hwAccelCookie, TRUE, &(*ppContextSSH)->mediumPool.pStartOfPool );
    }

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
    destroyLpfData(*ppContextSSH);
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */

#ifdef __ENABLE_MOCANA_SSH_X509V3_SIGN_SUPPORT__
    if ((*ppContextSSH)->pCommonName)
        FREE((*ppContextSSH)->pCommonName);
#endif

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSH, &(*ppContextSSH)->hwAccelCookie);
    FREE(*ppContextSSH);
    *ppContextSSH = NULL;

exit:
    return status;
}


#endif /* __ENABLE_MOCANA_SSH_CLIENT__ */



