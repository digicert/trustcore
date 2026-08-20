/*
 * ssh_nist.h
 *
 * Function prototypes for testing SSH against SP 800-135
 *
 */

#ifndef __SSH_NIST_H__
#define __SSH_NIST_H__

#ifdef __ENABLE_DIGICERT_SP800_135_ACVP__

enum {
    sshK =             1,
    sshH  =            2,
    sshSessionId  =    3,
    sshCTSIV  =        4,
    sshSTCIV  =        5,
    sshEncrCTS  =      6,
    sshEncrSTC  =      7,
    sshIntegrityCTS  = 8,
    sshIntegritySTC =  9
};

/* Set the hash alg, iv length, and key length. ppOptions will be allocated and filled by this function, for use
 * as input to getSSHValue or receiveNewKeysMessage */
MSTATUS setSSHDesiredLengths(sshContext *pContextSSH, ubyte hashAlg, sbyte4 ivLen, sbyte4 keyLen, ubyte **ppOptions);

/* Set a value in the SSH context. Type must be one of {sshK, sshH, sshSessionId} */
MSTATUS setSSHValue(sshContext *pContextSSH, ubyte type, ubyte *pValue, ubyte4 valueLen);

/* Get a value from the SSH context. New values are allocated by this function, caller is responsible to free
 * the pointer. Type must be one of {sshCTSIV, sshSTCIV, sshEncrCTS, sshEncrSTC, sshIntegrityCTS, sshIntegritySTC} */
MSTATUS getSSHValue(sshContext *pContextSSH, ubyte *pOptions, ubyte type, ubyte **ppValue, ubyte4 *pValueLen);

/* Free the internal buffer within the SSH context holding the K value */
void freeSSHK(sshContext *pContextSSH);

/* SSH function that performs the key derivation */
extern MSTATUS
receiveNewKeysMessage(sshContext *pContextSSH, ubyte *pOptionsSelected,
                      ubyte *pNewMesg, ubyte4 newMesgLen);

#endif
#endif
