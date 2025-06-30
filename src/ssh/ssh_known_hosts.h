/*
 * ssh_known_hosts.h
 *
 * Mocana Initialization Header
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

#ifndef __SSH_KNOWN_HOST_HEADER__
#define __SSH_KNOWN_HOST_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


#ifdef __ENABLE_MOCANA_SSH_KNOWN_HOSTS__

/**
@brief      Add a host entry to a NanoSSH known-host list.

@details    This function adds a host entry to the end of the NanoSSH
            known-host list.

Before calling this function, call SSH_KNOWN_HOSTS_checkHostEntryExits() to
check whether the host entry is already in the known-host list, which avoids
adding duplicate entries.

Or instead of calling SSH_KNOWN_HOSTS_addKnownHostsEntry (this function), you
can call SSH_KNOWN_HOSTS_updateKnownHostsEntry(), which checks the list to see
if the specified host name is already in the known-host list. If the host is
in the list, the entry is updated; if the host is not found, it is added.

@note       The address that is referenced by \p ppBuffer is changed by this
            function call.
            
This function allocates memory for a new known-host list buffer that is the
combined size of the existing known-host list plus the new entry. The function
copies the existing buffer contents plus the new entry to the newly
allocated buffer, and then frees the original buffer.

If this is the first call to SSH_KNOWN_HOSTS_addKnownHostsEntry after reading
a file of host entries, you should call SSH_KNOWN_HOSTS_updateEntries(), which
updates the value of the global variable that tracks the number of entries in 
the known-hosts list.

@ingroup    func_ssh_server_known_hosts

@since 5.4
@version 5.4 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_SSH_KNOWN_HOSTS__

@inc_file ssh_known_hosts.h

@param ppBuffer     NULL or a pointer to the address of a buffer containing
                      a list of known-host entries. On return, reference to the
                      new buffer containing the contents of the submitted buffer
                      (if any) plus an entry created from the submitted host
                      name and key. The original buffer, if not NULL, is freed.
@param pBufferLen   Pointer to the length of the input buffer, \p ppBuffer. On
                      return, the value is updated to the new buffer's length.
@param hostName     Pointer to DNS name or IP address to add.
@param pKey         Pointer to key associated with the host name, \p hostName,
                      to add.
@param pKeyLen      Pointer to length of the key, \p pKey.
@param pRetVal      On return, pointer to the value 1 if the host is added to
                      the known-host list; 0 if the host was not added.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ssh_known_hosts.c
*/
MOC_EXTERN MSTATUS SSH_KNOWN_HOSTS_addKnownHostsEntry(ubyte** ppBuffer, ubyte4* bufferLen, ubyte * hostName, ubyte * pKey, sbyte4 pKeyLen, ubyte4 * pRetVal);

/**
@brief      Determine whether a host entry already exists in a given
            known-host buffer.

@details    This function determines whether there is an entry for a given
            host in a given known-host buffer. If so, this function returns,
            through the \p pIndex parameter, the 0-based index to the found
            entry's line in the buffer.

@ingroup    func_ssh_server_known_hosts

@since 5.4
@version 5.4 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_SSH_KNOWN_HOSTS__


@inc_file ssh_known_hosts.h

@param pBuffer      Pointer to a buffer containing the known-hosts list
                      for NanoSSH.
@param bufferLen    Length of the input buffer, \p pBuffer.
@param hostName     Pointer to DNS name or IP address to search for.
@param pIndex       On return, if the entry is found (indicated by a value of
                      1 returned through the \p pRetVal parameter is 1), the
                      0-based index to the found entry's line in \p pBuffer.
@param pRetVal      On return, pointer to the value 1 if the entry is found in
                      \p pBuffer; 0 if the entry was not found.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ssh_known_hosts.c
*/
MOC_EXTERN MSTATUS SSH_KNOWN_HOSTS_checkHostEntryExists(ubyte* pBuffer, ubyte4 bufferLen, ubyte * hostName, ubyte4* pIndex, ubyte4 * pRetVal);

/**
@brief      Get the number of entries in the NanoSSH known-hosts list.

@details    This function returns (through the \p pEntries parameter) the
            number of entries in the NanoSSH known-hosts list. The entries
            count equals the global known-hosts entries count, \c
            SSH_KNOWN_HOSTS_entries, which is incremented for every successful
            call to SSH_KNOWN_HOSTS_addKnownHostsEntry(), and decremented for
            every successful call to SSH_KNOWN_HOSTS_removeKnownHostsEntry().

@warning    If you directly manipulate the NanoSSH known-hosts list (that is,
            add or delete entries without calling
            SSH_KNOWN_HOSTS_addKnownHostsEntry() or
            SSH_KNOWN_HOSTS_removeKnownHostsEntry()), you must call call
            SSH_KNOWN_HOSTS_updateEntries() to update the global known-hosts
            entries count. If you do not make this call, the global known-hosts
            entries count, \c SSH_KNOWN_HOSTS_entries, will be incorrect.

@ingroup    func_ssh_server_known_hosts

@since 5.4
@version 5.4 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_SSH_KNOWN_HOSTS__

@inc_file ssh_known_hosts.h

@param pEntries     On return, the number of entries in the NanoSSH known-hosts
                      list, based on the value of the global known-hosts
                      entries count, \c SSH_KNOWN_HOSTS_entries.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ssh_known_hosts.c
*/
MOC_EXTERN MSTATUS SSH_KNOWN_HOSTS_getEntries(sbyte4 *pEntries);

/*
@brief      Read a known-hosts file and store it in a given known-hosts buffer.

@details    This function reads a known-hosts file and stores its contents in
            a given known-hosts buffer. There is no validity checking on the
            file's contents; they are simply stored in the buffer.

@note       To avoid memory leaks, be sure to make a subsequent call to
            MOCANA_freeReadFile().

@ingroup    func_ssh_server_known_hosts

@since 5.4
@version 5.4 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_SSH_KNOWN_HOSTS__
+ \c \__ENABLE_MOCANA_IPV6__

@inc_file ssh_known_hosts.h

@param filename     Name of file to read.
@param ppBuffer     Pointer to a buffer in which to store the file's contents.
@param pBufferLen   On return, number of bytes stored in the buffer, \p ppBuffer.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This is a convenience function provided for your application's use;
            it is not used by Mocana SoT Platform code.

@funcdoc    ssh_known_hosts.c
*/
MOC_EXTERN MSTATUS SSH_KNOWN_HOSTS_readFile(sbyte* filename, ubyte** ppBuffer, ubyte4* pBufferLen);

/**
@brief      Remove a host entry from a given known-hosts buffer, if found.

@details    This function removes a host entry from a given known-hosts buffer,
            if found.

@ingroup    func_ssh_server_known_hosts

@since 5.4
@version 5.4 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_SSH_KNOWN_HOSTS__
+ \c \__ENABLE_MOCANA_IPV6__

@inc_file ssh_known_hosts.h

@param ppBuffer         NULL or a pointer to the address of a buffer containing
                          a list of known-host entries. On return, referec to
                          the new buffer containing the contents of the
                          submitted buffer (if any) minus the deleted entry.
                          The original buffer, if not NULL, is freed.
@param pBufferLen       Pointer to the length of the input buffer, \p
                          ppBuffer. On return, the value is updated to the new
                          buffer's length.
@param hostName         Pointer to DNS name or IP address to remove.\n
                          @note     If you pass a value in through the \p
                            passed_index parameter, it overrides the \p hostName
                            parameter. That is, the entry for the \p 
                            passed_index is removed even if it does not match
                            the \p hostName value.
@param passed_index     NULL to match the \p hostName value; otherwise the
                         0-based index of the line to remove from the given
                         known-hosts buffer, \p ppBuffer.
@param pRetVal          On return, pointer to the value 1 if the host is
                          removed from  the known-host list; 0 if the host was
                          not removed.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ssh_known_hosts.c
*/
MOC_EXTERN MSTATUS SSH_KNOWN_HOSTS_removeKnownHostsEntry(ubyte** ppBuffer, ubyte4* pBufferLen, ubyte * hostName, ubyte4 *passed_index, ubyte4* pRetVal);

/**
@brief      Get the key that corresponds to a given host name.

@details    This function returns (through the \p ppKey parameter) the key for
            a given host name.

@ingroup    func_ssh_server_known_hosts

@since 5.4
@version 5.4 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_SSH_KNOWN_HOSTS__
+ \c \__ENABLE_MOCANA_IPV6__

@inc_file ssh_known_hosts.h

@param pBuffer      NULL or a pointer to a buffer containing a list of
                      known-host entries.
@param bufferLen    Length of the input buffer, \p pBuffer.
@param hostName      DNS name or IP address that the key is matched to.
@param ppKey        On return, pointer to key value, if the key is found.
@param pKeyLen      On return, length of the key value, \p ppKey, if the key is
                      found.
@param pRetVal      On return, pointer to the value 1 if the is found; 0 if
                      not.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ssh_known_hosts.c
*/
MOC_EXTERN MSTATUS SSH_KNOWN_HOSTS_retrieveKeyForKnownHostsEntry(ubyte* pBuffer, ubyte4 bufferLen, ubyte * hostName, ubyte ** ppKey, ubyte4 * pKeyLen, ubyte4 * pRetVal);

/**
@brief      Update the global known-hosts entries count, based on a given 
            known-hosts buffer.

@details    The function updates the global known-hosts entries count, \c
            SSH_KNOWN_HOSTS_entries, based on the number of entries in a given
            buffer, \p pBuffer. 

If you directly manipulate the NanoSSH known-hosts list (that is, read a hosts
file by calling SSH_KNOWN_HOSTS_readFile(), or add or delete entries by means
other than calling SSH_KNOWN_HOSTS_addKnownHostsEntry() or
SSH_KNOWN_HOSTS_removeKnownHostsEntry()), you must call call
SSH_KNOWN_HOSTS_updateEntries to update the global variable count.

@ingroup    func_ssh_server_known_hosts

@since 5.4
@version 5.4 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_SSH_KNOWN_HOSTS__
+ \c \__ENABLE_MOCANA_IPV6__

@inc_file ssh_known_hosts.h

@param pBuffer       Pointer to a buffer containing a list of known-host entries.
@param bufferLen     Length the input buffer, \p pBuffer.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ssh_known_hosts.c
*/
MOC_EXTERN MSTATUS SSH_KNOWN_HOSTS_updateEntries(ubyte * pBuffer, ubyte4 bufferLen);

/**
@brief      Update or add a host entry to a NanoSSH known-host list.

@details    This function updates a host entry in a NanoSSH known-host list if 
            the entry is already present. If the entry is not in the known-host
            list, this function adds it.

@ingroup    func_ssh_server_known_hosts

@since 5.4
@version 5.4 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_SSH_KNOWN_HOSTS__
+ \c \__ENABLE_MOCANA_IPV6__

@inc_file ssh_known_hosts.h

@param ppBuffer     NULL or a pointer to the address of a buffer containing
                      a list of known-host entries. On return, reference to the
                      new buffer containing the contents of the submitted buffer
                      (if any) and the changed/added entry as specified by
                      the remaining parameters. The original buffer, if not NULL, is freed.
@param pBufferLen   Pointer to the length of the input buffer, \p ppBuffer. On
                      return, the value is updated to the new buffer's length.
@param hostName     Pointer to DNS name or IP address to update/add.
@param pKey         Pointer to key to update for the host name, \p hostName,
                      if the host is already in the buffer, or the key include
                      in the entry if it is added.
@param pKeyLen      Pointer to length of the key, \p pKey.
@param pRetVal      On return, pointer to the value 1 if the host is
                      updated/added; 0 if the host was not updated/added.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ssh_known_hosts.c
*/
MOC_EXTERN MSTATUS SSH_KNOWN_HOSTS_updateKnownHostsEntry(ubyte** ppBuffer, ubyte4* pBufferLen, ubyte * hostName, ubyte * pKey, sbyte4 pKeyLen, ubyte4 * pRetVal);

/**
@brief      Verify that a given key matches a given host's key in the given
            known-hosts buffer.

@details    This function verifies that a given key matches a given host's key
            in the given known-hosts buffer.

@ingroup    func_ssh_server_known_hosts

@since 5.4
@version 5.4 and later

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_SSH_KNOWN_HOSTS__
+ \c \__ENABLE_MOCANA_IPV6__

@inc_file ssh_known_hosts.h

@param pBuffer      NULL or a pointer to the address of a buffer containing
                      a list of known-host entries. 
@param bufferLen    Length of the input buffer, \p pBuffer.
@param hostName     Pointer to DNS name or IP address of the host to verify.
@param pKey         Pointer to key to match.
@param pKeyLen      Pointer to length of the key, \p pKey.
@param pRetVal      On return, pointer to the value 1 if the host key matches
                      the given key; 0 if the host key does not match the
                      given key.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ssh_known_hosts.c
*/
MOC_EXTERN MSTATUS SSH_KNOWN_HOSTS_verifyKnownHostKeyEntry(ubyte* pBuffer, ubyte4 bufferLen, ubyte* hostName, ubyte * pKey, sbyte4 pKeyLen, ubyte4 * pRetVal);
#endif


#ifdef __cplusplus
}
#endif

#endif /* __SSH_KNOWN_HOST_HEADER__ */
