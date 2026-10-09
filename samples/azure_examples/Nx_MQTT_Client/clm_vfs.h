/**
 * clm_vfs.h
 *
 * Public interface for the CLM RAM-backed virtual filesystem.
 * Provides all UTILS_* and DIGICERT_* file I/O symbols required by
 * TRUSTEDGE_EST_main() on bare-metal Azure RTOS / ThreadX (no FileX,
 * no POSIX).
 *
 * Call CLM_VFS_Reset() before each TRUSTEDGE_EST_main() invocation.
 * After it returns OK, call CLM_VFS_GetKeyDer() / CLM_VFS_GetCertDer()
 * to extract the enrolled key and certificate for flash storage.
 */

#ifndef CLM_VFS_H
#define CLM_VFS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * CLM_VFS_Reset – Wipe all VFS slots and reclaim the pool.
 * Must be called before each EST enrollment/renewal attempt.
 */
void CLM_VFS_Reset(void);

/**
 * CLM_VFS_GetKeyDer – Return a pointer to the enrolled private key in DER.
 * Returns 0 on success, -1 if no key file has been written yet.
 * The returned pointer is valid until the next CLM_VFS_Reset() call.
 */
int CLM_VFS_GetKeyDer(const uint8_t **ppKey, uint32_t *pLen);

/**
 * CLM_VFS_GetCertDer – Return a pointer to the enrolled device cert in DER.
 * Returns 0 on success, -1 if no certificate has been written yet.
 * The returned pointer is valid until the next CLM_VFS_Reset() call.
 */
int CLM_VFS_GetCertDer(const uint8_t **ppCert, uint32_t *pLen);

#ifdef __cplusplus
}
#endif

#endif /* CLM_VFS_H */
