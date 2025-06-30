/*
 * base64.h
 *
 * Base64 Encoder & Decoder Header
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


/*------------------------------------------------------------------*/

#ifndef __MOCANA_BASE64_HEADER__
#define __MOCANA_BASE64_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __IN_MOCANA_C__
/* these two functions should only be called from mocana.c */
MOC_EXTERN MSTATUS BASE64_initializeContext(void);
MOC_EXTERN MSTATUS BASE64_freeContext(void);
#endif

MOC_EXTERN MSTATUS BASE64_encodeMessage(const ubyte *pOrigMesg, ubyte4 origLen, ubyte **ppRetMesg, ubyte4 *pRetMesgLen);
MOC_EXTERN MSTATUS BASE64_urlEncodeMessage(const ubyte *pOrigMesg, ubyte4 origLen, ubyte **ppRetMesg, ubyte4 *pRetMesgLen);
MOC_EXTERN MSTATUS BASE64_decodeMessage(const ubyte *pOrigMesg, ubyte4 origLen, ubyte **ppRetMesg, ubyte4 *pRetMesgLen);
MOC_EXTERN MSTATUS BASE64_urlDecodeMessage(const ubyte *pOrigMesg, ubyte4 origLen, ubyte **ppRetMesg, ubyte4 *pRetMesgLen);
MOC_EXTERN MSTATUS BASE64_freeMessage(ubyte **ppMessage);

/** Make a PEM message out of the input DER.
 * <p>This function will allocate a new buffer, place a header, base 64 encode
 * the input (with appropriate line feeds), and place a footer. This will be
 * ASCII.
 * <p>The caller specifies what type of PEM data this will be, such as
 * CERTIFICATE, PRIVATE KEY, and so on. The pemType arg is one of the
 * MOC_PEM_TYPE_ values, such as MOC_PEM_TYPE_PRIVATE_KEY. This will determine
 * what the header and footer will be. For example, with PRIVATE_KEY, the header
 * and footer are
 * <pre>
 * <code>
 *    -----BEGIN PRIVATE KEY-----
 *    -----END PRIVATE KEY-----
 * </code>
 * </pre>
 * <p>The function will place a NULL-terminating character onto the end of the
 * buffer, but the return length does not include that character. For example,
 * the return length might be 350. If you look at buffer[349], you will see the
 * last character of the PEM, it will be '-'. If you look at buffer[350] you will
 * see a 0. So the function allocated 351 bytes, placed 350 bytes of PEM into the
 * buuuffer, then placed a NULL-terminating character.
 * <p>This function allocates memory for the result, it is the responsibility of
 * the caller to free that memory using MOC_FREE.
 *
 * @param pemType What type of PEM value is this? It must be one of the
 * MOC_PEM_TYPE_ values define in bsafe64.h.
 * @param pInputDer The data to be converted to PEM.
 * @param inputDerLen The length, in bytes, of the inputDer.
 * @param ppPemResult The address where the function will deposit the pointer to
 * allocated data containing the PEM data.
 * @param pPemResultLen The address where the function will deposit the length,
 * in bytes, of the PEM result. This length does not count the NULL-terminating
 * character.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @memory On success, memory is allocated for ppPemResult and must be freed by
 * calling MOC_FREE.
 */
MOC_EXTERN MSTATUS BASE64_makePemMessageAlloc (
  ubyte4 pemType,
  ubyte *pInputDer,
  ubyte4 inputDerLen,
  ubyte **ppPemResult,
  ubyte4 *pPemResultLen
  );

/** Decode a PEM message.
 * <p>This will strip the header and footer, then Base64 decode the contents. It
 * will allocate a buffer for the result and return it, the caller must free that
 * memory using MOC_FREE.
 * <p>The function will also determine what header was on the message and return
 * a flag indicating the type. The value returned will be one of the
 * MOC_PEM_TYPE_ values defined. If the header is unknown, the function will set
 * the return flag to MOC_PEM_TYPE_UNKNOWN and it will continue to decode the
 * message.
 *
 * @param pInputPem The PEM message.
 * @param inputPemLen The length, in bytes, of the PEM message.
 * @param pPemType The address where the function will deposit a flag indicating
 * which type of PEM message the input is.
 * @param ppDerResult The address where the function will deposit a pointer to
 * allocated memory containing the decoded PEM message.
 * @param pDerResultLen The address where the function will deposit the length,
 * in bytes, of the decoded message.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @memory On success, memory is allocated for ppDerResult and must be freed by
 * calling MOC_FREE.
 */
MOC_EXTERN MSTATUS BASE64_decodePemMessageAlloc (
  ubyte *pInputPem,
  ubyte4 inputPemLen,
  ubyte4 *pPemType,
  ubyte **ppDerResult,
  ubyte4 *pDerResultLen
  );

#define MOC_PEM_TYPE_UNKNOWN                0
#define MOC_PEM_TYPE_CERT_REQUEST           1
#define MOC_PEM_TYPE_CERT                   2
#define MOC_PEM_TYPE_PUB_KEY                3
#define MOC_PEM_TYPE_PRI_KEY                4
#define MOC_PEM_TYPE_CERT_ONE_LINE          5
#define MOC_PEM_TYPE_ENCR_PRI_KEY           6
#define MOC_PEM_TYPE_PRI_TAP_KEY            7
#define MOC_PEM_TYPE_CERT_REQUEST_ONE_LINE  8

#define MOC_PEM_REQ_HEADER_LEN      35
#define MOC_PEM_REQ_HEADER          "-----BEGIN CERTIFICATE REQUEST-----"
#define MOC_PEM_REQ_FOOTER_LEN      33
#define MOC_PEM_REQ_FOOTER          "-----END CERTIFICATE REQUEST-----"
#define MOC_PEM_CERT_HEADER_LEN     27
#define MOC_PEM_CERT_HEADER         "-----BEGIN CERTIFICATE-----"
#define MOC_PEM_CERT_FOOTER_LEN     25
#define MOC_PEM_CERT_FOOTER         "-----END CERTIFICATE-----"
#define MOC_PEM_PUB_HEADER_LEN      26
#define MOC_PEM_PUB_HEADER          "-----BEGIN PUBLIC KEY-----"
#define MOC_PEM_PUB_FOOTER_LEN      24
#define MOC_PEM_PUB_FOOTER          "-----END PUBLIC KEY-----"
#define MOC_PEM_PRI_HEADER_LEN      27
#define MOC_PEM_PRI_HEADER          "-----BEGIN PRIVATE KEY-----"
#define MOC_PEM_PRI_FOOTER_LEN      25
#define MOC_PEM_PRI_FOOTER          "-----END PRIVATE KEY-----"
#define MOC_PEM_ENCR_PRI_HEADER_LEN 37
#define MOC_PEM_ENCR_PRI_HEADER     "-----BEGIN ENCRYPTED PRIVATE KEY-----"
#define MOC_PEM_ENCR_PRI_FOOTER_LEN 35
#define MOC_PEM_ENCR_PRI_FOOTER     "-----END ENCRYPTED PRIVATE KEY-----"
#define MOC_PEM_PRI_TAP_HEADER_LEN  31
#define MOC_PEM_PRI_TAP_HEADER      "-----BEGIN TAP PRIVATE KEY-----"
#define MOC_PEM_PRI_TAP_FOOTER_LEN  29
#define MOC_PEM_PRI_TAP_FOOTER      "-----END TAP PRIVATE KEY-----"

#ifdef __cplusplus
}
#endif

#endif /* __MOCANA_BASE64_HEADER__ */
