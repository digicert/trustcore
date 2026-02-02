#! /usr/bin/env bash
# command to create a receipt request using OpenSSL CMS 1.0 or higher:

/usr/local/ssl/bin/openssl cms -sign -in DeBelloGallico.txt -outform DER -out receipt_request_signed.der -inkey  openssl_key2.pem  -signer openssl_cert2.pem  -receipt_request_all -receipt_request_to fferino@mocana.com 