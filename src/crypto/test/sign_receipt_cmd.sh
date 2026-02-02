#! /usr/bin/env bash

# command to generate a signed receipt 

/usr/local/ssl/bin/openssl cms -sign_receipt -in receipt_request_signed_multiple_signer_from_to.der -out sign_receipt_signed_multiple_signer_from_to.der -inform DER -outform DER -signer openssl_cert1.pem -inkey openssl_key1.pem
