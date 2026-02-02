openssl genrsa -out key%1.pem %1
openssl rsa -inform PEM -in key%1.pem -outform DER -out key%1.der
rm key%1.pem
