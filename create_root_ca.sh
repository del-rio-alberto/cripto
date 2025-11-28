#!/bin/bash
set -e

# Create directory structure
mkdir -p pki/root/private pki/root/certs pki/root/newcerts
chmod 700 pki/root/private
touch pki/root/index.txt
if [ ! -f pki/root/serial ]; then
    echo 1000 > pki/root/serial
fi

echo "Generating Root CA private key..."
openssl genrsa -aes256 -out pki/root/private/root.key.pem 4096

echo "Generating Root CA certificate..."
openssl req -config pki/ca-root.cnf \
      -key pki/root/private/root.key.pem \
      -new -x509 -days 3650 -sha256 -extensions v3_ca \
      -batch \
      -out pki/root/certs/root.cert.pem

echo "Root CA generated successfully."
echo "Private Key: pki/root/private/root.key.pem"
echo "Certificate: pki/root/certs/root.cert.pem"
