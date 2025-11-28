#!/bin/bash
set -e

# Create directory structure
mkdir -p pki/root/private pki/root/newcerts
chmod 700 pki/root/private
touch pki/root/index.txt
if [ ! -f pki/root/serial ]; then
    echo 1000 > pki/root/serial
fi

echo "Generating Root CA private key..."
openssl genrsa -aes256 -out pki/root/root.key 4096

echo "Generating Root CA certificate..."
openssl req -config pki/ca-root.cnf \
      -key pki/root/root.key \
      -new -x509 -days 3650 -sha256 -extensions v3_ca \
      -out pki/root/root.crt
