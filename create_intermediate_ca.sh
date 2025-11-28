#!/bin/bash
set -e

# Create directory structure
mkdir -p pki/intermediate/private pki/intermediate/newcerts
chmod 700 pki/intermediate/private
touch pki/intermediate/index.txt
if [ ! -f pki/intermediate/serial ]; then
    echo 1000 > pki/intermediate/serial
fi
if [ ! -f pki/intermediate/crlnumber ]; then
    echo 1000 > pki/intermediate/crlnumber
fi

echo "Generating Intermediate CA private key..."
openssl genrsa -aes256 -out pki/intermediate/intermediate.key 4096

echo "Generating Intermediate CA CSR..."
openssl req -config pki/ca-intermediate.cnf -new -sha256 \
      -key pki/intermediate/intermediate.key \
      -out pki/intermediate/intermediate.csr

echo "Signing Intermediate CA CSR with Root CA..."
openssl ca -config pki/ca-root.cnf -extensions v3_intermediate_ca \
      -extfile pki/ca-intermediate.cnf \
      -days 1825 -notext -md sha256 \
      -in pki/intermediate/intermediate.csr \
      -out pki/intermediate/intermediate.crt \
      -batch
