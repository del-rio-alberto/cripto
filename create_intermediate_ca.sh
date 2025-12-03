#!/bin/bash
set -e

# Create directory structure
mkdir -p pki/intermediate/private pki/intermediate/certs pki/intermediate/newcerts pki/intermediate/crl
chmod 700 pki/intermediate/private
touch pki/intermediate/index.txt
if [ ! -f pki/intermediate/serial ]; then
    echo 1000 > pki/intermediate/serial
fi
if [ ! -f pki/intermediate/crlnumber ]; then
    echo 1000 > pki/intermediate/crlnumber
fi

echo "Generating Intermediate CA private key..."
openssl genrsa -out pki/intermediate/intermediate.key 4096

echo "Generating Intermediate CA CSR..."
openssl req -config pki/ca-intermediate.cnf -new -sha256 -batch \
      -key pki/intermediate/intermediate.key \
      -out pki/intermediate/intermediate.csr

echo "Signing Intermediate CA CSR with Root CA..."
openssl ca -config pki/ca-root.cnf -extensions v3_intermediate_ca \
      -days 1825 -notext -md sha256 \
      -in pki/intermediate/intermediate.csr \
      -out pki/intermediate/intermediate.crt \
      -batch

echo "Generating initial CRL..."
openssl ca -config pki/ca-intermediate.cnf -gencrl -out pki/intermediate/crl.pem

echo "Intermediate CA generated successfully."
echo "Certificate: pki/intermediate/intermediate.crt"
echo "CRL: pki/intermediate/crl.pem"

# Optional: Create certificate chain
cat pki/intermediate/intermediate.crt pki/root/certs/root.cert.pem > pki/intermediate/ca-chain.crt
echo "Certificate chain: pki/intermediate/ca-chain.crt"
