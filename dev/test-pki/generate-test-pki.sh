#!/usr/bin/env bash

# This script should be run with `cargo make certs` from the root of this repo

# Based on:
# https://pki-tutorial.readthedocs.io/en/latest/simple/index.html

set -xe

SCRIPT_DIR="dev/test-pki"
KEY_DIR=$SCRIPT_DIR/gen
rm -rf $KEY_DIR

PASSWORD=password

# The rest of this script will create a full public key infrastructure for testing.
#
# First it creates a root certificate authority (CA). This CA is used to issue certificates to signing CAs.
# The root CA should not be used to issue certificates to end users such as clients or servers.
# The root CA sits at the base of the trust chain so it must self-sign its own certificate.
# 
# In order to issue a certificate, the party requesting the certificate creates a certificate request (CR).
# The CR is sent to a CA who will use it to generate a certificate signed by the CA.
#
# Once we have the root CA set up, we create a second CA called the signing CA.
# The signing CA generates a CR and sends it to the root CA to create its certificate.
# 
# Now that we have a signing CA, we can use it to generate certificates for the client and server.
#
# Finally, we'll concatenate some certificates together so that we can pass them to `rustls`.
# Certificate chains start with the top level certificate and flow down to the root CA.
#
# Signing CA chain:
# signing-ca.crt -> root-ca.crt
#
# Server CA chain:
# server.crt -> signing-ca.crt -> root-ca.crt
#
# Client CA chain:
# client.crt -> signing-ca.crt -> root-ca.crt



# Create root CA directories
mkdir -p $KEY_DIR/ca/root-ca/private $KEY_DIR/ca/root-ca/db $KEY_DIR/crl $KEY_DIR/certs
chmod 700 $KEY_DIR/ca/root-ca/private

# Create root CA database
cp /dev/null $KEY_DIR/ca/root-ca/db/root-ca.db
cp /dev/null $KEY_DIR/ca/root-ca/db/root-ca.db.attr
echo 01 > $KEY_DIR/ca/root-ca/db/root-ca.crt.srl
echo 01 > $KEY_DIR/ca/root-ca/db/root-ca.crl.srl

# Create root CA request
openssl req -new \
    -batch \
    -nodes \
    -config $SCRIPT_DIR/configs/root-ca.conf \
    -out $KEY_DIR/ca/root-ca.csr \
    -keyout $KEY_DIR/ca/root-ca/private/root-ca.key

# Create root CA certificate
openssl ca -selfsign \
    -batch \
    -config $SCRIPT_DIR/configs/root-ca.conf \
    -in $KEY_DIR/ca/root-ca.csr \
    -out $KEY_DIR/ca/root-ca.crt \
    -extensions root_ca_ext

# Create signing CA directories
mkdir -p $KEY_DIR/ca/signing-ca/private $KEY_DIR/ca/signing-ca/db $KEY_DIR/crl $KEY_DIR/certs
chmod 700 $KEY_DIR/ca/signing-ca/private

# Create signing CA database
cp /dev/null $KEY_DIR/ca/signing-ca/db/signing-ca.db
cp /dev/null $KEY_DIR/ca/signing-ca/db/signing-ca.db.attr
echo 01 > $KEY_DIR/ca/signing-ca/db/signing-ca.crt.srl
echo 01 > $KEY_DIR/ca/signing-ca/db/signing-ca.crl.srl

# Create signing CA request
openssl req -new \
    -batch \
    -nodes \
    -config $SCRIPT_DIR/configs/signing-ca.conf \
    -out $KEY_DIR/ca/signing-ca.csr \
    -keyout $KEY_DIR/ca/signing-ca/private/signing-ca.key

# Create signing CA certificate
openssl ca \
    -batch \
    -config $SCRIPT_DIR/configs/root-ca.conf \
    -in $KEY_DIR/ca/signing-ca.csr \
    -out $KEY_DIR/ca/signing-ca.crt \
    -extensions signing_ca_ext

# Create server certificate request
openssl req -new \
    -batch \
    -nodes \
    -config $SCRIPT_DIR/configs/server.conf \
    -out $KEY_DIR/certs/server.csr \
    -keyout $KEY_DIR/certs/server.key

# Create server certificate
openssl ca \
    -batch \
    -config $SCRIPT_DIR/configs/signing-ca.conf \
    -in $KEY_DIR/certs/server.csr \
    -out $KEY_DIR/certs/server.crt \
    -extensions server_ext

# Create client certificate request
openssl req -new \
    -batch \
    -nodes \
    -config $SCRIPT_DIR/configs/client.conf \
    -out $KEY_DIR/certs/client.csr \
    -keyout $KEY_DIR/certs/client.key

# Create client certificate
openssl ca \
    -batch \
    -config $SCRIPT_DIR/configs/signing-ca.conf \
    -in $KEY_DIR/certs/client.csr \
    -out $KEY_DIR/certs/client.crt \
    -extensions client_ext

# Create signing CA chain
cat $KEY_DIR/ca/signing-ca.crt $KEY_DIR/ca/root-ca.crt > \
    $KEY_DIR/ca/signing-ca.chain

# Create server chain
cat $KEY_DIR/certs/server.crt $KEY_DIR/ca/signing-ca.crt $KEY_DIR/ca/root-ca.crt > \
    $KEY_DIR/certs/server.chain

# Create client chain
cat $KEY_DIR/certs/client.crt $KEY_DIR/ca/signing-ca.crt $KEY_DIR/ca/root-ca.crt > \
    $KEY_DIR/certs/client.chain
