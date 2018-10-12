#!/bin/bash

set -x
set -e

rm -f output/hello output/signature? output/private output/public

echo -n hello > output/hello

# Generate a keypair
output/uecc_genkey output/public output/private

# Make signatures with uecc and libsecp256k1
output/uecc_sign output/private output/hello output/signature1
python3 -B sign.py output/private output/hello output/signature2

# Verify signatures using uecc
output/uecc_verify output/public output/hello output/signature1
output/uecc_verify output/public output/hello output/signature2

# Verify signatures using libsecp256k1
python3 -B verify.py output/public output/hello output/signature2
python3 -B verify.py output/public output/hello output/signature1

echo "Test OK"
