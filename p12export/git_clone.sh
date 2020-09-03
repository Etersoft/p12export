#!/bin/sh
#git clone --single-branch --branch OpenSSL_1_1_1d https://github.com/openssl/openssl.git openssl_1_1_1d
git clone https://github.com/gost-engine/engine.git engine
cd engine
# Use known good commit that actually compiles with Visual C
git checkout 20f99cd4df48ed150937a82cc57f233cadcc7c7e
cd ..
