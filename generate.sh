#!/bin/bash

mkdir -p keys || true
openssl ec -in keys/privateKey.pem -text -noout
openssl ec -pubin -in keys/publicKey.pem -text -noout