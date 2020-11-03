#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone https://github.com/adrianherrera/Angora.git \
	--branch improvement/angora-showmap \
	"$FUZZER/repo"

cp "$FUZZER/src/angora_driver.c" "$FUZZER/repo/angora_driver.c"
