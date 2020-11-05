#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone https://github.com/hazimeh/honggfuzz.git \
	--branch improvement/preserve_seeds "$FUZZER/repo"
