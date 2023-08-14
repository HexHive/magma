#!/bin/bash
set -e

export DEBIAN_FRONTEND=noninteractive

apt-get update -y && apt-get upgrade -y && \
    apt-get install -y make build-essential git wget gcc-7-plugin-dev gnupg lsb-release software-properties-common

# Anything below llvm 13 is disabling good afl++ instrumentation features
# and would make a comparison of afl++ to other fuzzers pointless.
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
./llvm.sh 13
rm -f llvm.sh

apt-get install -y libc++-13-dev libc++abi-13-dev

apt-get clean -y

