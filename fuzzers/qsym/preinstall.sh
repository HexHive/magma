#!/bin/bash
set -xe

apt-get update && \
    apt-get install -y make build-essential git wget

# Install QSYM fuzzer
#git clone https://github.com/sojhal/qsym.git

#pushd qsym
# disable ptrace_scope for PIN
#echo 0|sudo tee /proc/sys/kernel/yama/ptrace_scope

# install z3 and system deps
#./setup.sh

# install using virtual env
# virtualenv venv
# source venv/bin/activate
#pip install .
#popd

# Install AFL
git clone https://github.com/google/AFL.git
pushd AFL
sudo ln -s /usr/bin/make /usr/bin/gmake
sudo apt install clang -y
export LLVM_CONFIG=/usr/bin/llvm-config-3.8
AFL_NO_X86=1 gmake && gmake -C llvm_mode
popd