#!/bin/bash
set -xe

apt-get update && \
    apt-get install -y make build-essential git wget

#installing clag-9

sudo apt-get install build-essential xz-utils curl -y

curl -SL http://releases.llvm.org/9.0.0/clang%2bllvm-9.0.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz | tar -xJC .

mv clang+llvm-9.0.0-x86_64-linux-gnu-ubuntu-16.04 clang_9.0.0
sudo mv clang_9.0.0 /usr/local

export PATH=/usr/local/clang_9.0.0/bin:$PATH
export LD_LIBRARY_PATH=/usr/local/clang_9.0.0/lib:$LD_LIBRARY_PATH



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
#git clone https://github.com/google/AFL.git
#pushd AFL
#sudo ln -s /usr/bin/make /usr/bin/gmake
#sudo apt install clang -y
#export LLVM_CONFIG=/usr/bin/llvm-config-3.8
#AFL_NO_X86=1 gmake && gmake -C qemu_mode
#popd
