#!/bin/bash
set -e

apt-get update && \
    apt-get install -y make build-essential clang-9 git wget subversion \
        ninja-build python-pip zlib1g-dev rustc cargo inotify-tools

# Installl CMake from Kitware apt repository
wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | \
    gpg --dearmor - | \
    tee /usr/share/keyrings/kitware-archive-keyring.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ bionic main' | \
    tee /etc/apt/sources.list.d/kitware.list >/dev/null
apt-get update && \
    apt-get install -y cmake

pip install lit

update-alternatives \
  --install /usr/lib/llvm              llvm             /usr/lib/llvm-9  20 \
  --slave   /usr/bin/llvm-config       llvm-config      /usr/bin/llvm-config-9  \
    --slave   /usr/bin/llvm-ar           llvm-ar          /usr/bin/llvm-ar-9 \
    --slave   /usr/bin/llvm-as           llvm-as          /usr/bin/llvm-as-9 \
    --slave   /usr/bin/llvm-bcanalyzer   llvm-bcanalyzer  /usr/bin/llvm-bcanalyzer-9 \
    --slave   /usr/bin/llvm-c-test       llvm-c-test      /usr/bin/llvm-c-test-9 \
    --slave   /usr/bin/llvm-cov          llvm-cov         /usr/bin/llvm-cov-9 \
    --slave   /usr/bin/llvm-diff         llvm-diff        /usr/bin/llvm-diff-9 \
    --slave   /usr/bin/llvm-dis          llvm-dis         /usr/bin/llvm-dis-9 \
    --slave   /usr/bin/llvm-dwarfdump    llvm-dwarfdump   /usr/bin/llvm-dwarfdump-9 \
    --slave   /usr/bin/llvm-extract      llvm-extract     /usr/bin/llvm-extract-9 \
    --slave   /usr/bin/llvm-link         llvm-link        /usr/bin/llvm-link-9 \
    --slave   /usr/bin/llvm-mc           llvm-mc          /usr/bin/llvm-mc-9 \
    --slave   /usr/bin/llvm-nm           llvm-nm          /usr/bin/llvm-nm-9 \
    --slave   /usr/bin/llvm-objdump      llvm-objdump     /usr/bin/llvm-objdump-9 \
    --slave   /usr/bin/llvm-ranlib       llvm-ranlib      /usr/bin/llvm-ranlib-9 \
    --slave   /usr/bin/llvm-readobj      llvm-readobj     /usr/bin/llvm-readobj-9 \
    --slave   /usr/bin/llvm-rtdyld       llvm-rtdyld      /usr/bin/llvm-rtdyld-9 \
    --slave   /usr/bin/llvm-size         llvm-size        /usr/bin/llvm-size-9 \
    --slave   /usr/bin/llvm-stress       llvm-stress      /usr/bin/llvm-stress-9 \
    --slave   /usr/bin/llvm-symbolizer   llvm-symbolizer  /usr/bin/llvm-symbolizer-9 \
    --slave   /usr/bin/llvm-tblgen       llvm-tblgen      /usr/bin/llvm-tblgen-9

update-alternatives \
  --install /usr/bin/clang                 clang                  /usr/bin/clang-9     20 \
  --slave   /usr/bin/clang++               clang++                /usr/bin/clang++-9 \
  --slave   /usr/bin/clang-cpp             clang-cpp              /usr/bin/clang-cpp-9
