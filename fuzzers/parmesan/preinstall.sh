#!/bin/bash
set -e

apt-get update && \
    apt-get install -y make build-essential git golang-go \
    python-pip python-dev wget zlib1g-dev

# Install newer CMake (than Ubuntu repos)
wget -O /tmp/cmake.sh https://github.com/Kitware/CMake/releases/download/v3.20.5/cmake-3.20.5-linux-x86_64.sh
mkdir -p /opt/cmake
/bin/bash /tmp/cmake.sh --skip-license --exclude-subdir --prefix=/opt/cmake
rm -f /tmp/cmake.sh

# Adapted from parmesan/build/install_tools.sh (because it needs to be run as root)
pip install --upgrade pip==9.0.3
pip install wllvm

export GOPATH="/opt/go"
mkdir -p $GOPATH
go get github.com/SRI-CSL/gllvm/cmd/...
