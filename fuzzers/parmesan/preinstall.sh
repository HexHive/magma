#!/bin/bash
set -e

apt-get update && \
    apt-get install -y make build-essential git wget \
    python-pip python-dev wget zlib1g-dev libtinfo-dev

# Installl CMake from Kitware apt repository
wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | \
    gpg --dearmor - | \
    tee /usr/share/keyrings/kitware-archive-keyring.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ bionic main' | \
    tee /etc/apt/sources.list.d/kitware.list >/dev/null
apt-get update && \
    apt-get install -y cmake

# Adapted from parmesan/build/install_tools.sh (because it needs to be run as root)
pip install --upgrade pip==9.0.3
pip install wllvm

wget -qO- https://go.dev/dl/go1.19.1.linux-amd64.tar.gz | tar xz -C /usr/local/ --strip-components=1

# Install gllvm
export GOPATH="/opt/go"
mkdir -p $GOPATH
go install github.com/SRI-CSL/gllvm/cmd/...@latest
