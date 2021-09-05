#!/bin/bash
set -e

apt-get update && \
    apt-get install -y make build-essential git golang-go \
    python-pip python-dev wget zlib1g-dev

# Installl CMake from Kitware apt repository
wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | \
    gpg --dearmor - | \
    tee /usr/share/keyrings/kitware-archive-keyring.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ bionic main' | \
    tee /etc/apt/sources.list.d/kitware.list >/dev/null
apt-get update && \
    apt-get install -y cmake

# Install Python packages
pip install --upgrade pip==9.0.3
pip install wllvm

# Install gllvm
export GOPATH="/opt/go"
mkdir -p $GOPATH
go get github.com/SRI-CSL/gllvm/cmd/...
