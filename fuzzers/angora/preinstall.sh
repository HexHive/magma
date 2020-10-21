#!/bin/bash
set -e

apt-get update && \
    apt-get install -y make build-essential cmake git golang-go \
    python-pip python-dev wget zlib1g-dev

# Install Python packages
pip install --upgrade pip==9.0.3
pip install wllvm

# Install gllvm
go get github.com/SRI-CSL/gllvm/cmd/...
