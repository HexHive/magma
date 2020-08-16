#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

GO_VERSION="1.15"
GO_OS="linux"
GO_ARCH="amd64"

mkdir -p "$FUZZER/repo/goroot" "$FUZZER/repo/gopath"
curl -L "https://golang.org/dl/go${GO_VERSION}.${GO_OS}-${GO_ARCH}.tar.gz" | \
    tar xzf - -C "$FUZZER/repo/goroot" --strip-components=1

export GOROOT="$FUZZER/repo/goroot"
export GOPATH="$FUZZER/repo/gopath"
export PATH=$PATH:"$GOROOT/bin":"$GOPATH/bin"

go get github.com/SRI-CSL/gllvm/cmd/...
