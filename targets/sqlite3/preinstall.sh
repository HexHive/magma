#!/bin/bash

export DEBIAN_FRONTEND=noninteractive
apt-get update && \
    apt-get install -y make autoconf automake libtool curl tcl zlib1g-dev
