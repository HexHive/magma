#!/bin/bash

apt-get update && \
    apt-get install -y git make autoconf automake libtool bison re2c pkg-config \
        libicu-dev
