#!/bin/bash

apt-get update && \
    apt-get install -y git make autoconf automake libtool cmake nasm \
        zlib1g-dev liblzma-dev libjpeg-turbo8-dev wget
