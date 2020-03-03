#!/bin/bash

apt-get update && \
    apt-get install -y git make autoconf automake libtool pkg-config cmake \
        zlib1g-dev libjpeg-dev libopenjp2-7-dev libpng-dev libcairo2-dev \
        libtiff-dev liblcms2-dev libboost-dev