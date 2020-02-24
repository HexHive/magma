#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone https://gitlab.gnome.org/GNOME/libxml2.git \
    --branch master \
    "$TARGET/repo"
