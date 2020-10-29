#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://gitlab.gnome.org/GNOME/libxml2.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 7d6837ba0e282e94eb8630ad791f427e44a57491