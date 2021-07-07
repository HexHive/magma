#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://github.com/lua/lua.git "$TARGET/repo"
git -C "$TARGET/repo" checkout dbdc74dc5502c2e05e1c1e2ac894943f418c8431