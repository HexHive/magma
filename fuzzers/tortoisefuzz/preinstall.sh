#!/bin/bash
set -e

apt-get update && \
    apt-get install -y build-essential cmake ninja-build git wget python-dev
