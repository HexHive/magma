#!/bin/bash
set -e

apt-get update && \
    apt-get install -y make build-essential gcc g++ lcov git curl
