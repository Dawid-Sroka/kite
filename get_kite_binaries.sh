#!/bin/bash

RELEASE_URL="https://github.com/Dawid-Sroka/kite-binaries-builder/releases/download/v1.0.0/kite-binaries.zip"
curl -L -o kite-binaries.zip $RELEASE_URL
unzip kite-binaries.zip
mkdir -p sysroot
mv mimiker-sysroot/* sysroot/
