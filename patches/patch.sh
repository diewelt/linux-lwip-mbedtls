#!/bin/sh

cd lwip
if [ ! -e patched ]; then
    git clean -xdf
    git checkout .
    git apply ../patches/lwip-0001-cmakelists.patch
fi
