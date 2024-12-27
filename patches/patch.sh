#!/bin/sh

if [ ! -e mbedtls/framework/CMakeLists.txt ]; then
    cd mbedtls
    git submodule update --init
    cd ..
fi

cd lwip
if [ ! -e patched ]; then
    git clean -xdf
    git checkout .
    git apply ../patches/lwip-0001-cmakelists.patch
fi
cd ..

cd mbedtls
if [ ! -e patched ]; then
    git clean -xdf
    git checkout .
    git apply ../patches/mbedtls-1001-disable-platform-network-api.patch
fi
cd ..
