#!/bin/bash

set -eu -o pipefail

T="${TARGET}"
P="${PLATFORM}"


if [ "$P" = efi ]; then
    CC=clang BUILD_CC=clang TARGET_CC=clang HOST_CC=clang \
             ./configure --target="$T" --with-platform="$P" \
             --enable-stack-protector --enable-grub-mkfont --prefix="$(pwd)/grub-dist"
else
    CC=clang BUILD_CC=clang TARGET_CC=clang HOST_CC=clang \
             ./configure --target="$T" --with-platform="$P" \
             --enable-grub-mkfont --prefix="$(pwd)/grub-dist"
fi

make --quiet install
