#!/bin/bash

set -eu -o pipefail

T="${TARGET}"
P="${PLATFORM}"

CC=clang BUILD_CC=clang TARGET_CC=clang HOST_CC=clang \
	 ./configure --target="$T" --with-platform="$P" \
	 --enable-stack-protector --enable-grub-mkfont --prefix="$(pwd)/grub-dist"

make --quiet install
