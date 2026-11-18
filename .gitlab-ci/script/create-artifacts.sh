#!/bin/bash

set -xeu -o pipefail

# Set the number of parallel jobs for make, defaulting to 1 if it cannot be determined
CPU_COUNT=1

# turn grub-2.XX-rcY into grub-2.XX~rcY
GRUB_CI_COMMIT_TAG="$(echo "$CI_COMMIT_TAG" | sed 's/\([^-]*-[^-]*\)-/\1~/')"

# Do all work under a temporal directory
TMPDIR=$(mktemp -d)

if command -v nproc >/dev/null 2>&1
then
    CPU_COUNT=$(nproc 2>/dev/null)
fi

cd $TMPDIR

cp -av $CI_PROJECT_DIR grub-build

cd grub-build
./bootstrap
cd ..

# Working folders
mkdir -p artifacts i686-w64-mingw32-efi-gcc i686-w64-mingw32-pc-gcc x86_64-w64-mingw32-efi-gcc zip-merge

cd x86_64-w64-mingw32-efi-gcc
../grub-build/configure --build=x86_64-linux-gnu --host=x86_64-w64-mingw32 --target=x86_64-w64-mingw32 --with-platform=efi --enable-stack-protector
make -j $CPU_COUNT
make -j $CPU_COUNT windowszip
cd ..

cd i686-w64-mingw32-efi-gcc
../grub-build/configure --build=x86_64-linux-gnu --host=i686-w64-mingw32 --target=i686-w64-mingw32 --with-platform=efi --enable-stack-protector
make -j $CPU_COUNT
make -j $CPU_COUNT windowszip
cd ..

cd i686-w64-mingw32-pc-gcc
../grub-build/configure --build=x86_64-linux-gnu --host=i686-w64-mingw32 --target=i686-w64-mingw32 --with-platform=pc
make -j $CPU_COUNT
make -j $CPU_COUNT windowszip
cd ..

cd grub-build
./configure --prefix="$(pwd)/grub-dist" --enable-grub-themes
make -j $CPU_COUNT
make -j $CPU_COUNT install

# Release only consider .tar.gz (make dist) and .tar.xz (make dist-xz)
make -j $CPU_COUNT dist
make -j $CPU_COUNT dist-xz

# For testing purposes, also generate the rest of the supported make dist-* targets
make -j $CPU_COUNT dist-bzip2
make -j $CPU_COUNT dist-lzip
make -j $CPU_COUNT dist-zstd
cd ..

cd grub-build
# Use the gnulib cached in the container image, otherwise the one fetched by bootstrap
GNULIB_DIR="${GNULIB_SRCDIR:-$(pwd)/gnulib}"
cp -av "$GNULIB_DIR/doc/gendocs_template" docs
cd docs
"$GNULIB_DIR/build-aux/gendocs.sh" -o "./manual-grub" --email 'bug-grub@gnu.org' grub GRUB
"$GNULIB_DIR/build-aux/gendocs.sh" -o "./manual-grub-dev" --email 'bug-grub@gnu.org' grub-dev GRUB
cd ../..

cd zip-merge
unzip ../x86_64-w64-mingw32-efi-gcc/$GRUB_CI_COMMIT_TAG-for-windows.zip
unzip -o ../i686-w64-mingw32-efi-gcc/$GRUB_CI_COMMIT_TAG-for-windows.zip
unzip -o ../i686-w64-mingw32-pc-gcc/$GRUB_CI_COMMIT_TAG-for-windows.zip
cp -av ../grub-build/grub-dist/share/grub/* $GRUB_CI_COMMIT_TAG-for-windows
rm $GRUB_CI_COMMIT_TAG-for-windows/grub-mkconfig_lib
find $GRUB_CI_COMMIT_TAG-for-windows -empty -delete
zip -9r $GRUB_CI_COMMIT_TAG-for-windows.zip $GRUB_CI_COMMIT_TAG-for-windows
cd ..

cd artifacts
cp -av ../grub-build/$GRUB_CI_COMMIT_TAG.tar.{gz,xz} .
cp -av ../zip-merge/$GRUB_CI_COMMIT_TAG-for-windows.zip .

tar xvzf $GRUB_CI_COMMIT_TAG.tar.gz
rm $GRUB_CI_COMMIT_TAG.tar.gz
tar cvf $GRUB_CI_COMMIT_TAG.tar.gz -I 'gzip -9v' --owner=root --group=root --numeric-owner $GRUB_CI_COMMIT_TAG
rm -fr $GRUB_CI_COMMIT_TAG
tar xJvf $GRUB_CI_COMMIT_TAG.tar.xz
rm $GRUB_CI_COMMIT_TAG.tar.xz
tar cvf $GRUB_CI_COMMIT_TAG.tar.xz -I 'xz -9v' --owner=root --group=root --numeric-owner $GRUB_CI_COMMIT_TAG
rm -fr $GRUB_CI_COMMIT_TAG

cd ..

cp -av artifacts $CI_PROJECT_DIR
