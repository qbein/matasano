#!/bin/bash
# Jonathan Cardasis - 2018
# Builds OpenSSL libssl and libcrypto for macOS
# binary distribution (i386 and x86).

# Found through https://medium.com/@joncardasis/openssl-swift-everything-you-need-to-know-2a4f9f256462

VERSION="1.1.0h"
VERSION_SHA256_CHECKSUM="5835626cde9e99656585fc7aaa2302a73a7e1340bf8c14fd635a62c66802a517"

rm -r lib/OpenSSL
mkdir lib
mkdir .tmp

####################################
curl -o ".tmp/openssl.tar.gz" -O https://www.openssl.org/source/openssl-$VERSION.tar.gz

# Run a checksum to ensure this file wasn't tampered with
FILE_CHECKSUM=$(shasum -a 256 .tmp/openssl.tar.gz | awk '{print $1; exit}')
if [ "$FILE_CHECKSUM" != "$VERSION_SHA256_CHECKSUM" ]; then
  echo "OpenSSL v$VERSION failed checksum. Please ensure that you are on a trusted network."
  exit 1
fi

#OPENSSL_FOLDER="OpenSSL"
#OPENSSL_LIB_FOLDER="$TMP_FOLDER/$OPENSSL_FOLDER/lib"
#OPENSSL_INCLUDE_FOLDER="$TMP_FOLDER/$OPENSSL_FOLDER/include"
mkdir -p ".tmp/OpenSSL/lib"

# Unzip into i386 and x86 64bit folders
pushd .tmp
#tar -xvzf openssl.tar.gz
#mv openssl-$VERSION openssl_i386
tar -xvzf openssl.tar.gz
mv openssl-$VERSION openssl_x86_64

# Build Flavors
#pushd openssl_i386
#./Configure darwin-i386-cc
#echo "Building i386 static library..."
#make >> /dev/null 2>&1
#make install >> /dev/null 2>&1
#popd

pushd openssl_x86_64
./Configure darwin64-x86_64-cc
echo "Building x86 64 static library..."
make >> /dev/null 2>&1
make install >> /dev/null 2>&1

# Copy include and License into main OpenSSL folder (done after configure so <openssl/opensslconf.h> can be generated)
#pushd openssl_i386
cp -r include "../OpenSSL" # Copy include headers into hidden folder
cp LICENSE "../OpenSSL/" # Copy License

# Link
echo "Linking..."
lipo -create libcrypto.a -output "../OpenSSL/lib/libcrypto.a"
lipo -create libssl.a -output "../OpenSSL/lib/libssl.a"
popd

# Cleanup
rm openssl.tar.gz
#rm -r openssl_i386
rm -r openssl_x86_64
mv OpenSSL "../lib/"
popd
rm -r .tmp

echo "Finished OpenSSL generation script."
