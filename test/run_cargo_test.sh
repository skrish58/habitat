#!/bin/bash

set -ueo pipefail

hab pkg install core/bzip2
hab pkg install core/libarchive
hab pkg install core/libsodium
hab pkg install core/openssl
hab pkg install core/xz
hab pkg install core/zeromq
hab pkg install core/protobuf --binlink
export SODIUM_STATIC=true # so the libarchive crate links to sodium statically
export LIBARCHIVE_STATIC=true # so the libarchive crate *builds* statically
export OPENSSL_DIR="$(hab pkg path core/openssl)" # so the openssl crate knows what to build against
export OPENSSL_STATIC=true # so the openssl crate builds statically
export LIBZMQ_PREFIX=$(hab pkg path core/zeromq)
# now include openssl and zeromq so thney exists in the runtime library path when cargo test is run
export LD_LIBRARY_PATH="$(hab pkg path core/libsodium)/lib:$(hab pkg path core/zeromq)/lib"
# include these so that the cargo tests can bind to libarchive (which dynamically binds to xz, bzip, etc), openssl, and sodium at *runtime*
export LIBRARY_PATH="$(hab pkg path core/bzip2)/lib:$(hab pkg path core/libsodium)/lib:$(hab pkg path core/openssl)/lib:$(hab pkg path core/xz)/lib"
# setup pkgconfig so the libarchive crate can use pkg-config to fine bzip2 and xz at *build* time
export PKG_CONFIG_PATH="$(hab pkg path core/libarchive)/lib/pkgconfig:$(hab pkg path core/libsodium)/lib/pkgconfig:$(hab pkg path core/openssl)/lib/pkgconfig"

 cd "components/$1"
cargo test --verbose
