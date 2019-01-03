#!/usr/bin/env powershell

#Requires -Version 5

param (
    # The name of the component to be built. Defaults to none
    [string]$Component
)

$ErrorActionPreference="stop"
$env:RUSTUP_HOME="C:\rust\.rustup"
$env:CARGO_HOME="C:\rust\.cargo"
$env:Path="$env:Path;$env:CARGO_HOME\bin"

# $cargo = "C:\rust\.cargo\bin\cargo.exe"

Write-Host "--- Installing required prerequisites"
hab pkg install core/cacerts
hab pkg install core/libarchive
hab pkg install core/libsodium
hab pkg install core/openssl
hab pkg install core/protobuf
hab pkg install core/xz
hab pkg install core/zeromq
hab pkg install core/zlib

# Set up some path variables for ease of use later
$cacertsDir     = & hab pkg path core/cacerts
$libarchiveDir  = & hab pkg path core/libarchive
$libsodiumDir   = & hab pkg path core/libsodium
$opensslDir     = & hab pkg path core/openssl
$protobufDir    = & hab pkg path core/protobuf
$xzDir          = & hab pkg path core/xz
$zeromqDir      = & hab pkg path core/zeromq
$zlibDir        = & hab pkg path core/zlib

# Set some required variables
$env:SODIUM_LIB_DIR             = "$libsodiumDir\lib"
$env:LIBARCHIVE_INCLUDE_DIR     = "$libarchiveDir\include"
$env:LIBARCHIVE_LIB_DIR         = "$libarchiveDir\lib"
$env:OPENSSL_LIBS               = 'ssleay32:libeay32'
$env:OPENSSL_LIB_DIR            = "$opensslDir\lib"
$env:OPENSSL_INCLUDE_DIR        = "$opensslDir\include"
$env:LIBZMQ_PREFIX              = "$zeromqDir"
$env:SSL_CERT_FILE              = "$cacertsDir\ssl\certs\cacert.pem"
$env:SODIUM_STATIC              = "true"
$env:OPENSSL_STATIC             = "true"
$env:LD_LIBRARY_PATH            = "$env:LIBZMQ_PREFIX\lib;$env:SODIUM_LIB_DIR;$zlibDir\lib;$xzDir\lib"

# Make sure protoc is on the path, we also need to make sure the zmq DLL (in \bin) is on the path,
# because windows library pathing is weird.
$env:Path="$env:Path;$protobufDir\bin;$env:LIBZMQ_PREFIX\bin"

Write-Host "--- Running cargo test on $Component"
cd components/$Component
cargo test --verbose

if ($LASTEXITCODE -ne 0) {exit $LASTEXITCODE}
