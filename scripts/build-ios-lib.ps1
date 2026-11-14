# Cross-build the Rust core for iOS (libsupernet_ffi.a, see ios/supernet.h)
# from Windows, with Zig as C compiler and the real iPhoneOS SDK headers.
#
#   scripts/build-ios-lib.ps1 [-Sdk local/toolchain/iPhoneOS.sdk]
#
# The SDK folder needs SDKSettings.json, usr/include and usr/lib from a Mac's
# Xcode (`xcrun --sdk iphoneos --show-sdk-path`); only headers are used, a
# static library is not linked. Output: dist/ios/libsupernet_ffi.a
# On a Mac, `cargo build --release --target aarch64-apple-ios -p supernet-ffi`
# does the same without this script.
param([string]$Sdk = '')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$tc = Join-Path $root 'local\toolchain'
if (-not $Sdk) { $Sdk = Join-Path $tc 'iPhoneOS.sdk' }
if (-not (Test-Path (Join-Path $Sdk 'usr\include\stdio.h'))) { throw "没有 iOS SDK 头文件：$Sdk（从 Mac 上拷贝 usr/include）" }
$zig = Join-Path $tc 'zig-x86_64-windows-0.17.1\zig.exe'
if (-not (Test-Path $zig)) { & (Join-Path $PSScriptRoot 'build-linux.ps1') | Out-Null }   # fetches Zig and builds the wrapper
$env:SUPERNET_ZIG = $zig
# The minimum iOS version is part of Zig's target (it ignores -miphoneos-version-min);
# same as the app (ios/build.sh).
$env:SUPERNET_ZIG_TARGET = 'aarch64-ios.16.0'
Remove-Item Env:SUPERNET_ZIG_NO_SYSROOT -ErrorAction SilentlyContinue
$env:SDKROOT = (Resolve-Path $Sdk).Path
$env:IPHONEOS_DEPLOYMENT_TARGET = '16.0'
$env:CC_aarch64_apple_ios = Join-Path $tc 'zig-cc.exe'
$env:AR_aarch64_apple_ios = Join-Path $tc 'zig-ar.exe'
# boringtun also declares a cdylib, which cargo links even as a dependency.
$env:CARGO_TARGET_AARCH64_APPLE_IOS_LINKER = Join-Path $tc 'zig-cc.exe'
& rustup target add --toolchain stable-x86_64-pc-windows-gnu aarch64-apple-ios | Out-Null
& (Join-Path $PSScriptRoot 'cargo-cross.ps1') build --release --target aarch64-apple-ios -p supernet-ffi
if ($LASTEXITCODE) { throw 'build failed' }
$out = (New-Item -ItemType Directory -Force (Join-Path $root 'dist\ios')).FullName
Copy-Item (Join-Path $root 'target\aarch64-apple-ios\release\libsupernet_ffi.a') $out -Force
Copy-Item (Join-Path $root 'ios\supernet.h') $out -Force
Get-ChildItem $out | ForEach-Object { '{0}  {1:N1} MB' -f $_.FullName, ($_.Length / 1MB) }
