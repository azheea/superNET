# Build the coordinator as a static Linux binary (x86_64, musl) on Windows.
# Output: dist/linux/supernet-coord
#
# Pure Rust only (no C code), so Rust's own lld links it; build scripts and
# proc macros still run on Windows and use llvm-mingw like scripts/cargo.ps1.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$bin = $env:SUPERNET_MINGW
if (-not $bin) {
    $bin = Join-Path $root '..\server\starsavior\local_state\launcher-toolchain\llvm-mingw-20261104-msvcrt-x86_64\bin'
}
$bin = (Resolve-Path $bin).Path
$toolchain = 'stable-x86_64-pc-windows-gnu'
& rustup target add --toolchain $toolchain x86_64-unknown-linux-musl
if ($LASTEXITCODE) { throw 'rustup target add failed' }

$env:PATH = $bin + ';' + $env:PATH
Remove-Item Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue
# Host build scripts link with llvm-mingw, which lacks libgcc/libgcc_eh; use Rust's copies.
$support = Join-Path $env:USERPROFILE '.rustup\toolchains\stable-x86_64-pc-windows-gnu\lib\rustlib\x86_64-pc-windows-gnu\lib\self-contained'
$libs = (New-Item -ItemType Directory -Force (Join-Path $root 'local\toolchain\rust-gcc-libs')).FullName
Copy-Item (Join-Path $support 'libgcc.a'), (Join-Path $support 'libgcc_eh.a') $libs -Force
$env:LIBRARY_PATH = $libs
$env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = Join-Path $bin 'x86_64-w64-mingw32-gcc.exe'
$env:CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = 'rust-lld'
$env:CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS = '-C linker-flavor=ld.lld -C target-feature=+crt-static'
& cargo "+$toolchain" build -p supernet-coord --release --target x86_64-unknown-linux-musl
if ($LASTEXITCODE) { throw 'build failed' }

$out = (New-Item -ItemType Directory -Force (Join-Path $root 'dist\linux')).FullName
Copy-Item (Join-Path $root 'target\x86_64-unknown-linux-musl\release\supernet-coord') $out -Force
Get-FileHash (Join-Path $out 'supernet-coord') | Format-Table -AutoSize
