# Run cargo for another target from Windows (check/build of pure-Rust crates,
# or anything once a C cross compiler is configured by the caller).
#
#   scripts/cargo-cross.ps1 check --target x86_64-unknown-linux-musl -p supernet-tun
#
# Build scripts and proc macros still run on Windows: they use the gnu
# toolchain and llvm-mingw, as in scripts/cargo.ps1.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$bin = $env:SUPERNET_MINGW
if (-not $bin) {
    $bin = Join-Path $root '..\server\starsavior\local_state\launcher-toolchain\llvm-mingw-20261104-msvcrt-x86_64\bin'
}
$bin = (Resolve-Path $bin).Path
$env:PATH = $bin + ';' + $env:PATH
Remove-Item Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue
$env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = Join-Path $bin 'x86_64-w64-mingw32-gcc.exe'
$support = Join-Path $env:USERPROFILE '.rustup\toolchains\stable-x86_64-pc-windows-gnu\lib\rustlib\x86_64-pc-windows-gnu\lib\self-contained'
$libs = (New-Item -ItemType Directory -Force (Join-Path $root 'local\toolchain\rust-gcc-libs')).FullName
Copy-Item (Join-Path $support 'libgcc.a'), (Join-Path $support 'libgcc_eh.a') $libs -Force
$env:LIBRARY_PATH = $libs
& cargo +stable-x86_64-pc-windows-gnu @args
exit $LASTEXITCODE
