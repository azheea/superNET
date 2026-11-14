# Runs cargo with the windows-gnu toolchain and llvm-mingw (no Visual Studio needed).
# Usage: scripts/cargo.ps1 test --workspace
# Set SUPERNET_MINGW to an llvm-mingw "bin" directory to override the default.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$bin = $env:SUPERNET_MINGW
if (-not $bin) {
    $bin = Join-Path $root '..\server\starsavior\local_state\launcher-toolchain\llvm-mingw-20261104-msvcrt-x86_64\bin'
}
$bin = (Resolve-Path $bin).Path
$support = Join-Path $env:USERPROFILE '.rustup\toolchains\stable-x86_64-pc-windows-gnu\lib\rustlib\x86_64-pc-windows-gnu\lib\self-contained'
$libs = (New-Item -ItemType Directory -Force (Join-Path $root 'local\toolchain\rust-gcc-libs')).FullName
Copy-Item (Join-Path $support 'libgcc.a'), (Join-Path $support 'libgcc_eh.a') $libs -Force
$env:PATH = $bin + ';' + $env:PATH
$env:CARGO_ENCODED_RUSTFLAGS = ('-C', ('dlltool=' + $bin + '\llvm-dlltool.exe'), '-C', ('linker=' + $bin + '\x86_64-w64-mingw32-gcc.exe'), '-C', 'link-self-contained=no', '-L', ('native=' + $libs)) -join [char]31
& cargo +stable-x86_64-pc-windows-gnu @args
exit $LASTEXITCODE
