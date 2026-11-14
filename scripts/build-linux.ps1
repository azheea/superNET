# Build the headless superNET (`supernet`) for Linux x86_64 as a static musl binary.
# Output: dist/linux/supernet
#
# ring and boringtun contain C, so a Linux C compiler is needed: Zig's
# `zig cc` (downloaded to local/toolchain, SHA-256 checked) serves as C
# compiler and linker. Build scripts run on Windows (gnu toolchain + llvm-mingw).
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$tc = (New-Item -ItemType Directory -Force (Join-Path $root 'local\toolchain')).FullName
$zigVersion = '0.17.1'
$zigSha = 'b03f477a1943673e02aca0f570e8030dffd536ce1f45cbc4d3326ec31159562e'
$zigDir = Join-Path $tc "zig-x86_64-windows-$zigVersion"
if (-not (Test-Path (Join-Path $zigDir 'zig.exe'))) {
    $zip = Join-Path $tc 'zig.zip'
    if (-not (Test-Path $zip)) {
        Invoke-WebRequest "https://ziglang.org/download/$zigVersion/zig-x86_64-windows-$zigVersion.zip" -OutFile $zip
    }
    if ((Get-FileHash $zip -Algorithm SHA256).Hash -ne $zigSha.ToUpper()) { throw 'zig.zip 校验失败' }
    Expand-Archive $zip -DestinationPath $tc -Force
}
$zig = Join-Path $zigDir 'zig.exe'

# Wrappers (tools/zigcc): Zig as cc/linker and ar, dropping Rust target names.
& (Join-Path $PSScriptRoot 'cargo.ps1') build --release --manifest-path (Join-Path $root 'tools\zigcc\Cargo.toml') --target-dir (Join-Path $tc 'zigcc-build')
if ($LASTEXITCODE) { throw 'zigcc build failed' }
$wrapper = Join-Path $tc 'zigcc-build\release\zigcc.exe'
$cc = Join-Path $tc 'zig-cc.exe'
$ar = Join-Path $tc 'zig-ar.exe'
Copy-Item $wrapper $cc -Force
Copy-Item $wrapper $ar -Force
$env:SUPERNET_ZIG = $zig
$env:SUPERNET_ZIG_TARGET = 'x86_64-linux-musl'

& rustup target add --toolchain stable-x86_64-pc-windows-gnu x86_64-unknown-linux-musl | Out-Null
$env:CC_x86_64_unknown_linux_musl = $cc
$env:AR_x86_64_unknown_linux_musl = $ar
$env:CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = $cc
# Zig brings musl's own crt files; don't let rustc add its copies too.
$env:CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS = '-C link-self-contained=no -C target-feature=+crt-static'
& (Join-Path $PSScriptRoot 'cargo-cross.ps1') build --release --target x86_64-unknown-linux-musl -p supernet-cli
if ($LASTEXITCODE) { throw 'build failed' }

$out = (New-Item -ItemType Directory -Force (Join-Path $root 'dist\linux')).FullName
Copy-Item (Join-Path $root 'target\x86_64-unknown-linux-musl\release\supernet') $out -Force
Get-Item (Join-Path $out 'supernet') | ForEach-Object { '{0}  {1:N1} MB' -f $_.FullName, ($_.Length / 1MB) }
