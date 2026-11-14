# Cross-build the headless `supernet` for macOS from Windows (Apple Silicon
# and Intel), with Zig as C compiler and linker. The GUI app still needs a
# Mac (scripts/build-macos.sh); this binary covers TUN mode (`sudo supernet`).
# Output: dist/macos/supernet-aarch64, dist/macos/supernet-x86_64
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$tc = Join-Path $root 'local\toolchain'
$zig = Join-Path $tc 'zig-x86_64-windows-0.17.1\zig.exe'
if (-not (Test-Path $zig)) { & (Join-Path $PSScriptRoot 'build-linux.ps1') | Out-Null }   # fetches Zig and builds the wrapper
$cc = Join-Path $tc 'zig-cc.exe'
$ar = Join-Path $tc 'zig-ar.exe'
$env:SUPERNET_ZIG = $zig
$out = (New-Item -ItemType Directory -Force (Join-Path $root 'dist\macos')).FullName

foreach ($t in @(@{ rust = 'aarch64-apple-darwin'; zig = 'aarch64-macos'; name = 'aarch64' }, @{ rust = 'x86_64-apple-darwin'; zig = 'x86_64-macos'; name = 'x86_64' })) {
    & rustup target add --toolchain stable-x86_64-pc-windows-gnu $t.rust | Out-Null
    $env:SUPERNET_ZIG_TARGET = $t.zig
    $u = $t.rust.ToUpper().Replace('-', '_')
    $l = $t.rust.Replace('-', '_')
    Set-Item "Env:CC_$l" $cc
    Set-Item "Env:AR_$l" $ar
    Set-Item "Env:CARGO_TARGET_${u}_LINKER" $cc
    & (Join-Path $PSScriptRoot 'cargo-cross.ps1') build --release --target $t.rust -p supernet-cli
    if ($LASTEXITCODE) { throw "build failed for $($t.rust)" }
    Copy-Item (Join-Path $root "target\$($t.rust)\release\supernet") (Join-Path $out "supernet-$($t.name)") -Force
}
Get-ChildItem $out -Filter 'supernet-*' | ForEach-Object { '{0}  {1:N1} MB' -f $_.FullName, ($_.Length / 1MB) }
