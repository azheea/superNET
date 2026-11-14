# Cross-build the superNET app (GUI) for macOS from Windows: Zig links it
# against a Mac's real SDK stubs, then the bundle is put together here.
#
#   scripts/build-macos-app.ps1 [-Arch aarch64|x86_64] [-Sdk local/toolchain/MacOSX.sdk]
#
# The SDK folder needs SDKSettings.json, usr/include, usr/lib and the
# frameworks' .tbd stubs of a Mac's MacOSX SDK (`xcrun --sdk macosx
# --show-sdk-path`; about 50 MB, no headers of frameworks needed).
# Output: dist/macos/superNET.app (unsigned: sign it on the Mac with
# `codesign --force --deep -s - superNET.app`, or a Developer ID).
# On a Mac, scripts/build-macos.sh does the same with Tauri's own bundler.
param([ValidateSet('aarch64', 'x86_64')][string]$Arch = 'aarch64', [string]$Sdk = '')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$tc = Join-Path $root 'local\toolchain'
if (-not $Sdk) { $Sdk = Join-Path $tc 'MacOSX.sdk' }
if (-not (Test-Path (Join-Path $Sdk 'System\Library\Frameworks\AppKit.framework\AppKit.tbd'))) { throw "没有 macOS SDK：$Sdk" }
$zig = Join-Path $tc 'zig-x86_64-windows-0.17.1\zig.exe'
if (-not (Test-Path $zig)) { & (Join-Path $PSScriptRoot 'build-linux.ps1') | Out-Null }   # fetches Zig and builds the wrapper
$target = "$Arch-apple-darwin"
$l = $target.Replace('-', '_')
$u = $l.ToUpper()
$env:SUPERNET_ZIG = $zig
$env:SUPERNET_ZIG_TARGET = "$Arch-macos.12.0"
$env:SDKROOT = (Resolve-Path $Sdk).Path
$env:MACOSX_DEPLOYMENT_TARGET = '12.0'
Set-Item "Env:CC_$l" (Join-Path $tc 'zig-cc.exe')
Set-Item "Env:AR_$l" (Join-Path $tc 'zig-ar.exe')
Set-Item "Env:CARGO_TARGET_${u}_LINKER" (Join-Path $tc 'zig-cc.exe')

Push-Location (Join-Path $root 'app')
try { & npm run build; if ($LASTEXITCODE) { throw 'frontend build failed' } } finally { Pop-Location }
& rustup target add --toolchain stable-x86_64-pc-windows-gnu $target | Out-Null
# custom-protocol: serve the built frontend from the binary (what `tauri build` turns on).
& (Join-Path $PSScriptRoot 'cargo-cross.ps1') build --release --target $target --manifest-path (Join-Path $root 'app\src-tauri\Cargo.toml') --features tauri/custom-protocol
if ($LASTEXITCODE) { throw 'build failed' }
# The headless binary goes into the bundle too: TUN mode and the virtual
# network need root on macOS, and the app tells the user the sudo command.
# Not "supernet": macOS file systems ignore case, and that is superNET itself.
& (Join-Path $PSScriptRoot 'cargo-cross.ps1') build --release --target $target -p supernet-cli
if ($LASTEXITCODE) { throw 'cli build failed' }

$conf = Get-Content (Join-Path $root 'app\src-tauri\tauri.conf.json') -Raw | ConvertFrom-Json
$app = Join-Path $root 'dist\macos\superNET.app'
if (Test-Path $app) { Remove-Item -Recurse -Force $app }
$null = New-Item -ItemType Directory -Force (Join-Path $app 'Contents\MacOS'), (Join-Path $app 'Contents\Resources')
Copy-Item (Join-Path $root "target\$target\release\supernet-app") (Join-Path $app 'Contents\MacOS\superNET')
Copy-Item (Join-Path $root "target\$target\release\supernet") (Join-Path $app 'Contents\MacOS\supernet-cli')
Copy-Item (Join-Path $root 'app\src-tauri\icons\icon.icns') (Join-Path $app 'Contents\Resources\icon.icns')
$plist = @"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key><string>zh_CN</string>
	<key>CFBundleDisplayName</key><string>$($conf.productName)</string>
	<key>CFBundleExecutable</key><string>superNET</string>
	<key>CFBundleIconFile</key><string>icon.icns</string>
	<key>CFBundleIdentifier</key><string>$($conf.identifier)</string>
	<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
	<key>CFBundleName</key><string>$($conf.productName)</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleShortVersionString</key><string>$($conf.version)</string>
	<key>CFBundleVersion</key><string>$($conf.version)</string>
	<key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
	<key>LSMinimumSystemVersion</key><string>12.0</string>
	<key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
"@ -replace "`r`n", "`n"
[IO.File]::WriteAllText((Join-Path $app 'Contents\Info.plist'), $plist, (New-Object Text.UTF8Encoding $false))
[IO.File]::WriteAllText((Join-Path $app 'Contents\PkgInfo'), 'APPL????', (New-Object Text.UTF8Encoding $false))
# Windows file systems have no executable bit: the archive sets it (a plain
# copy of the folder to a Mac needs `chmod +x superNET.app/Contents/MacOS/*`).
$archive = Join-Path $root "dist\macos\superNET-macos-$Arch.tar.gz"
$py = @'
import os, sys, tarfile
src, out = sys.argv[1], sys.argv[2]
base = os.path.dirname(src)
def fix(ti):
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    ti.mode = 0o755 if (ti.isdir() or "/Contents/MacOS/" in ti.name) else 0o644
    return ti
with tarfile.open(out, "w:gz") as t:
    t.add(src, arcname=os.path.relpath(src, base).replace(os.sep, "/"), filter=fix)
'@
$py | & python -I - $app $archive
if ($LASTEXITCODE) { throw 'archive failed' }
'{0}  ({1:N1} MB)' -f $app, ((Get-Item (Join-Path $app 'Contents\MacOS\superNET')).Length / 1MB)
'{0}  ({1:N1} MB)' -f $archive, ((Get-Item $archive).Length / 1MB)
