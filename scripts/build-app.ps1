# Build the Windows app: frontend, then the release executable.
# Output: dist\windows\superNET.exe (+ WebView2Loader.dll) and a zip.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

Push-Location (Join-Path $root 'app')
try {
    if (-not (Test-Path node_modules)) { npm ci; if ($LASTEXITCODE) { throw 'npm ci failed' } }
    npm run build
    if ($LASTEXITCODE) { throw 'frontend build failed' }
} finally { Pop-Location }

& (Join-Path $PSScriptRoot 'cargo.ps1') build -p supernet-app --release --features tauri/custom-protocol
if ($LASTEXITCODE) { throw 'app build failed' }

$out = (New-Item -ItemType Directory -Force (Join-Path $root 'dist\windows')).FullName
Copy-Item (Join-Path $root 'target\release\supernet-app.exe') (Join-Path $out 'superNET.exe') -Force
# The windows-gnu build loads WebView2 through this DLL; it must sit next to the exe.
Copy-Item (Join-Path $root 'target\release\WebView2Loader.dll') $out -Force
# TUN mode needs the signed wintun.dll next to the exe (fetched and verified).
& (Join-Path $PSScriptRoot 'fetch-wintun.ps1')
Copy-Item (Join-Path $root 'local\wintun\wintun.dll') $out -Force
Copy-Item (Join-Path $root 'local\wintun\LICENSE.txt') (Join-Path $out 'wintun-LICENSE.txt') -Force
$zip = Join-Path $out 'superNET-windows-x64.zip'
Compress-Archive -LiteralPath (Join-Path $out 'superNET.exe'), (Join-Path $out 'WebView2Loader.dll'), (Join-Path $out 'wintun.dll'), (Join-Path $out 'wintun-LICENSE.txt') -DestinationPath $zip -Force
Get-FileHash (Join-Path $out 'superNET.exe'), $zip | Format-Table -AutoSize
