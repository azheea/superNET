# Download wintun.dll (needed for TUN mode on Windows) and verify it.
#
#   scripts/fetch-wintun.ps1 [-Arch amd64|arm64|x86]
#
# Output: local\wintun\wintun.dll and LICENSE.txt (git-ignored).
param([ValidateSet('amd64', 'arm64', 'x86')][string]$Arch = 'amd64')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$out = (New-Item -ItemType Directory -Force (Join-Path $root 'local\wintun')).FullName
$dll = Join-Path $out 'wintun.dll'
$zipHash = '07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51'
# Per architecture, from the official zip above (whose hash is pinned).
$dllHash = @{
    amd64 = 'E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE'
    arm64 = 'F7BA89005544BE9D85231A9E0D5F23B2D15B3311667E2DAD0DEBD344918A3F80'
    x86   = 'D694FA46AB4CFEBCB2632D094C7AA97278EEF2F8052438621766D863AE98A931'
}[$Arch]

if ((Test-Path $dll) -and (Get-FileHash $dll).Hash -eq $dllHash) { Write-Host 'wintun.dll already present'; exit 0 }

$tmp = Join-Path $out 'wintun-0.14.1.zip'
Invoke-WebRequest -UseBasicParsing -Uri 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $tmp
if ((Get-FileHash $tmp).Hash -ne $zipHash) { Remove-Item $tmp; throw 'wintun zip hash mismatch' }
$extract = Join-Path $out 'extract'
Expand-Archive -Force $tmp $extract
Copy-Item (Join-Path $extract "wintun\bin\$Arch\wintun.dll") $dll -Force
Copy-Item (Join-Path $extract 'wintun\LICENSE.txt') (Join-Path $out 'LICENSE.txt') -Force
Remove-Item -Recurse -Force $extract, $tmp

if ((Get-FileHash $dll).Hash -ne $dllHash) { throw 'wintun.dll hash mismatch' }
$sig = Get-AuthenticodeSignature $dll
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notlike 'CN=WireGuard LLC*') { throw "wintun.dll signature: $($sig.Status)" }
Write-Host "wintun.dll ok: $dll"
