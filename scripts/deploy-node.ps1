# Copy node/ to the server saved by setup-ssh.ps1 and run the installer.
#
#   scripts/deploy-node.ps1 [-- extra install.sh arguments, e.g. --port 51820]
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$cfgPath = Join-Path $root 'local\node-ssh.json'
if (-not (Test-Path $cfgPath)) { throw '先运行 scripts/setup-ssh.ps1 -Server <地址>' }
$c = Get-Content $cfgPath -Raw | ConvertFrom-Json
$target = "$($c.user)@$($c.server)"
$sshArgs = @('-i', $c.key, '-p', $c.port, '-o', 'BatchMode=yes')

# Line endings matter for bash: copy LF-only versions.
$stage = New-Item -ItemType Directory -Force (Join-Path $root 'local\node-stage')
foreach ($f in 'install.sh', 'supernet-node') {
    $text = (Get-Content (Join-Path (Join-Path $root 'node') $f) -Raw -Encoding UTF8) -replace "`r`n", "`n"
    [IO.File]::WriteAllText((Join-Path $stage.FullName $f), $text, (New-Object Text.UTF8Encoding $false))
}
ssh @sshArgs $target 'mkdir -p /root/supernet-node-install'
scp -i $c.key -P $c.port -o BatchMode=yes (Join-Path $stage.FullName 'install.sh') (Join-Path $stage.FullName 'supernet-node') "${target}:/root/supernet-node-install/"
if ($LASTEXITCODE) { throw 'scp failed' }
$extra = ($args | ForEach-Object { "'$_'" }) -join ' '
ssh @sshArgs $target "cd /root/supernet-node-install && chmod +x install.sh supernet-node && $(if ($c.user -ne 'root') { 'sudo ' })bash install.sh $extra"
exit $LASTEXITCODE
