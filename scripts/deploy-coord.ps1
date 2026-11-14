# Install or update the coordinator on the server saved by setup-ssh.ps1.
#
#   scripts/deploy-coord.ps1 [-Port 19190] [-Network superNET]
#
# Copies dist/linux/supernet-coord (build it with scripts/build-coord.ps1),
# installs a systemd service and prints the invite link. The server's wg0
# becomes a member of the network (10.66.0.1). Nothing else on the server
# (s-ui, existing wg0 peers) is touched.
param([int]$Port = 19190, [string]$Network = 'superNET')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$c = Get-Content (Join-Path $root 'local\node-ssh.json') -Raw | ConvertFrom-Json
$target = "$($c.user)@$($c.server)"
$sshArgs = @('-i', $c.key, '-p', $c.port, '-o', 'BatchMode=yes')
$binary = Join-Path $root 'dist\linux\supernet-coord'
if (-not (Test-Path $binary)) { throw '先运行 scripts/build-coord.ps1' }

$unit = @"
[Unit]
Description=superNET virtual network coordinator
After=network-online.target wg-quick@wg0.service
Wants=network-online.target

[Service]
# Listen on the public address itself: replies then always come from it,
# which NATs in front of devices require (a 0.0.0.0 socket may answer from
# another of the server's addresses).
ExecStart=/usr/local/bin/supernet-coord run --public $($c.server):$Port --listen $($c.server):$Port --wg wg0 --network $Network
Restart=on-failure
RestartSec=3
# Small and bounded on a 1 GB server.
MemoryMax=64M
Nice=5

[Install]
WantedBy=multi-user.target
"@ -replace "`r`n", "`n"
$stage = (New-Item -ItemType Directory -Force (Join-Path $root 'local\coord-stage')).FullName
[IO.File]::WriteAllText((Join-Path $stage 'supernet-coord.service'), $unit, (New-Object Text.UTF8Encoding $false))

scp -i $c.key -P $c.port -o BatchMode=yes $binary (Join-Path $stage 'supernet-coord.service') "${target}:/tmp/"
if ($LASTEXITCODE) { throw 'scp failed' }
$script = @"
set -e
install -m 0755 /tmp/supernet-coord /usr/local/bin/supernet-coord
install -m 0644 /tmp/supernet-coord.service /etc/systemd/system/supernet-coord.service
rm -f /tmp/supernet-coord /tmp/supernet-coord.service
cp -n /etc/wireguard/wg0.conf /etc/wireguard/wg0.conf.before-mesh 2>/dev/null || true
systemctl daemon-reload
systemctl enable supernet-coord >/dev/null 2>&1
systemctl restart supernet-coord
sleep 2
systemctl is-active supernet-coord
ps -o rss=,cmd= -C supernet-coord
/usr/local/bin/supernet-coord invite --public $($c.server):$Port
"@ -replace "`r`n", "`n"
$script | ssh @sshArgs $target 'bash -s'
exit $LASTEXITCODE
