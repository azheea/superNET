# Set up key-based SSH from this PC to the node server, for deployment and tests.
#
#   scripts/setup-ssh.ps1 -Server 1.2.3.4 [-User root] [-Port 22]
#
# 1. Creates a dedicated key in local\ssh\ (git-ignored; ~/.ssh is not touched).
# 2. Prints one line to paste into the server's shell; it authorizes the key.
# 3. Saves the connection in local\node-ssh.json and checks that login works.
# No password is ever asked for or stored here.
param(
    [Parameter(Mandatory = $true)][string]$Server,
    [string]$User = 'root',
    [int]$Port = 22
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dir = New-Item -ItemType Directory -Force (Join-Path $root 'local\ssh')
$key = Join-Path $dir.FullName 'supernet_node'

if (-not (Test-Path $key)) {
    ssh-keygen -q -t ed25519 -N '""' -C 'supernet-node-deploy' -f $key
    if ($LASTEXITCODE) { throw 'ssh-keygen failed' }
    # OpenSSH refuses private keys other users can read.
    icacls $key /inheritance:r /grant:r "$($env:USERNAME):(R)" | Out-Null
}
$pub = (Get-Content "$key.pub" -Raw).Trim()

@{ server = $Server; user = $User; port = $Port; key = $key } | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $root 'local\node-ssh.json')

Write-Host ''
Write-Host '在服务器上（用你平时的方式登录后）粘贴执行下面这一行：' -ForegroundColor Cyan
Write-Host ''
Write-Host "mkdir -p ~/.ssh && chmod 700 ~/.ssh && grep -qxF '$pub' ~/.ssh/authorized_keys 2>/dev/null || echo '$pub' >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys && echo superNET-key-ok"
Write-Host ''
Read-Host '执行完后按回车，我来测试连接'

$out = ssh -i $key -p $Port -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "$User@$Server" 'echo login-ok; . /etc/os-release; echo "$PRETTY_NAME $(uname -r)"; free -m | head -2'
if ($LASTEXITCODE) {
    Write-Host '连接失败：确认上面那行已在服务器执行，用户名、端口正确。' -ForegroundColor Red
    exit 1
}
$out
Write-Host '连接正常，已保存到 local\node-ssh.json。' -ForegroundColor Green
