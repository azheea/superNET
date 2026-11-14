# Publish the current tree to the public GitHub repository as one snapshot
# commit on top of the public history (the private history stays local).
#
#   scripts/publish.ps1 -Message "说明" [-Remote public] [-DryRun]
#
# Before anything is pushed, the tree is checked for:
#   - every pattern in local/publish-deny.txt (addresses, names, link formats
#     that must not be public; the file itself is never published), and
#   - every secret value found in local/*.yaml|*.txt|*.json|*.properties
#     (passwords, private keys, invite tokens).
# Any match stops the publish and names the file.
param([Parameter(Mandatory)][string]$Message, [string]$Remote = 'public', [switch]$DryRun)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (git status --porcelain) { throw '工作区有未提交的改动：先提交，发布的是 HEAD' }

$problems = @()
$deny = Join-Path $root 'local\publish-deny.txt'
if (-not (Test-Path $deny)) { throw "没有 $deny（要拦下的内容列表）" }
foreach ($p in Get-Content $deny -Encoding utf8) {
    if (-not $p.Trim() -or $p.StartsWith('#')) { continue }
    $hits = git grep -I -l -E -e $p HEAD -- . ':!vendor'
    if ($hits) { $problems += "规则 #$([array]::IndexOf((Get-Content $deny), $p))：$($hits -join ', ')" }
}
$secrets = @{}
Get-ChildItem (Join-Path $root 'local') -File -Include *.yaml, *.txt, *.json, *.properties -Recurse -Depth 1 | ForEach-Object {
    $text = Get-Content $_.FullName -Raw -Encoding utf8
    foreach ($m in [regex]::Matches($text, '(password|private_key|preshared_key|storePassword|keyPassword|invite)\s*[:=]\s*"?([^"\s]+)"?')) {
        if ($m.Groups[2].Value.Length -ge 8) { $secrets["$($_.Name):$($m.Groups[1].Value)"] = $m.Groups[2].Value }
    }
    foreach ($m in [regex]::Matches($text, '[?&]k=([A-Za-z0-9_\-]+)')) { $secrets["$($_.Name):invite-k"] = $m.Groups[1].Value }
}
foreach ($k in $secrets.Keys) {
    $hits = git grep -I -l -F -e $secrets[$k] HEAD -- .
    if ($hits) { $problems += "密钥 $k：$($hits -join ', ')" }
}
if ($problems) {
    $problems | ForEach-Object { Write-Host "拦下：$_" -ForegroundColor Red }
    throw '有不能公开的内容，没有发布'
}
"检查通过：$((Get-Content $deny | Where-Object { $_ -and -not $_.StartsWith('#') }).Count) 条规则、$($secrets.Count) 个密钥值都没有出现"

# Author: the GitHub account's noreply address (no real e-mail in public commits).
$ghId = gh api user --jq .id 2>$null
$login = gh api user --jq .login 2>$null
if ($ghId -and $login) {
    $env:GIT_AUTHOR_NAME = $login; $env:GIT_COMMITTER_NAME = $login
    $env:GIT_AUTHOR_EMAIL = "$ghId+$login@users.noreply.github.com"; $env:GIT_COMMITTER_EMAIL = $env:GIT_AUTHOR_EMAIL
}

# One commit holding HEAD's tree, on top of the public branch (if any).
$parent = git rev-parse --verify --quiet refs/heads/public
$tree = git rev-parse 'HEAD^{tree}'
# The message goes through a UTF-8 file: Windows PowerShell pipes text to
# native programs as ASCII, which turned every Chinese character into '?'.
$msgFile = Join-Path ([IO.Path]::GetTempPath()) "supernet-publish-$PID.txt"
[IO.File]::WriteAllText($msgFile, "$Message`n", (New-Object Text.UTF8Encoding $false))
try {
    $commit = if ($parent) { git commit-tree $tree -p $parent -F $msgFile } else { git commit-tree $tree -F $msgFile }
} finally { Remove-Item $msgFile -ErrorAction SilentlyContinue }
if ($parent -and (git rev-parse "$parent^{tree}") -eq $tree) { '公开版本已经是这个内容，不用发布'; exit 0 }
if ($DryRun) { "（演练）会发布提交 $commit"; exit 0 }
git update-ref refs/heads/public $commit
git push $Remote public:main
if ($LASTEXITCODE) { throw 'push 失败' }
"已发布 $commit"
