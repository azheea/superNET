# Build the Android app (APK).
#
#   scripts/build-android.ps1 [-Release] [-Targets x86_64,aarch64]
#
# Needs the Android SDK (platform 37.0, platform-tools), NDK 27 and JDK 17;
# see docs/DESIGN.md. Rust runs with the windows-gnu toolchain and
# llvm-mingw on the host (no Visual Studio), the NDK's clang for Android.
param([switch]$Release, [string[]]$Targets = @('x86_64'))
$ErrorActionPreference = 'Stop'
# `-File` passes `x86_64,aarch64` as one string.
$Targets = @($Targets | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$root = Split-Path -Parent $PSScriptRoot

if (-not $env:ANDROID_HOME) { $env:ANDROID_HOME = Join-Path $env:USERPROFILE 'Android\Sdk' }
if (-not $env:NDK_HOME) {
    $ndk = Get-ChildItem (Join-Path $env:ANDROID_HOME 'ndk') -Directory | Sort-Object Name | Select-Object -Last 1
    $env:NDK_HOME = $ndk.FullName
}
if (-not $env:JAVA_HOME) { $env:JAVA_HOME = (Get-ChildItem 'C:\Program Files\Microsoft' -Directory -Filter 'jdk-17*' | Select-Object -First 1).FullName }

$bin = $env:SUPERNET_MINGW
if (-not $bin) {
    $bin = Join-Path $root '..\server\starsavior\local_state\launcher-toolchain\llvm-mingw-20261104-msvcrt-x86_64\bin'
}
$bin = (Resolve-Path $bin).Path
$env:RUSTUP_TOOLCHAIN = 'stable-x86_64-pc-windows-gnu'
$env:PATH = $bin + ';' + $env:PATH
Remove-Item Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue
$env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = Join-Path $bin 'x86_64-w64-mingw32-gcc.exe'
$support = Join-Path $env:USERPROFILE '.rustup\toolchains\stable-x86_64-pc-windows-gnu\lib\rustlib\x86_64-pc-windows-gnu\lib\self-contained'
$libs = (New-Item -ItemType Directory -Force (Join-Path $root 'local\toolchain\rust-gcc-libs')).FullName
Copy-Item (Join-Path $support 'libgcc.a'), (Join-Path $support 'libgcc_eh.a') $libs -Force
$env:LIBRARY_PATH = $libs

# Rust targets, ABIs and Gradle flavours per architecture.
$arch = @{
    'x86_64'  = @{ triple = 'x86_64-linux-android'; abi = 'x86_64'; flavor = 'X86_64' }
    'aarch64' = @{ triple = 'aarch64-linux-android'; abi = 'arm64-v8a'; flavor = 'Arm64' }
}
$profile = if ($Release) { 'release' } else { 'debug' }
$started = Get-Date

Push-Location (Join-Path $root 'app')
try {
    # Builds the frontend, the Rust library and (normally) the APK. One step
    # symlinks the library into the Android project, which Windows refuses
    # without administrator rights or Developer Mode; then the fallback
    # below copies the library and runs Gradle itself.
    $a = @('tauri', 'android', 'build', '--apk', '--target') + $Targets
    if (-not $Release) { $a += '--debug' }
    & npx @a
    $tauriOk = ($LASTEXITCODE -eq 0)
    if (-not $tauriOk -and $Targets.Count -gt 1) {
        # Tauri stops at the first target's symlink, before compiling the
        # others: one target per run, so each library gets built.
        foreach ($t in $Targets | Select-Object -Skip 1) {
            $one = @('tauri', 'android', 'build', '--apk', '--target', $t)
            if (-not $Release) { $one += '--debug' }
            & npx @one
        }
    }
} finally { Pop-Location }

$android = Join-Path $root 'app\src-tauri\gen\android'
if (-not $tauriOk) {
$skip = @()
$assemble = @()
foreach ($t in $Targets) {
    $m = $arch[$t]
    if (-not $m) { throw "不支持的架构 $t" }
    $so = Join-Path $root "target\$($m.triple)\$profile\libsupernet_app.so"
    if (-not (Test-Path $so) -or (Get-Item $so).LastWriteTime -lt $started) { throw "Rust 库没有编译出来：$so" }
    $dir = New-Item -ItemType Directory -Force (Join-Path $android "app\src\main\jniLibs\$($m.abi)")
    Copy-Item $so (Join-Path $dir.FullName 'libsupernet_app.so') -Force
    $p = (Get-Culture).TextInfo.ToTitleCase($profile)
    $skip += @('-x', "rustBuild$($m.flavor)$p")
    $assemble += "assemble$($m.flavor)$p"
}

Push-Location $android
try {
    & .\gradlew.bat --no-daemon @assemble @skip
    if ($LASTEXITCODE) { throw 'gradle build failed' }
} finally { Pop-Location }
}

# Copy this build's APKs to dist/android.
$out = (New-Item -ItemType Directory -Force (Join-Path $root 'dist\android')).FullName
$apks = Get-ChildItem (Join-Path $android 'app\build\outputs\apk') -Recurse -Filter *.apk | Where-Object { $_.LastWriteTime -ge $started }
if (-not $apks) { throw '没有生成 APK' }
foreach ($apk in $apks) {
    $name = 'superNET-' + ($apk.BaseName -replace '^app-', '') + '.apk'
    Copy-Item $apk.FullName (Join-Path $out $name) -Force
    '{0}  {1:N1} MB' -f (Join-Path $out $name), ($apk.Length / 1MB)
}
