# ci/windows.ps1: Vega's Windows CI. Builds and runs the tests with the
# Swift 6.3.3 toolchain from winget, Visual Studio's x64 environment and
# OpenSSL from slproweb.com (C:\Program Files\OpenSSL-Win64), once per I/O
# backend: iocp (the default: overlapped requests) and afd (readiness, with
# VEGA_DRIVER=afd). Builds in %LOCALAPPDATA%\vega-ci-windows, kept between
# runs; the logs are next to it.
param([string]$Source = (Split-Path $PSScriptRoot -Parent), [string]$Filter = "",
      [string[]]$Drivers = @("iocp", "afd"))
$ErrorActionPreference = "Continue"

# Visual Studio's developer environment.
$installer = "C:\Program Files (x86)\Microsoft Visual Studio\Installer"
$env:Path = "$installer;" + $env:Path    # vcvars64.bat runs vswhere too
$vs = & "$installer\vswhere.exe" -latest -property installationPath
cmd /c "`"$vs\VC\Auxiliary\Build\vcvars64.bat`" >nul && set" | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process') }
}
# The toolchain, and SDKROOT, which a process started before it was set lacks.
$swift = "$env:LOCALAPPDATA\Programs\Swift"
$env:Path = "$swift\Toolchains\6.3.3+Asserts\usr\bin;$swift\Runtimes\6.3.3\usr\bin;" + $env:Path
foreach ($v in "SDKROOT", "DEVELOPER_DIR") {
    $x = [Environment]::GetEnvironmentVariable($v, "User")
    if (-not $x) { $x = [Environment]::GetEnvironmentVariable($v, "Machine") }
    if ($x) { Set-Item "env:$v" $x }
}
$ssl = "C:\Program Files\OpenSSL-Win64"
$env:INCLUDE = "$ssl\include;" + $env:INCLUDE
$env:LIB = "$ssl\lib\VC\x64\MD;" + $env:LIB
$env:Path = "$ssl\bin;" + $env:Path

Set-Location $Source
$scratch = "$env:LOCALAPPDATA\vega-ci-windows"
$start = Get-Date
# Output to a file, never a pipe: a pipe closed early (Select-Object -First)
# leaves swift-frontend blocked on it.
swift build --build-tests --scratch-path $scratch *> "$scratch.log"
$failed = 0
if ($LASTEXITCODE -ne 0) {
    $took = [int]((Get-Date) - $start).TotalSeconds
    $summary = Select-String -Path "$scratch.log" -Pattern "error:" | Select-Object -Last 1 | ForEach-Object { $_.Line }
    "FAIL  windows build (${took}s) $summary"
    Select-String -Path "$scratch.log" -Pattern "error:" | Select-Object -First 20 | ForEach-Object { "      " + $_.Line }
    exit 1
}
foreach ($driver in $Drivers) {
    $start = Get-Date
    $log = "$scratch-$driver.log"
    $env:VEGA_DRIVER = $driver
    $testArgs = @("test", "--skip-build", "--scratch-path", $scratch)
    if ($Filter) { $testArgs += @("--filter", $Filter) }
    swift @testArgs *> $log
    $code = $LASTEXITCODE
    $took = [int]((Get-Date) - $start).TotalSeconds
    $summary = Select-String -Path $log -Pattern "Test run with|error:" | Select-Object -Last 1 | ForEach-Object { $_.Line }
    if ($code -eq 0) {
        "PASS  windows-$driver (${took}s) $summary"
    } else {
        $failed = 1
        "FAIL  windows-$driver (${took}s, exit $code) $summary"
        Select-String -Path $log -Pattern "✘|×|error:" | Select-Object -First 20 | ForEach-Object { "      " + $_.Line }
    }
}
Remove-Item env:VEGA_DRIVER
exit $failed
