# ci/run.ps1 [-Linux] [-Windows] [-Jobs uring,epoll,...]: Vega's local CI from
# this Windows machine. With neither switch, both run.
#   Linux:   the working tree (committed or not) goes to the Linux box as a
#            tarball, and ci/linux.sh runs there in Docker. Builds are kept
#            in ~/vega-ci/src/.build-ci between runs.
#   Windows: ci/windows.ps1, here.
# macOS and the iOS simulator run on the Mac with ci/macos.sh.
# The box is shared: claim it from the other sessions before a run.
param([switch]$Linux, [switch]$Windows, [string[]]$Jobs = @(),
      [string]$Box = "grepjava@192.168.100.100")
if (-not $Linux -and -not $Windows) { $Linux = $true; $Windows = $true }
$root = Split-Path $PSScriptRoot -Parent
$failed = $false

if ($Linux) {
    Push-Location $root
    # A commit of the working tree, uncommitted changes and all.
    $tree = git stash create
    if (-not $tree) { $tree = git rev-parse HEAD }
    $label = git rev-parse --short HEAD
    if ($tree -ne (git rev-parse HEAD)) { $label += "+dirty" }
    $tar = Join-Path ([IO.Path]::GetTempPath()) "vega-ci.tar"
    git archive --format=tar -o $tar $tree
    Pop-Location
    "== Linux on $Box ($label)"
    scp -q $tar "${Box}:vega-ci.tar"
    $remote = "mkdir -p ~/vega-ci/src && cd ~/vega-ci/src && " +
              "find . -mindepth 1 -maxdepth 1 ! -name .build-ci -exec rm -rf {} + && " +
              "tar -xf ~/vega-ci.tar && echo $label > .ci-commit && bash ci/linux.sh $($Jobs -join ' ')"
    ssh $Box $remote
    if ($LASTEXITCODE -ne 0) { $failed = $true }
}

if ($Windows) {
    "== Windows"
    pwsh -NoProfile -File (Join-Path $PSScriptRoot "windows.ps1") -Source $root
    if ($LASTEXITCODE -ne 0) { $failed = $true }
}

if ($failed) { exit 1 }
