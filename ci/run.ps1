# ci/run.ps1 [-Linux] [-Windows] [-Conformance] [-Jobs uring,epoll,...]:
# Vega's local CI from this Windows machine. With no switch, Linux and
# Windows run.
#   Linux:   the working tree (changes to tracked files too; new files once
#            added to git) goes to the Linux box as a
#            tarball, and ci/linux.sh runs there in Docker. Builds are kept
#            in ~/vega-ci/src/.build-ci between runs.
#   Windows: ci/windows.ps1, here.
#   Conformance: ci/conformance.sh on the box, the same way: h2spec and
#            Autobahn (-Jobs h2spec or autobahn for one).
# macOS and the iOS simulator run on the Mac with ci/macos.sh.
# The box is shared: claim it from the other sessions before a run.
param([switch]$Linux, [switch]$Windows, [switch]$Conformance, [string[]]$Jobs = @(),
      [string]$Box = "grepjava@192.168.100.100")
if (-not $Linux -and -not $Windows -and -not $Conformance) { $Linux = $true; $Windows = $true }
$root = Split-Path $PSScriptRoot -Parent
$failed = $false

if ($Linux -or $Conformance) {
    Push-Location $root
    # A commit of the working tree, uncommitted changes and all.
    $tree = git stash create
    if (-not $tree) { $tree = git rev-parse HEAD }
    $label = git rev-parse --short HEAD
    if ($tree -ne (git rev-parse HEAD)) { $label += "+dirty" }
    $tar = Join-Path ([IO.Path]::GetTempPath()) "vega-ci.tar"
    git archive --format=tar -o $tar $tree
    Pop-Location
    $script = if ($Conformance) { "conformance.sh" } else { "linux.sh" }
    "== $script on $Box ($label)"
    scp -q $tar "${Box}:vega-ci.tar"
    $remote = "mkdir -p ~/vega-ci/src && cd ~/vega-ci/src && " +
              "find . -mindepth 1 -maxdepth 1 ! -name .build-ci -exec rm -rf {} + && " +
              "tar -xf ~/vega-ci.tar && echo $label > .ci-commit && bash ci/$script $(($Jobs -join ',') -split ',' -join ' ')"
    ssh $Box $remote
    if ($LASTEXITCODE -ne 0) { $failed = $true }
}

if ($Windows) {
    "== Windows"
    pwsh -NoProfile -File (Join-Path $PSScriptRoot "windows.ps1") -Source $root
    if ($LASTEXITCODE -ne 0) { $failed = $true }
}

if ($failed) { exit 1 }
