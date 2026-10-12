# Build Vega's patched Swift concurrency runtime (swift_Concurrency.dll) for
# Windows from the Swift release source plus runtime/patches/*.patch.
#
#   runtime\build-windows.ps1 [-Stock] [-Out DIR]
#
# UNTESTED: written to mirror build-linux.sh, not yet run on a Windows box.
#
# Needs, from an "x64 Native Tools Command Prompt for VS 2022" (or after
# Enter-VsDevShell, so INCLUDE/LIB/PATH point at MSVC and the Windows SDK):
#   - the Swift toolchain of the same release as $SwiftTag on PATH
#   - CMake >= 3.29 and Ninja (Visual Studio ships both), git, python
#
# Ship the result next to the app: Windows loads DLLs from the executable's
# directory before PATH, so an app-local swift_Concurrency.dll replaces the
# one the Swift runtime installer put on PATH, for that app only.
param(
    [switch]$Stock,
    [string]$Out,
    [string]$SwiftTag = $(if ($env:SWIFT_TAG) { $env:SWIFT_TAG } else { "swift-6.3.3-RELEASE" }),
    [string]$Work = $(if ($env:VEGA_RT_WORK) { $env:VEGA_RT_WORK } else { "$env:LOCALAPPDATA\vega-swift-runtime" }),
    [string]$SwiftRepo = $(if ($env:SWIFT_REPO) { $env:SWIFT_REPO } else { "https://github.com/swiftlang/swift.git" })
)
$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$variant = if ($Stock) { "stock" } else { "patched" }
if (-not $Out) { $Out = Join-Path $here "out\$variant-windows" }

function Run([string]$exe) {
    & $exe @args
    if ($LASTEXITCODE -ne 0) { throw "$exe failed ($LASTEXITCODE)" }
}

# Toolchain: the usr\ directory of the swiftc on PATH, and its release.
$info = swiftc -print-target-info | ConvertFrom-Json
$resources = $info.paths.runtimeResourcePath            # ...\usr\lib\swift
$tc = Split-Path (Split-Path $resources)                 # ...\usr
$want = $SwiftTag -replace '^swift-', '' -replace '-RELEASE$', ''
$version = (swiftc --version 2>&1 | Select-Object -First 1) -join ''
if ($version -notmatch "Swift version $([regex]::Escape($want))\b") {
    throw "toolchain is '$version', expected Swift $want"
}

# libdispatch from the Swift installation (the SDK holds the import library
# and headers, the runtime directory the DLL).
$swiftRoot = Split-Path (Split-Path (Split-Path $tc))     # ...\Programs\Swift
$dispatchLib = Get-ChildItem $swiftRoot -Recurse -Filter dispatch.lib -ErrorAction SilentlyContinue |
    Where-Object FullName -match 'x86_64|amd64' | Select-Object -First 1
$dispatchH = Get-ChildItem $swiftRoot -Recurse -Filter dispatch.h -ErrorAction SilentlyContinue |
    Where-Object { $_.Directory.Name -eq 'dispatch' } | Select-Object -First 1
if (-not $dispatchLib -or -not $dispatchH) { throw "libdispatch not found under $swiftRoot" }
$dispatchInclude = Split-Path $dispatchH.Directory.FullName

# The toolchain's own swift_Concurrency.dll, for the ABI gate.
$stockDll = Get-ChildItem $swiftRoot -Recurse -Filter swift_Concurrency.dll -ErrorAction SilentlyContinue |
    Where-Object FullName -match ([regex]::Escape($want)) | Select-Object -First 1

New-Item -ItemType Directory -Force $Work | Out-Null
$src = Join-Path $Work "src-$variant"
if (-not (Test-Path $src)) {
    Run git clone -q --depth 1 --branch $SwiftTag $SwiftRepo $src
}
Run git -C $src checkout -q -- .
if (-not $Stock) {
    foreach ($p in Get-ChildItem (Join-Path $here "patches") -Filter *.patch | Sort-Object Name) {
        Run git -C $src apply --whitespace=nowarn $p.FullName
        Write-Host "applied $($p.Name)"
    }
}
# The Runtimes\ build compiles copies of the stdlib sources.
Push-Location (Join-Path $src "Runtimes")
Run cmake -P Resync.cmake | Out-Null
Pop-Location

# Library evolution is the Windows default for shared builds (as in the
# toolchain's own build); set it explicitly anyway.
$build = Join-Path $Work "build-$variant-windows"
function Configure([string]$linkerFlags) {
    Run cmake -G Ninja -S (Join-Path $src "Runtimes\Core") -B $build `
        -DCMAKE_BUILD_TYPE=Release `
        -DBUILD_SHARED_LIBS=YES `
        -DSwiftCore_ENABLE_CONCURRENCY=ON `
        -DSwiftCore_ENABLE_LIBRARY_EVOLUTION=ON `
        "-DCMAKE_C_COMPILER=$tc\bin\clang-cl.exe" `
        "-DCMAKE_CXX_COMPILER=$tc\bin\clang-cl.exe" `
        "-DCMAKE_Swift_COMPILER=$tc\bin\swiftc.exe" `
        "-Ddispatch_INCLUDE_DIR=$dispatchInclude" `
        "-Ddispatch_LIBRARY=$($dispatchLib.FullName)" `
        "-DCMAKE_SHARED_LINKER_FLAGS=$linkerFlags"
}
Configure ""
# A Swift DLL must register its metadata sections with the runtime when it
# loads; swiftrt.obj does that. swiftc adds it when it links, this CMake
# project links with clang-cl, so add the project's own object by hand (on
# Linux, leaving it out made every by-name lookup of a concurrency type fail).
Run cmake --build $build --target swiftrt
$swiftrt = Get-ChildItem (Join-Path $build "runtime") -Recurse -Filter "SwiftRT-COFF.cpp.obj" |
    Where-Object FullName -notmatch 'swiftrtT' | Select-Object -First 1
if (-not $swiftrt) { throw "swiftrt object not built" }
Configure $swiftrt.FullName
Get-ChildItem $build -Recurse -Filter swift_Concurrency.dll | Remove-Item -Force  # force the relink
Run cmake --build $build --target swift_Concurrency

$dll = Get-ChildItem $build -Recurse -Filter swift_Concurrency.dll | Select-Object -First 1
if (-not $dll) { throw "build produced no swift_Concurrency.dll" }

# ABI gate: everything the toolchain's DLL exports must still be exported.
if ($stockDll -and (Get-Command dumpbin -ErrorAction SilentlyContinue)) {
    function Exports($path) {
        dumpbin /exports $path | ForEach-Object {
            if ($_ -match '^\s+\d+\s+[0-9A-F]+\s+[0-9A-F]+\s+(\S+)') { $Matches[1] }
        } | Sort-Object -Unique
    }
    $theirs = Exports $stockDll.FullName
    $ours = Exports $dll.FullName
    $missing = $theirs | Where-Object { $ours -notcontains $_ }
    if ($missing) {
        Write-Error "ABI mismatch: $(@($missing).Count) toolchain exports missing, e.g.`n$(($missing | Select-Object -First 20) -join "`n")"
    }
} else {
    Write-Warning "skipped the ABI gate (no toolchain swift_Concurrency.dll for $want or no dumpbin)"
}

New-Item -ItemType Directory -Force $Out | Out-Null
Copy-Item $dll.FullName $Out
$lib = Get-ChildItem $build -Recurse -Filter swift_Concurrency.lib | Select-Object -First 1
if ($lib) { Copy-Item $lib.FullName $Out }
Write-Host "built $Out\swift_Concurrency.dll"
