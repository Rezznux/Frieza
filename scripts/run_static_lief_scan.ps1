param(
    [string]$ApkPath,
    [string]$SourceDir,
    [string]$OutputPath
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($ApkPath) -and [string]::IsNullOrWhiteSpace($SourceDir)) {
    throw "Provide -ApkPath or -SourceDir."
}
if (-not [string]::IsNullOrWhiteSpace($ApkPath) -and -not [string]::IsNullOrWhiteSpace($SourceDir)) {
    throw "Use only one of -ApkPath or -SourceDir."
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$coreSrc = Join-Path $repoRoot "src"
$srcPath = Join-Path $repoRoot "static-lief\src"
$env:PYTHONPATH = "$coreSrc;$srcPath"

$args = @("-m", "apk_static_lief.cli")
if ($ApkPath) {
    $args += @("--apk", $ApkPath)
}
if ($SourceDir) {
    $args += @("--source-dir", $SourceDir)
}
if ($OutputPath) {
    $args += @("--output", $OutputPath)
}

python @args
