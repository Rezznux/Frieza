function Get-ApkitWorkspaceRoot {
    param([string]$WorkspaceRoot)

    if ($WorkspaceRoot) {
        $root = $WorkspaceRoot
    } elseif ($env:APKIT_HOME) {
        $root = $env:APKIT_HOME
    } elseif ($env:LOCALAPPDATA) {
        $root = Join-Path $env:LOCALAPPDATA "apk-intercept-kit"
    } else {
        $root = Join-Path $HOME ".apkit"
    }

    $resolved = [System.IO.Path]::GetFullPath($root)
    New-Item -ItemType Directory -Force -Path $resolved | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $resolved "sessions") | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $resolved "state") | Out-Null
    return $resolved
}

function Initialize-ApkitSessionLayout {
    param([string]$SessionPath)

    $resolved = [System.IO.Path]::GetFullPath($SessionPath)
    $dirs = @(
        $resolved,
        (Join-Path $resolved "input"),
        (Join-Path $resolved "static"),
        (Join-Path $resolved "generated-hooks"),
        (Join-Path $resolved "runtime"),
        (Join-Path $resolved "repacked"),
        (Join-Path $resolved "logs"),
        (Join-Path $resolved "trust"),
        (Join-Path $resolved "targets")
    )
    foreach ($dir in $dirs) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    return $resolved
}

function Resolve-ApkitSessionPath {
    param(
        [string]$WorkspaceRoot,
        [string]$SessionPath
    )

    if ($SessionPath) {
        return (Initialize-ApkitSessionLayout -SessionPath $SessionPath)
    }
    if ($env:APKIT_SESSION) {
        return (Initialize-ApkitSessionLayout -SessionPath $env:APKIT_SESSION)
    }

    $workspace = Get-ApkitWorkspaceRoot -WorkspaceRoot $WorkspaceRoot
    $activeFile = Join-Path $workspace "state\\active_session.txt"
    if (Test-Path $activeFile) {
        $active = (Get-Content -Path $activeFile -TotalCount 1).Trim()
        if ($active) {
            return (Initialize-ApkitSessionLayout -SessionPath $active)
        }
    }

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $newSession = Join-Path $workspace "sessions\\adhoc\\default\\$timestamp"
    $resolved = Initialize-ApkitSessionLayout -SessionPath $newSession
    $resolved | Set-Content -Path $activeFile -Encoding utf8
    return $resolved
}

function Get-ApkitSessionDir {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("input", "static", "generated-hooks", "runtime", "repacked", "logs", "trust", "targets")]
        [string]$Kind,
        [string]$WorkspaceRoot,
        [string]$SessionPath
    )

    $resolvedSession = Resolve-ApkitSessionPath -WorkspaceRoot $WorkspaceRoot -SessionPath $SessionPath
    $dir = Join-Path $resolvedSession $Kind
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    return $dir
}

function Get-ApkitTrustLogPath {
    param(
        [string]$WorkspaceRoot,
        [string]$SessionPath
    )

    if ($env:APKIT_TRUST_LOG) {
        $path = [System.IO.Path]::GetFullPath($env:APKIT_TRUST_LOG)
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null
        return $path
    }

    $trustDir = Get-ApkitSessionDir -Kind "trust" -WorkspaceRoot $WorkspaceRoot -SessionPath $SessionPath
    return (Join-Path $trustDir "events.jsonl")
}
