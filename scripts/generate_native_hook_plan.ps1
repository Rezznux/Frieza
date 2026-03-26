param(
    [Parameter(Mandatory = $true)]
    [string]$ReportPath,
    [string]$OutputScriptPath
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$coreSrc = Join-Path $repoRoot "src"
$srcPath = Join-Path $repoRoot "static-lief\src"
$env:PYTHONPATH = "$coreSrc;$srcPath"

$command = @"
from apk_static_lief.scanner import load_report, build_native_hook_plan, render_native_hook_script
import json
report = load_report(r'''$ReportPath''')
plan = build_native_hook_plan(report)
result = render_native_hook_script(plan, r'''$OutputScriptPath''' if r'''$OutputScriptPath''' else None)
print(json.dumps({'plan': plan, 'result': result}, indent=2, sort_keys=True))
"@

python -c $command
