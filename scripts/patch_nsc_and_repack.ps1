param(
    [Parameter(Mandatory = $true)]
    [string]$ApkPath,
    [string]$OutputDir,
    [switch]$InjectNetworkSecurityConfig,
    [switch]$EmbedGadget,
    [string]$GadgetRoot,
    [string]$KeystorePath,
    [string]$KeystorePass = "android",
    [string]$KeyAlias = "androiddebugkey",
    [string]$KeyPass = "android",
    [string]$WorkspaceRoot,
    [string]$SessionPath
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "_workspace.ps1")

function Require-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $Name"
    }
}

Require-Command apktool
Require-Command zipalign
Require-Command apksigner

$apk = Resolve-Path $ApkPath
if (-not $OutputDir) {
    $OutputDir = Get-ApkitSessionDir -Kind "repacked" -WorkspaceRoot $WorkspaceRoot -SessionPath $SessionPath
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$workDir = Join-Path $OutputDir "decoded"
$unsignedApk = Join-Path $OutputDir "unsigned.apk"
$alignedApk = Join-Path $OutputDir "aligned.apk"
$signedApk = Join-Path $OutputDir (([IO.Path]::GetFileNameWithoutExtension($apk)) + "-patched-signed.apk")

if (Test-Path $workDir) { cmd /c rmdir /s /q "$workDir" | Out-Null }
if (Test-Path $unsignedApk) { cmd /c del /f /q "$unsignedApk" | Out-Null }
if (Test-Path $alignedApk) { cmd /c del /f /q "$alignedApk" | Out-Null }
if (Test-Path $signedApk) { cmd /c del /f /q "$signedApk" | Out-Null }

& apktool d -f -o $workDir $apk | Out-Host

if ($InjectNetworkSecurityConfig) {
    $resXmlDir = Join-Path $workDir "res\xml"
    New-Item -ItemType Directory -Force -Path $resXmlDir | Out-Null
    $nscPath = Join-Path $resXmlDir "network_security_config.xml"
    @'
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors>
      <certificates src="system" />
      <certificates src="user" />
    </trust-anchors>
  </base-config>
</network-security-config>
'@ | Set-Content -Path $nscPath -Encoding utf8

    $manifestPath = Join-Path $workDir "AndroidManifest.xml"
    [xml]$manifest = Get-Content -Path $manifestPath
    $appNode = $manifest.manifest.application
    if (-not $appNode) {
        throw "Application node not found in manifest."
    }
    $androidNs = "http://schemas.android.com/apk/res/android"
    $attr = $appNode.Attributes.GetNamedItem("networkSecurityConfig", $androidNs)
    if (-not $attr) {
        $attr = $manifest.CreateAttribute("android", "networkSecurityConfig", $androidNs)
        $appNode.Attributes.Append($attr) | Out-Null
    }
    $attr.Value = "@xml/network_security_config"
    $manifest.Save($manifestPath)
}

if ($EmbedGadget) {
    if (-not $GadgetRoot) {
        throw "GadgetRoot is required when -EmbedGadget is used."
    }
    $libDir = Join-Path $workDir "lib"
    New-Item -ItemType Directory -Force -Path $libDir | Out-Null
    Get-ChildItem -Path $GadgetRoot -Directory | ForEach-Object {
        $abiDir = Join-Path $libDir $_.Name
        New-Item -ItemType Directory -Force -Path $abiDir | Out-Null
        Copy-Item -Path (Join-Path $_.FullName "libfrida-gadget.so") -Destination (Join-Path $abiDir "libfrida-gadget.so") -Force
    }
}

& apktool b $workDir -o $unsignedApk | Out-Host
& zipalign -f -p 4 $unsignedApk $alignedApk | Out-Host

if (-not $KeystorePath) {
    $KeystorePath = Join-Path $OutputDir "debug.keystore"
    if (-not (Test-Path $KeystorePath)) {
        Require-Command keytool
        & keytool -genkeypair -storetype JKS -keystore $KeystorePath -storepass $KeystorePass -keypass $KeyPass -alias $KeyAlias -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Android Debug,O=Codex,C=GB" | Out-Host
    }
}

& apksigner sign --ks $KeystorePath --ks-pass "pass:$KeystorePass" --key-pass "pass:$KeyPass" --ks-key-alias $KeyAlias --out $signedApk $alignedApk | Out-Host
Write-Host $signedApk
