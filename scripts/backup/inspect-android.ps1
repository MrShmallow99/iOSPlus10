# Read-only phone inventory. Does not reboot, mount, flash, or change slots.
[CmdletBinding()]
param(
    [string]$Adb = 'C:\platform-tools\adb.exe',
    [string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
    $OutputDirectory = Join-Path $scriptDirectory '../../out/android-inventory'
}
if (-not (Test-Path -LiteralPath $Adb -PathType Leaf)) { throw "ADB not found: $Adb" }
& $Adb get-state
if ($LASTEXITCODE -ne 0) { throw 'ADB cannot reach one authorized phone. No device changes were made.' }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
function Save-AdbRead([string]$Name, [string[]]$Arguments) {
    # Windows PowerShell turns native stderr into ErrorRecords. Preserve it in
    # the report and use the process exit code to decide whether the read failed.
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $result = & $Adb @Arguments 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedPreference
    }
    $result | Set-Content -LiteralPath (Join-Path $OutputDirectory $Name) -Encoding UTF8
    if ($code -ne 0) { throw "Read failed: $Name (exit $code). See the saved output." }
}
Save-AdbRead 'identity.txt' @('shell', 'for p in ro.product.model ro.product.device ro.product.board ro.build.display.id ro.build.version.release ro.build.version.security_patch ro.boot.flash.locked ro.boot.slot_suffix ro.boot.verifiedbootstate ro.crypto.state ro.crypto.type; do echo "$p=$(getprop $p)"; done')
Save-AdbRead 'root-access.txt' @('shell', 'su', '-c', "'id'")
if ((Get-Content -Raw -LiteralPath (Join-Path $OutputDirectory 'root-access.txt')) -notmatch '\buid=0\b') {
    throw 'Root access was not granted. Approve the shell root request on the phone and run again.'
}
Save-AdbRead 'storage.txt' @('shell', 'su', '-c', "'set -e; df -h /data; cat /proc/partitions; cat /proc/mounts'")
Save-AdbRead 'root-layout.txt' @('shell', 'su', '-c', "'set -e; id; ls -l /dev/block/by-name; cat /proc/self/mountinfo'")
Write-Host "Read-only inventory saved to $OutputDirectory"
Write-Host 'No backup was made. This inventory does not contain partition images or app data.'
