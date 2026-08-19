# Import the ActiveDirectory module on a best effort basis. It ships with RSAT and is not available on the
# PowerShell Gallery, so it cannot be declared in RequiredModules: that would break Test-ModuleManifest and
# the installation from the Gallery. Importing PSADDS stays possible without RSAT, only the functions that
# need it will fail, with an explicit message.
if (-not (Get-Module -Name 'ActiveDirectory')) {
    try {
        Import-Module -Name 'ActiveDirectory' -ErrorAction Stop
    }
    catch {
        Write-Warning 'The ActiveDirectory module could not be imported, the PSADDS functions will not work. Install RSAT (Windows) or the RSAT-AD-PowerShell feature (Windows Server).'
    }
}

# Dot-source every .ps1 file under Public/ and Private/ recursively.
$public = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue)
$private = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue)

foreach ($file in @($private + $public)) {
    try {
        . $file.FullName
    }
    catch {
        Write-Error "Failed to import function $($file.FullName): $_"
    }
}

Export-ModuleMember -Function $public.BaseName