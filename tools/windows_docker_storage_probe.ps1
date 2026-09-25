param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("before-collection", "before-prepare", "before-reference", "after-reference")]
    [string]$Boundary
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

function Get-CanonicalDataVhd {
    $locationSource = $null
    $candidatePaths = @()
    $registrationCandidate = $null
    $registrationSource = $null

    $lxssRoot = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss"
    $registrations = @()
    if (Test-Path -LiteralPath $lxssRoot) {
        $registrations = @(
            Get-ChildItem -LiteralPath $lxssRoot |
                ForEach-Object { Get-ItemProperty -LiteralPath $_.PSPath }
        )
    }
    $dataRegistrations = @(
        $registrations |
            Where-Object { $_.DistributionName -eq "docker-desktop-data" }
    )
    $desktopRegistrations = @(
        $registrations |
            Where-Object { $_.DistributionName -eq "docker-desktop" }
    )
    if ($dataRegistrations.Count -gt 1) {
        throw "multiple docker-desktop-data WSL registrations were found"
    }
    if ($desktopRegistrations.Count -gt 1) {
        throw "multiple docker-desktop WSL registrations were found"
    }
    if ($dataRegistrations.Count -eq 1) {
        $registration = $dataRegistrations[0]
        $basePath = [Environment]::ExpandEnvironmentVariables(
            [string]$registration.BasePath
        )
        if ($basePath.StartsWith("\\?\")) {
            $basePath = $basePath.Substring(4)
        }
        if (-not [System.IO.Path]::IsPathRooted($basePath)) {
            throw "the docker-desktop-data WSL BasePath is not absolute"
        }
        $vhdFileNameProperty = $registration.PSObject.Properties["VhdFileName"]
        $vhdFileName = if ($null -eq $vhdFileNameProperty) {
            ""
        }
        else {
            [string]$vhdFileNameProperty.Value
        }
        if ([string]::IsNullOrWhiteSpace($vhdFileName)) {
            $vhdFileName = "ext4.vhdx"
        }
        if (
            [System.IO.Path]::GetFileName($vhdFileName) -ne $vhdFileName -or
            [System.IO.Path]::GetExtension($vhdFileName) -ne ".vhdx"
        ) {
            throw "the docker-desktop-data WSL VHD filename is invalid"
        }
        $registrationCandidate = Join-Path $basePath $vhdFileName
        $registrationSource = "wsl-lxss-docker-desktop-data"
    }
    elseif ($desktopRegistrations.Count -eq 1) {
        # This Docker Desktop layout registers its engine under main and stores
        # the data disk in the sibling disk directory.
        $registration = $desktopRegistrations[0]
        $basePath = [Environment]::ExpandEnvironmentVariables(
            [string]$registration.BasePath
        )
        if ($basePath.StartsWith("\\?\")) {
            $basePath = $basePath.Substring(4)
        }
        if (-not [System.IO.Path]::IsPathRooted($basePath)) {
            throw "the docker-desktop WSL BasePath is not absolute"
        }
        $basePath = [System.IO.Path]::GetFullPath($basePath).TrimEnd("\")
        if (
            [string]::Equals(
                [System.IO.Path]::GetFileName($basePath),
                "main",
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            $vhdFileNameProperty = $registration.PSObject.Properties["VhdFileName"]
            $vhdFileName = if ($null -eq $vhdFileNameProperty) {
                ""
            }
            else {
                [string]$vhdFileNameProperty.Value
            }
            if ([string]::IsNullOrWhiteSpace($vhdFileName)) {
                $vhdFileName = "ext4.vhdx"
            }
            if (
                [System.IO.Path]::GetFileName($vhdFileName) -ne $vhdFileName -or
                [System.IO.Path]::GetExtension($vhdFileName) -ne ".vhdx"
            ) {
                throw "the docker-desktop WSL VHD filename is invalid"
            }
            $mainVhdPath = Join-Path $basePath $vhdFileName
            if (-not (Test-Path -LiteralPath $mainVhdPath -PathType Leaf)) {
                throw "the registered docker-desktop WSL VHDX is missing"
            }
            $mainVhd = Get-Item -Force -LiteralPath $mainVhdPath
            if (
                $mainVhd.PSIsContainer -or
                $mainVhd.Length -le 0 -or
                ($mainVhd.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
            ) {
                throw "the registered docker-desktop WSL VHDX is not a regular file"
            }
            $dataRoot = [System.IO.Path]::GetDirectoryName($basePath)
            $registrationCandidate = Join-Path $dataRoot "disk\docker_data.vhdx"
            $registrationSource = "wsl-lxss-docker-desktop-sibling-disk"
        }
    }

    $settingsStore = Join-Path $env:APPDATA "Docker\settings-store.json"
    $legacySettings = Join-Path $env:APPDATA "Docker\settings.json"
    $settingsPath = $null
    if (Test-Path -LiteralPath $settingsStore -PathType Leaf) {
        $settingsPath = $settingsStore
    }
    elseif (Test-Path -LiteralPath $legacySettings -PathType Leaf) {
        $settingsPath = $legacySettings
    }

    $configuredRoot = $null
    $settingsLocationSource = $null
    if ($null -ne $settingsPath) {
        $settings = Get-Content -Raw -LiteralPath $settingsPath |
            ConvertFrom-Json
        $configuredProperties = @(
            $settings.PSObject.Properties |
                Where-Object {
                    $_.Name -in @("diskImageLocation", "DataFolder") -and
                    -not [string]::IsNullOrWhiteSpace([string]$_.Value)
                }
        )
        $configuredValues = @(
            $configuredProperties |
                ForEach-Object {
                    $expanded = [Environment]::ExpandEnvironmentVariables(
                        [string]$_.Value
                    )
                    if (-not [System.IO.Path]::IsPathRooted($expanded)) {
                        throw "the Docker data location is not absolute"
                    }
                    [System.IO.Path]::GetFullPath($expanded).TrimEnd("\")
                } |
                Sort-Object -Unique
        )
        if ($configuredValues.Count -gt 1) {
            throw "Docker settings contain conflicting data locations"
        }
        if ($configuredValues.Count -eq 1) {
            $configuredRoot = $configuredValues[0]
            $settingsLocationSource = if ($settingsPath -eq $settingsStore) {
                "docker-settings-store"
            }
            else {
                "docker-legacy-settings"
            }
        }
    }

    $settingsCandidates = @()
    if ($null -ne $configuredRoot) {
        if (-not [System.IO.Path]::IsPathRooted($configuredRoot)) {
            throw "the Docker data location is not absolute"
        }
        if ([System.IO.Path]::GetExtension($configuredRoot) -eq ".vhdx") {
            $settingsCandidates = @($configuredRoot)
        }
        else {
            $settingsCandidates = @(
                (Join-Path $configuredRoot "docker_data.vhdx"),
                (Join-Path $configuredRoot "ext4.vhdx"),
                (Join-Path $configuredRoot "data\docker_data.vhdx"),
                (Join-Path $configuredRoot "data\ext4.vhdx"),
                (Join-Path $configuredRoot "disk\docker_data.vhdx"),
                (Join-Path $configuredRoot "disk\ext4.vhdx")
            )
        }
    }

    if ($null -ne $registrationCandidate) {
        if ($settingsCandidates.Count -gt 0) {
            $registeredFullPath = [System.IO.Path]::GetFullPath(
                $registrationCandidate
            )
            $settingsAgree = @(
                $settingsCandidates |
                    Where-Object {
                        [string]::Equals(
                            [System.IO.Path]::GetFullPath($_),
                            $registeredFullPath,
                            [System.StringComparison]::OrdinalIgnoreCase
                        )
                    }
            )
            if ($settingsAgree.Count -ne 1) {
                throw "Docker registration and settings contain conflicting data locations"
            }
        }
        $candidatePaths = @($registrationCandidate)
        $locationSource = $registrationSource
    }
    elseif ($settingsCandidates.Count -gt 0) {
        $candidatePaths = $settingsCandidates
        $locationSource = $settingsLocationSource
    }
    else {
        throw "Docker's active data location is not authoritatively configured"
    }

    $existing = @()
    foreach ($candidatePath in ($candidatePaths | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $candidatePath) {
            $item = Get-Item -Force -LiteralPath $candidatePath
            if ($item.PSIsContainer) {
                continue
            }
            if (
                ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
            ) {
                throw "the Docker data VHDX candidate is a reparse point"
            }
            $existing += $item
        }
    }
    if ($existing.Count -ne 1) {
        throw "expected exactly one Docker data VHDX; found $($existing.Count)"
    }
    return @($existing[0], $locationSource)
}

$resolved = Get-CanonicalDataVhd
$dataVhd = $resolved[0]
$locationSource = [string]$resolved[1]
$volumes = @(Get-Volume -FilePath $dataVhd.FullName)
if ($volumes.Count -ne 1) {
    throw "expected exactly one backing volume for the Docker data VHDX"
}
$volume = $volumes[0]
$operationalStatus = @(
    $volume.OperationalStatus | ForEach-Object { [string]$_ }
)
if (
    [string]$volume.HealthStatus -ne "Healthy" -or
    $operationalStatus -notcontains "OK"
) {
    throw "the Docker data VHDX backing volume is not healthy and operational"
}
if ([string]::IsNullOrWhiteSpace([string]$volume.UniqueId)) {
    throw "the Docker data VHDX backing volume has no unique identity"
}

$driveLetter = if ($null -eq $volume.DriveLetter) {
    $null
}
else {
    [string]$volume.DriveLetter
}
$sha256 = [System.Security.Cryptography.SHA256]::Create()
try {
    $probeStream = [System.IO.File]::OpenRead($PSCommandPath)
    try {
        $probeHashBytes = $sha256.ComputeHash($probeStream)
    }
    finally {
        $probeStream.Dispose()
    }
}
finally {
    $sha256.Dispose()
}
$probeHash = [System.BitConverter]::ToString($probeHashBytes).Replace("-", "").ToLowerInvariant()
$observation = [ordered]@{
    schema_version = 1
    probe = "powershell-get-volume-docker-data-vhdx-v1"
    probe_sha256 = $probeHash
    boundary = $Boundary
    observed_at = [DateTimeOffset]::UtcNow.ToString("o")
    location_source = $locationSource
    data_vhd_path = $dataVhd.FullName
    data_vhd_file_length_bytes = [int64]$dataVhd.Length
    backing_volume_unique_id = [string]$volume.UniqueId
    drive_letter = $driveLetter
    file_system = [string]$volume.FileSystem
    health_status = [string]$volume.HealthStatus
    operational_status = $operationalStatus
    total_bytes = [int64]$volume.Size
    available_bytes = [int64]$volume.SizeRemaining
}
$observation | ConvertTo-Json -Compress -Depth 4
