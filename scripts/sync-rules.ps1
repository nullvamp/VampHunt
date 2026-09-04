param([switch]$Force)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$rulesRoot = Join-Path $projectRoot 'rules'
$cacheRoot = Join-Path $rulesRoot 'cache'
$activeRoot = Join-Path $rulesRoot 'active'
$headers = @{ 'User-Agent' = 'VampHunt rule updater'; 'Accept' = 'application/vnd.github+json' }

New-Item -ItemType Directory -Force -Path $cacheRoot, $activeRoot | Out-Null

function Reset-ActiveDirectory {
    param([string]$Path)
    $resolvedActive = [IO.Path]::GetFullPath($activeRoot).TrimEnd('\') + '\'
    $resolvedTarget = [IO.Path]::GetFullPath($Path)
    if (-not $resolvedTarget.StartsWith($resolvedActive, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to replace a directory outside the active rules folder: $resolvedTarget"
    }
    if (Test-Path -LiteralPath $resolvedTarget) {
        [IO.Directory]::Delete("\\?\$resolvedTarget", $true)
    }
    New-Item -ItemType Directory -Force -Path $resolvedTarget | Out-Null
}

function Remove-ActivePath {
    param([string]$Path)
    $resolvedActive = [IO.Path]::GetFullPath($activeRoot).TrimEnd('\') + '\'
    $resolvedTarget = [IO.Path]::GetFullPath($Path)
    if (-not $resolvedTarget.StartsWith($resolvedActive, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a path outside the active rules folder: $resolvedTarget"
    }
    if (Test-Path -LiteralPath $resolvedTarget) {
        $item = Get-Item -LiteralPath $resolvedTarget
        if ($item.PSIsContainer) {
            [IO.Directory]::Delete("\\?\$resolvedTarget", $true)
        } else {
            [IO.File]::Delete("\\?\$resolvedTarget")
        }
    }
}

function Expand-ZipArchive {
    param([string]$Archive, [string]$Destination)
    & tar.exe -xf $Archive -C $Destination
    if ($LASTEXITCODE -ne 0) {
        throw "Could not extract $Archive"
    }
}

function Keep-SourceContent {
    param([string]$DestinationName, [string[]]$Names, [string]$RequiredDirectory)
    $destination = Join-Path $activeRoot $DestinationName
    $sourceRoot = if (Test-Path -LiteralPath (Join-Path $destination $RequiredDirectory)) {
        $destination
    } else {
        Get-ChildItem -LiteralPath $destination -Directory |
            Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName $RequiredDirectory) } |
            Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $sourceRoot) { throw "$DestinationName does not contain $RequiredDirectory" }
    $staging = Join-Path $activeRoot "_staging-$DestinationName"
    Reset-ActiveDirectory $staging
    foreach ($name in $Names) {
        $item = Join-Path $sourceRoot $name
        if (Test-Path -LiteralPath $item) {
            if ((Get-Item -LiteralPath $item).PSIsContainer) {
                $itemDestination = Join-Path $staging $name
                New-Item -ItemType Directory -Force -Path $itemDestination | Out-Null
                & robocopy.exe $item $itemDestination /E /R:1 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null
                if ($LASTEXITCODE -ge 8) { throw "Could not stage $item" }
            } else {
                Copy-Item -LiteralPath $item -Destination $staging -Force
            }
        }
    }
    Reset-ActiveDirectory $destination
    & robocopy.exe $staging $destination /E /R:1 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "Could not install the trimmed $DestinationName content" }
    Remove-ActivePath $staging
}

function Install-ReleaseAsset {
    param([string]$Repository, [string]$AssetName, [string]$DestinationName)
    $release = Invoke-RestMethod -Headers $headers "https://api.github.com/repos/$Repository/releases/latest"
    $asset = $release.assets | Where-Object name -eq $AssetName | Select-Object -First 1
    if (-not $asset) { throw "Release $($release.tag_name) does not contain $AssetName" }
    $archive = Join-Path $cacheRoot "$DestinationName-$($release.tag_name).zip"
    if ($Force -or -not (Test-Path -LiteralPath $archive)) {
        Invoke-WebRequest -Headers $headers -Uri $asset.browser_download_url -OutFile $archive
    }
    $destination = Join-Path $activeRoot $DestinationName
    Reset-ActiveDirectory $destination
    Expand-ZipArchive $archive $destination
    [pscustomobject]@{
        name = $DestinationName
        repository = "https://github.com/$Repository"
        release = $release.tag_name
        asset = $AssetName
        url = $asset.browser_download_url
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
    }
}

function Install-ReleaseAssetPattern {
    param([string]$Repository, [string]$AssetPattern, [string]$DestinationName)
    $release = Invoke-RestMethod -Headers $headers "https://api.github.com/repos/$Repository/releases/latest"
    $asset = $release.assets | Where-Object name -Match $AssetPattern | Select-Object -First 1
    if (-not $asset) { throw "Release $($release.tag_name) contains no asset matching $AssetPattern" }
    $archive = Join-Path $cacheRoot "$DestinationName-$($release.tag_name).zip"
    if ($Force -or -not (Test-Path -LiteralPath $archive)) {
        Invoke-WebRequest -Headers $headers -Uri $asset.browser_download_url -OutFile $archive
    }
    $destination = Join-Path $activeRoot $DestinationName
    Reset-ActiveDirectory $destination
    Expand-ZipArchive $archive $destination
    [pscustomobject]@{
        name = $DestinationName
        repository = "https://github.com/$Repository"
        release = $release.tag_name
        asset = $asset.name
        url = $asset.browser_download_url
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
    }
}

function Install-SourceArchive {
    param([string]$Repository, [string]$DestinationName)
    $commit = Invoke-RestMethod -Headers $headers "https://api.github.com/repos/$Repository/commits/HEAD"
    $archive = Join-Path $cacheRoot "$DestinationName-$($commit.sha).zip"
    $url = "https://github.com/$Repository/archive/$($commit.sha).zip"
    if ($Force -or -not (Test-Path -LiteralPath $archive)) {
        Invoke-WebRequest -Headers $headers -Uri $url -OutFile $archive
    }
    $destination = Join-Path $activeRoot $DestinationName
    Reset-ActiveDirectory $destination
    Expand-ZipArchive $archive $destination
    [pscustomobject]@{
        name = $DestinationName
        repository = "https://github.com/$Repository"
        release = $commit.sha
        asset = 'source archive'
        url = $url
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
    }
}

function Install-YaraX {
    $release = Invoke-RestMethod -Headers $headers 'https://api.github.com/repos/VirusTotal/yara-x/releases/latest'
    $asset = $release.assets | Where-Object name -Match 'yara-x-v.*-x86_64-pc-windows-msvc\.zip$' | Select-Object -First 1
    if (-not $asset) { throw 'The current YARA-X release has no Windows x64 command-line archive.' }
    $archive = Join-Path $cacheRoot "yara-x-$($release.tag_name)-windows-x64.zip"
    if ($Force -or -not (Test-Path -LiteralPath $archive)) {
        Invoke-WebRequest -Headers $headers -Uri $asset.browser_download_url -OutFile $archive
    }
    $destination = Join-Path $activeRoot 'yara-x'
    Reset-ActiveDirectory $destination
    Expand-ZipArchive $archive $destination
    [pscustomobject]@{
        name = 'yara-x-engine'
        repository = 'https://github.com/VirusTotal/yara-x'
        release = $release.tag_name
        asset = $asset.name
        url = $asset.browser_download_url
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
    }
}

$sources = @(
    Install-ReleaseAsset 'SigmaHQ/sigma' 'sigma_core.zip' 'sigma-core'
    Install-ReleaseAsset 'YARAHQ/yara-forge' 'yara-forge-rules-core.zip' 'yara-core'
    Install-YaraX
    Install-ReleaseAssetPattern 'Yamato-Security/hayabusa' '^hayabusa-.*-win-x64\.zip$' 'hayabusa-engine'
    Install-SourceArchive 'Yamato-Security/hayabusa-rules' 'hayabusa-rules'
    Install-ReleaseAsset 'WithSecureLabs/chainsaw' 'chainsaw_x86_64-pc-windows-msvc.zip' 'chainsaw-engine'
    Install-SourceArchive 'WithSecureLabs/chainsaw' 'chainsaw-rules'
)

# The Hayabusa binary archive includes a second rule checkout. The separately
# pinned rule source above is the only copy used by VampHunt.
Remove-ActivePath (Join-Path $activeRoot 'hayabusa-engine\rules')
Keep-SourceContent 'hayabusa-rules' @('config', 'hayabusa', 'sigma', 'LICENSE.md', 'README.md') 'sigma'
Keep-SourceContent 'chainsaw-rules' @('rules', 'LICENCE', 'README.md') 'rules'
$manifest = [ordered]@{
    schema = 1
    installed_utc = [DateTime]::UtcNow.ToString('o')
    policy = 'Pinned community sources; medium and higher matches require analyst review.'
    sources = $sources
}
$manifestJson = $manifest | ConvertTo-Json -Depth 6
[IO.File]::WriteAllText((Join-Path $rulesRoot 'manifest.json'), $manifestJson, [Text.UTF8Encoding]::new($false))
$sources | Format-Table name, release, sha256
