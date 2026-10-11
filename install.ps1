# Install nodkey from the latest GitHub release.
#   irm https://raw.githubusercontent.com/peters/nodkey-cli/main/install.ps1 | iex
# While the repository is private, use the GitHub CLI (it must be logged in):
#   gh api repos/peters/nodkey-cli/contents/install.ps1 -H 'Accept: application/vnd.github.raw' | iex
# $env:NODKEY_INSTALL_DIR picks the folder. $env:NODKEY_VERSION picks a tag.
$ErrorActionPreference = 'Stop'
$repo = 'peters/nodkey-cli'
$dir = if ($env:NODKEY_INSTALL_DIR) { $env:NODKEY_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\nodkey' }
$version = if ($env:NODKEY_VERSION) { $env:NODKEY_VERSION } else { 'latest' }
$asset = 'nodkey-x86_64-pc-windows-msvc.zip'

# The GitHub CLI can read private repositories; plain web requests only public ones.
$useGh = $false
if (Get-Command gh -ErrorAction SilentlyContinue) {
    gh auth token *> $null
    $useGh = ($LASTEXITCODE -eq 0)
}
if ($version -eq 'latest') {
    # The newest release, pre-releases included; GitHub's "latest" link skips those.
    if ($useGh) {
        $version = gh api "repos/$repo/releases?per_page=1" --jq '.[0].tag_name'
    } else {
        $version = (Invoke-RestMethod "https://api.github.com/repos/$repo/releases?per_page=1")[0].tag_name
    }
    if (-not $version) { throw "no release found for $repo" }
}

$work = Join-Path ([IO.Path]::GetTempPath()) ("nodkey-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
try {
    Write-Host "nodkey: downloading $asset ($version)"
    if ($useGh) {
        gh release download $version --repo $repo --pattern $asset --pattern SHA256SUMS --dir $work
        if ($LASTEXITCODE -ne 0) { throw "download failed" }
    } else {
        $base = "https://github.com/$repo/releases/download/$version"
        Invoke-WebRequest "$base/$asset" -OutFile (Join-Path $work $asset)
        Invoke-WebRequest "$base/SHA256SUMS" -OutFile (Join-Path $work 'SHA256SUMS')
    }
    $line = Get-Content (Join-Path $work 'SHA256SUMS') | Where-Object { $_ -match " $([regex]::Escape($asset))$" }
    $expected = ($line -split ' ')[0]
    $actual = (Get-FileHash (Join-Path $work $asset) -Algorithm SHA256).Hash.ToLower()
    if (-not $expected -or $expected -ne $actual) { throw "checksum mismatch for $asset" }
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Expand-Archive (Join-Path $work $asset) -DestinationPath $dir -Force
} finally {
    Remove-Item -Recurse -Force $work
}
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not ($userPath -split ';' -contains $dir)) {
    [Environment]::SetEnvironmentVariable('Path', "$dir;$userPath", 'User')
    Write-Host "nodkey: added $dir to your user PATH; open a new terminal"
}
Write-Host "nodkey: installed $(& (Join-Path $dir 'nodkey.exe') --version)"
Write-Host "nodkey: next, run 'nodkey setup' to add Nodkey to your coding agents, and 'nodkey pair' for the terminal"
