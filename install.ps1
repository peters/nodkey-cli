# Install nodkey from the latest GitHub release.
#   irm https://raw.githubusercontent.com/peters/nodkey-cli/main/install.ps1 | iex
# $env:NODKEY_INSTALL_DIR picks the folder. $env:NODKEY_VERSION picks a tag.
# The archive must match SHA256SUMS. With a logged-in GitHub CLI, its build provenance must also
# show that the release workflow of this repository built it (gh attestation verify).
$ErrorActionPreference = 'Stop'
$repo = 'peters/nodkey-cli'
$dir = if ($env:NODKEY_INSTALL_DIR) { $env:NODKEY_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\nodkey' }
$version = if ($env:NODKEY_VERSION) { $env:NODKEY_VERSION } else { 'latest' }
$asset = 'nodkey-x86_64-pc-windows-msvc.zip'

# A logged-in GitHub CLI avoids the API's limit on anonymous calls; plain web requests work too.
$useGh = $false
if (Get-Command gh -ErrorAction SilentlyContinue) {
    gh auth token *> $null
    $useGh = ($LASTEXITCODE -eq 0)
}
if ($version -eq 'latest') {
    # The newest stable release; while there is none, the newest pre-release. Drafts never.
    if ($useGh) {
        $version = gh api "repos/$repo/releases?per_page=30" `
            --jq '[.[] | select(.draft | not)] | (map(select(.prerelease | not)) + .)[0].tag_name // empty'
    } else {
        # A variable, so that the array of releases goes down the pipeline one by one.
        $all = Invoke-RestMethod "https://api.github.com/repos/$repo/releases?per_page=30"
        $releases = @($all | Where-Object { -not $_.draft })
        $pick = @($releases | Where-Object { -not $_.prerelease }) + @($releases) | Select-Object -First 1
        $version = if ($pick) { $pick.tag_name } else { $null }
    }
    if (-not $version) { throw "no release found for $repo" }
}
# gh attestation needs a GitHub CLI from 2024 or later.
$canVerify = $false
if ($useGh) {
    try {
        gh attestation --help *> $null
        $canVerify = ($LASTEXITCODE -eq 0)
    } catch {
        $canVerify = $false
    }
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
    # SHA256SUMS comes from the same release, so it finds damage, not a replaced release. Build
    # provenance does: the release workflow of this repository signs it at build time.
    if ($canVerify) {
        gh attestation verify (Join-Path $work $asset) --repo $repo | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "$asset has no valid build provenance from $repo; nothing was installed" }
        Write-Host "nodkey: checked the checksum and the build provenance (gh attestation verify)"
    } else {
        Write-Host "nodkey: checked the checksum; with a logged-in GitHub CLI (gh) the build provenance is checked too"
    }
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
