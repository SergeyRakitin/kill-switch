param(
    [string]$GoExe = 'D:\projects\github\tools\go\bin\go.exe',
    [string]$WindresExe = 'D:\projects\github\tools\mingw64\bin\windres.exe',
    [switch]$SkipInstall
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$originalLocation = Get-Location
$previousEnv = @{}
foreach ($name in @('GOPATH', 'GOMODCACHE', 'TEMP', 'TMP', 'CGO_ENABLED')) {
    $previousEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
try {
    Set-Location -LiteralPath $projectRoot
    $env:GOPATH = Join-Path $projectRoot 'temp/go-work'
    $env:GOMODCACHE = Join-Path $projectRoot 'temp/go-mod-cache'
    $env:TEMP = Join-Path $projectRoot 'temp/go-test-tmp'
    $env:TMP = $env:TEMP
    $env:CGO_ENABLED = '0'
    New-Item -ItemType Directory -Force $env:TEMP, (Join-Path $projectRoot 'dist') | Out-Null
    Set-Location -LiteralPath (Join-Path $projectRoot 'frontend')
    if (-not $SkipInstall) {
        npm ci
        if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
    }
    npm run build
    if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed' }
    Set-Location -LiteralPath (Join-Path $projectRoot 'cmd/guard-desktop')
    & $WindresExe -i app.rc -o app_windows_amd64.syso -O coff
    if ($LASTEXITCODE -ne 0) { throw 'Windows manifest compilation failed' }
    Set-Location -LiteralPath $projectRoot
    & $GoExe test ./internal/desktop ./internal/ui ./internal/diagnose
    if ($LASTEXITCODE -ne 0) { throw 'Desktop service tests failed' }
    & $GoExe build -trimpath -o 'dist/guard.exe' ./cmd/guard
    if ($LASTEXITCODE -ne 0) { throw 'Guard build failed' }
    & $GoExe build -trimpath -tags production -ldflags '-H windowsgui' -o 'dist/guard-desktop.exe' ./cmd/guard-desktop
    if ($LASTEXITCODE -ne 0) { throw 'Desktop build failed' }
    Write-Output (Join-Path $projectRoot 'dist/guard-desktop.exe')
} finally {
    Set-Location -LiteralPath $originalLocation.Path
    foreach ($name in $previousEnv.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previousEnv[$name], 'Process')
    }
}
