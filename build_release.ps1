# ============================================================
# build_release.ps1 — Сборка и упаковка всех релизных архивов
#
# 100% Pure Go: без CGO, без GCC/MSYS2, без внешнего FFmpeg.
# Собирает бинарники для Windows и Linux (amd64 / arm64)
# и пакует в .zip внутри директории release/
# ============================================================
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Set-Location $root

$binDir = Join-Path $root "bin"
$releaseDir = Join-Path $root "release"

# Версия — из единственного источника (update/update.go: CurrentVersion),
# руками тут ничего не правим. Схема релиза для апдейтера:
# тег vX.Y.Z + ассеты krushitel_X.Y.Z_<os>_<arch>.zip
$src = Get-Content (Join-Path $root "update\update.go") -Raw
$version = ([regex]::Match($src, 'CurrentVersion\s*=\s*"([^"]+)"')).Groups[1].Value
if (-not $version) { throw "не нашёл CurrentVersion в update/update.go" }

if (-not (Test-Path $binDir)) { New-Item -ItemType Directory -Path $binDir | Out-Null }
if (-not (Test-Path $releaseDir)) { New-Item -ItemType Directory -Path $releaseDir | Out-Null }

$targets = @(
    @{ OS = "windows"; Arch = "amd64"; Exe = "krushitel_windows_amd64.exe"; Zip = "krushitel_${version}_windows_amd64.zip" },
    @{ OS = "windows"; Arch = "arm64"; Exe = "krushitel_windows_arm64.exe"; Zip = "krushitel_${version}_windows_arm64.zip" },
    @{ OS = "linux";   Arch = "amd64"; Exe = "krushitel_linux_amd64";       Zip = "krushitel_${version}_linux_amd64.zip" },
    @{ OS = "linux";   Arch = "arm64"; Exe = "krushitel_linux_arm64";       Zip = "krushitel_${version}_linux_arm64.zip" }
)

Write-Host "`n=== Сборка и упаковка релизов krushitel v$version ===" -ForegroundColor Cyan

foreach ($t in $targets) {
    $exePath = Join-Path $binDir $t.Exe
    $zipPath = Join-Path $releaseDir $t.Zip

    Write-Host "[1/2] Компиляция $($t.OS)/$($t.Arch) -> $($t.Exe)..." -ForegroundColor Yellow
    $env:CGO_ENABLED = "0"
    $env:GOOS = $t.OS
    $env:GOARCH = $t.Arch

    go build -trimpath -ldflags="-s -w" -o $exePath .
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Ошибка компиляции $($t.OS)/$($t.Arch)"
        exit 1
    }

    $sizeMb = [math]::Round((Get-Item $exePath).Length / 1MB, 2)
    Write-Host "      Бинарник готов: $($t.Exe) ($sizeMb MB)" -ForegroundColor Green

    Write-Host "[2/2] Упаковка в $($t.Zip)..." -ForegroundColor Yellow
    if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
    Compress-Archive -Path $exePath -DestinationPath $zipPath -CompressionLevel Optimal

    $zipMb = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
    Write-Host "      Архив создан: $($t.Zip) ($zipMb MB)`n" -ForegroundColor Green
}

# Копирование в корневой krushitel.exe если не занят процессом
$rootExe = Join-Path $root "krushitel.exe"
$srcExe = Join-Path $binDir "krushitel_windows_amd64.exe"
try {
    Copy-Item -Path $srcExe -Destination $rootExe -Force -ErrorAction Stop
    Write-Host "[ok] Обновлен корневой krushitel.exe" -ForegroundColor Green
} catch {
    Write-Host "[i] Корневой krushitel.exe запущен в другой сессии (файл заблокирован)" -ForegroundColor Gray
}

Write-Host "=== Все архивы успешно упакованы в release/ ===`n" -ForegroundColor Cyan
