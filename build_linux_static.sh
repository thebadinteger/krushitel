#!/usr/bin/env bash
# ============================================================
# build_linux_static.sh — чистые Go-сборки krushitel для Linux
#
# Не требует CGO, GCC, Clang, Zig, Musl или внешнего FFmpeg.
# Декодеры H.264 и H.265 работают на чистом Go.
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p bin

echo "== linux/amd64 (pure Go, CGO_ENABLED=0) =="
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/krushitel_linux_amd64 .
echo "[ok] bin/krushitel_linux_amd64"

echo "== linux/arm64 (pure Go, CGO_ENABLED=0) =="
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o bin/krushitel_linux_arm64 .
echo "[ok] bin/krushitel_linux_arm64"

echo "============================================"
echo "[ok] Linux-бинарники собраны на чистом Go"
