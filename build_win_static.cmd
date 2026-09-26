@echo off
rem Pure Go build - no CGO, no gcc, no MSYS2, no external FFmpeg libs needed
setlocal
cd /d "%~dp0"
if not exist bin mkdir bin
echo == building windows/amd64 (pure Go, CGO_ENABLED=0) ==
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64
go build -trimpath -ldflags="-s -w" -o bin\krushitel_windows_amd64.exe .
if errorlevel 1 (
    echo [!] build failed
    exit /b 1
)
echo [ok] bin\krushitel_windows_amd64.exe
endlocal
