@echo off
REM SocradarBot launcher (Windows)
setlocal
cd /d "%~dp0"

if not exist "config.yaml" (
  echo [init] creating config.yaml from example ...
  copy /y "config.example.yaml" "config.yaml" >nul
)
if not exist "web\dist\index.html" (
  echo [warn] web\dist not found, running in API-only mode.
)

echo SocradarBot starting at http://127.0.0.1:8100
start "" "http://127.0.0.1:8100"
socradarbot.exe -addr 127.0.0.1:8100 -web web\dist
