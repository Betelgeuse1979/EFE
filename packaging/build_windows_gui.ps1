Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path "app\gui\app.py")) {
    throw "Run this script from the EFE repository root."
}

$venvPython = ".\.venv\Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
    Write-Host "Creating local virtual environment in .venv..."
    py -3.12 -m venv .venv
}

Write-Host "Installing runtime and packaging dependencies..."
& $venvPython -m pip install --upgrade pip
& $venvPython -m pip install -r requirements-dev.txt

Write-Host "Running tests before packaging..."
& $venvPython -m unittest discover -s tests

Write-Host "Cleaning previous PyInstaller artifacts..."
if (Test-Path "build") {
    Remove-Item -Recurse -Force "build"
}
if (Test-Path "dist") {
    Remove-Item -Recurse -Force "dist"
}
if (Test-Path "EFE.spec") {
    Remove-Item -Force "EFE.spec"
}

Write-Host "Building EFE GUI one-folder package..."
& $venvPython -m PyInstaller `
    --noconfirm `
    --clean `
    --onedir `
    --windowed `
    --name EFE `
    packaging\efe_gui_launcher.py

Write-Host ""
Write-Host "Build complete."
Write-Host "Output folder: dist\EFE"
Write-Host "Launch: dist\EFE\EFE.exe"
Write-Host "Runtime user data remains under %LOCALAPPDATA%\EFE\ unless EFE_DATA_DIR is set."
