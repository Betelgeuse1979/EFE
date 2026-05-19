# EFE Windows Packaging Prototype

This folder contains a developer packaging prototype for the EFE PySide6 GUI.

This is not an installer, not code signed, not auto-updating, and not a production release process. EFE remains an MVP and has not been independently audited.

## Scope

The v0.9 packaging prototype builds the GUI only. The CLI remains available from source:

```powershell
python -m app.main ...
```

A separate CLI executable can be considered later.

## Prerequisites

- Windows
- Python 3.12 available as `py -3.12`
- PowerShell
- Network access for `pip install`, unless dependencies are already cached

## Build Command

From the repository root:

```powershell
.\packaging\build_windows_gui.ps1
```

The script creates `.venv` if needed, installs `requirements-dev.txt`, runs the unit tests, removes previous PyInstaller `build/`, `dist/`, and generated `EFE.spec` artifacts, then runs a one-folder PyInstaller GUI build.

## Expected Output

```text
dist/
  EFE/
    EFE.exe
    ...
```

Launch the packaged GUI with:

```powershell
.\dist\EFE\EFE.exe
```

## Runtime User Data

The packaged GUI uses the same runtime data logic as source runs. On Windows, keys, encrypted/decrypted output folders, and the SQLite database are stored under:

```text
%LOCALAPPDATA%\EFE\
```

The app should not write keys or databases into the PyInstaller `dist/` folder.

`EFE_DATA_DIR` can override the data directory for development and testing, but normal users should not need to set it.

## Generated Artifacts

PyInstaller output is intentionally not tracked:

- `build/`
- `dist/`
- generated `*.spec` files

## Known Limitations

- GUI package only.
- No installer yet.
- No code signing yet.
- No auto-update.
- No Outlook/Gmail integration.
- No cloud sync.
- No QR scanning or webcam support.
- EFE is still an MVP and has not been independently audited.
