@echo off
REM ============================================================
REM SDL Timeline - Windows launcher
REM
REM Routes to:
REM   1. A bundled portable Python at .\python\python.exe (preferred)
REM   2. The system Python on PATH (fallback)
REM
REM No PyInstaller, no AV friction. The whole toolkit moves as a folder.
REM ============================================================

setlocal

REM Toolkit root = directory containing this .bat
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

REM Prefer bundled portable Python if present
set "PORTABLE_PY=%ROOT%\python\python.exe"
if exist "%PORTABLE_PY%" (
    set "PY=%PORTABLE_PY%"
) else (
    set "PY=python"
)

REM Tell cli.py where the toolkit root is so case folders land in the right place
set "SDL_TOOLKIT_ROOT=%ROOT%"

set "PYTHONIOENCODING=utf-8"

"%PY%" "%ROOT%\cli.py" %*
endlocal
