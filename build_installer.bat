@echo off
echo ========================================
echo Building PkgToolBox Installer
echo ========================================

:: Verifica se Inno Setup è installato
if not exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" (
    if not exist "C:\Program Files\Inno Setup 6\ISCC.exe" (
        echo ERRORE: Inno Setup 6 non trovato!
        echo Scarica e installa Inno Setup da: https://jrsoftware.org/isdl.php
        pause
        exit /b 1
    )
    set "ISCC=C:\Program Files\Inno Setup 6\ISCC.exe"
) else (
    set "ISCC=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
)

:: Verifica se esiste la build PyInstaller
if not exist "dist\PkgToolBox\PkgToolBox.exe" (
    echo ERRORE: Build PyInstaller non trovata!
    echo Esegui prima: py -m PyInstaller PkgToolBox.spec
    pause
    exit /b 1
)

:: Crea la directory di output se non esiste
if not exist "installer_output" mkdir installer_output

:: Compila l'installer
echo Compilazione installer in corso...
"%ISCC%" "PkgToolBox.iss"

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo Installer creato con successo!
    echo File: installer_output\PkgToolBox_Setup.exe
    echo ========================================
) else (
    echo.
    echo ========================================
    echo ERRORE durante la compilazione!
    echo ========================================
)

pause