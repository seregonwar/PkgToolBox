@echo off
echo Pulizia delle cartelle __pycache__ in corso...

:: Elimina tutte le cartelle __pycache__ ricorsivamente
FOR /d /r . %%d in (__pycache__) DO @IF EXIST "%%d" rd /s /q "%%d"

:: Elimina anche tutti i file .pyc
del /s /q *.pyc 2>nul

echo Pulizia completata!
pause 