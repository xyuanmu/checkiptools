@echo off & title pydig
cd /d %~dp0
:do
"%~dp0python/python27.exe" "%~dp0python/pydig.py"
pause
call :do