@echo off & title pydig
:do
"%~dp0python/python27.exe" "%~dp0python/pydig.py"
pause
call :do