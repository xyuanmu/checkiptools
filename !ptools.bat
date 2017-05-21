@echo off & title checkiptools
cd /d %~dp0
:do
"%~dp0python/python27.exe" "%~dp0python/iptools.py"
pause
call :do