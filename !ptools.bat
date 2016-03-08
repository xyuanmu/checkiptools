@echo off & title checkiptools
:do
"%~dp0python/python27.exe" "%~dp0python/iptools.py"
pause
call :do