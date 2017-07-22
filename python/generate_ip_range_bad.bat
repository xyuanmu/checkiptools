@echo off & title generate ip range bad & cd /d %~dp0
:do
"%~dp0python27.exe" "%~dp0generate_ip_range_bad.py"
pause