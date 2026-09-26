@echo off
"%NETBRIDGE_E2E_PYTHON%" "%~dp0az.py" %*
exit /b %ERRORLEVEL%
