@echo off
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath powershell -Verb RunAs -ArgumentList @('-NoExit','-ExecutionPolicy','Bypass','-File','%~dp0install.ps1')"
