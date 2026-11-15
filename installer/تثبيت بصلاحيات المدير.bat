@echo off
chcp 65001 >nul
cd /d "%~dp0"
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
set "APP="
for %%f in ("%~dp0*.exe") do set "APP=%%~ff"
if not defined APP (
  echo لم يُعثر على ملف البرنامج بجانب هذا الملف.
  pause
  exit /b 1
)
echo تشغيل التثبيت: "%APP%"
"%APP%" --setup
echo.
echo انتهى. أغلق هذه النافذة وافتح البرنامج.
pause
