# بناء ملفات exe لدرع المدرسة
# المتطلبات: python 3.11+ و pip install -r requirements.txt
# الاستخدام: powershell -ExecutionPolicy Bypass -File build\build.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "== تثبيت المتطلبات ==" -ForegroundColor Cyan
python -m pip install --quiet --disable-pip-version-check -r requirements.txt

$dist = Join-Path $root "dist"
$work = Join-Path $root "build\_work"
$common = @(
  "--noconfirm", "--clean", "--onefile",
  "--paths", "src",
  "--distpath", $dist,
  "--workpath", $work,
  "--specpath", (Join-Path $root "build")
)

Write-Host "== بناء الواجهة SchoolShield.exe ==" -ForegroundColor Cyan
python -m PyInstaller @common --windowed --name SchoolShield `
  --hidden-import arabic_reshaper --hidden-import bidi.algorithm `
  --hidden-import dns.resolver --hidden-import argon2 `
  build\entry_gui.py
if ($LASTEXITCODE -ne 0) { throw "فشل بناء الواجهة" }

Write-Host "== بناء الخدمة SchoolShieldService.exe ==" -ForegroundColor Cyan
python -m PyInstaller @common --console --name SchoolShieldService `
  --hidden-import win32timezone --hidden-import servicemanager `
  --hidden-import win32serviceutil --hidden-import win32service `
  --hidden-import dns.resolver --hidden-import argon2 `
  build\entry_service.py
if ($LASTEXITCODE -ne 0) { throw "فشل بناء الخدمة" }

Write-Host "== بناء أداة الإدارة schoolshield-admin.exe ==" -ForegroundColor Cyan
python -m PyInstaller @common --console --name schoolshield-admin `
  --hidden-import argon2 --hidden-import dns.resolver `
  build\entry_admin.py
if ($LASTEXITCODE -ne 0) { throw "فشل بناء أداة الإدارة" }

Write-Host ""
Write-Host "تمّ البناء في: $dist" -ForegroundColor Green
Get-ChildItem $dist -Filter *.exe | Format-Table Name, @{N='MB';E={[math]::Round($_.Length/1MB,1)}}
Write-Host ""
Write-Host "الخطوة التالية: بناء المثبّت" -ForegroundColor Yellow
Write-Host '  & "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\SchoolShield.iss'
Write-Host "أو التثبيت المباشر بدون Inno Setup:" -ForegroundColor Yellow
Write-Host '  powershell -ExecutionPolicy Bypass -File installer\install.ps1 -Organization "اسم-فريقك"'
