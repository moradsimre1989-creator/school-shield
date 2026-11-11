#Requires -RunAsAdministrator
<#
  درع المدرسة - تثبيت بأمر واحد
  irm https://raw.githubusercontent.com/moradsimre1989-creator/school-shield/main/installer/web-install.ps1 | iex
#>

$ErrorActionPreference = "Stop"
$ExeUrl = "https://github.com/moradsimre1989-creator/school-shield/releases/download/v2.0/SchoolShield.exe"
$InstallDir = Join-Path $env:ProgramFiles "SchoolShield"
$Exe = Join-Path $InstallDir "SchoolShield.exe"

Write-Host ""
Write-Host "  درع المدرسة" -ForegroundColor Cyan
Write-Host "  ------------" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir | Out-Null }

Write-Host "  [1/3] تنزيل البرنامج..." -ForegroundColor Yellow
try {
  $ProgressPreference = "SilentlyContinue"
  Invoke-WebRequest -Uri $ExeUrl -OutFile $Exe -UseBasicParsing -TimeoutSec 900
} catch {
  Write-Host "  فشل التنزيل: $_" -ForegroundColor Red
  Write-Host "  تأكد من الاتصال بالإنترنت وأعد المحاولة." -ForegroundColor Red
  Read-Host "  اضغط Enter للإغلاق"
  exit 1
}
Unblock-File $Exe
Write-Host "  تم." -ForegroundColor Green

Write-Host "  [2/3] تثبيت الحماية (قد يستغرق بضع دقائق)..." -ForegroundColor Yellow
$p = Start-Process -FilePath $Exe -ArgumentList "--setup" -Wait -PassThru
if ($p.ExitCode -ne 0) {
  Write-Host "  لم يكتمل التثبيت. راجع $env:ProgramData\SchoolShield\logs" -ForegroundColor Red
} else {
  Write-Host "  تم." -ForegroundColor Green
}

Write-Host "  [3/3] إنشاء الاختصار وفتح البرنامج..." -ForegroundColor Yellow
try {
  $ws = New-Object -ComObject WScript.Shell
  $lnk = $ws.CreateShortcut((Join-Path $env:PUBLIC "Desktop\درع المدرسة.lnk"))
  $lnk.TargetPath = $Exe
  $lnk.Save()
} catch { }
Start-Process $Exe

Write-Host ""
Write-Host "  خلص. افتح درع المدرسة من سطح المكتب واضغط (تفعيل الحماية)." -ForegroundColor Green
Write-Host "  سيُطلب تسجيل دخول بإيميل المدرسة مرة واحدة على هذا الجهاز." -ForegroundColor Green
Write-Host ""
