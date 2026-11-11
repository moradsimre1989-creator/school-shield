#Requires -RunAsAdministrator
<#
.SYNOPSIS
  مثبّت درع المدرسة - School Shield
.DESCRIPTION
  يثبّت الحماية كاملة على جهاز طالب واحد:
    1. نسخ ملفات البرنامج إلى Program Files
    2. تهيئة مجلدات البيانات مع ACL يمنع الطالب من التعديل
    3. تثبيت عميل Cloudflare One مُدارًا مع قفل مفتاح الإيقاف
    4. تثبيت خدمة الحماية الدائمة وتشديدها
    5. فرض سياسات المتصفحات وقواعد جدار الحماية
    6. إنشاء حساب المدير (كلمة المرور تُدخل تفاعليًا ولا تُخزَّن كنص صريح)
    7. تشغيل الفحص الحقيقي وعرض النتيجة
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File installer\install.ps1 -Organization "my-school"
#>
[CmdletBinding()]
param(
  [string]$Organization = "",
  [string]$AdminUser = "admin",
  [string]$SupportUrl = "",
  [string]$WarpMsi = "",
  [switch]$SkipWarp,
  [switch]$SkipAdminAccount
)

$ErrorActionPreference = "Stop"
$InstallDir = Join-Path $env:ProgramFiles "SchoolShield"
$DataDir    = Join-Path $env:ProgramData "SchoolShield"
$SecureDir  = Join-Path $DataDir "secure"
$ServiceName = "SchoolShield"
$WarpGaUrl  = "https://downloads.cloudflareclient.com/v1/download/windows/ga"

function Step($text) { Write-Host "`n== $text" -ForegroundColor Cyan }
function Ok($text)   { Write-Host "   [تم] $text" -ForegroundColor Green }
function Warn($text) { Write-Host "   [تنبيه] $text" -ForegroundColor Yellow }

if (-not $Organization) {
  Write-Host ""
  Write-Host "ادخل اسم فريق المدرسة في Cloudflare Zero Trust" -ForegroundColor Cyan
  $Organization = (Read-Host "اسم الفريق").Trim()
  if (-not $Organization) { throw "اسم الفريق مطلوب" }
}

$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root "dist"
# في حزمة التوزيع تكون ملفات exe بجانب السكربت نفسه
if (-not (Test-Path (Join-Path $dist "SchoolShield.exe"))) { $dist = $PSScriptRoot }

# ------------------------------------------------------------------
Step "التحقق من الملفات المطلوبة"
foreach ($exe in @("SchoolShield.exe", "SchoolShieldService.exe", "schoolshield-admin.exe")) {
  if (-not (Test-Path (Join-Path $dist $exe))) {
    throw "الملف $exe غير موجود في $dist. شغّل build\build.ps1 أولًا."
  }
}
Ok "ملفات البناء موجودة"

# ------------------------------------------------------------------
Step "نسخ البرنامج إلى $InstallDir"
if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir | Out-Null }
Copy-Item (Join-Path $dist "*.exe") $InstallDir -Force
# البرنامج نفسه: الطالب يقرأ وينفّذ فقط، ولا يكتب
& icacls $InstallDir /inheritance:r | Out-Null
& icacls $InstallDir /grant:r "*S-1-5-18:(OI)(CI)F" /grant:r "*S-1-5-32-544:(OI)(CI)F" /grant:r "*S-1-5-32-545:(OI)(CI)RX" | Out-Null
Ok "نُسخت ملفات البرنامج وضُبطت صلاحياتها"

# ------------------------------------------------------------------
Step "تهيئة مجلدات البيانات"
foreach ($d in @($DataDir, $SecureDir, (Join-Path $DataDir "logs"))) {
  if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
}
& icacls $DataDir /inheritance:r | Out-Null
& icacls $DataDir /grant:r "*S-1-5-18:(OI)(CI)F" /grant:r "*S-1-5-32-544:(OI)(CI)F" /grant:r "*S-1-5-32-545:(OI)(CI)R" | Out-Null
& icacls $SecureDir /inheritance:r | Out-Null
& icacls $SecureDir /grant:r "*S-1-5-18:(OI)(CI)F" /grant:r "*S-1-5-32-544:(OI)(CI)F" | Out-Null
Ok "مجلد الأسرار محجوب عن حسابات الطلاب تمامًا"

# ------------------------------------------------------------------
Step "كتابة سياسة المدرسة"
$policyPath = Join-Path $DataDir "policy.json"
if (Test-Path $policyPath) {
  $policy = (Get-Content $policyPath -Raw) -replace "^﻿", "" | ConvertFrom-Json
} else {
  $policy = [pscustomobject]@{}
}
$policy | Add-Member -NotePropertyName organization -NotePropertyValue $Organization -Force
[System.IO.File]::WriteAllText($policyPath, ($policy | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding $false))
Ok "المؤسسة: $Organization"

# ------------------------------------------------------------------
if (-not $SkipWarp) {
  Step "تثبيت عميل Cloudflare One (الفلترة الفعلية)"
  $msi = $WarpMsi
  if (-not $msi) {
    $msi = Join-Path $env:TEMP "Cloudflare_WARP.msi"
    Write-Host "   تنزيل أحدث إصدار..."
    try {
      Invoke-WebRequest -Uri $WarpGaUrl -OutFile $msi -UseBasicParsing -TimeoutSec 600
    } catch {
      throw "فشل تنزيل عميل Cloudflare One. نزّله يدويًا ومرّره عبر -WarpMsi. السبب: $_"
    }
  }
  if (-not (Test-Path $msi)) { throw "ملف MSI غير موجود: $msi" }

  # المعاملات الرسمية: ORGANIZATION / SWITCH_LOCKED / ONBOARDING / SUPPORT_URL
  $args = @("/i", "`"$msi`"", "/qn", "/norestart",
            "ORGANIZATION=`"$Organization`"", "SWITCH_LOCKED=`"true`"",
            "ONBOARDING=`"false`"")
  if ($SupportUrl) { $args += "SUPPORT_URL=`"$SupportUrl`"" }
  $p = Start-Process msiexec.exe -ArgumentList $args -Wait -PassThru
  if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) {
    throw "فشل تثبيت عميل Cloudflare One (رمز $($p.ExitCode))"
  }
  Ok "ثُبّت العميل ومفتاح الإيقاف مقفول"
} else {
  Warn "تم تخطّي تثبيت عميل الفلترة - الحجب لن يعمل بدونه"
}

# ------------------------------------------------------------------
Step "كتابة إعدادات العميل المُدارة (mdm.xml)"
$cfDir = Join-Path $env:ProgramData "Cloudflare"
if (-not (Test-Path $cfDir)) { New-Item -ItemType Directory -Path $cfDir | Out-Null }
$supportLine = ""
if ($SupportUrl) { $supportLine = "  <key>support_url</key>`n  <string>$SupportUrl</string>`n" }
$mdm = @"
<?xml version="1.0" encoding="UTF-8"?>
<dict>
  <key>organization</key>
  <string>$Organization</string>
  <key>switch_locked</key>
  <true/>
  <key>auto_connect</key>
  <integer>1</integer>
  <key>service_mode</key>
  <string>warp</string>
  <key>onboarding</key>
  <false/>
$supportLine</dict>
"@
[System.IO.File]::WriteAllText((Join-Path $cfDir "mdm.xml"), $mdm, (New-Object System.Text.UTF8Encoding $false))
& icacls $cfDir /inheritance:r | Out-Null
& icacls $cfDir /grant:r "*S-1-5-18:(OI)(CI)F" /grant:r "*S-1-5-32-544:(OI)(CI)F" /grant:r "*S-1-5-32-545:(OI)(CI)R" | Out-Null
Ok "switch_locked=true و auto_connect=1 - الطالب لا يستطيع إطفاء العميل"

# ------------------------------------------------------------------
Step "تثبيت خدمة الحماية الدائمة"
$svcExe = Join-Path $InstallDir "SchoolShieldService.exe"
& sc.exe stop $ServiceName 2>$null | Out-Null
& sc.exe delete $ServiceName 2>$null | Out-Null
Start-Sleep -Seconds 2
& sc.exe create $ServiceName binPath= "`"$svcExe`"" start= auto DisplayName= "School Shield Protection Service" | Out-Null
& sc.exe description $ServiceName "يفرض سياسات التصفح الآمن لحواسيب الطلاب ويمنع تعطيل الحماية من الحسابات العادية" | Out-Null
# إعادة تشغيل تلقائية إن قُتلت الخدمة
& sc.exe failure $ServiceName reset= 0 actions= restart/5000/restart/5000/restart/60000 | Out-Null
# منع الحسابات العادية من الإيقاف (DT) أو التعديل (WP)
$sddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWLOCRRC;;;BU)"
& sc.exe sdset $ServiceName $sddl | Out-Null
& sc.exe start $ServiceName | Out-Null
Start-Sleep -Seconds 3
$state = (& sc.exe query $ServiceName) -join " "
if ($state -match "RUNNING") { Ok "الخدمة تعمل ومحميّة من الإيقاف" } else { Warn "الخدمة لم تبدأ - راجع $DataDir\logs" }

# ------------------------------------------------------------------
Step "فرض سياسات المتصفحات وقواعد الشبكة"
& (Join-Path $InstallDir "schoolshield-admin.exe") enforce | Out-Null
Ok "SafeSearch و YouTube المقيّد و تعطيل DoH وقواعد جدار الحماية"

# ------------------------------------------------------------------
Step "اختصارات البرنامج"
$ws = New-Object -ComObject WScript.Shell
foreach ($target in @(
  (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\درع المدرسة.lnk"),
  (Join-Path $env:PUBLIC "Desktop\درع المدرسة.lnk"))) {
  try {
    $lnk = $ws.CreateShortcut($target)
    $lnk.TargetPath = Join-Path $InstallDir "SchoolShield.exe"
    $lnk.Description = "درع المدرسة - تصفّح آمن"
    $lnk.Save()
  } catch { Warn "تعذّر إنشاء اختصار: $target" }
}
Ok "أُنشئت الاختصارات"

# ------------------------------------------------------------------
if (-not $SkipAdminAccount) {
  Step "إنشاء حساب المدير"
  $adminFile = Join-Path $SecureDir "admin.json"
  if (Test-Path $adminFile) {
    Warn "حساب المدير موجود مسبقًا - لم يُعدّل"
  } else {
    Write-Host "   أدخل كلمة المرور الأولية للمستخدم '$AdminUser'."
    Write-Host "   لن تُخزَّن كنص صريح، وسيُطلب تغييرها عند أول دخول." -ForegroundColor Yellow
    & (Join-Path $InstallDir "schoolshield-admin.exe") provision --username $AdminUser
    if ($LASTEXITCODE -ne 0) { Warn "لم يكتمل إنشاء الحساب - نفّذه لاحقًا: schoolshield-admin provision" }
    else { Ok "أُنشئ حساب المدير $AdminUser" }
  }
}

# ------------------------------------------------------------------
Step "الفحص النهائي"
& (Join-Path $InstallDir "schoolshield-admin.exe") verify
$verifyCode = $LASTEXITCODE

Write-Host ""
if ($verifyCode -eq 0) {
  Write-Host "النتيجة: الحماية مفعّلة والفحوص ناجحة." -ForegroundColor Green
} else {
  Write-Host "النتيجة: الحماية غير مكتملة. راجع البنود الفاشلة أعلاه." -ForegroundColor Red
  Write-Host "الأسباب الشائعة:" -ForegroundColor Yellow
  Write-Host "  - لم تُطبَّق سياسات Gateway في لوحة Cloudflare Zero Trust بعد"
  Write-Host "  - الجهاز لم يُسجَّل بعد (افتح عميل Cloudflare One مرة واحدة)"
  Write-Host "  - حساب الطالب ما زال عضوًا في مجموعة Administrators"
  Write-Host "  - Device Management Protection غير مفعّلة في بروفايل الجهاز بلوحة Cloudflare"
}
Write-Host ""
Write-Host "الاختبار الإلزامي قبل التوزيع: سجّل الدخول بحساب طالب عادي وحاول إيقاف الحماية." -ForegroundColor Yellow
exit $verifyCode
