; درع المدرسة - School Shield
; مثبّت Inno Setup 6. البناء:
;   & "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\SchoolShield.iss
; المخرج: installer\Output\SchoolShield-Setup.exe
;
; المثبّت يطلب صلاحيات مدير Windows (PrivilegesRequired=admin). لا يمكن لأي
; متصفح تشغيله تلقائيًا بدون موافقة المستخدم على طلب UAC - وهذا سلوك Windows
; المقصود ولا نحاول تجاوزه.

#define AppName "درع المدرسة"
#define AppNameEn "School Shield"
#define AppVersion "1.0.0"
#define AppPublisher "School Shield"
#define OrgPlaceholder "REPLACE-WITH-YOUR-CLOUDFLARE-TEAM-NAME"

[Setup]
AppId={{A7E4C1B2-5D3F-4A91-9C7E-8F2B6D4E1A03}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\SchoolShield
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=Output
OutputBaseFilename=SchoolShield-Setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
; Windows 10 1809 وما فوق
MinVersion=10.0.17763
UninstallDisplayName={#AppName}
SetupLogging=yes

[Languages]
Name: "arabic"; MessagesFile: "compiler:Languages\Arabic.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "..\dist\SchoolShield.exe";        DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\SchoolShieldService.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\schoolshield-admin.exe";  DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md";                    DestDir: "{app}"; Flags: ignoreversion
Source: "..\docs\SETUP-CLOUDFLARE.md";     DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\docs\SECURITY.md";             DestDir: "{app}\docs"; Flags: ignoreversion
; ضع ملف MSI لعميل Cloudflare One بجانب المثبّت لتثبيت بلا إنترنت:
Source: "Cloudflare_WARP.msi"; DestDir: "{tmp}"; Flags: deleteafterinstall external skipifsourcedoesntexist

[Icons]
Name: "{group}\{#AppName}";        Filename: "{app}\SchoolShield.exe"
Name: "{commondesktop}\{#AppName}"; Filename: "{app}\SchoolShield.exe"

[Run]
; 1) تثبيت عميل الفلترة مُدارًا: المؤسسة + قفل المفتاح + بلا شاشات ترحيب
Filename: "msiexec.exe"; \
  Parameters: "/i ""{tmp}\Cloudflare_WARP.msi"" /qn /norestart ORGANIZATION=""{#OrgPlaceholder}"" SWITCH_LOCKED=""true"" ONBOARDING=""false"""; \
  StatusMsg: "تثبيت عميل الفلترة..."; Flags: waituntilterminated skipifdoesntexist

; 2) تثبيت خدمة الحماية وتشديدها
Filename: "{sys}\sc.exe"; Parameters: "create SchoolShield binPath= ""{app}\SchoolShieldService.exe"" start= auto DisplayName= ""School Shield Protection Service"""; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "failure SchoolShield reset= 0 actions= restart/5000/restart/5000/restart/60000"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "sdset SchoolShield D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWLOCRRC;;;BU)"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "start SchoolShield"; Flags: runhidden waituntilterminated

; 3) فرض السياسات + تشديد ACL وجدار الحماية
Filename: "{app}\schoolshield-admin.exe"; Parameters: "enforce"; StatusMsg: "فرض سياسات المدرسة..."; Flags: runhidden waituntilterminated

; 4) إنشاء حساب المدير (نافذة تفاعلية - كلمة المرور لا تُمرَّر في سطر الأوامر)
Filename: "{app}\schoolshield-admin.exe"; Parameters: "provision --username admin"; \
  StatusMsg: "إنشاء حساب المدير..."; Flags: waituntilterminated

; 5) فتح الواجهة لعرض نتيجة الفحص
Filename: "{app}\SchoolShield.exe"; Description: "فتح {#AppName}"; Flags: postinstall nowait skipifsilent

[UninstallRun]
; الإزالة تتطلب صلاحيات مدير Windows أصلًا (PrivilegesRequired=admin)
Filename: "{sys}\sc.exe"; Parameters: "stop SchoolShield"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "delete SchoolShield"; Flags: runhidden waituntilterminated

[Code]
procedure InitializeWizard();
begin
  if Pos('REPLACE-WITH', '{#OrgPlaceholder}') > 0 then
    MsgBox('تنبيه: لم تُضبط مؤسسة Cloudflare في ملف المثبّت.' + #13#10 +
           'عدّل OrgPlaceholder في SchoolShield.iss قبل التوزيع،' + #13#10 +
           'أو استخدم installer\install.ps1 -Organization "اسم-فريقك".',
           mbInformation, MB_OK);
end;
