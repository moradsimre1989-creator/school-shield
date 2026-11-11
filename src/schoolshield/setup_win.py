"""تثبيت ذاتي: ملف واحد يثبّت نفسه ويضبط كل الحماية.

يعمل داخل عملية مُرقّاة (يطلبها البرنامج من المستخدم عبر UAC)، وينفّذ
نفس خطوات مثبّت PowerShell بلا سكربتات خارجية:
  نسخ البرنامج ← ضبط ACL ← عميل الفلترة المُدار ← الخدمة الدائمة ← فرض السياسات
"""
from __future__ import annotations

import os
import shutil
import sys
import urllib.request
from pathlib import Path
from typing import Callable

from . import SERVICE_DISPLAY, SERVICE_NAME
from .config import load_policy, save_policy
from .paths import DATA_DIR, SECURE_DIR, ensure_dirs
from .winutil import is_elevated, lock_down_directory, log, run

WARP_GA_URL = "https://downloads.cloudflareclient.com/v1/download/windows/ga"
INSTALL_DIR = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "SchoolShield"
SERVICE_SDDL = (
    "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)"
    "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)"
    "(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWLOCRRC;;;BU)"
)

Progress = Callable[[str], None]


def _say(progress: Progress | None, text: str) -> None:
    log("setup: " + text)
    if progress:
        progress(text)


def self_path() -> Path:
    """مسار الملف الجاري تنفيذه (exe مجمّع أو مفسّر بايثون)."""
    return Path(sys.executable if getattr(sys, "frozen", False) else sys.argv[0])


def service_installed() -> bool:
    rc, _, _ = run(["sc.exe", "query", SERVICE_NAME])
    return rc == 0


def installed() -> bool:
    return (INSTALL_DIR / "SchoolShield.exe").exists() and service_installed()


def _copy_program(progress: Progress | None) -> Path:
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    target = INSTALL_DIR / "SchoolShield.exe"
    src = self_path()
    if src.resolve() != target.resolve():
        _say(progress, "نسخ البرنامج")
        shutil.copy2(src, target)
    # أدوات مساعدة إن وُجدت بجانب الملف
    for extra in ("schoolshield-admin.exe", "SchoolShieldService.exe"):
        candidate = src.parent / extra
        if candidate.exists():
            shutil.copy2(candidate, INSTALL_DIR / extra)
    run(["icacls", str(INSTALL_DIR), "/inheritance:r"])
    run(["icacls", str(INSTALL_DIR),
         "/grant:r", "*S-1-5-18:(OI)(CI)F",
         "/grant:r", "*S-1-5-32-544:(OI)(CI)F",
         "/grant:r", "*S-1-5-32-545:(OI)(CI)RX"])
    return target


def _prepare_data(organization: str, progress: Progress | None) -> None:
    _say(progress, "تهيئة ملفات الإعداد")
    ensure_dirs()
    policy = load_policy()
    policy["organization"] = organization
    save_policy(policy)
    lock_down_directory(str(DATA_DIR), allow_users_read=True)
    lock_down_directory(str(SECURE_DIR), allow_users_read=False)


def _install_client(organization: str, progress: Progress | None) -> str:
    """ينزّل عميل الفلترة ويثبّته مُدارًا مع قفل المفتاح."""
    from . import warp
    if not warp.installed():
        msi = Path(os.environ.get("TEMP", r"C:\Windows\Temp")) / "Cloudflare_WARP.msi"
        _say(progress, "تنزيل عميل الفلترة (قد يستغرق دقائق)")
        try:
            with urllib.request.urlopen(WARP_GA_URL, timeout=600) as response, \
                    msi.open("wb") as out:
                shutil.copyfileobj(response, out)
        except Exception as exc:
            return f"فشل تنزيل عميل الفلترة: {exc}"
        _say(progress, "تثبيت عميل الفلترة")
        rc, out, err = run([
            "msiexec", "/i", str(msi), "/qn", "/norestart",
            f'ORGANIZATION={organization}', "SWITCH_LOCKED=true", "ONBOARDING=false",
        ], timeout=900)
        if rc not in (0, 3010):
            return f"فشل تثبيت عميل الفلترة (رمز {rc}) {err or out}"
    _say(progress, "كتابة إعدادات العميل المُدارة")
    warp.write_mdm(organization, switch_locked=True, auto_connect=1,
                   service_mode="warp", onboarding=False)
    cf_dir = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Cloudflare"
    lock_down_directory(str(cf_dir), allow_users_read=True)
    return ""


def _install_service(exe: Path, progress: Progress | None) -> str:
    _say(progress, "تثبيت خدمة الحماية")
    run(["sc.exe", "stop", SERVICE_NAME])
    run(["sc.exe", "delete", SERVICE_NAME])
    rc, out, err = run([
        "sc.exe", "create", SERVICE_NAME,
        "binPath= " + f'"{exe}" --service',
        "start=", "auto", "DisplayName= " + SERVICE_DISPLAY,
    ])
    if rc != 0:
        return f"تعذّر إنشاء الخدمة: {err or out}"
    run(["sc.exe", "description", SERVICE_NAME,
         "يفرض سياسات التصفح الآمن لحواسيب الطلاب"])
    run(["sc.exe", "failure", SERVICE_NAME, "reset=", "0",
         "actions=", "restart/5000/restart/5000/restart/60000"])
    run(["sc.exe", "sdset", SERVICE_NAME, SERVICE_SDDL])
    rc, out, err = run(["sc.exe", "start", SERVICE_NAME], timeout=60)
    if rc != 0:
        return f"تعذّر تشغيل الخدمة: {err or out}"
    return ""


def _shortcuts(exe: Path) -> None:
    ps = (
        "$w = New-Object -ComObject WScript.Shell; "
        f"$l = $w.CreateShortcut('{os.environ.get('PUBLIC', r'C:\\Users\\Public')}"
        "\\Desktop\\درع المدرسة.lnk'); "
        f"$l.TargetPath = '{exe}'; $l.Save()"
    )
    run(["powershell", "-NoProfile", "-Command", ps], timeout=60)


def run_setup(organization: str, progress: Progress | None = None,
              disable_password: str = "") -> str:
    """ينفّذ التثبيت كاملًا. يرجع نصًّا فارغًا عند النجاح، أو سبب الفشل."""
    if not is_elevated():
        return "التثبيت يحتاج صلاحيات مدير Windows"
    if not organization:
        return "اسم مؤسسة المدرسة غير محدّد"
    try:
        exe = _copy_program(progress)
        _prepare_data(organization, progress)
        problem = _install_client(organization, progress)
        if problem:
            return problem
        problem = _install_service(exe, progress)
        if problem:
            return problem
        if disable_password:
            _say(progress, "ضبط كلمة مرور الإيقاف")
            from . import auth
            auth.provision_if_missing(disable_password)
        _say(progress, "فرض سياسات المتصفحات وقواعد الشبكة")
        from . import hardening
        hardening.enforce_all()
        _shortcuts(exe)
        _say(progress, "اكتمل التثبيت")
        return ""
    except Exception as exc:  # pragma: no cover
        log(f"setup فشل: {exc}")
        return str(exc)


def bundled_organization() -> str:
    """اسم الفريق من ملف school.cfg بجانب البرنامج، إن وُجد."""
    folders = [self_path().parent, INSTALL_DIR]
    bundled = getattr(sys, "_MEIPASS", None)
    if bundled:
        folders.insert(0, Path(bundled) / "schoolshield")
    for folder in folders:
        cfg = folder / "school.cfg"
        try:
            if cfg.exists():
                value = cfg.read_text(encoding="utf-8-sig").strip()
                if value:
                    return value
        except OSError:
            pass
    return str(load_policy().get("organization") or "")
