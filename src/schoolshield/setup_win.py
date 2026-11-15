"""تثبيت ذاتي: ملف واحد يثبّت نفسه ويضبط كل الحماية.

يعمل داخل عملية مُرقّاة (يطلبها البرنامج من المستخدم عبر UAC)، وينفّذ
نفس خطوات مثبّت PowerShell بلا سكربتات خارجية:
  نسخ البرنامج ← ضبط ACL ← عميل الفلترة المُدار ← الخدمة الدائمة ← فرض السياسات
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import time
import urllib.request
from pathlib import Path
from typing import Callable

from . import SERVICE_DISPLAY, SERVICE_NAME
from .config import load_policy, save_policy
from .paths import DATA_DIR, SECURE_DIR, ensure_dirs, warp_cli
from .winutil import is_elevated, lock_down_directory, log, run

# مصادر عميل الفلترة بالترتيب: نسخة المدرسة على GitHub ثم المصدر الرسمي.
# المصدر الرسمي ردّ HTTP 403 على الطلبات بلا ترويسة هوية، فنرسل هوية
# صادقة باسم البرنامج (لا ننتحل متصفحًا).
WARP_URLS = (
    "https://github.com/moradsimre1989-creator/school-shield/releases/download/"
    "v3.0/Cloudflare_WARP.msi",
    "https://downloads.cloudflareclient.com/v1/download/windows/ga",
)
USER_AGENT = "SchoolShield/3.1 (+https://github.com/moradsimre1989-creator/school-shield)"
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


def _digest(path: Path) -> str:
    """بصمة الملف - مقارنة الحجم وحدها تُخفي تحديثًا بنفس الحجم."""
    import hashlib
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                h.update(block)
    except OSError:
        return ""
    return h.hexdigest()


def installed_exe() -> Path | None:
    """الملف الذي تشير إليه الخدمة فعلًا، أو أي نسخة مثبّتة."""
    code, info, _ = run(["sc.exe", "qc", SERVICE_NAME])
    if code == 0:
        for line in info.splitlines():
            if "BINARY_PATH_NAME" not in line.upper():
                continue
            # المسار يحوي مسافات، فنأخذ السطر كاملًا بعد النقطتين
            value = line.split(":", 1)[1].strip() if ":" in line else ""
            value = value.split(" --")[0].strip().strip('"')
            candidate = Path(value)
            if candidate.exists():
                return candidate
    for name in sorted(INSTALL_DIR.glob("SchoolShield-*.exe")):
        return name
    return None


def target_for(src: Path) -> Path:
    """مسار التثبيت مشتق من بصمة المحتوى: نسخة جديدة تعني اسم ملف جديد.

    هكذا لا نكتب أبدًا فوق ملف تعمل منه الخدمة - وهذا سبب خطأ
    Access denied الذي كان يوقف التحديث على الأجهزة المثبّتة.
    """
    return INSTALL_DIR / f"SchoolShield-{_digest(src)[:10]}.exe"


def installed() -> bool:
    """مثبّت = الخدمة موجودة وتعمل من نفس نسخة الملف الذي شغّله المستخدم."""
    if not service_installed():
        return False
    current = self_path()
    wanted = target_for(current)
    if not wanted.exists():
        return False
    try:
        if current.resolve() == wanted.resolve():
            return True
    except OSError:
        pass
    active = installed_exe()
    return active is not None and active.name == wanted.name


def _copy_program(progress: Progress | None) -> Path:
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    src = self_path()
    target = target_for(src)
    if not target.exists():
        _say(progress, "نسخ البرنامج")
        # اسم جديد لكل نسخة: مستحيل أن يكون مقفولًا من خدمة تعمل
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



def _replace_running_exe(src: Path, target: Path, progress: Progress | None) -> None:
    """يستبدل ملف البرنامج حتى لو كانت الخدمة تعمل منه.

    Windows يمنع الكتابة فوق ملف قيد التشغيل (Permission denied)، لكنه
    يسمح بإعادة تسميته. فنوقف الخدمة، وإن بقي الملف مقفلًا نزيحه جانبًا.
    """
    if target.exists():
        run(["sc.exe", "stop", SERVICE_NAME], timeout=60)
        for _ in range(10):
            try:
                target.unlink()
                break
            except OSError:
                time.sleep(2)
    try:
        shutil.copy2(src, target)
        return
    except OSError:
        pass
    # الملف ما زال مقفلًا: أزحه باسم آخر ثم انسخ الجديد مكانه
    stale = target.with_name("SchoolShield.old.exe")
    try:
        stale.unlink()
    except OSError:
        pass
    _say(progress, "تحرير النسخة القديمة")
    os.replace(target, stale)
    shutil.copy2(src, target)


def _prepare_data(organization: str, progress: Progress | None) -> None:
    _say(progress, "تهيئة ملفات الإعداد")
    ensure_dirs()
    policy = load_policy()
    policy["organization"] = organization
    save_policy(policy)
    lock_down_directory(str(DATA_DIR), allow_users_read=True)
    lock_down_directory(str(SECURE_DIR), allow_users_read=False)


def _install_client(organization: str, progress: Progress | None,
                    needs_reboot: list[str]) -> str:
    """ينزّل عميل الفلترة ويثبّته مُدارًا مع قفل المفتاح."""
    from . import warp
    if not warp.installed():
        msi = Path(os.environ.get("TEMP", r"C:\Windows\Temp")) / "Cloudflare_WARP.msi"
        _say(progress, "تنزيل عميل الفلترة (قد يستغرق دقائق)")
        problem = _download_client(msi, progress)
        if problem:
            return problem
        _say(progress, "تثبيت عميل الفلترة")
        rc, out, err = run([
            "msiexec", "/i", str(msi), "/qn", "/norestart",
            f'ORGANIZATION={organization}', "SWITCH_LOCKED=true", "ONBOARDING=false",
        ], timeout=900)
        if rc not in (0, 3010):
            return f"فشل تثبيت عميل الفلترة (رمز {rc}) {err or out}"
        if rc == 3010:
            needs_reboot.append("العميل يحتاج إعادة تشغيل")
    _say(progress, "كتابة إعدادات العميل المُدارة")
    token_id, token_secret = bundled_service_token()
    warp.write_mdm(organization, switch_locked=True, auto_connect=1,
                   service_mode="warp", onboarding=False,
                   auth_client_id=token_id, auth_client_secret=token_secret)
    # mdm.xml يحوي سرّ توكن المدرسة. لا يُمنح الطلاب قراءته، ولا نلمس
    # صلاحيات مجلد المورّد كله حتى لا نكسر مكوّنات العميل.
    run(["icacls", str(warp.WARP_MDM_FILE), "/inheritance:r",
         "/grant:r", "*S-1-5-18:F", "/grant:r", "*S-1-5-32-544:F"])
    if token_id and token_secret:
        _register_with_token(progress)
    return ""


def _warp_service_name() -> str:
    for service in ("CloudflareWARP", "WarpSvc", "Cloudflare WARP"):
        if run(["sc.exe", "query", service])[0] == 0:
            return service
    return ""


def _wait_for_daemon(progress: Progress | None, seconds: int = 180) -> bool:
    """ينتظر استجابة خدمة عميل الفلترة، ويشغّلها إن كانت متوقفة.

    بعد تثبيت الحزمة مباشرة قد تتأخر الخدمة في القيام، وهذا سبب رسالة
    «العميل مثبّت لكن خدمته لا تستجيب».
    """
    from . import warp
    service = _warp_service_name()
    waited = 0
    while waited < seconds:
        if service:
            state = run(["sc.exe", "query", service])[1]
            if "RUNNING" not in state.upper():
                run(["sc.exe", "start", service], timeout=60)
        if warp.status().get("ok"):
            return True
        _say(progress, f"بانتظار خدمة الفلترة... ({waited} ثانية)")
        time.sleep(5)
        waited += 5
    return False


def _register_with_token(progress: Progress | None) -> None:
    """يسجّل الجهاز بتوكن المدرسة بدل انتظار تسجيل دخول المستخدم."""
    from . import warp
    exe = warp_cli()
    if not exe:
        return
    if not _wait_for_daemon(progress):
        _say(progress, "تم التثبيت - أعد تشغيل الحاسوب لإكمال التفعيل")
        return
    if warp.registration().get("ok") and warp.status().get("connected"):
        return
    _say(progress, "تسجيل الجهاز تلقائيًا")
    run([exe, "--accept-tos", "registration", "delete"], timeout=60)
    service = _warp_service_name()
    if service:
        run(["sc.exe", "stop", service], timeout=90)
        time.sleep(3)
        run(["sc.exe", "start", service], timeout=90)
    if not _wait_for_daemon(progress):
        _say(progress, "تم التثبيت - أعد تشغيل الحاسوب لإكمال التفعيل")
        return
    for _ in range(24):
        if warp.status().get("connected"):
            _say(progress, "تم تسجيل الجهاز")
            return
        warp.connect()
        time.sleep(5)
    _say(progress, "تم التثبيت - أعد تشغيل الحاسوب لإكمال التفعيل")


def _download_client(msi: Path, progress: Progress | None) -> str:
    """ينزّل حزمة العميل من عدة مصادر، ثم يجرّب curl المرفق مع Windows."""
    errors: list[str] = []
    for index, url in enumerate(WARP_URLS, start=1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=900) as response, \
                    msi.open("wb") as out:
                shutil.copyfileobj(response, out)
            if msi.exists() and msi.stat().st_size > 10_000_000:
                return ""
            errors.append(f"مصدر {index}: ملف ناقص")
        except Exception as exc:
            errors.append(f"مصدر {index}: {exc}")
        _say(progress, f"تعذّر المصدر {index} - تجربة مصدر آخر")
    for url in WARP_URLS:
        rc, _, err = run(["curl.exe", "-sL", "--max-time", "900",
                          "-A", USER_AGENT, "-o", str(msi), url], timeout=960)
        if rc == 0 and msi.exists() and msi.stat().st_size > 10_000_000:
            return ""
        errors.append("curl: " + (err or "فشل")[:60])
    return "فشل تنزيل عميل الفلترة. " + " | ".join(errors[:3])


def _install_service(exe: Path, progress: Progress | None) -> str:
    _say(progress, "تثبيت خدمة الحماية")
    run(["sc.exe", "stop", SERVICE_NAME], timeout=90)
    run(["sc.exe", "delete", SERVICE_NAME], timeout=60)
    # الحذف يبقى معلّقًا ما دام أي برنامج يمسك الخدمة (services.msc مثلًا)
    for _ in range(15):
        if not service_installed():
            break
        time.sleep(2)
    else:
        return "الخدمة القديمة ما زالت قيد الاستخدام - أغلق نافذة Services وأعد المحاولة"
    # مسار البرنامج يحتوي مسافة، وتمريره عبر sc.exe مباشرة يشوّه الاقتباس
    # فيُسجَّل مسار خاطئ ولا تبدأ الخدمة. PowerShell يتولّى الاقتباس صحيحًا.
    bin_path = f'"{exe}" --service'
    ps = (
        "$ErrorActionPreference='Stop'; "
        f"New-Service -Name '{SERVICE_NAME}' "
        f"-BinaryPathName '{bin_path}' "
        f"-DisplayName '{SERVICE_DISPLAY}' -StartupType Automatic"
    )
    rc, out, err = run(["powershell", "-NoProfile", "-Command", ps], timeout=120)
    if rc != 0:
        return f"تعذّر إنشاء الخدمة: {(err or out)[:160]}"
    # تحقّق أن المسار المسجَّل هو الصحيح فعلًا
    _, info, _ = run(["sc.exe", "qc", SERVICE_NAME])
    if exe.name not in info:
        return "أُنشئت الخدمة بمسار غير صحيح"
    run(["sc.exe", "description", SERVICE_NAME,
         "يفرض سياسات التصفح الآمن لحواسيب الطلاب"])
    run(["sc.exe", "failure", SERVICE_NAME, "reset=", "0",
         "actions=", "restart/5000/restart/5000/restart/60000"])
    run(["sc.exe", "sdset", SERVICE_NAME, SERVICE_SDDL])
    rc, out, err = run(["sc.exe", "start", SERVICE_NAME], timeout=60)
    if rc != 0:
        return f"تعذّر تشغيل الخدمة: {(err or out)[:160]}"
    # رمز نجاح لا يعني أنها بقيت تعمل - نتأكد مرتين بفاصل زمني
    for attempt in range(2):
        time.sleep(8)
        state = run(["sc.exe", "query", SERVICE_NAME])[1].upper()
        if "RUNNING" not in state:
            return "الخدمة بدأت ثم توقفت - راجع سجلّ البرنامج"
    return ""


def _cleanup_old_copies(keep: Path) -> None:
    """يحذف النسخ السابقة بعد نجاح التثبيت. فشل الحذف لا يُفشل التثبيت."""
    for old in INSTALL_DIR.glob("SchoolShield-*.exe"):
        if old.name.lower() == keep.name.lower():
            continue
        try:
            old.unlink()
        except OSError:
            pass


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
    if not re.fullmatch(r"[A-Za-z0-9._-]+", organization):
        return "اسم المؤسسة غير صالح (حروف وأرقام وشرطات فقط)"
    needs_reboot: list[str] = []
    try:
        exe = _copy_program(progress)
        _prepare_data(organization, progress)
        problem = _install_client(organization, progress, needs_reboot)
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
        _cleanup_old_copies(exe)
        if needs_reboot:
            _say(progress, "اكتمل التثبيت")
            return "REBOOT"
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


def bundled_service_token() -> tuple[str, str]:
    """توكن تسجيل الأجهزة من ملف token.cfg المرفق، إن وُجد.

    السطر الأول: Client ID، والثاني: Client Secret. وجوده يجعل الجهاز
    يسجّل نفسه تلقائيًا بلا تسجيل دخول.
    """
    folders = [self_path().parent, INSTALL_DIR]
    bundled = getattr(sys, "_MEIPASS", None)
    if bundled:
        folders.insert(0, Path(bundled) / "schoolshield")
    for folder in folders:
        cfg = folder / "token.cfg"
        try:
            if cfg.exists():
                lines = [l.strip() for l in
                         cfg.read_text(encoding="utf-8-sig").splitlines() if l.strip()]
                if len(lines) >= 2:
                    return lines[0], lines[1]
        except OSError:
            pass
    return "", ""
