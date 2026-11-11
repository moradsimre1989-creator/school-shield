"""مساعدات Windows: الصلاحيات، تنفيذ الأوامر، سجل التدقيق."""
from __future__ import annotations

import ctypes
import datetime as _dt
import os
import subprocess
from typing import Sequence

from .paths import AUDIT_FILE, LOG_FILE, ensure_dirs

CREATE_NO_WINDOW = 0x08000000


def is_elevated() -> bool:
    """هل العملية الحالية تعمل بصلاحيات مدير Windows فعلية؟"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def current_user() -> str:
    domain = os.environ.get('USERDOMAIN', '')
    return domain + chr(92) + os.environ.get('USERNAME', '?')


def run(cmd: Sequence[str], timeout: int = 30) -> tuple[int, str, str]:
    """ينفّذ أمرًا بدون نافذة ويرجع (الكود، الخرج، الخطأ)."""
    try:
        p = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except FileNotFoundError:
        return 127, "", "command not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as exc:  # pragma: no cover
        return 1, "", str(exc)


def _stamp() -> str:
    return _dt.datetime.now().isoformat(timespec="seconds")


def log(message: str) -> None:
    ensure_dirs()
    try:
        with LOG_FILE.open("a", encoding="utf-8") as fh:
            fh.write(f"{_stamp()} {message}\n")
    except OSError:
        pass


def audit(action: str, detail: str = "") -> None:
    """سجل تدقيق إداري داخل المجلد المحمي."""
    ensure_dirs()
    try:
        with AUDIT_FILE.open("a", encoding="utf-8") as fh:
            fh.write(f"{_stamp()}\t{current_user()}\t{action}\t{detail}\n")
    except OSError:
        pass


def lock_down_directory(path: str, allow_users_read: bool) -> bool:
    """يضبط ACL: SYSTEM و Administrators كامل، Users قراءة أو لا شيء."""
    rc, _, _ = run(["icacls", path, "/inheritance:r"])
    ok = rc == 0
    grants = [
        "/grant:r", "*S-1-5-18:(OI)(CI)F",   # SYSTEM
        "/grant:r", "*S-1-5-32-544:(OI)(CI)F",  # Administrators
    ]
    if allow_users_read:
        grants += ["/grant:r", "*S-1-5-32-545:(OI)(CI)R"]  # Users: قراءة فقط
    else:
        grants += ["/remove:g", "*S-1-5-32-545", "/remove:g", "*S-1-1-0"]
    rc2, _, _ = run(["icacls", path] + grants)
    return ok and rc2 == 0
