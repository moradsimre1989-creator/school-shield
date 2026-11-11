"""حساب المدير: تجزئة Argon2id، إلزام تغيير كلمة المرور، وحماية من التكرار.

لا تُخزَّن كلمة المرور أبدًا - لا في الكود، ولا في ملف التثبيت، ولا في السجل.
الملف الوحيد الذي يحمل التجزئة محمي بـ ACL لا يسمح لمجموعة Users بالقراءة.

مهم: معرفة كلمة مرور التطبيق لا تمنح صلاحيات Windows. كل عملية فعلية
(إيقاف مؤقت، إزالة) تتطلب كذلك عملية مُرقّاة (Administrator) لأن الملفات
والخدمات محميّة بـ ACL على مستوى النظام.
"""
from __future__ import annotations

import datetime as _dt
import json
import secrets
import string
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from .paths import ADMIN_FILE, SECURE_DIR, ensure_dirs
from .winutil import audit, is_elevated, lock_down_directory

# معاملات Argon2id: متوافقة مع توصيات OWASP لأجهزة مكتبية
_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32)

MAX_FAILURES_BEFORE_LOCK = 5
BASE_LOCK_SECONDS = 60          # يتضاعف مع كل دفعة فشل
MAX_LOCK_SECONDS = 3600
MIN_PASSWORD_LEN = 12


class AuthError(Exception):
    """خطأ مصادقة يُعرض للمستخدم كما هو."""


class NotProvisioned(AuthError):
    pass


def _now() -> _dt.datetime:
    return _dt.datetime.now()


def _load() -> dict[str, Any]:
    try:
        return json.loads(ADMIN_FILE.read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        raise NotProvisioned("لم يُنشأ حساب المدير بعد")
    except (OSError, ValueError) as exc:
        raise AuthError(f"ملف حساب المدير غير قابل للقراءة: {exc}")


def _save(data: dict[str, Any]) -> None:
    ensure_dirs()
    ADMIN_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                          encoding="utf-8")
    lock_down_directory(str(SECURE_DIR), allow_users_read=False)


def is_provisioned() -> bool:
    return ADMIN_FILE.exists()


def password_problems(password: str, username: str = "") -> list[str]:
    """قواعد قوة كلمة المرور. تُطبَّق على كل تغيير."""
    problems = []
    if len(password) < MIN_PASSWORD_LEN:
        problems.append(f"الطول أقل من {MIN_PASSWORD_LEN} حرفًا")
    if not any(c.isupper() for c in password):
        problems.append("لا يوجد حرف كبير (A-Z)")
    if not any(c.islower() for c in password):
        problems.append("لا يوجد حرف صغير (a-z)")
    if not any(c.isdigit() for c in password):
        problems.append("لا يوجد رقم")
    if not any(c in string.punctuation for c in password):
        problems.append("لا يوجد رمز خاص")
    if username and username.lower() in password.lower():
        problems.append("تحتوي اسم المستخدم")
    weak = {"password", "12345678", "qwerty", "school", "shield", "admin",
            "schoolshield", "12345678910", "passw0rd"}
    if password.lower() in weak or password.lower().strip("0123456789") in weak:
        problems.append("كلمة مرور شائعة أو هي نفسها كلمة المرور الأولية")
    return problems


def provision(username: str, initial_password: str, *,
              force_change: bool = True) -> None:
    """إنشاء حساب المدير لمرة واحدة. يُشغَّل من مثبّت مُرقّى.

    كلمة المرور الأولية تُقبل كما هي (ولو كانت ضعيفة) لكن يُفرض تغييرها
    عند أول تسجيل دخول، ولا تُقبل كلمة مرور دائمة ضعيفة.
    """
    if not is_elevated():
        raise AuthError("إنشاء حساب المدير يتطلب تشغيل الأداة كمدير Windows")
    if is_provisioned():
        raise AuthError("حساب المدير مُنشأ مسبقًا. استخدم change-password")
    if not username or not initial_password:
        raise AuthError("اسم المستخدم وكلمة المرور مطلوبان")
    _save({
        "username": username,
        "hash": _HASHER.hash(initial_password),
        "must_change": force_change,
        "created_at": _now().isoformat(timespec="seconds"),
        "password_changed_at": None,
        "failures": 0,
        "failure_streaks": 0,
        "locked_until": None,
    })
    audit("provision", f"username={username} must_change={force_change}")


def _lock_remaining(data: dict[str, Any]) -> int:
    until = data.get("locked_until")
    if not until:
        return 0
    try:
        delta = (_dt.datetime.fromisoformat(until) - _now()).total_seconds()
    except ValueError:
        return 0
    return max(0, int(delta))


def verify(username: str, password: str) -> dict[str, Any]:
    """تحقق من بيانات المدير مع حماية ضد المحاولات المتكررة."""
    data = _load()
    remaining = _lock_remaining(data)
    if remaining:
        audit("login_locked", f"remaining={remaining}s")
        raise AuthError(f"الحساب مقفل مؤقتًا. أعد المحاولة بعد {remaining} ثانية")

    ok = username.strip().lower() == str(data["username"]).lower()
    try:
        _HASHER.verify(data["hash"], password)
    except (VerifyMismatchError, InvalidHashError):
        ok = False
    except Exception:
        ok = False

    if not ok:
        data["failures"] = int(data.get("failures", 0)) + 1
        if data["failures"] >= MAX_FAILURES_BEFORE_LOCK:
            streak = int(data.get("failure_streaks", 0)) + 1
            delay = min(BASE_LOCK_SECONDS * (2 ** (streak - 1)), MAX_LOCK_SECONDS)
            data.update({
                "failures": 0,
                "failure_streaks": streak,
                "locked_until": (_now() + _dt.timedelta(seconds=delay)).isoformat(
                    timespec="seconds"),
            })
            _save(data)
            audit("login_lockout", f"streak={streak} delay={delay}s")
            raise AuthError(f"تجاوزت عدد المحاولات. الحساب مقفل {delay} ثانية")
        _save(data)
        audit("login_failed", f"failures={data['failures']}")
        raise AuthError("اسم المستخدم أو كلمة المرور غير صحيحة")

    # نجاح: صفّر العدّادات، وحدّث التجزئة إن تغيّرت المعاملات
    if _HASHER.check_needs_rehash(data["hash"]):
        data["hash"] = _HASHER.hash(password)
    data.update({"failures": 0, "failure_streaks": 0, "locked_until": None,
                 "last_login": _now().isoformat(timespec="seconds")})
    _save(data)
    audit("login_ok", f"username={username}")
    return {"username": data["username"], "must_change": bool(data.get("must_change"))}


def change_password(username: str, old_password: str, new_password: str) -> None:
    """تغيير كلمة المرور مع فرض قواعد القوة."""
    verify(username, old_password)
    problems = password_problems(new_password, username)
    if problems:
        raise AuthError("كلمة المرور الجديدة ضعيفة: " + "، ".join(problems))
    if new_password == old_password:
        raise AuthError("كلمة المرور الجديدة مطابقة للقديمة")
    data = _load()
    data.update({
        "hash": _HASHER.hash(new_password),
        "must_change": False,
        "password_changed_at": _now().isoformat(timespec="seconds"),
    })
    _save(data)
    audit("password_changed", f"username={username}")


def suggest_password(length: int = 18) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        if not password_problems(candidate):
            return candidate


def status() -> dict[str, Any]:
    """حالة الحساب بدون أي معلومة سرية."""
    if not is_provisioned():
        return {"provisioned": False}
    data = _load()
    return {
        "provisioned": True,
        "username": data.get("username"),
        "must_change": bool(data.get("must_change")),
        "created_at": data.get("created_at"),
        "password_changed_at": data.get("password_changed_at"),
        "locked_seconds": _lock_remaining(data),
    }


def verify_password(password: str) -> bool:
    """تحقق من كلمة المرور فقط - تستعمله الخدمة عند طلب الإيقاف."""
    try:
        data = _load()
    except AuthError:
        return False
    try:
        verify(str(data.get("username") or "admin"), password)
        return True
    except AuthError:
        return False


def provision_if_missing(password: str, username: str = "admin") -> None:
    """ينشئ حساب الإدارة عند أول تثبيت إن لم يكن موجودًا."""
    if is_provisioned() or not password:
        return
    _save({
        "username": username,
        "hash": _HASHER.hash(password),
        "must_change": False,
        "created_at": _now().isoformat(timespec="seconds"),
        "password_changed_at": _now().isoformat(timespec="seconds"),
        "failures": 0,
        "failure_streaks": 0,
        "locked_until": None,
    })
    audit("provision", "username=" + username)
