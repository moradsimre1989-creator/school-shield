"""خدمة Windows الدائمة لدرع المدرسة.

تعمل كـ LocalSystem، مستقلة تمامًا عن واجهة البرنامج:
  - تُعيد فرض سياسات المتصفحات والتشديد كل دورة (إصلاح أي تلاعب)
  - تتأكد أن عميل الفلترة متصل، وتعيد وصله إن انفصل
  - تنفّذ الفحوص السبعة وتكتب الحالة إلى status.json
  - تستجيب لثلاثة أوامر فقط: STATUS / VERIFY / ENFORCE

إغلاق نافذة البرنامج لا يوقف شيئًا، وإعادة التشغيل تُعيدها تلقائيًا
(Start=auto + sc failure restart).
"""
from __future__ import annotations

import datetime as _dt
import json
import socket
import threading
import time
from typing import Any

from . import SERVICE_DISPLAY, SERVICE_NAME, __version__
from .config import load_policy
from .paths import IPC_HOST, IPC_PORT, ensure_dirs
from .winutil import log

PAUSE_MINUTES = 60

_STOP = threading.Event()
_LOCK = threading.Lock()


# --------------------------- منطق الدورة ---------------------------

def _enforce() -> dict[str, Any]:
    from . import hardening
    return hardening.enforce_all()


def _ensure_client_connected() -> None:
    from . import setup_win, warp
    if not warp.installed():
        return
    st = warp.status()
    if st["connected"]:
        return
    log("العميل غير متصل - محاولة إعادة الوصل")
    warp.connect()
    # تسجيل مفقود + توكن مدرسة متوفّر = سجّل الجهاز بلا تدخّل المستخدم
    if not warp.registration().get("ok"):
        token_id, token_secret = setup_win.bundled_service_token()
        if token_id and token_secret:
            log("تسجيل الجهاز بتوكن المدرسة")
            warp.write_mdm(load_policy().get("organization", ""),
                           switch_locked=True, auto_connect=1,
                           service_mode="warp", onboarding=False,
                           auth_client_id=token_id,
                           auth_client_secret=token_secret)
            setup_win._register_with_token(None)


_LAST_DNS_REPAIR = [0.0]
DNS_REPAIR_EVERY = 600  # ثانية - لا نعيد الوصل في كل دورة


def _repair_dns_if_leaking(report: dict[str, Any]) -> None:
    """العميل متصل والحجب فاشل = استعلامات الأسماء تخرج خارج النفق.

    إعادة وصل العميل تجعله يعيد فرض خادم أسمائه على بطاقات الشبكة، وهي
    خطوة آمنة وقابلة للتراجع - لا نلمس إعدادات البطاقة بأنفسنا كي لا
    نكسر خوادم المدرسة الداخلية وVeyon.
    """
    import time as _t
    from . import warp
    leaking = any(r.get("key") in ("adult_block", "violence_block")
                  and r.get("state") == "fail"
                  for r in report.get("checks", []))
    if not leaking:
        return
    if not warp.status().get("connected"):
        return
    now = _t.monotonic()
    if now - _LAST_DNS_REPAIR[0] < DNS_REPAIR_EVERY:
        return
    _LAST_DNS_REPAIR[0] = now
    log("الحجب فاشل رغم الاتصال - إعادة وصل العميل لإعادة فرض خادم الأسماء")
    try:
        warp.reconnect()
    except Exception as exc:
        log(f"إعادة الوصل خطأ: {exc}")


def _verify_and_publish() -> dict[str, Any]:
    from . import checks
    report = checks.run_all()
    report["service_version"] = __version__
    checks.write_status(report)
    return report


def cycle(enforce: bool = True) -> dict[str, Any]:
    """دورة واحدة كاملة: فرض ثم وصل ثم فحص."""
    with _LOCK:
        paused = False
        try:
            from . import checks
            paused = checks.pause_state().get("active", False)
        except Exception as exc:  # pragma: no cover
            log(f"pause_state خطأ: {exc}")
        if enforce and not paused:
            try:
                _enforce()
            except Exception as exc:
                log(f"enforce خطأ: {exc}")
            try:
                _ensure_client_connected()
            except Exception as exc:
                log(f"connect خطأ: {exc}")
        report = _verify_and_publish()
        if enforce and not paused:
            try:
                _repair_dns_if_leaking(report)
            except Exception as exc:
                log(f"إصلاح الأسماء خطأ: {exc}")
        return report


# --------------------------- قناة IPC ---------------------------

def _handle(conn: socket.socket) -> None:
    from . import checks
    from .ipc import ALLOWED_COMMANDS
    try:
        conn.settimeout(120)
        payload = conn.recv(1024).decode("utf-8", errors="replace").strip()
        parts = payload.split("	", 1)
        raw = parts[0].upper()
        password = parts[1] if len(parts) > 1 else ""
        if raw not in ALLOWED_COMMANDS:
            reply: dict[str, Any] = {"ok": False, "error": "أمر غير مسموح"}
        elif raw in ("PAUSE", "RESUME"):
            reply = _handle_pause(raw, password)
        elif raw == "STATUS":
            reply = {"ok": True, "report": checks.read_status() or cycle(enforce=False)}
        elif raw == "VERIFY":
            reply = {"ok": True, "report": cycle(enforce=False)}
        else:  # ENFORCE
            reply = {"ok": True, "report": cycle(enforce=True)}
        conn.sendall(json.dumps(reply, ensure_ascii=False).encode("utf-8"))
    except Exception as exc:
        log(f"IPC خطأ: {exc}")
        try:
            conn.sendall(json.dumps({"ok": False, "error": str(exc)}).encode("utf-8"))
        except OSError:
            pass
    finally:
        try:
            conn.close()
        except OSError:
            pass



def _handle_pause(command: str, password: str) -> dict[str, Any]:
    """إيقاف أو استئناف الحماية بعد التحقق من كلمة مرور المدير.

    الخدمة تعمل كـ SYSTEM فهي وحدها من يكتب ملف الإيقاف داخل المجلد المحمي.
    """
    from . import auth, checks
    from .paths import PAUSE_FILE, ensure_dirs
    from .winutil import audit
    if not auth.is_provisioned():
        return {"ok": False, "error": "لم تُضبط كلمة مرور للإيقاف على هذا الجهاز"}
    if not password or not auth.verify_password(password):
        audit("ipc_pause_denied", command)
        return {"ok": False, "error": "كلمة المرور غير صحيحة"}
    ensure_dirs()
    if command == "RESUME":
        PAUSE_FILE.unlink(missing_ok=True)
        audit("ipc_resume", "")
        return {"ok": True, "report": cycle(enforce=True)}
    until = _dt.datetime.now() + _dt.timedelta(minutes=PAUSE_MINUTES)
    PAUSE_FILE.write_text(json.dumps(
        {"until": until.isoformat(timespec="seconds"), "by": "admin"},
        ensure_ascii=False), encoding="utf-8")
    audit("ipc_pause", f"minutes={PAUSE_MINUTES}")
    return {"ok": True, "report": _verify_and_publish()}


def _ipc_server() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((IPC_HOST, IPC_PORT))  # loopback فقط - لا وصول من الشبكة
        srv.listen(8)
        srv.settimeout(1.0)
        log(f"IPC يستمع على {IPC_HOST}:{IPC_PORT}")
        while not _STOP.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=_handle, args=(conn,), daemon=True).start()
    finally:
        srv.close()


def watchdog() -> None:
    """الحلقة الدائمة."""
    ensure_dirs()
    interval = int(load_policy().get("watchdog_interval_seconds", 60))
    log(f"بدء الخدمة {__version__} بفاصل {interval}s")
    threading.Thread(target=_ipc_server, daemon=True).start()
    while not _STOP.is_set():
        started = time.time()
        try:
            report = cycle(enforce=True)
            log("الحالة: " + report["overall"] + " " + json.dumps(
                report["summary"], ensure_ascii=False))
        except Exception as exc:
            log(f"دورة فاشلة: {exc}")
        wait = max(5.0, interval - (time.time() - started))
        _STOP.wait(wait)
    log("توقّفت الخدمة")


def stop() -> None:
    _STOP.set()


# --------------------------- غلاف خدمة Windows ---------------------------
try:
    import servicemanager
    import win32service
    import win32serviceutil

    class SchoolShieldService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY
        _svc_description_ = (
            "يفرض سياسات التصفح الآمن لحواسيب الطلاب ويمنع تعطيل الحماية "
            "من الحسابات العادية."
        )

        def __init__(self, args):
            super().__init__(args)
            _STOP.clear()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            stop()

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            watchdog()

    def service_main() -> None:
        """نقطة الدخول عند تشغيل الـ exe كخدمة أو لإدارتها."""
        import sys
        for _stream in (sys.stdout, sys.stderr):
            try:
                _stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
        if len(sys.argv) > 1 and sys.argv[1] == "--run-console":
            print("تشغيل حلقة الحماية في وضع التشخيص. أوقفها بـ Ctrl+C.")
            try:
                watchdog()
            except KeyboardInterrupt:
                stop()
            return
        if len(sys.argv) == 1:
            try:
                servicemanager.Initialize()
                servicemanager.PrepareToHostSingle(SchoolShieldService)
                servicemanager.StartServiceCtrlDispatcher()
            except Exception as exc:
                code = getattr(exc, "winerror", None)
                if code is None and getattr(exc, "args", None):
                    code = exc.args[0]
                if code == 1063:
                    print("هذا الملف خدمة Windows ولا يُشغَّل بالنقر المباشر.")
                    print("للتثبيت (كمدير):  sc create SchoolShield binPath= \"...\" start= auto")
                    print("للتشخيص:          SchoolShieldService.exe --run-console")
                    raise SystemExit(1)
                raise
        else:
            win32serviceutil.HandleCommandLine(SchoolShieldService)

except ImportError:  # pragma: no cover - بيئة بلا pywin32
    SchoolShieldService = None  # type: ignore[assignment]

    def service_main() -> None:
        raise SystemExit("pywin32 غير مثبّت - لا يمكن تشغيل الخدمة")


if __name__ == "__main__":
    service_main()
