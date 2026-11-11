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

import json
import socket
import threading
import time
from typing import Any

from . import SERVICE_DISPLAY, SERVICE_NAME, __version__
from .config import load_policy
from .paths import IPC_HOST, IPC_PORT, ensure_dirs
from .winutil import log

_STOP = threading.Event()
_LOCK = threading.Lock()


# --------------------------- منطق الدورة ---------------------------

def _enforce() -> dict[str, Any]:
    from . import hardening
    return hardening.enforce_all()


def _ensure_client_connected() -> None:
    from . import warp
    if not warp.installed():
        return
    st = warp.status()
    if not st["connected"]:
        log("العميل غير متصل - محاولة إعادة الوصل")
        warp.connect()


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
        return _verify_and_publish()


# --------------------------- قناة IPC ---------------------------

def _handle(conn: socket.socket) -> None:
    from . import checks
    from .ipc import ALLOWED_COMMANDS
    try:
        conn.settimeout(120)
        raw = conn.recv(256).decode("utf-8", errors="replace").strip().upper()
        if raw not in ALLOWED_COMMANDS:
            reply: dict[str, Any] = {"ok": False, "error": "أمر غير مسموح"}
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
