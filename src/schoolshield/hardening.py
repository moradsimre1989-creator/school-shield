"""تشديد النظام: منع إيقاف الخدمة، منع تعديل الملفات، حجب تجاوز الفلترة.

كل الآليات هنا رسمية من Windows: ACL على الخدمات والملفات، إعادة تشغيل تلقائي
للخدمة، وقواعد جدار حماية Windows. لا حِيَل مخفية ولا أساليب تخريبية.

حدّ معروف ومُعلن: من يملك صلاحيات Administrator على Windows يستطيع في النهاية
إزالة أي برنامج. الهدف المضمون هنا هو منع حساب الطالب العادي.
"""
from __future__ import annotations

import os
import winreg
from typing import Any

from . import SERVICE_NAME
from .config import load_policy
from .paths import DATA_DIR, SECURE_DIR, WARP_MDM_FILE
from .winutil import log, lock_down_directory, run

FW_PREFIX = "SchoolShield -"
WARP_SERVICES = ("CloudflareWARP", "Cloudflare WARP", "WarpSvc")

PASS = "pass"
FAIL = "fail"
UNVERIFIED = "unverified"


# ------------------------- فرض التشديد -------------------------

def harden_service_recovery(service: str = SERVICE_NAME) -> bool:
    """إعادة تشغيل الخدمة تلقائيًا إذا قُتلت - حتى من مدير."""
    rc, _, _ = run([
        "sc.exe", "failure", service, "reset=", "0",
        "actions=", "restart/5000/restart/5000/restart/60000",
    ])
    return rc == 0


def harden_service_acl(service: str = SERVICE_NAME) -> bool:
    """SDDL: SYSTEM و Administrators تحكّم كامل، Users قراءة فقط (لا إيقاف).

    SDDL مبني على الافتراضي الآمن لخدمات Windows، مع إزالة أي منح
    لمجموعة Interactive/Users يسمح بـ STOP (RP/WP/DT).
    """
    sddl = (
        "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)"      # SYSTEM: كامل
        "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)"  # Administrators: كامل
        "(A;;CCLCSWLOCRRC;;;IU)"              # Interactive: قراءة واستعلام فقط
        "(A;;CCLCSWLOCRRC;;;SU)"              # Service: قراءة
        "(A;;CCLCSWLOCRRC;;;BU)"              # Users: قراءة فقط - لا STOP
        "S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"  # تدقيق أي فشل
    )
    rc, out, err = run(["sc.exe", "sdset", service, sddl])
    if rc != 0:
        log(f"sdset فشل على {service}: {err or out}")
    return rc == 0


def harden_warp_service() -> dict[str, Any]:
    """نفس التشديد على خدمة عميل الفلترة إن وُجدت."""
    done = []
    for svc in WARP_SERVICES:
        rc, _, _ = run(["sc.exe", "query", svc])
        if rc == 0:
            harden_service_acl(svc)
            harden_service_recovery(svc)
            done.append(svc)
    return {"hardened": done}


def harden_files() -> dict[str, Any]:
    """ACL على ملفات البرنامج: الطالب يقرأ الحالة فقط، ولا يرى المجلد الآمن."""
    results = {
        "data_dir": lock_down_directory(str(DATA_DIR), allow_users_read=True),
        "secure_dir": lock_down_directory(str(SECURE_DIR), allow_users_read=False),
    }
    if WARP_MDM_FILE.exists():
        results["warp_mdm"] = lock_down_directory(str(WARP_MDM_FILE.parent),
                                                  allow_users_read=True)
    return results


def firewall_rules() -> list[list[str]]:
    """قواعد حجب تجاوز الفلترة: DNS عام + منافذ VPN."""
    pol = load_policy()
    rules: list[list[str]] = []
    if pol.get("block_public_dns_ips", True):
        ips = ",".join(pol.get("public_dns_blocklist", []))
        if ips:
            for proto in ("UDP", "TCP"):
                rules.append([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={FW_PREFIX} Public DNS {proto}", "dir=out", "action=block",
                    f"protocol={proto}", "remoteport=53", f"remoteip={ips}",
                    "enable=yes", "profile=any",
                ])
    if pol.get("block_vpn_ports", True):
        for entry in pol.get("vpn_ports", []):
            proto, port = entry["proto"], entry["port"]
            rules.append([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={FW_PREFIX} VPN {proto}/{port}", "dir=out", "action=block",
                f"protocol={proto}", f"remoteport={port}", "enable=yes", "profile=any",
            ])
    return rules


def apply_firewall() -> dict[str, Any]:
    """يحذف القواعد القديمة ثم يضيفها من جديد (idempotent)."""
    added, failed = 0, []
    for rule in firewall_rules():
        name = next(a for a in rule if a.startswith("name="))
        run(["netsh", "advfirewall", "firewall", "delete", "rule", name])
        rc, out, err = run(rule)
        if rc == 0:
            added += 1
        else:
            failed.append(f"{name}: {err or out}")
    return {"added": added, "failed": failed}


def remove_firewall() -> int:
    """يحذف كل قواعد البرنامج - يُستخدم عند الإزالة الإدارية فقط."""
    removed = 0
    for rule in firewall_rules():
        name = next(a for a in rule if a.startswith("name="))
        rc, _, _ = run(["netsh", "advfirewall", "firewall", "delete", "rule", name])
        if rc == 0:
            removed += 1
    return removed


def enforce_all() -> dict[str, Any]:
    """كل خطوات التشديد. تُنفَّذ من الخدمة (SYSTEM) أو من مدير مُرقّى."""
    from .policies import enforce_browser_policies
    out = {
        "service_acl": harden_service_acl(),
        "service_recovery": harden_service_recovery(),
        "warp_service": harden_warp_service(),
        "files": harden_files(),
        "firewall": apply_firewall(),
    }
    if load_policy().get("enforce_browser_policies", True):
        out["browser_policies"] = enforce_browser_policies()
    log("enforce_all: " + str(out))
    return out


# ------------------------- تقرير منع التعطيل -------------------------

def _item(title: str, state: str, detail: str = "") -> dict[str, str]:
    return {"title": title, "state": state, "detail": detail}


def _service_sdl(service: str) -> str:
    rc, out, err = run(["sc.exe", "sdshow", service])
    return out if rc == 0 else ""


def _users_can_stop(sddl: str) -> bool | None:
    """هل يسمح الوصف الأمني لمجموعة عامة بإيقاف الخدمة؟ (DT = stop)."""
    if not sddl:
        return None
    import re
    for ace in re.findall(r"\(([^)]*)\)", sddl):
        parts = ace.split(";")
        if len(parts) < 6 or not parts[0].startswith("A"):
            continue
        rights, sid = parts[2], parts[5]
        if sid in ("BU", "IU", "WD", "AU") and ("DT" in rights or "WP" in rights):
            return True
    return False


def _student_is_admin() -> dict[str, str]:
    """هل المستخدمون التفاعليون أعضاء في مجموعة Administrators؟"""
    rc, out, err = run(["net", "localgroup", "Administrators"])
    if rc != 0:
        return _item("التحقق من عضوية مجموعة Administrators", UNVERIFIED,
                     (err or out)[:120])
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    try:
        start = next(i for i, l in enumerate(lines) if set(l) == {"-"}) + 1
    except StopIteration:
        start = 0
    members = [l for l in lines[start:] if not l.lower().startswith("the command")]
    me = os.environ.get("USERNAME", "")
    risky = [m for m in members
             if m.lower() not in ("administrator", "domain admins", "admin")]
    detail = "الأعضاء: " + ", ".join(members[:6])
    if me and any(me.lower() in m.lower() for m in members):
        return _item("حساب الطالب ليس عضوًا في Administrators", FAIL,
                     f"الحساب الحالي ({me}) عضو في Administrators. {detail}")
    if len(risky) > 1:
        return _item("حساب الطالب ليس عضوًا في Administrators", UNVERIFIED,
                     "يوجد أكثر من حساب مدير - راجع القائمة. " + detail)
    return _item("حساب الطالب ليس عضوًا في Administrators", PASS, detail)


def _warp_switch_locked() -> dict[str, str]:
    from . import warp
    mdm = warp.read_mdm()
    if not mdm:
        return _item("قفل مفتاح الإيقاف في عميل الفلترة", FAIL,
                     "ملف الإعدادات المُدارة mdm.xml غير موجود")
    locked = mdm.get("switch_locked") is True
    auto = mdm.get("auto_connect")
    if not locked:
        return _item("قفل مفتاح الإيقاف في عميل الفلترة", FAIL,
                     "switch_locked غير مفعّل")
    if auto is None:
        return _item("قفل مفتاح الإيقاف في عميل الفلترة", UNVERIFIED,
                     "switch_locked مفعّل لكن auto_connect غير مضبوط "
                     "(Cloudflare تطلب ضبطه مع القفل)")
    return _item("قفل مفتاح الإيقاف في عميل الفلترة", PASS,
                 f"switch_locked=true, auto_connect={auto}")


def _warp_uninstall_protection() -> dict[str, str]:
    from . import warp
    if not warp.installed():
        return _item("حماية إلغاء تثبيت عميل الفلترة", FAIL, "العميل غير مثبّت")
    info = warp.uninstall_protection()
    if not info["known"]:
        return _item("حماية إلغاء تثبيت عميل الفلترة", UNVERIFIED,
                     "لا يمكن استعلام الحالة من الجهاز - تُضبط من لوحة Cloudflare "
                     "(Settings > WARP Client > Uninstall protection)")
    return _item("حماية إلغاء تثبيت عميل الفلترة",
                 PASS if info["enabled"] else FAIL, info["raw"][:120])


def _our_service_state() -> dict[str, str]:
    rc, out, err = run(["sc.exe", "query", SERVICE_NAME])
    if rc != 0:
        return _item("خدمة درع المدرسة تعمل", FAIL, "الخدمة غير مثبّتة")
    if "RUNNING" not in out.upper():
        return _item("خدمة درع المدرسة تعمل", FAIL, "الخدمة متوقفة")
    return _item("خدمة درع المدرسة تعمل", PASS, "RUNNING")


def _service_stop_protection() -> dict[str, str]:
    sddl = _service_sdl(SERVICE_NAME)
    can = _users_can_stop(sddl)
    if can is None:
        return _item("حساب عادي لا يستطيع إيقاف الخدمة", UNVERIFIED,
                     "تعذّر قراءة الوصف الأمني للخدمة")
    if can:
        return _item("حساب عادي لا يستطيع إيقاف الخدمة", FAIL,
                     "الوصف الأمني يمنح مجموعة عامة صلاحية الإيقاف")
    return _item("حساب عادي لا يستطيع إيقاف الخدمة", PASS, sddl[:120])


def _secure_dir_protection() -> dict[str, str]:
    if not SECURE_DIR.exists():
        return _item("ملفات الإدارة محمية بـ ACL", UNVERIFIED, "المجلد الآمن غير موجود")
    rc, out, err = run(["icacls", str(SECURE_DIR)])
    if rc != 0:
        return _item("ملفات الإدارة محمية بـ ACL", UNVERIFIED, (err or out)[:120])
    lowered = out.lower()
    leaked = [tok for tok in ("\\users", "everyone", "authenticated users")
              if tok in lowered]
    if leaked:
        return _item("ملفات الإدارة محمية بـ ACL", FAIL,
                     "وصول عام إلى مجلد الأسرار: " + ", ".join(leaked))
    return _item("ملفات الإدارة محمية بـ ACL", PASS, "SYSTEM و Administrators فقط")


def _firewall_state() -> dict[str, str]:
    expected = len(firewall_rules())
    if expected == 0:
        return _item("قواعد حجب تجاوز الفلترة", UNVERIFIED, "التشديد الشبكي مُطفأ بالسياسة")
    rc, out, err = run(["netsh", "advfirewall", "firewall", "show", "rule",
                        "name=all"], timeout=60)
    if rc != 0:
        return _item("قواعد حجب تجاوز الفلترة", UNVERIFIED, (err or out)[:120])
    found = out.count(FW_PREFIX)
    if found == 0:
        return _item("قواعد حجب تجاوز الفلترة", FAIL, "لم تُطبَّق أي قاعدة")
    if found < expected:
        return _item("قواعد حجب تجاوز الفلترة", UNVERIFIED,
                     f"{found} من {expected} قاعدة مطبّقة")
    return _item("قواعد حجب تجاوز الفلترة", PASS, f"{found} قاعدة مطبّقة")


def _system_doh_state() -> dict[str, str]:
    if not load_policy().get("disable_system_doh", True):
        return _item("تعطيل DNS المشفّر في النظام", UNVERIFIED, "مُطفأ بالسياسة")
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
        ) as key:
            value, _ = winreg.QueryValueEx(key, "EnableAutoDoh")
            return _item("تعطيل DNS المشفّر في النظام",
                         PASS if value == 0 else FAIL, f"EnableAutoDoh={value}")
    except OSError:
        return _item("تعطيل DNS المشفّر في النظام", FAIL, "القيمة غير مضبوطة")


def tamper_report() -> dict[str, Any]:
    items = [
        _our_service_state(),
        _service_stop_protection(),
        _warp_switch_locked(),
        _warp_uninstall_protection(),
        _student_is_admin(),
        _secure_dir_protection(),
        _firewall_state(),
        _system_doh_state(),
    ]
    return {"items": items}
