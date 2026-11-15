"""التعامل مع عميل Cloudflare One (WARP) عبر warp-cli وملف mdm.xml."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

from .paths import WARP_MDM_FILE, warp_cli
from .winutil import run


def installed() -> bool:
    return warp_cli() is not None


def _cli(*args: str, timeout: int = 20) -> tuple[int, str, str]:
    exe = warp_cli()
    if exe is None:
        return 127, "", "warp-cli not installed"
    return run([exe, *args], timeout=timeout)


def status() -> dict[str, Any]:
    """حالة الاتصال. يرجع {'ok', 'raw', 'connected'}."""
    rc, out, err = _cli("--accept-tos", "status")
    text = (out or err or "")
    connected = bool(re.search(r"Status update:\s*Connected", text, re.I)) or \
        bool(re.search(r"\bConnected\b", text, re.I)) and "Disconnected" not in text
    return {"ok": rc == 0, "connected": connected, "raw": text}


def registration() -> dict[str, Any]:
    """هل الجهاز مسجّل ضمن مؤسسة Zero Trust؟"""
    for args in (("--accept-tos", "registration", "show"), ("--accept-tos", "account")):
        rc, out, err = _cli(*args)
        text = out or err
        if rc == 0 and text:
            # "Account type: Team" ليس اسم المؤسسة. الاسم في سطر Organization
            # وحده؛ أي سطر آخر يُهمل وإلا قارنّا "Team" باسم المدرسة.
            org = None
            m = re.search(r"^\s*(?:Organization|Team\s*name)\s*:\s*(\S+)",
                          text, re.I | re.M)
            if m:
                org = m.group(1).strip()
            managed = bool(org) or bool(
                re.search(r"^\s*Account type\s*:\s*Team\b", text, re.I | re.M))
            return {"ok": True, "raw": text, "organization": org,
                    "team_managed": managed}
    return {"ok": False, "raw": "", "organization": None, "team_managed": False}


def settings_raw() -> str:
    rc, out, err = _cli("--accept-tos", "settings")
    return out or err


def uninstall_protection() -> dict[str, Any]:
    """حالة حماية إلغاء التثبيت. تُدار من لوحة Cloudflare؛ قد لا يوفر CLI استعلامًا."""
    for args in (("--accept-tos", "uninstall-protection", "status"),
                 ("--accept-tos", "uninstall-protection", "show")):
        rc, out, err = _cli(*args)
        text = (out or err).strip()
        if rc == 0 and text and "unknown" not in text.lower() and "error" not in text.lower():
            enabled = bool(re.search(r"\b(enabled|on|locked|true)\b", text, re.I))
            return {"known": True, "enabled": enabled, "raw": text}
    # fallback: تظهر ضمن settings في بعض الإصدارات
    s = settings_raw()
    m = re.search(r"uninstall[_ -]?protection\s*[:=]\s*(\w+)", s, re.I)
    if m:
        return {"known": True, "enabled": m.group(1).lower() in ("true", "on", "enabled"),
                "raw": m.group(0)}
    return {"known": False, "enabled": False, "raw": ""}


def read_mdm() -> dict[str, Any]:
    """يقرأ ملف mdm.xml في ProgramData/Cloudflare (صيغة plist dict)."""
    if not WARP_MDM_FILE.exists():
        return {}
    try:
        text = WARP_MDM_FILE.read_text(encoding="utf-8-sig", errors="replace")
        if "<dict>" not in text:
            return {}
        if not text.lstrip().startswith("<?xml"):
            text = "<?xml version='1.0' encoding='UTF-8'?>" + text
        root = ET.fromstring(text)
        node = root if root.tag == "dict" else (root.find(".//dict") or ET.Element("dict"))
        out: dict[str, Any] = {}
        key = None
        for child in list(node):
            if child.tag == "key":
                key = (child.text or "").strip()
            elif key is not None:
                if child.tag == "true":
                    out[key] = True
                elif child.tag == "false":
                    out[key] = False
                elif child.tag == "integer":
                    out[key] = int((child.text or "0").strip())
                else:
                    out[key] = (child.text or "").strip()
                key = None
        return out
    except (OSError, ET.ParseError, ValueError):
        return {}


def write_mdm(organization: str, *, switch_locked: bool = True,
              auto_connect: int = 1, service_mode: str = "warp",
              support_url: str = "", onboarding: bool = False,
              auth_client_id: str = "", auth_client_secret: str = "") -> None:
    """يكتب إعدادات العميل المُدارة.

    مع توكن الخدمة (auth_client_id/secret) يسجّل الجهاز نفسه تلقائيًا بلا
    تسجيل دخول. الملف يُحفظ في مجلد تقرؤه مجموعة Users فقط، ولا يُكتب
    التوكن إلا إذا مُرّر صراحةً.
    """
    from xml.sax.saxutils import escape
    organization = escape(organization)
    support_url = escape(support_url)
    auth_client_id = escape(auth_client_id)
    auth_client_secret = escape(auth_client_secret)
    WARP_MDM_FILE.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
        "<dict>",
        "  <key>organization</key>",
        f"  <string>{organization}</string>",
        "  <key>switch_locked</key>",
        f"  <{'true' if switch_locked else 'false'}/>",
        "  <key>auto_connect</key>",
        f"  <integer>{auto_connect}</integer>",
        "  <key>service_mode</key>",
        f"  <string>{service_mode}</string>",
        "  <key>onboarding</key>",
        f"  <{'true' if onboarding else 'false'}/>",
    ]
    if support_url:
        lines += ["  <key>support_url</key>", f"  <string>{support_url}</string>"]
    if auth_client_id and auth_client_secret:
        lines += ["  <key>auth_client_id</key>", f"  <string>{auth_client_id}</string>",
                  "  <key>auth_client_secret</key>",
                  f"  <string>{auth_client_secret}</string>"]
    lines.append("</dict>")
    WARP_MDM_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")


def connect() -> bool:
    rc, _, _ = _cli("--accept-tos", "connect")
    return rc == 0


def reconnect() -> bool:
    """فصل ثم وصل: يجعل العميل يعيد فرض خادم أسمائه على بطاقات الشبكة."""
    import time
    _cli("--accept-tos", "disconnect", timeout=30)
    time.sleep(3)
    return connect()
