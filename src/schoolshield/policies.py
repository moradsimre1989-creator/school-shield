"""فرض سياسات Windows الرسمية (Registry Policies) لمنع تجاوز الفلترة.

كل ما هنا موثّق من المصنّعين:
  - Chrome/Edge: ForceGoogleSafeSearch، ForceYouTubeRestrict، DnsOverHttpsMode
  - Firefox: DNSOverHTTPS (Enabled=0، Locked=1)
  - Windows: Dnscache/EnableAutoDoh=0

الكتابة تحت HKLM\\SOFTWARE\\Policies تحتاج صلاحيات مدير، والحساب العادي
لا يملك صلاحية تعديلها - وهذا بالضبط ما يمنع الطالب من فك الفلترة.
"""
from __future__ import annotations

import winreg
from typing import Any, Iterable

from .config import load_policy

HKLM = winreg.HKEY_LOCAL_MACHINE
REG_DWORD = winreg.REG_DWORD
REG_SZ = winreg.REG_SZ


def policy_map() -> dict[str, list[tuple[str, int, Any]]]:
    """خريطة: مسار مفتاح -> [(الاسم، النوع، القيمة)]."""
    pol = load_policy()
    yt = int(pol.get("youtube_restrict_level", 2))
    chromium = [
        ("ForceGoogleSafeSearch", REG_DWORD, 1),
        ("ForceYouTubeRestrict", REG_DWORD, yt),
        ("DnsOverHttpsMode", REG_SZ, "off"),
        ("BuiltInDnsClientEnabled", REG_DWORD, 0),
        ("IncognitoModeAvailability", REG_DWORD, 1),
    ]
    edge = chromium + [("InPrivateModeAvailability", REG_DWORD, 1)]
    mapping: dict[str, list[tuple[str, int, Any]]] = {
        r"SOFTWARE\Policies\Google\Chrome": chromium,
        r"SOFTWARE\Policies\Microsoft\Edge": edge,
        r"SOFTWARE\Policies\Mozilla\Firefox": [
            ("DisablePrivateBrowsing", REG_DWORD, 1),
            ("BlockAboutConfig", REG_DWORD, 1),
        ],
        r"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS": [
            ("Enabled", REG_DWORD, 0),
            ("Locked", REG_DWORD, 1),
        ],
    }
    if pol.get("disable_system_doh", True):
        mapping[r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"] = [
            ("EnableAutoDoh", REG_DWORD, 0),
        ]
    return mapping


def _read(path: str, name: str) -> tuple[bool, Any]:
    try:
        with winreg.OpenKey(HKLM, path, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return True, value
    except OSError:
        return False, None


def audit_browser_policies() -> dict[str, dict[str, Any]]:
    """يقرأ كل القيم المتوقعة ويرجع تقريرًا بلا أي تعديل."""
    report: dict[str, dict[str, Any]] = {}
    for path, values in policy_map().items():
        for name, _rtype, expected in values:
            found, actual = _read(path, name)
            report[f"{path.rsplit(chr(92), 1)[-1]}/{name}"] = {
                "path": path, "name": name, "expected": expected,
                "actual": actual, "ok": found and actual == expected,
            }
    return report


def enforce_browser_policies() -> dict[str, Any]:
    """يكتب كل السياسات. يحتاج صلاحيات مدير (يعمل داخل الخدمة كـ SYSTEM)."""
    written, failed = 0, []
    for path, values in policy_map().items():
        try:
            with winreg.CreateKeyEx(HKLM, path, 0, winreg.KEY_SET_VALUE) as key:
                for name, rtype, value in values:
                    try:
                        winreg.SetValueEx(key, name, 0, rtype, value)
                        written += 1
                    except OSError as exc:
                        failed.append(f"{path}\\{name}: {exc}")
        except OSError as exc:
            failed.append(f"{path}: {exc}")
    return {"written": written, "failed": failed}


def iter_expected() -> Iterable[tuple[str, str, Any]]:
    for path, values in policy_map().items():
        for name, _rtype, expected in values:
            yield path, name, expected
