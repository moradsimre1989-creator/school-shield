"""فحص DNS حقيقي. لا يُفتح أي محتوى إباحي - الاستعلام يقف عند طبقة الأسماء.

درس من الميدان: على ويندوز مع نفق WARP، قد لا تجد مكتبة dnspython أي خادم
أسماء صالح في الريجستري، فتفشل كل الاستعلامات ويبدو الجهاز بلا إنترنت بينما
المتصفح يعمل. لذلك نكتشف الخوادم من أكثر من مصدر، ونتحقق أن الخادم يُجيب
فعلًا قبل الاعتماد عليه، ونسقط أخيرًا إلى محلّل ويندوز نفسه.
"""
from __future__ import annotations

import ipaddress
import socket
import sys
import threading
from typing import Any

import dns.exception
import dns.rdatatype
import dns.resolver

from .config import CF_BLOCK_IPS, NULL_IPS

BLOCKED = "blocked"        # Gateway أعاد صفحة حجب أو عنوانًا صفريًا أو REFUSED
ALLOWED = "allowed"        # عنوان حقيقي -> غير محجوب
INCONCLUSIVE = "unknown"   # غير حاسم - لا يُحتسب حجبًا ولا سماحًا
NO_RESOLVER = "no_resolver"  # لا يوجد خادم أسماء صالح على الجهاز أصلًا

CONTROL_DOMAIN = "www.google.com"            # نطاق يجب أن يُجيب دائمًا
WARP_LOOPBACK = ("127.0.2.2", "127.0.2.3")   # خادم WARP المحلي
SYSTEM_DETAIL = "عبر محلّل Windows"

_LOCK = threading.Lock()
_CACHED: "dns.resolver.Resolver | None" = None
_PROBED = False


def _clean(raw: object) -> str | None:
    """يُسقط العناوين التي لا تصلح خادم أسماء ويوحّد الصيغة."""
    text = str(raw).strip().split("%")[0]
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if addr.is_link_local or addr.is_unspecified or addr.is_multicast:
        return None
    if addr.version == 6 and str(addr).lower().startswith("fec0"):
        return None
    return str(addr)


def _candidate_nameservers() -> list[str]:
    found: list[str] = []

    def add(items) -> None:
        for raw in items:
            ns = _clean(raw)
            if ns and ns not in found:
                found.append(ns)

    try:  # 1) ما يراه dnspython في الريجستري
        add(dns.resolver.Resolver(configure=True).nameservers)
    except Exception:
        pass
    if sys.platform == "win32":  # 2) واجهة IP Helper - ترى محوّل WARP
        try:
            import dns.win32util as win32util
            previous = win32util._config_method
            try:
                win32util.set_config_method(win32util.ConfigMethod.Win32)
                add(win32util.get_dns_info().nameservers)
            finally:
                win32util.set_config_method(previous)
        except Exception:
            pass
    add(WARP_LOOPBACK)  # 3) خادم WARP المحلي الثابت
    return found


def _answers(nameserver: str, timeout: float) -> bool:
    probe = dns.resolver.Resolver(configure=False)
    probe.nameservers = [nameserver]
    probe.timeout = probe.lifetime = timeout
    try:
        probe.resolve(CONTROL_DOMAIN, "A", raise_on_no_answer=False)
        return True
    except dns.exception.DNSException:
        return False
    except OSError:
        return False


def usable_resolver(probe_timeout: float = 2.5,
                    refresh: bool = False) -> "dns.resolver.Resolver | None":
    """خادم أسماء مُثبت أنه يُجيب، أو None إذا لم يوجد أي خادم صالح."""
    global _CACHED, _PROBED
    with _LOCK:
        if _PROBED and not refresh:
            return _CACHED
        good = [ns for ns in _candidate_nameservers() if _answers(ns, probe_timeout)]
        _PROBED = True
        if not good:
            _CACHED = None
            return None
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = good
        resolver.timeout = 2.5                       # لكل خادم
        resolver.lifetime = max(6.0, 2.5 * len(good))  # لا تُستهلك المهلة على خادم ميت
        _CACHED = resolver
        return resolver


def resolver_diagnostics() -> dict[str, Any]:
    resolver = usable_resolver()
    return {"ok": resolver is not None,
            "nameservers": list(resolver.nameservers) if resolver else [],
            "candidates": _candidate_nameservers()}


def _classify(ips: list[str], cnames: list[str], detail: str = "") -> dict[str, Any]:
    if set(ips) & CF_BLOCK_IPS:
        return {"state": BLOCKED, "ips": ips, "cnames": cnames,
                "detail": "صفحة حجب Cloudflare"}
    if ips and set(ips) <= NULL_IPS:
        return {"state": BLOCKED, "ips": ips, "cnames": cnames,
                "detail": "عنوان صفري - حجب بدون صفحة"}
    return {"state": ALLOWED, "ips": ips, "cnames": cnames, "detail": detail}


def _via_system(domain: str) -> dict[str, Any]:
    """آخر ملاذ: محلّل ويندوز نفسه - يحترم قواعد WARP لكنه لا يعطي CNAME."""
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return {"state": INCONCLUSIVE, "ips": [], "cnames": [],
                "detail": f"getaddrinfo {exc.errno}"}
    except OSError as exc:
        return {"state": INCONCLUSIVE, "ips": [], "cnames": [], "detail": str(exc)[:80]}
    ips = sorted({info[4][0] for info in infos})
    if not ips:
        return {"state": INCONCLUSIVE, "ips": [], "cnames": [], "detail": "لا يوجد عنوان"}
    return _classify(ips, [], SYSTEM_DETAIL)


def resolve(domain: str, timeout: float = 4.0) -> dict[str, Any]:
    """استعلام A واحد مع تصنيف النتيجة إلى محجوب/مسموح/غير حاسم."""
    resolver = usable_resolver()
    if resolver is None:
        result = _via_system(domain)
        if result["state"] == INCONCLUSIVE:
            return {"state": NO_RESOLVER, "ips": [], "cnames": [],
                    "detail": "لا يوجد خادم أسماء صالح على الجهاز"}
        return result
    try:
        ans = resolver.resolve(domain, "A", raise_on_no_answer=False)
        ips = sorted({x.address for x in ans if hasattr(x, "address")})
        cnames: list[str] = []
        try:
            for rrset in ans.response.answer:
                if rrset.rdtype == dns.rdatatype.CNAME:
                    cnames += [str(x.target).rstrip(".") for x in rrset]
        except Exception:
            pass
        if not ips:
            return {"state": INCONCLUSIVE, "ips": [], "cnames": cnames,
                    "detail": "لا يوجد سجل A"}
        return _classify(ips, cnames)
    except dns.resolver.NXDOMAIN:
        return {"state": INCONCLUSIVE, "ips": [], "cnames": [],
                "detail": "NXDOMAIN - النطاق غير موجود"}
    except dns.resolver.NoNameservers as exc:
        message = str(exc)
        if "REFUSED" in message.upper():
            return {"state": BLOCKED, "ips": [], "cnames": [], "detail": message[:160]}
        usable_resolver(refresh=True)   # الخادم مات - أعد الاستكشاف
        return _via_system(domain)
    except (dns.exception.Timeout, dns.exception.DNSException) as exc:
        return {"state": INCONCLUSIVE, "ips": [], "cnames": [],
                "detail": f"{type(exc).__name__}: {str(exc)[:120]}"}
    except OSError as exc:              # winreg أو socket - لا تُسقط الفحص كله
        return {"state": INCONCLUSIVE, "ips": [], "cnames": [],
                "detail": f"OSError: {exc}"}


def safesearch_target(domain: str) -> dict[str, Any]:
    """يتحقق من إعادة توجيه البحث الآمن عبر CNAME (آلية Gateway الرسمية)."""
    res = resolve(domain)
    return {"cnames": res.get("cnames", []), "ips": res.get("ips", []),
            "state": res.get("state"), "detail": res.get("detail", ""),
            "raw": " ".join(res.get("cnames", [])).lower()}
