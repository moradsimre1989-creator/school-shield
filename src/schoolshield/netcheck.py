"""فحص DNS حقيقي. لا يُفتح أي محتوى إباحي - الاستعلام يقف عند طبقة الأسماء."""
from __future__ import annotations

from typing import Any

import dns.exception
import dns.rdatatype
import dns.resolver

from .config import CF_BLOCK_IPS, NULL_IPS

# نتائج ممكنة لكل نطاق
BLOCKED = "blocked"        # Gateway أعاد صفحة حجب أو عنوانًا صفريًا أو REFUSED
ALLOWED = "allowed"        # عنوان حقيقي -> غير محجوب
INCONCLUSIVE = "unknown"   # النطاق غير موجود أصلًا أو خطأ شبكة -> لا يُحتسب حجبًا


def resolve(domain: str, timeout: float = 4.0) -> dict[str, Any]:
    """استعلام A واحد مع تصنيف النتيجة إلى محجوب/مسموح/غير حاسم."""
    r = dns.resolver.Resolver(configure=True)
    r.lifetime = timeout
    r.timeout = timeout
    try:
        ans = r.resolve(domain, "A", raise_on_no_answer=False)
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
        if set(ips) & CF_BLOCK_IPS:
            return {"state": BLOCKED, "ips": ips, "cnames": cnames,
                    "detail": "صفحة حجب Cloudflare"}
        if set(ips) <= NULL_IPS:
            return {"state": BLOCKED, "ips": ips, "cnames": cnames,
                    "detail": "عنوان صفري - حجب بدون صفحة"}
        return {"state": ALLOWED, "ips": ips, "cnames": cnames, "detail": ""}
    except dns.resolver.NXDOMAIN:
        return {"state": INCONCLUSIVE, "ips": [], "cnames": [],
                "detail": "NXDOMAIN - النطاق غير موجود"}
    except dns.resolver.NoNameservers as exc:
        # REFUSED من Gateway يظهر هنا، ويعني حجبًا بدون صفحة
        msg = str(exc)
        state = BLOCKED if "REFUSED" in msg.upper() else INCONCLUSIVE
        return {"state": state, "ips": [], "cnames": [], "detail": msg[:160]}
    except (dns.exception.Timeout, dns.exception.DNSException) as exc:
        return {"state": INCONCLUSIVE, "ips": [], "cnames": [],
                "detail": f"{type(exc).__name__}: {str(exc)[:120]}"}


def safesearch_target(domain: str) -> dict[str, Any]:
    """يتحقق من إعادة توجيه البحث الآمن عبر CNAME (آلية Gateway الرسمية)."""
    res = resolve(domain)
    joined = " ".join(res.get("cnames", [])).lower()
    return {"cnames": res.get("cnames", []), "ips": res.get("ips", []), "raw": joined}
