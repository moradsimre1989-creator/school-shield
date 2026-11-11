"""محرّك التحقق: سبعة فحوص حقيقية.

القاعدة: المؤشر لا يصير أخضر إلا إذا نجحت كل الفحوص.
أي فحص لم يكتمل يُعرض كـ"غير متحقق" (كهرماني) ولا يُحتسب نجاحًا.
"""
from __future__ import annotations

import concurrent.futures as _cf
import datetime as _dt
import json
from typing import Any, Callable

from . import netcheck, warp
from .config import load_policy
from .netcheck import ALLOWED, BLOCKED
from .paths import PAUSE_FILE, STATUS_FILE, ensure_dirs
from .winutil import is_elevated

PASS = "pass"
FAIL = "fail"
UNVERIFIED = "unverified"

# الفحوص التي تُسقط المؤشر إلى الأحمر إن لم تنجح
CRITICAL = {"client", "registration", "adult_block", "education", "tamper"}


def _result(key: str, title: str, state: str, detail: str = "",
            items: list | None = None) -> dict[str, Any]:
    return {"key": key, "title": title, "state": state, "detail": detail,
            "items": items or [], "critical": key in CRITICAL}


def _batch(domains: list[str]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    if not domains:
        return out
    with _cf.ThreadPoolExecutor(max_workers=min(8, len(domains))) as ex:
        futs = {ex.submit(netcheck.resolve, d): d for d in domains}
        for fut in _cf.as_completed(futs):
            out[futs[fut]] = fut.result()
    return out


# ---------------------------- الفحوص ----------------------------

def check_client() -> dict[str, Any]:
    """1) عميل الفلترة مثبّت ويعمل ومتصل."""
    title = "عميل الفلترة مثبّت ومتصل"
    if not warp.installed():
        return _result("client", title, FAIL, "عميل Cloudflare One غير مثبّت على الجهاز")
    st = warp.status()
    if not st["ok"]:
        return _result("client", title, FAIL, "العميل مثبّت لكن خدمته لا تستجيب")
    if not st["connected"]:
        return _result("client", title, FAIL, "العميل غير متصل: " + st["raw"][:120])
    return _result("client", title, PASS, st["raw"][:120])


def check_registration() -> dict[str, Any]:
    """2) الجهاز مسجّل ضمن مؤسسة المدرسة وسياساتها."""
    title = "الجهاز مسجّل ضمن سياسة المدرسة"
    if not warp.installed():
        return _result("registration", title, FAIL, "العميل غير مثبّت")
    policy = load_policy()
    mdm = warp.read_mdm()
    reg = warp.registration()
    org_expected = (policy.get("organization") or "").strip()
    org_mdm = str(mdm.get("organization") or "").strip()
    parts = []
    if org_mdm:
        parts.append("mdm.xml: " + org_mdm)
    if reg.get("organization"):
        parts.append("client: " + str(reg["organization"]))
    detail = " | ".join(parts) or (reg.get("raw") or "")[:120]
    if not org_expected:
        return _result("registration", title, UNVERIFIED,
                       "اسم مؤسسة المدرسة غير مُعدّ في policy.json")
    if not reg.get("ok"):
        return _result("registration", title, FAIL, "لا يوجد تسجيل فعّال للجهاز")
    if org_mdm.lower() != org_expected.lower():
        return _result("registration", title, FAIL,
                       "إعداد العميل لا يطابق مؤسسة المدرسة (" + detail + ")")
    return _result("registration", title, PASS, detail)


def check_adult_block() -> dict[str, Any]:
    """3) حجب الإباحية - فحص DNS حقيقي على نطاقات مصنّفة فعلًا."""
    title = "حجب المواقع الإباحية"
    policy = load_policy()
    domains = list(policy["probe_adult"])
    res = _batch(domains)
    items = [dict({"domain": d}, **res[d]) for d in domains if d in res]
    blocked = [i for i in items if i["state"] == BLOCKED]
    allowed = [i for i in items if i["state"] == ALLOWED]
    extra = _batch(list(policy["probe_category_guess"]))
    items += [dict({"domain": d, "note": "نطاق اختبار غير موثّق رسميًا"}, **v)
              for d, v in extra.items()]
    if allowed:
        return _result("adult_block", title, FAIL,
                       "نطاقات غير محجوبة: " + ", ".join(i["domain"] for i in allowed), items)
    if not blocked:
        return _result("adult_block", title, UNVERIFIED,
                       "لم يكتمل أي استعلام DNS - تحقّق من الشبكة", items)
    if len(blocked) < len(domains):
        return _result("adult_block", title, UNVERIFIED,
                       f"محجوب {len(blocked)} من {len(domains)}، والباقي غير حاسم", items)
    return _result("adult_block", title, PASS,
                   f"كل النطاقات محجوبة ({len(blocked)}/{len(domains)})", items)


def check_violence_block() -> dict[str, Any]:
    """4) حجب العنف الدموي. NXDOMAIN لا يُعتبر حجبًا."""
    title = "حجب مواقع العنف"
    policy = load_policy()
    domains = list(policy["probe_violence"])
    res = _batch(domains)
    items = [dict({"domain": d}, **res[d]) for d in domains if d in res]
    allowed = [i for i in items if i["state"] == ALLOWED]
    blocked = [i for i in items if i["state"] == BLOCKED]
    if allowed:
        return _result("violence_block", title, FAIL,
                       "نطاقات غير محجوبة: " + ", ".join(i["domain"] for i in allowed), items)
    if not blocked:
        return _result("violence_block", title, UNVERIFIED,
                       "النطاقات غير حاسمة (غير موجودة أو تعذّر الاستعلام)", items)
    return _result("violence_block", title, PASS,
                   f"محجوب {len(blocked)}/{len(domains)}", items)


def _browser_policy_state() -> dict[str, str]:
    from .policies import audit_browser_policies
    report = audit_browser_policies()
    if not report:
        return {"state": UNVERIFIED, "detail": "تعذّر قراءة سجل السياسات"}
    bad = [k for k, v in report.items() if not v["ok"]]
    if bad:
        return {"state": FAIL, "detail": "قيم ناقصة: " + ", ".join(bad[:4])}
    return {"state": PASS, "detail": f"{len(report)} قيمة سياسة مطبّقة"}


def check_safesearch() -> dict[str, Any]:
    """5) فرض البحث الآمن ووضع YouTube المقيّد."""
    title = "فرض البحث الآمن و YouTube المقيّد"
    expectations = {
        "www.google.com": "forcesafesearch.google.com",
        "www.bing.com": "strict.bing.com",
        "www.youtube.com": "restrict",
    }
    items: list[dict[str, Any]] = []
    ok = 0
    missing: list[str] = []
    for domain, needle in expectations.items():
        info = netcheck.safesearch_target(domain)
        hit = needle in info["raw"]
        items.append({"domain": domain, "expected": needle, "cnames": info["cnames"],
                      "state": PASS if hit else FAIL})
        if hit:
            ok += 1
        else:
            missing.append(domain)
    reg = _browser_policy_state()
    items.append({"domain": "سياسات المتصفحات (Registry)", "state": reg["state"],
                  "detail": reg["detail"]})
    if ok == 0 and reg["state"] != PASS:
        return _result("safesearch", title, FAIL,
                       "لا DNS ولا سياسات المتصفح تفرض البحث الآمن", items)
    if ok < len(expectations) or reg["state"] != PASS:
        return _result("safesearch", title, UNVERIFIED,
                       "مفروض جزئيًا: " + (", ".join(missing) or reg["detail"]), items)
    return _result("safesearch", title, PASS, "مفروض عبر DNS وسياسات المتصفحات", items)


def check_education() -> dict[str, Any]:
    """6) المواقع التعليمية تعمل ولم تُحجب بالخطأ."""
    title = "المواقع التعليمية تعمل"
    policy = load_policy()
    domains = list(policy["probe_education"])
    res = _batch(domains)
    items = [dict({"domain": d}, **res[d]) for d in domains if d in res]
    wrongly_blocked = [i for i in items if i["state"] == BLOCKED]
    allowed = [i for i in items if i["state"] == ALLOWED]
    if wrongly_blocked:
        return _result("education", title, FAIL,
                       "محجوبة بالخطأ: " + ", ".join(i["domain"] for i in wrongly_blocked), items)
    if not allowed:
        return _result("education", title, UNVERIFIED, "تعذّر الوصول إلى خدمة الأسماء", items)
    if len(allowed) < len(domains):
        return _result("education", title, UNVERIFIED,
                       f"يعمل {len(allowed)} من {len(domains)}، والباقي غير حاسم", items)
    return _result("education", title, PASS, f"{len(allowed)}/{len(domains)} موقع يعمل", items)


def check_tamper_resistance() -> dict[str, Any]:
    """7) الطالب بحساب Windows عادي لا يستطيع تعطيل الحماية."""
    from .hardening import tamper_report
    title = "الطالب لا يستطيع تعطيل الحماية"
    rep = tamper_report()
    items = rep["items"]
    bad = [i for i in items if i["state"] == FAIL]
    unk = [i for i in items if i["state"] == UNVERIFIED]
    if bad:
        return _result("tamper", title, FAIL, "; ".join(i["title"] for i in bad), items)
    if unk:
        return _result("tamper", title, UNVERIFIED, "; ".join(i["title"] for i in unk), items)
    return _result("tamper", title, PASS, "كل قيود المنع مطبّقة", items)


ALL_CHECKS: tuple[Callable[[], dict[str, Any]], ...] = (
    check_client,
    check_registration,
    check_adult_block,
    check_violence_block,
    check_safesearch,
    check_education,
    check_tamper_resistance,
)


def pause_state() -> dict[str, Any]:
    """إيقاف إداري مؤقت - يُقرأ من ملف محمي بـ ACL للمديرين فقط."""
    try:
        data = json.loads(PAUSE_FILE.read_text(encoding="utf-8"))
        until = _dt.datetime.fromisoformat(data["until"])
        if until > _dt.datetime.now():
            return {"active": True, "until": data["until"], "by": data.get("by", "?")}
    except (OSError, ValueError, KeyError):
        pass
    return {"active": False}


def run_all() -> dict[str, Any]:
    results = [fn() for fn in ALL_CHECKS]
    any_fail = [r for r in results if r["state"] == FAIL]
    unverified = [r for r in results if r["state"] == UNVERIFIED]
    critical_not_pass = [r for r in results if r["critical"] and r["state"] != PASS]
    if any_fail or critical_not_pass:
        overall = "red"
    elif unverified:
        overall = "amber"
    else:
        overall = "green"
    paused = pause_state()
    if paused.get("active"):
        overall = "red"
    return {
        "overall": overall,
        "checked_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "elevated_scan": is_elevated(),
        "paused": paused,
        "summary": {
            "pass": sum(1 for r in results if r["state"] == PASS),
            "fail": len(any_fail),
            "unverified": len(unverified),
            "total": len(results),
        },
        "checks": results,
    }


def write_status(report: dict[str, Any]) -> bool:
    """يكتب تقرير الحالة. الخدمة (SYSTEM) هي من تكتبه عادةً.

    الحساب العادي لا يملك صلاحية الكتابة - وهذا مقصود - فلا نُسقط الفحص،
    بل نرجع False ونكتفي بعرض النتيجة.
    """
    try:
        ensure_dirs()
        tmp = STATUS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                       encoding="utf-8")
        tmp.replace(STATUS_FILE)
        return True
    except OSError:
        return False


def read_status() -> dict[str, Any] | None:
    try:
        return json.loads(STATUS_FILE.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None
