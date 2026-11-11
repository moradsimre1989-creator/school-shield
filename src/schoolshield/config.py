"""سياسة المدرسة: نطاقات الاختبار، المواقع التعليمية، وخيارات التشديد."""
from __future__ import annotations

import json
from typing import Any

from .paths import POLICY_FILE, ensure_dirs

# عناوين صفحة الحجب في Cloudflare Gateway (موثقة رسميًا)
CF_BLOCK_IPS = {"162.159.36.12", "162.159.46.12"}
# عند تعطيل صفحة الحجب يرد Gateway بـ 0.0.0.0 / ::
NULL_IPS = {"0.0.0.0", "::"}

DEFAULT_POLICY: dict[str, Any] = {
    "organization": "",  # اسم فريق Cloudflare Zero Trust - يُملأ عند الإعداد
    "gateway_doh_subdomain": "",

    # نطاقات اختبار رسمية من Cloudflare (فئات أمنية فقط - موثقة)
    "probe_official": [
        "malware.testcategory.com",
        "phishing.testcategory.com",
        "anonymizer.testcategory.com",
    ],
    # نطاقات اختبار مُستنتجة من قاعدة Cloudflare نفسها، غير مذكورة في الجدول الرسمي
    # تُعرض نتيجتها كـ"إضافية" ولا تُسقط الفحص وحدها
    "probe_category_guess": [
        "adultthemes.testcategory.com",
        "nudity.testcategory.com",
        "pornography.testcategory.com",
        "violence.testcategory.com",
    ],
    # فحص حقيقي: نطاقات إباحية معروفة. الفحص عبر DNS فقط - لا يُفتح أي محتوى
    "probe_adult": [
        "pornhub.com",
        "xvideos.com",
        "xnxx.com",
        "xhamster.com",
    ],
    # نطاقات عنف دموي معروفة (قد تكون معطّلة أصلًا - نميّز NXDOMAIN عن الحجب)
    "probe_violence": [
        "theync.com",
        "kaotic.com",
        "documentingreality.com",
    ],
    # مواقع يجب أن تبقى شغّالة
    "probe_education": [
        "www.google.com",
        "www.canva.com",
        "kahoot.it",
        "wordwall.net",
        "app.genial.ly",
        "www.tinkercad.com",
        "education.minecraft.net",
        "classroom.google.com",
        "edu.gov.il",
    ],
    # خيارات التشديد
    "enforce_browser_policies": True,
    "disable_system_doh": True,
    "block_public_dns_ips": True,
    "block_vpn_ports": True,
    "youtube_restrict_level": 2,  # 1 = متوسط، 2 = صارم
    "watchdog_interval_seconds": 60,
    # عناوين DNS عامة تُحجب لمنع تجاوز الفلترة (Cloudflare مستثنى لأن العميل يستخدمه)
    "public_dns_blocklist": [
        "8.8.8.8", "8.8.4.4",          # Google
        "9.9.9.9", "149.112.112.112",  # Quad9
        "208.67.222.222", "208.67.220.220",  # OpenDNS
        "94.140.14.14", "94.140.15.15",      # AdGuard
        "76.76.2.0", "76.76.10.0",           # Control D
        "185.228.168.9", "185.228.169.9",    # CleanBrowsing
    ],
    "vpn_ports": [
        {"proto": "UDP", "port": "1194"},   # OpenVPN
        {"proto": "UDP", "port": "51820"},  # WireGuard
        {"proto": "UDP", "port": "500"},    # IKE
        {"proto": "UDP", "port": "4500"},   # IPsec NAT-T
        {"proto": "TCP", "port": "1723"},   # PPTP
        {"proto": "TCP", "port": "853"},    # DNS over TLS
        {"proto": "UDP", "port": "853"},
    ],
}


def load_policy() -> dict[str, Any]:
    ensure_dirs()
    policy = dict(DEFAULT_POLICY)
    if POLICY_FILE.exists():
        try:
            policy.update(json.loads(POLICY_FILE.read_text(encoding="utf-8-sig")))
        except (OSError, ValueError):
            pass
    return policy


def save_policy(policy: dict[str, Any]) -> None:
    ensure_dirs()
    POLICY_FILE.write_text(
        json.dumps(policy, ensure_ascii=False, indent=2), encoding="utf-8"
    )
