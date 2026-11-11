"""مسارات ثابتة للتطبيق. لا تُخزَّن أي أسرار في مجلد البرنامج القابل للقراءة."""
from __future__ import annotations

import os
from pathlib import Path

PROGRAM_DATA = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
DATA_DIR = PROGRAM_DATA / "SchoolShield"

# ملفات يقرأها الطالب (قراءة فقط) - لا تحتوي أسرارًا
STATUS_FILE = DATA_DIR / "status.json"
POLICY_FILE = DATA_DIR / "policy.json"
LOG_FILE = DATA_DIR / "logs" / "schoolshield.log"

# ملفات إدارية: ACL يمنع وصول Users تمامًا
SECURE_DIR = DATA_DIR / "secure"
ADMIN_FILE = SECURE_DIR / "admin.json"
PAUSE_FILE = SECURE_DIR / "pause.json"
AUDIT_FILE = SECURE_DIR / "audit.log"

# ملف إعدادات عميل Cloudflare المُدار
WARP_MDM_FILE = PROGRAM_DATA / "Cloudflare" / "mdm.xml"

IPC_HOST = "127.0.0.1"
IPC_PORT = 47811


def ensure_dirs() -> None:
    for d in (DATA_DIR, SECURE_DIR, LOG_FILE.parent):
        d.mkdir(parents=True, exist_ok=True)


def warp_cli() -> str | None:
    """يرجع مسار warp-cli.exe إن كان العميل مثبتًا."""
    candidates = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Cloudflare" / "Cloudflare WARP" / "warp-cli.exe",
        Path(r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe"),
        Path(r"C:\Program Files (x86)\Cloudflare\Cloudflare WARP\warp-cli.exe"),
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return None
