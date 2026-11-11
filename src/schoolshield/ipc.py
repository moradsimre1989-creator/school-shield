"""قناة اتصال محلية بين الواجهة والخدمة.

البروتوكول مُقيَّد بخمسة أوامر: STATUS و VERIFY و ENFORCE و PAUSE و RESUME.
الإيقاف والاستئناف يتطلبان كلمة مرور المدير، والخدمة (SYSTEM) هي من تتحقق
منها بتجزئة Argon2id. الطالب لا يملك الكلمة، ولا يستطيع قراءة تجزئتها لأن
ملفها محجوب عنه بـ ACL، ولا يستطيع تجاوز القناة لأنها على loopback فقط.
"""
from __future__ import annotations

import json
import socket
from typing import Any

from .paths import IPC_HOST, IPC_PORT

ALLOWED_COMMANDS = ("STATUS", "VERIFY", "ENFORCE", "PAUSE", "RESUME")
_MAX_PAYLOAD = 256 * 1024


def request(command: str, timeout: float = 90.0,
            password: str | None = None) -> dict[str, Any]:
    """يرسل أمرًا إلى الخدمة ويرجع الرد JSON."""
    command = command.strip().upper()
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f"أمر غير مسموح: {command}")
    if password is not None:
        command = command + "	" + password
    with socket.create_connection((IPC_HOST, IPC_PORT), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((command + "\n").encode("utf-8"))
        chunks = []
        total = 0
        while True:
            data = sock.recv(8192)
            if not data:
                break
            chunks.append(data)
            total += len(data)
            if total > _MAX_PAYLOAD:
                break
    raw = b"".join(chunks).decode("utf-8", errors="replace").strip()
    if not raw:
        raise ConnectionError("الخدمة لم تُرجع ردًا")
    return json.loads(raw)


def service_reachable(timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((IPC_HOST, IPC_PORT), timeout=timeout):
            return True
    except OSError:
        return False
