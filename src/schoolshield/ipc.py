"""قناة اتصال محلية بين الواجهة والخدمة.

البروتوكول مُقيَّد بثلاثة أوامر فقط: STATUS و VERIFY و ENFORCE.
لا يوجد أمر لتعطيل الحماية - لا في البروتوكول ولا في الخدمة. الطالب لا يستطيع
إيقاف الحماية عبر هذه القناة حتى لو كتب عميلًا خاصًا به.

الإيقاف الإداري يمر عبر ملف داخل المجلد المحمي بـ ACL، أي يتطلب صلاحيات
Administrator على مستوى النظام - لا كلمة مرور فقط.
"""
from __future__ import annotations

import json
import socket
from typing import Any

from .paths import IPC_HOST, IPC_PORT

ALLOWED_COMMANDS = ("STATUS", "VERIFY", "ENFORCE")
_MAX_PAYLOAD = 256 * 1024


def request(command: str, timeout: float = 90.0) -> dict[str, Any]:
    """يرسل أمرًا إلى الخدمة ويرجع الرد JSON."""
    command = command.strip().upper()
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f"أمر غير مسموح: {command}")
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
