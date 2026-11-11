"""تشكيل النص العربي لـ Tk (Tk لا يصل الحروف ولا يطبّق الاتجاه تلقائيًا).

ملاحظة عملية مهمة: إذا بدأ النص برمز أو إيموجي، يستنتج خوارزم bidi اتجاهًا
من اليسار إلى اليمين فينعكس السطر كله. لذلك نفرض الاتجاه RTL دائمًا.
"""
from __future__ import annotations

try:
    import arabic_reshaper
    from bidi.algorithm import get_display

    _READY = True
except Exception:  # pragma: no cover
    _READY = False


def _display(text: str) -> str:
    try:
        return get_display(text, base_dir="R")
    except TypeError:  # إصدارات لا تدعم base_dir
        return get_display(text)


def ar(text: str) -> str:
    """يرجع النص جاهزًا للعرض من اليمين إلى اليسار بحروف موصولة."""
    if not _READY or not text:
        return text
    try:
        return _display(arabic_reshaper.reshape(text))
    except Exception:
        return text


def available() -> bool:
    return _READY
