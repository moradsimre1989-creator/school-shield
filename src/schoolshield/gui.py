"""واجهة درع المدرسة: مؤشر واحد كبير وزر واحد.

ما يراه الطالب: الحالة وزر "تفعيل الحماية" فقط.
لا يوجد زر تعطيل، ولا إعدادات تقنية، ولا طريقة لإيقاف أي شيء من هنا.
"""
from __future__ import annotations

import threading
import tkinter as tk
from tkinter import font as tkfont
from tkinter import messagebox, ttk
from typing import Any

from . import APP_NAME_AR, __version__, auth, checks, ipc
from .arabic import ar
from .winutil import is_elevated

BG = "#0f172a"
CARD = "#1b2740"
TXT = "#eef2ff"
MUTED = "#93a4c8"
GREEN = "#16a34a"
RED = "#dc2626"
AMBER = "#d97706"
BLUE = "#2563eb"

STATE_LABELS = {
    "pass": ("ناجح", GREEN),
    "fail": ("فاشل", RED),
    "unverified": ("غير متحقق", AMBER),
}

# ملاحظة: لا نضع إيموجي داخل النص العربي - وجوده يُبدّل محرّك الخطوط في Tk
# فينعكس ترتيب السطر. الدائرة الملوّنة تُرسم على Canvas مستقل بدل ذلك.
OVERALL = {
    "green": ("الحماية مفعّلة", GREEN, "الفلترة شغّالة واختبارات الحجب ناجحة"),
    "red": ("الحماية غير مفعّلة", RED, "الفلترة متوقفة أو فشل اختبار أساسي"),
    "amber": ("الحماية غير مكتملة", AMBER, "بعض الاختبارات لم تكتمل - اضغط تفعيل الحماية"),
    "checking": ("جارٍ التحقق", BLUE, "تنفيذ اختبارات الحجب الحقيقية..."),
}


class ShieldApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME_AR} - School Shield {__version__}")
        self.configure(bg=BG)
        self.geometry("760x620")
        self.minsize(680, 560)
        self._busy = False
        self._fonts()
        self._build()
        self.after(200, lambda: self._load_cached())
        self.after(5000, self._tick)

    # ---------------- بناء الواجهة ----------------
    def _fonts(self) -> None:
        family = "Segoe UI"
        self.f_title = tkfont.Font(family=family, size=26, weight="bold")
        self.f_status = tkfont.Font(family=family, size=30, weight="bold")
        self.f_body = tkfont.Font(family=family, size=12)
        self.f_small = tkfont.Font(family=family, size=10)

    def _build(self) -> None:
        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", pady=(18, 6), padx=22)
        tk.Label(header, text=ar(APP_NAME_AR), bg=BG, fg=TXT,
                 font=self.f_title, anchor="e").pack(fill="x")
        tk.Label(header, text=ar("تصفّح آمن لطلابنا"), bg=BG, fg=MUTED,
                 font=self.f_small, anchor="e").pack(fill="x")

        card = tk.Frame(self, bg=CARD, bd=0, highlightthickness=0)
        card.pack(fill="x", padx=22, pady=12)
        row = tk.Frame(card, bg=CARD)
        row.pack(pady=(20, 4))
        self.lbl_status = tk.Label(row, text=ar(OVERALL["red"][0]), bg=CARD, fg=RED,
                                   font=self.f_status)
        self.lbl_status.pack(side="left", padx=(14, 0))
        self.dot = tk.Canvas(row, width=46, height=46, bg=CARD, highlightthickness=0)
        self.dot_id = self.dot.create_oval(6, 6, 42, 42, fill=RED, outline="")
        self.dot.pack(side="left")
        self.lbl_sub = tk.Label(card, text=ar(OVERALL["red"][2]), bg=CARD, fg=MUTED,
                                font=self.f_body, pady=(0))
        self.lbl_sub.pack(fill="x", pady=(0, 14))

        self.btn = tk.Button(self, text=ar("تفعيل الحماية"), command=self._activate,
                             bg=BLUE, fg="white", font=self.f_body, relief="flat",
                             activebackground="#1d4ed8", activeforeground="white",
                             cursor="hand2", pady=12)
        self.btn.pack(fill="x", padx=22, pady=(0, 8))

        # زر الإيقاف: يفتح طلب صلاحيات Windows ثم يسأل عن كلمة مرور المدير.
        # الطالب بحساب عادي لا يتجاوز طلب الصلاحيات، فالزر لا يفيده.
        self.btn_off = tk.Button(self, text=ar("إيقاف الحماية (للمدير)"),
                                 command=self._toggle_off, bg=CARD, fg=MUTED,
                                 font=self.f_small, relief="flat", cursor="hand2",
                                 activebackground="#24324f", activeforeground=TXT,
                                 pady=8)
        self.btn_off.pack(fill="x", padx=22, pady=(0, 10))

        tk.Label(self, text=ar("نتائج الفحص"), bg=BG, fg=MUTED, font=self.f_small,
                 anchor="e").pack(fill="x", padx=22)
        wrap = tk.Frame(self, bg=BG)
        wrap.pack(fill="both", expand=True, padx=22, pady=(4, 8))
        self.details = tk.Text(wrap, bg=CARD, fg=TXT, font=self.f_body, wrap="word",
                               relief="flat", highlightthickness=0, padx=12, pady=10,
                               state="disabled", cursor="arrow")
        self.details.tag_configure("line", justify="right", spacing1=2, spacing3=2)
        self.details.tag_configure("pass", foreground="#86efac", justify="right")
        self.details.tag_configure("fail", foreground="#fca5a5", justify="right")
        self.details.tag_configure("unverified", foreground="#fcd34d", justify="right")
        self.details.tag_configure("detail", foreground=MUTED, justify="right",
                                   font=self.f_small, spacing3=6)
        scroll = ttk.Scrollbar(wrap, orient="vertical", command=self.details.yview)
        self.details.configure(yscrollcommand=scroll.set)
        scroll.pack(side="left", fill="y")
        self.details.pack(side="right", fill="both", expand=True)

        footer = tk.Frame(self, bg=BG)
        footer.pack(fill="x", padx=22, pady=(0, 16))
        self.lbl_foot = tk.Label(footer, text="", bg=BG, fg=MUTED,
                                 font=self.f_small, anchor="e")
        self.lbl_foot.pack(side="right", fill="x", expand=True)
        tk.Button(footer, text=ar("دخول المدير"), command=self._admin_login,
                  bg=CARD, fg=MUTED, font=self.f_small, relief="flat",
                  cursor="hand2").pack(side="left")

    # ---------------- الحالة ----------------
    def _set_overall(self, key: str) -> None:
        text, color, sub = OVERALL[key]
        self.lbl_status.configure(text=ar(text), fg=color)
        self.dot.itemconfigure(self.dot_id, fill=color)
        self.lbl_sub.configure(text=ar(sub))

    def _write_details(self, items: list[dict[str, Any]]) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", tk.END)
        for item in items:
            label, _c = STATE_LABELS.get(item["state"], ("؟", MUTED))
            mark = {"pass": "✔", "fail": "✘", "unverified": "⚠"}.get(item["state"], "•")
            line = ar(f"{item['title']} — {label} {mark}")
            self.details.insert(tk.END, line + "\n", item["state"])
            if item.get("detail"):
                self.details.insert(tk.END, ar(item["detail"][:220]) + "\n", "detail")
        self.details.configure(state="disabled")

    def _load_cached(self) -> None:
        report = checks.read_status()
        if report:
            self._render(report)
        else:
            self._set_overall("red")
            self.lbl_foot.configure(text=ar("لا يوجد فحص سابق - اضغط تفعيل الحماية"))

    def _render(self, report: dict[str, Any]) -> None:
        self._set_overall(report.get("overall", "red"))
        self._write_details(report.get("checks", []))
        self._sync_off_button(report)
        summary = report.get("summary", {})
        paused = report.get("paused", {})
        foot = ar(
            f"آخر فحص: {report.get('checked_at', '—')}  |  ناجح {summary.get('pass', 0)}"
            f" / فاشل {summary.get('fail', 0)} / غير متحقق {summary.get('unverified', 0)}"
        )
        if paused.get("active"):
            foot = ar(f"⚠ إيقاف إداري مؤقت حتى {paused.get('until')}")
        self.lbl_foot.configure(text=foot)

    # ---------------- الأفعال ----------------
    def _activate(self) -> None:
        """زر واحد: يثبّت إن لم يكن مثبّتًا، ثم يفحص ويعرض النتيجة."""
        if self._busy:
            return
        if self._needs_setup():
            self._set_overall("checking")
            self.lbl_foot.configure(text=ar("التثبيت لأول مرة..."))
            self._run_setup()
            return
        self._busy = True
        self.btn.configure(state="disabled", text=ar("جارٍ التحقق..."))
        self._set_overall("checking")
        self._write_details([])
        threading.Thread(target=self._activate_worker, daemon=True).start()

    def _needs_setup(self) -> bool:
        from . import setup_win
        return not setup_win.installed()

    def _run_setup(self) -> None:
        """تثبيت ذاتي بضغطة واحدة: يطلب صلاحيات Windows ثم ينفّذ كل شيء."""
        import ctypes
        from . import setup_win
        org = setup_win.bundled_organization()
        params = "--setup" + (f' "{org}"' if org else "")
        try:
            rc = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", str(setup_win.self_path()), params, None, 1)
        except Exception as exc:
            self._activate_done(None, f"تعذّر بدء التثبيت: {exc}")
            return
        if rc <= 32:
            self._activate_done(None, "التثبيت يحتاج موافقتك على صلاحيات Windows.")
            return
        self.lbl_foot.configure(text=ar("جارٍ التثبيت... اترك النافذة السوداء تعمل"))
        self.after(20000, self._activate)

    def _activate_worker(self) -> None:
        report, error = None, None
        try:
            if ipc.service_reachable():
                reply = ipc.request("ENFORCE")
                report = reply.get("report") if reply.get("ok") else None
                error = None if reply.get("ok") else reply.get("error")
            else:
                # الخدمة غير متاحة: نفّذ فحصًا للقراءة فقط بلا فرض
                report = checks.run_all()
                checks.write_status(report)
                error = ("خدمة الحماية لا تعمل - تم تنفيذ فحص فقط بدون فرض. "
                         "شغّل المثبّت كمدير لتثبيت الخدمة.")
        except Exception as exc:
            error = str(exc)
        self.after(0, lambda: self._activate_done(report, error))

    def _activate_done(self, report: dict[str, Any] | None, error: str | None) -> None:
        self._busy = False
        self.btn.configure(state="normal", text=ar("تفعيل الحماية"))
        if report:
            self._render(report)
        else:
            self._set_overall("red")
        if error:
            self.lbl_foot.configure(text=ar("⚠ " + error[:150]))

    def _admin_tool(self) -> tuple[str, str]:
        """مسار أداة الإدارة: ملف exe بجانب البرنامج، أو وحدة بايثون في التطوير."""
        import sys
        from pathlib import Path
        if getattr(sys, "frozen", False):
            exe = Path(sys.executable).with_name("schoolshield-admin.exe")
            if exe.exists():
                return str(exe), ""
        return sys.executable, "-m schoolshield.admin_cli"

    def _toggle_off(self) -> None:
        """إيقاف أو استئناف الحماية - يتطلب صلاحيات Windows وكلمة مرور المدير معًا."""
        import ctypes
        report = checks.read_status() or {}
        paused = report.get("paused", {}).get("active", False)
        verb = "resume" if paused else "pause --minutes 30"
        tool, prefix = self._admin_tool()
        params = (prefix + " " + verb).strip()
        try:
            rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", tool, params,
                                                     None, 1)
        except Exception as exc:
            messagebox.showerror(ar("درع المدرسة"), ar(f"تعذّر التشغيل: {exc}"))
            return
        if rc <= 32:
            messagebox.showwarning(
                ar("درع المدرسة"),
                ar("هذه العملية تحتاج صلاحيات مدير Windows.\n"
                   "حساب الطالب لا يستطيع إيقاف الحماية."),
            )
            return
        self.after(2500, self._activate)

    def _sync_off_button(self, report: dict[str, Any]) -> None:
        paused = report.get("paused", {}).get("active", False)
        self.btn_off.configure(
            text=ar("استئناف الحماية (للمدير)" if paused else "إيقاف الحماية (للمدير)"))

    def _tick(self) -> None:
        """تحديث دوري من ملف الحالة الذي تكتبه الخدمة."""
        if not self._busy:
            report = checks.read_status()
            if report:
                self._render(report)
        self.after(15000, self._tick)

    def _admin_login(self) -> None:
        AdminDialog(self)


class AdminDialog(tk.Toplevel):
    """نافذة دخول المدير. النجاح يفتح نافذة تغيير كلمة المرور إن كان مطلوبًا."""

    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        self.title(ar("دخول المدير"))
        self.configure(bg=BG)
        self.geometry("460x300")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()
        f_body = tkfont.Font(family="Segoe UI", size=12)

        tk.Label(self, text=ar("دخول المدير"), bg=BG, fg=TXT,
                 font=tkfont.Font(family="Segoe UI", size=18, weight="bold")
                 ).pack(pady=(18, 10))
        st = auth.status()
        if not st.get("provisioned"):
            tk.Label(self, text=ar("لم يُنشأ حساب المدير بعد.\nشغّل: schoolshield-admin provision"),
                     bg=BG, fg=AMBER, font=f_body, justify="center").pack(pady=20)
            tk.Button(self, text=ar("إغلاق"), command=self.destroy, bg=CARD, fg=TXT,
                      relief="flat").pack()
            return

        frm = tk.Frame(self, bg=BG)
        frm.pack(padx=24, fill="x")
        tk.Label(frm, text=ar("اسم المستخدم"), bg=BG, fg=MUTED, anchor="e",
                 font=f_body).pack(fill="x")
        self.e_user = tk.Entry(frm, justify="right", font=f_body)
        self.e_user.insert(0, st.get("username") or "")
        self.e_user.pack(fill="x", pady=(0, 10))
        tk.Label(frm, text=ar("كلمة المرور"), bg=BG, fg=MUTED, anchor="e",
                 font=f_body).pack(fill="x")
        self.e_pass = tk.Entry(frm, show="●", justify="right", font=f_body)
        self.e_pass.pack(fill="x", pady=(0, 14))
        self.e_pass.bind("<Return>", lambda _e: self._submit())
        tk.Button(self, text=ar("دخول"), command=self._submit, bg=BLUE, fg="white",
                  relief="flat", font=f_body, pady=8, cursor="hand2"
                  ).pack(fill="x", padx=24)
        self.lbl_err = tk.Label(self, text="", bg=BG, fg=RED, font=f_body,
                                wraplength=400, justify="center")
        self.lbl_err.pack(pady=8)
        self.e_pass.focus_set()

    def _submit(self) -> None:
        user = self.e_user.get().strip()
        pwd = self.e_pass.get()
        try:
            info = auth.verify(user, pwd)
        except auth.AuthError as exc:
            self.lbl_err.configure(text=ar(str(exc)))
            self.e_pass.delete(0, tk.END)
            return
        self.destroy()
        if info["must_change"]:
            ChangePasswordDialog(self.master, user, pwd)
        else:
            messagebox.showinfo(
                ar("درع المدرسة"),
                ar("تم الدخول.\nالعمليات الإدارية (إيقاف مؤقت / إزالة) تُنفَّذ من:\n"
                   "schoolshield-admin  — وتتطلب صلاحيات مدير Windows."),
            )


class ChangePasswordDialog(tk.Toplevel):
    """إلزام تغيير كلمة المرور الأولية."""

    def __init__(self, master: tk.Misc, username: str, old_password: str) -> None:
        super().__init__(master)
        self.username, self.old = username, old_password
        self.title(ar("تغيير كلمة المرور إلزامي"))
        self.configure(bg=BG)
        self.geometry("520x380")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()
        f_body = tkfont.Font(family="Segoe UI", size=12)
        tk.Label(self, text=ar("يجب تغيير كلمة المرور الأولية"), bg=BG, fg=AMBER,
                 font=tkfont.Font(family="Segoe UI", size=16, weight="bold")
                 ).pack(pady=(18, 6))
        tk.Label(self, text=ar(f"١٢ حرفًا على الأقل، مع حرف كبير وصغير ورقم ورمز"),
                 bg=BG, fg=MUTED, font=f_body).pack(pady=(0, 12))
        frm = tk.Frame(self, bg=BG)
        frm.pack(padx=24, fill="x")
        tk.Label(frm, text=ar("كلمة المرور الجديدة"), bg=BG, fg=MUTED, anchor="e",
                 font=f_body).pack(fill="x")
        self.e1 = tk.Entry(frm, show="●", justify="right", font=f_body)
        self.e1.pack(fill="x", pady=(0, 10))
        tk.Label(frm, text=ar("تأكيد كلمة المرور"), bg=BG, fg=MUTED, anchor="e",
                 font=f_body).pack(fill="x")
        self.e2 = tk.Entry(frm, show="●", justify="right", font=f_body)
        self.e2.pack(fill="x", pady=(0, 10))
        tk.Button(self, text=ar("حفظ"), command=self._save, bg=GREEN, fg="white",
                  relief="flat", font=f_body, pady=8, cursor="hand2"
                  ).pack(fill="x", padx=24, pady=(6, 4))
        tk.Button(self, text=ar("اقترح كلمة مرور قوية"), command=self._suggest,
                  bg=CARD, fg=TXT, relief="flat", font=f_body
                  ).pack(fill="x", padx=24)
        self.lbl = tk.Label(self, text="", bg=BG, fg=RED, font=f_body,
                            wraplength=460, justify="center")
        self.lbl.pack(pady=8)
        self.e1.focus_set()

    def _suggest(self) -> None:
        suggestion = auth.suggest_password()
        self.e1.delete(0, tk.END)
        self.e1.insert(0, suggestion)
        self.e2.delete(0, tk.END)
        self.e2.insert(0, suggestion)
        self.lbl.configure(fg=AMBER, text=ar("انسخها الآن إلى مكان آمن قبل الحفظ"))

    def _save(self) -> None:
        p1, p2 = self.e1.get(), self.e2.get()
        if p1 != p2:
            self.lbl.configure(fg=RED, text=ar("الكلمتان غير متطابقتين"))
            return
        try:
            auth.change_password(self.username, self.old, p1)
        except auth.AuthError as exc:
            self.lbl.configure(fg=RED, text=ar(str(exc)))
            return
        messagebox.showinfo(ar("درع المدرسة"), ar("تم تغيير كلمة المرور بنجاح"))
        self.destroy()


def main() -> None:
    app = ShieldApp()
    if is_elevated():
        app.title(app.title() + ar("  [مُرقّى]"))
    app.mainloop()


if __name__ == "__main__":
    main()
