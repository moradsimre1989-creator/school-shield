"""نقطة دخول واحدة: واجهة، أو خدمة، أو تثبيت ذاتي بنافذة تقدّم."""
import multiprocessing
import pathlib
import sys


def _run_service() -> None:
    sys.argv = [sys.argv[0]]
    from schoolshield.service import service_main
    service_main()


def _run_setup(args) -> None:
    """التثبيت مع نافذة صغيرة تعرض الخطوة الحالية - لا يبقى المستخدم أمام صمت."""
    import queue
    import threading
    import tkinter as tk
    from tkinter import font as tkfont

    from schoolshield import setup_win
    from schoolshield.arabic import ar

    org = args[1] if len(args) > 1 else setup_win.bundled_organization()
    # كلمة المرور تصل عبر ملف مؤقت (لا عبر سطر الأوامر) ويُحذف فور قراءته
    disable_password = ""
    secret_path = args[2] if len(args) > 2 else ""
    if secret_path:
        handle = pathlib.Path(secret_path)
        try:
            disable_password = handle.read_text(encoding="utf-8").strip()
        except OSError:
            disable_password = ""
        finally:
            try:
                handle.unlink()
            except OSError:
                pass

    root = tk.Tk()
    root.title("درع المدرسة")
    root.configure(bg="#0f172a")
    root.geometry("520x210")
    root.resizable(False, False)
    f_title = tkfont.Font(family="Segoe UI", size=17, weight="bold")
    f_body = tkfont.Font(family="Segoe UI", size=12)
    tk.Label(root, text=ar("جارٍ تثبيت الحماية"), bg="#0f172a", fg="#eef2ff",
             font=f_title).pack(pady=(26, 6))
    status = tk.Label(root, text=ar("البدء..."), bg="#0f172a", fg="#93a4c8",
                      font=f_body, wraplength=460)
    status.pack()
    hint = tk.Label(root, text=ar("قد يستغرق عدة دقائق - لا تغلق هذه النافذة"),
                    bg="#0f172a", fg="#5b6b80", font=tkfont.Font(family="Segoe UI", size=10))
    hint.pack(pady=(14, 0))

    result = {"problem": None, "done": False}

    messages: "queue.Queue[str]" = queue.Queue()

    def progress(text: str) -> None:
        messages.put(text)

    def worker() -> None:
        # أي استثناء هنا كان يترك النافذة معلّقة إلى الأبد
        try:
            result["problem"] = setup_win.run_setup(
                org, progress=progress, disable_password=disable_password)
        except BaseException as exc:
            result["problem"] = f"{type(exc).__name__}: {exc}"
        finally:
            result["done"] = True

    def dump_error(problem: str) -> str:
        """يكتب سبب الفشل وآخر أسطر السجل على سطح المكتب ليسهل إرساله."""
        import os
        from schoolshield.paths import LOG_FILE
        desktop = pathlib.Path(os.environ.get("USERPROFILE", ".")) / "Desktop"
        out = desktop / "درع المدرسة - خطأ.txt"
        lines = ["سبب الفشل:", str(problem), "", "آخر أسطر السجل:"]
        try:
            lines += LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()[-25:]
        except OSError:
            lines.append("(لا يوجد سجل)")
        from schoolshield.paths import DATA_DIR
        text = chr(10).join(lines)
        saved = ""
        for path in (out, DATA_DIR / "logs" / "خطأ-التثبيت.txt"):
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
                saved = saved or str(path)
            except OSError:
                pass
        return saved

    def poll() -> None:
        while True:
            try:
                status.configure(text=ar(messages.get_nowait()))
            except queue.Empty:
                break
        if result["done"]:
            if result["problem"] == "REBOOT":
                status.configure(text=ar("اكتمل التثبيت"), fg="#86efac")
                hint.configure(text=ar("أعد تشغيل الحاسوب لتفعيل الحماية"))
                tk.Button(root, text=ar("إغلاق"), command=root.destroy, bg="#1b2740",
                          fg="#eef2ff", relief="flat").pack(pady=10)
                result["problem"] = None
                return
            if result["problem"]:
                status.configure(text=ar("فشل: " + str(result["problem"])[:160]),
                                 fg="#fca5a5")
                saved = dump_error(result["problem"])
                hint.configure(text=ar("التفاصيل في: درع المدرسة - خطأ.txt على سطح المكتب"
                                       if saved else "أغلق النافذة وأعد المحاولة"))
                tk.Button(root, text=ar("إغلاق"), command=root.destroy, bg="#1b2740",
                          fg="#eef2ff", relief="flat").pack(pady=10)
            else:
                root.destroy()
            return
        root.after(300, poll)

    threading.Thread(target=worker, daemon=True).start()
    root.after(300, poll)
    root.mainloop()
    sys.exit(1 if result["problem"] else 0)


def main() -> None:
    multiprocessing.freeze_support()
    args = sys.argv[1:]
    if args and args[0] == "--service":
        _run_service()
        return
    if args and args[0] == "--setup":
        _run_setup(args)
        return
    from schoolshield.gui import main as gui_main
    gui_main()


if __name__ == "__main__":
    main()
