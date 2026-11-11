"""نقطة دخول واحدة: واجهة، أو خدمة، أو تثبيت ذاتي بنافذة تقدّم."""
import multiprocessing
import sys


def _run_service() -> None:
    sys.argv = [sys.argv[0]]
    from schoolshield.service import service_main
    service_main()


def _run_setup(args) -> None:
    """التثبيت مع نافذة صغيرة تعرض الخطوة الحالية - لا يبقى المستخدم أمام صمت."""
    import threading
    import tkinter as tk
    from tkinter import font as tkfont

    from schoolshield import setup_win
    from schoolshield.arabic import ar

    org = args[1] if len(args) > 1 else setup_win.bundled_organization()
    disable_password = args[2] if len(args) > 2 else ""

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

    def progress(text: str) -> None:
        root.after(0, lambda: status.configure(text=ar(text)))

    def worker() -> None:
        result["problem"] = setup_win.run_setup(
            org, progress=progress, disable_password=disable_password)
        result["done"] = True

    def poll() -> None:
        if result["done"]:
            if result["problem"]:
                status.configure(text=ar("فشل: " + str(result["problem"])[:160]),
                                 fg="#fca5a5")
                hint.configure(text=ar("أغلق النافذة وأعد المحاولة"))
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
