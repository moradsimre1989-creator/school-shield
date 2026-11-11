"""نقطة دخول واحدة: واجهة، أو خدمة، أو تثبيت ذاتي."""
import multiprocessing
import sys


def main() -> None:
    multiprocessing.freeze_support()
    args = sys.argv[1:]
    if args and args[0] == "--service":
        sys.argv = [sys.argv[0]]
        from schoolshield.service import service_main
        service_main()
        return
    if args and args[0] == "--setup":
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
        from schoolshield import setup_win
        org = args[1] if len(args) > 1 else setup_win.bundled_organization()
        problem = setup_win.run_setup(org, progress=lambda s: print(s, flush=True))
        if problem:
            print("فشل: " + problem)
            sys.exit(1)
        sys.exit(0)
    from schoolshield.gui import main as gui_main
    gui_main()


if __name__ == "__main__":
    main()
