"""أداة المدير: إعداد الحساب، فرض السياسات، فحص، إيقاف مؤقت، إزالة.

كل أمر يغيّر حالة الحماية يتطلب شيئين معًا:
  1. كلمة مرور المدير (Argon2id)
  2. عملية مُرقّاة بصلاحيات Administrator على Windows
معرفة كلمة المرور وحدها لا تكفي.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import getpass
import json
import sys

from . import APP_NAME_AR, SERVICE_NAME, __version__, auth, checks, hardening, ipc, warp
from .config import load_policy, save_policy
from .paths import ADMIN_FILE, PAUSE_FILE, SECURE_DIR, STATUS_FILE, ensure_dirs
from .winutil import audit, is_elevated, run


def _utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _need_admin() -> None:
    if not is_elevated():
        raise SystemExit("هذا الأمر يتطلب تشغيل الأداة كمدير Windows "
                         "(Run as administrator)")


def _authenticate() -> str:
    st = auth.status()
    if not st.get("provisioned"):
        raise SystemExit("حساب المدير غير مُنشأ. نفّذ: schoolshield-admin provision")
    username = input(f"اسم المستخدم [{st['username']}]: ").strip() or st["username"]
    password = getpass.getpass("كلمة المرور: ")
    info = auth.verify(username, password)
    if info["must_change"]:
        print("يجب تغيير كلمة المرور الأولية قبل أي عملية إدارية.")
        _change_password_flow(username, password)
    return username


def _change_password_flow(username: str, old: str) -> None:
    while True:
        new1 = getpass.getpass("كلمة المرور الجديدة: ")
        new2 = getpass.getpass("تأكيد كلمة المرور: ")
        if new1 != new2:
            print("الكلمتان غير متطابقتين.")
            continue
        try:
            auth.change_password(username, old, new1)
        except auth.AuthError as exc:
            print(str(exc))
            continue
        print("تم تغيير كلمة المرور.")
        return


# ----------------------------- الأوامر -----------------------------

def cmd_provision(args: argparse.Namespace) -> int:
    _need_admin()
    ensure_dirs()
    print(f"إنشاء حساب مدير {APP_NAME_AR}")
    username = args.username
    pwd = getpass.getpass("كلمة المرور الأولية (لن تُخزَّن كنص صريح): ")
    if not pwd:
        print("كلمة المرور مطلوبة.")
        return 2
    pwd2 = getpass.getpass("تأكيد كلمة المرور الأولية: ")
    if pwd != pwd2:
        print("الكلمتان غير متطابقتين.")
        return 2
    auth.provision(username, pwd, force_change=True)
    print(f"تم إنشاء الحساب: {username}")
    print("سيُطلب تغيير كلمة المرور عند أول تسجيل دخول.")
    print(f"ملف الحساب: {ADMIN_FILE} (محمي بـ ACL للمديرين فقط)")
    return 0


def cmd_setup_org(args: argparse.Namespace) -> int:
    """يربط الجهاز بمؤسسة Cloudflare Zero Trust ويقفل مفتاح الإيقاف."""
    _need_admin()
    _authenticate()
    policy = load_policy()
    policy["organization"] = args.organization
    if args.doh_subdomain:
        policy["gateway_doh_subdomain"] = args.doh_subdomain
    save_policy(policy)
    warp.write_mdm(
        args.organization,
        switch_locked=True,
        auto_connect=1,
        service_mode="warp",
        support_url=args.support_url or "",
        onboarding=False,
    )
    audit("setup_org", args.organization)
    print(f"تم ضبط المؤسسة: {args.organization}")
    print("switch_locked=true و auto_connect=1 مكتوبان في mdm.xml")
    print("لا تنسَ تشغيل Device Management Protection في بروفايل الجهاز بلوحة Cloudflare.")
    return 0


def cmd_enforce(args: argparse.Namespace) -> int:
    _need_admin()
    result = hardening.enforce_all()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    if args.via_service and ipc.service_reachable():
        report = ipc.request("VERIFY")["report"]
    else:
        report = checks.run_all()
        checks.write_status(report)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["overall"] == "green" else 1
    mark = {"pass": "[ناجح]", "fail": "[فاشل]", "unverified": "[غير متحقق]"}
    overall = {"green": "🟢 الحماية مفعّلة", "red": "🔴 الحماية غير مفعّلة",
               "amber": "🟡 الحماية غير مكتملة"}[report["overall"]]
    print(f"\n{overall}    ({report['checked_at']})\n")
    for item in report["checks"]:
        crit = "*" if item["critical"] else " "
        print(f"{crit} {mark[item['state']]:<14} {item['title']}")
        if item["detail"]:
            print(f"      {item['detail']}")
    s = report["summary"]
    print(f"\nناجح {s['pass']} / فاشل {s['fail']} / غير متحقق {s['unverified']}"
          f" من {s['total']}")
    print("* = فحص أساسي، فشله يعني أن النظام غير جاهز للتوزيع")
    if not report.get("elevated_scan"):
        print("ملاحظة: الفحص جرى بدون صلاحيات مدير، وبعض البنود تُقرأ بشكل محدود.")
    return 0 if report["overall"] == "green" else 1


def cmd_status(args: argparse.Namespace) -> int:
    report = checks.read_status()
    print(json.dumps({
        "admin": auth.status(),
        "service_reachable": ipc.service_reachable(),
        "client_installed": warp.installed(),
        "last_report": report and {
            "overall": report["overall"], "checked_at": report["checked_at"],
            "summary": report["summary"],
        },
        "status_file": str(STATUS_FILE),
    }, ensure_ascii=False, indent=2))
    return 0


def cmd_pause(args: argparse.Namespace) -> int:
    """إيقاف إداري مؤقت. يُكتب داخل مجلد محمي بـ ACL -> يتطلب مدير Windows."""
    _need_admin()
    username = _authenticate()
    minutes = max(1, min(args.minutes, 240))
    until = _dt.datetime.now() + _dt.timedelta(minutes=minutes)
    ensure_dirs()
    PAUSE_FILE.write_text(json.dumps({
        "until": until.isoformat(timespec="seconds"), "by": username,
        "reason": args.reason or "",
    }, ensure_ascii=False), encoding="utf-8")
    audit("pause", f"minutes={minutes} reason={args.reason or ''}")
    print(f"تم الإيقاف المؤقت حتى {until:%H:%M}. المؤشر سيظهر أحمر طوال هذه المدة.")
    return 0


def cmd_resume(args: argparse.Namespace) -> int:
    _need_admin()
    _authenticate()
    PAUSE_FILE.unlink(missing_ok=True)
    audit("resume", "")
    if ipc.service_reachable():
        ipc.request("ENFORCE")
    print("تم استئناف الحماية وإعادة فرض السياسات.")
    return 0


def cmd_change_password(args: argparse.Namespace) -> int:
    st = auth.status()
    if not st.get("provisioned"):
        raise SystemExit("حساب المدير غير مُنشأ.")
    username = input(f"اسم المستخدم [{st['username']}]: ").strip() or st["username"]
    old = getpass.getpass("كلمة المرور الحالية: ")
    auth.verify(username, old)
    _change_password_flow(username, old)
    return 0


def cmd_install_service(args: argparse.Namespace) -> int:
    _need_admin()
    exe = args.exe or sys.executable
    if exe.lower().endswith("python.exe") or exe.lower().endswith("pythonw.exe"):
        print("ملاحظة: تثبيت الخدمة من مفسّر Python مباشرة للتطوير فقط.")
        binpath = f'"{exe}" -m schoolshield.service'
    else:
        binpath = f'"{exe}"'
    run(["sc.exe", "create", SERVICE_NAME, f"binPath= {binpath}", "start=", "auto",
         "DisplayName= School Shield Protection Service"])
    run(["sc.exe", "description", SERVICE_NAME,
         "يفرض سياسات التصفح الآمن لحواسيب الطلاب"])
    hardening.harden_service_recovery()
    hardening.harden_service_acl()
    rc, out, err = run(["sc.exe", "start", SERVICE_NAME])
    print(out or err)
    audit("install_service", binpath)
    return 0 if rc == 0 else 1


def cmd_uninstall(args: argparse.Namespace) -> int:
    """إزالة إدارية كاملة. تتطلب مدير Windows + كلمة مرور المدير."""
    _need_admin()
    _authenticate()
    if input("اكتب UNINSTALL للتأكيد: ").strip() != "UNINSTALL":
        print("أُلغي.")
        return 1
    run(["sc.exe", "stop", SERVICE_NAME])
    run(["sc.exe", "delete", SERVICE_NAME])
    removed = hardening.remove_firewall()
    audit("uninstall", f"firewall_rules_removed={removed}")
    print(f"أُزيلت الخدمة و {removed} قاعدة جدار حماية.")
    print("ملاحظة: عميل Cloudflare One وسياسات المتصفحات تبقى حتى تُزال يدويًا؛")
    print("إزالة العميل مع حماية إلغاء التثبيت تحتاج UNINSTALL_TOKEN من لوحة Cloudflare.")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    _need_admin()
    from .paths import AUDIT_FILE
    if not AUDIT_FILE.exists():
        print("لا يوجد سجل تدقيق بعد.")
        return 0
    print(AUDIT_FILE.read_text(encoding="utf-8")[-8000:])
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="schoolshield-admin",
        description=f"{APP_NAME_AR} - أداة إدارة ({__version__})")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("provision", help="إنشاء حساب المدير لمرة واحدة")
    sp.add_argument("--username", default="admin")
    sp.set_defaults(func=cmd_provision)

    sp = sub.add_parser("setup-org", help="ربط الجهاز بمؤسسة Cloudflare وقفل المفتاح")
    sp.add_argument("organization")
    sp.add_argument("--doh-subdomain", default="")
    sp.add_argument("--support-url", default="")
    sp.set_defaults(func=cmd_setup_org)

    sp = sub.add_parser("enforce", help="فرض كل السياسات والتشديد الآن")
    sp.set_defaults(func=cmd_enforce)

    sp = sub.add_parser("verify", help="تنفيذ الفحوص السبعة")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--via-service", action="store_true")
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("status", help="ملخّص الحالة")
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("pause", help="إيقاف إداري مؤقت")
    sp.add_argument("--minutes", type=int, default=15)
    sp.add_argument("--reason", default="")
    sp.set_defaults(func=cmd_pause)

    sp = sub.add_parser("resume", help="استئناف الحماية")
    sp.set_defaults(func=cmd_resume)

    sp = sub.add_parser("change-password", help="تغيير كلمة مرور المدير")
    sp.set_defaults(func=cmd_change_password)

    sp = sub.add_parser("install-service", help="تثبيت خدمة الحماية")
    sp.add_argument("--exe", default="")
    sp.set_defaults(func=cmd_install_service)

    sp = sub.add_parser("uninstall", help="إزالة إدارية كاملة")
    sp.set_defaults(func=cmd_uninstall)

    sp = sub.add_parser("audit-log", help="عرض سجل التدقيق")
    sp.set_defaults(func=cmd_audit)
    return p


def main(argv: list[str] | None = None) -> int:
    _utf8()
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except auth.AuthError as exc:
        print(f"خطأ مصادقة: {exc}")
        return 3
    except KeyboardInterrupt:
        print("\nأُلغي.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
