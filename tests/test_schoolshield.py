"""اختبارات درع المدرسة.

تشغيل:  python -m unittest discover -s tests -v
الاختبارات لا تعدّل حالة الجهاز ولا تتصل بأي موقع إباحي؛ ما يخص الشبكة
يُحاكى بالكامل عدا اختبار DNS واحد اختياري لنطاق تعليمي.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from schoolshield import checks, netcheck  # noqa: E402
from schoolshield.config import CF_BLOCK_IPS  # noqa: E402


class TestBlockDetection(unittest.TestCase):
    """تصنيف ردود DNS: ما الذي يُعتبر حجبًا فعليًا؟"""

    def test_block_page_ips_mean_blocked(self):
        for ip in CF_BLOCK_IPS:
            with mock.patch.object(netcheck.dns.resolver, "Resolver") as R:
                R.return_value.resolve.return_value = _answer([ip])
                res = netcheck.resolve("example.com")
            self.assertEqual(res["state"], netcheck.BLOCKED)

    def test_zero_ip_means_blocked(self):
        with mock.patch.object(netcheck.dns.resolver, "Resolver") as R:
            R.return_value.resolve.return_value = _answer(["0.0.0.0"])
            res = netcheck.resolve("example.com")
        self.assertEqual(res["state"], netcheck.BLOCKED)

    def test_real_ip_means_allowed(self):
        with mock.patch.object(netcheck.dns.resolver, "Resolver") as R:
            R.return_value.resolve.return_value = _answer(["93.184.216.34"])
            res = netcheck.resolve("example.com")
        self.assertEqual(res["state"], netcheck.ALLOWED)

    def test_nxdomain_is_not_blocked(self):
        """نطاق ميت ليس نطاقًا محجوبًا - خطأ شائع يعطي أخضر كاذبًا."""
        with mock.patch.object(netcheck.dns.resolver, "Resolver") as R:
            R.return_value.resolve.side_effect = netcheck.dns.resolver.NXDOMAIN()
            res = netcheck.resolve("dead-domain.example")
        self.assertEqual(res["state"], netcheck.INCONCLUSIVE)

    def test_timeout_is_not_blocked(self):
        with mock.patch.object(netcheck.dns.resolver, "Resolver") as R:
            R.return_value.resolve.side_effect = netcheck.dns.exception.Timeout()
            res = netcheck.resolve("slow.example")
        self.assertEqual(res["state"], netcheck.INCONCLUSIVE)


class TestOverallVerdict(unittest.TestCase):
    """المؤشر الأخضر لا يُمنح إلا باستحقاق."""

    def _run_with(self, states: dict[str, str]) -> dict:
        def fake(key, title, state):
            return lambda: {"key": key, "title": title, "state": state,
                            "detail": "", "items": [], "critical": key in checks.CRITICAL}
        fakes = tuple(fake(k, k, v) for k, v in states.items())
        with mock.patch.object(checks, "ALL_CHECKS", fakes), \
                mock.patch.object(checks, "pause_state", return_value={"active": False}):
            return checks.run_all()

    def test_all_pass_is_green(self):
        states = {k: checks.PASS for k in
                  ("client", "registration", "adult_block", "violence_block",
                   "safesearch", "education", "tamper")}
        self.assertEqual(self._run_with(states)["overall"], "green")

    def test_one_failure_is_red(self):
        states = {k: checks.PASS for k in
                  ("client", "registration", "adult_block", "violence_block",
                   "safesearch", "education", "tamper")}
        states["adult_block"] = checks.FAIL
        self.assertEqual(self._run_with(states)["overall"], "red")

    def test_unverified_critical_is_red_not_green(self):
        """فحص أساسي لم يكتمل = ليس أخضر أبدًا."""
        states = {k: checks.PASS for k in
                  ("client", "registration", "adult_block", "violence_block",
                   "safesearch", "education", "tamper")}
        states["tamper"] = checks.UNVERIFIED
        self.assertEqual(self._run_with(states)["overall"], "red")

    def test_unverified_secondary_is_amber(self):
        states = {k: checks.PASS for k in
                  ("client", "registration", "adult_block", "violence_block",
                   "safesearch", "education", "tamper")}
        states["violence_block"] = checks.UNVERIFIED
        self.assertEqual(self._run_with(states)["overall"], "amber")

    def test_admin_pause_forces_red(self):
        states = {k: checks.PASS for k in
                  ("client", "registration", "adult_block", "violence_block",
                   "safesearch", "education", "tamper")}
        def fake(key, state):
            return lambda: {"key": key, "title": key, "state": state, "detail": "",
                            "items": [], "critical": key in checks.CRITICAL}
        fakes = tuple(fake(k, v) for k, v in states.items())
        with mock.patch.object(checks, "ALL_CHECKS", fakes), \
                mock.patch.object(checks, "pause_state",
                                  return_value={"active": True, "until": "x"}):
            self.assertEqual(checks.run_all()["overall"], "red")


class TestAdminAuth(unittest.TestCase):
    """حساب المدير: تجزئة، إلزام تغيير، قفل بعد المحاولات."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.admin_file = Path(self.tmp.name) / "admin.json"
        patches = [
            mock.patch("schoolshield.auth.ADMIN_FILE", self.admin_file),
            mock.patch("schoolshield.auth.SECURE_DIR", Path(self.tmp.name)),
            mock.patch("schoolshield.auth.is_elevated", return_value=True),
            mock.patch("schoolshield.auth.lock_down_directory", return_value=True),
            mock.patch("schoolshield.auth.audit"),
            mock.patch("schoolshield.auth.ensure_dirs"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self.tmp.cleanup)
        from schoolshield import auth
        self.auth = auth

    def test_password_never_stored_in_plaintext(self):
        self.auth.provision("schooladmin", "Initial-Pass-1")
        raw = self.admin_file.read_text(encoding="utf-8")
        self.assertNotIn("Initial-Pass-1", raw)
        self.assertIn("$argon2id$", json.loads(raw)["hash"])

    def test_initial_password_forces_change(self):
        self.auth.provision("schooladmin", "Initial-Pass-1")
        self.assertTrue(self.auth.verify("schooladmin", "Initial-Pass-1")["must_change"])

    def test_wrong_password_rejected(self):
        self.auth.provision("schooladmin", "Initial-Pass-1")
        with self.assertRaises(self.auth.AuthError):
            self.auth.verify("schooladmin", "wrong-password")

    def test_lockout_after_repeated_failures(self):
        self.auth.provision("schooladmin", "Initial-Pass-1")
        for _ in range(self.auth.MAX_FAILURES_BEFORE_LOCK - 1):
            with self.assertRaises(self.auth.AuthError):
                self.auth.verify("schooladmin", "nope")
        with self.assertRaises(self.auth.AuthError) as ctx:
            self.auth.verify("schooladmin", "nope")
        self.assertIn("مقفل", str(ctx.exception))
        # حتى كلمة المرور الصحيحة تُرفض أثناء القفل
        with self.assertRaises(self.auth.AuthError):
            self.auth.verify("schooladmin", "Initial-Pass-1")

    def test_weak_new_password_rejected(self):
        self.auth.provision("schooladmin", "Initial-Pass-1")
        for weak in ("short1!A", "alllowercase123!", "NoDigits!!!!!", "Initial-Pass-1"):
            with self.assertRaises(self.auth.AuthError):
                self.auth.change_password("schooladmin", "Initial-Pass-1", weak)

    def test_strong_password_accepted_and_clears_flag(self):
        self.auth.provision("schooladmin", "Initial-Pass-1")
        self.auth.change_password("schooladmin", "Initial-Pass-1", "Qamar#2026_School!x")
        self.assertFalse(self.auth.verify("schooladmin", "Qamar#2026_School!x")["must_change"])

    def test_suggested_password_is_strong(self):
        self.assertEqual(self.auth.password_problems(self.auth.suggest_password()), [])

    def test_provision_requires_elevation(self):
        with mock.patch("schoolshield.auth.is_elevated", return_value=False):
            with self.assertRaises(self.auth.AuthError):
                self.auth.provision("schooladmin", "Initial-Pass-1")


class TestIpcProtocol(unittest.TestCase):
    """البروتوكول لا يحتوي أي أمر لتعطيل الحماية."""

    def test_no_unauthenticated_disable(self):
        """الإيقاف موجود لكنه لا يُنفَّذ بلا كلمة مرور، والإزالة ليست في البروتوكول."""
        from schoolshield import ipc, service
        for forbidden in ("DISABLE", "OFF", "UNINSTALL", "STOP"):
            self.assertNotIn(forbidden, ipc.ALLOWED_COMMANDS)
        with mock.patch("schoolshield.auth.is_provisioned", return_value=True),                 mock.patch("schoolshield.auth.verify_password", return_value=False),                 mock.patch("schoolshield.winutil.audit"):
            reply = service._handle_pause("PAUSE", "wrong-password")
        self.assertFalse(reply["ok"])

    def test_pause_rejected_without_password(self):
        from schoolshield import service
        with mock.patch("schoolshield.auth.is_provisioned", return_value=True),                 mock.patch("schoolshield.winutil.audit"):
            reply = service._handle_pause("PAUSE", "")
        self.assertFalse(reply["ok"])

    def test_unknown_command_rejected_client_side(self):
        from schoolshield import ipc
        with self.assertRaises(ValueError):
            ipc.request("DISABLE")


class TestServiceHardening(unittest.TestCase):
    """الوصف الأمني للخدمة يجب ألّا يمنح الطلاب حق الإيقاف."""

    def test_users_cannot_stop_in_our_sddl(self):
        from schoolshield import hardening
        sddl = ("D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)"
                "(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWLOCRRC;;;BU)")
        self.assertFalse(hardening._users_can_stop(sddl))

    def test_permissive_sddl_is_detected(self):
        from schoolshield import hardening
        bad = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRRC;;;BU)"
        self.assertTrue(hardening._users_can_stop(bad))


class TestMdmConfig(unittest.TestCase):
    """ملف إعدادات العميل المُدارة يُكتب ويُقرأ بالمفاتيح الرسمية."""

    def test_write_then_read_roundtrip(self):
        from schoolshield import warp
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mdm.xml"
            with mock.patch("schoolshield.warp.WARP_MDM_FILE", path):
                warp.write_mdm("my-school", switch_locked=True, auto_connect=1)
                data = warp.read_mdm()
        self.assertEqual(data["organization"], "my-school")
        self.assertIs(data["switch_locked"], True)
        self.assertEqual(data["auto_connect"], 1)

    def test_mdm_contains_no_secrets(self):
        from schoolshield import warp
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mdm.xml"
            with mock.patch("schoolshield.warp.WARP_MDM_FILE", path):
                warp.write_mdm("my-school")
                text = path.read_text(encoding="utf-8")
        for secret in ("auth_client_secret", "password", "schooladmin"):
            self.assertNotIn(secret, text)


class TestArabicShaping(unittest.TestCase):
    def test_shaping_available_and_stable(self):
        from schoolshield.arabic import ar, available
        self.assertTrue(available(), "arabic-reshaper/python-bidi غير مثبّتين")
        out = ar("الحماية مفعّلة")
        self.assertTrue(out)
        self.assertEqual(out, ar("الحماية مفعّلة"))


def _answer(ips: list[str]):
    """ردّ DNS مُحاكى."""
    recs = [mock.Mock(address=ip) for ip in ips]
    ans = mock.MagicMock()
    ans.__iter__.return_value = iter(recs)
    ans.response.answer = []
    return ans


if __name__ == "__main__":
    unittest.main(verbosity=2)
