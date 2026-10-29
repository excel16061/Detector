import unittest

from rat_detect import (
    assess_permissions,
    parse_active_admins,
    parse_package_installers,
    parse_requested_permissions,
    parse_settings_component_list,
)

# Fixture shapes are written by hand to match the dumpsys layout as documented
# in AOSP. They must be checked against output from real devices before use.
DPM_DUMP = """\
Current Device Policy Manager state:
  Enabled Device Admin:
    ComponentInfo{com.google.android.apps.work/.DeviceAdminReceiver}
    ComponentInfo{com.evil.rat/.AdminReceiver}
  Device Owner: null
"""

PKG_DUMP = """\
Packages:
  Package [com.evil.rat] (abc123):
    userId=10123
    requested permissions:
      android.permission.READ_SMS
      android.permission.RECEIVE_SMS
      android.permission.SYSTEM_ALERT_WINDOW
      android.permission.INTERNET
    install permissions:
      android.permission.INTERNET
"""


class ParserTests(unittest.TestCase):
    def test_admins_only_from_admin_section(self):
        self.assertEqual(
            parse_active_admins(DPM_DUMP),
            ["com.evil.rat/.AdminReceiver",
             "com.google.android.apps.work/.DeviceAdminReceiver"])

    def test_settings_list_handles_null_and_multiple(self):
        self.assertEqual(parse_settings_component_list("null\n"), [])
        self.assertEqual(
            parse_settings_component_list("a/.S:b/.T"), ["a/.S", "b/.T"])

    def test_installers_detect_sideloaded(self):
        out = ("package:com.evil.rat  installer=null\n"
               "package:com.shop.app  installer=com.android.vending\n")
        self.assertEqual(parse_package_installers(out), {
            "com.evil.rat": None,
            "com.shop.app": "com.android.vending",
        })

    def test_requested_permissions_stop_at_next_heading(self):
        perms = parse_requested_permissions(PKG_DUMP)
        self.assertIn("android.permission.READ_SMS", perms)
        self.assertIn("android.permission.INTERNET", perms)
        self.assertEqual(len(perms), 4)  # install-permissions block must not be counted

    def test_risk_score(self):
        score, hits = assess_permissions({"android.permission.READ_SMS",
                                          "android.permission.RECEIVE_SMS",
                                          "android.permission.SYSTEM_ALERT_WINDOW"})
        self.assertEqual(score, 6)
        self.assertEqual(len(hits), 3)


if __name__ == "__main__":
    unittest.main()
