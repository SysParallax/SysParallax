"""Offline tests: no GitHub/Discord network access and no credentials required."""
import importlib.util
import os
import pathlib
import unittest
from unittest.mock import patch

PATH = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "control_center.py"
spec = importlib.util.spec_from_file_location("control_center", PATH)
cc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cc)


class ControlCenterTests(unittest.TestCase):
    def test_clean_prevents_mentions_and_multiline(self):
        result = cc.clean("@everyone\n**security** <@123> *alert*")
        self.assertNotIn("@everyone", result)
        self.assertNotIn("\n", result)
        self.assertIn("＠everyone", result)

    def test_bot_dashboard_marker_and_author(self):
        msg = {"id": "123", "author": {"id": "2"},
               "embeds": [{"footer": {"text": cc.MARKER}}]}
        self.assertTrue(cc.is_own_dashboard(msg, "2"))
        self.assertFalse(cc.is_own_dashboard(msg, "3"))
        self.assertFalse(cc.is_own_dashboard({"author": {"id": "2"}, "embeds": []}, "2"))

    def test_find_existing_pinned_message(self):
        own = {"id": "123456", "author": {"id": "2"},
               "embeds": [{"footer": {"text": cc.MARKER}}]}
        with patch.object(cc, "discord", return_value={"items": [{"message": own}], "has_more": False}) as mock:
            self.assertEqual(cc.locate_message("123456789012345678", "token", "2"), ("123456", True))
            self.assertEqual(mock.call_count, 1)

    def test_publish_updates_instead_of_posting(self):
        with patch.object(cc, "discord", side_effect=[{"id": "999"}, {"id": "123"}]) as mock, \
             patch.object(cc, "locate_message", return_value=("123", True)):
            out = cc.publish("123456789012345678", "token", {"embeds": []})
            self.assertEqual(out, "123")
            self.assertEqual(mock.call_args.kwargs["method"], "PATCH")

    def test_publish_creates_pins_once(self):
        with patch.object(cc, "discord", side_effect=[{"id": "2"}, {"id": "123"}, None]) as mock, \
             patch.object(cc, "locate_message", return_value=(None, False)):
            cc.publish("123456789012345678", "token", {"embeds": []})
            self.assertEqual(mock.call_args.kwargs["method"], "PUT")

    def test_publish_repins_found_unpinned_message(self):
        with patch.object(cc, "discord", side_effect=[{"id": "2"}, {"id": "123"}, None]) as mock, \
             patch.object(cc, "locate_message", return_value=("123", False)):
            self.assertEqual(cc.publish("123456789012345678", "token", {"embeds": []}), "123")
            self.assertEqual([x.kwargs.get("method", "GET") for x in mock.call_args_list], ["GET", "PATCH", "PUT"])

    def test_status_success_and_failure(self):
        success = {"workflow_runs": [{"status": "completed", "conclusion": "success",
            "head_branch": "main", "html_url": "https://github.com/SysParallax/SysParallax/actions/runs/123"}]}
        with patch.object(cc, "gh", return_value=success):
            self.assertEqual(cc.workflow_status("SysParallax/SysParallax", "ci.yml", "CI")["status"], "success")
        failure = {"workflow_runs": [{"status": "completed", "conclusion": "failure",
            "head_branch": "main", "html_url": "https://github.com/SysParallax/SysParallax/actions/runs/123"}]}
        with patch.object(cc, "gh", return_value=failure):
            self.assertEqual(cc.workflow_status("SysParallax/SysParallax", "ci.yml", "CI")["status"], "failure")

    def test_issue_summary_empty(self):
        with patch.object(cc, "gh", return_value={"total_count": 0, "items": []}):
            count, text = cc.issue_summary("SysParallax/SysParallax", "issue")
            self.assertEqual(count, 0)
            self.assertIn("Aucun", text)

    def test_release_not_published(self):
        with patch.object(cc, "safe_gh", return_value=None):
            self.assertIn("Aucune release", cc.release_summary("SysParallax/SysParallax"))

    def test_optional_health_checks(self):
        self.assertIn("Aucun", cc.service_summary(""))
        with self.assertRaises(ValueError):
            cc.service_summary("not json")
        self.assertIn("invalide", cc.service_summary('{"API":"http://localhost:8080/health"}'))

    def test_payload_shape(self):
        with patch.object(cc, "workflow_status", return_value={"status": "success", "line": "🟢 OK"}), \
             patch.object(cc, "issue_summary", return_value=(0, "Aucun")), \
             patch.object(cc, "release_summary", return_value="Aucune release"), \
             patch.dict(os.environ, {"SYSPARALLAX_HEALTHCHECKS": ""}):
            payload = cc.build_payload("SysParallax/SysParallax")
            self.assertEqual(len(payload["embeds"]), 1)
            self.assertEqual(payload["embeds"][0]["footer"]["text"], cc.MARKER)
            self.assertEqual(len(payload["embeds"][0]["fields"]), 7)
            self.assertEqual(payload["allowed_mentions"], {"parse": []})
            self.assertEqual(payload["embeds"][0]["color"], cc.GOOD)


if __name__ == "__main__":
    unittest.main()
