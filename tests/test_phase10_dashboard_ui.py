"""
Phase 10 Dashboard UI static checks (Phase 3 of the improvement plan).

The page is verified in a real browser manually; these checks stop regressions of
the accessibility / safety properties that a static read of the HTML can prove.
"""

from __future__ import annotations

import re
import unittest

from blockchain_lite.network.web_dashboard import HTML_DASHBOARD as HTML


class TestDashboardMarkup(unittest.TestCase):
    def test_no_blocking_alerts(self) -> None:
        self.assertNotIn("alert(", HTML)

    def test_live_region_for_status_messages(self) -> None:
        self.assertRegex(HTML, r'id="toast"[^>]*role="status"[^>]*aria-live="polite"')

    def test_every_form_control_has_a_label(self) -> None:
        controls = re.findall(r'<(?:input|select|textarea)\b[^>]*\bid="([^"]+)"', HTML)
        labelled = set(re.findall(r'<label\b[^>]*\bfor="([^"]+)"', HTML))
        self.assertGreaterEqual(len(controls), 8)
        self.assertEqual([c for c in controls if c not in labelled], [])

    def test_tabs_use_aria_tab_pattern(self) -> None:
        self.assertIn('role="tablist"', HTML)
        self.assertEqual(len(re.findall(r'<button\b[^>]*role="tab"', HTML)), 4)
        self.assertEqual(len(re.findall(r'<section\b[^>]*role="tabpanel"', HTML)), 4)
        self.assertEqual(HTML.count('aria-selected="true"'), 1)

    def test_modal_is_an_accessible_dialog(self) -> None:
        self.assertIn('role="dialog"', HTML)
        self.assertIn('aria-modal="true"', HTML)
        self.assertIn("'Escape'", HTML)

    def test_responsive_and_reduced_motion_rules(self) -> None:
        self.assertRegex(HTML, r"@media \(max-width: \d+px\)")
        self.assertIn("@media (prefers-reduced-motion: reduce)", HTML)
        self.assertIn(":focus-visible", HTML)

    def test_server_data_never_interpolated_into_inline_handlers(self) -> None:
        self.assertIn("function esc(", HTML)
        self.assertIsNone(re.search(r'on\w+="[^"]*\$\{', HTML))

    def test_polling_pauses_when_hidden(self) -> None:
        self.assertIn("document.hidden", HTML)
        self.assertIn("visibilitychange", HTML)


if __name__ == "__main__":
    unittest.main()
