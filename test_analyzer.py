
import unittest
from collections import Counter

from analyzer import find_suspicious_ips, analyze_logs


class TestSecurityDetection(unittest.TestCase):

    def test_five_failures_trigger_alert(self):
        attempts = Counter({"198.51.100.20": 5})
        self.assertIn(
            "198.51.100.20",
            find_suspicious_ips(attempts)
        )

    def test_four_failures_do_not_trigger_alert(self):
        attempts = Counter({"198.51.100.20": 4})
        self.assertNotIn(
            "198.51.100.20",
            find_suspicious_ips(attempts)
        )

    def test_different_ips_are_counted_separately(self):
        attempts = Counter({
            "198.51.100.20": 3,
            "203.0.113.15": 2
        })
        self.assertEqual(find_suspicious_ips(attempts), set())

    def test_empty_logs_produce_no_alerts(self):
        result = analyze_logs([])
        self.assertEqual(result["suspicious_ips"], set())
        self.assertEqual(result["successful_logins"], 0)
        self.assertEqual(result["total_failed_logins"], 0)


if __name__ == "__main__":
    unittest.main()
