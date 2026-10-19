import unittest

from logsentinel.parsers import parse_ssh_line, parse_access_line, normalize_url


class TestSshParser(unittest.TestCase):
    def test_failed_password(self):
        line = "Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for root from 173.234.31.186 port 38926 ssh2"
        ev = parse_ssh_line(line, 2026)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.action, "failed_password")
        self.assertEqual(ev.src_ip, "173.234.31.186")
        self.assertEqual(ev.user, "root")

    def test_invalid_user(self):
        line = "Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186"
        ev = parse_ssh_line(line, 2026)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.action, "invalid_user")
        self.assertEqual(ev.user, "webmaster")

    def test_accepted(self):
        line = "Dec 10 07:00:00 LabSZ sshd[24200]: Accepted password for admin from 10.0.0.5 port 22 ssh2"
        ev = parse_ssh_line(line, 2026)
        self.assertEqual(ev.action, "accepted")
        self.assertEqual(ev.user, "admin")

    def test_irrelevant_line_returns_none(self):
        self.assertIsNone(parse_ssh_line("Dec 10 06:55:46 LabSZ sshd[24200]: Connection closed by 1.2.3.4", 2026))


class TestWebParser(unittest.TestCase):
    def test_access_line(self):
        line = '192.0.2.77 - - [15/Sep/2026:10:20:31 +0300] "GET /urun.php?id=1 HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
        ev = parse_access_line(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.src_ip, "192.0.2.77")
        self.assertEqual(ev.method, "GET")
        self.assertEqual(ev.status, 200)

    def test_malformed_line_returns_none(self):
        self.assertIsNone(parse_access_line("bu gecerli bir log satiri degil"))


class TestNormalizeUrl(unittest.TestCase):
    def test_lowercase(self):
        self.assertEqual(normalize_url("/ADMIN/Panel"), "/admin/panel")

    def test_double_url_decode(self):
        # %27%20OR%20%271%27%3D%271  ->  ' or '1'='1
        self.assertIn("or", normalize_url("/x?q=%27%20OR%20%271%27%3D%271"))


if __name__ == "__main__":
    unittest.main()
