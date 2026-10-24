import contextlib
import io
import json
import math
import random
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from expert_system import KnowledgeBase, combine, extract, infer, inspect, load_samples
from expert_system.cli import main
from expert_system.extractor import brand_for_domain, host_of, registered_domain
from expert_system.knowledge import DEFAULT_KB
from expert_system.report import how_text, to_markdown
from expert_system.webapp import create_server

KB = KnowledgeBase.load()
SAMPLES = load_samples()

EXPECTED = {   # sample -> (verdict label, headline threat)
    "bank_alert": ("Likely scam", "credential_phishing"),
    "parcel_fee": ("Likely scam", "payment_scam"),
    "prize": ("Likely scam", "advance_fee_scam"),
    "invoice_attachment": ("Likely scam", "malware_delivery"),
    "ceo_giftcards": ("Likely scam", "ceo_fraud"),
    "streaming_html": ("Likely scam", "data_harvesting"),
    "otp_whatsapp": ("Likely scam", "account_takeover"),
    "genuine_receipt": ("Low risk", None),
}

BENIGN = {
    "meeting": "Hi team, the standup is moved to 3pm today. Join here: https://zoom.us/j/93812 See you then!",
    "shipped": "From: Amazon <shipment-tracking@amazon.com>\nSubject: Your Amazon order has shipped\n\n"
               "Hello Yasmeen,\nYour package is on its way. Track it at https://www.amazon.com/progress-tracker/package?id=123\n",
    "reset": "From: Google <no-reply@accounts.google.com>\nSubject: Password reset request\n\nHi Yasmeen,\n"
             "We received a request to reset your password. If this was you, use the link below. If not, ignore this email.\n"
             "https://accounts.google.com/signin/recovery\n",
    "friend": "hey are we still on for dinner tonight? text me when you leave work",
    "bank_otp": "Northwind Bank: 482913 is your one-time code for a card payment of 25.00 USD at CAFE NOIR. "
                "Never share this code with anyone.",
}


def signals(text):
    return {k for k, s in extract(text).signals.items() if s.cf > 0}


class ExtractorTests(unittest.TestCase):
    def test_domain_helpers(self):
        self.assertEqual(host_of("https://www.Example.co.uk/path"), "example.co.uk")
        self.assertEqual(registered_domain("mail.shop.example.co.uk"), "example.co.uk")
        self.assertEqual(registered_domain("a.b.example.com"), "example.com")

    def test_lookalike_domains(self):
        self.assertEqual(brand_for_domain("paypa1-secure-login.com"), "paypal")
        self.assertEqual(brand_for_domain("streamfiix-account.com"), "streamflix")    # one letter changed
        self.assertEqual(brand_for_domain("amaz0n-orders.net"), "amazon")
        self.assertEqual(brand_for_domain("northwind-bank-alerts.com"), "northwind bank")
        self.assertIsNotNone(brand_for_domain("xn--pypal-4ve.com"))
        for official in ("paypal.com", "mailer.streamflix.com", "accounts.google.com", "example.org"):
            self.assertIsNone(brand_for_domain(official), official)

    def test_bank_alert_signals(self):
        found = signals(SAMPLES["bank_alert"]["text"])
        for s in ("sender_mismatch", "reply_to_mismatch", "lookalike_domain", "insecure_link", "urgent_tone",
                  "threat_language", "asks_credentials", "generic_greeting", "brand_link_mismatch"):
            self.assertIn(s, found)

    def test_html_link_text_mismatch_and_ip(self):
        found = signals(SAMPLES["streaming_html"]["text"])
        self.assertIn("link_text_mismatch", found)
        self.assertIn("ip_address_link", found)
        self.assertIn("lookalike_domain", found)

    def test_attachment_names_and_email_addresses_are_not_links(self):
        ex = extract(SAMPLES["invoice_attachment"]["text"])
        self.assertIn("risky_attachment", ex.signals)
        self.assertEqual(ex.links, [])
        ex = extract(SAMPLES["ceo_giftcards"]["text"])
        self.assertEqual(ex.links, [])

    def test_text_inside_email_addresses_is_not_a_link(self):
        ex = extract("From: Help <support@cloudvau1t-storage.com>\nReply-To: help.desk.team@outlook.com\n"
                     "Subject: hi\n\nWrite to help.desk.team@outlook.com or visit http://bit.ly/x")
        self.assertEqual([l["host"] for l in ex.links], ["bit.ly"])

    def test_brand_mentioned_in_passing_is_not_a_claim(self):
        found = signals("From: Sam <sam@example.org>\nSubject: lunch\n\nCan you bring my Apple charger tomorrow?")
        self.assertNotIn("claims_brand", found)

    def test_role_from_free_mail(self):
        found = signals(SAMPLES["ceo_giftcards"]["text"])
        self.assertTrue({"free_mail_brand", "secrecy_request", "asks_payment"} <= found)

    def test_code_request(self):
        self.assertIn("asks_code", signals(SAMPLES["otp_whatsapp"]["text"]))
        self.assertNotIn("asks_code", signals(BENIGN["bank_otp"]))

    def test_spans_point_at_the_evidence(self):
        ex = extract(SAMPLES["parcel_fee"]["text"])
        for sig in ex.signals.values():
            for a, b in sig.spans:
                self.assertTrue(0 <= a < b <= len(ex.text))
        a, b = ex.signals["url_shortener"].spans[0]
        self.assertIn("bit.ly", ex.text[a:b])

    def test_empty_and_odd_input(self):
        self.assertEqual(extract("").signals, {})
        extract("From: \nSubject:\n\n<a href='javascript:void(0)'>x</a>")


class ReasoningTests(unittest.TestCase):
    def test_every_sample_gets_the_expected_verdict(self):
        for name, (label, headline) in EXPECTED.items():
            v = inspect(KB, SAMPLES[name]["text"])["verdict"]
            self.assertEqual(v["label"], label, name)
            self.assertEqual(v["top"]["fact"] if v["top"] else None, headline, name)

    def test_no_false_alarms_on_ordinary_messages(self):
        for name, text in BENIGN.items():
            v = inspect(KB, text)["verdict"]
            self.assertEqual(v["label"], "Low risk", name)

    def test_multi_step_chain(self):
        out = inspect(KB, SAMPLES["bank_alert"]["text"])
        tree = how_text(out["result"], "report_message")
        for step in ("S1", "S3", "C1", "X1", "A11"):
            self.assertIn(step, tree)
        self.assertEqual(max(KB.level(r) for r in KB.rules), 5)

    def test_override_removes_a_signal_and_re_reasons(self):
        before = inspect(KB, SAMPLES["parcel_fee"]["text"])["verdict"]
        after = inspect(KB, SAMPLES["parcel_fee"]["text"], {"brand_link_mismatch": None})["verdict"]
        self.assertEqual(before["label"], "Likely scam")
        self.assertEqual(after["label"], "Suspicious")
        added = inspect(KB, BENIGN["friend"], {"asks_code": 1.0, "urgent_tone": 1.0})["verdict"]
        self.assertEqual(added["top"]["fact"], "account_takeover")
        with self.assertRaises(ValueError):
            inspect(KB, "hi", {"made_up": 1})

    def test_urgent_advice_comes_first(self):
        recs = inspect(KB, SAMPLES["bank_alert"]["text"])["result"].recommendations
        self.assertEqual(recs[0]["severity"], "danger")
        self.assertEqual([r["severity"] for r in recs], sorted((r["severity"] for r in recs),
                         key=["danger", "caution", "advice"].index))

    def test_rule_order_does_not_change_results(self):
        data = json.loads(DEFAULT_KB.read_text(encoding="utf-8"))
        rng = random.Random(3)
        base = {n: inspect(KB, s["text"])["result"].facts for n, s in SAMPLES.items()}
        for _ in range(5):
            rng.shuffle(data["rules"])
            kb = KnowledgeBase.from_dict(data)
            for n, s in SAMPLES.items():
                got = inspect(kb, s["text"])["result"].facts
                self.assertEqual(set(got), set(base[n]))
                for k in got:
                    self.assertTrue(math.isclose(got[k], base[n][k], abs_tol=1e-12))

    def test_certainty_combination(self):
        self.assertAlmostEqual(combine(0.6, 0.5), 0.8)
        self.assertAlmostEqual(combine(-0.6, -0.5), -0.8)

    def test_knowledge_base_is_clean(self):
        self.assertEqual(KB.lint(), [])
        concluded = {r.conclusion for r in KB.rules}
        self.assertTrue(set(KB.actions) <= concluded)
        self.assertTrue(set(KB.verdict["threats"]) <= concluded)

    def test_reports(self):
        md = to_markdown(inspect(KB, SAMPLES["prize"]["text"])["result"])
        self.assertTrue(md.startswith("# PhishGuard reasoning report"))
        json.dumps(inspect(KB, SAMPLES["prize"]["text"])["result"].to_dict())


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_samples_and_inspect(self):
        self.assertIn("bank_alert", run_cli("samples")[1])
        code, out, _ = run_cli("--sample", "bank_alert", "--brief")
        self.assertEqual(code, 0)
        self.assertIn("VERDICT: LIKELY SCAM", out)
        code, out, _ = run_cli("inspect", "--text", BENIGN["friend"], "--brief")
        self.assertIn("LOW RISK", out)

    def test_file_json_report_explain(self):
        with tempfile.TemporaryDirectory() as tmp:
            msg = Path(tmp) / "m.txt"
            msg.write_text(SAMPLES["prize"]["text"])
            code, out, _ = run_cli("inspect", str(msg), "--json")
            self.assertEqual(json.loads(out)["verdict"]["top"]["fact"], "advance_fee_scam")
            report = Path(tmp) / "r.md"
            self.assertEqual(run_cli("inspect", str(msg), "--report", str(report))[0], 0)
            self.assertIn("PhishGuard", report.read_text())
        code, out, _ = run_cli("explain", "ceo_fraud", "--sample", "ceo_giftcards")
        self.assertIn("secrecy_request", out)
        self.assertEqual(run_cli("explain", "ceo_fraud", "--sample", "genuine_receipt")[0], 1)

    def test_lint_rules_and_errors(self):
        self.assertIn("OK: no problems found", run_cli("lint")[1])
        self.assertIn("C1", run_cli("rules")[1])
        self.assertEqual(run_cli("--sample", "nope")[0], 2)
        self.assertEqual(run_cli("inspect", "missing-file.eml")[0], 2)


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = create_server(KB, port=0)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def call(self, path, body=None):
        req = urllib.request.Request(self.base + path, data=None if body is None else json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read()) if path.startswith("/api") else r.read()
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_page_and_kb(self):
        status, html = self.call("/")
        self.assertEqual(status, 200)
        self.assertIn(b"PhishGuard", html)
        status, kb = self.call("/api/kb")
        self.assertEqual(len(kb["samples"]), len(SAMPLES))
        self.assertIn("claims_brand", kb["context"])

    def test_inspect_and_report(self):
        status, data = self.call("/api/inspect", {"text": SAMPLES["ceo_giftcards"]["text"], "overrides": {}})
        self.assertEqual(status, 200)
        self.assertEqual(data["verdict"]["top"]["fact"], "ceo_fraud")
        self.assertTrue(data["graph"]["nodes"])
        status, data = self.call("/api/report", {"text": SAMPLES["prize"]["text"], "format": "txt"})
        self.assertIn("PHISHGUARD", data["content"])

    def test_bad_requests(self):
        for body in ({"text": ""}, {"text": "hi", "overrides": {"nope": 1}}, {"text": "hi", "overrides": {"asks_code": 5}},
                     {"text": 42}, {"text": "hi", "overrides": []}):
            self.assertEqual(self.call("/api/inspect", body)[0], 400, body)
        self.assertEqual(self.call("/api/report", {"text": "hi", "format": "exe"})[0], 400)


if __name__ == "__main__":
    unittest.main()
