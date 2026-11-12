import unittest
from main import audit

GOOD = {'Strict-Transport-Security':'max-age=31536000; includeSubDomains', 'Content-Security-Policy':"default-src 'self'; frame-ancestors 'none'",'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'}
class Tests(unittest.TestCase):
    def test_policy_pass(self): self.assertEqual(audit(GOOD),[])
    def test_case_insensitive_names(self): self.assertEqual(audit({k.upper():v for k,v in GOOD.items()}),[])
    def test_missing(self): self.assertEqual(len(audit({})),5)
    def test_hsts_disabled(self): self.assertIn('hsts',[x['rule'] for x in audit(dict(GOOD, **{'Strict-Transport-Security':'max-age=0'}))])
    def test_unsafe_script(self): self.assertIn('csp_script',[x['rule'] for x in audit(dict(GOOD, **{'Content-Security-Policy':"script-src 'unsafe-inline'; frame-ancestors 'none'"}))])
    def test_invalid(self):
        with self.assertRaises(ValueError): audit({'x':1})
