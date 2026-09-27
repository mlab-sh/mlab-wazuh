import json
import os
import subprocess
import sys
import tempfile
import unittest

from helpers import FakeAPI, FakeQueue, load

m = load('custom-mlab')

SHA = 'a' * 64
HASH_OK = {'verdict': 'known_malicious', 'known_malicious': True, 'file_name': 'x.exe',
           'sources_hit': 1, 'sources': {'noise': 'dropped'}, 'cached': True}
FIM = {'id': '1', 'agent': {'id': '001', 'name': 'web01', 'ip': '10.0.0.5'},
       'rule': {'id': '554', 'groups': ['ossec', 'syscheck']},
       'syscheck': {'path': '/tmp/x.exe', 'sha256_after': SHA}}


class Indicators(unittest.TestCase):
    ALL = {'hash': True, 'url': True, 'cve': True, 'ip': True}

    def test_fim_prefers_sha256_and_falls_back_to_md5(self):
        self.assertEqual(m.indicators({'syscheck': {'sha256_after': SHA, 'md5_after': 'b' * 32}}, m.DEFAULTS),
                         [('hash', SHA)])
        self.assertEqual(m.indicators({'syscheck': {'md5_after': 'b' * 32}}, m.DEFAULTS), [('hash', 'b' * 32)])

    def test_sysmon_hashes_lowercased_and_deduped(self):
        a = {'syscheck': {'sha256_after': SHA},
             'data': {'win': {'eventdata': {'hashes': 'SHA1=X,MD5=Y,SHA256=' + SHA.upper() + ',IMPHASH=Z'}}}}
        self.assertEqual(m.indicators(a, m.DEFAULTS), [('hash', SHA)])

    def test_optional_kinds_off_by_default(self):
        a = {'data': {'url': 'http://x', 'vulnerability': {'cve': 'CVE-2024-1'}, 'srcip': '8.8.8.8'}}
        self.assertEqual(m.indicators(a, m.DEFAULTS), [])
        self.assertEqual(m.indicators(a, self.ALL),
                         [('url', 'http://x'), ('cve', 'CVE-2024-1'), ('ip', '8.8.8.8')])

    def test_internal_and_garbage_ips_never_sent(self):
        for ip in ('10.0.0.1', '192.168.1.1', '127.0.0.1', '100.64.0.1', 'fe80::1', 'any', 'not-an-ip'):
            self.assertEqual(m.indicators({'data': {'srcip': ip}}, self.ALL), [], ip)

    def test_missing_or_non_dict_fields(self):
        self.assertEqual(m.indicators({'syscheck': 'oops', 'data': None}, self.ALL), [])


class Options(unittest.TestCase):
    def test_options_file_found_among_extra_args(self):
        f = tempfile.NamedTemporaryFile('w', suffix='.options', delete=False)
        json.dump({'url': True}, f)
        f.close()
        opts = m.load_options(['x', 'alert', 'key', '', 'debug', f.name])
        self.assertEqual(opts, {'hash': True, 'url': True, 'cve': False, 'ip': False})

    def test_no_options_means_defaults(self):
        self.assertEqual(m.load_options(['x', 'alert', 'key', '']), m.DEFAULTS)


class Cache(unittest.TestCase):
    def test_expiry(self):
        c = m.Cache(os.path.join(tempfile.mkdtemp(), 'c.db'))
        c.put('k', {'v': 1})
        c.put('old', {'v': 2}, ttl=-1)
        self.assertEqual(c.get('k'), {'v': 1})
        self.assertIsNone(c.get('old'))
        self.assertIsNone(c.get('missing'))
        c.db.close()


class Wire(unittest.TestCase):
    """Runs the integration against a local fake mlab API and a real unix socket."""

    def setUp(self):
        self.api = FakeAPI({'/scan/hash': (200, HASH_OK)})
        self.queue = FakeQueue()
        self.tmp = tempfile.mkdtemp()
        self.saved = m.QUEUE, m.CACHE
        m.QUEUE, m.CACHE = self.queue.path, os.path.join(self.tmp, 'c.db')

    def tearDown(self):
        m.QUEUE, m.CACHE = self.saved
        self.api.close()
        self.queue.close()

    def go(self, alert, options=None):
        path = os.path.join(self.tmp, 'alert.json')
        with open(path, 'w') as f:
            json.dump(alert, f)
        args = ['custom-mlab', path, 'mlab_k', self.api.url]
        if options is not None:
            opt = os.path.join(self.tmp, 'custom-mlab.options')
            with open(opt, 'w') as f:
                json.dump(options, f)
            args.append(opt)
        m.run(args)

    def test_agent_alert_end_to_end(self):
        self.go(FIM)
        req, = self.api.requests
        self.assertEqual(req['path'], f'/scan/hash?hash={SHA}')
        self.assertEqual(req['headers']['Authorization'], 'token mlab_k')
        msg, = self.queue.messages()
        self.assertTrue(msg.startswith('1:[001] (web01) 10.0.0.5->mlab:{'), msg)
        ev = json.loads(msg.split('->mlab:', 1)[1])
        self.assertEqual(ev['integration'], 'mlab')
        self.assertEqual(ev['mlab'], {'type': 'hash', 'value': SHA, 'verdict': 'known_malicious',
                                      'known_malicious': True, 'file_name': 'x.exe', 'sources_hit': 1})
        self.assertEqual(ev['source'], {'alert_id': '1', 'rule': '554', 'description': None, 'file': '/tmp/x.exe'})

    def test_manager_alert_header(self):
        self.go({**FIM, 'agent': {'id': '000', 'name': 'manager'}})
        msg, = self.queue.messages()
        self.assertTrue(msg.startswith('1:mlab:{'), msg)

    def test_cache_hit_skips_api_but_still_emits(self):
        self.go(FIM)
        self.go({**FIM, 'id': '2'})
        self.assertEqual(len(self.api.requests), 1)
        self.assertEqual([e['source']['alert_id'] for e in self.queue.events()], ['1', '2'])

    def test_quota_400_parks_only_that_kind(self):
        self.api.routes['/scan/ip'] = (400, {'error': 'IP lookup limit reached. Please try again later.'})
        alert = {**FIM, 'data': {'srcip': '8.8.8.8'}}
        self.go(alert, {'ip': True})
        self.go({**alert, 'data': {'srcip': '1.1.1.1'}, 'syscheck': {'sha256_after': 'c' * 64}}, {'ip': True})
        paths = [r['path'].split('?')[0] for r in self.api.requests]
        self.assertEqual(paths, ['/scan/hash', '/scan/ip', '/scan/hash'])  # 2nd IP never asked, hashes still are
        self.assertEqual([e['mlab']['type'] for e in self.queue.events()], ['hash', 'hash'])

    def test_other_errors_are_retried_next_time(self):
        self.api.routes['/scan/hash'] = (500, {'error': 'boom'})
        self.go(FIM)
        self.go(FIM)
        self.assertEqual(len(self.api.requests), 2)  # neither cached nor parked
        self.assertEqual(self.queue.messages(), [])

    def test_plain_400_is_not_mistaken_for_quota(self):
        self.api.routes['/scan/hash'] = (400, {'error': 'invalid hash'})
        self.go(FIM)
        self.go(FIM)
        self.assertEqual(len(self.api.requests), 2)

    def test_url_and_ip_responses_trimmed(self):
        self.api.routes['/scan/url'] = (200, {'host': 'bit.ly', 'findings': [
            {'severity': 'high', 'title': 'Executable payload'}, {'severity': 'medium', 'title': 'Shortener'},
            {'severity': 'high', 'title': 'Other'}]})
        self.api.routes['/scan/ip'] = (200, {'country_code': 'DE', 'tor': {'available': True, 'is_tor': True},
                                             'rdap': {'big': 'dropped'}})
        self.go({'id': '3', 'data': {'url': 'http://bit.ly/x.exe', 'srcip': '185.220.101.1'}},
                {'hash': False, 'url': True, 'ip': True})
        url, ip = [e['mlab'] for e in self.queue.events()]
        self.assertEqual(url['findings'], ['Executable payload', 'Shortener', 'Other'])
        self.assertEqual(url['severities'], ['high', 'medium'])
        self.assertEqual(ip, {'type': 'ip', 'value': '185.220.101.1', 'country_code': 'DE', 'tor': True})
        self.assertEqual(self.api.requests[0]['path'], '/scan/url?url=http%3A%2F%2Fbit.ly%2Fx.exe')

    def test_unwritable_cache_still_enriches(self):
        m.CACHE = '/nonexistent-dir/mlab-cache.db'  # what happened with /var/ossec/var (root-owned)
        self.go(FIM)
        self.assertEqual(self.queue.events()[0]['mlab']['verdict'], 'known_malicious')

    def test_cve_keeps_prioritisation_fields(self):
        self.api.routes['/cve/CVE-2021-44228'] = (200, {
            'id': 'CVE-2021-44228', 'description': 'long text', 'cvss_score': 10.0, 'cvss_severity': 'CRITICAL',
            'epss_score': 0.94, 'in_kev': True, 'kev_date_added': '2021-12-10', 'in_eu_kev': False,
            'kev_due_date': None, 'references': [{'url': 'x'}], 'risk_score': 99.9})
        m.VULN, saved = self.api.url, m.VULN
        try:
            self.go({'id': '4', 'data': {'vulnerability': {'cve': 'CVE-2021-44228'}}}, {'hash': False, 'cve': True})
        finally:
            m.VULN = saved
        ev, = self.queue.events()
        self.assertEqual(ev['mlab'], {'type': 'cve', 'value': 'CVE-2021-44228', 'cvss_score': 10.0,
                                      'cvss_severity': 'CRITICAL', 'epss_score': 0.94, 'in_kev': True,
                                      'kev_date_added': '2021-12-10', 'in_eu_kev': False, 'risk_score': 99.9})
        self.assertEqual(self.api.requests[0]['headers'].get('Authorization'), None)  # public API, key not leaked

    def test_own_events_ignored(self):
        self.go({**FIM, 'rule': {'groups': ['mlab']}})
        self.go({**FIM, 'data': {'integration': 'mlab'}})
        self.assertEqual(self.api.requests, [])


class Cli(unittest.TestCase):
    def test_bad_input_exits_1_without_traceback(self):
        p = subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), '..', 'integrations', 'custom-mlab.py'),
                            '/nonexistent.json', 'k', ''], capture_output=True, text=True)
        self.assertEqual(p.returncode, 1)
        self.assertEqual(p.stderr, '')


if __name__ == '__main__':
    unittest.main()
