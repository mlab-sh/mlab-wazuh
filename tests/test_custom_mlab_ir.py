import json
import os
import tempfile
import unittest
import urllib.error

from helpers import FakeAPI, load

m = load('custom-mlab-ir')

ALERT = {
    'id': '1695812345.123', 'timestamp': '2026-09-27T10:00:00.000+0000', 'location': 'syscheck',
    'full_log': "File '/tmp/x' added",
    'rule': {'id': '554', 'level': 12, 'description': 'File added to the system.',
             'groups': ['ossec', 'syscheck'], 'mitre': {'id': ['T1204']}},
    'agent': {'id': '001', 'name': 'web01', 'ip': '10.0.0.5'},
    'syscheck': {'path': '/tmp/x', 'sha256_after': 'a' * 64, 'md5_after': 'b' * 32},
    'data': {'srcip': '10.0.0.5'},
}
INGEST = '/api/v1/ingest/alert'


class Payload(unittest.TestCase):
    def test_mapping(self):
        p = m.payload(ALERT)
        self.assertEqual(p['title'], 'File added to the system.')
        self.assertEqual(p['severity'], 'high')
        self.assertEqual(p['source'], 'wazuh')
        self.assertEqual(p['external_id'], '1695812345.123')
        self.assertEqual(p['dedup_key'], 'wazuh:554:001')
        self.assertEqual(p['tags'], ['ossec', 'syscheck', 'T1204'])
        self.assertEqual(p['description'].splitlines(), [
            'Agent: web01 (001) 10.0.0.5', 'Location: syscheck', 'Rule: 554 level 12',
            'Timestamp: 2026-09-27T10:00:00.000+0000', '', "File '/tmp/x' added"])
        self.assertEqual(p['observables'], [
            {'value': '10.0.0.5'},                       # srcip == agent.ip, kept once
            {'value': 'a' * 64, 'type': 'hash'},          # sha256 preferred over md5
            {'value': '/tmp/x', 'type': 'filename'},
            {'value': 'web01', 'type': 'hostname'},
        ])

    def test_severity_boundaries_always_a_word(self):
        cases = {0: 'info', 3: 'info', 4: 'low', 6: 'low', 7: 'medium', 9: 'medium',
                 10: 'high', 12: 'high', 13: 'critical', 15: 'critical', None: 'info', '11': 'high'}
        for level, want in cases.items():
            self.assertEqual(m.severity(level), want, level)

    def test_minimal_manager_alert(self):
        p = m.payload({'id': '9', 'rule': {'id': '5501', 'level': 3}, 'agent': {'id': '000', 'name': 'mgr'}})
        self.assertEqual(p['title'], 'Wazuh rule 5501')  # no description: still accepted by ir (title required)
        self.assertEqual(p['tags'], [])
        self.assertEqual(p['observables'], [{'value': 'mgr', 'type': 'hostname'}])

    def test_sysmon_url_cve_and_any_ip(self):
        p = m.payload({'rule': {}, 'agent': {'ip': 'any'},
                       'data': {'dstip': '8.8.8.8', 'url': 'http://x', 'vulnerability': {'cve': 'CVE-2024-1'},
                                'win': {'eventdata': {'hashes': 'MD5=Y,SHA256=' + 'C' * 64}}}})
        self.assertEqual(p['observables'], [
            {'value': '8.8.8.8'}, {'value': 'c' * 64, 'type': 'hash'},
            {'value': 'http://x', 'type': 'url'}, {'value': 'CVE-2024-1', 'type': 'cve'}])

    def test_mlab_enrichment_alert(self):
        # what actually reaches ir: the rule 100601 alert built on custom-mlab's event, no syscheck block
        a = {'id': '5', 'rule': {'id': '100601', 'level': 12, 'description': 'mlab: known malicious file /mlab-fim/x'},
             'agent': {'id': '002', 'name': 'web01', 'ip': '172.18.0.8'},
             'data': {'integration': 'mlab', 'mlab': {'type': 'hash', 'value': 'a' * 64, 'verdict': 'known_malicious'},
                      'source': {'file': '/mlab-fim/x', 'rule': '554'}}}
        self.assertEqual(m.payload(a)['dedup_key'], 'wazuh:100601:002:' + 'a' * 64)
        self.assertEqual(m.payload(a)['observables'], [
            {'value': '172.18.0.8'}, {'value': 'a' * 64, 'type': 'hash'},
            {'value': '/mlab-fim/x', 'type': 'filename'}, {'value': 'web01', 'type': 'hostname'}])
        self.assertEqual(m.payload({'rule': {}, 'agent': {},
                                    'data': {'mlab': {'type': 'ip', 'value': '8.8.8.8'}}})['observables'],
                         [{'value': '8.8.8.8'}])

    def test_payload_is_json_serialisable(self):
        json.dumps(m.payload(ALERT))


class Wire(unittest.TestCase):
    def setUp(self):
        self.api = FakeAPI({INGEST: (200, {'status': 'created', 'uuid': 'u1', 'deduplicated': False})})
        self.alert = os.path.join(tempfile.mkdtemp(), 'alert.json')
        with open(self.alert, 'w') as f:
            json.dump(ALERT, f)

    def tearDown(self):
        self.api.close()

    def run_it(self, base=None):
        m.run(['custom-mlab-ir', self.alert, 'mlab_app_x', base or self.api.url])

    def test_end_to_end_request(self):
        self.run_it(self.api.url + '/')  # trailing slash in hook_url tolerated
        req, = self.api.requests
        self.assertEqual((req['method'], req['path']), ('POST', INGEST))
        self.assertEqual(req['headers']['Authorization'], 'token mlab_app_x')
        self.assertEqual(req['headers']['Content-Type'], 'application/json')
        self.assertEqual(req['body'], m.payload(ALERT))

    def test_duplicate_is_success(self):
        self.api.routes[INGEST] = (200, {'status': 'duplicate', 'uuid': 'u1', 'deduplicated': True, 'ingest_count': 2})
        self.run_it()

    def test_rate_limit_in_200_body_is_an_error(self):
        self.api.routes[INGEST] = (200, {'status': 'error', 'error': 'Ingestion rate limit exceeded'})
        with self.assertRaisesRegex(RuntimeError, 'rate limit'):
            self.run_it()

    def test_http_errors_raise(self):
        for status in (400, 401, 404, 500):
            self.api.routes[INGEST] = (status, {'error': 'x'})
            with self.assertRaises(urllib.error.HTTPError):
                self.run_it()

    def test_unreachable_server_raises(self):
        with self.assertRaises(OSError):
            self.run_it('http://127.0.0.1:1')


if __name__ == '__main__':
    unittest.main()
