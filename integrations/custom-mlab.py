#!/usr/bin/env python3
# Wazuh integratord -> mlab.sh enrichment.
# argv: alert_file api_key hook_url [debug] [options_file]
# Results go back to Wazuh's queue as one JSON event per indicator, under "mlab".

import ipaddress
import json
import os
import socket
import ssl
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

WAZUH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
QUEUE = os.path.join(WAZUH, 'queue', 'sockets', 'queue')
LOG = os.path.join(WAZUH, 'logs', 'integrations.log')
CACHE = os.path.join(WAZUH, 'tmp', 'mlab-cache.db')  # integratord runs as wazuh: var/ is root-owned
BASE = 'https://mlab.sh/api/v1'
VULN = 'https://vuln.mlab.sh/api/v1'
TTL = 24 * 3600          # a verdict is reused for a day
QUOTA_BACKOFF = 3600     # after "limit reached", stop asking that bucket for an hour
DEFAULTS = {'hash': True, 'url': False, 'cve': False, 'ip': False}

# Wazuh's embedded Python has no CA store of its own (looks in /usr/local/ssl): use certifi, which it ships.
try:
    import certifi
    TLS = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    TLS = ssl.create_default_context()

debug = False


def log(msg):
    if debug:
        with open(LOG, 'a') as f:
            f.write(f'{time.strftime("%a %b %d %H:%M:%S %Z %Y")} custom-mlab: {msg}\n')


class Cache:
    def __init__(self, path):
        try:
            self.db = sqlite3.connect(path, timeout=10)
            self.db.execute('CREATE TABLE IF NOT EXISTS c (k TEXT PRIMARY KEY, v TEXT, exp REAL)')
        except sqlite3.Error as e:  # no persistent cache is better than no enrichment
            log(f'cache {path} unusable ({e}), running without it')
            self.db = sqlite3.connect(':memory:')
            self.db.execute('CREATE TABLE c (k TEXT PRIMARY KEY, v TEXT, exp REAL)')

    def get(self, k):
        row = self.db.execute('SELECT v FROM c WHERE k=? AND exp>?', (k, time.time())).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, k, v, ttl=TTL):
        self.db.execute('REPLACE INTO c VALUES (?,?,?)', (k, json.dumps(v), time.time() + ttl))
        self.db.commit()


class QuotaReached(Exception):
    pass


def call(url, key=None):
    req = urllib.request.Request(url, headers={'User-Agent': 'mlab-wazuh'})
    if key:
        req.add_header('Authorization', f'token {key}')
    try:
        with urllib.request.urlopen(req, timeout=20, context=TLS) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors='replace')
        # mlab.sh answers quota exhaustion with a 400 "... limit reached", not a 429
        if e.code in (400, 429) and 'limit' in body.lower():
            raise QuotaReached(body)
        raise


def field(alert, path):
    cur = alert
    for k in path.split('.'):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def indicators(alert, opts):
    """(kind, value) pairs worth looking up in this alert."""
    out = []
    if opts['hash']:
        h = field(alert, 'syscheck.sha256_after') or field(alert, 'syscheck.md5_after')
        if h:
            out.append(('hash', h))
        # Sysmon: "SHA1=..,MD5=..,SHA256=..,IMPHASH=.."
        for part in str(field(alert, 'data.win.eventdata.hashes') or '').split(','):
            if part.upper().startswith('SHA256='):
                out.append(('hash', part.split('=', 1)[1].lower()))
    if opts['url'] and field(alert, 'data.url'):
        out.append(('url', field(alert, 'data.url')))
    if opts['cve'] and field(alert, 'data.vulnerability.cve'):
        out.append(('cve', field(alert, 'data.vulnerability.cve')))
    if opts['ip']:
        for p in ('data.srcip', 'data.dstip'):
            v = field(alert, p)
            try:
                if v and ipaddress.ip_address(v).is_global:  # never send internal IPs out
                    out.append(('ip', v))
            except ValueError:
                pass
    return list(dict.fromkeys(out))


def lookup(kind, value, key, base):
    q = urllib.parse.quote(value, safe='')
    if kind == 'hash':
        r = call(f'{base}/scan/hash?hash={q}', key)
        keep = ('verdict', 'known_malicious', 'family', 'file_name', 'product', 'trust',
                'sources_hit', 'sources_answered', 'summary')
        return {k: r[k] for k in keep if k in r}
    if kind == 'url':
        r = call(f'{base}/scan/url?url={q}', key)
        findings = r.get('findings') or []
        return {'host': r.get('host'), 'findings': [f.get('title') for f in findings],
                'severities': sorted({f.get('severity') for f in findings if f.get('severity')})}
    if kind == 'cve':
        r = call(f'{VULN}/cve/{q}')
        keep = ('cvss_score', 'cvss_severity', 'epss_score', 'epss_percentile', 'in_kev', 'kev_date_added',
                'in_eu_kev', 'risk_score')
        return {k: r[k] for k in keep if r.get(k) is not None}
    if kind == 'ip':
        r = call(f'{base}/scan/ip?ip={q}', key)
        keep = ('country_code', 'as', 'org', 'proxy', 'hosting', 'tor')
        out = {k: r[k] for k in keep if k in r}
        if isinstance(out.get('tor'), dict):
            out['tor'] = bool(out['tor'].get('is_tor'))
        return out
    raise ValueError(kind)


def send(event, agent):
    if not agent or agent.get('id') == '000':
        msg = f'1:mlab:{json.dumps(event)}'
    else:
        msg = f'1:[{agent["id"]}] ({agent["name"]}) {agent.get("ip", "any")}->mlab:{json.dumps(event)}'
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.connect(QUEUE)
    s.send(msg.encode())
    s.close()


def load_options(args):
    opts = dict(DEFAULTS)
    for a in args[4:]:
        if a.endswith('options') and os.path.isfile(a):
            with open(a) as f:
                opts.update(json.load(f) or {})
    return opts


def run(args):
    global debug
    debug = 'debug' in args[4:]
    alert_file, key = args[1], args[2]
    base = (args[3] if len(args) > 3 and args[3].startswith('http') else BASE).rstrip('/')
    opts = load_options(args)

    with open(alert_file) as f:
        alert = json.load(f)
    # never enrich our own events
    if field(alert, 'data.integration') == 'mlab' or 'mlab' in (field(alert, 'rule.groups') or []):
        return

    cache = Cache(CACHE)
    try:
        enrich(alert, opts, cache, key, base)
    finally:
        cache.db.close()


def enrich(alert, opts, cache, key, base):
    for kind, value in indicators(alert, opts):
        ck = f'{kind}:{value}'
        result = cache.get(ck)
        if result is None:
            if cache.get(f'quota:{kind}'):
                log(f'{kind} quota exhausted, skipping {value}')
                continue
            try:
                result = lookup(kind, value, key, base)
            except QuotaReached as e:
                log(f'quota reached ({kind}): {e}')
                cache.put(f'quota:{kind}', True, QUOTA_BACKOFF)
                continue
            except Exception as e:  # network / API error: drop this indicator, never crash integratord
                log(f'lookup {ck} failed: {e}')
                continue
            cache.put(ck, result)
        send({'integration': 'mlab',
              'mlab': {'type': kind, 'value': value, **result},
              'source': {'alert_id': alert.get('id'), 'rule': field(alert, 'rule.id'),
                         'description': field(alert, 'rule.description'),
                         'file': field(alert, 'syscheck.path')}},
             alert.get('agent'))


if __name__ == '__main__':
    try:
        run(sys.argv)
    except Exception as e:
        log(f'fatal: {e}')
        sys.exit(1)
