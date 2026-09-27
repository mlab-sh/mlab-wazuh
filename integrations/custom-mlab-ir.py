#!/usr/bin/env python3
# Wazuh integratord -> ir.mlab.sh alert ingestion (POST /api/v1/ingest/alert).
# argv: alert_file api_key hook_url [debug] [options_file]
# hook_url is the ir.mlab.sh base URL (e.g. https://ir.example.com); api_key an app token (mlab_app_...).
# Which alerts get sent is decided by <level>/<group>/<rule_id> in ossec.conf.

import json
import os
import ssl
import sys
import time
import urllib.request

WAZUH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
LOG = os.path.join(WAZUH, 'logs', 'integrations.log')

debug = False

# Wazuh's embedded Python has no CA store of its own (looks in /usr/local/ssl): use certifi, which it ships.
try:
    import certifi
    TLS = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    TLS = ssl.create_default_context()


def log(msg):
    if debug:
        with open(LOG, 'a') as f:
            f.write(f'{time.strftime("%a %b %d %H:%M:%S %Z %Y")} custom-mlab-ir: {msg}\n')


def field(alert, path):
    cur = alert
    for k in path.split('.'):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def severity(level):
    # ir.mlab.sh reads bare numbers 6-100 as a risk score, so always send a word
    level = int(level or 0)
    if level >= 13:
        return 'critical'
    if level >= 10:
        return 'high'
    if level >= 7:
        return 'medium'
    if level >= 4:
        return 'low'
    return 'info'


def observables(alert):
    out = []
    for p in ('data.srcip', 'data.dstip', 'agent.ip'):
        if field(alert, p) and field(alert, p) != 'any':
            out.append({'value': field(alert, p)})  # ipv4/ipv6 auto-detected by ir
    for p in ('syscheck.sha256_after', 'syscheck.md5_after'):
        if field(alert, p):
            out.append({'value': field(alert, p), 'type': 'hash'})
            break
    for part in str(field(alert, 'data.win.eventdata.hashes') or '').split(','):
        if part.upper().startswith('SHA256='):
            out.append({'value': part.split('=', 1)[1].lower(), 'type': 'hash'})
    # alerts raised on custom-mlab's events carry the indicator in data.mlab and the file in data.source
    mlab_type = {'hash': 'hash', 'url': 'url', 'cve': 'cve'}.get(field(alert, 'data.mlab.type'))
    if mlab_type and field(alert, 'data.mlab.value'):
        out.append({'value': field(alert, 'data.mlab.value'), 'type': mlab_type})
    elif field(alert, 'data.mlab.type') == 'ip' and field(alert, 'data.mlab.value'):
        out.append({'value': field(alert, 'data.mlab.value')})  # ipv4/ipv6 auto-detected by ir
    for p, t in (('data.url', 'url'), ('data.vulnerability.cve', 'cve'),
                 ('syscheck.path', 'filename'), ('data.source.file', 'filename'), ('agent.name', 'hostname')):
        if field(alert, p):
            out.append({'value': field(alert, p), 'type': t})
    seen, uniq = set(), []
    for o in out:
        if o['value'] not in seen:
            seen.add(o['value'])
            uniq.append(o)
    return uniq[:100]  # ir.mlab.sh caps observables per alert at 100


def payload(alert):
    rule, agent = alert.get('rule', {}), alert.get('agent', {})
    context = [f'Agent: {agent.get("name")} ({agent.get("id")}) {agent.get("ip", "")}'.strip(),
               f'Location: {alert.get("location")}',
               f'Rule: {rule.get("id")} level {rule.get("level")}',
               f'Timestamp: {alert.get("timestamp")}']
    if alert.get('full_log'):
        context += ['', alert['full_log']]
    mitre = field(alert, 'rule.mitre.id') or []
    return {
        'title': rule.get('description') or f'Wazuh rule {rule.get("id")}',
        'severity': severity(rule.get('level')),
        'source': 'wazuh',
        'external_id': alert.get('id'),
        # same rule + agent (+ same mlab indicator) collapses into one ir alert; ir never updates it
        'dedup_key': ':'.join(str(x) for x in ('wazuh', rule.get('id'), agent.get('id'),
                                                  field(alert, 'data.mlab.value')) if x),
        'description': '\n'.join(context),
        'tags': list(rule.get('groups') or []) + list(mitre),
        'observables': observables(alert),
    }


def post(base, key, body):
    req = urllib.request.Request(base.rstrip('/') + '/api/v1/ingest/alert',
                                 data=json.dumps(body).encode(), method='POST',
                                 headers={'Content-Type': 'application/json', 'User-Agent': 'mlab-wazuh',
                                          'Authorization': f'token {key}'})
    with urllib.request.urlopen(req, timeout=20, context=TLS) as r:
        res = json.load(r)
    # ir.mlab.sh rate limiting answers 200 with {"status":"error"}
    if res.get('status') == 'error':
        raise RuntimeError(res.get('error'))
    return res


def run(args):
    global debug
    debug = 'debug' in args[4:]
    alert_file, key, base = args[1], args[2], args[3]
    with open(alert_file) as f:
        alert = json.load(f)
    res = post(base, key, payload(alert))
    log(f'{alert.get("id")} -> {res.get("status")} {res.get("uuid")}')


if __name__ == '__main__':
    try:
        run(sys.argv)
    except Exception as e:
        log(f'fatal: {e}')
        sys.exit(1)
