#!/usr/bin/env bash
# End-to-end checks against the running dev stack (dev/setup.sh first).
# Chain under test: agent FIM -> manager alert -> custom-mlab -> mlab.sh -> rule 100601 -> custom-mlab-ir -> ir.mlab.sh
set -uo pipefail
cd "$(dirname "$0")/.."

IR=http://localhost:8080
GEN=dev/.generated
fails=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
ko()   { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fails=$((fails+1)); }
step() { printf '\n\033[1m[%s]\033[0m\n' "$*"; }
mgr()  { docker compose exec -T wazuh.manager "$@"; }
# wait_for <seconds> <command...>: retry every 2s until the command succeeds
wait_for() { local end=$((SECONDS+$1)); shift; until "$@"; do [ $SECONDS -ge $end ] && return 1; sleep 2; done; }

free_gb=$(df -g . | awk 'NR==2 {print $4}')
[ "$free_gb" -ge 5 ] || { echo "only ${free_gb} GB free on disk (< 5 GB), stop the stack first: docker compose stop"; exit 1; }

step "1. Unit tests"
if out=$(python3 -m unittest discover -s tests 2>&1); then ok "$(tail -1 <<<"$out") ($(grep -oE 'Ran [0-9]+ tests' <<<"$out"))"
else ko "unit tests"; tail -20 <<<"$out" | sed 's/^/    /'; fi

step "2. Services reachable"
curl -sk -o /dev/null -w '%{http_code}' https://localhost:8443/app/login | grep -qE '200|302' && ok "Wazuh dashboard https://localhost:8443" || ko "Wazuh dashboard"
curl -s -o /dev/null -w '%{http_code}' "$IR/" | grep -qE '^[23]' && ok "ir.mlab.sh $IR" || ko "ir.mlab.sh"
mgr /var/ossec/bin/agent_control -l | grep -q 'web01.*Active' && ok "agent web01 active" || ko "agent web01 not active"

step "3. Files deployed in the manager"
for f in integrations/custom-mlab integrations/custom-mlab.py integrations/custom-mlab-ir integrations/custom-mlab-ir.py etc/rules/mlab_rules.xml; do
  mgr test -r "/var/ossec/$f" && ok "$f" || ko "$f missing"
done
mgr grep -q '<name>custom-mlab-ir</name>' /var/ossec/etc/ossec.conf && ok "integrations declared in ossec.conf" || ko "ossec.conf"
mgr pgrep -f wazuh-integratord >/dev/null && ok "wazuh-integratord running" || ko "wazuh-integratord not running"

step "4. Rules (wazuh-logtest)"
# wazuh-logtest is not ready for a while after the manager (re)starts: keep trying for 30s
logtest1() { mgr /var/ossec/bin/wazuh-logtest <<<"$1" 2>&1 | grep -q "id: '$2'"; }
logtest() { wait_for 30 logtest1 "$@"; }
logtest '{"integration":"mlab","mlab":{"type":"hash","value":"x","verdict":"known_malicious"},"source":{"file":"/tmp/x"}}' 100601 \
  && ok "hash known_malicious -> 100601 (level 12)" || ko "100601"
logtest '{"integration":"mlab","mlab":{"type":"hash","value":"x","verdict":"known_good"},"source":{"file":"/tmp/x"}}' 100602 \
  && ok "hash known_good -> 100602" || ko "100602"
logtest '{"integration":"mlab","mlab":{"type":"url","value":"http://bit.ly/x.exe","severities":["high","medium"]}}' 100603 \
  && ok "url with high finding -> 100603" || ko "100603"
logtest '{"integration":"mlab","mlab":{"type":"ip","value":"185.220.101.1","tor":true}}' 100604 \
  && ok "tor ip -> 100604" || ko "100604"

step "5. Full chain: EICAR dropped on agent web01"
EICAR_SHA=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
name="eicar-$(date +%s).com"
drop() { docker compose exec -T wazuh.agent sh -c "printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*' > /mlab-fim/$1"; }
alert() { mgr grep -h "$1" /var/ossec/logs/alerts/alerts.json | grep "\"id\":\"$2\""; }
alert_id() { alert "$1" 100601 | tail -1 | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["id"])'; }
# custom-mlab-ir logs "<wazuh alert id> -> created|duplicate <ir uuid>"
ir_result() { mgr grep -h "custom-mlab-ir: $1 -> " /var/ossec/logs/integrations.log | tail -1 | awk '{print $(NF-1), $NF}'; }
irlogin() { curl -s -c "$GEN/ir_cookies" -o /dev/null -H 'Content-Type: application/json' \
  -d '{"email":"admin@localhost","password":"adminadmin"}' "$IR/api/v1/auth/login"; }

drop "$name"
echo "  wrote /mlab-fim/$name on web01 (EICAR, sha256 ${EICAR_SHA:0:12}...)"
wait_for 120 alert "$name" 554 >/dev/null && ok "FIM alert 554 (file added)" || ko "no FIM alert for $name"
wait_for 60 alert "$name" 100601 >/dev/null && ok "mlab.sh verdict known_malicious -> rule 100601 level 12" \
  || ko "no 100601 for $name (see /var/ossec/logs/integrations.log)"
id1=$(alert_id "$name")
if [ -n "$id1" ] && wait_for 30 sh -c "[ -n \"\$(docker compose exec -T wazuh.manager grep -h 'custom-mlab-ir: $id1 -> ' /var/ossec/logs/integrations.log)\" ]"; then
  read -r status1 uuid <<<"$(ir_result "$id1")"
  ok "sent to ir.mlab.sh: $status1 (uuid $uuid)"
  irlogin
  a=$(curl -s -b "$GEN/ir_cookies" "$IR/api/v1/alerts/$uuid")
  grep -q '"severity": *"high"' <<<"$a" && ok "ir alert severity high (Wazuh level 12)" || ko "severity: ${a:0:300}"
  grep -q 'known malicious file' <<<"$a" && ok "ir alert title from rule 100601" || ko "title: ${a:0:300}"
  grep -q '"source": *"siem"' <<<"$a" && ok "ir alert source siem (tag source:wazuh)" || ko "source: ${a:0:300}"
  obs=$(curl -s -b "$GEN/ir_cookies" "$IR/api/v1/observables/by-alert/$uuid")
  grep -q "$EICAR_SHA" <<<"$obs" && ok "observable: EICAR sha256 (hash)" || ko "no hash observable"
  grep -q '"/mlab-fim/' <<<"$obs" && ok "observable: file path" || ko "no filename observable"
  grep -q '"web01"' <<<"$obs" && ok "observable: hostname web01" || ko "no hostname observable"
else
  ko "custom-mlab-ir did not send alert $id1"
fi

step "6. Dedup: same malware on same agent collapses in ir.mlab.sh"
drop "again-$name"
wait_for 90 alert "again-$name" 100601 >/dev/null && ok "second EICAR -> 100601 (verdict served from cache)" \
  || ko "no 100601 for again-$name"
id2=$(alert_id "again-$name")
wait_for 30 sh -c "[ -n \"\$(docker compose exec -T wazuh.manager grep -h 'custom-mlab-ir: $id2 -> ' /var/ossec/logs/integrations.log)\" ]"
read -r status2 uuid2 <<<"$(ir_result "$id2")"
[ "$status2" = duplicate ] && [ "$uuid2" = "${uuid:-x}" ] && ok "ir answered duplicate, same alert $uuid2" \
  || ko "expected duplicate of ${uuid:-?}, got '$status2 $uuid2'"

step "7. IP, URL and CVE through the real pipeline (agent logs -> Wazuh rule -> custom-mlab)"
ts=$(date +%s)
agent_log() { docker compose exec -T wazuh.agent sh -c "cat >> /mlab-logs/$1" <<<"$2"; }
# chain <marker> <first rule> <mlab rule>: the source alert, then the mlab alert built on it (data.source.alert_id)
chain() {
  wait_for 90 alert "$1" "$2" >/dev/null || { ko "no rule $2 alert for $1"; return 1; }
  local src; src=$(alert "$1" "$2" | tail -1 | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["id"])')
  ok "rule $2 fired (alert $src)"
  wait_for 60 alert "\"alert_id\":\"$src\"" "$3" >/dev/null || { ko "no mlab rule $3 for alert $src"; return 1; }
  mlab_alert=$(alert "\"alert_id\":\"$src\"" "$3" | tail -1)
}
field() { python3 -c 'import json,sys; d=json.loads(sys.argv[1])
for k in sys.argv[2].split("."): d=d.get(k, {}) if isinstance(d, dict) else {}
print(d)' "$mlab_alert" "$1"; }

echo "  IP: sshd failure from Tor exit 185.220.101.1"
agent_log auth.log "$(date '+%b %d %H:%M:%S') web01 sshd[4242]: Failed password for invalid user mlab$ts from 185.220.101.1 port 4242 ssh2"
if chain "mlab$ts" 5710 100604; then
  ok "mlab.sh: tor=$(field data.mlab.tor) country=$(field data.mlab.country_code) -> rule 100604"
elif mgr grep -q 'quota reached (ip)\|ip quota exhausted' /var/ossec/logs/integrations.log; then
  fails=$((fails-1))  # the ko above is the quota, not a bug: handled as designed (logged, IP lookups parked 1h)
  printf '  \033[33mSKIP\033[0m IP quota exhausted on mlab.sh (anonymous: 5/day). Put MLAB_API_KEY in .env and re-run dev/setup.sh\n'
fi

echo "  URL: squid blocked http://bit.ly/invoice-$ts.exe"
agent_log squid.log "$ts.000    150 10.0.0.5 TCP_DENIED/403 3605 GET http://bit.ly/invoice-$ts.exe - HIER_NONE/- text/html"
if chain "invoice-$ts" 35005 100603; then
  ok "mlab.sh: findings=$(field data.mlab.findings) -> rule 100603"
fi

echo "  CVE: CVE-2021-44228 (Log4Shell) reported on package log4j-$ts"
agent_log vuln.json "{\"vulnerability\":{\"cve\":\"CVE-2021-44228\",\"status\":\"Active\",\"severity\":\"Critical\",\"package\":{\"name\":\"log4j-$ts\",\"version\":\"2.14.1\"}}}"
if chain "log4j-$ts" 23506 100606; then
  ok "vuln.mlab.sh: in_kev=$(field data.mlab.in_kev) cvss=$(field data.mlab.cvss_score) epss=$(field data.mlab.epss_score) -> rule 100606 level 13"
  cve_id=$(field id)
  wait_for 30 sh -c "[ -n \"\$(docker compose exec -T wazuh.manager grep -h 'custom-mlab-ir: $cve_id -> ' /var/ossec/logs/integrations.log)\" ]"
  read -r st cu <<<"$(ir_result "$cve_id")"
  obs=$(curl -s -b "$GEN/ir_cookies" "$IR/api/v1/observables/by-alert/$cu")
  [ -n "$cu" ] && grep -q 'CVE-2021-44228' <<<"$obs" && ok "level 13 -> ir.mlab.sh ($st), observable CVE-2021-44228" \
    || ko "KEV alert not in ir.mlab.sh ('$st $cu')"
fi

step "8. Indexed for the dashboard"
indexed() { docker compose exec -T wazuh.indexer curl -sk -u admin:SecretPassword \
  "https://localhost:9200/wazuh-alerts-*/_count?q=rule.id:100601" | grep -qE '"count":[1-9]'; }
wait_for 90 indexed && ok "rule 100601 in wazuh-alerts-* (visible in Threat Hunting)" || ko "not indexed yet"

step "9. Integration log (last lines)"
mgr grep -E 'custom-mlab' /var/ossec/logs/integrations.log 2>/dev/null | tail -5 | cut -c1-200 | sed 's/^/  /'

echo
[ "$fails" -eq 0 ] && printf '\033[32mAll checks passed.\033[0m\n' || printf '\033[31m%d check(s) failed.\033[0m\n' "$fails"
exit "$fails"
