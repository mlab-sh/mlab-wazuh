#!/usr/bin/env bash
# Feed sample custom-mlab events to wazuh-logtest and check which rule fires.
# LOGTEST is the command that runs wazuh-logtest reading stdin; default: the dev stack's manager.
# Used by dev/e2e.sh and by CI (against a bare wazuh-manager container).
set -uo pipefail
LOGTEST=${LOGTEST:-docker compose exec -T wazuh.manager /var/ossec/bin/wazuh-logtest}
fails=0

# check <expected rule id> <expected level> <label> <json event>
check() {
  local out
  # wazuh-logtest is not ready for a while after the manager starts: retry for 60s
  for _ in $(seq 30); do
    out=$($LOGTEST <<<"$4" 2>&1)
    grep -q "id: '$1'" <<<"$out" && break
    sleep 2
  done
  if grep -q "id: '$1'" <<<"$out" && grep -q "level: '$2'" <<<"$out"; then
    printf '  \033[32mPASS\033[0m %s -> %s (level %s)\n' "$3" "$1" "$2"
  else
    printf '  \033[31mFAIL\033[0m %s: expected rule %s level %s, got: %s\n' "$3" "$1" "$2" \
      "$(grep -E "id: |level: " <<<"$out" | tr -s '\t\n ' ' ')"
    fails=$((fails+1))
  fi
}

check 100601 12 "hash known_malicious" '{"integration":"mlab","mlab":{"type":"hash","value":"x","verdict":"known_malicious"},"source":{"file":"/tmp/x"}}'
check 100602 3  "hash known_good"      '{"integration":"mlab","mlab":{"type":"hash","value":"x","verdict":"known_good"},"source":{"file":"/tmp/x"}}'
check 100600 0  "hash unknown (silent)" '{"integration":"mlab","mlab":{"type":"hash","value":"x","verdict":"unknown"},"source":{"file":"/tmp/x"}}'
check 100603 7  "url with high finding" '{"integration":"mlab","mlab":{"type":"url","value":"http://bit.ly/x.exe","severities":["high","medium"]}}'
check 100600 0  "url, medium only"     '{"integration":"mlab","mlab":{"type":"url","value":"http://x","severities":["medium"]}}'
check 100604 6  "tor ip"               '{"integration":"mlab","mlab":{"type":"ip","value":"185.220.101.1","tor":true}}'
check 100605 3  "cve context"          '{"integration":"mlab","mlab":{"type":"cve","value":"CVE-2024-3094","cvss_score":10,"epss_score":0.86,"in_kev":false}}'
check 100606 13 "cve in KEV"           '{"integration":"mlab","mlab":{"type":"cve","value":"CVE-2021-44228","in_kev":true,"kev_date_added":"2021-12-10"}}'

exit "$fails"
