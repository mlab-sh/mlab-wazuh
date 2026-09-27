# mlab-wazuh

Enrich Wazuh alerts with [mlab.sh](https://mlab.sh): file hashes (FIM, Sysmon), and optionally URLs, CVEs and public IPs.
Each lookup comes back into Wazuh as an event under `data.mlab.*`, matched by `rules/mlab_rules.xml` (IDs 100600-100699):

| Rule | Level | When |
|---|---|---|
| 100601 | 12 | file hash known malicious |
| 100602 | 3 | file hash known good |
| 100603 | 7 | URL with a high/critical finding |
| 100604 | 6 | IP is a Tor exit node |
| 100605 | 3 | CVE context (CVSS, EPSS) |
| 100606 | 13 | CVE in the CISA KEV (exploited in the wild) |

| Lookup | Alert field | mlab quota |
|---|---|---|
| hash (default on) | `syscheck.sha256_after` / `md5_after`, Sysmon `data.win.eventdata.hashes` | none |
| url | `data.url` | none |
| cve | `data.vulnerability.cve` (vuln.mlab.sh) | none |
| ip | `data.srcip`, `data.dstip` (public only) | ip |

Results are cached 24h in `/var/ossec/tmp/mlab-cache.db`; a bucket that hits its quota is paused for an hour.

## Install (manager)

```sh
cp integrations/custom-mlab* /var/ossec/integrations/
cp rules/mlab_rules.xml /var/ossec/etc/rules/
chown root:wazuh /var/ossec/integrations/custom-mlab* /var/ossec/etc/rules/mlab_rules.xml
chmod 750 /var/ossec/integrations/custom-mlab*
```

`/var/ossec/etc/ossec.conf`:

```xml
<integration>
  <name>custom-mlab</name>
  <api_key>mlab_...</api_key>
  <group>syscheck,sysmon_event1,authentication_failed,squid,vulnerability-detector</group>
  <alert_format>json</alert_format>
  <options>{"url": true, "cve": false, "ip": false}</options>
</integration>
```

`<hook_url>` is optional (defaults to `https://mlab.sh/api/v1`). Restart: `systemctl restart wazuh-manager`.
Debug logs go to `/var/ossec/logs/integrations.log` when integratord runs in debug mode.

## Forward alerts to ir.mlab.sh

`custom-mlab-ir` posts alerts to `POST /api/v1/ingest/alert` on your ir.mlab.sh instance.
Create an **app token** (`mlab_app_...`) in ir.mlab.sh under Settings → API keys.

| ir.mlab.sh field | From the Wazuh alert |
|---|---|
| `title` | `rule.description` |
| `severity` | `rule.level`: 13+ critical, 10+ high, 7+ medium, 4+ low, else info |
| `external_id` | `id` |
| `dedup_key` | `wazuh:<rule.id>:<agent.id>`, plus `:<indicator>` on mlab alerts (repeats collapse into one alert, `ingest_count` goes up) |
| `description` | agent, location, rule, timestamp, `full_log` |
| `tags` | `rule.groups` + MITRE ids |
| `observables` | src/dst/agent IP, file hash, URL, CVE, file path, agent name |

```xml
<integration>
  <name>custom-mlab-ir</name>
  <hook_url>https://ir.example.com</hook_url>
  <api_key>mlab_app_...</api_key>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

Observables ingested this way are not auto-enriched by ir.mlab.sh; `custom-mlab` covers the enrichment on the Wazuh side.

## Test

```sh
python3 -m unittest discover -s tests
```

## Dev stack

Wazuh 4.14.8 (manager, indexer, dashboard, one agent `web01`) + ir.mlab.sh, with this repo's integrations and rules mounted live.
Needs Docker with ~8 GB RAM and `MLAB_IR_LI=<ir.mlab.sh licence>` in `.env` (optionally `MLAB_API_KEY=mlab_...`, otherwise mlab.sh lookups are anonymous).

```sh
dev/setup.sh   # certs, ir.mlab.sh app token, rendered ossec.conf, everything up
dev/e2e.sh     # unit tests, logtest on the rules, EICAR dropped on web01 -> mlab.sh -> rule 100601 -> ir.mlab.sh
```

| | URL | Login |
|---|---|---|
| Wazuh dashboard | https://localhost:8443 | `admin` / `SecretPassword` |
| ir.mlab.sh | http://localhost:8080 | `admin@localhost` / `adminadmin` |

After editing an integration script nothing needs restarting (files are bind-mounted); after editing `rules/mlab_rules.xml` or `dev/wazuh/*` re-run `dev/setup.sh` (it recreates the manager: the image only copies its config on create, a plain restart is not enough).
Tear down: `docker compose down -v`.
