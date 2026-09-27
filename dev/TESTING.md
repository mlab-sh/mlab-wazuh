# Tester la stack à la main

Prérequis : `dev/setup.sh` terminé (« Stack is up »). Toutes les commandes se lancent depuis la racine du repo.
Garder au moins 5 Go libres : `df -h .` ; en cas de doute `docker compose stop`.

| | URL | Login |
|---|---|---|
| Wazuh dashboard | https://localhost:8443 (certificat auto-signé, accepter l'avertissement) | `admin` / `SecretPassword` |
| ir.mlab.sh | http://localhost:8080 | `admin@localhost` / `adminadmin` |

## 0. Tout d'un coup

```sh
dev/e2e.sh
```
Attendu : `All checks passed.` Rejouable autant de fois que voulu.

## 1. La stack tourne

```sh
docker compose ps
docker compose exec wazuh.manager /var/ossec/bin/agent_control -l
```
Attendu : 8 services `Up`, et l'agent `web01` en `Active`.

## 2. Les règles mlab (sans réseau)

```sh
echo '{"integration":"mlab","mlab":{"type":"hash","value":"x","verdict":"known_malicious"},"source":{"file":"/tmp/x"}}' \
  | docker compose exec -T wazuh.manager /var/ossec/bin/wazuh-logtest
```
Attendu : `id: '100601'`, `level: '12'`. Varier `verdict` en `known_good` → règle `100602`, niveau 3.

## 3. Un malware sur l'agent → verdict mlab.sh

Déposer EICAR (fichier de test antivirus inoffensif) dans le dossier surveillé en temps réel :
```sh
docker compose exec wazuh.agent sh -c "printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*' > /mlab-fim/test-\$(date +%s).com"
```
Puis, dans les ~10 secondes :
```sh
docker compose exec wazuh.manager sh -c "grep '\"100601\"' /var/ossec/logs/alerts/alerts.json | tail -1" | python3 -m json.tool
```
Attendu : `rule.level` 12, `data.mlab.verdict` = `known_malicious`, `data.mlab.file_name` = `eicar.com`, `data.source.file` = le fichier déposé.

Dans le **dashboard Wazuh** : menu → Threat Hunting → Events, filtre `rule.id:100601` (ou `rule.groups:mlab`).

## 4. L'alerte arrive dans ir.mlab.sh

Dans **ir.mlab.sh** → Alerts (http://localhost:8080/a/) :
- titre `mlab: known malicious file /mlab-fim/...`, sévérité **high**, tags `mlab`, `malware`, `T1204`, `source:wazuh` ;
- en ouvrant l'alerte : description avec agent / règle / horodatage ; observables : hash sha256 EICAR, chemin du fichier, `web01`, IP de l'agent.

Côté Wazuh, la trace de l'envoi :
```sh
docker compose exec wazuh.manager grep custom-mlab-ir /var/ossec/logs/integrations.log | tail -3
```
Attendu : `<id alerte> -> created <uuid>` puis `duplicate` pour les suivantes.

## 5. Déduplication

Relancer la commande de l'étape 3 (nouveau nom, même contenu). Attendu :
- une nouvelle alerte 100601 dans Wazuh (verdict servi par le cache, pas de nouvel appel mlab.sh) ;
- **pas** de nouvelle alerte dans ir.mlab.sh : la même, `duplicate` dans le log ci-dessus.
Un autre malware (autre hash) ou un autre agent créerait une nouvelle alerte ir.

## 6. IP, URL, CVE (logs de l'agent → règle Wazuh standard → mlab)

L'agent lit `/mlab-logs/{auth.log,squid.log,vuln.json}` ; on y écrit des lignes réalistes :
```sh
# IP : échec SSH depuis un nœud Tor → règle 5710 → mlab.sh /scan/ip → 100604 (tor=true)
docker compose exec wazuh.agent sh -c "echo \"\$(date '+%b %d %H:%M:%S') web01 sshd[1]: Failed password for invalid user bob from 185.220.101.1 port 22 ssh2\" >> /mlab-logs/auth.log"

# URL : proxy squid qui bloque un .exe (garder les espaces, format squid réel) → règle 35005 → mlab.sh /scan/url → 100603 (finding high)
docker compose exec wazuh.agent sh -c "echo \"\$(date +%s).000    150 10.0.0.5 TCP_DENIED/403 3605 GET http://bit.ly/facture-\$RANDOM.exe - HIER_NONE/- text/html\" >> /mlab-logs/squid.log"

# CVE : même format que le module vulnérabilités → règle 23506 (critique) → vuln.mlab.sh → 100606 (KEV, niveau 13) → ir.mlab.sh
docker compose exec wazuh.agent sh -c "echo '{\"vulnerability\":{\"cve\":\"CVE-2021-44228\",\"status\":\"Active\",\"severity\":\"Critical\",\"package\":{\"name\":\"log4j-core\",\"version\":\"2.14.1\"}}}' >> /mlab-logs/vuln.json"
```
Voir le résultat : dashboard → Threat Hunting, filtre `rule.groups:mlab`, ou
```sh
docker compose exec wazuh.manager sh -c "grep '\"integration\":\"mlab\"' /var/ossec/logs/alerts/alerts.json | tail -3" | cut -c1-400
```
Le lookup IP consomme le quota mlab.sh (5/jour en anonyme). Une fois épuisé : `quota reached (ip)` dans `integrations.log`, les IP sont mises en pause 1h, le reste continue. Mettre `MLAB_API_KEY=mlab_...` dans `.env` puis `dev/setup.sh` pour utiliser ton quota d'orga.

## 7. Robustesse

- **mlab.sh injoignable** : `docker compose exec wazuh.manager sh -c 'echo "127.0.0.1 mlab.sh" >> /etc/hosts'`, refaire l'étape 3 → pas de 100601, une ligne `lookup ... failed` dans `integrations.log`, et Wazuh continue normalement. Annuler : `docker compose restart wazuh.manager`.
- **ir.mlab.sh arrêté** : `docker compose stop ir-app`, refaire l'étape 3 → 100601 présente dans Wazuh, erreur dans `integrations.log`, rien ne plante. `docker compose start ir-app` pour revenir.

## Modifier et retester

- Scripts `integrations/*.py` : pris en compte immédiatement (dossier monté).
- `rules/mlab_rules.xml` ou `dev/wazuh/*.conf` : `dev/setup.sh` (re-génère la conf et recrée le manager si elle a changé ; un simple `restart` ne suffit pas).
- Tests unitaires : `python3 -m unittest discover -s tests`.

## Arrêter / nettoyer

```sh
docker compose stop        # garde tout, libère CPU/RAM
docker compose down -v     # supprime conteneurs + volumes de ce projet (~1 Go)
docker image rm wazuh/wazuh-manager:4.14.8 wazuh/wazuh-indexer:4.14.8 wazuh/wazuh-dashboard:4.14.8 \
  wazuh/wazuh-agent:4.14.8 wazuh/wazuh-certs-generator:0.0.4 ghcr.io/mlab-sh/ir.mlab.sh:latest \
  ghcr.io/mlab-sh/ir.mlab.sh-executor:latest mysql:8 clickhouse/clickhouse-server:latest   # ~10 Go
```
