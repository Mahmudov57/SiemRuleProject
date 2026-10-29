import os
import glob
import yaml
import requests
import urllib3
from urllib.parse import quote

urllib3.disable_warnings()

HOST = os.environ["SPLUNK_HOST"].rstrip("/")
HEADERS = {"Authorization": f"Bearer {os.environ['SPLUNK_TOKEN']}"}
BASE = f"{HOST}/servicesNS/nobody/search/saved/searches"


def deploy(rule):
    name = rule["name"]
    data = {
        "search": rule["search"],
        "description": f"{rule.get('description', '')} [MITRE {rule.get('mitre', '')}]",
        "is_scheduled": "1",
        "cron_schedule": rule.get("cron", "*/15 * * * *"),
        "dispatch.earliest_time": rule.get("earliest", "-15m"),
        "dispatch.latest_time": "now",
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",
        "alert.severity": str(rule.get("severity", 3)),
        "alert.track": "1",
        "output_mode": "json",
    }
    # Əvvəlcə update cəhdi, 404 olarsa create
    r = requests.post(f"{BASE}/{quote(name, safe='')}", headers=HEADERS, data=data, verify=False, timeout=30)
    if r.status_code == 404:
        r = requests.post(BASE, headers=HEADERS, data={"name": name, **data}, verify=False, timeout=30)
    r.raise_for_status()
    print(f"OK: {name}")


files = sorted(glob.glob("rules/splunk/*.y*ml"))
if not files:
    raise SystemExit("Rule faylı tapılmadı")

for f in files:
    with open(f, encoding="utf-8") as fh:
        deploy(yaml.safe_load(fh))
