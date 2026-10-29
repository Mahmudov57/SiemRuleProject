import os
import sys
import glob
import argparse
import requests
import urllib3
import yaml
from urllib.parse import quote

MARKER = "[managed-by: github]"
REQUIRED = ["name", "description", "mitre", "severity", "search", "false_positives"]

HOST = os.environ["SPLUNK_HOST"].rstrip("/")
HEADERS = {"Authorization": f"Bearer {os.environ['SPLUNK_TOKEN']}"}
VERIFY = os.environ.get("SPLUNK_VERIFY_TLS", "false").lower() == "true"
BASE = f"{HOST}/servicesNS/nobody/search/saved/searches"

if not VERIFY:
    urllib3.disable_warnings()


def load_rules():
    rules = []
    for path in sorted(glob.glob("rules/splunk/*.y*ml")):
        with open(path, encoding="utf-8") as fh:
            rule = yaml.safe_load(fh)
        missing = [k for k in REQUIRED if not rule.get(k)]
        if missing:
            raise ValueError(f"{path}: çatışmayan sahələr: {missing}")
        rule["_file"] = path
        rules.append(rule)
    names = [r["name"] for r in rules]
    if len(names) != len(set(names)):
        raise ValueError("Təkrarlanan rule adları var")
    return rules


def build_payload(rule):
    fp = "; ".join(rule["false_positives"])
    desc = (
        f"{rule['description']} | MITRE: {rule['mitre']} | "
        f"FP: {fp} | {MARKER}"
    )
    data = {
        "search": rule["search"],
        "description": desc,
        "is_scheduled": "1",
        "cron_schedule": rule.get("cron", "*/15 * * * *"),
        "dispatch.earliest_time": rule.get("earliest", "-15m"),
        "dispatch.latest_time": "now",
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",
        "alert.severity": str(rule["severity"]),
        "alert.track": "1",
        "alert.suppress": "1",
        "alert.suppress.period": rule.get("throttle_period", "1h"),
        "alert.suppress.fields": rule.get("throttle_fields", ""),
        "disabled": "0",
        "output_mode": "json",
    }
    return data


def deploy(rule, dry_run):
    name = rule["name"]
    data = build_payload(rule)
    if dry_run:
        print(f"[DRY-RUN] {name}")
        return
    url = f"{BASE}/{quote(name, safe='')}"
    r = requests.post(url, headers=HEADERS, data=data, verify=VERIFY, timeout=30)
    action = "UPDATED"
    if r.status_code == 404:
        r = requests.post(BASE, headers=HEADERS, data={"name": name, **data},
                          verify=VERIFY, timeout=30)
        action = "CREATED"
    r.raise_for_status()
    print(f"{action}: {name} ({rule['mitre']})")


def remove_orphans(local_names, dry_run):
    r = requests.get(BASE, headers=HEADERS, verify=VERIFY, timeout=30,
                     params={"output_mode": "json", "count": 0})
    r.raise_for_status()
    for entry in r.json()["entry"]:
        desc = entry["content"].get("description") or ""
        if MARKER in desc and entry["name"] not in local_names:
            if dry_run:
                print(f"[DRY-RUN] DELETE: {entry['name']}")
                continue
            d = requests.delete(f"{BASE}/{quote(entry['name'], safe='')}",
                                headers=HEADERS, verify=VERIFY, timeout=30)
            d.raise_for_status()
            print(f"DELETED (repoda yoxdur): {entry['name']}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    rules = load_rules()
    failed = []
    for rule in rules:
        try:
            deploy(rule, args.dry_run)
        except Exception as exc:
            print(f"FAILED: {rule['name']} -> {exc}")
            failed.append(rule["name"])

    if not failed:
        remove_orphans({r["name"] for r in rules}, args.dry_run)

    print(f"\nCəmi: {len(rules)} | Uğurlu: {len(rules) - len(failed)} | Xəta: {len(failed)}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
