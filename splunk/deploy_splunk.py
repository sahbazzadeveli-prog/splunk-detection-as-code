import os
import json
import glob
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_HOST = os.getenv("SPLUNK_HOST")
SPLUNK_PORT = os.getenv("SPLUNK_PORT", "8089")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN")

headers = {"Authorization": f"Bearer {SPLUNK_TOKEN}"}
rule_files = glob.glob("splunk/rules/*.json")

for file_path in rule_files:
    with open(file_path, "r", encoding="utf-8") as f:
        rule = json.load(f)

    rule_name = rule["name"]
    url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/servicesNS/nobody/search/saved/searches/{rule_name}?output_mode=json"

    payload = {
        "search": rule["search"],
        "cron_schedule": rule.get("cron_schedule", "*/5 * * * *"),
        "is_scheduled": "1",
        "disabled": "0",
        "description": rule.get("description", "")
    }

    response = requests.post(url, headers=headers, data=payload, verify=False)
    if response.status_code in [200, 201]:
        print(f"[SUCCESS] Qayda yeniləndi: {rule_name}")
    else:
        create_url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/servicesNS/nobody/search/saved/searches?output_mode=json"
        payload["name"] = rule_name
        res_create = requests.post(create_url, headers=headers, data=payload, verify=False)
        print(f"[CREATED] Yeni qayda yaradıldı ({res_create.status_code}): {rule_name}")
