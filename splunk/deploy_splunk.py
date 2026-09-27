import os
import json
import glob
import requests
import urllib3
import yaml

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_HOST = os.getenv("SPLUNK_HOST")
SPLUNK_PORT = os.getenv("SPLUNK_PORT", "8089")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN")

headers = {"Authorization": f"Bearer {SPLUNK_TOKEN}"}
rule_files = glob.glob("splunk/rules/**/*.yml", recursive=True)

for file_path in rule_files:
    with open(file_path, "r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)

    if not rule:
        continue

    rule_name = rule.get("title", "Unnamed Sigma Rule")
    # Splunk adlarında boşluq və xüsusi simvollar problem yaratmasın deyə təmizləyirik
    safe_rule_name = rule_name.replace(" ", "_").replace("-", "_")
    
    # Sigma daxilindəki detection şərtini Splunk search formatına uyğunlaşdırırıq (sadələşdirilmiş)
    description = rule.get("description", "")
    
    url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/servicesNS/nobody/search/saved/searches/{safe_rule_name}?output_mode=json"

    # Sigma qaydasını Splunk Saved Search formatına çeviririk
    payload = {
        "name": safe_rule_name,
        "search": f'index=* | eval rule_title="{rule_name}"', # Buranı öz log indexinə uyğunlaşdıra bilərsən
        "cron_schedule": "*/5 * * * *",
        "is_scheduled": "1",
        "disabled": "0",
        "description": description
    }

    response = requests.post(url, headers=headers, data=payload, verify=False)
    if response.status_code in [200, 201]:
        print(f"[SUCCESS] Qayda yeniləndi: {safe_rule_name}")
    else:
        create_url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/servicesNS/nobody/search/saved/searches?output_mode=json"
        res_create = requests.post(create_url, headers=headers, data=payload, verify=False)
        print(f"[CREATED] Yeni qayda yaradıldı ({res_create.status_code}): {safe_rule_name}")
