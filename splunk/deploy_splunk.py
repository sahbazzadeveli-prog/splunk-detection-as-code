import os
import glob
import yaml
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunk_host = os.getenv("SPLUNK_HOST", "64.177.50.61")
splunk_port = os.getenv("SPLUNK_PORT", "8089")
splunk_token = os.getenv("SPLUNK_TOKEN")

headers = {
    "Authorization": f"Bearer {splunk_token}"
}

rule_files = glob.glob("splunk/rules/**/*.yml", recursive=True)

for file_path in rule_files:
    with open(file_path, "r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)
    
    if not rule:
        continue

    rule_name = rule.get("title", "Unnamed Sigma Rule")
    safe_rule_name = rule_name.replace(" ", "_").replace("-", "_")
    description = rule.get("description", "")
    
    url = f"https://{splunk_host}:{splunk_port}/servicesNS/nobody/search/saved/searches/{safe_rule_name}?output_mode=json"
    
    payload = {
        "name": safe_rule_name,
        "search": 'index="web_api"',
        "cron_schedule": "*/5 * * * *",
        "is_scheduled": "1",
        "disabled": "0",
        "description": description
    }
    
    response = requests.post(url, headers=headers, data=payload, verify=False)
    
    if response.status_code in [200, 201]:
        print(f"[SUCCESS] Qayda yeniləndi: {safe_rule_name}")
    else:
        create_url = f"https://{splunk_host}:{splunk_port}/servicesNS/nobody/search/saved/searches?output_mode=json"
        res_create = requests.post(create_url, headers=headers, data=payload, verify=False)
        print(f"[CREATED] Yeni qayda yaradıldı ({res_create.status_code}): {safe_rule_name}")
