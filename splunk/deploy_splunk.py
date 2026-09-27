import os
import glob
import yaml
import requests
import urllib3
from urllib.parse import quote

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunk_host = os.getenv("SPLUNK_HOST", "64.177.50.61")
splunk_port = os.getenv("SPLUNK_PORT", "8089")
splunk_token = os.getenv("SPLUNK_TOKEN")

TELEGRAM_BOT_ID = os.getenv("TELEGRAM_BOT_ID")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

headers = {
    "Authorization": f"Bearer {splunk_token}"
}

rule_files = glob.glob("splunk/rules/**/*.yml", recursive=True)

SEVERITY_MAP = {"low": "2", "medium": "3", "high": "4", "critical": "5"}


def render_value(real_field, value, modifier):
    if modifier == "contains":
        pattern = f"*{value}*"
    elif modifier == "startswith":
        pattern = f"{value}*"
    elif modifier == "endswith":
        pattern = f"*{value}"
    else:
        pattern = f"{value}"
    return f'{real_field}="{pattern}"'


def build_selection_spl(selection_block):
    terms = []
    for field, value in selection_block.items():
        if "|" in field:
            real_field, modifier = field.split("|", 1)
        else:
            real_field, modifier = field, None

        if isinstance(value, list):
            or_terms = " OR ".join([render_value(real_field, v, modifier) for v in value])
            terms.append(f"({or_terms})")
        else:
            terms.append(render_value(real_field, value, modifier))
    return " ".join(terms)


def build_spl_from_sigma(rule):
    detection = rule.get("detection", {})
    logsource = rule.get("logsource", {})
    condition = detection.get("condition", "selection")

    index_prefix = ""
    product = logsource.get("product", "")
    if product:
        index_prefix = f'index="{product}" '

    selection_blocks = {
        key: value for key, value in detection.items() if key != "condition"
    }

    if not selection_blocks:
        return None

    if len(selection_blocks) == 1:
        only_block = next(iter(selection_blocks.values()))
        block_spl = build_selection_spl(only_block)
        return f"{index_prefix}{block_spl}" if block_spl else None

    rendered_blocks = {
        name: build_selection_spl(block) for name, block in selection_blocks.items()
    }

    condition_lower = condition.lower()
    if " or " in condition_lower:
        joiner = " OR "
    else:
        joiner = " AND "

    combined = joiner.join([f"({spl})" for spl in rendered_blocks.values() if spl])
    if not combined:
        return None

    return f"{index_prefix}({combined})"


for file_path in rule_files:
    with open(file_path, "r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)

    if not rule:
        continue

    rule_name = rule.get("title", "Unnamed Sigma Rule")
    safe_rule_name = rule_name.replace(" ", "_").replace("-", "_")
    encoded_rule_name = quote(safe_rule_name, safe="")
    description = rule.get("description", "")
    level = rule.get("level", "medium")

    spl_search = build_spl_from_sigma(rule)
    if not spl_search:
        print(f"[SKIP] {file_path} üçün SPL qurula bilmədi (detection boşdur)")
        continue

    owner = "nobody"
    app = "search"
    base_url = f"https://{splunk_host}:{splunk_port}/servicesNS/{owner}/{app}/saved/searches"
    check_url = f"https://{splunk_host}:{splunk_port}/servicesNS/-/-/saved/searches/{encoded_rule_name}?output_mode=json"

    payload = {
        "name": safe_rule_name,
        "search": spl_search,
        "cron_schedule": "*/5 * * * *",
        "dispatch.earliest_time": "-6m",
        "dispatch.latest_time": "now",
        "is_scheduled": "1",
        "disabled": "0",
        "description": description,
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",
        "alert.track": "1",
        "alert.suppress": "0",
        "alert.severity": SEVERITY_MAP.get(level, "3"),
    }

    if TELEGRAM_BOT_ID and TELEGRAM_CHAT_ID:
        payload.update({
            "actions": "telegram",
            "action.telegram": "1",
            "action.telegram.param.bot_id": TELEGRAM_BOT_ID,
            "action.telegram.param.chat_id": TELEGRAM_CHAT_ID,
            "action.telegram.param.severity": level,
            "action.telegram.param.event_title": rule_name,
            "action.telegram.param.message": f"Alert triggered: {rule_name} - {description}",
        })

    check_response = requests.get(check_url, headers=headers, verify=False)

    if check_response.status_code == 200:
        # Qlobal/paylaşılan (nobody) namespace-i məcburi işlədirik ki,
        # istifadəçiyə xas gizli surət yaranmasın
        real_owner, real_app = "nobody", "search"

        update_payload = {k: v for k, v in payload.items() if k != "name"}
        real_update_url = f"https://{splunk_host}:{splunk_port}/servicesNS/{real_owner}/{real_app}/saved/searches/{encoded_rule_name}?output_mode=json"
        response = requests.post(real_update_url, headers=headers, data=update_payload, verify=False)
        if response.status_code in [200, 201]:
            print(f"[SUCCESS] Qayda yeniləndi: {safe_rule_name} (owner={real_owner}, app={real_app})")
        else:
            print(f"[ERROR] {safe_rule_name} yenilənə bilmədi: {response.status_code} - {response.text[:300]}")
    else:
        print(f"[DEBUG] {safe_rule_name} üçün GET check {check_response.status_code} qaytardı: {check_response.text[:200]}")
        response = requests.post(f"{base_url}?output_mode=json", headers=headers, data=payload, verify=False)
        if response.status_code in [200, 201]:
            print(f"[CREATED] Yeni qayda yaradıldı: {safe_rule_name}")
        else:
            print(f"[ERROR] {safe_rule_name} yaradıla bilmədi: {response.status_code} - {response.text[:300]}")
