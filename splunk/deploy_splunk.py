import os
import glob
import yaml
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

splunk_host = os.getenv("SPLUNK_HOST", "64.177.50.61")
splunk_port = os.getenv("SPLUNK_PORT", "8089")
splunk_token = os.getenv("SPLUNK_TOKEN")

# Telegram parametrləri - bunları da GitHub Secrets kimi əlavə et
TELEGRAM_BOT_ID = os.getenv("TELEGRAM_BOT_ID")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

headers = {
    "Authorization": f"Bearer {splunk_token}"
}

rule_files = glob.glob("splunk/rules/**/*.yml", recursive=True)


def render_value(real_field, value, modifier):
    """Bir sahə üçün SPL şərti qurur, Sigma modifikatoruna görə wildcard yerləşdirir."""
    if modifier == "contains":
        pattern = f"*{value}*"
    elif modifier == "startswith":
        pattern = f"{value}*"
    elif modifier == "endswith":
        pattern = f"*{value}"
    else:
        pattern = f"{value}"
    return f'{real_field}="{pattern}"'


def build_spl_from_sigma(rule):
    """
    Sigma 'detection' blokunu SPL-ə çevirir.
    'selection' altında sahə adları modifikator daşıya bilər: field, field|contains,
    field|startswith, field|endswith. Hamısı düzgün SPL wildcard sintaksisinə çevrilir
    (pipe işarəsi SPL əmr ayırıcısı ilə qarışmasın deyə, modifikator SPL-ə YAZILMIR,
    yalnız dəyərin özünə wildcard əlavə olunur).
    """
    detection = rule.get("detection", {})
    selection = detection.get("selection", {})
    logsource = rule.get("logsource", {})

    conditions = []

    product = logsource.get("product", "")
    if product:
        conditions.append(f'index="{product}"')

    for field, value in selection.items():
        if "|" in field:
            real_field, modifier = field.split("|", 1)
        else:
            real_field, modifier = field, None

        if isinstance(value, list):
            terms = " OR ".join([render_value(real_field, v, modifier) for v in value])
            conditions.append(f"({terms})")
        else:
            conditions.append(render_value(real_field, value, modifier))

    if not conditions:
        return None

    return " ".join(conditions)


for file_path in rule_files:
    with open(file_path, "r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)

    if not rule:
        continue

    rule_name = rule.get("title", "Unnamed Sigma Rule")
    safe_rule_name = rule_name.replace(" ", "_").replace("-", "_")
    description = rule.get("description", "")
    level = rule.get("level", "medium")

    spl_search = build_spl_from_sigma(rule)
    if not spl_search:
        print(f"[SKIP] {file_path} üçün SPL qurula bilmədi (detection boşdur)")
        continue

    # NOT: "nobody" əvəzinə konkret owner ("admin") istifadə olunur ki, update və create
    # eyni namespace-ə düşsün - əks halda hər push-da "already exists" konflikti yaranır.
    owner = "admin"
    app = "search"
    url = f"https://{splunk_host}:{splunk_port}/servicesNS/{owner}/{app}/saved/searches/{safe_rule_name}?output_mode=json"

    payload = {
        "name": safe_rule_name,
        "search": spl_search,
        "cron_schedule": "*/5 * * * *",
        "is_scheduled": "1",
        "disabled": "0",
        "description": description,
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",
    }

    # Telegram Alert Action parametrləri (app-ın adına görə param adları fərqli ola bilər -
    # Splunk-da quraşdırdığın Telegram app-ının "Setup" səhifəsindən dəqiq adları yoxla)
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

    response = requests.post(url, headers=headers, data=payload, verify=False)

    if response.status_code in [200, 201]:
        print(f"[SUCCESS] Qayda yeniləndi: {safe_rule_name}")
    else:
        print(f"[INFO] Update alınmadı ({response.status_code}), yaratmağa cəhd olunur: {response.text[:200]}")
        create_url = f"https://{splunk_host}:{splunk_port}/servicesNS/{owner}/{app}/saved/searches?output_mode=json"
        res_create = requests.post(create_url, headers=headers, data=payload, verify=False)
        if res_create.status_code in [200, 201]:
            print(f"[CREATED] Yeni qayda yaradıldı: {safe_rule_name}")
        else:
            print(f"[ERROR] {safe_rule_name} yaradıla bilmədi: {res_create.status_code} - {res_create.text[:300]}")
