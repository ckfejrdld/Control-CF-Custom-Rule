import requests
import config

def control_custom_rule(rule_name, state):
    headers = {
        "X-Auth-Key": config.api_key,
        "X-Auth-Email": config.email,
        "Content-Type": "application/json"
    }
    response = requests.get(f"https://api.cloudflare.com/client/v4/zones/{config.zone_id}/rulesets", headers=headers)
    for ruleset in response.json()['result']:
        if ruleset.get('phase') == 'http_request_firewall_custom' and ruleset.get('name') == 'default':
            RULESET_ID = ruleset['id']
            break

    response = requests.get(f"https://api.cloudflare.com/client/v4/zones/{config.zone_id}/rulesets/{RULESET_ID}", headers=headers)
    for rule in response.json()['result']['rules']:
        if rule.get('description') == rule_name:
            RULE_ID = rule['id']
            payload = {
                "action": rule["action"],
                "description": rule["description"],
                "enabled": state,
                "expression": rule["expression"]
            }
            break

    url = f"https://api.cloudflare.com/client/v4/zones/{config.zone_id}/rulesets/{RULESET_ID}/rules/{RULE_ID}"

    response = requests.patch(url, headers=headers, json=payload)