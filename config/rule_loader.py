import json
import os

# Default fallback rules in case the JSON file is missing or invalid.
DEFAULT_RULES = {
    "syn_flood": {
        "enabled": True,
        "threshold": 10,
        "severity": "HIGH"
    },
    "port_scan": {
        "enabled": True,
        "threshold": 10,
        "severity": "HIGH"
    }
}

def load_rules(config_path="config/rules.json"):
    """
    Loads detection rules from a JSON file.
    Validates structure and provides defaults if something goes wrong.
    """
    
    if not os.path.exists(config_path):
        return DEFAULT_RULES.copy()
        
    try:
        with open(config_path, "r") as f:
            data = json.load(f)
            
        # Basic validation
        if not isinstance(data, dict):
            return DEFAULT_RULES.copy()
            
        validated_rules = {}
        
        # Merge with defaults to ensure all required fields are present
        for rule_name, default_config in DEFAULT_RULES.items():
            rule_config = data.get(rule_name, {})
            
            validated_rules[rule_name] = {
                "enabled": rule_config.get("enabled", default_config["enabled"]),
                "threshold": rule_config.get("threshold", default_config["threshold"]),
                "severity": rule_config.get("severity", default_config["severity"])
            }
            
        return validated_rules
        
    except (json.JSONDecodeError, IOError, Exception):
        # Gracefully handle malformed JSON or read errors
        return DEFAULT_RULES.copy()

def save_rules(rules_data, config_path="config/rules.json"):
    """
    Saves detection rules to the JSON configuration file.
    Returns True on success, False on error.
    """
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        
        with open(config_path, "w") as f:
            json.dump(rules_data, f, indent=4)
        return True
    except IOError:
        return False
