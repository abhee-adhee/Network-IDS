import os
from config.rule_loader import load_rules, DEFAULT_RULES

def test_loader():
    rules = load_rules("config/rules.json")
    
    if rules == DEFAULT_RULES:
        # Note: If rules.json exactly matches the defaults, this will print "Default Rules Loaded".
        # But this is a simple check per the prompt requirements.
        print("Default Rules Loaded")
    else:
        print("Loaded Rules")
        
    print(rules)

if __name__ == "__main__":
    test_loader()
