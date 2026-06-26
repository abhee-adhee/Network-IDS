# Detection Engine
from detector.rules import (
    syn_flood_rule,
    port_scan_rule
)

from logger.alert_manager import raise_alert


def detect(packet):

    rules = [
        syn_flood_rule,
        port_scan_rule
    ]

    for rule in rules:

        alert = rule(packet)

        if alert:
            raise_alert(alert)
