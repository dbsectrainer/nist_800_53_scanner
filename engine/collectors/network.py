"""Network configuration collectors."""

from __future__ import annotations

import hashlib
import json

from .base import Collector

_ANY_SOURCES = {"any", "*", "all", "0.0.0.0/0", "::/0"}
_ALLOW_ACTIONS = {"allow", "accept", "permit"}
_DENY_ACTIONS = {"deny", "drop", "reject", "block"}


def _normalise_rule(rule: dict) -> dict:
    source = str(rule.get("source") or "").strip().lower()
    action = str(rule.get("action") or "").strip().lower()
    return {
        "source": "any" if source in _ANY_SOURCES else source,
        "action": "allow" if action in _ALLOW_ACTIONS else "deny" if action in _DENY_ACTIONS else action,
        "source_raw": rule.get("source"),
        "action_raw": rule.get("action"),
    }


class FirewallRulesCollector(Collector):
    """Reads JSON firewall exports listed in ``firewall.config_paths``.

    Unreadable or malformed files are recorded as unreadable (a coverage gap),
    not treated as permissive or as compliant.
    """

    name = "firewall_rules"
    evidence_type = "network.firewall_rules"

    def gather(self) -> dict:
        paths = (self.config.get("firewall") or {}).get("config_paths") or []
        if not paths:
            raise KeyError("firewall.config_paths not configured")
        configs, unreadable, flat = [], [], []
        for path in paths:
            try:
                with open(path, "rb") as fh:
                    body = fh.read()
                data = json.loads(body.decode("utf-8"))
                rules = [_normalise_rule(r) for r in data.get("rules", [])]
                configs.append({"path": path, "rule_count": len(rules), "sha256": hashlib.sha256(body).hexdigest()})
                flat.extend({"path": path, **r} for r in rules)
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, AttributeError, TypeError) as exc:
                unreadable.append({"path": path, "error": str(exc)})
        return {"configs": configs, "rules": flat, "unreadable": unreadable}
