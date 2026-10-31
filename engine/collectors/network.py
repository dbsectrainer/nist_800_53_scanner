"""Network configuration collectors."""

from __future__ import annotations

import json

from .base import Collector


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
                with open(path, encoding="utf-8") as fh:
                    data = json.load(fh)
                rules = [{"source": r.get("source"), "action": r.get("action")} for r in data.get("rules", [])]
                configs.append({"path": path, "rule_count": len(rules)})
                flat.extend({"path": path, **r} for r in rules)
            except (OSError, json.JSONDecodeError, AttributeError) as exc:
                unreadable.append({"path": path, "error": str(exc)})
        return {"configs": configs, "rules": flat, "unreadable": unreadable}
