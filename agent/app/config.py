from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class AgentConfig:
    # Files
    data_dir: str = os.getenv("REALM_AGENT_DATA_DIR", "/etc/realm-agent")
    rules_file: str = os.getenv("REALM_AGENT_RULES_FILE", "/etc/realm-agent/rules.json")
    agent_env_file: str = os.getenv("REALM_AGENT_ENV_FILE", "/etc/realm-agent/agent.env")
    realm_config_file: str = os.getenv("REALM_CONFIG_FILE", "/etc/realm/config.json")

    # Realm service
    realm_service: str = os.getenv("REALM_SERVICE", "realm.service")

    # Auth
    token: str = os.getenv("REALM_AGENT_TOKEN", "")

    # Panel heartbeat
    panel_url: str = os.getenv("REALM_PANEL_URL", "")
    agent_id: str = os.getenv("REALM_AGENT_ID", "")
    heartbeat_interval: int = int(os.getenv("REALM_AGENT_HEARTBEAT_INTERVAL", "30"))

    # Apply behavior
    auto_apply: bool = os.getenv("REALM_AGENT_AUTO_APPLY", "1") not in ("0", "false", "False")

    # TLS verification for panel
    panel_verify_tls: bool = os.getenv("REALM_PANEL_VERIFY_TLS", "0") in ("1", "true", "True")

    # Allow running shell commands
    allow_shell: bool = os.getenv("REALM_AGENT_ALLOW_SHELL", "1") not in ("0", "false", "False")


CFG = AgentConfig()
