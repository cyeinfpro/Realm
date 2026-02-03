from __future__ import annotations

from typing import List, Optional, Literal

from pydantic import BaseModel, Field


RuleType = Literal["tcp_udp", "wss_client", "wss_server"]
BalanceAlgo = Literal["roundrobin", "iphash"]


class Target(BaseModel):
    addr: str = Field(..., description="host:port")


class Rule(BaseModel):
    id: str
    name: str
    listen: str = Field(..., description="0.0.0.0:PORT")

    # "tcp_udp" is normal realm forward. WSS rules map to transports.
    type: RuleType = "tcp_udp"

    protocol: str = Field("tcp+udp", description="tcp | udp | tcp+udp")

    targets: List[str] = Field(default_factory=list, description="target list host:port")
    balance: BalanceAlgo = "roundrobin"
    enabled: bool = True

    # WSS options (client/server)
    wss_host: Optional[str] = None
    wss_path: Optional[str] = None
    wss_sni: Optional[str] = None
    wss_insecure: bool = True

    # Server-side WSS certificate paths (optional; auto-generate if missing)
    wss_cert: Optional[str] = None
    wss_key: Optional[str] = None


class RuleCreate(BaseModel):
    name: str
    listen_port: int = Field(..., ge=1, le=65535)
    type: RuleType = "tcp_udp"
    protocol: str = "tcp+udp"
    targets: List[str]
    balance: BalanceAlgo = "roundrobin"
    enabled: bool = True

    wss_host: Optional[str] = None
    wss_path: Optional[str] = None
    wss_sni: Optional[str] = None
    wss_insecure: bool = True


class RuleUpdate(BaseModel):
    name: Optional[str] = None
    listen: Optional[str] = None
    type: Optional[RuleType] = None
    protocol: Optional[str] = None
    targets: Optional[List[str]] = None
    balance: Optional[BalanceAlgo] = None
    enabled: Optional[bool] = None

    wss_host: Optional[str] = None
    wss_path: Optional[str] = None
    wss_sni: Optional[str] = None
    wss_insecure: Optional[bool] = None


class ApplyResult(BaseModel):
    ok: bool
    message: str


class ServiceStatus(BaseModel):
    realm_active: bool
    realm_status: str
    rules_enabled: int
    rules_total: int
    now: int
    connections: dict = Field(default_factory=dict, description="rule_id -> {inbound:int, outbound:{target:int}}")
    target_status: dict = Field(default_factory=dict, description="rule_id -> {target_addr: bool}")


class LogsResponse(BaseModel):
    unit: str
    lines: List[str]
