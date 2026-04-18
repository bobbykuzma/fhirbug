"""Data models for the FHIR toolkit."""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


class Severity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(enum.Enum):
    AUTHN = "authentication"
    AUTHZ = "authorization"
    DATA_LEAK = "data_leakage"
    INJECTION = "injection"
    CONFIG = "misconfiguration"
    INFO_DISC = "information_disclosure"
    LOGIC = "business_logic"


@dataclass
class Finding:
    title: str
    severity: Severity
    category: FindingCategory
    description: str
    endpoint: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    cvss_vector: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["category"] = self.category.value
        return d


@dataclass
class EndpointInfo:
    base_url: str
    fhir_version: str = ""
    vendor: str = ""
    software_name: str = ""
    software_version: str = ""
    supported_resources: list[str] = field(default_factory=list)
    search_params: dict[str, list[str]] = field(default_factory=dict)
    operations: list[str] = field(default_factory=list)
    security: dict[str, Any] = field(default_factory=dict)
    smart_config: dict[str, Any] = field(default_factory=dict)
    interactions: dict[str, list[str]] = field(default_factory=dict)
    raw_capability: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    start_time: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    end_time: str = ""
    endpoint_info: EndpointInfo | None = None
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_error(self, error: str) -> None:
        self.errors.append(error)

    def finalize(self) -> None:
        self.end_time = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "endpoint_info": self.endpoint_info.to_dict() if self.endpoint_info else None,
            "findings": [f.to_dict() for f in self.findings],
            "findings_summary": {
                s.value: len([f for f in self.findings if f.severity == s])
                for s in Severity
            },
            "errors": self.errors,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
