"""Pydantic schemas for collector output, model output, and reports."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

RiskLevel = Literal["low", "medium", "high"]


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        parts = [p.strip(" -•") for p in value.replace(";", "\n").split("\n")]
        return [p for p in parts if p]
    if isinstance(value, dict):
        return [f"{k}: {v}" if v else str(k) for k, v in value.items()]
    if isinstance(value, (list, tuple, set)):
        out: list[str] = []
        for item in value:
            if isinstance(item, str):
                if item.strip():
                    out.append(item.strip())
            elif isinstance(item, dict):
                out.extend(_as_str_list(item.get("value") or item.get("name") or item))
            elif item is not None:
                out.append(str(item))
        return out
    return [str(value)]


class CollectorResult(BaseModel):
    """One collector's outcome for one target. Never raises."""

    model_config = ConfigDict(extra="allow")

    collector: str
    target: str
    target_type: str
    ok: bool = True
    skipped: bool = False
    note: str | None = None
    error: str | None = None
    data: Any = None
    elapsed_ms: int = 0
    cached: bool = False

    @property
    def has_data(self) -> bool:
        if self.skipped or not self.ok or self.data is None:
            return False
        if isinstance(self.data, (list, dict, str)):
            return len(self.data) > 0
        return True


class Breach(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    date: str | None = None
    data_types: list[str] = Field(default_factory=list)
    source: str | None = None

    @field_validator("name", "date", "source", mode="before")
    @classmethod
    def _stringify(cls, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, (list, tuple)):
            return ", ".join(str(v) for v in value)
        return str(value)

    @field_validator("data_types", mode="before")
    @classmethod
    def _types(cls, value: Any) -> list[str]:
        return _as_str_list(value)


class AssociatedAccount(BaseModel):
    model_config = ConfigDict(extra="allow")

    platform: str
    url: str | None = None
    handle: str | None = None
    note: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _normalize(cls, value: Any) -> Any:
        if isinstance(value, str):
            return {"platform": value}
        return value

    @field_validator("platform", "url", "handle", "note", mode="before")
    @classmethod
    def _stringify(cls, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, (list, tuple)):
            return ", ".join(str(v) for v in value)
        return str(value)


class Analysis(BaseModel):
    """The strict shape we demand back from the model."""

    model_config = ConfigDict(extra="allow")

    summary: str = ""
    breaches: list[Breach] = Field(default_factory=list)
    associated_accounts: list[AssociatedAccount] = Field(default_factory=list)
    infrastructure_notes: list[str] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)
    risk_level: RiskLevel = "low"
    recommendations: list[str] = Field(default_factory=list)
    confidence: dict[str, str] = Field(default_factory=dict)

    @field_validator("summary", mode="before")
    @classmethod
    def _summary(cls, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, (list, dict)):
            return "\n".join(_as_str_list(value))
        return str(value).strip()

    @field_validator("subdomains", "recommendations", "infrastructure_notes", mode="before")
    @classmethod
    def _lists(cls, value: Any) -> list[str]:
        return _as_str_list(value)

    @field_validator("breaches", mode="before")
    @classmethod
    def _breaches(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [{"name": value}] if value.strip() else []
        return value or []

    @field_validator("associated_accounts", mode="before")
    @classmethod
    def _accounts(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [{"platform": value}] if value.strip() else []
        return value or []

    @field_validator("subdomains")
    @classmethod
    def _dedupe(cls, value: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for item in value:
            key = item.strip().lower()
            if key and key not in seen:
                seen.add(key)
                out.append(item.strip())
        return out

    @field_validator("risk_level", mode="before")
    @classmethod
    def _risk(cls, value: Any) -> Any:
        if value is None:
            return "low"
        text = str(value).strip().lower()
        for level in ("high", "medium", "low"):
            if level in text:
                return level
        return "low"


class Report(BaseModel):
    """A rendered-ready record of one target lookup."""

    schema_version: str = "1"
    target: str
    target_type: str
    generated_at: str = Field(default_factory=_utcnow_iso)
    model: str | None = None
    base_url: str | None = None
    elapsed_ms: int = 0
    collectors: list[CollectorResult] = Field(default_factory=list)
    analysis: Analysis | None = None
    notes: list[str] = Field(default_factory=list)

    @property
    def ok_collectors(self) -> list[CollectorResult]:
        return [c for c in self.collectors if c.has_data]


class PromptBundle(BaseModel):
    """The package handed to the model."""

    target: str
    target_type: str
    collected_at: str = Field(default_factory=_utcnow_iso)
    results: list[CollectorResult] = Field(default_factory=list)
    signals: dict[str, Any] = Field(default_factory=dict)

    def to_prompt_json(self) -> str:
        payload = {
            "target": self.target,
            "target_type": self.target_type,
            "signals": self.signals,
            "sources": [
                {
                    "source": r.collector,
                    "status": "ok" if r.ok else ("skipped" if r.skipped else "error"),
                    "note": r.note,
                    "data": r.data,
                }
                for r in self.results
                if r.ok and not r.skipped
            ],
            "unavailable_sources": [
                {"source": r.collector, "reason": r.note or r.error or "unknown"}
                for r in self.results
                if not r.ok or r.skipped
            ],
        }
        import json

        return json.dumps(payload, indent=2, ensure_ascii=False, default=str)
