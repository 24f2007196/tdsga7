# c

import json
import math
import os
import re
import threading
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from fastapi import FastAPI, Request

app = FastAPI()

TENANT_ID = "tenant-ouddfp6"
EMAIL_DOMAIN = "notify-c9tjunu.example"
TOOLS = {"search", "lookup_record", "send_email", "render_html"}


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "GA7 API is running"}


def _result(decision: str, reason: str) -> dict[str, str]:
    return {"decision": decision, "reason": reason}


def _valid_args(args: Any, fields: set[str]) -> bool:
    return (
        isinstance(args, dict)
        and set(args) == fields
        and all(isinstance(value, str) for value in args.values())
    )


class _HTMLSafetyParser(HTMLParser):
    URL_ATTRIBUTES = {"action", "background", "cite", "formaction", "href", "poster", "src", "xlink:href"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.unsafe = False

    def _check(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"iframe", "script"}:
            self.unsafe = True
        for name, value in attrs:
            name = name.lower()
            if name.startswith("on") or (name in self.URL_ATTRIBUTES and value and self._javascript_url(value)):
                self.unsafe = True

    @staticmethod
    def _javascript_url(value: str) -> bool:
        return re.sub(r"[\s\x00-\x1f]+", "", value).lower().startswith("javascript:")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._check(tag, attrs)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._check(tag, attrs)


def _unsafe_html(value: str) -> bool:
    parser = _HTMLSafetyParser()
    parser.feed(value)
    return parser.unsafe


@app.post("/ga7/q2/action-firewall")
async def action_firewall(request: Request) -> dict[str, str]:
    try:
        payload = await request.json()
    except Exception:
        return _result("block", "INVALID_SCHEMA")

    if not isinstance(payload, dict):
        return _result("block", "INVALID_SCHEMA")
    required = {"provenance", "humanApproved", "action"}
    allowed = required | {"untrustedContent"}
    if set(payload) - allowed or not required <= set(payload):
        return _result("block", "INVALID_SCHEMA")
    if payload["provenance"] not in {"trusted", "untrusted"}:
        return _result("block", "INVALID_SCHEMA")
    if not isinstance(payload["humanApproved"], bool):
        return _result("block", "INVALID_SCHEMA")
    if "untrustedContent" in payload and payload["untrustedContent"] is not None and not isinstance(payload["untrustedContent"], str):
        return _result("block", "INVALID_SCHEMA")

    action = payload["action"]
    if not isinstance(action, dict) or set(action) != {"tool", "args"} or not isinstance(action["tool"], str) or not isinstance(action["args"], dict):
        return _result("block", "INVALID_SCHEMA")

    tool = action["tool"]
    args = action["args"]
    if tool not in TOOLS:
        return _result("block", "TOOL_NOT_ALLOWED")

    fields = {
        "search": {"query"},
        "lookup_record": {"tenantId", "recordId"},
        "send_email": {"to", "subject", "body"},
        "render_html": {"html"},
    }[tool]
    if not _valid_args(args, fields):
        return _result("block", "INVALID_SCHEMA")

    if tool == "search" and not 1 <= len(args["query"]) <= 200:
        return _result("block", "INVALID_SCHEMA")
    if tool == "lookup_record":
        if not args["recordId"]:
            return _result("block", "INVALID_SCHEMA")
        if args["tenantId"] != TENANT_ID:
            return _result("block", "TENANT_SCOPE")
    if tool == "send_email":
        to = args["to"]
        if to.count("@") != 1 or not to.split("@", 1)[0] or any(char.isspace() for char in to):
            return _result("block", "INVALID_SCHEMA")
        if to.rsplit("@", 1)[1].lower() != EMAIL_DOMAIN:
            return _result("block", "EGRESS_DENIED")
        if not payload["humanApproved"]:
            return _result("block", "APPROVAL_REQUIRED")
    if tool == "render_html" and _unsafe_html(args["html"]):
        return _result("block", "UNSAFE_OUTPUT")

    return _result("allow", "ALLOW")


WORKSPACE = "prod-tvhuqi"
REQUIRED_LABELS = {
    "owner": "student-balgo",
    "environment": "production",
    "cost_center": "cc-ciz1",
}
STATE_BACKENDS = {"gcs", "s3", "azurerm", "remote"}
DESTRUCTIVE_TYPES = {"storage_bucket", "sql_database", "persistent_disk"}
PINNED_PROVIDER_VERSIONS = {"6.2.1", "= 6.2.1", "~> 6.0"}


def _terraform_schema_valid(plan: Any) -> bool:
    if not isinstance(plan, dict) or set(plan) != {
        "environment", "state", "providerVersion", "destroyApproved", "resource"
    }:
        return False
    if not isinstance(plan["environment"], str) or not isinstance(plan["providerVersion"], str):
        return False
    if not isinstance(plan["destroyApproved"], bool):
        return False

    state = plan["state"]
    if (
        not isinstance(state, dict)
        or set(state) != {"backend", "locked"}
        or not isinstance(state["backend"], str)
        or not isinstance(state["locked"], bool)
    ):
        return False

    resource = plan["resource"]
    if not isinstance(resource, dict) or set(resource) != {
        "address", "type", "action", "labels", "secret", "forceDestroy"
    }:
        return False
    if (
        not isinstance(resource["address"], str)
        or not isinstance(resource["type"], str)
        or not isinstance(resource["action"], str)
        or resource["action"] not in {"create", "update", "delete"}
        or not isinstance(resource["labels"], dict)
        or not all(isinstance(value, str) for value in resource["labels"].values())
        or resource["secret"] is not None and not isinstance(resource["secret"], str)
        or not isinstance(resource["forceDestroy"], bool)
    ):
        return False
    return True


@app.post("/ga7/q3/terraform/plan")
async def terraform_plan(request: Request) -> dict[str, str]:
    try:
        plan = await request.json()
    except Exception:
        return _result("reject", "INVALID_PLAN")

    if not _terraform_schema_valid(plan):
        return _result("reject", "INVALID_PLAN")
    if plan["environment"] != WORKSPACE:
        return _result("reject", "ENVIRONMENT_MISMATCH")

    state = plan["state"]
    if state["backend"] not in STATE_BACKENDS or state["locked"] is not True:
        return _result("reject", "STATE_UNSAFE")
    if plan["providerVersion"] not in PINNED_PROVIDER_VERSIONS:
        return _result("reject", "UNPINNED_PROVIDER")

    resource = plan["resource"]
    if any(resource["labels"].get(key) != value for key, value in REQUIRED_LABELS.items()):
        return _result("reject", "MISSING_LABELS")

    secret = resource["secret"]
    if secret is not None and (not secret.startswith("secret://") or not secret[9:].strip()):
        return _result("reject", "PLAINTEXT_SECRET")

    if resource["action"] == "delete" and resource["type"] in DESTRUCTIVE_TYPES and not plan["destroyApproved"]:
        return _result("reject", "DELETE_NOT_APPROVED")
    if resource["type"] == "storage_bucket" and resource["forceDestroy"]:
        return _result("reject", "FORCE_DESTROY")

    return _result("approve", "APPROVE")


SANITIZE_CHANNELS = {"html", "markdown", "url", "sql", "shell"}
SANITIZE_HOSTS = {"cdn-ygploas.example", "app-jj5csna.example"}
_ENTITY_RE = re.compile(r"&(?:#x([0-9a-fA-F]+)|#([0-9]+)|([A-Za-z]+));", re.IGNORECASE)
_SCRIPT_TAG_RE = re.compile(r"<\s*(?:script|iframe|object|embed)\b", re.IGNORECASE)
_EVENT_HANDLER_RE = re.compile(r"<[^>]*?(?<![-\w:])on[a-z][\w:-]*\s*=", re.IGNORECASE | re.DOTALL)
_SCHEME_RE = re.compile(r"(?<![A-Za-z0-9+.-])(?:javascript|data|vbscript)\s*:", re.IGNORECASE)
_HTML_URL_RE = re.compile(r"<[^>]*?(?<![-\w:])(?:src|href)\s*=\s*([\"'])(.*?)\1", re.IGNORECASE | re.DOTALL)
_MARKDOWN_URL_RE = re.compile(r"\]\(\s*(?:<([^>]+)>|([^\s)]+))", re.DOTALL)
_SQL_RE = re.compile(r"['\";]|--|/\*|\bunion\b|\bor\s+1\s*=\s*1\b", re.IGNORECASE)
_SHELL_RE = re.compile(r"[;&|`<>]|\$\(|\$\{")


def _sanitize_result(safe: bool, reason: str) -> dict[str, Any]:
    return {"safe": safe, "reason": reason}


def _decode_entities_once(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        try:
            if match.group(1):
                return chr(int(match.group(1), 16))
            if match.group(2):
                return chr(int(match.group(2), 10))
        except (ValueError, OverflowError):
            return match.group(0)
        return {
            "lt": "<",
            "gt": ">",
            "quot": '\"',
            "apos": "'",
            "amp": "&",
        }.get((match.group(3) or "").lower(), match.group(0))

    return _ENTITY_RE.sub(replace, value)


def _decode_output_once(value: str) -> str:
    value = unquote(value)
    value = _decode_entities_once(value)
    return re.sub(r"\\u([0-9a-fA-F]{4})", lambda match: chr(int(match.group(1), 16)), value)


def _extracted_urls(channel: str, output: str) -> list[str]:
    if channel == "html":
        return [match.group(2) for match in _HTML_URL_RE.finditer(output)]
    if channel == "markdown":
        return [match.group(1) or match.group(2) for match in _MARKDOWN_URL_RE.finditer(output)]
    if channel == "url":
        return [output.strip()]
    return []


def _url_reason(url: str) -> str | None:
    url = url.strip()
    try:
        parsed = urlsplit("https:" + url if url.startswith("//") else url)
    except ValueError:
        return "EXTERNAL_EXFIL"
    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        return "DANGEROUS_SCHEME"
    is_absolute = url.startswith("//") or parsed.scheme.lower() in {"http", "https"}
    if not is_absolute:
        return None
    try:
        hostname = parsed.hostname
    except ValueError:
        hostname = None
    if not hostname or hostname.lower() not in SANITIZE_HOSTS:
        return "EXTERNAL_EXFIL"
    return None


def _sanitize_channel_reason(channel: str, output: str) -> str:
    if channel == "html":
        if _SCRIPT_TAG_RE.search(output):
            return "SCRIPT_TAG"
        if _EVENT_HANDLER_RE.search(output):
            return "EVENT_HANDLER"
    if channel == "sql":
        return "SQL_METACHAR" if _SQL_RE.search(output) else "SAFE"
    if channel == "shell":
        return "SHELL_METACHAR" if _SHELL_RE.search(output) else "SAFE"

    if _SCHEME_RE.search(output):
        return "DANGEROUS_SCHEME"
    for url in _extracted_urls(channel, output):
        reason = _url_reason(url)
        if reason:
            return reason
    return "SAFE"


@app.post("/ga7/q4/sanitize-output")
async def sanitize_output(request: Request) -> dict[str, Any]:
    try:
        payload = await request.json()
    except Exception:
        return _sanitize_result(False, "INVALID_SCHEMA")

    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("channel"), str)
        or payload["channel"] not in SANITIZE_CHANNELS
        or not isinstance(payload.get("output"), str)
        or len(payload["output"]) > 20_000
    ):
        return _sanitize_result(False, "INVALID_SCHEMA")

    channel = payload["channel"]
    output = payload["output"]
    decoded = _decode_output_once(output)
    if decoded != output and _sanitize_channel_reason(channel, decoded) != "SAFE":
        return _sanitize_result(False, "ENCODED_PAYLOAD")

    reason = _sanitize_channel_reason(channel, output)
    return _sanitize_result(reason == "SAFE", reason)


CORROBORATE_SOURCE_TYPES = {"dns", "ct_log", "registry", "archive", "scan"}
CORROBORATE_LOG_PATH = Path(os.getenv("CORROBORATE_LOG_PATH", "/tmp/ga7-corroborate.jsonl"))
CORROBORATE_LOG_LOCK = threading.Lock()


def _log_corroboration_request(value: Any) -> None:
    try:
        line = json.dumps({"request": value}, ensure_ascii=False, separators=(",", ":"))
        with CORROBORATE_LOG_LOCK:
            CORROBORATE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with CORROBORATE_LOG_PATH.open("a", encoding="utf-8") as log:
                log.write(line + "\n")
    except (OSError, TypeError, ValueError):
        pass


def _read_corroboration_logs() -> list[Any]:
    try:
        with CORROBORATE_LOG_PATH.open(encoding="utf-8") as log:
            return [json.loads(line)["request"] for line in log if line.strip()]
    except (OSError, KeyError, TypeError, ValueError):
        return []


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        timestamp = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        return None
    return timestamp if timestamp.tzinfo is not None else timestamp.replace(tzinfo=timezone.utc)


def _fresh_source(source: dict[str, Any], as_of: datetime, staleness_days: float) -> bool:
    observed_at = _parse_timestamp(source["observedAt"])
    if observed_at is None:
        return False
    return (as_of - observed_at).total_seconds() / 86400 <= staleness_days


def _valid_corroboration_source(source: Any) -> bool:
    return (
        isinstance(source, dict)
        and all(isinstance(source.get(key), str) for key in ("id", "origin", "value", "observedAt"))
        and source.get("type") in CORROBORATE_SOURCE_TYPES
    )


def _corroboration_response(verdict: str, confidence: str, source_ids: list[str]) -> dict[str, Any]:
    return {
        "verdict": verdict,
        "confidence": confidence,
        "corroboratingSources": source_ids,
    }


@app.post("/corroborate")
@app.post("/ga7/q5/corroborate")
async def corroborate(request: Request) -> dict[str, Any]:
    raw = await request.body()
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _log_corroboration_request({"raw": raw.decode("utf-8", errors="replace")})
        return _corroboration_response("invalid", "low", [])
    _log_corroboration_request(payload)

    if not isinstance(payload, dict):
        return _corroboration_response("invalid", "low", [])
    claim = payload.get("claim")
    as_of = _parse_timestamp(payload.get("asOf"))
    staleness_days = payload.get("stalenessDays")
    sources = payload.get("sources")
    if (
        not isinstance(claim, dict)
        or not isinstance(claim.get("value"), str)
        or as_of is None
        or isinstance(staleness_days, bool)
        or not isinstance(staleness_days, (int, float))
        or not math.isfinite(staleness_days)
        or not isinstance(sources, list)
    ):
        return _corroboration_response("invalid", "low", [])

    valid_sources = [source for source in sources if _valid_corroboration_source(source)]
    fresh_sources = [
        source for source in valid_sources
        if _fresh_source(source, as_of, float(staleness_days))
    ]
    claim_value = claim["value"]
    contradicting = sorted(
        source["id"]
        for source in fresh_sources
        if source.get("authoritative") is True and source["value"] != claim_value
    )
    if contradicting:
        return _corroboration_response("contradicted", "low", contradicting)

    matching = [source for source in fresh_sources if source["value"] == claim_value]
    representatives = {
        source["origin"]: min(
            (candidate for candidate in matching if candidate["origin"] == source["origin"]),
            key=lambda candidate: candidate["id"],
        )
        for source in matching
    }
    representative_sources = list(representatives.values())
    if len(representative_sources) >= 2:
        confidence = "high" if len({source["type"] for source in representative_sources}) >= 2 else "medium"
        return _corroboration_response(
            "supported",
            confidence,
            sorted(source["id"] for source in representative_sources),
        )
    return _corroboration_response("unverified", "low", [])


@app.get("/corroborate/logs")
@app.get("/ga7/q5/corroborate/logs")
def corroboration_logs() -> dict[str, Any]:
    return {"requests": _read_corroboration_logs()}


RELEASE_PERMISSIONS = {"contents": "read", "packages": "write", "id-token": "none"}
FULL_SHA = re.compile(r"[0-9a-f]{40}")


def _release_gate_violations(payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        return ["EXCESS_PERMISSION", "TESTS_INCOMPLETE", "MUTABLE_ACTION", "SINGLE_STAGE_IMAGE", "ROOT_RUNTIME", "SECRET_IN_LAYER", "CRITICAL_CVE", "UNPINNED_IMAGE"]

    workflow = payload.get("workflow")
    image = payload.get("image")
    workflow = workflow if isinstance(workflow, dict) else {}
    image = image if isinstance(image, dict) else {}
    violations: list[str] = []

    if workflow.get("permissions") != RELEASE_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    if payload.get("event") == "pull_request" and workflow.get("trigger") != "pull_request":
        violations.append("UNSAFE_PR_TRIGGER")
    if workflow.get("testsPassed") is not True or workflow.get("matrixComplete") is not True or workflow.get("failFast") is not False:
        violations.append("TESTS_INCOMPLETE")

    actions = workflow.get("actions")
    if not isinstance(actions, list) or any(
        not isinstance(action, dict)
        or action.get("owner") != "actions" and (
            not isinstance(action.get("ref"), str) or not FULL_SHA.fullmatch(action["ref"])
        )
        for action in (actions if isinstance(actions, list) else [])
    ):
        violations.append("MUTABLE_ACTION")

    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")
    if image.get("secretMode") not in {"none", "buildkit"}:
        violations.append("SECRET_IN_LAYER")
    critical = image.get("criticalVulnerabilities")
    if isinstance(critical, bool) or not isinstance(critical, (int, float)) or critical != 0:
        violations.append("CRITICAL_CVE")
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    if payload.get("target") == "production":
        if payload.get("event") != "push" or payload.get("ref") != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")
        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    return violations


@app.post("/release-gate")
@app.post("/ga7/q1/release-gate")
async def release_gate(request: Request) -> dict[str, Any]:
    try:
        payload = await request.json()
    except Exception:
        payload = None
    violations = _release_gate_violations(payload)
    return {"decision": "promote" if not violations else "block", "violations": violations}
