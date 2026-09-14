#!/usr/bin/env python3
"""Thin public V-001 outbound claim/poll proof add-on."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

PACKAGE_VERSION = "0.1.21-remote-control-lab"
PROTOCOL_AGENT_VERSION = "0.1.17-lab"
SOURCE_REVISION = "bkho_remote_agent:0.1.21-remote-control-lab:v001-thin-public-host-network-egress"
PROTOCOL_SCHEMA_VERSION = "claim-poll-v11-v007-websocket-config-proof"
CONTROL_MODE = "outbound_https_poll"
CLAIM_TTL_SECONDS = 15 * 60
STATE_PATH = Path("/data/claim_state.json")
REDACTED = "[REDACTED]"

SECRET_KEYS = {"claim_secret", "poll_token", "signature", "Authorization"}
TELEMETRY_STAGES = {
    "process_started",
    "options_loaded",
    "control_endpoint_configured",
    "control_endpoint_url_valid",
    "claim_state_loaded_or_absent",
    "dns_resolution_started",
    "dns_resolution_succeeded",
    "dns_resolution_failed",
    "tls_connect_started",
    "tls_connect_succeeded",
    "tls_connect_failed",
    "claim_request_started",
    "claim_request_http_status",
    "claim_request_accepted",
    "claim_request_rejected",
    "poll_loop_entered",
    "poll_request_started",
    "poll_request_accepted",
    "unexpected_command_blocked",
    "fatal_startup_error",
}


class ProtocolError(Exception):
    pass


def utc_now() -> datetime:
    return datetime.now(UTC)


def rfc3339(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_rfc3339(value: str) -> datetime:
    if not value.endswith("Z"):
        raise ValueError("timestamp must be UTC")
    return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(UTC)


def base32_token(byte_count: int, *, grouped: bool = False) -> str:
    value = base64.b32encode(secrets.token_bytes(byte_count)).decode("ascii").rstrip("=")
    return value[:4] + "-" + value[4:8] if grouped else value


def looks_secret_like(value: str) -> bool:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        return False
    lowered = value.lower()
    markers = ("bearer ", "token=", "poll-token", "bkho-poll-", "authorization")
    return any(marker in lowered for marker in markers) or (
        len(value) >= 40 and any(char.isdigit() for char in value) and any(char.isalpha() for char in value)
    )


def sanitize(value):
    if isinstance(value, dict):
        safe = {}
        for key, item in value.items():
            key_text = str(key)
            safe[key_text] = REDACTED if key_text in SECRET_KEYS else sanitize(item)
        return safe
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        return REDACTED if looks_secret_like(value) else value
    return value


def read_options() -> dict:
    try:
        with open("/data/options.json", "r", encoding="utf-8") as handle:
            options = json.load(handle)
            return options if isinstance(options, dict) else {}
    except FileNotFoundError:
        return {}


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)


def read_json(path: Path) -> dict | None:
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
            return payload if isinstance(payload, dict) else None
    except FileNotFoundError:
        return None


def record(stage: str, *, status: str = "ok", details: dict | None = None, exc: BaseException | None = None) -> dict:
    event = {
        "timestamp": rfc3339(utc_now()),
        "stage": stage if stage in TELEMETRY_STAGES else "fatal_startup_error",
        "status": status,
        "details": {},
    }
    if details:
        allowed = {"hostname", "port", "http_status", "poll_seconds", "state_status", "claim_state"}
        event["details"].update({key: value for key, value in details.items() if key in allowed})
    if exc:
        event["details"]["exception_type"] = exc.__class__.__name__
    print(json.dumps(sanitize(event), sort_keys=True), flush=True)
    return event


def create_claim(now: datetime | None = None) -> dict:
    current = now or utc_now()
    claim_secret = secrets.token_urlsafe(32)
    return {
        "state": "UNCLAIMED",
        "agent_id": "bkho-agent-" + base32_token(10).lower(),
        "package_version": PACKAGE_VERSION,
        "agent_version": PROTOCOL_AGENT_VERSION,
        "control_mode": CONTROL_MODE,
        "device_code": base32_token(5, grouped=True),
        "claim_secret": claim_secret,
        "claim_secret_hash": hashlib.sha256(claim_secret.encode("utf-8")).hexdigest(),
        "created_at": rfc3339(current),
        "claim_expires_at": rfc3339(current + timedelta(seconds=CLAIM_TTL_SECONDS)),
    }


def load_or_create_claim() -> dict:
    state = read_json(STATE_PATH)
    if state:
        return state
    state = create_claim()
    write_json(STATE_PATH, state)
    return state


def stable_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def signature(state: dict, payload: dict) -> str:
    secret = str(state.get("poll_token") or state["claim_secret"])
    return hmac.new(secret.encode("utf-8"), stable_json(payload), hashlib.sha256).hexdigest()


def claim_request(state: dict) -> dict:
    return {
        "type": "CLAIM",
        "agent_id": state["agent_id"],
        "agent_version": PROTOCOL_AGENT_VERSION,
        "control_mode": CONTROL_MODE,
        "device_code": state["device_code"],
        "claim_secret_hash": state["claim_secret_hash"],
        "claim_expires_at": state["claim_expires_at"],
        "protocol_schema_version": PROTOCOL_SCHEMA_VERSION,
        "capabilities": ["outbound_claim", "signed_noop_poll"],
    }


def poll_request(state: dict) -> dict:
    payload = {
        "type": "POLL",
        "agent_id": state["agent_id"],
        "agent_version": PROTOCOL_AGENT_VERSION,
        "site_id": state.get("site_id"),
        "deployment_run_id": state.get("deployment_run_id"),
        "instance_id": state.get("instance_id"),
        "poll_token_expires_at": state.get("poll_token_expires_at"),
    }
    payload["signature"] = signature(state, payload)
    return payload


def post_json(url: str, payload: dict) -> dict:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ProtocolError("control endpoint must use https")
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        body = response.read(1024 * 128)
    parsed_body = json.loads(body.decode("utf-8")) if body else {}
    if not isinstance(parsed_body, dict):
        raise ProtocolError("control response must be an object")
    parsed_body["_http_status"] = response.status
    return parsed_body


def accept_claim(state: dict, response: dict) -> dict:
    if response.get("status") != "CLAIMED":
        raise ProtocolError("claim not accepted")
    expected_version = response.get("expected_agent_version", PROTOCOL_AGENT_VERSION)
    if expected_version != PROTOCOL_AGENT_VERSION:
        raise ProtocolError("agent version incompatible")
    required = ["site_id", "deployment_run_id", "instance_id", "poll_token", "poll_token_expires_at"]
    missing = [key for key in required if not response.get(key)]
    if missing:
        raise ProtocolError("claim response incomplete")
    if utc_now() >= parse_rfc3339(str(response["poll_token_expires_at"])):
        raise ProtocolError("poll token expired")
    updated = dict(state)
    updated.update(
        {
            "state": "CLAIMED",
            "site_id": response["site_id"],
            "deployment_run_id": response["deployment_run_id"],
            "instance_id": response["instance_id"],
            "poll_token": response["poll_token"],
            "poll_token_expires_at": response["poll_token_expires_at"],
            "claimed_at": rfc3339(utc_now()),
        }
    )
    write_json(STATE_PATH, updated)
    return updated


def poll_once(control_url: str) -> dict:
    state = load_or_create_claim()
    base = control_url.rstrip("/")
    if state.get("state") == "UNCLAIMED":
        record("claim_request_started")
        response = post_json(base + "/claim", claim_request(state))
        if response.get("_http_status"):
            record("claim_request_http_status", details={"http_status": response["_http_status"]})
        if response.get("status") == "CLAIMED":
            record("claim_request_accepted")
            return {"status": "CLAIMED", "claim": sanitize(accept_claim(state, response))}
        if response.get("status") == "PENDING":
            record("claim_request_accepted")
            return {"status": "PENDING", "claim": sanitize(state)}
        raise ProtocolError("unsupported claim response")

    if state.get("state") != "CLAIMED":
        raise ProtocolError("claim state is blocked")
    record("poll_request_started")
    response = post_json(base + "/poll", poll_request(state))
    if response.get("status") in (None, "NOOP"):
        record("poll_request_accepted")
        return {"status": "NOOP", "claim": sanitize(state)}
    command = str(response.get("command") or "")
    blocked = dict(state)
    blocked["state"] = "BLOCKED_UNEXPECTED_COMMAND"
    blocked["blocked_command"] = command
    write_json(STATE_PATH, blocked)
    record("unexpected_command_blocked", status="failed")
    raise ProtocolError("unexpected command received")


def validate_endpoint(url: str) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ProtocolError("control endpoint must use https")
    return parsed


def probe_dns_tls(url: str) -> None:
    parsed = validate_endpoint(url)
    host = parsed.hostname or ""
    port = parsed.port or 443
    record("dns_resolution_started", details={"hostname": host, "port": port})
    socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    record("dns_resolution_succeeded", details={"hostname": host, "port": port})
    record("tls_connect_started", details={"hostname": host, "port": port})
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=20) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                pass
        record("tls_connect_succeeded", details={"hostname": host, "port": port})
    except Exception as exc:
        record("tls_connect_failed", status="failed", details={"hostname": host, "port": port}, exc=exc)


def main() -> None:
    record("process_started")
    options = read_options()
    record("options_loaded")
    endpoint = str(options.get("control_endpoint_url") or "")
    poll_seconds = int(options.get("claim_poll_seconds") or 10)
    if not endpoint:
        record("control_endpoint_configured", status="failed")
        while True:
            time.sleep(3600)
    record("control_endpoint_configured", details={"poll_seconds": poll_seconds})
    try:
        validate_endpoint(endpoint)
        record("control_endpoint_url_valid")
        existing = read_json(STATE_PATH)
        record(
            "claim_state_loaded_or_absent",
            details={
                "state_status": "loaded" if existing else "absent",
                "claim_state": str(existing.get("state")) if existing else "UNCLAIMED",
            },
        )
        probe_dns_tls(endpoint)
    except Exception as exc:
        record("fatal_startup_error", status="failed", exc=exc)
        while True:
            time.sleep(3600)
    record("poll_loop_entered")
    while True:
        try:
            poll_once(endpoint)
        except urllib.error.HTTPError as exc:
            record("claim_request_http_status", status="failed", details={"http_status": exc.code}, exc=exc)
        except Exception as exc:
            record("claim_request_rejected", status="failed", exc=exc)
        time.sleep(poll_seconds)


if __name__ == "__main__":
    main()
